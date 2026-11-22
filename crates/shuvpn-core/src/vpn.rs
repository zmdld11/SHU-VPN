//! OpenVPN 进程与 management 接口管理（docs/protocol.md §6）。
//!
//! 复用已装社区版 `openvpn.exe`，以
//! `--management 127.0.0.1 <port> --management-query-passwords --management-hold
//! --auth-retry interact` 拉起，经 TCP management 接口程序化应答：
//!
//! - `>PASSWORD:Need 'Auth' username/password` → 学号 + 统一身份认证密码
//! - 静态挑战（`--static-challenge`，SHU 的 OTP 独立弹框即此）→ `SCRV1:<b64密码>:<b64口令>`
//!   或密码口令拼接（FORMAT 标志决定）
//! - 动态挑战（CRV1，验证失败消息携带）→ `CRV1:<flags>:<opaque>:<b64用户名>:<口令>`
//! - `>INFOMSG:CR_TEXT:...`（2.5+ 服务端推送）→ `cr-response <b64口令>`（防御性支持）
//!
//! 帧格式依据 OpenVPN 官方 management-notes.txt；挑战应答在收到时**实时取新口令**
//!（30s 时效）。协议解析为纯函数，离线单测覆盖。

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, Mutex};

use crate::error::{CoreError, Result};

/// 社区版 openvpn.exe 默认路径。
pub const DEFAULT_OPENVPN_PATH: &str = r"C:\Program Files\OpenVPN\bin\openvpn.exe";

/// 内置的 SHU.ovpn（学校官方公开分发的连接配置，对全体用户相同，无任何
/// 个人凭据；来源与更新地址见 README「配置来源」）。connect 缺省使用它，
/// 写成临时文件后交给 openvpn；`--config` 仍可指向用户自备配置。
pub const EMBEDDED_SHU_OVPN: &str = include_str!("../../../assets/shu.ovpn");

/// management 连接等待上限（openvpn 打开端口通常 <1s）。
const MGMT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// 连续认证失败多少次后放弃（避免口令/密码错误时无限重试）。
const MAX_AUTH_FAILURES: usize = 3;

// ---------------------------------------------------------------------------
// 事件与状态
// ---------------------------------------------------------------------------

/// 连接等待的看门狗间隔（兜底释放 hold / 静默超时检查）。取短值是安全的：
/// `hold release` 幂等（不在 hold 中也返回 SUCCESS），补发无害，而丢失的
/// 单次释放会卡住整个启动（实测见 docs/protocol.md §6）。
const WATCHDOG_INTERVAL: Duration = Duration::from_secs(3);

/// 看门狗最多补发 hold release 的次数（避免异常场景无限循环）。
const MAX_WATCHDOG_RELEASES: usize = 5;

/// 连接过程中对外广播的事件。
#[derive(Debug, Clone)]
pub enum VpnEvent {
    /// management `>STATE:` 通知（name 为 OpenVPN 原生状态名）。
    State {
        name: String,
        reason: Option<String>,
    },
    /// 日志行（management >LOG 或子进程 stdout/stderr）。
    Log(String),
    /// 需要用户关注的通知（如 SSO 会话失效）。
    Notice(String),
}

impl VpnEvent {
    /// `>STATE:` 状态名是否表示已连接（Initialization Sequence Completed）。
    pub fn state_is_connected(name: &str) -> bool {
        name == "CONNECTED"
    }
}

// ---------------------------------------------------------------------------
// management 行解析（纯函数）
// ---------------------------------------------------------------------------

/// `>PASSWORD:Need 'Auth'` 的附带的挑战上下文。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeedAuth {
    /// 只要求用户名（服务端声明版本 ≥4 才会出现）。
    pub username_only: bool,
    /// 静态挑战（shu.ovpn `--static-challenge` 的 SC:<flag>,<text>）。
    pub static_challenge: Option<StaticChallenge>,
}

/// 静态挑战：`SC:<flag>,<text>`；flag bit0=ECHO、bit1=FORMAT（1 表示密码与应答拼接）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticChallenge {
    pub flag: u8,
    pub text: String,
}

/// 动态挑战：验证失败消息里的 `['CRV1:<flags>:<opaque>:<b64用户名>:<文本>']`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicChallenge {
    pub flags: String,
    pub opaque: String,
    pub username_b64: String,
    pub text: String,
}

/// 一行 management 输出解析出的事件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MgmtEvent {
    State {
        name: String,
        reason: Option<String>,
    },
    NeedAuth(NeedAuth),
    VerificationFailed {
        reason: String,
        dynamic: Option<DynamicChallenge>,
    },
    AuthToken,
    /// openvpn 处于 hold 等待状态（应答 `hold release` 以启动连接）。
    /// 注意：该通知可能滞后于握手——GUI 的标准做法是**收到 >HOLD 才释放**，
    /// 握手阶段立即释放会与主线程进入 hold 等待产生竞态（实测 2.7.8 卡死）。
    Hold,
    Log(String),
    Info(String),
    Infomsg(String),
    Fatal(String),
    Other(String),
}

/// 解析一行 management 输出；无法识别时归入 [`MgmtEvent::Other`]。
pub fn parse_mgmt_line(line: &str) -> MgmtEvent {
    let Some(rest) = line.strip_prefix('>') else {
        return MgmtEvent::Other(line.to_string());
    };
    let (kind, payload) = rest.split_once(':').unwrap_or((rest, ""));
    match kind {
        "STATE" => {
            let mut fields = payload.split(',');
            let _ts = fields.next();
            let name = fields.next().unwrap_or("").to_string();
            let reason = fields.next().filter(|s| !s.is_empty()).map(str::to_string);
            MgmtEvent::State { name, reason }
        }
        "PASSWORD" => {
            if let Some(sc) = payload.strip_prefix("Need 'Auth' username/password SC:") {
                let static_challenge = sc.split_once(',').and_then(|(flag, text)| {
                    flag.trim().parse::<u8>().ok().map(|flag| StaticChallenge {
                        flag,
                        text: text.to_string(),
                    })
                });
                return MgmtEvent::NeedAuth(NeedAuth {
                    username_only: false,
                    static_challenge,
                });
            }
            if payload.starts_with("Need 'Auth' username/password") {
                return MgmtEvent::NeedAuth(NeedAuth {
                    username_only: false,
                    static_challenge: None,
                });
            }
            if payload.starts_with("Need 'Auth' username") {
                return MgmtEvent::NeedAuth(NeedAuth {
                    username_only: true,
                    static_challenge: None,
                });
            }
            if let Some(rest) = payload.strip_prefix("Verification Failed:") {
                let reason = first_quoted(rest).unwrap_or(rest.trim());
                let dynamic = extract_crv1(rest).map(|s| parse_crv1(&s));
                return MgmtEvent::VerificationFailed {
                    reason: reason.to_string(),
                    dynamic,
                };
            }
            if payload.starts_with("Auth-Token:") {
                return MgmtEvent::AuthToken;
            }
            MgmtEvent::Other(line.to_string())
        }
        "LOG" => MgmtEvent::Log(payload.to_string()),
        "INFO" => MgmtEvent::Info(payload.to_string()),
        "INFOMSG" => MgmtEvent::Infomsg(payload.to_string()),
        "FATAL" => MgmtEvent::Fatal(payload.to_string()),
        "HOLD" => MgmtEvent::Hold,
        _ => MgmtEvent::Other(line.to_string()),
    }
}

/// 从 `Verification Failed` 载荷提取动态挑战串（`CRV1:` 起，到结尾 `']` 止）。
fn extract_crv1(s: &str) -> Option<String> {
    let start = s.find("CRV1:")?;
    let seg = &s[start..];
    let seg = seg.strip_suffix("']").unwrap_or(seg);
    Some(seg.trim_end().to_string())
}

/// 解析 `CRV1:<flags>:<opaque>:<b64用户名>:<文本>`；文本段允许包含冒号。
pub fn parse_crv1(s: &str) -> DynamicChallenge {
    let mut parts = s.splitn(4, ':');
    let _tag = parts.next();
    let flags = parts.next().unwrap_or("").to_string();
    let opaque = parts.next().unwrap_or("").to_string();
    let rest = parts.next().unwrap_or("");
    let (username_b64, text) = rest.split_once(':').unwrap_or((rest, ""));
    DynamicChallenge {
        flags,
        opaque,
        username_b64: username_b64.to_string(),
        text: text.to_string(),
    }
}

/// 提取载荷里第一对单引号内容（如 `'Auth'`）。
fn first_quoted(s: &str) -> Option<&str> {
    let start = s.find('\'')? + 1;
    let rest = &s[start..];
    let end = rest.find('\'')?;
    Some(&rest[..end])
}

// ---------------------------------------------------------------------------
// 应答构造（纯函数）
// ---------------------------------------------------------------------------

/// management 命令参数转义（与 config 解析一致的 `\` 与 `"` 处理）。
pub fn escape_mgmt(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(c),
        }
    }
    out
}

fn quoted(s: &str) -> String {
    format!("\"{}\"", escape_mgmt(s))
}

/// 构造对 `Need 'Auth'` 的应答命令序列。
///
/// - `dynamic`（CRV1）优先：应答 `password "Auth" "CRV1:<flags>:<opaque>:<b64用户名>:<口令>"`，
///   flags/opaque/b64 用户名原样回传挑战值（模板语义），用户名取挑战解码值；
/// - 静态挑战按 FORMAT（flag bit1）：0 → `SCRV1:<b64密码>:<b64口令>`；1 → 密码口令拼接；
/// - `username_only` 只回用户名行。
pub fn auth_response_lines(
    username: &str,
    password: &str,
    otp: &str,
    need: &NeedAuth,
    dynamic: Option<&DynamicChallenge>,
) -> Vec<String> {
    let b64 = base64::engine::general_purpose::STANDARD;

    if let Some(d) = dynamic {
        let responded_user =
            decode_b64_utf8(&d.username_b64).unwrap_or_else(|| username.to_string());
        let crv1 = format!(
            "CRV1:{}:{}:{}:{}",
            escape_mgmt(&d.flags),
            escape_mgmt(&d.opaque),
            d.username_b64,
            otp
        );
        return vec![
            format!("username \"Auth\" {}", quoted(&responded_user)),
            format!("password \"Auth\" {}", quoted(&crv1)),
        ];
    }

    let mut lines = Vec::with_capacity(2);
    lines.push(format!("username \"Auth\" {}", quoted(username)));
    if need.username_only {
        return lines;
    }
    let password_line = match &need.static_challenge {
        Some(sc) if sc.flag & 0x2 != 0 => {
            // FORMAT=1：密码与应答直接拼接
            format!("password \"Auth\" {}", quoted(&format!("{password}{otp}")))
        }
        Some(_sc) => {
            // FORMAT=0：SCRV1 打包（base64 均标准带填充）
            let packed = format!(
                "SCRV1:{}:{}",
                b64.encode(password.as_bytes()),
                b64.encode(otp.as_bytes())
            );
            format!("password \"Auth\" {}", quoted(&packed))
        }
        None => format!("password \"Auth\" {}", quoted(password)),
    };
    lines.push(password_line);
    lines
}

/// 构造 `>INFOMSG:CR_TEXT:`（2.5+ crtext 流程）的 `cr-response` 命令。
pub fn cr_response_line(otp: &str) -> String {
    format!(
        "cr-response {}",
        base64::engine::general_purpose::STANDARD.encode(otp.as_bytes())
    )
}

fn decode_b64_utf8(s: &str) -> Option<String> {
    if s.is_empty() {
        return None;
    }
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s))
        .ok()?;
    String::from_utf8(raw).ok()
}

// ---------------------------------------------------------------------------
// 凭据源
// ---------------------------------------------------------------------------

/// 连接时的凭据来源：用户名/密码来自 SecretStore，OTP 按需现取。
#[async_trait]
pub trait AuthSource: Send + Sync {
    async fn username(&self) -> Result<String>;
    async fn password(&self) -> Result<String>;
    /// 取一个**当前有效**的 6 位口令（30s 时效；实现方负责缓存/重取）。
    async fn otp_response(&self) -> Result<String>;
}

// ---------------------------------------------------------------------------
// 进程与 management 循环
// ---------------------------------------------------------------------------

/// openvpn 进程与配置路径。
#[derive(Debug, Clone)]
pub struct VpnConfig {
    pub openvpn_path: PathBuf,
    pub config_path: PathBuf,
}

impl VpnConfig {
    pub fn new(config_path: impl Into<PathBuf>) -> Self {
        Self {
            openvpn_path: PathBuf::from(DEFAULT_OPENVPN_PATH),
            config_path: config_path.into(),
        }
    }
}

/// 运行中的 VPN 会话句柄：`disconnect()` 走 SIGTERM 优雅退出。
pub struct VpnHandle {
    cmd_tx: mpsc::UnboundedSender<String>,
    child: Arc<Mutex<Option<Child>>>,
}

impl VpnHandle {
    /// 请求断开（SIGTERM）；等待进程退出，超时强杀。
    pub async fn disconnect(&self) -> Result<()> {
        let _ = self.cmd_tx.send("signal SIGTERM".to_string());
        let mut guard = self.child.lock().await;
        if let Some(child) = guard.as_mut() {
            match tokio::time::timeout(Duration::from_secs(10), child.wait()).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    return Err(CoreError::Protocol(format!("等待 openvpn 退出失败: {e}")))
                }
                Err(_) => {
                    let _ = child.kill().await;
                    return Err(CoreError::Protocol(
                        "openvpn 未在 10s 内退出，已强杀".to_string(),
                    ));
                }
            }
        }
        *guard = None;
        Ok(())
    }
}

/// 拉起 openvpn 并接管 management 接口；事件经 `events` 广播。
///
/// 凭据缺失/OTP 获取失败/连续认证失败时广播 `State{name:"FAILED"}` 并终止进程。
pub async fn launch(
    cfg: &VpnConfig,
    auth: Arc<dyn AuthSource>,
    events: mpsc::UnboundedSender<VpnEvent>,
) -> Result<VpnHandle> {
    if !Path::new(&cfg.openvpn_path).exists() {
        return Err(CoreError::Protocol(format!(
            "找不到 openvpn.exe: {}（请在设置中指定社区版安装路径）",
            cfg.openvpn_path.display()
        )));
    }
    if !Path::new(&cfg.config_path).exists() {
        return Err(CoreError::Protocol(format!(
            "找不到 ovpn 配置: {}",
            cfg.config_path.display()
        )));
    }

    let port = free_mgmt_port()?;
    let mut cmd = Command::new(&cfg.openvpn_path);
    cmd.args([
        "--config",
        &cfg.config_path.to_string_lossy(),
        "--management",
        "127.0.0.1",
        &port.to_string(),
        "--management-query-passwords",
        "--management-hold",
        "--auth-retry",
        "interact",
        "--verb",
        "4",
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true);

    let mut child = cmd
        .spawn()
        .map_err(|e| CoreError::Protocol(format!("openvpn 启动失败: {e}")))?;

    // 子进程输出转发为日志事件（路由/TAP/权限错误都出现在这里）
    if let Some(stdout) = child.stdout.take() {
        let ev = events.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = ev.send(VpnEvent::Log(format!("[out] {line}")));
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        let ev = events.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = ev.send(VpnEvent::Log(format!("[err] {line}")));
            }
        });
    }

    let child = Arc::new(Mutex::new(Some(child)));
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<String>();
    let handle = VpnHandle {
        cmd_tx,
        child: child.clone(),
    };

    tokio::spawn(supervise(port, auth, events, cmd_rx, child));
    Ok(handle)
}

/// 选一个空闲的管理端口（先占后放，竞态窗口可忽略）。
fn free_mgmt_port() -> Result<u16> {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .map_err(|e| CoreError::Protocol(format!("management 端口分配失败: {e}")))
}

/// 监督任务：连 management → 握手（log/state on + hold release）→ 事件循环。
async fn supervise(
    port: u16,
    auth: Arc<dyn AuthSource>,
    events: mpsc::UnboundedSender<VpnEvent>,
    mut cmd_rx: mpsc::UnboundedReceiver<String>,
    child: Arc<Mutex<Option<Child>>>,
) {
    let _ = events.send(VpnEvent::State {
        name: "LAUNCHING".into(),
        reason: None,
    });

    let stream = match connect_mgmt(port).await {
        Ok(s) => s,
        Err(e) => {
            fail(&events, child, &e.to_string()).await;
            return;
        }
    };
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    // 握手：开启实时日志/状态通知。**不在此处释放 hold**——立即释放会与
    // openvpn 主线程进入 hold 等待产生竞态（实测 2.7.8 卡死），标准做法
    // （openvpn-gui）是收到 >HOLD 通知后再 `hold release`。
    for init in ["log on", "state on"] {
        let _ = writer.write_all(format!("{init}\n").as_bytes()).await;
    }
    let _ = writer.flush().await;

    let mut pending_dynamic: Option<DynamicChallenge> = None;
    let mut auth_failures = 0usize;
    let mut connected = false;
    // 见到首个 >STATE（RESOLVE 等）即说明 hold 已释放、连接在推进
    let mut saw_state = false;
    // 看门狗：>HOLD 通知可能在 management 客户端连上之前就发出（实测 2.7.8
    // 两种时序均出现过），收不到时按短间隔补发 hold release，直至状态推进
    let mut watchdog_fires = 0usize;
    let watchdog = tokio::time::sleep(WATCHDOG_INTERVAL);
    tokio::pin!(watchdog);

    loop {
        tokio::select! {
            line = lines.next_line() => {
                match line {
                    Ok(Some(line)) => {
                        let line = line.trim_end().to_string();
                        if line.is_empty() { continue; }
                        watchdog.as_mut().reset(tokio::time::Instant::now() + WATCHDOG_INTERVAL);
                        match parse_mgmt_line(&line) {
                            MgmtEvent::Hold => {
                                // 收到 >HOLD：此时释放才真正生效
                                let _ = writer
                                    .write_all(b"hold release\n")
                                    .await;
                                let _ = writer.flush().await;
                                let _ = events.send(VpnEvent::Notice("已应答 >HOLD，释放并启动连接".into()));
                            }
                            MgmtEvent::State { name, reason } => {
                                auth_failures = 0;
                                saw_state = true;
                                if name == "CONNECTED" {
                                    connected = true;
                                }
                                let _ = events.send(VpnEvent::State { name: name.clone(), reason });
                                if name == "EXITING" {
                                    break;
                                }
                            }
                            MgmtEvent::NeedAuth(need) => {
                                match build_auth(&auth, &need, pending_dynamic.as_ref()).await {
                                    Ok(reply) => {
                                        for cmd in reply {
                                            let _ = writer.write_all(format!("{cmd}\n").as_bytes()).await;
                                        }
                                        let _ = writer.flush().await;
                                        pending_dynamic = None;
                                    }
                                    Err(e) => {
                                        fail(&events, child, &format!("凭据准备失败: {e}")).await;
                                        break;
                                    }
                                }
                            }
                            MgmtEvent::VerificationFailed { reason, dynamic } => {
                                if let Some(d) = dynamic {
                                    pending_dynamic = Some(d);
                                }
                                auth_failures += 1;
                                let _ = events.send(VpnEvent::Notice(format!(
                                    "认证失败（第 {auth_failures}/{MAX_AUTH_FAILURES} 次）: {reason}"
                                )));
                                if auth_failures >= MAX_AUTH_FAILURES {
                                    fail(&events, child, &format!("连续 {auth_failures} 次认证失败: {reason}")).await;
                                    break;
                                }
                            }
                            MgmtEvent::Infomsg(payload) => {
                                // 2.5+ crtext：挑战到达时现取口令应答（防御性支持）
                                if payload.starts_with("CR_TEXT:") {
                                    match auth.otp_response().await {
                                        Ok(otp) => {
                                            let cmd = cr_response_line(&otp);
                                            let _ = writer.write_all(format!("{cmd}\n").as_bytes()).await;
                                            let _ = writer.flush().await;
                                        }
                                        Err(e) => {
                                            fail(&events, child, &format!("OTP 获取失败: {e}")).await;
                                            break;
                                        }
                                    }
                                } else {
                                    let _ = events.send(VpnEvent::Notice(payload));
                                }
                            }
                            MgmtEvent::Fatal(msg) => {
                                fail(&events, child, &format!("openvpn 致命错误: {msg}")).await;
                                break;
                            }
                            MgmtEvent::Log(msg) => {
                                let _ = events.send(VpnEvent::Log(msg));
                            }
                            MgmtEvent::Info(msg) => {
                                let _ = events.send(VpnEvent::Log(format!("[info] {msg}")));
                            }
                            MgmtEvent::AuthToken | MgmtEvent::Other(_) => {
                                let _ = events.send(VpnEvent::Log(line));
                            }
                        }
                    }
                    Ok(None) => {
                        // management 连接关闭 = 进程退出
                        let reason = match child.lock().await.as_mut() {
                            Some(c) => c.wait().await.ok().map(|s| format!("exit code {s}")),
                            None => Some("process gone".into()),
                        };
                        let _ = events.send(VpnEvent::State {
                            name: "EXITING".into(),
                            reason,
                        });
                        break;
                    }
                    Err(e) => {
                        fail(&events, child, &format!("management 读取失败: {e}")).await;
                        break;
                    }
                }
            }
            Some(cmd) = cmd_rx.recv() => {
                watchdog.as_mut().reset(tokio::time::Instant::now() + WATCHDOG_INTERVAL);
                if writer.write_all(format!("{cmd}\n").as_bytes()).await.is_err() {
                    break;
                }
                let _ = writer.flush().await;
            }
            _ = &mut watchdog => {
                if connected || saw_state {
                    // hold 已释放（连接推进中/已建立），静默属正常，不干预
                    watchdog.as_mut().reset(tokio::time::Instant::now() + WATCHDOG_INTERVAL);
                    continue;
                }
                watchdog_fires += 1;
                if watchdog_fires > MAX_WATCHDOG_RELEASES {
                    fail(&events, child, "连接启动超时：多次兜底释放 hold 后仍无进展").await;
                    break;
                }
                // 兜底：>HOLD 未送达（attach 前已发出），按短间隔补发直至状态推进
                let _ = writer.write_all(b"hold release\n").await;
                let _ = writer.flush().await;
                let _ = events.send(VpnEvent::Notice(format!(
                    "看门狗兜底：未见 >HOLD，第 {watchdog_fires} 次补发 hold release"
                )));
                watchdog.as_mut().reset(tokio::time::Instant::now() + WATCHDOG_INTERVAL);
            }
            else => break,
        }
    }
}

/// 连接 management 端口（openvpn 启动到开端口有短暂延迟）。
async fn connect_mgmt(port: u16) -> Result<TcpStream> {
    let addr = format!("127.0.0.1:{port}");
    let deadline = tokio::time::Instant::now() + MGMT_CONNECT_TIMEOUT;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(CoreError::Protocol(format!(
                "{MGMT_CONNECT_TIMEOUT:?} 内未能连上 management 端口 {addr}"
            )));
        }
        match TcpStream::connect(&addr).await {
            Ok(s) => return Ok(s),
            Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
}

/// 组装认证应答；含挑战时实时取新口令。
async fn build_auth(
    auth: &Arc<dyn AuthSource>,
    need: &NeedAuth,
    dynamic: Option<&DynamicChallenge>,
) -> Result<Vec<String>> {
    let username = auth.username().await?;
    let password = auth.password().await?;
    let needs_otp = dynamic.is_some() || need.static_challenge.is_some();
    let otp = if needs_otp {
        auth.otp_response().await?
    } else {
        String::new()
    };
    Ok(auth_response_lines(
        &username, &password, &otp, need, dynamic,
    ))
}

/// 广播失败并终止 openvpn 进程。
async fn fail(
    events: &mpsc::UnboundedSender<VpnEvent>,
    child: Arc<Mutex<Option<Child>>>,
    reason: &str,
) {
    let _ = events.send(VpnEvent::State {
        name: "FAILED".into(),
        reason: Some(reason.to_string()),
    });
    let mut guard = child.lock().await;
    if let Some(c) = guard.as_mut() {
        let _ = c.kill().await;
        if let Ok(status) = c.wait().await {
            let _ = events.send(VpnEvent::Log(format!("[openvpn] exited: {status}")));
        }
    }
}
