//! SHU-VPN 桌面壳：tauri 命令、托盘常驻、core 事件桥接。
//!
//! 职责边界：协议与 VPN 管理都在 shuvpn-core；本层只做
//! 凭据/设置持久化（Windows 凭据管理器 + 应用数据目录 JSON）、
//! 前端命令与事件转发、托盘交互。

#![cfg_attr(mobile, tauri::mobile_entry_point)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use shuvpn_core::error::{CoreError, Result as CoreResult};
use shuvpn_core::flow::{ensure_session, CodePrompt};
use shuvpn_core::otp::{OtpClient, OtpCode};
use shuvpn_core::secrets::{OsSecretStore, SecretStore};
use shuvpn_core::session::{SessionConfig, ShuSession};
use shuvpn_core::vpn::{self, AuthSource, VpnConfig, VpnEvent, VpnHandle};
use shuvpn_core::TwoStepMethod;
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};

const KEYRING_SERVICE: &str = "SHU-VPN";
const KEY_USERNAME: &str = "vpn.username";
const KEY_PASSWORD: &str = "vpn.password";
/// 验证码弹窗等待上限。
const CODE_TIMEOUT: Duration = Duration::from_secs(180);
/// 前端据此识别「未保存凭据」并弹首次使用引导。
const NO_CREDENTIALS: &str = "NO_CREDENTIALS:尚未保存学号与密码";
/// 内嵌官方 MSI 的 SHA256（与 release.yml 的 VENDOR_MSI_SHA256 一致）。
/// 安装前校验，杜绝损坏/被替换的包交给 msiexec。
const PREREQ_MSI_SHA256: &str = "D050EFADC6CABC4E304EB810DD7FEDFC54B859D34730AB9CDCB22D61EB86AB7A";

// ---------------------------------------------------------------------------
// 设置（应用数据目录 settings.json）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Settings {
    /// 2FA 通道："sms"（默认）| "wecom"。
    two_fa_method: String,
    /// 是否校验 TLS 证书（默认开启；学校证书链异常时由用户显式关闭）。
    verify_tls: bool,
    /// openvpn.exe 自定义路径（None = 默认安装路径）。
    openvpn_path: Option<String>,
    /// 隐藏托盘图标（关窗行为随之变为直接退出，否则无法唤回窗口）。
    hide_tray: bool,
    /// 分流模式：仅校内网段走 VPN（route-nopull + 学习到的网段显式指路）。
    split_tunnel: bool,
    /// 自定义背景图文件名（存于应用数据目录，None = 默认毛玻璃）。
    wallpaper: Option<String>,
    /// 全局快捷键（连接/断开切换），None 或空串 = 不启用。
    hotkey: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            two_fa_method: "sms".into(),
            verify_tls: true,
            openvpn_path: None,
            hide_tray: false,
            split_tunnel: false,
            wallpaper: None,
            hotkey: Some("Ctrl+Alt+V".into()),
        }
    }
}

impl Settings {
    fn two_fa(&self) -> TwoStepMethod {
        match self.two_fa_method.as_str() {
            "wecom" => TwoStepMethod::Wecom,
            _ => TwoStepMethod::Sms,
        }
    }

    fn load(dir: &Path) -> Self {
        std::fs::read_to_string(dir.join("settings.json"))
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default()
    }

    fn save(&self, dir: &Path) -> Result<(), String> {
        let raw = serde_json::to_string_pretty(self).map_err(es)?;
        std::fs::write(dir.join("settings.json"), raw).map_err(es)
    }
}

// ---------------------------------------------------------------------------
// 应用状态与事件
// ---------------------------------------------------------------------------

struct AppState {
    /// 运行中的 openvpn 句柄（None = 未连接）。
    handle: AsyncMutex<Option<VpnHandle>>,
    /// 前端可见状态：idle | connecting | connected | failed。
    status: Mutex<String>,
    /// 等待中的 2FA 验证码回传通道（前端 submit_2fa_code 填充）。
    code_pending: Arc<AsyncMutex<Option<oneshot::Sender<String>>>>,
    /// 连接取消标志：SSO/2FA 阶段（handle 尚为 None）请求断开时置位，
    /// connect_inner 检查点据此中断流程（见 issue #9 卡死修复）。
    cancel_connect: Arc<std::sync::atomic::AtomicBool>,
}

/// 转发给前端的统一事件（`vpn-event`，tag=kind）。
#[derive(Serialize, Clone)]
#[serde(tag = "kind", rename_all = "camelCase")]
enum UiEvent {
    State {
        name: String,
        reason: Option<String>,
    },
    Log {
        line: String,
    },
    Notice {
        text: String,
    },
    Progress {
        text: String,
    },
}

fn emit(app: &AppHandle, ev: UiEvent) {
    let _ = app.emit("vpn-event", ev);
}

fn es<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

fn data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_local_data_dir().map_err(es)?;
    std::fs::create_dir_all(&dir).map_err(es)?;
    Ok(dir)
}

// ---------------------------------------------------------------------------
// core 适配层：UI 验证码回调 + 连接凭据源
// ---------------------------------------------------------------------------

/// 把前端验证码弹窗桥接为 core 的 [`CodePrompt`]。
struct UiCodePrompt {
    app: AppHandle,
    pending: Arc<AsyncMutex<Option<oneshot::Sender<String>>>>,
}

#[async_trait]
impl CodePrompt for UiCodePrompt {
    async fn prompt(&self, method: TwoStepMethod) -> CoreResult<String> {
        let (tx, rx) = oneshot::channel();
        *self.pending.lock().await = Some(tx);
        let channel = match method {
            TwoStepMethod::Sms => "手机短信",
            TwoStepMethod::Wecom => "企业微信",
        };
        emit(
            &self.app,
            UiEvent::Notice {
                text: format!("需要两步验证，验证码已通过{channel}发送"),
            },
        );
        let _ = self.app.emit(
            "2fa-required",
            serde_json::json!({ "method": method.as_str() }),
        );
        match tokio::time::timeout(CODE_TIMEOUT, rx).await {
            Ok(Ok(code)) => Ok(code),
            _ => {
                // 超时/取消：清掉残留 sender，下次重新弹窗
                *self.pending.lock().await = None;
                Err(CoreError::Protocol("验证码输入超时或已取消".into()))
            }
        }
    }
}

/// 连接凭据源：账密来自凭据管理器，OTP 现取并做 30s 内缓存。
struct GuiAuth {
    app: AppHandle,
    username: String,
    password: String,
    session: Arc<ShuSession>,
    otp_cache: AsyncMutex<Option<OtpCode>>,
}

#[async_trait]
impl AuthSource for GuiAuth {
    async fn username(&self) -> CoreResult<String> {
        Ok(self.username.clone())
    }

    async fn password(&self) -> CoreResult<String> {
        Ok(self.password.clone())
    }

    async fn otp_response(&self) -> CoreResult<String> {
        let mut cache = self.otp_cache.lock().await;
        if let Some(otp) = cache.as_ref() {
            if otp.valid_for() > 5.0 {
                return Ok(otp.code.clone());
            }
        }
        let otp = OtpClient::new(self.session.clone()).redeem().await?;
        emit(
            &self.app,
            UiEvent::Progress {
                text: format!(
                    "✓ 取得 OTP 口令 {}（剩余 {:.0}s）",
                    otp,
                    otp.valid_for().max(0.0)
                ),
            },
        );
        let code = otp.code.clone();
        *cache = Some(otp);
        Ok(code)
    }
}

// ---------------------------------------------------------------------------
// 连接 / 断开
// ---------------------------------------------------------------------------

async fn do_connect(app: AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    if state.handle.lock().await.is_some() {
        return Err("已有连接进行中".into());
    }
    {
        let mut status = state.status.lock().unwrap();
        if *status == "connecting" {
            return Err("正在连接中，请稍候".into());
        }
        *status = "connecting".into();
    }
    state
        .cancel_connect
        .store(false, std::sync::atomic::Ordering::Relaxed);
    update_tray(&app, "connecting");
    // 托盘/快捷键发起的连接前端无从感知：显式广播，让主窗口状态环立即进入动画
    emit(
        &app,
        UiEvent::State {
            name: "CONNECTING".into(),
            reason: None,
        },
    );

    match connect_inner(&app).await {
        Ok(()) => Ok(()),
        Err(msg) => {
            let cancelled = msg.contains("取消");
            let final_status = if cancelled { "idle" } else { "failed" };
            *app.state::<AppState>().status.lock().unwrap() = final_status.into();
            update_tray(&app, final_status);
            emit(
                &app,
                UiEvent::Notice {
                    text: format!("✗ {msg}"),
                },
            );
            Err(msg)
        }
    }
}

async fn connect_inner(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    let cancelled = || {
        state
            .cancel_connect
            .load(std::sync::atomic::Ordering::Relaxed)
    };
    if cancelled() {
        return Err("连接已取消".into());
    }
    let dir = data_dir(app)?;
    let settings = Settings::load(&dir);

    // ① 凭据
    let store = OsSecretStore::new(KEYRING_SERVICE);
    let username = store
        .get(KEY_USERNAME)
        .map_err(es)?
        .ok_or_else(|| NO_CREDENTIALS.to_string())?;
    let password = store
        .get(KEY_PASSWORD)
        .map_err(es)?
        .ok_or_else(|| NO_CREDENTIALS.to_string())?;

    // ② SSO 会话（含 2FA 交互，验证码弹窗经 UiCodePrompt）
    emit(
        app,
        UiEvent::Progress {
            text: "正在建立 SSO 会话…".into(),
        },
    );
    let session = Arc::new(
        ShuSession::new(SessionConfig {
            verify_tls: settings.verify_tls,
            ..Default::default()
        })
        .map_err(es)?,
    );
    let _ = session.load_cookies(dir.join("cookies.json"));
    let prompt = UiCodePrompt {
        app: app.clone(),
        pending: state.code_pending.clone(),
    };
    ensure_session(&session, &username, &password, settings.two_fa(), &prompt)
        .await
        .map_err(es)?;
    if cancelled() {
        return Err("连接已取消".into());
    }
    session.save_cookies(dir.join("cookies.json")).map_err(es)?;
    emit(
        app,
        UiEvent::Progress {
            text: "SSO 会话就绪，启动 openvpn…".into(),
        },
    );

    // ③ 内置学校公开配置写入数据目录（每次覆盖保持最新）
    let ovpn_path = dir.join("shu.ovpn");
    std::fs::write(&ovpn_path, vpn::EMBEDDED_SHU_OVPN).map_err(es)?;

    let mut cfg = VpnConfig::new(&ovpn_path);
    if let Some(custom) = settings.openvpn_path.as_deref().filter(|s| !s.is_empty()) {
        cfg.openvpn_path = PathBuf::from(custom);
    }
    if settings.split_tunnel {
        // 分流模式：忽略服务器推送路由，用学习到的校内网段显式指路。
        // 没学过网段（从未全局连接成功过）则拒绝，避免空分流。
        let routes = load_learned_routes(&dir);
        if routes.is_empty() {
            return Err(
                "分流模式需要先正常（全局）连接一次以学习校内网段，请关闭分流后连接一次".into(),
            );
        }
        cfg.route_nopull = true;
        cfg.extra_routes = routes.into_iter().map(|r| (r.net, r.mask)).collect();
        emit(
            app,
            UiEvent::Progress {
                text: "分流模式：仅校内网段走 VPN，其余流量直连".into(),
            },
        );
    }

    // ④ 拉起 openvpn 并转发事件
    let auth = Arc::new(GuiAuth {
        app: app.clone(),
        username,
        password,
        session: session.clone(),
        otp_cache: AsyncMutex::new(None),
    });
    let (tx, rx) = mpsc::unbounded_channel::<VpnEvent>();
    if cancelled() {
        return Err("连接已取消".into());
    }
    let handle = vpn::launch(&cfg, auth, tx).await.map_err(es)?;
    *state.handle.lock().await = Some(handle);
    spawn_forwarder(app.clone(), rx);
    // 取消竞态兜底：断开请求落在最后一个检查点之后时，回收刚拉起的进程
    if cancelled() {
        if let Some(h) = state.handle.lock().await.take() {
            let _ = h.disconnect().await;
        }
        return Err("连接已取消".into());
    }
    Ok(())
}

async fn do_disconnect(app: AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    let handle = state.handle.lock().await.take();
    match handle {
        Some(h) => {
            emit(
                &app,
                UiEvent::Progress {
                    text: "正在断开…".into(),
                },
            );
            h.disconnect().await.map_err(es)
        }
        None => {
            // openvpn 尚未拉起（SSO/2FA 阶段）：中断连接流程本身。
            // drop 等待中的验证码 sender 让 UiCodePrompt 立即失败，流程快速终止；
            // connect_inner 的取消检查点随后收尾（含刚拉起进程的兜底回收）。
            let connecting = *state.status.lock().unwrap() == "connecting";
            if connecting {
                state
                    .cancel_connect
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                *state.code_pending.lock().await = None;
                *state.status.lock().unwrap() = "idle".into();
                update_tray(&app, "idle");
                // 托盘/快捷键发起的中断也要复位主窗口状态（EXITING → idle）
                emit(
                    &app,
                    UiEvent::State {
                        name: "EXITING".into(),
                        reason: Some("已中断连接流程".into()),
                    },
                );
                Ok(())
            } else {
                Err("当前没有进行中的连接".into())
            }
        }
    }
}

/// core `VpnEvent` → 前端 `vpn-event`；通道关闭（进程退出）时清理句柄。
fn spawn_forwarder(app: AppHandle, mut rx: mpsc::UnboundedReceiver<VpnEvent>) {
    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();
        // 本次连接学到的校内网段（PUSH_REPLY）；CONNECTED 时落盘为分流模式缓存
        let mut learned: std::collections::BTreeSet<(String, String)> = Default::default();
        loop {
            match rx.recv().await {
                Some(VpnEvent::State { name, reason }) => {
                    let next = match name.as_str() {
                        "CONNECTED" => "connected",
                        "FAILED" => "failed",
                        "EXITING" => "idle",
                        _ => "connecting",
                    };
                    *state.status.lock().unwrap() = next.to_string();
                    update_tray(&app, next);
                    if name == "CONNECTED" && !learned.is_empty() {
                        // 全局连接成功：用本次学习结果覆盖网段缓存（学校改网段时自动跟进）
                        let routes: Vec<LearnedRoute> = learned
                            .iter()
                            .map(|(net, mask)| LearnedRoute {
                                net: net.clone(),
                                mask: mask.clone(),
                            })
                            .collect();
                        if let Ok(dir) = app.path().app_local_data_dir() {
                            if let Ok(json) = serde_json::to_vec_pretty(&routes) {
                                let _ = std::fs::write(routes_path(&dir), json);
                                emit(
                                    &app,
                                    UiEvent::Notice {
                                        text: format!(
                                            "已学习 {} 个校内网段（分流模式可用）",
                                            routes.len()
                                        ),
                                    },
                                );
                            }
                        }
                    }
                    emit(&app, UiEvent::State { name, reason });
                }
                Some(VpnEvent::RoutePushed { net, mask }) => {
                    learned.insert((net, mask));
                }
                Some(VpnEvent::Log(line)) => emit(&app, UiEvent::Log { line }),
                Some(VpnEvent::Notice(text)) => emit(&app, UiEvent::Notice { text }),
                None => break,
            }
        }
        *state.handle.lock().await = None;
        let mut status = state.status.lock().unwrap();
        if *status == "connecting" {
            *status = "failed".into();
        }
        drop(status);
        emit(
            &app,
            UiEvent::Notice {
                text: "openvpn 进程已退出".into(),
            },
        );
    });
}

/// 内置前置依赖 MSI（NSIS resources；release.yml 从官方 swupdate 取件）。
/// 兼容多种 resources 落盘布局（保持相对路径 / 平铺 / exe 同级）。
fn find_prereq_msi(app: &AppHandle) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(dir) = app.path().resource_dir() {
        candidates.push(dir.join("resources").join("openvpn-prereq.msi"));
        candidates.push(dir.join("openvpn-prereq.msi"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("resources").join("openvpn-prereq.msi"));
            candidates.push(dir.join("openvpn-prereq.msi"));
        }
    }
    candidates.into_iter().find(|p| p.exists())
}

/// 去掉 Windows verbatim 前缀（`\\?\` / `\\?\UNC\`）。msiexec 不认这类路径
/// （实测返回 1619 ERROR_INSTALL_PACKAGE_OPEN_FAILED，与文件本身无关）。
fn plain_path(p: &Path) -> PathBuf {
    let s = p.as_os_str().to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        PathBuf::from(rest.to_string())
    } else {
        p.to_path_buf()
    }
}

/// 计算文件 SHA256（大写 hex）。
async fn sha256_file(path: &Path) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let bytes = tokio::fs::read(path).await.map_err(es)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect())
}

// ---------------------------------------------------------------------------
// tauri 命令
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusInfo {
    status: String,
    has_credentials: bool,
    username: Option<String>,
    settings: Settings,
    openvpn_path: String,
    openvpn_found: bool,
    /// 安装包内置了 OpenVPN MSI（可一键安装前置依赖）。
    msi_available: bool,
    /// 已学习的校内网段数（分流模式可用性提示）。
    routes_learned: usize,
}

/// 分流模式网段缓存（连接时从 PUSH_REPLY 学习，见 VpnEvent::RoutePushed）。
fn routes_path(dir: &Path) -> PathBuf {
    dir.join("routes.json")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LearnedRoute {
    net: String,
    mask: String,
}

fn load_learned_routes(dir: &Path) -> Vec<LearnedRoute> {
    std::fs::read(routes_path(dir))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

#[tauri::command]
fn get_status(app: AppHandle) -> StatusInfo {
    let dir = app
        .path()
        .app_local_data_dir()
        .unwrap_or_else(|_| PathBuf::from("."));
    let settings = Settings::load(&dir);
    let store = OsSecretStore::new(KEYRING_SERVICE);
    let username = store.get(KEY_USERNAME).ok().flatten();
    let has_credentials = username.is_some() && store.get(KEY_PASSWORD).ok().flatten().is_some();
    let openvpn_path = settings
        .openvpn_path
        .clone()
        .unwrap_or_else(|| vpn::DEFAULT_OPENVPN_PATH.to_string());
    let openvpn_found = Path::new(&openvpn_path).exists();
    let msi_available = find_prereq_msi(&app).is_some();
    let routes_learned = load_learned_routes(&dir).len();
    let status = app.state::<AppState>().status.lock().unwrap().clone();
    StatusInfo {
        status,
        has_credentials,
        username,
        settings,
        openvpn_path,
        openvpn_found,
        msi_available,
        routes_learned,
    }
}

#[tauri::command]
async fn connect(app: AppHandle) -> Result<(), String> {
    do_connect(app).await
}

#[tauri::command]
async fn disconnect(app: AppHandle) -> Result<(), String> {
    do_disconnect(app).await
}

#[tauri::command]
async fn submit_2fa_code(state: State<'_, AppState>, code: String) -> Result<(), String> {
    let sender = state.code_pending.lock().await.take();
    match sender {
        Some(tx) => tx.send(code).map_err(|_| "验证码请求已失效".to_string()),
        None => Err("当前没有等待验证码的请求".into()),
    }
}

#[tauri::command]
async fn cancel_2fa_code(state: State<'_, AppState>) -> Result<(), String> {
    // 直接丢弃 sender：UiCodePrompt 立即收到失败
    *state.code_pending.lock().await = None;
    Ok(())
}

#[tauri::command]
fn save_credentials(username: String, password: String) -> Result<(), String> {
    if username.trim().is_empty() || password.is_empty() {
        return Err("学号与密码不能为空".into());
    }
    let store = OsSecretStore::new(KEYRING_SERVICE);
    store.set(KEY_USERNAME, username.trim()).map_err(es)?;
    store.set(KEY_PASSWORD, &password).map_err(es)?;
    Ok(())
}

#[tauri::command]
fn clear_credentials() -> Result<(), String> {
    let store = OsSecretStore::new(KEYRING_SERVICE);
    store.delete(KEY_USERNAME).map_err(es)?;
    store.delete(KEY_PASSWORD).map_err(es)?;
    Ok(())
}

#[tauri::command]
async fn save_settings(app: AppHandle, settings: Settings) -> Result<(), String> {
    if !["sms", "wecom"].contains(&settings.two_fa_method.as_str()) {
        return Err("two_fa_method 仅支持 sms | wecom".into());
    }
    let dir = data_dir(&app)?;
    let current = Settings::load(&dir);
    let hide_tray_changed = current.hide_tray != settings.hide_tray;
    let hotkey_changed = current.hotkey != settings.hotkey;
    // 先验证并应用快捷键（格式非法直接报错，settings 不落盘，前端回读放弃）
    if hotkey_changed {
        apply_hotkey(&app, &settings.hotkey)?;
    }
    settings.save(&dir)?;
    if hide_tray_changed {
        // 托盘隐藏时关窗行为变为直接退出（否则窗口藏起后无法唤回）
        apply_tray_visibility(&app, settings.hide_tray);
    }
    Ok(())
}

#[tauri::command]
fn open_url(url: String) -> Result<(), String> {
    // 只放行 http(s)；经 explorer 打开默认浏览器（无 shell 解析，URL 里的 & 安全）
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err("仅支持 http(s) 链接".into());
    }
    std::process::Command::new("explorer")
        .arg(url)
        .spawn()
        .map_err(es)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 开机自启（计划任务方案）
// ---------------------------------------------------------------------------
// 本应用是 requireAdministrator 提权程序：HKCU Run 注册表键对提权程序无效
// （登录时被 UAC 静默拦截）。正确做法是注册「以最高权限运行」的登录触发
// 计划任务——登录时静默启动、不弹 UAC。状态以系统计划任务为唯一事实源，
// 不落 settings.json，避免与系统状态不同步。

const AUTOSTART_TASK: &str = "SHU-VPN";

// schtasks.exe 是控制台程序，调用时同样必须抑制窗口（否则每次开关设置弹黑框）
#[cfg(target_os = "windows")]
fn hide_console(cmd: &mut tokio::process::Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.as_std_mut().creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(target_os = "windows"))]
fn hide_console(_cmd: &mut tokio::process::Command) {}

async fn run_schtasks(args: &[&str]) -> Result<std::process::Output, String> {
    let mut cmd = tokio::process::Command::new("schtasks");
    hide_console(&mut cmd);
    cmd.args(args).output().await.map_err(es)
}

#[tauri::command]
async fn get_autostart() -> Result<bool, String> {
    // 任务存在 → 退出码 0；不存在 → 非 0（输出为本地化编码，不用内容判定）
    Ok(run_schtasks(&["/query", "/tn", AUTOSTART_TASK])
        .await?
        .status
        .success())
}

/// 自启任务动作携带的参数：登录启动时窗口保持隐藏（静默驻留托盘）。
pub const AUTOSTART_ARG: &str = "--hidden";

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// schtasks /query /xml 的输出是 UTF-16LE（带 BOM）；无 BOM 时按 UTF-8 兜底。
fn decode_task_xml(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let units: Vec<u16> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

/// 生成开机自启的计划任务 XML。
///
/// 关键点（都是 schtasks CLI 拼参做不到/会踩坑的）：
/// - Command 用裸路径（XML 字段精确匹配，无需引号），Arguments 独立字段带
///   `--hidden`（登录启动静默驻留托盘）
/// - ExecutionTimeLimit=PT0S：默认 72h 时限会把挂后台的进程杀掉
/// - 电池两项 false：笔记本电池登录也自启、切电池不中断
fn autostart_task_xml(exe: &std::path::Path) -> Vec<u8> {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Triggers>
    <LogonTrigger>
      <StartBoundary>2025-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>{}</Command>
      <Arguments>{}</Arguments>
    </Exec>
  </Actions>
</Task>
"#,
        xml_escape(&exe.to_string_lossy()),
        AUTOSTART_ARG,
    );
    // schtasks /xml 要求 UTF-16（带 BOM）
    let mut bytes: Vec<u8> = Vec::with_capacity(xml.len() * 2 + 2);
    bytes.extend_from_slice(&0xFEFF_u16.to_le_bytes());
    for unit in xml.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

#[tauri::command]
async fn set_autostart(enable: bool) -> Result<(), String> {
    if enable {
        // 用任务 XML 注册而非 /tr 拼接（见 autostart_task_xml 注释）
        let exe = std::env::current_exe().map_err(es)?;
        let xml_path = std::env::temp_dir().join("shu-vpn-autostart.xml");
        std::fs::write(&xml_path, autostart_task_xml(&exe)).map_err(es)?;
        let out = run_schtasks(&[
            "/create",
            "/tn",
            AUTOSTART_TASK,
            "/xml",
            &xml_path.to_string_lossy(),
            "/f",
        ])
        .await?;
        let _ = std::fs::remove_file(&xml_path);
        if !out.status.success() {
            return Err(format!(
                "注册开机自启失败（schtasks 退出码 {:?}）。开发模式（非管理员）下此功能不可用",
                out.status.code()
            ));
        }
        // 注册后回读校验关键字段（schtasks 对无效 XML 可能静默降级，不校验留坑）
        let verify = run_schtasks(&["/query", "/tn", AUTOSTART_TASK, "/xml"]).await?;
        let text = decode_task_xml(&verify.stdout);
        let exe_str = exe.to_string_lossy().to_string();
        let sane = text.contains(&exe_str)
            && text.contains(AUTOSTART_ARG)
            && text.contains("PT0S")
            && text.contains("HighestAvailable")
            && text.contains("DisallowStartIfOnBatteries>false");
        if !sane {
            return Err("自启任务注册异常（关键参数缺失），请重试或反馈日志".into());
        }
    } else {
        // 先查询：任务本就不存在时直接视为成功（schtasks 输出是本地化编码，无法按内容判重）
        if !run_schtasks(&["/query", "/tn", AUTOSTART_TASK])
            .await?
            .status
            .success()
        {
            return Ok(());
        }
        let out = run_schtasks(&["/delete", "/tn", AUTOSTART_TASK, "/f"]).await?;
        if !out.status.success() {
            return Err(format!(
                "取消开机自启失败（schtasks 退出码 {:?}）",
                out.status.code()
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 自定义背景图（存应用数据目录 wallpaper.img，前端以 data URL 应用）
// ---------------------------------------------------------------------------

const WALLPAPER_MAX: usize = 10 * 1024 * 1024;

/// 按魔数识别图片格式（不信任扩展名与前端 mime 声明）。
fn detect_image_mime(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G']) {
        Some("image/png")
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else if bytes.starts_with(b"GIF8") {
        Some("image/gif")
    } else {
        None
    }
}

#[tauri::command]
async fn set_wallpaper(app: AppHandle, data: String) -> Result<(), String> {
    // 前端传 data URL（data:image/png;base64,xxx）；兼容只传 base64 部分的情况
    let b64 = data.rsplit(',').next().unwrap_or(&data);
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(es)?;
    if bytes.len() > WALLPAPER_MAX {
        return Err("图片过大（上限 10MB）".into());
    }
    detect_image_mime(&bytes).ok_or("仅支持 PNG / JPEG / WebP / GIF 图片")?;
    let dir = data_dir(&app)?;
    tokio::fs::write(dir.join("wallpaper.img"), &bytes)
        .await
        .map_err(es)?;
    let mut settings = Settings::load(&dir);
    settings.wallpaper = Some("wallpaper.img".into());
    settings.save(&dir)
}

#[tauri::command]
async fn get_wallpaper(app: AppHandle) -> Result<Option<String>, String> {
    let dir = data_dir(&app)?;
    let settings = Settings::load(&dir);
    let Some(name) = settings.wallpaper else {
        return Ok(None);
    };
    let path = dir.join(&name);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = tokio::fs::read(path).await.map_err(es)?;
    let mime = detect_image_mime(&bytes).ok_or("背景图格式异常，请重新设置")?;
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    Ok(Some(format!("data:{mime};base64,{b64}")))
}

#[tauri::command]
async fn clear_wallpaper(app: AppHandle) -> Result<(), String> {
    let dir = data_dir(&app)?;
    let mut settings = Settings::load(&dir);
    if let Some(name) = settings.wallpaper.take() {
        let _ = tokio::fs::remove_file(dir.join(name)).await;
    }
    settings.save(&dir)
}

/// 静默安装内置的官方 OpenVPN MSI（前置依赖，约 30-60s）。
/// 要求当前进程有管理员权限（release 构建为 requireAdministrator）。
#[tauri::command]
async fn install_openvpn(app: AppHandle) -> Result<(), String> {
    let embedded = find_prereq_msi(&app)
        .ok_or_else(|| "安装包里没有内置 OpenVPN 安装包，请从官方下载安装".to_string())?;

    // ① 完整性校验：损坏/被替换的包直接拒绝，不交给 msiexec
    let digest = sha256_file(&embedded).await?;
    if !digest.eq_ignore_ascii_case(PREREQ_MSI_SHA256) {
        return Err(
            "内嵌 OpenVPN 安装包校验失败（SHA256 不匹配），请重新安装 SHU-VPN 或手动安装官方 OpenVPN"
                .into(),
        );
    }

    // ② 复制到应用数据目录再安装：规避 Program Files 下资源目录的 ACL/锁定边角，
    //    并统一为非 verbatim 路径（msiexec 不认 \\?\ 前缀，实测 1619）
    let dir = data_dir(&app)?;
    let local = dir.join("openvpn-prereq.msi");
    tokio::fs::copy(&embedded, &local).await.map_err(es)?;

    emit(
        &app,
        UiEvent::Progress {
            text: "正在静默安装官方 OpenVPN（约 30-60 秒）…".into(),
        },
    );
    // ③ 全量日志落盘：任何失败都可凭日志定位（%LOCALAPPDATA%\com.zmdld11.shuvpn\）
    let log = dir.join("msiexec-verbose.log");
    let output = tokio::process::Command::new("msiexec")
        .arg("/i")
        .arg(plain_path(&local))
        .args(["/qn", "/norestart"])
        .arg("/L*v")
        .arg(plain_path(&log))
        .output()
        .await
        .map_err(es)?;
    let code = output.status.code().unwrap_or(-1);
    let openvpn_ready = Path::new(vpn::DEFAULT_OPENVPN_PATH).exists();
    // 0 = 成功；3010 = 成功但建议重启；1638 = 本机已有其他版本（复用已装版本即可）
    let ok = code == 0 || code == 3010 || (code == 1638 && openvpn_ready);
    if !ok {
        return Err(format!(
            "OpenVPN 静默安装失败（msiexec 退出码 {code}），详细日志: {}",
            log.display()
        ));
    }
    if !openvpn_ready {
        return Err("OpenVPN 安装完成但未检测到 openvpn.exe，请在设置中指定路径".into());
    }
    let _ = tokio::fs::remove_file(&local).await;
    emit(
        &app,
        UiEvent::Progress {
            text: "✓ 官方 OpenVPN 已安装".into(),
        },
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 托盘与入口
// ---------------------------------------------------------------------------

fn show_main_window(app: &AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
    }
}

// ---------------------------------------------------------------------------
// 托盘：动态图标（随状态变色）+ 菜单互斥 + 可隐藏
// ---------------------------------------------------------------------------

const TRAY_ID: &str = "main-tray";

struct TrayItems {
    connect: tauri::menu::MenuItem<tauri::Wry>,
    disconnect: tauri::menu::MenuItem<tauri::Wry>,
}

fn tray_status_text(status: &str) -> &str {
    match status {
        "connecting" => "连接中…",
        "connected" => "已连接",
        "failed" => "连接失败",
        _ => "未连接",
    }
}

/// 代码绘制托盘图标（32×32 RGBA 圆环，与主界面状态环同款配色）：
/// idle 灰环 / connecting 黄环 / connected 绿环 + 中心点 / failed 红环。
fn draw_tray_icon(status: &str) -> tauri::image::Image<'static> {
    const S: usize = 32;
    let (r, g, b) = match status {
        "connected" => (0x34u8, 0xc7, 0x7b),
        "connecting" => (0xf0, 0xb4, 0x29),
        "failed" => (0xff, 0x7b, 0x72),
        _ => (0x9a, 0xa7, 0xbf),
    };
    let mut buf = vec![0u8; S * S * 4];
    let cx = (S as f32 - 1.0) / 2.0;
    for y in 0..S {
        for x in 0..S {
            let dx = x as f32 - cx;
            let dy = y as f32 - cx;
            let d = (dx * dx + dy * dy).sqrt();
            let idx = (y * S + x) * 4;
            let mut alpha = 0.0f32;
            // 粗圆环（半径 7-14，宽 7px），边缘 1px 线性抗锯齿
            if (7.0..=14.0).contains(&d) {
                alpha = 1.0 - (d - 7.0).abs().min((d - 14.0).abs()).clamp(0.0, 1.0);
            }
            // connected 加中心实心点（同样 1px 抗锯齿）
            if status == "connected" && d <= 9.0 {
                alpha = alpha.max(1.0 - (9.0 - d).clamp(0.0, 1.0));
            }
            if alpha > 0.0 {
                let a = (alpha * 255.0) as u8;
                let prev = buf[idx + 3];
                // 混合（中心点与环重叠处取较实者）
                buf[idx] = r;
                buf[idx + 1] = g;
                buf[idx + 2] = b;
                buf[idx + 3] = a.max(prev);
            }
        }
    }
    tauri::image::Image::new_owned(buf, S as u32, S as u32)
}

/// 按状态更新托盘：图标、tooltip、菜单连接/断开互斥。
/// 托盘被用户隐藏时静默跳过（图标不存在）。
fn update_tray(app: &AppHandle, status: &str) {
    let text = tray_status_text(status);
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_icon(Some(draw_tray_icon(status)));
        let _ = tray.set_tooltip(Some(format!("SHU-VPN · {text}")));
    }
    let items = app.state::<TrayItems>();
    let connected = matches!(status, "connected" | "connecting");
    let _ = items.connect.set_enabled(!connected);
    let _ = items.disconnect.set_enabled(connected);
}

/// 按设置应用托盘可见性（设置切换与启动时各调用一次）。
fn apply_tray_visibility(app: &AppHandle, hide: bool) {
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_visible(!hide);
    }
}

// ---------------------------------------------------------------------------
// 全局快捷键（连接/断开切换）
// ---------------------------------------------------------------------------

/// 按当前状态切换连接：未连接/失败 → 连接；连接中/已连接 → 断开。
async fn toggle_connect(app: AppHandle) {
    let status = app.state::<AppState>().status.lock().unwrap().clone();
    let res = match status.as_str() {
        "connected" | "connecting" => do_disconnect(app.clone()).await,
        _ => do_connect(app.clone()).await,
    };
    if let Err(e) = res {
        emit(
            &app,
            UiEvent::Notice {
                text: format!("快捷键操作: {e}"),
            },
        );
    }
}

/// 按 settings.hotkey 注册全局快捷键（启动与设置变更时调用）。
/// None/空串 = 清除注册；格式非法返回 Err（前端回读放弃）。
fn apply_hotkey(app: &AppHandle, hotkey: &Option<String>) -> Result<(), String> {
    use tauri_plugin_global_shortcut::{GlobalShortcutExt, Shortcut};
    let gs = app.global_shortcut();
    let _ = gs.unregister_all();
    if let Some(hk) = hotkey.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        let shortcut: Shortcut = hk
            .parse()
            .map_err(|_| format!("快捷键格式无效: {hk}（示例 Ctrl+Alt+V）"))?;
        gs.on_shortcut(shortcut, |app, _shortcut, event| {
            if event.state() == tauri_plugin_global_shortcut::ShortcutState::Pressed {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    toggle_connect(app).await;
                });
            }
        })
        .map_err(es)?;
    }
    Ok(())
}

fn setup_tray(app: &AppHandle) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::TrayIconBuilder;

    let show = MenuItem::with_id(app, "show", "显示主窗口", true, None::<&str>)?;
    let connect = MenuItem::with_id(app, "connect", "连接 VPN", true, None::<&str>)?;
    let disconnect = MenuItem::with_id(app, "disconnect", "断开", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &connect, &disconnect, &quit])?;

    app.manage(TrayItems {
        connect: connect.clone(),
        disconnect: disconnect.clone(),
    });

    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .tooltip("SHU-VPN")
        .menu(&menu);
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder
        .on_menu_event(|app, event| match event.id().as_ref() {
            "show" => show_main_window(app),
            "connect" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = do_connect(app).await;
                });
            }
            "disconnect" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = do_disconnect(app).await;
                });
            }
            "quit" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    // 先优雅断开（SIGTERM + 超时强杀），再退出
                    let _ = do_disconnect(app.clone()).await;
                    app.exit(0);
                });
            }
            _ => {}
        })
        .build(app)?;
    update_tray(app, "idle");
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState {
            handle: AsyncMutex::new(None),
            status: Mutex::new("idle".into()),
            code_pending: Arc::new(AsyncMutex::new(None)),
            cancel_connect: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            get_status,
            connect,
            disconnect,
            submit_2fa_code,
            cancel_2fa_code,
            save_credentials,
            clear_credentials,
            save_settings,
            open_url,
            install_openvpn,
            get_autostart,
            set_autostart,
            set_wallpaper,
            get_wallpaper,
            clear_wallpaper,
        ])
        .setup(|app| {
            setup_tray(app.handle())?;
            let handle = app.handle();
            let dir_settings = match data_dir(handle) {
                Ok(dir) => Some((dir.clone(), Settings::load(&dir))),
                Err(_) => None,
            };
            if let Some((_, settings)) = &dir_settings {
                apply_tray_visibility(handle, settings.hide_tray);
                // 快捷键注册失败不阻断启动（可能与其他软件冲突），仅输出诊断
                if let Err(e) = apply_hotkey(handle, &settings.hotkey) {
                    eprintln!("[shu-vpn] 全局快捷键注册失败: {e}");
                }
            }
            // 窗口配置 visible:false（消灭启动闪窗），显示时机在此决定：
            // 自启任务带 --hidden 静默驻留托盘；普通启动照常显示
            if !std::env::args().any(|a| a == AUTOSTART_ARG) {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // 托盘可见：关窗 = 最小化到托盘（保持连接与通知），退出走托盘菜单；
            // 托盘被隐藏：关窗 = 直接退出（窗口藏起后没有入口可唤回）
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let app = window.app_handle();
                let hide_tray = match data_dir(app) {
                    Ok(dir) => Settings::load(&dir).hide_tray,
                    Err(_) => false,
                };
                if hide_tray {
                    let app = app.clone();
                    tauri::async_runtime::spawn(async move {
                        let _ = do_disconnect(app.clone()).await;
                        app.exit(0);
                    });
                } else {
                    let _ = window.hide();
                    api.prevent_close();
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("failed to run SHU-VPN");
}
