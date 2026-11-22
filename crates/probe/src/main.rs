//! SHU-VPN 联调探测 CLI。
//!
//! 子命令覆盖协议验证全链路（#4）与真实 VPN 连接（#5）：
//!
//! ```text
//! shuvpn-probe login  [--from-file <creds.json>] [--method sms|wecom]  # SSO 登录（自动发 2FA 码）
//! shuvpn-probe verify --code 123456                                    # 提交 2FA 验证码并顺带取 OTP
//! shuvpn-probe otp                                                     # 会话复用直接取 OTP（常用）
//! shuvpn-probe creds --set [--from-file <creds.json>]                  # 学号密码写入系统凭据库
//! shuvpn-probe connect [--config shu.ovpn]                             # 连接 VPN（无弹窗，Ctrl+C 断开）
//! ```
//!
//! 凭据/中间状态文件（`.probe-*`）均已 gitignore；verify 成功后立即删除
//! 含密码的 state 文件；VPN 连接的账密/OTP 经 management 接口程序化应答。
//!
//! 退出码：0 成功；2 登录失败；3 发码/验证/会话失败；6 取码失败；9 用法错误。

use std::io::Write as _;
use std::process::ExitCode;
use std::sync::Arc;

use async_trait::async_trait;
use shuvpn_core::error::{CoreError, Result as CoreResult};
use shuvpn_core::otp::{OtpClient, OtpCode};
use shuvpn_core::secrets::{OsSecretStore, SecretStore};
use shuvpn_core::session::{SessionConfig, ShuSession};
use shuvpn_core::sso::otp_login_params;
use shuvpn_core::vpn::{self, AuthSource, VpnConfig, VpnEvent, VpnHandle};
use shuvpn_core::TwoStepMethod;
use tokio::sync::Mutex;

const COOKIES_FILE: &str = ".probe-cookies.json";
const STATE_FILE: &str = ".probe-state.json";
const KEYRING_SERVICE: &str = "SHU-VPN";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    match rt.block_on(run(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

async fn run(args: Vec<String>) -> Result<(), ExitCode> {
    let cmd = args.first().map(String::as_str);
    match cmd {
        Some("login") => {
            let from_file = flag_value(&args, "--from-file");
            let method_flag = match flag_value(&args, "--method").as_deref() {
                Some("sms") => Some(TwoStepMethod::Sms),
                Some("wecom") => Some(TwoStepMethod::Wecom),
                Some(other) => {
                    return Err(usage(&format!("--method 只接受 sms|wecom，得到 {other}")))
                }
                None => None,
            };
            cmd_login(from_file.as_deref(), method_flag).await
        }
        Some("verify") => {
            let code = flag_value(&args, "--code").ok_or_else(|| usage("--code <验证码> 必填"))?;
            cmd_verify(&code).await
        }
        Some("otp") => cmd_otp().await,
        Some("creds") => cmd_creds(&args).await,
        Some("connect") => cmd_connect(flag_value(&args, "--config")).await,
        _ => {
            print_usage();
            Err(ExitCode::from(9))
        }
    }
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn usage(msg: &str) -> ExitCode {
    eprintln!("用法错误: {msg}");
    print_usage();
    ExitCode::from(9)
}

fn print_usage() {
    eprintln!(
        "用法: shuvpn-probe <login [--from-file <json>] [--method sms|wecom] | verify --code <码> | otp | creds --set [--from-file <json>] | creds --show | creds --clear | connect [--config shu.ovpn]>"
    );
}

fn new_session() -> Result<Arc<ShuSession>, ExitCode> {
    ShuSession::new(SessionConfig::default())
        .map(Arc::new)
        .map_err(|e| {
            eprintln!("✗ 会话构建失败: {e}");
            ExitCode::from(9)
        })
}

fn keyring_store() -> OsSecretStore {
    OsSecretStore::new(KEYRING_SERVICE)
}

// ---------------------------------------------------------------------------
// login
// ---------------------------------------------------------------------------

async fn cmd_login(
    from_file: Option<&str>,
    method_flag: Option<TwoStepMethod>,
) -> Result<(), ExitCode> {
    let (username, password, preferred) = read_credentials(from_file)?;
    let preferred = method_flag.or(preferred);
    let session = new_session()?;
    let params = otp_login_params();

    println!("[1/2] POST /oauth/userLogin ...");
    let resp = session
        .login(&username, &password, &params)
        .await
        .map_err(err_to_code)?;
    println!("  ✓ 认证成功（message=success）");

    if !resp.two_step_required {
        session.save_cookies(COOKIES_FILE).map_err(err_to_code)?;
        println!("[2/2] 无需两步验证，SSO 会话已建立 → {COOKIES_FILE}");
        println!("  下一步: shuvpn-probe otp");
        return Ok(());
    }

    // 选通道：显式指定（--method / 文件 method 字段）> 可用通道里的 sms
    //（用户偏好：短信比企微方便）> 服务端首个 > 默认 sms
    let method = preferred
        .filter(|m| resp.two_step_methods.contains(m))
        .or_else(|| {
            resp.two_step_methods
                .iter()
                .find(|m| **m == TwoStepMethod::Sms)
                .copied()
        })
        .or_else(|| resp.two_step_methods.first().copied())
        .unwrap_or(TwoStepMethod::Sms);
    println!(
        "[2/2] 需要两步验证，可用通道: {:?}，选用 {:?}",
        resp.two_step_methods, method
    );
    session.send_2fa(method).await.map_err(err_to_code)?;
    println!("  ✓ 验证码已发送（{:?} 通道）", method);

    // verify 需要重新提交密码（协议如此），暂存本地待 verify 消费
    let state = serde_json::json!({
        "username": username,
        "password": password,
        "params": params,
        "method": method.as_str(),
    });
    std::fs::write(STATE_FILE, state.to_string()).map_err(|e| {
        eprintln!("✗ 状态文件写入失败: {e}");
        ExitCode::from(9)
    })?;
    session.save_cookies(COOKIES_FILE).map_err(err_to_code)?;
    println!("  下一步: shuvpn-probe verify --code <验证码>");
    Ok(())
}

fn read_credentials(
    from_file: Option<&str>,
) -> Result<(String, String, Option<TwoStepMethod>), ExitCode> {
    if let Some(path) = from_file {
        let raw = std::fs::read_to_string(path).map_err(|e| {
            eprintln!("✗ 凭据文件读取失败 {path}: {e}");
            ExitCode::from(9)
        })?;
        let v: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
            eprintln!("✗ 凭据文件不是合法 JSON: {e}");
            ExitCode::from(9)
        })?;
        let username = v["username"].as_str().unwrap_or_default().to_string();
        let password = v["password"].as_str().unwrap_or_default().to_string();
        let method = match v["method"].as_str() {
            Some("sms") => Some(TwoStepMethod::Sms),
            Some("wecom") => Some(TwoStepMethod::Wecom),
            _ => None,
        };
        if username.is_empty() || password.is_empty() {
            return Err(usage("凭据文件需含 username / password"));
        }
        return Ok((username, password, method));
    }

    let username = prompt("学号/工号: ");
    // 提示语走 stdout（PS 对 stderr 按控制台代码页解码会乱码），rpassword 只静默读
    print!("密码（不回显）: ");
    let _ = std::io::stdout().flush();
    let password = rpassword::read_password().unwrap_or_default();
    if username.is_empty() || password.is_empty() {
        return Err(usage("学号与密码不能为空"));
    }
    Ok((username, password, None))
}

fn prompt(text: &str) -> String {
    print!("{text}");
    let _ = std::io::stdout().flush();
    let mut buf = String::new();
    let _ = std::io::stdin().read_line(&mut buf);
    buf.trim().to_string()
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

async fn cmd_verify(code: &str) -> Result<(), ExitCode> {
    let raw = std::fs::read_to_string(STATE_FILE).map_err(|e| {
        eprintln!("✗ 找不到 {STATE_FILE}（先运行 login 使其生成）: {e}");
        ExitCode::from(9)
    })?;
    let state: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
        eprintln!("✗ {STATE_FILE} 不是合法 JSON: {e}");
        ExitCode::from(9)
    })?;
    let username = state["username"].as_str().unwrap_or_default().to_string();
    let password = state["password"].as_str().unwrap_or_default().to_string();
    let params = state["params"].as_str().unwrap_or_default().to_string();
    let method = match state["method"].as_str() {
        Some("sms") => TwoStepMethod::Sms,
        _ => TwoStepMethod::Wecom,
    };
    if username.is_empty() || password.is_empty() {
        return Err(usage("state 文件缺 username/password，请重新 login"));
    }

    let session = new_session()?;
    session.load_cookies(COOKIES_FILE).map_err(err_to_code)?;
    println!("[1/2] POST /oauth/twoStep/verify ...");
    session
        .verify_2fa(&username, &password, &params, code, method)
        .await
        .map_err(err_to_code)?;
    println!("  ✓ 两步验证通过，SSO 会话已建立");

    // 验证成功：立即销毁含密码的中间状态
    let _ = std::fs::remove_file(STATE_FILE);
    session.save_cookies(COOKIES_FILE).map_err(err_to_code)?;

    println!("[2/2] 顺带验证 OTP 取码链路 ...");
    print_otp(&session).await
}

// ---------------------------------------------------------------------------
// otp
// ---------------------------------------------------------------------------

async fn cmd_otp() -> Result<(), ExitCode> {
    let session = load_session()?;
    print_otp(&session).await
}

fn load_session() -> Result<Arc<ShuSession>, ExitCode> {
    let session = new_session()?;
    match session.load_cookies(COOKIES_FILE) {
        Ok(true) => Ok(session),
        Ok(false) => {
            eprintln!("✗ 没有 {COOKIES_FILE}，先运行 login");
            Err(ExitCode::from(9))
        }
        Err(e) => {
            eprintln!("✗ cookie 恢复失败: {e}");
            Err(ExitCode::from(9))
        }
    }
}

async fn print_otp(session: &Arc<ShuSession>) -> Result<(), ExitCode> {
    let client = OtpClient::new(session.clone());
    println!("[*] 预热 + authorize + Callback + 取码 ...");
    let otp = match client.redeem().await {
        Ok(otp) => otp,
        Err(CoreError::SessionExpired) => {
            eprintln!("✗ SSO 会话失效（authorize 被踢回登录页）——运行 shuvpn-probe login 重新登录");
            return Err(ExitCode::from(3));
        }
        Err(e) => return Err(err_to_code(e)),
    };
    print_otp_panel(&otp);
    println!("  请与官网 https://otp.shu.edu.cn 同时刻口令人工比对。");
    Ok(())
}

fn print_otp_panel(otp: &OtpCode) {
    println!();
    println!("  ──────────────────────────────");
    println!(
        "   OTP 口令: {}   （剩余 {}s / {}s）",
        otp, otp.remaining_secs, otp.period_secs
    );
    println!(
        "   账户    : {}",
        if otp.account.is_empty() {
            "(未知)"
        } else {
            &otp.account
        }
    );
    println!("  ──────────────────────────────");
}

// ---------------------------------------------------------------------------
// creds（系统凭据库）
// ---------------------------------------------------------------------------

async fn cmd_creds(args: &[String]) -> Result<(), ExitCode> {
    let store = keyring_store();
    if has_flag(args, "--set") {
        let (username, password, _) = read_credentials(flag_value(args, "--from-file").as_deref())?;
        store.set("vpn.username", &username).map_err(err_to_code)?;
        store.set("vpn.password", &password).map_err(err_to_code)?;
        println!("  ✓ 学号与密码已写入系统凭据库（service={KEYRING_SERVICE}）");
        return Ok(());
    }
    if has_flag(args, "--show") {
        let username = store.get("vpn.username").map_err(err_to_code)?;
        let password = store.get("vpn.password").map_err(err_to_code)?;
        println!(
            "  username: {}",
            username.unwrap_or_else(|| "(未设置)".into())
        );
        println!(
            "  password: {}",
            if password.is_some() {
                "(已保存)"
            } else {
                "(未设置)"
            }
        );
        return Ok(());
    }
    if has_flag(args, "--clear") {
        store.delete("vpn.username").map_err(err_to_code)?;
        store.delete("vpn.password").map_err(err_to_code)?;
        println!("  ✓ 凭据已清除");
        return Ok(());
    }
    Err(usage("creds 需要 --set / --show / --clear 之一"))
}

// ---------------------------------------------------------------------------
// connect（真实 VPN 连接，management 接口自动应答）
// ---------------------------------------------------------------------------

/// probe 的凭据源：账密来自系统凭据库，OTP 现取并做 30s 内缓存。
struct ProbeAuth {
    username: String,
    password: String,
    session: Arc<ShuSession>,
    otp_cache: Mutex<Option<OtpCode>>,
}

#[async_trait]
impl AuthSource for ProbeAuth {
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
        println!(
            "  ✓ 取得 OTP 口令 {}（剩余 {:.0}s）",
            otp,
            otp.valid_for().max(0.0)
        );
        let code = otp.code.clone();
        *cache = Some(otp);
        Ok(code)
    }
}

async fn cmd_connect(config: Option<String>) -> Result<(), ExitCode> {
    let store = keyring_store();
    let username = store
        .get("vpn.username")
        .map_err(err_to_code)?
        .ok_or_else(|| usage("系统凭据库没有学号——先运行 creds --set"))?;
    let password = store
        .get("vpn.password")
        .map_err(err_to_code)?
        .ok_or_else(|| usage("系统凭据库没有密码——先运行 creds --set"))?;
    let session = load_session()?;

    let cfg_path = config.unwrap_or_else(|| "shu.ovpn".to_string());
    let cfg = VpnConfig::new(&cfg_path);
    let auth = Arc::new(ProbeAuth {
        username,
        password,
        session: session.clone(),
        otp_cache: Mutex::new(None),
    });

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<VpnEvent>();
    println!("[*] 启动 openvpn（{}）...", cfg.openvpn_path.display());
    let handle: VpnHandle = vpn::launch(&cfg, auth, tx).await.map_err(err_to_code)?;
    println!("  ✓ 进程已启动，接管 management 接口");

    // 连接期：同步打印事件，直到 Connected / Failed / 进程退出
    loop {
        match rx.recv().await {
            Some(VpnEvent::State { name, reason }) => match name.as_str() {
                "CONNECTED" => {
                    println!("  ✓ CONNECTED —— Initialization Sequence Completed");
                    break;
                }
                "FAILED" => {
                    eprintln!("✗ 连接失败: {}", reason.unwrap_or_default());
                    return Err(ExitCode::from(2));
                }
                other => {
                    if let Some(r) = reason {
                        println!("  [state] {other}（{r}）");
                    } else {
                        println!("  [state] {other}");
                    }
                }
            },
            Some(VpnEvent::Log(l)) => println!("  [log] {l}"),
            Some(VpnEvent::Notice(n)) => println!("  [!] {n}"),
            None => {
                eprintln!("✗ openvpn 进程提前退出");
                return Err(ExitCode::from(2));
            }
        }
    }

    // 已连接：事件转后台打印，Ctrl+C 优雅断开
    println!("  已连接。按 Ctrl+C 断开退出。");
    let drain = tokio::spawn(async move {
        while let Some(ev) = rx.recv().await {
            match ev {
                VpnEvent::State { name, reason } => {
                    if let Some(r) = reason {
                        println!("  [state] {name}（{r}）");
                    } else {
                        println!("  [state] {name}");
                    }
                }
                VpnEvent::Log(l) => println!("  [log] {l}"),
                VpnEvent::Notice(n) => println!("  [!] {n}"),
            }
        }
    });
    let _ = tokio::signal::ctrl_c().await;
    println!("[*] 断开连接 ...");
    drain.abort();
    handle.disconnect().await.map_err(err_to_code)?;
    println!("  ✓ 已断开");
    Ok(())
}

/// 把 CoreError 映射为退出码并打印（2 登录 / 3 发码·验证·会话 / 6 解析 / 其他 9）。
fn err_to_code(e: CoreError) -> ExitCode {
    let code = match &e {
        CoreError::Protocol(_) => ExitCode::from(2),
        CoreError::SessionExpired => ExitCode::from(3),
        CoreError::Parse(_) => ExitCode::from(6),
        _ => ExitCode::from(9),
    };
    eprintln!("✗ {e}");
    code
}
