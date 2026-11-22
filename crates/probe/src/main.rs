//! SHU-VPN 联调探测 CLI（Issue #4）。
//!
//! 三个子命令，配合完成「SSO 登录 → 2FA → OTP 取码」的真实环境验证：
//!
//! ```text
//! shuvpn-probe login  [--from-file <creds.json>]   # SSO 登录（需要时自动发 2FA 码）
//! shuvpn-probe verify --code 123456                # 提交 2FA 验证码并顺带取 OTP
//! shuvpn-probe otp                                 # 用现有会话直接取 OTP（常用）
//! ```
//!
//! 凭据来源：默认交互输入（密码不回显）；`--from-file` 读本地 JSON
//! （`{"username": "...", "password": "...", "method": "wecom"|"sms"}`）。
//! 中间状态写入 `.probe-cookies.json` / `.probe-state.json`（均已 gitignore）；
//! verify 成功后立即删除含密码的 state 文件。
//!
//! 退出码：0 成功；2 登录失败；3 发码/验证失败；6 取码失败；9 用法错误。

use std::io::Write as _;
use std::process::ExitCode;
use std::sync::Arc;

use shuvpn_core::error::CoreError;
use shuvpn_core::otp::OtpClient;
use shuvpn_core::session::{SessionConfig, ShuSession};
use shuvpn_core::sso::otp_login_params;
use shuvpn_core::TwoStepMethod;

const COOKIES_FILE: &str = ".probe-cookies.json";
const STATE_FILE: &str = ".probe-state.json";

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
            cmd_login(from_file.as_deref()).await
        }
        Some("verify") => {
            let code = flag_value(&args, "--code").ok_or_else(|| usage("--code <验证码> 必填"))?;
            cmd_verify(&code).await
        }
        Some("otp") => cmd_otp().await,
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

fn usage(msg: &str) -> ExitCode {
    eprintln!("用法错误: {msg}");
    print_usage();
    ExitCode::from(9)
}

fn print_usage() {
    eprintln!("用法: shuvpn-probe <login [--from-file <json>] | verify --code <码> | otp>");
}

fn new_session() -> Result<Arc<ShuSession>, ExitCode> {
    ShuSession::new(SessionConfig::default())
        .map(Arc::new)
        .map_err(|e| {
            eprintln!("✗ 会话构建失败: {e}");
            ExitCode::from(9)
        })
}

// ---------------------------------------------------------------------------
// login
// ---------------------------------------------------------------------------

async fn cmd_login(from_file: Option<&str>) -> Result<(), ExitCode> {
    let (username, password, preferred) = read_credentials(from_file)?;
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

    // 选通道：文件指定 > twoStepMethods 首个可用 > 默认 wecom
    let method = preferred
        .filter(|m| resp.two_step_methods.contains(m))
        .or_else(|| resp.two_step_methods.first().copied())
        .unwrap_or(TwoStepMethod::Wecom);
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
    let password = rpassword::prompt_password("密码（不回显）: ").unwrap_or_default();
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
    let session = new_session()?;
    match session.load_cookies(COOKIES_FILE) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("✗ 没有 {COOKIES_FILE}，先运行 login");
            return Err(ExitCode::from(9));
        }
        Err(e) => {
            eprintln!("✗ cookie 恢复失败: {e}");
            return Err(ExitCode::from(9));
        }
    }
    print_otp(&session).await
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
    println!("  请与官网 https://otp.shu.edu.cn 同时刻口令人工比对。");
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
