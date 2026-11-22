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
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            two_fa_method: "sms".into(),
            verify_tls: true,
            openvpn_path: None,
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

    match connect_inner(&app).await {
        Ok(()) => Ok(()),
        Err(msg) => {
            let cancelled = msg.contains("取消");
            *app.state::<AppState>().status.lock().unwrap() = if cancelled {
                "idle".into()
            } else {
                "failed".into()
            };
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

    // ④ 拉起 openvpn 并转发事件
    let auth = Arc::new(GuiAuth {
        app: app.clone(),
        username,
        password,
        session: session.clone(),
        otp_cache: AsyncMutex::new(None),
    });
    let (tx, rx) = mpsc::unbounded_channel::<VpnEvent>();
    let handle = vpn::launch(&cfg, auth, tx).await.map_err(es)?;
    *state.handle.lock().await = Some(handle);
    spawn_forwarder(app.clone(), rx);
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
        None => Err("当前没有进行中的连接".into()),
    }
}

/// core `VpnEvent` → 前端 `vpn-event`；通道关闭（进程退出）时清理句柄。
fn spawn_forwarder(app: AppHandle, mut rx: mpsc::UnboundedReceiver<VpnEvent>) {
    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();
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
                    emit(&app, UiEvent::State { name, reason });
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
    let status = app.state::<AppState>().status.lock().unwrap().clone();
    StatusInfo {
        status,
        has_credentials,
        username,
        settings,
        openvpn_path,
        openvpn_found,
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
    settings.save(&data_dir(&app)?)
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
// 托盘与入口
// ---------------------------------------------------------------------------

fn show_main_window(app: &AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
    }
}

fn setup_tray(app: &AppHandle) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::TrayIconBuilder;

    let show = MenuItem::with_id(app, "show", "显示主窗口", true, None::<&str>)?;
    let connect = MenuItem::with_id(app, "connect", "连接 VPN", true, None::<&str>)?;
    let disconnect = MenuItem::with_id(app, "disconnect", "断开", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &connect, &disconnect, &quit])?;

    let mut builder = TrayIconBuilder::with_id("main-tray")
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
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState {
            handle: AsyncMutex::new(None),
            status: Mutex::new("idle".into()),
            code_pending: Arc::new(AsyncMutex::new(None)),
        })
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
        ])
        .setup(|app| {
            setup_tray(app.handle())?;
            Ok(())
        })
        .on_window_event(|window, event| {
            // 关窗 = 最小化到托盘（保持连接与通知），退出走托盘菜单
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .expect("failed to run SHU-VPN");
}
