//! HTTP / 会话底座：no-redirect 客户端、共享 cookie jar、RSA 公钥与密码加密。
//!
//! 协议要点（docs/protocol.md §1、§2.1–§2.2）：
//! - 全部协议请求**不自动跟随重定向**，Location 一律手动读；
//! - `SHU_OAUTH2` 会话 Cookie 持久化到本地（JSON 格式的 cookie jar）；
//! - 登录密码用学校 RSA 公钥（PKCS#1 v1.5）加密后 base64 提交，公钥
//!   「缓存 → 在线抓取 → 内置回退」三级获取。

use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use base64::Engine;
use rand::rngs::OsRng;
use regex::bytes::Regex as BytesRegex;
use regex::Regex;
use reqwest::Client;
use reqwest_cookie_store::CookieStoreRwLock;
use rsa::pkcs8::DecodePublicKey;
use rsa::Pkcs1v15Encrypt;
use tokio::sync::Mutex;

use crate::error::{CoreError, Result};
use crate::sso;

/// 桌面 Chrome UA（站点不校验，但需像浏览器）。
pub const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36";

/// HTML 请求的 Accept 头。
pub const HTML_ACCEPT: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

/// 会话与 HTTP 配置。
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// SSO base（默认 `https://newsso.shu.edu.cn`；单测指向 mock server）。
    pub base: String,
    /// 是否校验 TLS 证书（默认开启；学校证书链异常时由设置层关闭）。
    pub verify_tls: bool,
    /// 单请求超时。
    pub timeout: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            base: sso::SSO_BASE.to_string(),
            verify_tls: true,
            timeout: Duration::from_secs(30),
        }
    }
}

/// 共享的 HTTP 会话：cookie jar 对 SSO 与 OTP 客户端统一可见。
pub struct ShuSession {
    config: SessionConfig,
    cookies: Arc<CookieStoreRwLock>,
    http: Client,
    /// 生效公钥缓存（Some = 已定）。
    key_cache: Mutex<Option<String>>,
}

impl ShuSession {
    /// 构建会话；HTTP 客户端构建失败时返回 [`CoreError::Protocol`]。
    pub fn new(config: SessionConfig) -> Result<Self> {
        let cookies = Arc::new(CookieStoreRwLock::default());
        let http = build_client(&config, cookies.clone())?;
        Ok(Self {
            config,
            cookies,
            http,
            key_cache: Mutex::new(None),
        })
    }

    /// 绝对 URL（基于配置的 base）。
    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}{}", self.config.base.trim_end_matches('/'), path)
    }

    pub(crate) fn http(&self) -> &Client {
        &self.http
    }

    /// 公钥 PEM：缓存 → 在线抓取 → 内置回退（docs/protocol.md §2.1–§2.2）。
    pub async fn public_key_pem(&self) -> Result<String> {
        if let Some(pem) = self.key_cache.lock().await.clone() {
            return Ok(pem);
        }
        let fetched = fetch_public_key_pem(&self.http, &self.config.base).await;
        let pem = match fetched {
            Some(raw) => normalize_pem(&raw),
            None => {
                log::warn!("RSA 公钥在线抓取失败，使用内置回退公钥");
                sso::FALLBACK_RSA_PUBLIC_KEY_PEM.to_string()
            }
        };
        *self.key_cache.lock().await = Some(pem.clone());
        Ok(pem)
    }

    /// 测试/高级用法：直接注入公钥，跳过在线抓取。
    pub async fn set_public_key_override(&self, pem: &str) {
        *self.key_cache.lock().await = Some(normalize_pem(pem));
    }

    /// 登录密码 RSA PKCS#1 v1.5 加密 → base64（docs/protocol.md §2）。
    pub async fn encrypt_password(&self, password: &str) -> Result<String> {
        let pem = self.public_key_pem().await?;
        let key = rsa::RsaPublicKey::from_public_key_pem(&pem)
            .map_err(|e| CoreError::Parse(format!("RSA 公钥解析失败: {e}")))?;
        let ct = key
            .encrypt(&mut OsRng, Pkcs1v15Encrypt, password.as_bytes())
            .map_err(|e| CoreError::Protocol(format!("密码加密失败: {e}")))?;
        Ok(base64::engine::general_purpose::STANDARD.encode(ct))
    }

    /// 把当前 cookie jar 持久化为 JSON 文件（存放目录由调用方保证安全）。
    ///
    /// 注意必须用「含非持久化 cookie」的保存变体：`SHU_OAUTH2` 这类
    /// 服务器会话 cookie 不带 `Expires`，默认序列化会把它丢掉。
    pub fn save_cookies(&self, path: impl AsRef<Path>) -> Result<()> {
        let file = std::fs::File::create(path.as_ref())
            .map_err(|e| CoreError::Protocol(format!("cookie 文件创建失败: {e}")))?;
        let mut writer = std::io::BufWriter::new(file);
        let guard = self.cookies.read().expect("cookie 锁中毒");
        cookie_store::serde::json::save_incl_expired_and_nonpersistent(&guard, &mut writer)
            .map_err(|e| CoreError::Protocol(format!("cookie 持久化失败: {e}")))?;
        Ok(())
    }

    /// 从 JSON 文件恢复 cookie jar；文件不存在时返回 `Ok(false)`。
    pub fn load_cookies(&self, path: impl AsRef<Path>) -> Result<bool> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(false);
        }
        let file = std::fs::File::open(path)
            .map_err(|e| CoreError::Protocol(format!("cookie 文件打开失败: {e}")))?;
        let reader = std::io::BufReader::new(file);
        let store = cookie_store::serde::json::load_all(reader)
            .map_err(|e| CoreError::Protocol(format!("cookie 恢复失败: {e}")))?;
        *self.cookies.write().expect("cookie 锁中毒") = store;
        Ok(true)
    }

    /// 粗判定是否已有 SSO 会话（存在名为 `SHU_OAUTH2` 的 cookie）。
    /// 是否真正有效由 authorize 是否被踢回登录页判定。
    pub fn has_session_cookie(&self) -> bool {
        self.cookies
            .read()
            .expect("cookie 锁中毒")
            .iter_any()
            .any(|c| c.name() == sso::SSO_SESSION_COOKIE)
    }

    /// 清空会话 cookie（退出登录）。
    pub fn clear_cookies(&self) {
        *self.cookies.write().expect("cookie 锁中毒") =
            reqwest_cookie_store::CookieStore::default();
    }
}

fn build_client(config: &SessionConfig, cookies: Arc<CookieStoreRwLock>) -> Result<Client> {
    let mut builder = Client::builder()
        .timeout(config.timeout)
        .user_agent(USER_AGENT)
        // 协议约定：所有重定向手动读 Location（docs/protocol.md §1）
        .redirect(reqwest::redirect::Policy::none())
        .cookie_provider(cookies);
    if !config.verify_tls {
        log::warn!("TLS 证书校验已关闭（设置层显式开启），存在中间人风险");
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder
        .build()
        .map_err(|e| CoreError::Protocol(format!("HTTP 客户端构建失败: {e}")))
}

/// 在线抓取公钥：`/oauth2/login/` 页 → 清单 JS → 登录 chunk → PEM。
/// 任一环节失败返回 `None`（调用方走回退），不让公钥问题阻断登录。
async fn fetch_public_key_pem(http: &Client, base: &str) -> Option<String> {
    static MANIFEST_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"["'](/(?:preload_helper|umi)\.[0-9a-f]+\.js)["']"#).expect("valid regex")
    });
    static JS_URL_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r#"["'](/[A-Za-z0-9_\-./]+\.js)["']"#).expect("valid regex"));
    static LOGIN_CHUNK_RE: LazyLock<BytesRegex> = LazyLock::new(|| {
        BytesRegex::new(r#"["'](/?(?:p__oauth2__login__index)\.[0-9a-f]+\.async\.js)["']"#)
            .expect("valid regex")
    });
    static PEM_RE: LazyLock<BytesRegex> = LazyLock::new(|| {
        BytesRegex::new(r"-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----")
            .expect("valid regex")
    });

    async fn get_text(http: &Client, url: &str) -> Option<String> {
        let resp = http
            .get(url)
            .header("Accept", HTML_ACCEPT)
            .send()
            .await
            .ok()?;
        if resp.status().is_success() {
            Some(resp.text().await.ok()?)
        } else {
            None
        }
    }

    let html = get_text(http, &format!("{base}/oauth2/login/")).await?;

    // 清单脚本：先按页面明确引用的找，找不到退到通用 .js URL 里筛
    let mut manifest_urls: Vec<String> = MANIFEST_RE
        .captures_iter(&html)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
        .collect();
    if manifest_urls.is_empty() {
        manifest_urls = JS_URL_RE
            .captures_iter(&html)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .filter(|u| u.contains("preload_helper") || u.contains("/umi"))
            .collect();
    }

    let mut chunk_name: Option<String> = None;
    for manifest in &manifest_urls {
        let text = match get_text(http, &format!("{base}{manifest}")).await {
            Some(t) => t,
            None => continue,
        };
        if let Some(m) = LOGIN_CHUNK_RE.captures(text.as_bytes()) {
            chunk_name = Some(String::from_utf8_lossy(m.get(1)?.as_bytes()).to_string());
            break;
        }
    }
    let chunk_name = chunk_name?;

    let chunk_url = if chunk_name.starts_with('/') {
        chunk_name
    } else {
        format!("/{chunk_name}")
    };
    let chunk = get_text(http, &format!("{base}{chunk_url}")).await?;
    let m = PEM_RE.captures(chunk.as_bytes())?;
    Some(String::from_utf8_lossy(m.get(0)?.as_bytes()).to_string())
}

/// 把抓到的 PEM（可能含多余空白/换行）规范化为标准 64 列格式。
fn normalize_pem(pem: &str) -> String {
    let body: String = pem
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let mut out = String::from("-----BEGIN PUBLIC KEY-----\n");
    let bytes = body.as_bytes();
    for (i, chunk) in bytes.chunks(64).enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&String::from_utf8_lossy(chunk));
    }
    out.push_str("\n-----END PUBLIC KEY-----");
    out
}
