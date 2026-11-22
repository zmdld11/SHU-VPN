//! SSO（newsso.shu.edu.cn）登录协议：常量 + 登录 / 两步验证 / OAuth2 授权。
//!
//! 完整流程规格见 `docs/protocol.md` §2–§4。所有接口判定以响应 JSON 的
//! `message == "success"` 为准；任何协议外响应 fail loud。

use base64::Engine;
use serde_json::{json, Value};
use url::Url;

use crate::error::{CoreError, Result};
use crate::session::{ShuSession, HTML_ACCEPT};
use crate::TwoStepMethod;

// ---------------------------------------------------------------------------
// 协议常量
// ---------------------------------------------------------------------------

/// SSO 站点根地址。
pub const SSO_BASE: &str = "https://newsso.shu.edu.cn";

/// 登录接口 `tenantId` 固定值（服务端按字符串校验）。
pub const DEFAULT_TENANT: &str = "上海大学";

/// SSO 会话 Cookie 名（HttpOnly，newsso 域内可跨系统复用）。
pub const SSO_SESSION_COOKIE: &str = "SHU_OAUTH2";

/// 登录接口路径。
pub const USER_LOGIN_PATH: &str = "/oauth/userLogin";

/// 两步验证端点。
pub const TWO_STEP_SEND_PATH: &str = "/oauth/twoStep/send";
pub const TWO_STEP_VERIFY_PATH: &str = "/oauth/twoStep/verify";

/// OAuth2 授权端点（响应不自动跟随，读 Location）。
pub const AUTHORIZE_PATH: &str = "/oauth/authorize";

/// authorize 的 Location 落回登录页 = 会话失效。
pub const NEEDS_LOGIN_MARKER: &str = "/oauth2/login/";

/// OTP 业务系统在 SSO 侧的 OAuth2 客户端参数（公开常量，非机密）。
/// 注意 `redirect_uri` 是双斜杠（站点原样如此）。
pub const OTP_CLIENT_ID: &str = "05Q1L8woQK5350aK1U5o5GKh411ar3h1";
pub const OTP_CLIENT_NAME: &str = "OTP令牌";
pub const OTP_REDIRECT_URI: &str = "https://otp.shu.edu.cn//Callback.aspx";
pub const OTP_SCOPE: &str = "read write";

/// 学校登录密码 RSA 公钥（1024bit，公开信息）。在线抓取失败时的内置回退值；
/// 在线抓取链路见 `docs/protocol.md` §2.1。
pub const FALLBACK_RSA_PUBLIC_KEY_PEM: &str = "\
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDl/aCgRl9f/4ON9MewoVnV58OL
OU2ALBi2FKc5yIsfSpivKxe7A6FitJjHva3WpM7gvVOinMehp6if2UNIkbaN+plW
f5IwqEVxsNZpeixc4GsbY9dXEk3WtRjwGSyDLySzEESH/kpJVoxO7ijRYqU+2oSR
wTBNePOk1H+LRQokgQIDAQAB
-----END PUBLIC KEY-----";

// ---------------------------------------------------------------------------
// 类型
// ---------------------------------------------------------------------------

/// 登录响应（`message == "success"` 之后的部分）。
#[derive(Debug, Clone)]
pub struct LoginResponse {
    /// 是否需要两步验证。
    pub two_step_required: bool,
    /// 可用的两步验证通道。
    pub two_step_methods: Vec<TwoStepMethod>,
    /// 原始响应（日志/诊断用，可能包含敏感字段，勿整体入库）。
    pub raw: Value,
}

/// authorize 请求结果。
#[derive(Debug, Clone)]
pub struct AuthorizeResult {
    /// 响应 `Location`（可能为空）。
    pub location: String,
    /// 从 Location 提取的一次性授权码。
    pub code: Option<String>,
    /// Location 落回登录页 = SSO 会话失效。
    pub needs_login: bool,
}

// ---------------------------------------------------------------------------
// params 编码
// ---------------------------------------------------------------------------

/// `userLogin` 的 `params` 字段：OAuth 参数 JSON → **base64url 无填充**
/// （docs/protocol.md §2）。服务端只校验格式、不关心具体业务系统。
pub fn encode_login_params(
    client_id: &str,
    client_name: &str,
    scope: &str,
    redirect_uri: &str,
) -> String {
    let payload = json!({
        "responseType": "code",
        "clientId": client_id,
        "clientName": client_name,
        "scope": scope,
        "redirectUri": redirect_uri,
        "state": "",
    });
    let raw = serde_json::to_string(&payload).expect("json 序列化不会失败");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.as_bytes())
}

/// OTP 系统的 login `params`（固定使用 OTP 客户端参数，state 留空）。
pub fn otp_login_params() -> String {
    encode_login_params(OTP_CLIENT_ID, OTP_CLIENT_NAME, OTP_SCOPE, OTP_REDIRECT_URI)
}

// ---------------------------------------------------------------------------
// SSO API（挂在 ShuSession 上，cookie 与 HTTP 由 session 层提供）
// ---------------------------------------------------------------------------

impl ShuSession {
    /// 密码登录（docs/protocol.md §2）。
    ///
    /// `params_b64` 用 [`encode_login_params`]（或 [`otp_login_params`]）生成。
    /// 返回 [`LoginResponse`]；`two_step_required == true` 时继续
    /// [`ShuSession::send_2fa`] / [`ShuSession::verify_2fa`]。
    pub async fn login(
        &self,
        username: &str,
        password: &str,
        params_b64: &str,
    ) -> Result<LoginResponse> {
        let encrypted = self.encrypt_password(password).await?;
        let body = json!({
            "username": username,
            "password": encrypted,
            "tenantId": DEFAULT_TENANT,
            "params": params_b64,
        });
        // 协议要求：登录请求带 Request-Id（uuid4）
        let resp = self
            .http()
            .post(self.url(USER_LOGIN_PATH))
            .header("Request-Id", uuid::Uuid::new_v4().to_string())
            .json(&body)
            .send()
            .await?;
        let data = read_json(resp, "userLogin").await?;
        require_success(&data, "登录")?;
        Ok(LoginResponse {
            two_step_required: data
                .get("twoStepRequired")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            two_step_methods: parse_two_step_methods(&data),
            raw: data,
        })
    }

    /// 触发两步验证发码（docs/protocol.md §3）。
    pub async fn send_2fa(&self, method: TwoStepMethod) -> Result<()> {
        let resp = self
            .http()
            .post(self.url(TWO_STEP_SEND_PATH))
            .json(&json!({ "method": method.as_str() }))
            .send()
            .await?;
        let data = read_json(resp, "twoStep/send").await?;
        require_success(&data, "发码")
    }

    /// 提交两步验证码（密码按协议重新加密提交）。
    pub async fn verify_2fa(
        &self,
        username: &str,
        password: &str,
        params_b64: &str,
        code: &str,
        method: TwoStepMethod,
    ) -> Result<()> {
        let encrypted = self.encrypt_password(password).await?;
        let body = json!({
            "username": username,
            "password": encrypted,
            "tenantId": DEFAULT_TENANT,
            "params": params_b64,
            "code": code,
            "method": method.as_str(),
        });
        let resp = self
            .http()
            .post(self.url(TWO_STEP_VERIFY_PATH))
            .json(&body)
            .send()
            .await?;
        let data = read_json(resp, "twoStep/verify").await?;
        require_success(&data, "验证")
    }

    /// OAuth2 授权取码（docs/protocol.md §4）。不自动跟随重定向。
    ///
    /// `state` 为空时不携带该参数。成功时 [`AuthorizeResult::code`] 为 `Some`；
    /// [`AuthorizeResult::needs_login`] 为 `true` 表示 SSO 会话失效。
    pub async fn authorize(
        &self,
        client_id: &str,
        redirect_uri: &str,
        scope: &str,
        state: &str,
    ) -> Result<AuthorizeResult> {
        let mut url = Url::parse(&self.url(AUTHORIZE_PATH))
            .map_err(|e| CoreError::Protocol(format!("authorize URL 构造失败: {e}")))?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", scope);
        if !state.is_empty() {
            url.query_pairs_mut().append_pair("state", state);
        }

        let resp = self
            .http()
            .get(url)
            .header("Accept", HTML_ACCEPT)
            .send()
            .await?;
        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let code = extract_code(&location);
        let needs_login = location.contains(NEEDS_LOGIN_MARKER);
        Ok(AuthorizeResult {
            location,
            code,
            needs_login,
        })
    }
}

// ---------------------------------------------------------------------------
// 内部工具
// ---------------------------------------------------------------------------

/// 读取响应 JSON；非 JSON / 非成功状态时 fail loud。
async fn read_json(resp: reqwest::Response, what: &str) -> Result<Value> {
    let status = resp.status();
    let text = resp.text().await?;
    serde_json::from_str(&text).map_err(|_| {
        let preview: String = text.chars().take(200).collect();
        CoreError::Protocol(format!(
            "{what} 返回非 JSON（HTTP {}）: {preview}",
            status.as_u16()
        ))
    })
}

/// 校验 `message == "success"`，否则带原因报协议错误。
fn require_success(data: &Value, what: &str) -> Result<()> {
    if data.get("message").and_then(Value::as_str) == Some("success") {
        Ok(())
    } else {
        Err(CoreError::Protocol(format!(
            "{what}失败: {}",
            data.get("message")
                .and_then(Value::as_str)
                .unwrap_or("(无 message 字段)")
        )))
    }
}

/// 从 `twoStepMethods` 提取可用通道（键名 -> 通道；未知键忽略）。
fn parse_two_step_methods(data: &Value) -> Vec<TwoStepMethod> {
    let Some(obj) = data.get("twoStepMethods").and_then(Value::as_object) else {
        return Vec::new();
    };
    obj.keys()
        .filter_map(|k| match k.as_str() {
            "wecom" => Some(TwoStepMethod::Wecom),
            "sms" => Some(TwoStepMethod::Sms),
            _ => None,
        })
        .collect()
}

/// 从 Location 查询串提取一次性授权码。
fn extract_code(location: &str) -> Option<String> {
    if !location.contains("code=") {
        return None;
    }
    Url::parse(location).ok().and_then(|u| {
        u.query_pairs()
            .find(|(k, _)| k == "code")
            .map(|(_, v)| v.into_owned())
    })
}
