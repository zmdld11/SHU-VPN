//! flow 模块离线单测：wiremock 模拟 SSO 端点，覆盖会话有效直连 /
//! 过期重登 / 2FA 通道选择 / 验证码回调路径 / 验证失败 fail loud。
//! 全部场景不触网，不含任何真实凭据。

use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};
use shuvpn_core::flow::ensure_session;
use shuvpn_core::session::{SessionConfig, ShuSession};
use shuvpn_core::sso::FALLBACK_RSA_PUBLIC_KEY_PEM;
use shuvpn_core::TwoStepMethod;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

async fn session_with_key(uri: &str) -> ShuSession {
    let s = ShuSession::new(SessionConfig {
        base: uri.to_string(),
        verify_tls: true,
        timeout: Duration::from_secs(5),
    })
    .expect("session");
    // 登录/验证都要 RSA 加密密码；注入固定公钥跳过在线抓取链
    s.set_public_key_override(FALLBACK_RSA_PUBLIC_KEY_PEM).await;
    s
}

/// 固定返回验证码的回调，记录被询问的通道。
struct FixedPrompt {
    code: &'static str,
    seen: Mutex<Vec<TwoStepMethod>>,
}

impl FixedPrompt {
    fn new(code: &'static str) -> Self {
        Self {
            code,
            seen: Mutex::new(Vec::new()),
        }
    }

    fn asked(&self) -> Vec<TwoStepMethod> {
        self.seen.lock().unwrap().clone()
    }
}

#[async_trait]
impl shuvpn_core::flow::CodePrompt for FixedPrompt {
    async fn prompt(&self, method: TwoStepMethod) -> shuvpn_core::Result<String> {
        self.seen.lock().unwrap().push(method);
        Ok(self.code.to_string())
    }
}

// ---------------------------------------------------------------------------
// mock 端点
// ---------------------------------------------------------------------------

/// authorize 被踢回登录页（会话失效）。
fn authorize_needs_login() -> Mock {
    Mock::given(method("GET"))
        .and(path("/oauth/authorize"))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "Location",
            "https://newsso.shu.edu.cn/oauth2/login/?redirect=x",
        ))
}

/// authorize 成功发授权码（会话有效）。
fn authorize_ok() -> Mock {
    Mock::given(method("GET"))
        .and(path("/oauth/authorize"))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "Location",
            "https://otp.shu.edu.cn//Callback.aspx?code=c1&state=s1",
        ))
}

/// userLogin：twoStepRequired 可配，回显请求体供断言。
fn login_mock(two_step: bool, methods: &[&str]) -> Mock {
    let methods: Value = methods
        .iter()
        .map(|m| (m.to_string(), Value::String("通道".into())))
        .collect::<serde_json::Map<String, Value>>()
        .into();
    Mock::given(method("POST"))
        .and(path("/oauth/userLogin"))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            assert_eq!(body["tenantId"], "上海大学");
            assert!(body["username"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false));
            assert!(body["password"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false));
            ResponseTemplate::new(200).set_body_json(json!({
                "message": "success",
                "twoStepRequired": two_step,
                "twoStepMethods": methods,
            }))
        })
}

fn send_ok() -> Mock {
    Mock::given(method("POST"))
        .and(path("/oauth/twoStep/send"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"message": "success"})))
}

fn verify_ok() -> Mock {
    Mock::given(method("POST"))
        .and(path("/oauth/twoStep/verify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"message": "success"})))
}

fn verify_bad() -> Mock {
    Mock::given(method("POST"))
        .and(path("/oauth/twoStep/verify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"message": "验证码错误"})))
}

/// mock 一个种 cookie 的端点并访问之，让会话带上 SHU_OAUTH2。
async fn seed_cookie(session: &ShuSession, server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/seed"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Set-Cookie", "SHU_OAUTH2=test-session; Path=/"),
        )
        .mount(server)
        .await;
    let resp = session
        .http()
        .get(format!("{}/seed", server.uri()))
        .send()
        .await
        .expect("seed request");
    assert_eq!(resp.status(), 200);
}

/// 统计 server 收到某路径的请求数。
async fn hits(server: &MockServer, path: &str) -> usize {
    server
        .received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|r| r.url.path() == path)
        .count()
}

// ---------------------------------------------------------------------------
// 用例
// ---------------------------------------------------------------------------

#[tokio::test]
async fn valid_session_skips_login() {
    let server = MockServer::start().await;
    authorize_ok().mount(&server).await;
    let session = session_with_key(&server.uri()).await;
    seed_cookie(&session, &server).await;

    let prompt = FixedPrompt::new("123456");
    ensure_session(&session, "u", "p", TwoStepMethod::Sms, &prompt)
        .await
        .expect("会话有效时应直接通过");

    assert_eq!(hits(&server, "/oauth/userLogin").await, 0);
    assert!(prompt.asked().is_empty());
}

#[tokio::test]
async fn no_cookie_logs_in_without_2fa() {
    let server = MockServer::start().await;
    login_mock(false, &[]).mount(&server).await;
    let session = session_with_key(&server.uri()).await;

    let prompt = FixedPrompt::new("123456");
    ensure_session(&session, "u", "p", TwoStepMethod::Sms, &prompt)
        .await
        .expect("无 cookie 应走登录并成功");

    assert_eq!(hits(&server, "/oauth/userLogin").await, 1);
    assert!(prompt.asked().is_empty());
}

#[tokio::test]
async fn stale_cookie_relogins() {
    let server = MockServer::start().await;
    authorize_needs_login().mount(&server).await;
    login_mock(false, &[]).mount(&server).await;
    let session = session_with_key(&server.uri()).await;
    seed_cookie(&session, &server).await;

    let prompt = FixedPrompt::new("123456");
    ensure_session(&session, "u", "p", TwoStepMethod::Sms, &prompt)
        .await
        .expect("过期 cookie 应回退到登录");

    assert_eq!(hits(&server, "/oauth/userLogin").await, 1);
}

#[tokio::test]
async fn two_step_defaults_to_sms() {
    let server = MockServer::start().await;
    login_mock(true, &["sms", "wecom"]).mount(&server).await;
    send_ok().mount(&server).await;
    verify_ok().mount(&server).await;
    let session = session_with_key(&server.uri()).await;

    let prompt = FixedPrompt::new("654321");
    ensure_session(&session, "u", "p", TwoStepMethod::Sms, &prompt)
        .await
        .expect("2FA 路径应成功");

    assert_eq!(prompt.asked(), vec![TwoStepMethod::Sms]);
    // send 请求体应为 sms
    let sent = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.url.path() == "/oauth/twoStep/send")
        .expect("send 被调用");
    let body: Value = serde_json::from_slice(&sent.body).unwrap();
    assert_eq!(body["method"], "sms");
}

#[tokio::test]
async fn two_step_preferred_wecom_respected() {
    let server = MockServer::start().await;
    login_mock(true, &["sms", "wecom"]).mount(&server).await;
    send_ok().mount(&server).await;
    verify_ok().mount(&server).await;
    let session = session_with_key(&server.uri()).await;

    let prompt = FixedPrompt::new("654321");
    ensure_session(&session, "u", "p", TwoStepMethod::Wecom, &prompt)
        .await
        .expect("2FA 路径应成功");

    assert_eq!(prompt.asked(), vec![TwoStepMethod::Wecom]);
}

#[tokio::test]
async fn two_step_preferred_unavailable_falls_back() {
    // 偏好 sms 但服务端只提供 wecom → 选 wecom
    let server = MockServer::start().await;
    login_mock(true, &["wecom"]).mount(&server).await;
    send_ok().mount(&server).await;
    verify_ok().mount(&server).await;
    let session = session_with_key(&server.uri()).await;

    let prompt = FixedPrompt::new("654321");
    ensure_session(&session, "u", "p", TwoStepMethod::Sms, &prompt)
        .await
        .expect("回退通道应成功");

    assert_eq!(prompt.asked(), vec![TwoStepMethod::Wecom]);
}

#[tokio::test]
async fn wrong_code_fails_loud() {
    let server = MockServer::start().await;
    login_mock(true, &["sms"]).mount(&server).await;
    send_ok().mount(&server).await;
    verify_bad().mount(&server).await;
    let session = session_with_key(&server.uri()).await;

    let prompt = FixedPrompt::new("000000");
    let err = ensure_session(&session, "u", "p", TwoStepMethod::Sms, &prompt)
        .await
        .expect_err("验证码错误应 fail loud");
    assert!(matches!(err, shuvpn_core::CoreError::Protocol(ref m) if m.contains("验证码错误")));
    // 只询问一次：core 不静默重试，重试决策交给上层
    assert_eq!(prompt.asked().len(), 1);
}
