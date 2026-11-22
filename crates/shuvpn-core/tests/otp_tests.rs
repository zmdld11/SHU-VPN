//! OTP 模块离线单测：wiremock 模拟 otp 站 + SSO authorize 端点。
//! 覆盖 redeem 全流程（state 透传断言）、会话失效、站点改版 fail loud。
//! 不触网、不含真实凭据。

use std::sync::{Arc, Mutex};

use shuvpn_core::error::{CoreError, Result};
use shuvpn_core::otp::OtpClient;
use shuvpn_core::session::{SessionConfig, ShuSession};
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// 登录态下的 OTP 整页（口令 6 位）。
fn otp_page(code: &str, remaining: u64) -> String {
    format!(
        r#"<html><body>
<span id="DataList1_LabelNum_0">{code}</span>
<span id="DataList1_LabelAccount_0">25120000</span>
<script>let remainingSeconds = {remaining}; const totalSeconds = 30;</script>
</body></html>"#
    )
}

async fn session_at(uri: &str) -> Arc<ShuSession> {
    Arc::new(
        ShuSession::new(SessionConfig {
            base: uri.to_string(),
            verify_tls: true,
            timeout: Duration::from_secs(5),
        })
        .expect("session"),
    )
}

/// 预热 mock：GET / → 302 到 authorize 页并携带固定 state（只生效一次，
/// 之后的 GET / 落到登录态整页 mock）。
fn bootstrap_mock(server_uri: String, state: impl Into<String>) -> Mock {
    let state = state.into();
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(move |_req: &Request| {
            let loc = format!(
                "{server_uri}/oauth/authorize?response_type=code&client_id=05Q1L8woQK5350aK1U5o5GKh411ar3h1&state={state}"
            );
            ResponseTemplate::new(302).insert_header("Location", loc)
        })
        .up_to_n_times(1)
}

/// 登录态整页 mock：GET / → 200 + 页面 + Refresh 头。
fn page_mock(code: &str, remaining: u64) -> Mock {
    let body = otp_page(code, remaining);
    let refresh = remaining.to_string();
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(move |_req: &Request| {
            ResponseTemplate::new(200)
                .set_body_string(body.clone())
                .insert_header("Refresh", refresh.clone())
        })
}

/// authorize mock：把请求里的 state 原样回填进 Callback Location，
/// 并记录收到的 state（供透传断言）。
fn authorize_mock(seen: Arc<Mutex<Vec<String>>>, location: String) -> Mock {
    Mock::given(method("GET"))
        .and(path("/oauth/authorize"))
        .respond_with(move |req: &Request| {
            let url = req.url.to_string();
            let state = url::Url::parse(&url)
                .ok()
                .and_then(|u| {
                    u.query_pairs()
                        .find(|(k, _)| k == "state")
                        .map(|(_, v)| v.into_owned())
                })
                .unwrap_or_default();
            seen.lock().expect("seen lock").push(state);
            ResponseTemplate::new(302).insert_header("Location", location.clone())
        })
}

// ---------------------------------------------------------------------------
// redeem 全流程
// ---------------------------------------------------------------------------

#[tokio::test]
async fn redeem_full_flow_passes_state_and_fetches_code() -> Result<()> {
    let server = MockServer::start().await;
    let uri = server.uri();

    bootstrap_mock(uri.clone(), "FIXED-STATE-123")
        .mount(&server)
        .await;
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let cb_loc = format!("{uri}/Callback.aspx?code=AUTHCODE9&state=IGNORED");
    authorize_mock(seen.clone(), cb_loc).mount(&server).await;
    // Callback.aspx：Refresh 头跳转（非 302），客户端需手动跟进
    Mock::given(method("GET"))
        .and(path("/Callback.aspx"))
        .respond_with(|_req: &Request| {
            ResponseTemplate::new(200)
                .set_body_string("callback ok")
                .insert_header("Refresh", "0;url=Default.aspx")
        })
        .mount(&server)
        .await;
    // Default.aspx（跟进目标）
    Mock::given(method("GET"))
        .and(path("/Default.aspx"))
        .respond_with(|_req: &Request| {
            ResponseTemplate::new(200).set_body_string(otp_page("956370", 14))
        })
        .mount(&server)
        .await;
    // 登录态整页（fetch_code 用，紧跟在 bootstrap 之后）
    page_mock("685970", 17).mount(&server).await;

    let client = OtpClient::with_base(session_at(&uri).await, uri.clone());
    let otp = client.redeem().await?;

    // fetch_code 命中的是登录态整页 mock；state 已透传给 authorize
    assert_eq!(otp.code, "685970");
    assert_eq!(otp.account, "25120000");
    assert_eq!(otp.remaining_secs, 17); // Refresh 头优先于页面脚本
    assert_eq!(otp.period_secs, 30);
    let seen_states = seen.lock().expect("seen lock");
    assert_eq!(seen_states.len(), 1);
    assert_eq!(seen_states[0], "FIXED-STATE-123");
    Ok(())
}

#[tokio::test]
async fn redeem_kicked_to_login_is_session_expired() {
    let server = MockServer::start().await;
    let uri = server.uri();
    bootstrap_mock(uri.clone(), "S1").mount(&server).await;
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    authorize_mock(seen, format!("{uri}/oauth2/login/eyJhbGc"))
        .mount(&server)
        .await;

    let client = OtpClient::with_base(session_at(&uri).await, uri);
    let err = client.redeem().await.expect_err("should fail");
    assert!(matches!(err, CoreError::SessionExpired));
}

#[tokio::test]
async fn bootstrap_without_state_is_parse_error() {
    let server = MockServer::start().await;
    let uri = server.uri();
    let base = uri.clone();
    // 302 但 Location 里没有 state
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(move |_req: &Request| {
            ResponseTemplate::new(302)
                .insert_header("Location", format!("{base}/oauth/authorize?client_id=x"))
        })
        .up_to_n_times(1)
        .mount(&server)
        .await;

    let client = OtpClient::with_base(session_at(&uri).await, uri);
    let err = client.redeem().await.expect_err("should fail");
    assert!(matches!(err, CoreError::Parse(ref m) if m.contains("state")));
}

// ---------------------------------------------------------------------------
// fetch_code
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fetch_code_refresh_header_wins() -> Result<()> {
    let server = MockServer::start().await;
    page_mock("123456", 9).mount(&server).await;

    let client = OtpClient::with_base(session_at(&server.uri()).await, server.uri());
    let otp = client.fetch_code().await?;
    assert_eq!(otp.code, "123456");
    assert_eq!(otp.remaining_secs, 9);
    Ok(())
}

#[tokio::test]
async fn fetch_code_kicked_to_login_is_session_expired() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(|_req: &Request| {
            ResponseTemplate::new(302)
                .insert_header("Location", "https://newsso.shu.edu.cn/oauth2/login/xyz")
        })
        .mount(&server)
        .await;

    let client = OtpClient::with_base(session_at(&server.uri()).await, server.uri());
    let err = client.fetch_code().await.expect_err("should fail");
    assert!(matches!(err, CoreError::SessionExpired));
}

#[tokio::test]
async fn fetch_code_without_span_is_parse_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(|_req: &Request| {
            ResponseTemplate::new(200).set_body_string("<html>结构变了</html>")
        })
        .mount(&server)
        .await;

    let client = OtpClient::with_base(session_at(&server.uri()).await, server.uri());
    let err = client.fetch_code().await.expect_err("should fail");
    assert!(matches!(err, CoreError::Parse(ref m) if m.contains("口令节点")));
}
