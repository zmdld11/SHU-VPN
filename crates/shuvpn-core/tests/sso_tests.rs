//! SSO 模块离线单测：wiremock 模拟 newsso 端点，覆盖登录 / 2FA / 授权 /
//! params 编码 / RSA 加解密往返 / 公钥抓取链 / cookie 持久化。
//! 全部场景不触网，不含任何真实凭据。

use base64::Engine;
use rand::rngs::OsRng;
use rsa::pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};
use shuvpn_core::error::{CoreError, Result};
use shuvpn_core::session::{SessionConfig, ShuSession};
use shuvpn_core::sso::{encode_login_params, otp_login_params, AuthorizeResult, LoginResponse};
use shuvpn_core::TwoStepMethod;
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// 生成本地测试 RSA 密钥对（模拟学校公钥，私钥仅用于解密断言）。
fn test_keypair() -> (RsaPublicKey, RsaPrivateKey) {
    let priv_key = RsaPrivateKey::new(&mut OsRng, 1024).expect("keygen");
    (priv_key.to_public_key(), priv_key)
}

/// 公钥 → SPKI PEM（测试用，编码失败即 panic）。
fn pem_of(key: &RsaPublicKey) -> String {
    key.to_public_key_pem(LineEnding::LF).expect("encode pem")
}

async fn session_at(uri: &str) -> ShuSession {
    ShuSession::new(SessionConfig {
        base: uri.to_string(),
        verify_tls: true,
        timeout: Duration::from_secs(5),
    })
    .expect("session")
}

/// 把测试公钥注入会话，跳过在线抓取链。
async fn session_with_key(uri: &str, pem: &str) -> ShuSession {
    let s = session_at(uri).await;
    s.set_public_key_override(pem).await;
    s
}

// ---------------------------------------------------------------------------
// params 编码
// ---------------------------------------------------------------------------

#[test]
fn encode_login_params_is_base64url_no_pad() {
    let encoded = encode_login_params(
        "05Q1L8woQK5350aK1U5o5GKh411ar3h1",
        "OTP令牌",
        "read write",
        "https://otp.shu.edu.cn//Callback.aspx",
    );
    // base64url 无填充：不含 '+'、'/'、'='；含 '_'（urlsafe 特征）
    assert!(!encoded.contains('+') && !encoded.contains('/') && !encoded.contains('='));
    // 可逆解码
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&encoded)
        .expect("decode");
    let v: Value = serde_json::from_slice(&decoded).expect("json");
    assert_eq!(v["responseType"], "code");
    assert_eq!(v["clientId"], "05Q1L8woQK5350aK1U5o5GKh411ar3h1");
    assert_eq!(v["redirectUri"], "https://otp.shu.edu.cn//Callback.aspx");
    assert_eq!(v["state"], "");
}

// ---------------------------------------------------------------------------
// 登录
// ---------------------------------------------------------------------------

/// userLogin mock：校验请求字段并回显（便于断言），返回 twoStepRequired=false。
fn login_mock(echo: bool) -> Mock {
    Mock::given(method("POST"))
        .and(path("/oauth/userLogin"))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            let mut resp = json!({
                "message": "success",
                "twoStepRequired": false,
                "twoStepMethods": {},
            });
            if echo {
                resp["_echo"] = json!({
                    "username": body["username"],
                    "password": body["password"],
                    "tenantId": body["tenantId"],
                    "params": body["params"],
                    "request_id": req
                        .headers
                        .get("request-id")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or(""),
                });
            }
            ResponseTemplate::new(200).set_body_json(resp)
        })
}

#[tokio::test]
async fn login_success_without_2fa() -> Result<()> {
    let (pub_key, priv_key) = test_keypair();
    let pem = pem_of(&pub_key);
    let server = MockServer::start().await;
    let echo = server.uri().clone();
    login_mock(true).mount(&server).await;

    let session = session_with_key(&echo, &pem).await;
    let params = otp_login_params();
    let resp: LoginResponse = session.login("25120000", "test-password", &params).await?;

    assert!(!resp.two_step_required);
    let echo = resp.raw["_echo"].clone();
    assert_eq!(echo["username"], "25120000");
    assert_eq!(echo["tenantId"], "上海大学");
    assert_eq!(echo["params"], params);
    // Request-Id 头存在且可解析为 uuid
    assert!(!echo["request_id"].as_str().unwrap_or("").is_empty());
    // 密码：base64(RSA(PKCS1v15)) —— 用测试私钥解密还原比对
    let ct = base64::engine::general_purpose::STANDARD
        .decode(echo["password"].as_str().unwrap())
        .expect("base64 ct");
    let plain = priv_key.decrypt(Pkcs1v15Encrypt, &ct).expect("decrypt");
    assert_eq!(plain, b"test-password");
    Ok(())
}

#[tokio::test]
async fn login_failure_returns_protocol_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/userLogin"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": "密码错误",
        })))
        .mount(&server)
        .await;

    let session = session_with_key(&server.uri(), &pem_of(&test_keypair().0)).await;
    let err = session
        .login("u", "p", &otp_login_params())
        .await
        .expect_err("should fail");
    match err {
        CoreError::Protocol(msg) => assert!(msg.contains("密码错误")),
        other => panic!("期望 Protocol 错误，得到: {other:?}"),
    }
}

#[tokio::test]
async fn login_non_json_response_fails_loud() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/userLogin"))
        .respond_with(ResponseTemplate::new(502).set_body_string("<html>oops</html>"))
        .mount(&server)
        .await;

    let session = session_with_key(&server.uri(), &pem_of(&test_keypair().0)).await;
    let err = session
        .login("u", "p", &otp_login_params())
        .await
        .expect_err("should fail");
    assert!(
        matches!(err, CoreError::Protocol(ref m) if m.contains("非 JSON") && m.contains("502"))
    );
}

// ---------------------------------------------------------------------------
// 两步验证
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_step_full_flow() -> Result<()> {
    let (pub_key, _priv) = test_keypair();
    let pem = pem_of(&pub_key);
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/oauth/userLogin"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": "success",
            "twoStepRequired": true,
            "twoStepMethods": {"wecom": {"name": "企业微信"}, "sms": {"name": "短信"}},
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth/twoStep/send"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"message": "success"})))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/oauth/twoStep/verify"))
        .respond_with(move |req: &Request| {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            ResponseTemplate::new(200).set_body_json(json!({
                "message": "success",
                "_echo": {"code": body["code"], "method": body["method"]},
            }))
        })
        .mount(&server)
        .await;

    let session = session_with_key(&server.uri(), &pem).await;
    let resp = session.login("25120000", "pw", &otp_login_params()).await?;
    assert!(resp.two_step_required);
    // 通道解析：响应顺序不定，须包含 wecom 与 sms
    assert!(resp.two_step_methods.contains(&TwoStepMethod::Wecom));
    assert!(resp.two_step_methods.contains(&TwoStepMethod::Sms));

    session.send_2fa(TwoStepMethod::Wecom).await?;
    session
        .verify_2fa(
            "25120000",
            "pw",
            &otp_login_params(),
            "123456",
            TwoStepMethod::Wecom,
        )
        .await?;
    Ok(())
}

#[tokio::test]
async fn send_2fa_failure_is_loud() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/twoStep/send"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"message": "发送过于频繁"})))
        .mount(&server)
        .await;

    let session = session_at(&server.uri()).await;
    let err = session
        .send_2fa(TwoStepMethod::Sms)
        .await
        .expect_err("should fail");
    assert!(
        matches!(err, CoreError::Protocol(ref m) if m.contains("发码失败") && m.contains("发送过于频繁"))
    );
}

// ---------------------------------------------------------------------------
// OAuth2 授权
// ---------------------------------------------------------------------------

#[tokio::test]
async fn authorize_extracts_code() -> Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth/authorize"))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "Location",
            "https://otp.shu.edu.cn//Callback.aspx?code=AUTHCODE123&state=st",
        ))
        .mount(&server)
        .await;

    let session = session_at(&server.uri()).await;
    let result: AuthorizeResult = session
        .authorize(
            "05Q1L8woQK5350aK1U5o5GKh411ar3h1",
            "https://otp.shu.edu.cn//Callback.aspx",
            "read write",
            "st",
        )
        .await?;
    assert_eq!(result.code.as_deref(), Some("AUTHCODE123"));
    assert!(!result.needs_login);
    Ok(())
}

#[tokio::test]
async fn authorize_kicked_to_login_page_means_session_expired() -> Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth/authorize"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", "https://newsso.shu.edu.cn/oauth2/login/eyJhbGc"),
        )
        .mount(&server)
        .await;

    let session = session_at(&server.uri()).await;
    let result = session
        .authorize(
            "cid",
            "https://otp.shu.edu.cn//Callback.aspx",
            "read write",
            "",
        )
        .await?;
    assert!(result.needs_login);
    assert_eq!(result.code, None);
    Ok(())
}

// ---------------------------------------------------------------------------
// 公钥：抓取链与回退
// ---------------------------------------------------------------------------

#[tokio::test]
async fn public_key_fetched_via_bundle_chain() -> Result<()> {
    let (pub_key, _priv) = test_keypair();
    let pem = pem_of(&pub_key);
    // chunk 里的 PEM 可能是单行形态，验证 normalize
    let single_line = pem.replace('\n', "");

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/oauth2/login/"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(r#"<script src="/umi.abc123.js"></script>"#),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/umi.abc123.js"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"chunkMap={"/p__oauth2__login__index.def456.async.js":1}"#),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/p__oauth2__login__index.def456.async.js"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(format!(r#"var Pe="{}";v.setPublicKey(Pe)"#, single_line)),
        )
        .mount(&server)
        .await;

    let session = session_at(&server.uri()).await;
    let got = session.public_key_pem().await?;
    assert!(got.starts_with("-----BEGIN PUBLIC KEY-----"));
    // 规范化后 64 列换行、可解析
    let key = rsa::RsaPublicKey::from_public_key_pem(&got).expect("parseable");
    assert_eq!(key, pub_key);
    Ok(())
}

#[tokio::test]
async fn public_key_falls_back_to_builtin() -> Result<()> {
    // 空服务器（所有请求 404）→ 走内置回退公钥
    let server = MockServer::start().await;
    let session = session_at(&server.uri()).await;
    let got = session.public_key_pem().await?;
    assert_eq!(got, shuvpn_core::sso::FALLBACK_RSA_PUBLIC_KEY_PEM);
    // 内置回退公钥必须可解析（防手抖改坏常量）
    rsa::RsaPublicKey::from_public_key_pem(&got).expect("fallback parseable");
    Ok(())
}

// ---------------------------------------------------------------------------
// 会话 cookie 持久化
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cookies_roundtrip_through_file() -> Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/userLogin"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"message": "success"}))
                .insert_header("Set-Cookie", "SHU_OAUTH2=sess-token-xyz; Path=/; HttpOnly"),
        )
        .mount(&server)
        .await;

    let session = session_with_key(&server.uri(), &pem_of(&test_keypair().0)).await;
    assert!(!session.has_session_cookie());
    session.login("u", "p", &otp_login_params()).await?;
    assert!(session.has_session_cookie());

    let path =
        std::env::temp_dir().join(format!("shuvpn-test-cookies-{}.json", std::process::id()));
    session.save_cookies(&path)?;

    // 新会话从文件恢复
    let session2 = session_at(&server.uri()).await;
    assert!(session2.load_cookies(&path)?);
    assert!(session2.has_session_cookie());
    let _ = std::fs::remove_file(&path);
    Ok(())
}
