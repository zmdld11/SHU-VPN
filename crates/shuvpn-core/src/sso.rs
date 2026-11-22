//! SSO（newsso.shu.edu.cn）登录协议常量与类型。
//!
//! 完整流程规格见 `docs/protocol.md` §2–§4：
//! userLogin（RSA 加密密码）→ 2FA send/verify → SHU_OAUTH2 会话 →
//! /oauth/authorize 取授权码。实现由 Issue #2 承担。

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

/// OAuth2 授权端点（不自动跟随跟随重定向，读 Location）。
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
