//! OTP 令牌站（otp.shu.edu.cn）取码协议常量与解析模式。
//!
//! 站点为 ASP.NET WebForms 单页。规格见 `docs/protocol.md` §5：
//! state 预热 state + ASP.NET_SessionId → authorize → Callback.aspx
//! （Refresh 头跳转，非 302）→ Default.aspx 解析口令。
//! 实现由 Issue #3 承担。

/// OTP 站点根地址。
pub const OTP_BASE: &str = "https://otp.shu.edu.cn";

/// 口令轮换周期（秒），页面 `const totalSeconds` 缺失时的默认值。
pub const OTP_DEFAULT_PERIOD_SECS: u64 = 30;

/// 口令长度（实测 6 位；匹配放宽到 4-8，非 6 位视为站点改版并报错）。
pub const OTP_CODE_LEN: usize = 6;

/// 口令 span 正则（容忍属性顺序与引号风格变化）。
pub const CODE_PATTERN: &str = r#"id=["']DataList1_LabelNum_\d+["'][^>]*>\s*(\d{4,8})\s*<"#;

/// 账户名 span 正则。
pub const ACCOUNT_PATTERN: &str = r#"id=["']DataList1_LabelAccount_\d+["'][^>]*>\s*([^<]*?)\s*<"#;

/// 页面内联脚本剩余秒数正则（与 `Refresh` 头互为印证，头优先）。
pub const REMAIN_JS_PATTERN: &str = r"let\s+remainingSeconds\s*=\s*(\d+)\s*;";

/// 页面内联脚本周期正则。
pub const TOTAL_JS_PATTERN: &str = r"const\s+totalSeconds\s*=\s*(\d+)\s*;";

/// 成功页面 URL 特征。
pub const SUCCESS_URL_MARKER: &str = "Default.aspx";

/// 成功页面正文特征。
pub const SUCCESS_BODY_MARKER: &str = "账户名";
