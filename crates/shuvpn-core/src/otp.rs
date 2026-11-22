//! OTP 令牌站（otp.shu.edu.cn）取码协议。
//!
//! 站点为 ASP.NET WebForms 单页，规格见 `docs/protocol.md` §5：
//! state 预热（state + `ASP.NET_SessionId`）→ SSO authorize → Callback.aspx
//! （`Refresh` 头跳转，非 302）→ `Default.aspx` 解析口令。
//!
//! 口令由服务端渲染进 `<span>`，**不做本地 TOTP 推算**（避免时钟漂移）；
//! 口令每 30 秒轮换，取码节拍由调用方决定。

use std::sync::{Arc, LazyLock};
use std::time::Instant;

use regex::{Regex, RegexBuilder};
use url::Url;

use crate::error::{CoreError, Result};
use crate::session::{ShuSession, HTML_ACCEPT};
use crate::sso;

// ---------------------------------------------------------------------------
// 协议常量
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// 类型
// ---------------------------------------------------------------------------

/// 一次取码的结果。
#[derive(Debug, Clone)]
pub struct OtpCode {
    /// 6 位动态口令。
    pub code: String,
    /// 账户名（页面 `DataList1_LabelAccount_N`，用于确认登录的是本账号）。
    pub account: String,
    /// 剩余有效秒数（`Refresh` 头，缺失时按页面脚本，再缺按周期）。
    pub remaining_secs: u64,
    /// 轮换周期（秒）。
    pub period_secs: u64,
    /// 取码时刻（本地单调时钟起点，用于实时倒计时）。
    pub fetched_at: Instant,
}

impl OtpCode {
    /// 距失效还剩多少秒（实时计算，可为负）。
    pub fn valid_for(&self) -> f64 {
        self.remaining_secs as f64 - self.fetched_at.elapsed().as_secs_f64()
    }
}

impl std::fmt::Display for OtpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 6 位口令按 3+3 分组，念/抄都方便
        if self.code.len() == OTP_CODE_LEN {
            write!(f, "{} {}", &self.code[..3], &self.code[3..])
        } else {
            write!(f, "{}", self.code)
        }
    }
}

/// 一次页面解析的中间结果（供 [`parse_page`] 直测）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedPage {
    pub code: String,
    pub account: String,
    pub remaining_from_js: Option<u64>,
    pub period: Option<u64>,
}

// ---------------------------------------------------------------------------
// 解析（纯函数，离线直测）
// ---------------------------------------------------------------------------

fn code_regex() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        RegexBuilder::new(CODE_PATTERN)
            .build()
            .expect("valid regex")
    });
    &RE
}

fn account_regex() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        RegexBuilder::new(ACCOUNT_PATTERN)
            .build()
            .expect("valid regex")
    });
    &RE
}

fn remain_js_regex() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        RegexBuilder::new(REMAIN_JS_PATTERN)
            .build()
            .expect("valid regex")
    });
    &RE
}

fn total_js_regex() -> &'static Regex {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        RegexBuilder::new(TOTAL_JS_PATTERN)
            .build()
            .expect("valid regex")
    });
    &RE
}

/// 从 `Default.aspx` 页面 HTML 解析口令等数据。
///
/// 口令缺失 → [`CoreError::Parse`]（会话失效或站点改版）；长度非
/// [`OTP_CODE_LEN`] → [`CoreError::Parse`]（站点改版，需要人工核对协议文档）。
pub(crate) fn parse_page(html: &str) -> Result<ParsedPage> {
    let code = code_regex()
        .captures(html)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .ok_or_else(|| {
            CoreError::Parse(format!(
                "页面里没有找到口令节点（会话可能已失效或站点改版）: {}",
                preview(html)
            ))
        })?;
    if code.len() != OTP_CODE_LEN {
        return Err(CoreError::Parse(format!(
            "口令长度异常（期望 {OTP_CODE_LEN} 位，实际 {} 位：{code}），站点可能已改版",
            code.len()
        )));
    }
    let account = account_regex()
        .captures(html)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string())
        .unwrap_or_default();
    let remaining_from_js = remain_js_regex()
        .captures(html)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse().ok());
    let period = total_js_regex()
        .captures(html)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse().ok());
    Ok(ParsedPage {
        code,
        account,
        remaining_from_js,
        period,
    })
}

/// 压平空白后截一段正文预览。
fn preview(html: &str) -> String {
    let flat: String = html.split_whitespace().collect::<Vec<_>>().join(" ");
    flat.chars().take(160).collect()
}

// ---------------------------------------------------------------------------
// OTP 客户端
// ---------------------------------------------------------------------------

/// OTP 站点取码客户端：复用 [`ShuSession`] 的 cookie jar 与 HTTP 底座。
pub struct OtpClient {
    session: Arc<ShuSession>,
    base: String,
}

impl OtpClient {
    /// 使用默认站点地址构建。
    pub fn new(session: Arc<ShuSession>) -> Self {
        Self {
            session,
            base: OTP_BASE.to_string(),
        }
    }

    /// 测试/自定义入口地址。
    pub fn with_base(session: Arc<ShuSession>, base: impl Into<String>) -> Self {
        Self {
            session,
            base: base.into(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base.trim_end_matches('/'), path)
    }

    /// 完整换会话流程：预热 state → authorize → Callback → Default.aspx。
    /// 成功后 OTP 站会话建立，并顺带返回首次取到的口令。
    pub async fn redeem(&self) -> Result<OtpCode> {
        // ① 预热：GET / 不跟随重定向，取 Location 里的 state，
        //    同时种下 ASP.NET_SessionId（缺了 Callback 会报「State验证失败」）
        let resp = self
            .session
            .http()
            .get(self.url("/"))
            .header("Accept", HTML_ACCEPT)
            .send()
            .await?;
        let location = header_str(&resp, "location");
        if location.is_empty() {
            return Err(CoreError::Parse(
                "OTP 预热响应没有 Location（站点可能已改版）".into(),
            ));
        }
        let state = Url::parse(&location)
            .ok()
            .and_then(|u| {
                u.query_pairs()
                    .find(|(k, _)| k == "state")
                    .map(|(_, v)| v.into_owned())
            })
            .ok_or_else(|| CoreError::Parse(format!("OTP 预热 Location 缺少 state: {location}")))?;

        // ② SSO authorize（state 原样透传，docs/protocol.md §4）
        let auth = self
            .session
            .authorize(
                sso::OTP_CLIENT_ID,
                sso::OTP_REDIRECT_URI,
                sso::OTP_SCOPE,
                &state,
            )
            .await?;
        if auth.needs_login {
            return Err(CoreError::SessionExpired);
        }
        if auth.location.is_empty() {
            return Err(CoreError::Protocol(
                "authorize 未返回重定向地址，无法换取 OTP 会话".into(),
            ));
        }

        // ③ Callback.aspx：校验 state 后用 Refresh 头跳转（非 302），手动跟进
        let resp = self
            .session
            .http()
            .get(&auth.location)
            .header("Accept", HTML_ACCEPT)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(CoreError::SessionExpired);
        }
        let final_url = resp.url().to_string();

        // ④ 最终 URL 不在 Default.aspx 时跟进一次，并做成功判定
        if !final_url.contains(SUCCESS_URL_MARKER) {
            let resp = self
                .session
                .http()
                .get(self.url("/Default.aspx"))
                .header("Accept", HTML_ACCEPT)
                .send()
                .await?;
            if !resp.status().is_success() {
                return Err(CoreError::SessionExpired);
            }
            // URL 已确认；正文特征作二次信号，缺失时告警（解析层仍会 fail loud）
            let body = resp.text().await?;
            if !body.contains(SUCCESS_BODY_MARKER) {
                log::warn!(
                    "Default.aspx 未检测到「{}」，站点可能已改版",
                    SUCCESS_BODY_MARKER
                );
            }
        }
        self.fetch_code().await
    }

    /// 取一次当前口令（登录态下 `GET /` 直接返回整页）。
    pub async fn fetch_code(&self) -> Result<OtpCode> {
        let resp = self
            .session
            .http()
            .get(self.url("/"))
            .header("Accept", HTML_ACCEPT)
            .send()
            .await?;
        // 登录态下是 200；302/4xx 说明被踢回 newsso（会话失效）
        if !resp.status().is_success() {
            return Err(CoreError::SessionExpired);
        }
        let refresh = header_str(&resp, "refresh");
        let html = resp.text().await?;
        let parsed = parse_page(&html)?;

        // 剩余秒数：Refresh 头（纯数字）优先，缺失时退回页面脚本，再缺按周期
        let remaining = refresh
            .parse::<u64>()
            .ok()
            .or(parsed.remaining_from_js)
            .unwrap_or(OTP_DEFAULT_PERIOD_SECS);
        let period = parsed.period.unwrap_or(OTP_DEFAULT_PERIOD_SECS);

        Ok(OtpCode {
            code: parsed.code,
            account: parsed.account,
            remaining_secs: remaining,
            period_secs: period,
            fetched_at: Instant::now(),
        })
    }
}

/// 读响应头（小写化匹配，取不到为空串）。
fn header_str(resp: &reqwest::Response, name: &str) -> String {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page_html(code: &str, account: &str, remaining: u64, period: u64) -> String {
        format!(
            r#"<html><body>
<span id="DataList1_LabelNum_0" style="font-weight:bold">{code}</span>
<span id="DataList1_LabelAccount_0">{account}</span>
<script>let remainingSeconds = {remaining}; const totalSeconds = {period};</script>
</body></html>"#
        )
    }

    #[test]
    fn parse_page_extracts_all_fields() {
        let p = parse_page(&page_html("956370", "25120000", 14, 30)).expect("parse ok");
        assert_eq!(p.code, "956370");
        assert_eq!(p.account, "25120000");
        assert_eq!(p.remaining_from_js, Some(14));
        assert_eq!(p.period, Some(30));
    }

    #[test]
    fn parse_page_missing_code_is_parse_error() {
        let err = parse_page("<html>登录引导页</html>").expect_err("should fail");
        assert!(matches!(err, CoreError::Parse(ref m) if m.contains("口令节点")));
    }

    #[test]
    fn parse_page_wrong_length_is_parse_error() {
        let html = page_html("12345678", "25120000", 10, 30);
        let err = parse_page(&html).expect_err("should fail");
        assert!(matches!(err, CoreError::Parse(ref m) if m.contains("长度异常")));
    }

    #[test]
    fn parse_page_tolerates_attribute_variants() {
        // 单引号 + 多余空白 + 前缀数字位（_1 索引）
        let html = r#"<span id='DataList1_LabelNum_1'  class="num"> 685970 </span>"#;
        let p = parse_page(html).expect("parse ok");
        assert_eq!(p.code, "685970");
    }

    #[test]
    fn display_groups_six_digit_code() {
        let otp = OtpCode {
            code: "956370".into(),
            account: String::new(),
            remaining_secs: 30,
            period_secs: 30,
            fetched_at: Instant::now(),
        };
        assert_eq!(otp.to_string(), "956 370");
    }
}
