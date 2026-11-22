//! 统一错误类型：网络失败、协议异常、页面解析失败分门别类，便于上层
//! 决定「静默重试 / 提示用户输验证码 / 提示学校改版」。

/// 协议核心统一错误。
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// HTTP 请求层失败（超时、连接拒绝、TLS 等）。
    #[error("HTTP 请求失败: {0}")]
    Http(#[from] reqwest::Error),

    /// 服务端返回了协议之外的响应（如 message 非 success、缺少字段）。
    #[error("协议错误: {0}")]
    Protocol(String),

    /// 页面/响应解析失败 —— 多半是学校改版，需要人工核对 docs/protocol.md。
    #[error("解析失败: {0}")]
    Parse(String),

    /// SSO 会话失效（302 回登录页 / 非 200），需要重新登录。
    #[error("SSO 会话失效，需要重新登录")]
    SessionExpired,

    /// SSO 要求两步验证，等待用户输入验证码。
    #[error("需要两步验证（验证码已发送至 {0:?}）")]
    TwoStepRequired(TwoStepMethod),
}

/// 两步验证通道（对应 SSO `twoStepMethods` 的可用键）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TwoStepMethod {
    /// 企业微信。
    Wecom,
    /// 手机短信。
    Sms,
}

impl TwoStepMethod {
    /// 接口里使用的字符串值。
    pub fn as_str(self) -> &'static str {
        match self {
            TwoStepMethod::Wecom => "wecom",
            TwoStepMethod::Sms => "sms",
        }
    }
}

/// 核心层统一 `Result` 别名。
pub type Result<T> = std::result::Result<T, CoreError>;
