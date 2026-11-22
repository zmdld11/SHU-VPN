//! 会话保障流程：探测会话 →（失效时）登录 →（需要时）2FA → OTP 就绪。
//!
//! 2FA 验证码通过 [`CodePrompt`] 异步回调获取：CLI 传终端实现、桌面端传
//! UI 弹窗实现，core 不关心提示形态。通道选择优先级
//! 「显式 preferred > sms（用户偏好）> 服务端首个 > sms」与 probe 一致。

use async_trait::async_trait;

use crate::error::Result;
use crate::session::ShuSession;
use crate::sso::{otp_login_params, OTP_CLIENT_ID, OTP_REDIRECT_URI, OTP_SCOPE};
use crate::TwoStepMethod;

/// 2FA 验证码获取回调抽象。
///
/// 调用前 core 已完成发码（`twoStep/send`）；实现方负责把「等待验证码」
/// 呈现给用户并返回输入值。取消/超时由实现方以错误表示，core 原样上抛。
#[async_trait]
pub trait CodePrompt: Send + Sync {
    async fn prompt(&self, method: TwoStepMethod) -> Result<String>;
}

/// 确保 [`ShuSession`] 处于可用 SSO 会话：
///
/// 1. 已有会话 cookie 时先用 authorize 探测，未被踢回登录页即认为有效；
/// 2. 无 cookie 或已失效则 `userLogin` 登录；`twoStepRequired` 时按优先级
///    选通道发码，经回调取验证码提交。
///
/// 成功后调用方应调用 `save_cookies` 持久化会话。
pub async fn ensure_session(
    session: &ShuSession,
    username: &str,
    password: &str,
    preferred: TwoStepMethod,
    prompt: &dyn CodePrompt,
) -> Result<()> {
    if session.has_session_cookie() {
        let auth = session
            .authorize(OTP_CLIENT_ID, OTP_REDIRECT_URI, OTP_SCOPE, "")
            .await?;
        if !auth.needs_login {
            return Ok(());
        }
    }

    let params = otp_login_params();
    let resp = session.login(username, password, &params).await?;
    if !resp.two_step_required {
        return Ok(());
    }

    // 通道优先级：preferred（须在可用列表中）> sms > 服务端首个 > sms
    let method = if resp.two_step_methods.contains(&preferred) {
        preferred
    } else {
        resp.two_step_methods
            .iter()
            .find(|m| **m == TwoStepMethod::Sms)
            .copied()
            .or_else(|| resp.two_step_methods.first().copied())
            .unwrap_or(TwoStepMethod::Sms)
    };
    session.send_2fa(method).await?;
    let code = prompt.prompt(method).await?;
    session
        .verify_2fa(username, password, &params, &code, method)
        .await?;
    Ok(())
}
