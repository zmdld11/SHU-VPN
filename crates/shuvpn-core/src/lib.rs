//! SHU-VPN 协议核心。
//!
//! 封装上海大学统一身份认证（newsso.shu.edu.cn）登录、OTP 令牌站（otp.shu.edu.cn）
//! 取码与凭据存储抽象。协议规格见仓库 `docs/protocol.md`，模块注释只做索引；
//! 规格与实现不一致时，以 `docs/protocol.md` 为准并同步更新。
//!
//! 设计约束：
//! - 零 UI / Tauri 依赖，可被桌面壳与未来的移动伴侣端复用；
//! - 所有解析点 fail loud（学校改版时明确报错，不静默容错）；
//! - 不做本地 TOTP 推算，口令只从服务端页面读取。

pub mod error;
pub mod flow;
pub mod otp;
pub mod secrets;
pub mod session;
pub mod sso;
pub mod vpn;

pub use error::{CoreError, Result, TwoStepMethod};
