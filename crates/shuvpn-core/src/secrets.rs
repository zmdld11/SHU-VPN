//! 凭据安全存储抽象。
//!
//! 桌面端实现基于 Windows 凭据管理器（DPAPI）；未来安卓伴侣端注入
//! Keystore / Keychain 实现。core 只依赖本 trait，不直接接触平台 API。

/// 键值型安全存储抽象。
///
/// 约定：`value` 均为 UTF-8 字符串（密码、序列化后的会话 Cookie 等）。
/// 实现方需保证进程外不可读（由操作系统凭据机制保证），且失败时返回
/// [`crate::CoreError::Protocol`] 并附原始错误信息。
pub trait SecretStore: Send + Sync {
    /// 读取；不存在时返回 `Ok(None)`。
    fn get(&self, key: &str) -> crate::Result<Option<String>>;

    /// 写入（存在则覆盖）。
    fn set(&self, key: &str, value: &str) -> crate::Result<()>;

    /// 删除；不存在时静默成功。
    fn delete(&self, key: &str) -> crate::Result<()>;
}
