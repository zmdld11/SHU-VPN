//! 凭据安全存储抽象。
//!
//! 桌面端实现基于操作系统凭据库（Windows 凭据管理器 / macOS 钥匙串 /
//! Linux Secret Service）；未来安卓伴侣端注入 Keystore 实现。
//! core 只依赖本 trait 与 [`OsSecretStore`]，不直接接触平台 API。

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

/// 操作系统凭据库实现（keyring crate：Windows 凭据管理器等）。
///
/// key 约定：`vpn.username` / `vpn.password` / `sso.session` 等，
/// 作为凭据条目的「用户名」字段存储（同一 service 下互不冲突）。
pub struct OsSecretStore {
    service: String,
}

impl OsSecretStore {
    /// 以应用名作为凭据 service 标识（如 `SHU-VPN`）。
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }
}

impl SecretStore for OsSecretStore {
    fn get(&self, key: &str) -> crate::Result<Option<String>> {
        let entry = keyring::Entry::new(&self.service, key)
            .map_err(|e| crate::CoreError::Protocol(format!("凭据条目创建失败: {e}")))?;
        match entry.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(crate::CoreError::Protocol(format!("凭据读取失败: {e}"))),
        }
    }

    fn set(&self, key: &str, value: &str) -> crate::Result<()> {
        let entry = keyring::Entry::new(&self.service, key)
            .map_err(|e| crate::CoreError::Protocol(format!("凭据条目创建失败: {e}")))?;
        entry
            .set_password(value)
            .map_err(|e| crate::CoreError::Protocol(format!("凭据写入失败: {e}")))
    }

    fn delete(&self, key: &str) -> crate::Result<()> {
        let entry = keyring::Entry::new(&self.service, key)
            .map_err(|e| crate::CoreError::Protocol(format!("凭据条目创建失败: {e}")))?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(crate::CoreError::Protocol(format!("凭据删除失败: {e}"))),
        }
    }
}
