//! 构建脚本：release 构建注入 requireAdministrator manifest。
//!
//! openvpn.exe 需要 TAP/路由权限（与 openvpn-gui 一致要求管理员运行）；
//! dev 构建保持默认 asInvoker，避免每次调试弹 UAC（调试连接时在
//! 管理员终端跑 `npm run tauri dev` 即可继承提权）。

const ADMIN_MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0" processorArchitecture="*" name="com.zmdld11.shuvpn" type="win32"/>
  <description>SHU-VPN</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2</dpiAwareness>
    </windowsSettings>
  </application>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
</assembly>
"#;

fn main() {
    let mut attrs = tauri_build::Attributes::default();
    if std::env::var("PROFILE").as_deref() == Ok("release") {
        attrs = attrs
            .windows_attributes(tauri_build::WindowsAttributes::new().app_manifest(ADMIN_MANIFEST));
    }
    tauri_build::try_build(attrs).expect("tauri build failed");
}
