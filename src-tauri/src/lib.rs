//! SHU-VPN 桌面壳入口。
//!
//! Issue #5 在此接入 openvpn.exe 进程与 management 接口管理，
//! Issue #6 在此接入托盘常驻与前端 command 桥接。

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("failed to run SHU-VPN");
}
