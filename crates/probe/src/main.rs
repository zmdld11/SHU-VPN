//! SHU-VPN 联调探测 CLI（脚手架占位）。
//!
//! Issue #4 将在此实现交互式端到端探测：读入学号密码（不落盘）→
//! SSO 登录（2FA 时终端输码）→ 抓取 OTP → 打印口令与剩余秒数，
//! 与官网人工比对。当前仅打印协议端点清单。

fn main() {
    println!("SHU-VPN probe —— 联调探测 CLI（脚手架占位）");
    println!();
    println!("协议端点（详见 docs/protocol.md）：");
    println!(
        "  SSO 登录 : {}/oauth/userLogin",
        shuvpn_core::sso::SSO_BASE
    );
    println!(
        "  2FA      : {}/oauth/twoStep/send",
        shuvpn_core::sso::SSO_BASE
    );
    println!(
        "  授权     : {}/oauth/authorize",
        shuvpn_core::sso::SSO_BASE
    );
    println!("  OTP 取码 : {}", shuvpn_core::otp::OTP_BASE);
    println!();
    println!("交互式探测将在 Issue #4 实现。");
}
