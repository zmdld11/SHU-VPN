# SHU-VPN

上海大学（SHU）OpenVPN 特供客户端：把「学号密码 + 每周一次的系统登录 + OTP 令牌手动复制」
全部自动化，只保留一个轻量、正常的界面。

## 它解决什么

学校 VPN 更新后连接流程变成：

> 导入 shu.ovpn → 输学号密码 → （约每周一次）登录统一身份认证 →
> （需要时）输入发送到企业微信/手机的验证码 → 打开 OTP 令牌站复制 6 位口令 → 粘回 VPN 客户端

SHU-VPN 把中间所有环节自动化：SSO 会话静默续期、验证码自动触发发送（用户只输入收到的码）、
OTP 令牌自动抓取并程序化提交给 openvpn.exe。用户操作只剩：**点连接（偶尔输一次验证码）**。

## 架构

```
┌────────────────────────── SHU-VPN (Tauri 2) ──────────────────────────┐
│  ui/            Vue 3 界面（状态 / 日志 / 验证码弹窗 / 设置）          │
│  src-tauri/     桌面壳：托盘常驻、通知、openvpn.exe 进程与             │
│                 management 接口（账密 + static-challenge 应答）        │
│  crates/                                                        │
│   ├── shuvpn-core/   协议核心（无 UI 依赖，未来安卓伴侣模式复用）      │
│   │     ├── sso.rs      SSO 登录 / 2FA / OAuth2 授权                  │
│   │     ├── otp.rs      OTP 令牌站取码                                │
│   │     └── secrets.rs  凭据存储抽象（桌面: Windows 凭据管理器）       │
│   └── probe/         联调探测 CLI                                     │
└───────────────────────────────────────────────────────────────────────┘
        │                                │
        ▼                                ▼
  newsso.shu.edu.cn                openvpn.exe（复用已装社区版）
  otp.shu.edu.cn                   （TAP/驱动由社区版安装器负责）
```

协议细节见 [docs/protocol.md](docs/protocol.md)。

## 状态

| 里程碑 | Issue | 状态 |
| :-- | :-- | :-- |
| 脚手架（workspace / CI / 打包） | #1 | ✅ |
| core-SSO（登录 / 2FA / 授权） | #2 | ✅ |
| core-OTP（预热 / 取码） | #3 | ✅ |
| probe 真实联调 | #4 | ✅ |
| 桌面 VPN 管理（management 接口） | #5 | ✅ 实测 CONNECTED |
| UI + v0.1 发布 | #6 | ✅（v0.1.0） |
| 发布前打磨（毛玻璃 UI / 自启 / 黑窗修复） | #7 | ✅（v0.2.0） |
| 分流模式 / 托盘增强 / 快捷键 / 自定义背景 | #8 #9 | ✅（v0.4.0） |

## 下载

最新版安装包见 [Releases](https://github.com/zmdld11/SHU-VPN/releases/latest)
（`SHU-VPN_x.y.z_x64-setup.exe`，约 7.3 MB，含官方未修改 OpenVPN 2.7.9；安装需管理员权限）。

## 配置来源

仓库内置了学校官方公开分发的连接配置 [`assets/shu.ovpn`](assets/shu.ovpn)（对全体师生相同，
不含任何个人凭据，内含 CA 证书与服务器列表）。`connect` 缺省使用内置配置，也可用
`--config` 指定自备配置。

- 官方下载地址（上海大学信息服务门户）：
  https://vpn.shu.edu.cn/system/_content/download.jsp?urltype=news.DownloadAttachUrl&owner=1400141026&wbfileid=26FE81EE4A989F244CACDE8959CAE3BD
- 学校系统升级导致内置配置失效时，优先以上方地址为准，用 `--config` 指向新文件；
  并欢迎提 issue 同步更新内置配置。

## 内置 OpenVPN（前置依赖）

发布版安装包内嵌**官方未修改**的 OpenVPN 2.7.9 Windows MSI（amd64，官方 Authenticode
签名）：未检测到 OpenVPN 社区版时，应用可一键静默安装（约 30-60s，含官方签名的 TAP
驱动）；已安装则直接复用本机版本，不重复安装。

- 来源：官方原包存于仓库的 [vendor-openvpn-2.7.9](https://github.com/zmdld11/SHU-VPN/releases/tag/vendor-openvpn-2.7.9)
  release（SHA256 指纹锁定在 release 流水线里）；官方 CDN `swupdate.openvpn.org` 作
  兜底来源
- 许可合规：OpenVPN 为 GPLv2，许可全文随包分发
  （`src-tauri/resources/OPENVPN-LICENSE-GPLv2.txt`）；TAP 驱动 tap-windows6 为
  GPL-2.0 / MIT 双许可
- 不修改、不重打包任何 OpenVPN 二进制；升级官方版本只需改 release.yml 里的
  `OPENVPN_MSI_VERSION`
- 开发模式（`npm run tauri dev`）不内嵌 MSI，需自行安装 OpenVPN 社区版

## 开发

前置依赖：Rust (MSVC)、Node.js ≥ 20、WebView2（Win11 自带）、已安装 OpenVPN 社区版
（开发调试需要；发布版未安装时可用内置的一键安装）。

```bash
npm install && npm install --prefix ui   # 安装前端依赖（根 + ui）
npm run tauri dev                        # 本地开发
cargo test --workspace                   # 协议层单测（离线 mock）
cargo clippy --workspace -- -D warnings  # 静态检查
npm run tauri build                      # 打 NSIS 安装包
```

## 免责声明

本项目仅供个人学习与研究，用于自动化**本人账号**的登录流程，不绕过任何认证环节
（验证码仍需本人输入）。使用请遵守学校相关规定；接口随学校系统升级可能失效。

## 致谢

协议链路的公开分析参考（均为独立实现，未复用代码）：
[preca-hoshino/shu-sso-poc](https://github.com/preca-hoshino/shu-sso-poc) ·
[preca-hoshino/shu-otp-poc](https://github.com/preca-hoshino/shu-otp-poc) ·
[BlueFisher/SHU-selfreport](https://github.com/BlueFisher/SHU-selfreport)

## License

[MIT](LICENSE)
