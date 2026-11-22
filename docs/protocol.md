# SHU SSO / OTP / VPN 协议规格

> 本文档记录本项目依赖的上海大学统一身份认证（newsso）、OTP 令牌站（otp.shu.edu.cn）
> 与 OpenVPN 客户端交互的全部接口事实，是 `shuvpn-core` 实现的唯一依据。
>
> **来源声明**：内容为独立抓包分析 + 社区公开资料交叉验证所得的协议事实描述，
> 不含任何第三方代码。各端点、字段、页面结构均经过实测核对。
> 学校系统改版后本文需同步更新；所有解析点要求 fail loud，不做静默容错。

## 0. 总览

```
应用启动
  │
  ├─ 载入本地会话 Cookie（SHU_OAUTH2，newsso.shu.edu.cn 域）
  │
  ├─ 会话有效 ──→ OTP 取码 ──→ 经 management 接口应答 openvpn.exe ──→ 已连接
  │                                    │
  └─ 会话失效（302/401/403）           │（口令每 30s 轮换，重连/重协商时重新取）
       │
       ├─ SSO 密码登录（RSA 加密，静默）
       │     ├─ 无需 2FA ──→ 会话建立
       │     └─ 需 2FA ──→ 自动触发发码（企微/短信）──→ 用户输入验证码 ──→ 会话建立
       │
       └─ 回到 OTP 取码
```

- 授权码一次性、绑定 state，不可复用。
- `SHU_OAUTH2` 会话 Cookie 在 newsso 域内可跨系统复用，有效期约一周（用户实测），
  过期后重新走登录流程即可，无需重新导入 ovpn。

## 1. 通用约定

| 项 | 值 |
| :-- | :-- |
| SSO Base | `https://newsso.shu.edu.cn` |
| OTP Base | `https://otp.shu.edu.cn` |
| User-Agent | Chrome 桌面 UA（站点不校验，但需像浏览器） |
| Accept | JSON 接口 `application/json, text/plain, */*`；HTML 接口 `text/html,...` |
| Origin / Referer | JSON 接口带 `Origin: <SSO Base>`、`Referer: <SSO Base>/` |
| Request-Id | 登录接口带 `Request-Id: <uuid4>` 请求头 |
| TLS | **默认开启证书校验**。社区实现曾因学校证书链问题禁用校验；本项目在设置中提供开关，默认关闭（即校验开启） |
| Cookie | 用标准 cookie jar 持久化；关键字段 `SHU_OAUTH2`（HttpOnly）与 otp 站的 `ASP.NET_SessionId` |

## 2. SSO 密码登录

`POST https://newsso.shu.edu.cn/oauth/userLogin`（JSON body）

```json
{
  "username": "<学号>",
  "password": "<RSA 加密后的密码，base64>",
  "tenantId": "上海大学",
  "params": "<base64url 无填充，见下>"
}
```

- **密码加密**：RSA **PKCS#1 v1.5**，公钥为学校 1024bit RSA 公钥（公开信息，
  见 §2.2 回退常量），结果 base64 编码。
- **params**：把一个 OAuth2 参数对象 JSON 序列化后做 **base64url（去掉 `=` 填充）**：

  ```json
  {
    "responseType": "code",
    "clientId": "<目标业务系统 client_id>",
    "clientName": "<业务系统名>",
    "scope": "<scope>",
    "redirectUri": "<redirect_uri>",
    "state": ""
  }
  ```

  服务端只校验格式、不关心具体是哪个业务系统。本项目固定使用 OTP 系统的参数（§4）。
- **响应**（JSON）：`{ "message": "success", "twoStepRequired": <bool>,
  "twoStepMethods": { ... } }`。`message != "success"` 时为登录失败（含原因）。

### 2.1 公钥在线获取（缓存 + 回退）

公钥内嵌在前端登录 chunk 中，chunk 名带内容 hash，故运行时按以下链路抓取，
成功后缓存本地；失败时使用内置回退常量（下）：

1. `GET /oauth2/login/` 页面 HTML；
2. 提取清单脚本 URL（`preloadHelper|umi.<hash>.js` 模式）；
3. 在清单中找登录 chunk 名 `p__oauth2__login__index.<hash>.async.js`；
4. 在 chunk JS 里正则提取 `-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----`。

### 2.2 内置回退公钥（学校公钥，公开信息）

```text
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDl/aCgRl9f/4ON9MewoVnV58OL
OU2ALBi2FKc5yIsfSpivKxe7A6FitJjHva3WpM7gvVOinMehp6if2UNIkbaN+plW
f5IwqEVxsNZpeixc4GsbY9dXEk3WtRjwGSyDLySzEESH/kpJVoxO7ijRYqU+2oSR
wTBNePOk1H+LRQokgQIDAQAB
-----END PUBLIC KEY-----
```

## 3. 两步验证（2FA）

登录响应 `twoStepRequired == true` 时：

| 步骤 | 端点 | Body |
| :-- | :-- | :-- |
| 发码 | `POST /oauth/twoStep/send` | `{"method": "wecom" \| "sms"}` |
| 校验 | `POST /oauth/twoStep/verify` | `{"username", "password"(重新 RSA 加密), "tenantId", "params", "code", "method"}` |

- 可用通道以 `twoStepMethods` 的键为准；本项目默认 `wecom`，设置中可切换 `sms`。
- 发码与校验响应均为 `{ "message": "success" }` 判定。
- 校验成功后响应 `Set-Cookie: SHU_OAUTH2=...`（HttpOnly，newsso 域），会话建立。

## 4. OAuth2 授权（以 OTP 系统为例）

OTP 系统在 SSO 侧的客户端参数（公开常量，非机密）：

| 参数 | 值 |
| :-- | :-- |
| client_id | `05Q1L8woQK5350aK1U5o5GKh411ar3h1` |
| client_name | `OTP令牌` |
| redirect_uri | `https://otp.shu.edu.cn//Callback.aspx`（注意是**双斜杠**，原样使用） |
| scope | `read write` |

```
GET /oauth/authorize
    ?response_type=code
    &client_id=05Q1L8woQK5350aK1U5o5GKh411ar3h1
    &redirect_uri=https%3a%2f%2fotp.shu.edu.cn%2f%2fCallback.aspx
    &scope=read+write
    &state=<state>
```

- **禁止自动跟随重定向**，读 `Location` 响应头：
  - 含 `code=` → 授权码获取成功；
  - 含 `/oauth2/login/` → SSO 会话失效，需重新登录。

## 5. OTP 令牌站（otp.shu.edu.cn，ASP.NET WebForms / IIS）

### 5.1 state 预热（必须）

```
GET https://otp.shu.edu.cn/          ← 不跟随重定向
```

- 从 `Location` 查询串提取 `state` 参数（后续 authorize 原样携带）；
- 同时该响应种下 `ASP.NET_SessionId` Cookie。**不做预热直接走 authorize，
  Callback.aspx 会报「State验证失败」**。

### 5.2 回调换会话

```
GET <authorize 的 Location>          ← 即 Callback.aspx?code=...&state=...
```

- Callback.aspx 校验 state 后用 **`Refresh: 0;url=Default.aspx` 响应头**跳转
  （不是 302，HTTP 客户端不会自动跟随），需手动再请求一次：
  `GET https://otp.shu.edu.cn/Default.aspx`。
- 成功判定：最终 URL 含 `Default.aspx`，或响应体含「账户名」。

### 5.3 取码与解析

登录态下 `GET https://otp.shu.edu.cn/` 直接返回 HTTP 200 整页（等价 `/Default.aspx`，
少一跳）。口令由服务端渲染，**不做本地 TOTP 推算**（避免时钟漂移）：

| 数据 | 位置 | 说明 |
| :-- | :-- | :-- |
| 口令 | `id="DataList1_LabelNum_<N>"` span 文本 | 6 位数字（匹配放宽为 4-8 位，非 6 位即报错） |
| 账户名 | `id="DataList1_LabelAccount_<N>"` span 文本 | 用于确认登录的是本账号 |
| 剩余秒数 | `Refresh` 响应头（纯数字），缺失时取页面 `let remainingSeconds = N;` | 两者实测一致 |
| 周期 | 页面 `const totalSeconds = N;`，缺失时按 30s | 口令每 30s 轮换 |

解析正则（容忍属性顺序与引号风格变化）：

```text
code:    id=["']DataList1_LabelNum_\d+["'][^>]*>\s*(\d{4,8})\s*<
account: id=["']DataList1_LabelAccount_\d+["'][^>]*>\s*([^<]*?)\s*<
remain:  let\s+remainingSeconds\s*=\s*(\d+)\s*;
period:  const\s+totalSeconds\s*=\s*(\d+)\s*;
```

**失效特征**：HTTP 非 200 / 302 回 newsso → 触发 §2 重新登录。

## 6. OpenVPN 侧

- `shu.ovpn` 使用 **static-challenge**（账密验证后客户端弹出独立验证码输入框）。
- 本项目不弹窗，而是以参数化方式运行社区版 `openvpn.exe`
  （默认 `C:\Program Files\OpenVPN\bin\openvpn.exe`）：
  `--management 127.0.0.1 <随机端口>` + `--auth-retry interact` +
  `--management-query-passwords`，在 management 接口上：
  - 应答账密请求（`Auth` 段：学号 + 统一身份认证密码）；
  - 应答 OTP 挑战（CRV1/CR_TEXT 帧，实现时对照 OpenVPN 2.6 management 文档）。
- **OTP 时效 30s**：连接发起前现取一个；断线重连、TLS 重协商触发重认证时重新取。
- 若 `shu.ovpn` 带 `auth-nocache`，重协商时服务端会重新索要完整凭据，
  management 循环统一处理，无需特殊分支。

## 7. 安全与隐私

- 学号/密码存 **Windows 凭据管理器**（DPAPI）；会话 Cookie 存本地用户目录并收紧 ACL。
- 仓库（含 issue/PR/日志）严禁出现：真实学号、密码、验证码、Cookie、`shu.ovpn` 内容。
  `.gitignore` 已兜底 `*.ovpn`、`*.pem`、`captures/`、`*session*.json` 等。
- 探测/联调产物只写内存或本地未跟踪目录；提交前人工过一遍 `git status`。
