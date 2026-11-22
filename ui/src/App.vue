<script setup lang="ts">
// SHU-VPN 主界面：连接控制 / 状态与日志 / 2FA 验证码弹窗 / 首次使用引导 / 设置。
// 事件契约见 src-tauri/src/lib.rs 的 UiEvent（vpn-event, tag=kind）。
import { nextTick, onMounted, onUnmounted, ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

interface UiEvent {
  kind: "state" | "log" | "notice" | "progress";
  name?: string;
  reason?: string | null;
  line?: string;
  text?: string;
}

interface Settings {
  twoFaMethod: string;
  verifyTls: boolean;
  openvpnPath: string | null;
}

interface StatusInfo {
  status: string;
  hasCredentials: boolean;
  username: string | null;
  settings: Settings;
  openvpnPath: string;
  openvpnFound: boolean;
  msiAvailable: boolean;
}

/** 学校官方 shu.ovpn 下载页（README「配置来源」同款地址） */
const OFFICIAL_DOWNLOAD =
  "https://vpn.shu.edu.cn/system/_content/download.jsp?urltype=news.DownloadAttachUrl&owner=1400141026&wbfileid=26FE81EE4A989F244CACDE8959CAE3BD";

const STATUS_TEXT: Record<string, string> = {
  idle: "未连接",
  connecting: "连接中…",
  connected: "已连接",
  failed: "连接失败",
};

const status = ref("idle");
const stateName = ref("");
const logs = ref<string[]>([]);
const info = ref<StatusInfo | null>(null);
const busy = ref(false);
const installing = ref(false);
const errMsg = ref("");
const logBox = ref<HTMLElement | null>(null);

// 2FA 验证码弹窗
const showCode = ref(false);
const codeMethod = ref("sms");
const codeInput = ref("");
const codeErr = ref("");

// 首次使用账号引导弹窗
const showCreds = ref(false);
const credUser = ref("");
const credPass = ref("");
const credErr = ref("");

let unlisteners: UnlistenFn[] = [];

function now(): string {
  return new Date().toLocaleTimeString("zh-CN", { hour12: false });
}

function log(line: string): void {
  logs.value.push(`[${now()}] ${line}`);
  if (logs.value.length > 400) logs.value.splice(0, logs.value.length - 400);
  nextTick(() => {
    if (logBox.value) logBox.value.scrollTop = logBox.value.scrollHeight;
  });
}

async function refreshStatus(): Promise<void> {
  try {
    info.value = await invoke<StatusInfo>("get_status");
    status.value = info.value.status;
  } catch (e) {
    log("获取状态失败: " + String(e));
  }
}

onMounted(async () => {
  unlisteners.push(
    await listen<UiEvent>("vpn-event", (e) => {
      const ev = e.payload;
      switch (ev.kind) {
        case "state":
          stateName.value = ev.name ?? "";
          if (ev.name === "CONNECTED") {
            status.value = "connected";
            errMsg.value = "";
            log("✓ 已连接（Initialization Sequence Completed）");
          } else if (ev.name === "FAILED") {
            status.value = "failed";
            errMsg.value = ev.reason ?? "连接失败";
            log("✗ 连接失败: " + (ev.reason ?? ""));
          } else if (ev.name === "EXITING") {
            status.value = "idle";
            log("连接已断开" + (ev.reason ? `（${ev.reason}）` : ""));
          } else {
            log(`[state] ${ev.name}${ev.reason ? `（${ev.reason}）` : ""}`);
          }
          break;
        case "log":
          log(ev.line ?? "");
          break;
        case "notice":
          log("⚠ " + (ev.text ?? ""));
          break;
        case "progress":
          log("… " + (ev.text ?? ""));
          break;
      }
    }),
  );
  unlisteners.push(
    await listen<{ method: string }>("2fa-required", (e) => {
      codeMethod.value = e.payload.method;
      codeInput.value = "";
      codeErr.value = "";
      showCode.value = true;
      log("等待输入验证码…");
    }),
  );
  await refreshStatus();
  if (info.value && !info.value.hasCredentials) showCreds.value = true;
});

onUnmounted(() => {
  unlisteners.forEach((f) => f());
  unlisteners = [];
});

async function connect(): Promise<void> {
  errMsg.value = "";
  busy.value = true;
  status.value = "connecting";
  try {
    await invoke("connect");
    log("连接流程已启动");
  } catch (e) {
    const msg = String(e);
    if (msg.startsWith("NO_CREDENTIALS")) {
      showCreds.value = true;
      status.value = "idle";
    } else {
      errMsg.value = msg;
      status.value = "failed";
      log("✗ " + msg);
    }
  } finally {
    busy.value = false;
    await refreshStatus();
  }
}

async function disconnect(): Promise<void> {
  busy.value = true;
  try {
    await invoke("disconnect");
  } catch (e) {
    errMsg.value = String(e);
    log("✗ " + String(e));
  } finally {
    busy.value = false;
    await refreshStatus();
  }
}

async function submitCode(): Promise<void> {
  const code = codeInput.value.trim();
  if (!/^\d{4,8}$/.test(code)) {
    codeErr.value = "请输入 4-8 位数字验证码";
    return;
  }
  try {
    await invoke("submit_2fa_code", { code });
    showCode.value = false;
    log("已提交验证码");
  } catch (e) {
    codeErr.value = String(e);
  }
}

async function cancelCode(): Promise<void> {
  try {
    await invoke("cancel_2fa_code");
  } catch {
    /* 忽略 */
  }
  showCode.value = false;
  status.value = "idle";
  errMsg.value = "已取消验证码输入，可重新点击连接";
}

async function saveCredsAndConnect(): Promise<void> {
  if (!credUser.value.trim() || !credPass.value) {
    credErr.value = "学号与密码不能为空";
    return;
  }
  try {
    await invoke("save_credentials", {
      username: credUser.value.trim(),
      password: credPass.value,
    });
    credPass.value = "";
    showCreds.value = false;
    await refreshStatus();
    await connect();
  } catch (e) {
    credErr.value = String(e);
  }
}

async function saveSettings(): Promise<void> {
  if (!info.value) return;
  try {
    await invoke("save_settings", { settings: info.value.settings });
    await refreshStatus();
    log("设置已保存");
  } catch (e) {
    log("保存设置失败: " + String(e));
    await refreshStatus(); // 回读，放弃非法值
  }
}

async function clearCreds(): Promise<void> {
  if (!window.confirm("确定删除已保存的学号与密码？")) return;
  try {
    await invoke("clear_credentials");
    await refreshStatus();
    log("凭据已清除");
  } catch (e) {
    log(String(e));
  }
}

function openDownload(): void {
  invoke("open_url", { url: OFFICIAL_DOWNLOAD }).catch((e) => log(String(e)));
}

async function installOpenVpn(): Promise<void> {
  installing.value = true;
  try {
    await invoke("install_openvpn");
    await refreshStatus();
    log("✓ OpenVPN 安装完成，可以直接连接");
  } catch (e) {
    errMsg.value = String(e);
    log("✗ OpenVPN 安装失败: " + String(e));
  } finally {
    installing.value = false;
  }
}
</script>

<template>
  <div class="shell">
    <header>
      <div class="brand"><span class="logo">SH</span>SHU-VPN</div>
      <div class="chip" :class="status">{{ STATUS_TEXT[status] || status }}</div>
    </header>

    <main>
      <section class="card hero">
        <div class="state-line">
          <span class="dot" :class="status"></span>
          <span class="state-text">
            {{ STATUS_TEXT[status] || status }}
            <small v-if="stateName && status === 'connecting'">· {{ stateName }}</small>
          </span>
        </div>
        <p v-if="errMsg" class="err">{{ errMsg }}</p>
        <div class="actions">
          <button
            v-if="status !== 'connected'"
            class="primary"
            :disabled="busy || status === 'connecting'"
            @click="connect"
          >
            {{ status === "connecting" ? "连接中…" : "连接" }}
          </button>
          <button v-else class="danger" :disabled="busy" @click="disconnect">断开</button>
        </div>
        <p class="hint">
          连接过程全自动：SSO 会话静默续期、OTP 令牌自动获取；只有需要两步验证时才会弹窗请输入验证码。
        </p>
      </section>

      <section v-if="info && !info.openvpnFound" class="banner warn">
        <template v-if="info.msiAvailable">
          <span>未检测到 OpenVPN——应用内置官方安装包，一键安装即可</span>
          <button class="btn-mini" :disabled="installing" @click="installOpenVpn">
            {{ installing ? "安装中…" : "一键安装" }}
          </button>
        </template>
        <template v-else>
          <span>未检测到 OpenVPN 社区版（{{ info.openvpnPath }}）</span>
          <button class="link" @click="openDownload">前往官方下载</button>
        </template>
      </section>

      <section class="card logs">
        <div class="logs-head">
          <span>运行日志</span>
          <button class="link" @click="logs = []">清空</button>
        </div>
        <div ref="logBox" class="log-box">
          <div v-for="(l, i) in logs" :key="i" class="log-line">{{ l }}</div>
          <div v-if="!logs.length" class="log-empty">暂无日志</div>
        </div>
      </section>

      <details v-if="info" class="card settings">
        <summary>设置</summary>
        <div class="field">
          <label>两步验证通道</label>
          <div class="radio-row">
            <label>
              <input v-model="info.settings.twoFaMethod" type="radio" value="sms" @change="saveSettings" />
              手机短信（推荐）
            </label>
            <label>
              <input v-model="info.settings.twoFaMethod" type="radio" value="wecom" @change="saveSettings" />
              企业微信
            </label>
          </div>
        </div>
        <div class="field">
          <label class="check-row">
            <input v-model="info.settings.verifyTls" type="checkbox" @change="saveSettings" />
            校验服务器 TLS 证书
          </label>
        </div>
        <div class="field">
          <label>OpenVPN 程序</label>
          <p class="muted">
            {{ info.openvpnPath }}{{ info.openvpnFound ? "" : "（未找到，可自装社区版后重启应用）" }}
          </p>
        </div>
        <div class="field">
          <label>账号</label>
          <p class="muted">
            {{ info.username ? `已保存：${info.username}` : "未保存" }}
            <button v-if="info.hasCredentials" class="link" @click="clearCreds">清除记住的密码</button>
          </p>
        </div>
      </details>
    </main>

    <!-- 2FA 验证码弹窗 -->
    <div v-if="showCode" class="mask">
      <div class="modal">
        <h3>输入两步验证码</h3>
        <p>验证码已发送至{{ codeMethod === "sms" ? "手机短信" : "企业微信" }}，5 分钟内有效。</p>
        <input
          v-model="codeInput"
          class="code-input"
          maxlength="8"
          inputmode="numeric"
          placeholder="6 位验证码"
          @keyup.enter="submitCode"
        />
        <p v-if="codeErr" class="err">{{ codeErr }}</p>
        <div class="modal-actions">
          <button class="ghost" @click="cancelCode">取消</button>
          <button class="primary" @click="submitCode">提交</button>
        </div>
      </div>
    </div>

    <!-- 首次使用账号引导 -->
    <div v-if="showCreds" class="mask">
      <div class="modal">
        <h3>保存账号</h3>
        <p>学号与密码将存入 Windows 凭据管理器（本机本账户可读），不会写入任何文件。</p>
        <input v-model="credUser" placeholder="学号 / 工号" @keyup.enter="saveCredsAndConnect" />
        <input
          v-model="credPass"
          type="password"
          placeholder="统一身份认证密码"
          @keyup.enter="saveCredsAndConnect"
        />
        <p v-if="credErr" class="err">{{ credErr }}</p>
        <div class="modal-actions">
          <button class="ghost" @click="showCreds = false">稍后再说</button>
          <button class="primary" @click="saveCredsAndConnect">保存并连接</button>
        </div>
      </div>
    </div>
  </div>
</template>

<style>
:root {
  color-scheme: dark;
  font-family: "Segoe UI", "Microsoft YaHei", system-ui, sans-serif;
}
* {
  box-sizing: border-box;
}
body {
  margin: 0;
  background: transparent;
}
.shell {
  display: flex;
  flex-direction: column;
  gap: 12px;
  padding: 18px 20px;
  min-height: 100vh;
  background: linear-gradient(160deg, #10182b, #1c2740);
  color: #e8ecf4;
  user-select: none;
}
header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.brand {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 18px;
  font-weight: 600;
  letter-spacing: 0.5px;
}
.logo {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 26px;
  height: 26px;
  border-radius: 8px;
  background: #3b6ef5;
  font-size: 12px;
  font-weight: 700;
}
.chip {
  font-size: 12px;
  padding: 3px 12px;
  border-radius: 999px;
  border: 1px solid #33415e;
  color: #93a4c3;
}
.chip.connected {
  color: #34c77b;
  border-color: #34c77b66;
}
.chip.failed {
  color: #ff7b72;
  border-color: #ff7b7266;
}
.chip.connecting {
  color: #f0b429;
  border-color: #f0b42966;
}
main {
  display: flex;
  flex-direction: column;
  gap: 12px;
  flex: 1;
  min-height: 0;
}
.card {
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 14px;
  padding: 16px;
}
.hero {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.state-line {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 22px;
  font-weight: 600;
}
.state-text small {
  font-size: 13px;
  color: #93a4c3;
  font-weight: 400;
}
.dot {
  width: 14px;
  height: 14px;
  border-radius: 50%;
  background: #6b7688;
  flex: none;
}
.dot.connected {
  background: #34c77b;
  box-shadow: 0 0 10px #34c77b88;
}
.dot.connecting {
  background: #f0b429;
  animation: pulse 1.2s ease-in-out infinite;
}
.dot.failed {
  background: #ff7b72;
}
@keyframes pulse {
  50% {
    opacity: 0.35;
  }
}
.err {
  margin: 0;
  color: #ff7b72;
  font-size: 13px;
  word-break: break-all;
}
.actions {
  display: flex;
  gap: 10px;
}
button {
  font: inherit;
  border: none;
  border-radius: 10px;
  padding: 10px 18px;
  cursor: pointer;
  color: #e8ecf4;
}
button:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}
.primary {
  flex: 1;
  background: #3b6ef5;
  font-weight: 600;
}
.primary:hover:not(:disabled) {
  background: #4d7cf7;
}
.danger {
  flex: 1;
  background: #b8443c;
  font-weight: 600;
}
.danger:hover:not(:disabled) {
  background: #cf4f46;
}
.ghost {
  background: rgba(255, 255, 255, 0.08);
}
.link {
  background: none;
  color: #6ea8ff;
  padding: 0 6px;
  font-size: 13px;
}
.btn-mini {
  flex: none;
  background: #f0b429;
  color: #1a1408;
  font-size: 12.5px;
  font-weight: 600;
  padding: 6px 14px;
  border-radius: 8px;
}
.btn-mini:hover:not(:disabled) {
  background: #f6c14b;
}
.link:hover {
  text-decoration: underline;
}
.hint {
  margin: 0;
  font-size: 12px;
  color: #93a4c3;
  line-height: 1.6;
}
.banner.warn {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  background: rgba(240, 180, 41, 0.08);
  border: 1px solid rgba(240, 180, 41, 0.35);
  border-radius: 12px;
  padding: 10px 14px;
  font-size: 13px;
  color: #f0b429;
  word-break: break-all;
}
.logs {
  display: flex;
  flex-direction: column;
  gap: 8px;
  flex: 1;
  min-height: 120px;
}
.logs-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 13px;
  color: #93a4c3;
}
.log-box {
  flex: 1;
  min-height: 110px;
  max-height: 220px;
  overflow-y: auto;
  background: rgba(0, 0, 0, 0.25);
  border-radius: 8px;
  padding: 8px 10px;
  font-family: Consolas, "Courier New", monospace;
  font-size: 11.5px;
  line-height: 1.55;
  user-select: text;
}
.log-line {
  white-space: pre-wrap;
  word-break: break-all;
  color: #b9c4d8;
}
.log-empty {
  color: #6b7688;
}
.settings {
  color: #cdd6e6;
}
.settings summary {
  cursor: pointer;
  font-size: 14px;
}
.field {
  margin-top: 12px;
}
.field > label {
  display: block;
  font-size: 12px;
  color: #93a4c3;
  margin-bottom: 6px;
}
.radio-row {
  display: flex;
  gap: 18px;
  font-size: 13px;
}
.check-row {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px !important;
  color: #cdd6e6 !important;
}
.muted {
  margin: 0;
  font-size: 12.5px;
  color: #93a4c3;
  word-break: break-all;
}
.mask {
  position: fixed;
  inset: 0;
  background: rgba(5, 10, 22, 0.72);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  z-index: 10;
}
.modal {
  width: 100%;
  max-width: 340px;
  background: #182338;
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 14px;
  padding: 20px;
  box-shadow: 0 18px 60px rgba(0, 0, 0, 0.5);
}
.modal h3 {
  margin: 0 0 8px;
  font-size: 17px;
}
.modal p {
  margin: 0 0 12px;
  font-size: 12.5px;
  color: #93a4c3;
  line-height: 1.6;
}
.modal input {
  width: 100%;
  margin-bottom: 10px;
  padding: 10px 12px;
  border-radius: 10px;
  border: 1px solid #33415e;
  background: rgba(0, 0, 0, 0.3);
  color: #e8ecf4;
  font: inherit;
  outline: none;
}
.modal input:focus {
  border-color: #3b6ef5;
}
.code-input {
  font-size: 20px;
  letter-spacing: 8px;
  text-align: center;
}
.modal-actions {
  display: flex;
  gap: 10px;
  margin-top: 6px;
}
.modal-actions .primary,
.modal-actions .ghost {
  flex: 1;
}
</style>
