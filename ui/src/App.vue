<script setup lang="ts">
// SHU-VPN 主界面（毛玻璃深色 · 自绘标题栏）：
// 大状态环 + 连接控制 / 日志抽屉 / 设置面板（含开机自启）/ 2FA 与首用引导弹窗。
// 事件契约见 src-tauri/src/lib.rs 的 UiEvent（vpn-event, tag=kind）。
import { computed, nextTick, onMounted, onUnmounted, ref } from "vue";
import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";

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
  hideTray: boolean;
  splitTunnel: boolean;
  wallpaper: string | null;
  hotkey: string | null;
}

interface StatusInfo {
  status: string;
  hasCredentials: boolean;
  username: string | null;
  settings: Settings;
  openvpnPath: string;
  openvpnFound: boolean;
  msiAvailable: boolean;
  routesLearned: number;
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

const win = getCurrentWindow();

const status = ref("idle");
const stateName = ref("");
const logs = ref<string[]>([]);
const info = ref<StatusInfo | null>(null);
const busy = ref(false);
const installing = ref(false);
const errMsg = ref("");
const logBox = ref<HTMLElement | null>(null);
const showLogs = ref(false);
const showSettings = ref(false);

// 开机自启（状态以系统计划任务为唯一事实源，见 lib.rs set_autostart）
const autostart = ref(false);
const autostartBusy = ref(false);

// 自定义背景图（后端存应用数据目录，前端以 data URL 应用）
const wallpaperUrl = ref("");
const wallInput = ref<HTMLInputElement | null>(null);

// 自定义规则文件（分流模式附加路由；后端解析校验）
const rulesText = ref("");
const rulesSummary = ref("");

/** 有背景图时叠加深色渐变遮罩（保证文字可读），无图时保持默认毛玻璃 */
const shellStyle = computed(() =>
  wallpaperUrl.value
    ? {
        backgroundImage: `linear-gradient(rgba(13,18,32,0.78), rgba(13,18,32,0.88)), url(${wallpaperUrl.value})`,
        backgroundSize: "cover",
        backgroundPosition: "center",
      }
    : {},
);

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

async function loadAutostart(): Promise<void> {
  try {
    autostart.value = await invoke<boolean>("get_autostart");
  } catch {
    autostart.value = false;
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
          } else if (ev.name === "CONNECTING") {
            // 托盘/快捷键发起的连接也驱动主窗口动画（见 #9）
            status.value = "connecting";
            errMsg.value = "";
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
  await loadAutostart();
  try {
    wallpaperUrl.value = (await invoke<string | null>("get_wallpaper")) ?? "";
  } catch {
    wallpaperUrl.value = "";
  }
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

async function toggleAutostart(): Promise<void> {
  autostartBusy.value = true;
  const next = !autostart.value;
  try {
    await invoke("set_autostart", { enable: next });
    autostart.value = next;
    log(next ? "✓ 已开启开机自启（下次登录静默启动）" : "已关闭开机自启");
  } catch (e) {
    log("✗ 开机自启设置失败: " + String(e));
  } finally {
    autostartBusy.value = false;
  }
}

async function setTwoFa(method: string): Promise<void> {
  if (!info.value) return;
  info.value.settings.twoFaMethod = method;
  await saveSettings();
}

async function toggleVerifyTls(): Promise<void> {
  if (!info.value) return;
  info.value.settings.verifyTls = !info.value.settings.verifyTls;
  await saveSettings();
}

async function toggleSplitTunnel(): Promise<void> {
  if (!info.value) return;
  const next = !info.value.settings.splitTunnel;
  if (next && info.value.routesLearned === 0) {
    log("⚠ 分流模式需要先正常连接一次以学习校内网段，本次仍将开启但连接前请先全局连接一次");
  }
  info.value.settings.splitTunnel = next;
  await saveSettings();
  await refreshStatus();
}

async function toggleHideTray(): Promise<void> {
  if (!info.value) return;
  info.value.settings.hideTray = !info.value.settings.hideTray;
  await saveSettings();
  log(
    info.value.settings.hideTray
      ? "已隐藏托盘图标：关闭窗口将直接退出应用"
      : "已恢复托盘图标",
  );
}

async function saveHotkey(e: Event): Promise<void> {
  if (!info.value) return;
  const v = (e.target as HTMLInputElement).value.trim();
  if ((info.value.settings.hotkey ?? "") === v) return;
  info.value.settings.hotkey = v === "" ? null : v;
  await saveSettings(); // 格式非法时后端报错 → refreshStatus 回读放弃
}

function pickWallpaper(): void {
  wallInput.value?.click();
}

async function onWallFile(e: Event): Promise<void> {
  const file = (e.target as HTMLInputElement).files?.[0];
  (e.target as HTMLInputElement).value = ""; // 允许重复选同一文件
  if (!file) return;
  if (file.size > 10 * 1024 * 1024) {
    log("✗ 图片过大（上限 10MB）");
    return;
  }
  const dataUrl = await new Promise<string>((resolve, reject) => {
    const r = new FileReader();
    r.onload = () => resolve(r.result as string);
    r.onerror = () => reject(r.error);
    r.readAsDataURL(file);
  }).catch(() => "");
  if (!dataUrl) {
    log("✗ 读取图片失败");
    return;
  }
  try {
    await invoke("set_wallpaper", { data: dataUrl });
    wallpaperUrl.value = dataUrl;
    log("✓ 背景已更新");
  } catch (e) {
    log("✗ 设置背景失败: " + String(e));
  }
}

async function clearWallpaper(): Promise<void> {
  try {
    await invoke("clear_wallpaper");
    wallpaperUrl.value = "";
    log("已恢复默认背景");
  } catch (e) {
    log(String(e));
  }
}

async function loadRules(): Promise<void> {
  try {
    rulesText.value = await invoke<string>("get_custom_rules");
    rulesSummary.value = "";
  } catch (e) {
    log("读取规则失败: " + String(e));
  }
}

function openSettings(): void {
  showSettings.value = true;
  loadRules();
}

async function saveRules(): Promise<void> {
  try {
    const r = await invoke<{ routes: number; hosts: number; errors: string[] }>(
      "save_custom_rules",
      { text: rulesText.value },
    );
    r.errors.forEach((e) => log("⚠ 自定义规则 " + e + "（已跳过）"));
    rulesSummary.value =
      `${r.routes} 条网段 · ${r.hosts} 个域名` +
      (r.errors.length ? ` · ${r.errors.length} 条无效` : " · 格式正确") +
      " · 重连后生效";
    log("✓ 自定义规则已保存（重连后生效）");
  } catch (e) {
    log("✗ 保存规则失败: " + String(e));
  }
}
</script>

<template>
  <div class="shell" :style="shellStyle">
    <!-- 自绘标题栏（无边框窗口）：拖动区 + 窗口控制 -->
    <header class="titlebar" data-tauri-drag-region>
      <div class="brand" data-tauri-drag-region>
        <span class="logo">SH</span>
        <span>SHU-VPN</span>
      </div>
      <div class="win-btns">
        <button class="wbtn" title="最小化" @click="win.minimize()">
          <svg viewBox="0 0 12 12"><path d="M2 6h8" /></svg>
        </button>
        <button class="wbtn" title="最大化/还原" @click="win.toggleMaximize()">
          <svg viewBox="0 0 12 12"><rect x="2.5" y="2.5" width="7" height="7" rx="1" /></svg>
        </button>
        <button class="wbtn close" title="关闭（最小化到托盘）" @click="win.close()">
          <svg viewBox="0 0 12 12"><path d="M3 3l6 6M9 3l-6 6" /></svg>
        </button>
      </div>
    </header>

    <main>
      <!-- 状态环（核心视觉） -->
      <section class="hero">
        <div class="ring" :class="status">
          <div class="ring-icon">
            <!-- idle / connecting：电源符号 -->
            <svg v-if="status !== 'connected' && status !== 'failed'" viewBox="0 0 24 24">
              <path d="M12 3v8" class="ic" />
              <path d="M6.6 6.6a8 8 0 1 0 10.8 0" class="ic" />
            </svg>
            <!-- connected：对勾 -->
            <svg v-else-if="status === 'connected'" viewBox="0 0 24 24">
              <path d="M5 12.5l4.5 4.5L19 8" class="ic" />
            </svg>
            <!-- failed：感叹号 -->
            <svg v-else viewBox="0 0 24 24">
              <path d="M12 5v9" class="ic" />
              <path d="M12 17.8v.4" class="ic dot-line" />
            </svg>
          </div>
        </div>
        <div class="state-text">{{ STATUS_TEXT[status] || status }}</div>
        <div v-if="stateName && status === 'connecting'" class="state-sub">{{ stateName }}</div>
        <p v-if="errMsg" class="err">{{ errMsg }}</p>

        <button
          v-if="status !== 'connected'"
          class="main-btn"
          :disabled="busy || status === 'connecting'"
          @click="connect"
        >
          {{ status === "connecting" ? "连接中…" : "连接 VPN" }}
        </button>
        <button v-else class="main-btn stop" :disabled="busy" @click="disconnect">断开连接</button>
        <p class="hint">全自动连接：SSO 续期、OTP 令牌自动获取；仅两步验证时需要你输入验证码。</p>
      </section>

      <!-- OpenVPN 缺失提示 -->
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

      <!-- 运行日志抽屉 -->
      <section class="log-drawer" :class="{ open: showLogs }">
        <div class="clip">
          <div ref="logBox" class="log-box">
            <div v-for="(l, i) in logs" :key="i" class="log-line">{{ l }}</div>
            <div v-if="!logs.length" class="log-empty">暂无日志</div>
          </div>
        </div>
      </section>

      <!-- 底部工具行 -->
      <footer class="dock">
        <button class="dock-btn" @click="openSettings">
          <svg viewBox="0 0 16 16">
            <circle cx="8" cy="8" r="2.2" />
            <path
              d="M8 1.8v1.6M8 12.6v1.6M1.8 8h1.6M12.6 8h1.6M3.6 3.6l1.1 1.1M11.3 11.3l1.1 1.1M12.4 3.6l-1.1 1.1M4.7 11.3l-1.1 1.1"
            />
          </svg>
          设置
        </button>
        <div class="dock-spacer"></div>
        <button class="dock-btn" :class="{ on: showLogs }" @click="showLogs = !showLogs">
          运行日志<span v-if="logs.length" class="count">{{ logs.length }}</span>
          <svg viewBox="0 0 16 16" class="chev" :class="{ flip: showLogs }">
            <path d="M4 6.5l4 4 4-4" />
          </svg>
        </button>
        <button v-if="showLogs" class="dock-btn" @click="logs = []">清空</button>
      </footer>
    </main>

    <!-- 2FA 验证码弹窗 -->
    <div v-if="showCode" class="mask" @click.self="cancelCode">
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
    <div v-if="showCreds" class="mask" @click.self="showCreds = false">
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

    <!-- 设置面板 -->
    <div v-if="showSettings" class="mask" @click.self="showSettings = false">
      <div class="modal settings-panel">
        <h3>设置</h3>

        <div class="field">
          <label>两步验证通道</label>
          <div class="seg">
            <button
              :class="{ sel: info?.settings.twoFaMethod === 'sms' }"
              @click="setTwoFa('sms')"
            >
              手机短信
            </button>
            <button
              :class="{ sel: info?.settings.twoFaMethod === 'wecom' }"
              @click="setTwoFa('wecom')"
            >
              企业微信
            </button>
          </div>
        </div>

        <div class="row">
          <span>校验服务器 TLS 证书</span>
          <button
            class="switch"
            :class="{ on: info?.settings.verifyTls }"
            :disabled="!info"
            @click="toggleVerifyTls"
          ></button>
        </div>

        <div class="row">
          <span>开机自启<small>登录 Windows 后静默启动</small></span>
          <button
            class="switch"
            :class="{ on: autostart }"
            :disabled="autostartBusy"
            @click="toggleAutostart"
          ></button>
        </div>

        <div class="row">
          <span>
            分流模式<small>
              仅校内网段走 VPN，其余流量直连；切换后需重连生效 · 已学习
              {{ info?.routesLearned ?? 0 }} 个网段
            </small>
          </span>
          <button
            class="switch"
            :class="{ on: info?.settings.splitTunnel }"
            :disabled="!info"
            @click="toggleSplitTunnel"
          ></button>
        </div>

        <div class="row">
          <span>隐藏托盘图标<small>隐藏后关闭窗口将直接退出应用</small></span>
          <button
            class="switch"
            :class="{ on: info?.settings.hideTray }"
            :disabled="!info"
            @click="toggleHideTray"
          ></button>
        </div>

        <div class="field">
          <label>自定义背景（PNG / JPEG / WebP / GIF，≤10MB）</label>
          <div class="wall-btns">
            <button class="ghost wall-btn" @click="pickWallpaper">选择图片</button>
            <button v-if="wallpaperUrl" class="ghost wall-btn" @click="clearWallpaper">
              清除
            </button>
          </div>
          <input
            ref="wallInput"
            type="file"
            accept="image/png,image/jpeg,image/webp,image/gif"
            style="display: none"
            @change="onWallFile"
          />
        </div>

        <div class="field">
          <label>全局快捷键（连接 / 断开切换，回车保存；清空关闭）</label>
          <input
            class="hk-input"
            :value="info?.settings.hotkey ?? ''"
            placeholder="Ctrl+Alt+V"
            @keyup.enter="saveHotkey($event)"
            @blur="saveHotkey($event)"
          />
        </div>

        <div class="field">
          <label>自定义规则（分流模式附加，重连生效；每行一条：CIDR 网段 / HOST 域名，# 注释）</label>
          <textarea
            v-model="rulesText"
            class="rules-area"
            rows="6"
            spellcheck="false"
            placeholder="10.60.0.0/16&#10;10.7.0.0 255.0.0.0&#10;HOST cnki.net"
          ></textarea>
          <div class="rules-row">
            <button class="ghost wall-btn" @click="saveRules">保存规则</button>
            <span class="rules-summary">{{ rulesSummary || "仅在分流模式下生效" }}</span>
          </div>
        </div>

        <div class="field">
          <label>OpenVPN 程序</label>
          <p class="muted">
            {{ info?.openvpnPath
            }}{{ info?.openvpnFound ? "" : "（未找到，可自装社区版后重启应用）" }}
          </p>
        </div>

        <div class="field">
          <label>账号</label>
          <p class="muted">
            {{ info?.username ? `已保存：${info.username}` : "未保存" }}
            <button v-if="info?.hasCredentials" class="link" @click="clearCreds">
              清除记住的密码
            </button>
          </p>
        </div>

        <div class="modal-actions">
          <button class="ghost" @click="showSettings = false">关闭</button>
        </div>
      </div>
    </div>
  </div>
</template>

<style>
:root {
  color-scheme: dark;
  font-family: "Segoe UI Variable Display", "Segoe UI", "Microsoft YaHei", system-ui, sans-serif;
}
* {
  box-sizing: border-box;
}
body {
  margin: 0;
  background: transparent;
}
/* acrylic 失效时这层半透明深蓝兜底，不破相 */
.shell {
  display: flex;
  flex-direction: column;
  height: 100vh;
  overflow: hidden;
  background: rgba(13, 18, 32, 0.72);
  color: #e9eef7;
  user-select: none;
}

/* ---------- 自绘标题栏 ---------- */
.titlebar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 44px;
  padding: 0 8px 0 16px;
  flex: none;
}
.brand {
  display: flex;
  align-items: center;
  gap: 9px;
  font-size: 14px;
  font-weight: 600;
  letter-spacing: 0.6px;
}
.logo {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 24px;
  height: 24px;
  border-radius: 7px;
  background: linear-gradient(135deg, #3b82f6, #06b6d4);
  font-size: 11px;
  font-weight: 700;
  color: #fff;
}
.win-btns {
  display: flex;
  gap: 2px;
}
.wbtn {
  width: 40px;
  height: 32px;
  padding: 0;
  border: none;
  border-radius: 8px;
  background: transparent;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}
.wbtn svg {
  width: 12px;
  height: 12px;
  stroke: #a9b6cd;
  stroke-width: 1.2;
  fill: none;
  stroke-linecap: round;
}
.wbtn:hover {
  background: rgba(255, 255, 255, 0.09);
}
.wbtn.close:hover {
  background: #e5484d;
}
.wbtn.close:hover svg {
  stroke: #fff;
}

/* ---------- 主区 ---------- */
main {
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
  padding: 6px 20px 14px;
  gap: 10px;
}
.hero {
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 12px;
}

/* 状态环 */
.ring {
  position: relative;
  width: 108px;
  height: 108px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
}
/* 渐变环身：conic-gradient + mask 挖空成 3px 圆环（状态色由 .ring.<status>::before 覆盖） */
.ring::before {
  content: "";
  position: absolute;
  inset: 0;
  border-radius: 50%;
  padding: 3px;
  background: conic-gradient(from 210deg, #4a5570, #333d52 65%);
  -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
  -webkit-mask-composite: xor;
  mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
  mask-composite: exclude;
}
.ring-icon svg {
  width: 38px;
  height: 38px;
  fill: none;
  stroke-width: 1.8;
  stroke-linecap: round;
}
.ring.idle::before {
  background: conic-gradient(from 210deg, #4a5570, #333d52 65%);
}
.ring.idle .ring-icon svg {
  stroke: #7c8aa5;
}
.ring.connecting::before {
  background: conic-gradient(from 0deg, transparent 15%, #f0b429 85%);
  animation: spin 1.1s linear infinite;
}
.ring.connecting .ring-icon svg {
  stroke: #f0b429;
}
.ring.connected::before {
  background: conic-gradient(from 210deg, #34d399, #06b6d4 85%);
  box-shadow: 0 0 24px rgba(52, 211, 153, 0.35);
}
.ring.connected .ring-icon svg {
  stroke: #45dfab;
}
.ring.failed::before {
  background: conic-gradient(from 210deg, #f87171, #b94446 65%);
}
.ring.failed .ring-icon svg {
  stroke: #f87171;
}
.ring.connecting .ring-icon svg {
  animation: breathe 1.2s ease-in-out infinite;
}
@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}
@keyframes breathe {
  50% {
    opacity: 0.4;
  }
}

.state-text {
  font-size: 21px;
  font-weight: 650;
  letter-spacing: 0.4px;
}
.state-sub {
  margin-top: -8px;
  font-size: 12.5px;
  color: #93a4c3;
  font-family: Consolas, "Courier New", monospace;
}
.err {
  margin: 0;
  max-width: 100%;
  color: #ff8585;
  font-size: 12.5px;
  line-height: 1.5;
  word-break: break-all;
  text-align: center;
  user-select: text;
}

/* 主连接按钮 */
.main-btn {
  min-width: 200px;
  padding: 13px 28px;
  border: none;
  border-radius: 999px;
  font: inherit;
  font-size: 15px;
  font-weight: 650;
  letter-spacing: 1px;
  color: #fff;
  background: linear-gradient(135deg, #3b82f6, #0891b5);
  box-shadow: 0 6px 22px rgba(59, 130, 246, 0.32);
  cursor: pointer;
  transition: transform 0.15s ease, box-shadow 0.15s ease, filter 0.15s ease;
}
.main-btn:hover:not(:disabled) {
  filter: brightness(1.1);
  transform: translateY(-1px);
  box-shadow: 0 8px 26px rgba(59, 130, 246, 0.42);
}
.main-btn:active:not(:disabled) {
  transform: translateY(0);
}
.main-btn.stop {
  background: linear-gradient(135deg, #e5484d, #b94446);
  box-shadow: 0 6px 22px rgba(229, 72, 77, 0.3);
}
.main-btn:disabled {
  opacity: 0.55;
  cursor: not-allowed;
}
.hint {
  margin: 0;
  max-width: 300px;
  font-size: 11.5px;
  color: #7e8cab;
  line-height: 1.7;
  text-align: center;
}

/* ---------- OpenVPN 缺失 banner ---------- */
.banner.warn {
  flex: none;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  background: rgba(240, 180, 41, 0.09);
  border: 1px solid rgba(240, 180, 41, 0.35);
  border-radius: 12px;
  padding: 10px 14px;
  font-size: 12.5px;
  color: #f0b429;
  word-break: break-all;
}
.btn-mini {
  flex: none;
  border: none;
  background: #f0b429;
  color: #1a1408;
  font-size: 12px;
  font-weight: 650;
  padding: 6px 14px;
  border-radius: 8px;
  cursor: pointer;
}
.btn-mini:hover:not(:disabled) {
  background: #f6c14b;
}
.btn-mini:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
.link {
  border: none;
  background: none;
  color: #6ea8ff;
  padding: 0 4px;
  font-size: 12.5px;
  cursor: pointer;
}
.link:hover {
  text-decoration: underline;
}

/* ---------- 日志抽屉（grid-rows 过渡展开） ---------- */
.log-drawer {
  flex: none;
  display: grid;
  grid-template-rows: 0fr;
  transition: grid-template-rows 0.25s ease;
}
.log-drawer.open {
  grid-template-rows: minmax(0, 190px);
}
.log-drawer .clip {
  overflow: hidden;
  min-height: 0;
}
.log-box {
  height: 100%;
  max-height: 190px;
  overflow-y: auto;
  background: rgba(0, 0, 0, 0.28);
  border: 1px solid rgba(255, 255, 255, 0.07);
  border-radius: 10px;
  padding: 8px 12px;
  font-family: Consolas, "Courier New", monospace;
  font-size: 11.5px;
  line-height: 1.6;
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

/* ---------- 底部工具行 ---------- */
.dock {
  flex: none;
  display: flex;
  align-items: center;
  gap: 4px;
  border-top: 1px solid rgba(255, 255, 255, 0.07);
  padding-top: 10px;
}
.dock-spacer {
  flex: 1;
}
.dock-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  border: none;
  background: transparent;
  color: #93a4c3;
  font-size: 12.5px;
  padding: 7px 12px;
  border-radius: 9px;
  cursor: pointer;
}
.dock-btn svg {
  width: 14px;
  height: 14px;
  fill: none;
  stroke: #93a4c3;
  stroke-width: 1.3;
  stroke-linecap: round;
}
.dock-btn:hover {
  background: rgba(255, 255, 255, 0.08);
  color: #e9eef7;
}
.dock-btn:hover svg {
  stroke: #e9eef7;
}
.dock-btn.on {
  color: #6ea8ff;
}
.dock-btn.on svg {
  stroke: #6ea8ff;
}
.count {
  font-size: 10.5px;
  background: rgba(110, 168, 255, 0.16);
  color: #6ea8ff;
  padding: 1px 7px;
  border-radius: 999px;
}
.chev {
  transition: transform 0.25s ease;
}
.chev.flip {
  transform: rotate(180deg);
}

/* ---------- 弹窗 ---------- */
.mask {
  position: fixed;
  inset: 0;
  background: rgba(4, 8, 18, 0.6);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  z-index: 10;
}
.modal {
  width: 100%;
  max-width: 340px;
  max-height: calc(100vh - 48px);
  overflow-y: auto;
  background: rgba(21, 28, 45, 0.94);
  border: 1px solid rgba(255, 255, 255, 0.12);
  border-radius: 16px;
  padding: 20px;
  box-shadow: 0 18px 60px rgba(0, 0, 0, 0.5);
}
.modal h3 {
  margin: 0 0 10px;
  font-size: 16.5px;
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
  color: #e9eef7;
  font: inherit;
  outline: none;
}
.modal input:focus {
  border-color: #3b82f6;
}
.code-input {
  font-size: 20px;
  letter-spacing: 8px;
  text-align: center;
}
.modal-actions {
  display: flex;
  gap: 10px;
  margin-top: 8px;
}
button {
  font: inherit;
}
.modal-actions .primary,
.modal-actions .ghost {
  flex: 1;
  border: none;
  border-radius: 10px;
  padding: 10px 16px;
  font-weight: 600;
  cursor: pointer;
  color: #e9eef7;
}
.primary {
  background: linear-gradient(135deg, #3b82f6, #0891b5);
}
.primary:hover {
  filter: brightness(1.1);
}
.ghost {
  background: rgba(255, 255, 255, 0.08);
}
.ghost:hover {
  background: rgba(255, 255, 255, 0.14);
}

/* ---------- 设置面板 ---------- */
.settings-panel {
  max-width: 360px;
}
.field {
  margin-top: 14px;
}
.field > label {
  display: block;
  font-size: 12px;
  color: #93a4c3;
  margin-bottom: 6px;
}
.seg {
  display: flex;
  background: rgba(0, 0, 0, 0.28);
  border: 1px solid #2b3850;
  border-radius: 10px;
  padding: 3px;
  gap: 3px;
}
.seg button {
  flex: 1;
  border: none;
  background: transparent;
  color: #93a4c3;
  font-size: 13px;
  padding: 7px 0;
  border-radius: 8px;
  cursor: pointer;
}
.seg button.sel {
  background: rgba(59, 130, 246, 0.28);
  color: #dbe7ff;
  font-weight: 600;
}
.row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-top: 14px;
  font-size: 13.5px;
  color: #dde5f2;
}
.row small {
  display: block;
  font-size: 11px;
  color: #7e8cab;
  margin-top: 2px;
}
/* 开关 */
.switch {
  flex: none;
  width: 40px;
  height: 22px;
  border: none;
  border-radius: 999px;
  background: rgba(255, 255, 255, 0.16);
  position: relative;
  cursor: pointer;
  transition: background 0.2s ease;
  padding: 0;
}
.switch::after {
  content: "";
  position: absolute;
  top: 3px;
  left: 3px;
  width: 16px;
  height: 16px;
  border-radius: 50%;
  background: #cfd8ea;
  transition: left 0.2s ease;
}
.switch.on {
  background: linear-gradient(90deg, #3b82f6, #0891b5);
}
.switch.on::after {
  left: 21px;
  background: #fff;
}
.switch:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}
.muted {
  margin: 0;
  font-size: 12px;
  color: #93a4c3;
  word-break: break-all;
  line-height: 1.6;
}
.wall-btns {
  display: flex;
  gap: 8px;
}
.wall-btn {
  border: none;
  border-radius: 9px;
  background: rgba(255, 255, 255, 0.1);
  color: #e9eef7;
  font-size: 12.5px;
  padding: 8px 16px;
  cursor: pointer;
}
.wall-btn:hover {
  background: rgba(255, 255, 255, 0.16);
}
.hk-input {
  width: 100%;
  padding: 9px 12px;
  border-radius: 9px;
  border: 1px solid #33415e;
  background: rgba(0, 0, 0, 0.3);
  color: #e9eef7;
  font: inherit;
  font-size: 13px;
  outline: none;
}
.hk-input:focus {
  border-color: #3b82f6;
}
.rules-area {
  width: 100%;
  padding: 9px 12px;
  border-radius: 9px;
  border: 1px solid #33415e;
  background: rgba(0, 0, 0, 0.3);
  color: #e9eef7;
  font-family: Consolas, "Courier New", monospace;
  font-size: 12px;
  line-height: 1.6;
  outline: none;
  resize: vertical;
  user-select: text;
}
.rules-area:focus {
  border-color: #3b82f6;
}
.rules-row {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-top: 8px;
}
.rules-summary {
  font-size: 11.5px;
  color: #7e8cab;
}
</style>
