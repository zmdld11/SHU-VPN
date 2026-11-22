<script setup lang="ts">
// 脚手架占位界面：Issue #6 替换为完整 UI（状态/日志/验证码弹窗/设置）。
const status = "未连接";
const scaffoldNote = "脚手架阶段 —— 连接逻辑将在 Issue #5 接入";
</script>

<template>
  <main class="shell">
    <header>
      <h1>SHU-VPN</h1>
      <span class="badge">v0.1.0-scaffold</span>
    </header>

    <section class="card">
      <div class="status-dot" :class="{ connected: false }"></div>
      <div>
        <div class="status-label">连接状态</div>
        <div class="status-value">{{ status }}</div>
      </div>
    </section>

    <section class="card muted">
      <p>{{ scaffoldNote }}</p>
      <ul>
        <li>SSO 自动登录 / 2FA —— Issue #2</li>
        <li>OTP 令牌自动抓取 —— Issue #3</li>
        <li>openvpn.exe management 接入 —— Issue #5</li>
        <li>完整界面与托盘 —— Issue #6</li>
      </ul>
    </section>
  </main>
</template>

<style>
:root {
  color-scheme: light dark;
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
  padding: 20px;
  min-height: 100vh;
  background: linear-gradient(160deg, #10182b, #1c2740);
  color: #e8ecf4;
}
header {
  display: flex;
  align-items: baseline;
  gap: 10px;
}
h1 {
  font-size: 22px;
  margin: 0;
  letter-spacing: 0.5px;
}
.badge {
  font-size: 11px;
  color: #93a4c3;
  border: 1px solid #33415e;
  border-radius: 999px;
  padding: 2px 10px;
}
.card {
  display: flex;
  align-items: center;
  gap: 14px;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 14px;
  padding: 18px;
}
.card.muted {
  display: block;
  color: #93a4c3;
  font-size: 13px;
  line-height: 1.7;
}
.status-dot {
  width: 14px;
  height: 14px;
  border-radius: 50%;
  background: #6b7688;
  flex: none;
}
.status-dot.connected {
  background: #34c77b;
  box-shadow: 0 0 10px #34c77b88;
}
.status-label {
  font-size: 12px;
  color: #93a4c3;
}
.status-value {
  font-size: 20px;
  font-weight: 600;
}
</style>
