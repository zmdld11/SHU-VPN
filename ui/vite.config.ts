import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

// Tauri 前端约定：固定端口、不清屏、浏览器目标对齐 WebView2
export default defineConfig({
  plugins: [vue()],
  clearScreen: false,
  server: {
    port: 5173,
    strictPort: true,
  },
  build: {
    target: "chrome110",
  },
});
