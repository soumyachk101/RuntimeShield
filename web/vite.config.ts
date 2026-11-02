import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // The control plane is same-origin in dev via this proxy; the UI
    // never embeds the control-plane address in code.
    proxy: {
      "/v1": {
        target: process.env.RUNSHIELD_CONTROL_PLANE ?? "http://localhost:8080",
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: "node",
    globals: true,
  },
});
