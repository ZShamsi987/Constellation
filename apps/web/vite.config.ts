import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "CONSTELLATION_");
  const controller =
    env.CONSTELLATION_CONTROLLER_ORIGIN ?? "http://127.0.0.1:4317";
  const port = Number(env.CONSTELLATION_WEB_PORT ?? "5173");
  return {
    plugins: [react()],
    define:
      mode === "desktop"
        ? {
            "import.meta.env.VITE_API_BASE": JSON.stringify(controller),
          }
        : undefined,
    server: {
      port,
      strictPort: true,
      proxy: {
        "/health": controller,
        "/ready": controller,
        "/v1": controller,
        "/constellation": {
          target: controller,
          ws: true,
        },
      },
    },
  };
});
