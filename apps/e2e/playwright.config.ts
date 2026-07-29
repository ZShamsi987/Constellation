import { defineConfig } from "@playwright/test";

const webPort = 15173;
const controllerPort = 14327;

export default defineConfig({
  testDir: "./tests",
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? "github" : "line",
  outputDir: "../../test-results/playwright",
  use: {
    baseURL: `http://127.0.0.1:${webPort}`,
    browserName: "chromium",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: [
    {
      name: "controller",
      command: `bash scripts/e2e-daemon.sh ${controllerPort}`,
      cwd: "../..",
      url: `http://127.0.0.1:${controllerPort}/ready`,
      timeout: 600_000,
      reuseExistingServer: false,
      stdout: "ignore",
      stderr: "pipe",
      gracefulShutdown: { signal: "SIGTERM", timeout: 5_000 },
    },
    {
      name: "web",
      command: "pnpm --filter @constellation/web dev",
      cwd: "../..",
      env: {
        CONSTELLATION_CONTROLLER_ORIGIN: `http://127.0.0.1:${controllerPort}`,
        CONSTELLATION_WEB_PORT: String(webPort),
      },
      url: `http://127.0.0.1:${webPort}`,
      timeout: 120_000,
      reuseExistingServer: false,
      stdout: "ignore",
      stderr: "pipe",
      gracefulShutdown: { signal: "SIGTERM", timeout: 5_000 },
    },
  ],
});
