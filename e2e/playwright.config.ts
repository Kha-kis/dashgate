import { defineConfig, devices } from "@playwright/test";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

const projectRoot = path.resolve(__dirname, "..");
const exeName = process.platform === "win32" ? "dashgate.exe" : "dashgate";

// Create a fresh temp directory for the test database
const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "dashgate-e2e-"));

export default defineConfig({
  testDir: "./tests",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: process.env.CI ? "github" : "html",
  timeout: 30_000,
  expect: {
    timeout: 5_000,
  },
  use: {
    baseURL: "http://localhost:1740",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },
  webServer: {
    command: path.join(projectRoot, exeName),
    url: "http://localhost:1740/health",
    reuseExistingServer: !!process.env.BASE_URL,
    timeout: 15_000,
    stdout: "pipe",
    stderr: "pipe",
    env: {
      ...(process.env as Record<string, string>),
      CONFIG_PATH: path.join(__dirname, "helpers", "test-config.yaml"),
      DB_PATH: path.join(tempDir, "dashgate.db"),
      ICONS_PATH: path.join(projectRoot, "static", "icons"),
      PORT: "1740",
      COOKIE_SECURE: "false",
      TEMPLATES_PATH: path.join(projectRoot, "templates"),
      STATIC_PATH: path.join(projectRoot, "static"),
      DEV_MODE: "false",
      LOGIN_RATE_LIMIT: "1000",
    },
  },
  projects: [
    {
      name: "setup",
      testMatch: "setup.spec.ts",
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "main",
      testIgnore: ["setup.spec.ts", "oidc.spec.ts"],
      dependencies: ["setup"],
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "oidc",
      testMatch: "oidc.spec.ts",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
