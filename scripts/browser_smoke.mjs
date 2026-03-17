#!/usr/bin/env node

import net from "node:net";
import process from "node:process";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "@playwright/test";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, "..");
const dashboardDir = resolve(repoRoot, "dashboard");
const python = resolve(repoRoot, "venv", "bin", "python");
const seedScript = resolve(repoRoot, "scripts", "seed_dev_data.py");

const port = Number(process.env.BROWSER_SMOKE_PORT || "18091");
const smokeMode = process.env.BROWSER_SMOKE_MODE || "full";
const baseUrl = `http://127.0.0.1:${port}`;
const dbPath = process.env.BROWSER_SMOKE_DB || "/tmp/security-dashboard-browser-smoke.db";
const artifactsDir = resolve(repoRoot, "artifacts", "browser-smoke");
const localLibDir = resolve(repoRoot, ".local-playwright-libs", "extracted", "usr", "lib", "x86_64-linux-gnu");

mkdirSync(artifactsDir, { recursive: true });

function runOrThrow(cmd, args, opts = {}) {
  const result = spawnSync(cmd, args, { encoding: "utf-8", ...opts });
  if (result.status !== 0) {
    const msg = [
      `Command failed: ${cmd} ${args.join(" ")}`,
      result.stdout || "",
      result.stderr || "",
    ]
      .join("\n")
      .trim();
    throw new Error(msg);
  }
  return result;
}

function waitForPort(host, openPort, timeoutMs) {
  return new Promise((resolvePort, rejectPort) => {
    const startedAt = Date.now();
    const tryOnce = () => {
      const socket = new net.Socket();
      socket.setTimeout(1000);
      socket.once("connect", () => {
        socket.destroy();
        resolvePort();
      });
      const onError = () => {
        socket.destroy();
        if (Date.now() - startedAt >= timeoutMs) {
          rejectPort(new Error(`Timed out waiting for ${host}:${openPort}`));
          return;
        }
        setTimeout(tryOnce, 200);
      };
      socket.once("timeout", onError);
      socket.once("error", onError);
      socket.connect(openPort, host);
    };
    tryOnce();
  });
}

function parseInteger(text) {
  const digits = String(text).replace(/[^\d]/g, "");
  return Number.parseInt(digits || "0", 10);
}

async function readTotalScansKpi(page) {
  const totalScansCard = page.locator(".kpi-card").filter({
    has: page.locator(".kpi-label", { hasText: "Total Scans" }),
  }).first();
  const raw = await totalScansCard.locator(".kpi-value").innerText();
  return parseInteger(raw);
}

async function clickNav(page, label) {
  await page.locator("a.nav-item", { hasText: label }).first().click();
  await page.waitForTimeout(900);
}

function topbarRefreshButton(page) {
  return page.locator(".topbar-right > button.btn-secondary").filter({ hasText: "Refresh" }).first();
}

async function ensureCompareSelection(page) {
  const pair = await page.evaluate(() => {
    const selectA = document.querySelector("#compare-scan-a");
    const selectB = document.querySelector("#compare-scan-b");
    if (!(selectA instanceof HTMLSelectElement) || !(selectB instanceof HTMLSelectElement)) return null;
    const optionMap = new Map();
    for (const option of Array.from(selectA.options)) {
      if (!option.value) continue;
      const text = option.textContent || "";
      const target = text.split("—")[1]?.split("(")[0]?.trim() || text.trim();
      if (!optionMap.has(target)) optionMap.set(target, []);
      optionMap.get(target).push(option.value);
    }
    for (const values of optionMap.values()) {
      if (values.length >= 2) {
        return { a: values[0], b: values[1] };
      }
    }
    return null;
  });
  if (!pair) {
    throw new Error("Unable to find two comparable scans for compare smoke test");
  }
  await page.selectOption("#compare-scan-a", pair.a);
  await page.waitForTimeout(300);
  await page.selectOption("#compare-scan-b", pair.b);
  await Promise.all([
    page.waitForResponse((res) => res.url().includes("/api/scans/compare") && res.status() < 400, { timeout: 15000 }),
    page.getByRole("button", { name: "Compare" }).click(),
  ]);
  await page.waitForTimeout(1200);
}

function insertFreshRuntimeScan() {
  const code = `
import sqlite3
from datetime import datetime, timezone

db_path = ${JSON.stringify(dbPath)}
scan_id = "browser-smoke-scan"
now = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

conn = sqlite3.connect(db_path)
conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
conn.execute(
    """
    INSERT INTO scans (
        id, created_at, finished_at, target_type, target_name, target_value,
        status, policy_status, findings_count, critical_count, high_count,
        medium_count, low_count, info_count, unknown_count, raw_report_dir,
        normalized_report_path, artifacts_json, tools_json, error_message
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
    (
        scan_id, now, now, "git", "browser-target", "https://example.test/browser-target",
        "COMPLETED", "PASSED", 1, 1, 0, 0, 0, 0, 0, "", "", "[]", "[]", None,
    ),
)
conn.execute(
    """
    INSERT INTO findings (
        scan_id, timestamp, target_type, target_name, tool, category, severity,
        title, description, file, line, package, version, cve, remediation,
        raw_reference, fingerprint
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
    (
        scan_id, now, "git", "browser-target", "browser-smoke", "cve", "CRITICAL",
        "Browser smoke critical", "Inserted during browser smoke test",
        "browser.py", 1, None, None, "CVE-2099-0002", "Fix it", "{}", "browser-smoke-fingerprint",
    ),
)
conn.commit()
conn.close()
`;
  runOrThrow(python, ["-c", code]);
}

function readDbScanCount() {
  const code = `
import sqlite3
db_path = ${JSON.stringify(dbPath)}
conn = sqlite3.connect(db_path)
value = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
conn.close()
print(value)
`;
  const result = runOrThrow(python, ["-c", code], { encoding: "utf-8" });
  return Number.parseInt(String(result.stdout || "").trim(), 10);
}

async function readApiKpiTotalScans(page) {
  const payload = await page.evaluate(async () => {
    const res = await fetch("/api/kpi", { credentials: "same-origin" });
    const body = await res.json().catch(() => ({}));
    return { status: res.status, body };
  });
  return {
    status: payload.status,
    totalScans: Number(payload.body?.total_scans ?? 0),
  };
}

async function frontendHasRefreshDashboardPatch(page) {
  return page.evaluate(async () => {
    const res = await fetch("/static/app.js", { credentials: "same-origin" });
    const text = await res.text();
    return text.includes("refreshDashboardData");
  });
}

async function inspectVueRefreshState(page) {
  return page.evaluate(async () => {
    const appEl = document.querySelector("#app");
    const proxy = appEl?.__vue_app__?._instance?.proxy;
    if (!proxy) return { hasProxy: false };
    const before = Number(proxy.kpis?.total_scans ?? 0);
    let called = false;
    let error = "";
    try {
      if (typeof proxy.refreshDashboardData === "function") {
        await proxy.refreshDashboardData();
        called = true;
      }
    } catch (err) {
      error = String(err?.message || err || "");
    }
    const after = Number(proxy.kpis?.total_scans ?? 0);
    return {
      hasProxy: true,
      hasMethod: typeof proxy.refreshDashboardData === "function",
      currentPage: String(proxy.currentPage || ""),
      called,
      error,
      before,
      after,
    };
  });
}

async function main() {
  console.log("[browser-smoke] seeding DB");
  runOrThrow(python, [seedScript, "--db-path", dbPath, "--clear"], {
    cwd: repoRoot,
    stdio: "inherit",
  });

  console.log("[browser-smoke] starting dashboard");
  const serverEnv = {
    ...process.env,
    DASHBOARD_DB_PATH: dbPath,
    DASHBOARD_USERNAME: "runtime",
    DASHBOARD_PASSWORD: "runtime-pass",
    DASHBOARD_SESSION_SECRET: "runtime-session-secret-1234567890",
    DASHBOARD_DISABLE_LIFESPAN: "1",
    DASHBOARD_CSP_ALLOW_UNSAFE_EVAL: "1",
  };
  const server = spawn(
    python,
    ["-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", String(port)],
    { cwd: dashboardDir, env: serverEnv, stdio: ["ignore", "pipe", "pipe"] },
  );

  let serverLogs = "";
  server.stdout.on("data", (chunk) => {
    serverLogs += chunk.toString();
  });
  server.stderr.on("data", (chunk) => {
    serverLogs += chunk.toString();
  });

  try {
    await waitForPort("127.0.0.1", port, 30000);
    console.log("[browser-smoke] server ready");

    const browserEnv = { ...process.env };
    if (existsSync(localLibDir)) {
      browserEnv.LD_LIBRARY_PATH = [localLibDir, process.env.LD_LIBRARY_PATH || ""].filter(Boolean).join(":");
    }
    const browser = await chromium.launch({ headless: true, env: browserEnv });
    const page = await browser.newPage();
    const consoleIssues = [];
    const apiFailures = [];
    const apiCalls = [];

    page.on("pageerror", (err) => {
      const stack = err && err.stack ? `\n${err.stack}` : "";
      consoleIssues.push(`pageerror: ${err.message}${stack}`);
    });
    page.on("console", (msg) => {
      if (msg.type() === "error") {
        consoleIssues.push(`console:${msg.type()}: ${msg.text()}`);
      }
    });
    page.on("response", (res) => {
      if (res.url().startsWith(`${baseUrl}/api/`)) {
        apiCalls.push(`${res.status()} ${res.url().replace(baseUrl, "")}`);
      }
      if (res.url().startsWith(`${baseUrl}/api/`) && res.status() >= 400) {
        apiFailures.push(`${res.status()} ${res.url()}`);
      }
    });

    await page.goto(`${baseUrl}/login`, { waitUntil: "domcontentloaded" });
    await page.screenshot({ path: resolve(artifactsDir, "01-login.png"), fullPage: true });

    await page.fill("input[name='username']", "runtime");
    await page.fill("input[name='password']", "runtime-pass");
    await Promise.all([
      page.waitForURL((url) => url.href === `${baseUrl}/`, { timeout: 15000 }),
      page.click("button[type='submit']"),
    ]);

    // Force dashboard view explicitly so hash-based routing state does not
    // leave us on a non-dashboard tab without KPI cards.
    if (page.url().includes("/login")) {
      throw new Error("Login failed: still on /login after submit");
    }
    await page.goto(`${baseUrl}/#dashboard`, { waitUntil: "domcontentloaded" });
    try {
      await page.waitForSelector(".kpi-card .kpi-value", { timeout: 15000 });
    } catch (err) {
      const debugPath = resolve(artifactsDir, "debug-kpi-timeout.png");
      await page.screenshot({ path: debugPath, fullPage: true }).catch(() => {});
      const snippet = (await page.textContent("body").catch(() => "") || "").replace(/\s+/g, " ").slice(0, 500);
      throw new Error(
        `KPI selector timeout at url=${page.url()} debug_screenshot=${debugPath} ` +
          `console_issues=${JSON.stringify(consoleIssues)} body_snippet=${snippet}`,
      );
    }
    const totalScansBefore = await readTotalScansKpi(page);
    await page.screenshot({ path: resolve(artifactsDir, "02-dashboard.png"), fullPage: true });

    let totalScansAfter = totalScansBefore;

    if (smokeMode !== "dashboard_only") {
      await clickNav(page, "Scans");
      await page.screenshot({ path: resolve(artifactsDir, "03-scans.png"), fullPage: true });

      await clickNav(page, "Findings");
      await page.locator("tr.row-clickable").nth(1).focus();
      await page.keyboard.press("Enter");
      await page.waitForTimeout(700);
      await page.keyboard.press("Escape");
      await page.waitForTimeout(400);
      await page.getByRole("button", { name: "Details" }).first().click();
      await page.waitForTimeout(700);
      await page.screenshot({ path: resolve(artifactsDir, "04-findings-modal.png"), fullPage: true });
      await page.locator(".modal-close").first().click();
      await page.waitForTimeout(400);
      await page.screenshot({ path: resolve(artifactsDir, "05-findings.png"), fullPage: true });

      await clickNav(page, "Analytics");
      await page.waitForTimeout(1800);
      await page.screenshot({ path: resolve(artifactsDir, "06-analytics.png"), fullPage: true });

      await clickNav(page, "Compare");
      await ensureCompareSelection(page);
      await page.screenshot({ path: resolve(artifactsDir, "07-compare.png"), fullPage: true });

      await clickNav(page, "Settings");
      await page.waitForTimeout(700);
      await page.screenshot({ path: resolve(artifactsDir, "08-settings-apikeys.png"), fullPage: true });
      await page.getByRole("button", { name: /new key/i }).click();
      await page.waitForTimeout(500);
      await page.screenshot({ path: resolve(artifactsDir, "08-settings-apikeys-modal.png"), fullPage: true });
      await page.locator(".modal-close").first().click();
      await page.waitForTimeout(300);
      await page.getByRole("tab", { name: "Webhooks" }).click();
      await page.waitForTimeout(500);
      await page.screenshot({ path: resolve(artifactsDir, "09-settings-webhooks.png"), fullPage: true });
      await page.getByRole("button", { name: /new webhook/i }).click();
      await page.waitForTimeout(500);
      await page.screenshot({ path: resolve(artifactsDir, "09-settings-webhooks-modal.png"), fullPage: true });
      await page.locator(".modal-close").first().click();
      await page.waitForTimeout(300);
      await page.getByRole("tab", { name: "Notifications" }).click();
      await page.waitForTimeout(500);
      await page.screenshot({ path: resolve(artifactsDir, "10-settings-notifications.png"), fullPage: true });

      await clickNav(page, "Dashboard");
      await page.waitForTimeout(700);
      await page.getByRole("button", { name: "Toggle theme" }).click();
      await page.waitForTimeout(900);
      await page.screenshot({ path: resolve(artifactsDir, "11-dashboard-light.png"), fullPage: true });
      await page.getByRole("button", { name: "Toggle theme" }).click();
      await page.waitForTimeout(900);

      await page.setViewportSize({ width: 430, height: 932 });
      await page.waitForTimeout(700);
      await page.getByRole("button", { name: "Open navigation menu" }).click();
      await page.waitForTimeout(600);
      await page.screenshot({ path: resolve(artifactsDir, "12-mobile-nav.png"), fullPage: true });
      await page.locator(".mobile-nav-backdrop").click({ force: true });
      await page.setViewportSize({ width: 1280, height: 720 });
      await page.waitForTimeout(600);

      await page.getByRole("button", { name: /new scan/i }).first().click();
      await page.waitForTimeout(500);
      await page.screenshot({ path: resolve(artifactsDir, "13-scan-modal.png"), fullPage: true });
      await page.keyboard.press("Escape");
      await page.waitForTimeout(400);

      insertFreshRuntimeScan();
      const dbCountAfterInsert = readDbScanCount();
        await clickNav(page, "Dashboard");
        await page.waitForTimeout(1000);
        let refreshTriggeredKpiRequest = false;
        try {
          await Promise.all([
            page.waitForResponse(
              (res) => res.url().startsWith(`${baseUrl}/api/kpi`) && res.status() < 400,
              { timeout: 5000 },
            ),
            topbarRefreshButton(page).click(),
          ]);
          refreshTriggeredKpiRequest = true;
        } catch (_) {
          await topbarRefreshButton(page).click();
        }

      const expected = totalScansBefore + 1;
      const timeoutAt = Date.now() + 10000;
      while (Date.now() < timeoutAt) {
        totalScansAfter = await readTotalScansKpi(page);
        if (totalScansAfter === expected) {
          break;
        }
        await page.waitForTimeout(300);
      }
      if (totalScansAfter !== expected) {
        const apiKpi = await readApiKpiTotalScans(page);
        const frontendPatched = await frontendHasRefreshDashboardPatch(page);
        const vueState = await inspectVueRefreshState(page);
        const recentApiCalls = apiCalls.slice(-12).join(" | ");
        throw new Error(
          `KPI refresh failed: expected total scans ${expected}, got ${totalScansAfter} ` +
            `(db=${dbCountAfterInsert}, api_status=${apiKpi.status}, api_total_scans=${apiKpi.totalScans}, ` +
            `refresh_triggered_kpi_request=${refreshTriggeredKpiRequest}, frontend_patched=${frontendPatched}, ` +
            `vue_state=${JSON.stringify(vueState)}, recent_api_calls=${recentApiCalls})`,
        );
      }

      await page.screenshot({ path: resolve(artifactsDir, "14-dashboard-refreshed.png"), fullPage: true });

      await page.getByRole("button", { name: "Sign out" }).click();
      await page.waitForURL((url) => url.href.startsWith(`${baseUrl}/login`), { timeout: 15000 });
      await page.waitForTimeout(500);
      await page.screenshot({ path: resolve(artifactsDir, "15-logout.png"), fullPage: true });
    } else {
      await page.waitForTimeout(5000);
    }
    await browser.close();

    if (consoleIssues.length) {
      throw new Error(`Browser console/page errors detected:\n${consoleIssues.join("\n")}`);
    }
    if (apiFailures.length) {
      throw new Error(`API failures detected:\n${apiFailures.join("\n")}`);
    }

    console.log(
      JSON.stringify(
        {
          ok: true,
          totalScansBefore,
          totalScansAfter,
          screenshots: artifactsDir,
        },
        null,
        2,
      ),
    );
  } finally {
    server.kill("SIGTERM");
    await new Promise((resolveDone) => setTimeout(resolveDone, 200));
    if (server.exitCode === null) {
      server.kill("SIGKILL");
    }
    if (serverLogs.trim()) {
      console.log("[browser-smoke] server logs captured");
    }
  }
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
