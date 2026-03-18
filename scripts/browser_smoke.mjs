#!/usr/bin/env node

import process from "node:process";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "@playwright/test";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, "..");
const dashboardDir = resolve(repoRoot, "dashboard");
const python = resolve(repoRoot, "venv", "bin", "python");
const seedScript = resolve(repoRoot, "scripts", "seed_dev_data.py");

const smokeMode = process.env.BROWSER_SMOKE_MODE || "full";
const seedMode = process.env.BROWSER_SMOKE_SEED_MODE || "normal";
const defaultPort = seedMode === "edge" ? "18092" : "18091";
const port = Number(process.env.BROWSER_SMOKE_PORT || defaultPort);
const baseUrl = `http://127.0.0.1:${port}`;
const dbPath = process.env.BROWSER_SMOKE_DB || `/tmp/security-dashboard-browser-smoke-${seedMode}.db`;
const artifactsDir = resolve(repoRoot, "artifacts", "browser-smoke");
const localLibDir = resolve(repoRoot, ".local-playwright-libs", "extracted", "usr", "lib", "x86_64-linux-gnu");

mkdirSync(artifactsDir, { recursive: true });

for (const entry of readdirSync(artifactsDir, { withFileTypes: true })) {
  if (entry.isFile() && entry.name.endsWith(".png")) {
    rmSync(resolve(artifactsDir, entry.name), { force: true });
  }
}

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

async function getVueState(page, expression) {
  return page.evaluate((expr) => {
    const appEl = document.querySelector("#app");
    const proxy = appEl?.__vue_app__?._instance?.proxy;
    if (!proxy) return null;
    return Function("proxy", `return (${expr});`)(proxy);
  }, expression);
}

async function waitForVuePage(page, expectedPage, timeoutMs = 8000) {
  await page.waitForFunction(
    (expected) => {
      const appEl = document.querySelector("#app");
      const proxy = appEl?.__vue_app__?._instance?.proxy;
      return proxy?.currentPage === expected;
    },
    expectedPage,
    { timeout: timeoutMs },
  );
}

async function expectTheme(page, expected) {
  const result = await page.evaluate(() => ({
    themeAttr: document.documentElement.getAttribute("data-theme") || "dark",
    storedTheme: window.localStorage.getItem("ssp-theme") || "dark",
  }));
  if (result.themeAttr !== expected || result.storedTheme !== expected) {
    throw new Error(`Theme mismatch: expected ${expected}, got attr=${result.themeAttr} storage=${result.storedTheme}`);
  }
}

async function setDialogAutoAccept(page) {
  page.on("dialog", async (dialog) => {
    await dialog.accept();
  });
}

async function waitForModal(page, selector) {
  await page.waitForSelector(selector, { timeout: 8000 });
}

async function waitForToast(page, pattern, timeoutMs = 8000) {
  await page.locator(".toast").filter({ hasText: pattern }).first().waitFor({ timeout: timeoutMs });
}

async function waitForToastsCleared(page, timeoutMs = 8000) {
  await page.waitForFunction(
    () => Array.from(document.querySelectorAll(".toast")).every((toast) => {
      const style = window.getComputedStyle(toast);
      return style.display === "none" || style.visibility === "hidden" || style.opacity === "0";
    }),
    { timeout: timeoutMs },
  ).catch(() => {});
}

async function waitForHash(page, hashPrefix, timeoutMs = 8000) {
  await page.waitForFunction(
    (expected) => window.location.hash.startsWith(expected),
    hashPrefix,
    { timeout: timeoutMs },
  );
}

async function waitForServerReady(url, timeoutMs = 15000) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    try {
      const res = await fetch(url, { redirect: "manual" });
      if (res.ok || res.status === 302 || res.status === 307) return;
    } catch {
      // Keep polling until the timeout expires.
    }
    await new Promise((resolveReady) => setTimeout(resolveReady, 250));
  }
  throw new Error(`Timed out waiting for dashboard readiness at ${url}`);
}

async function clickAndWaitForPage(page, buttonPattern, expectedPage, timeoutMs = 10000) {
  await Promise.all([
    waitForHash(page, `#${expectedPage}`, timeoutMs),
    page.getByRole("button", { name: buttonPattern }).first().click(),
  ]);
  await waitForVuePage(page, expectedPage, timeoutMs);
}

async function assertModalClosed(page, selector) {
  const visible = await page.locator(selector).count();
  if (visible !== 0) throw new Error(`Expected modal ${selector} to be closed`);
}

function topbarRefreshButton(page) {
  return page.locator(".topbar-right > button.btn-secondary").filter({ hasText: "Refresh" }).first();
}

async function ensureCompareSelection(page) {
  const pair = await page.evaluate(() => {
    const appEl = document.querySelector("#app");
    const proxy = appEl?.__vue_app__?._instance?.proxy;
    if (proxy && Array.isArray(proxy.compareScanList)) {
      const grouped = new Map();
      for (const scan of proxy.compareScanList) {
        if (!scan?.id || !scan?.target_name) continue;
        const key = String(scan.target_name);
        if (!grouped.has(key)) grouped.set(key, []);
        grouped.get(key).push(String(scan.id));
      }
      for (const values of grouped.values()) {
        if (values.length >= 2) {
          return { a: values[0], b: values[1] };
        }
      }
    }
    const selectA = document.querySelector("#compare-scan-a");
    const selectB = document.querySelector("#compare-scan-b");
    if (!(selectA instanceof HTMLSelectElement) || !(selectB instanceof HTMLSelectElement)) return null;
    const optionMap = new Map();
    for (const option of Array.from(selectA.options)) {
      if (!option.value) continue;
      const text = option.textContent || "";
      const target = text.split("·")[0]?.replace(/^#/, '').trim() || text.trim();
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
    page.getByRole("button", { name: /analyze drift|run comparison|compare/i }).click(),
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
  runOrThrow(python, [seedScript, "--db-path", dbPath, "--clear", "--mode", seedMode], {
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
  server.on("exit", (code, signal) => {
    serverLogs += `\n[server-exit] code=${code} signal=${signal}\n`;
  });

  try {
    await waitForServerReady(`${baseUrl}/login`);
    console.log("[browser-smoke] server ready");

    const browserEnv = { ...process.env };
    if (existsSync(localLibDir)) {
      browserEnv.LD_LIBRARY_PATH = [localLibDir, process.env.LD_LIBRARY_PATH || ""].filter(Boolean).join(":");
    }
    const browser = await chromium.launch({ headless: true, env: browserEnv });
    const page = await browser.newPage();
    let currentStep = "bootstrap";
    const markStep = (label) => {
      currentStep = label;
      console.log(`[browser-smoke] step: ${label}`);
    };
    const consoleIssues = [];
    const apiFailures = [];
    const apiCalls = [];
    await setDialogAutoAccept(page);

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

    markStep("login-page");
    await page.goto(`${baseUrl}/login`, { waitUntil: "domcontentloaded" });
    await page.screenshot({ path: resolve(artifactsDir, "01-login.png"), fullPage: true });

    markStep("login-submit");
    await page.fill("input[name='username']", "runtime");
    await page.fill("input[name='password']", "runtime-pass");
    await Promise.all([
      page.waitForURL((url) => url.href.startsWith(`${baseUrl}/`) && !url.href.includes("/login"), { timeout: 15000 }),
      page.click("button[type='submit']"),
    ]);

    // Force dashboard view explicitly so hash-based routing state does not
    // leave us on a non-dashboard tab without KPI cards.
    if (page.url().includes("/login")) {
      throw new Error("Login failed: still on /login after submit");
    }
    markStep("dashboard-bootstrap");
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
      markStep("dashboard-review-queue");
      await page.locator(".threat-rail-card").getByRole("button", { name: /review queue/i }).click();
      await page.waitForTimeout(1200);
      const reviewQueueState = await page.evaluate(() => ({ hash: window.location.hash }));
      if (!String(reviewQueueState?.hash || "").startsWith("#findings?severity=CRITICAL")) {
        throw new Error(`Dashboard Review queue navigation failed: ${JSON.stringify(reviewQueueState)}`);
      }

      markStep("dashboard-review-scans");
      await clickNav(page, "Dashboard");
      await page.locator(".chart-card-hero").getByRole("button", { name: /review scans/i }).click();
      await page.waitForTimeout(1200);
      const reviewScansState = await page.evaluate(() => ({ hash: window.location.hash }));
      if (!String(reviewScansState?.hash || "").startsWith("#scans")) {
        throw new Error(`Dashboard Review scans navigation failed: ${JSON.stringify(reviewScansState)}`);
      }

      markStep("dashboard-view-analytics");
      await clickNav(page, "Dashboard");
      await page.locator(".threat-rail-card").getByRole("button", { name: /view analytics/i }).click();
      await page.waitForTimeout(1200);
      const reviewAnalyticsState = await page.evaluate(() => ({ hash: window.location.hash }));
      if (!String(reviewAnalyticsState?.hash || "").startsWith("#analytics")) {
        throw new Error(`Dashboard View analytics navigation failed: ${JSON.stringify(reviewAnalyticsState)}`);
      }
      await clickNav(page, "Dashboard");

      markStep("sidebar-collapse-expand");
      await page.locator(".sidebar-toggle").click();
      await page.waitForTimeout(300);
      const collapsed = await page.locator(".sidebar").evaluate((el) => el.classList.contains("collapsed"));
      if (!collapsed) throw new Error("Sidebar collapse toggle failed");
      await page.locator(".sidebar-toggle").click();
      await page.waitForTimeout(300);
      const expanded = await page.locator(".sidebar").evaluate((el) => !el.classList.contains("collapsed"));
      if (!expanded) throw new Error("Sidebar expand toggle failed");

      markStep("dashboard-launch-scan-modal");
      await page.getByRole("button", { name: /launch scan/i }).first().click();
      await waitForModal(page, "#new-scan-name");
      await page.locator(".modal-overlay").click({ force: true, position: { x: 8, y: 8 } });
      await page.waitForTimeout(300);
      await assertModalClosed(page, "#new-scan-name");

      markStep("scans-workflow");
      await clickNav(page, "Scans");
      await page.locator("tbody tr.row-clickable").first().waitFor({ timeout: 10000 });
      const firstScanTarget = (await page.locator(".table-primary-stack-scan .table-primary").first().textContent())?.trim() || "";
      if (!firstScanTarget) throw new Error("Scans page did not load any rows for validation");
      await page.fill("#scans-filter-search", String(firstScanTarget).slice(0, 10));
      await page.waitForTimeout(700);
      const scanRowsAfterSearch = await page.locator("tbody tr.row-clickable").count();
      if (!scanRowsAfterSearch || scanRowsAfterSearch < 1) {
        throw new Error("Scans search filter returned no rows for the chosen target");
      }
      await page.selectOption("#scans-filter-status", { index: 1 });
      await page.waitForTimeout(600);
      await page.selectOption("#scans-filter-policy", { index: 1 });
      await page.waitForTimeout(600);
      await page.getByRole("button", { name: "Reset" }).click();
      await page.waitForTimeout(700);
      await page.getByRole("button", { name: "High" }).click();
      await page.waitForTimeout(250);
      const highHeaderHidden = await page.getByRole("columnheader", { name: /High/ }).count();
      if (highHeaderHidden !== 0) throw new Error("Scan visible column toggle failed to hide High");
      await page.getByRole("button", { name: "High" }).click();
      await page.waitForTimeout(250);
      const highHeaderRestored = await page.getByRole("columnheader", { name: /High/ }).count();
      if (highHeaderRestored < 1) throw new Error("Scan visible column toggle failed to restore High");

      await page.locator("tr.row-clickable").nth(0).click();
      await waitForModal(page, "#scan-modal-title");
      await page.keyboard.press("Escape");
      await page.waitForTimeout(300);
      await assertModalClosed(page, "#scan-modal-title");

      await page.getByRole("button", { name: /^View details for scan / }).first().click();
      await waitForModal(page, "#scan-modal-title");
      await page.locator(".modal-close").first().click();
      await page.waitForTimeout(300);
      await assertModalClosed(page, "#scan-modal-title");

      const findingsActionLabel = await page.evaluate(() => {
        const rows = Array.from(document.querySelectorAll("tbody tr.row-clickable"));
        for (const row of rows) {
          const findingsCountCell = row.querySelector("td:nth-child(7)");
          const button = row.querySelector('button[aria-label^="Open findings for scan "]');
          const count = Number.parseInt((findingsCountCell?.textContent || "").replace(/[^\d]/g, "") || "0", 10);
          if (button instanceof HTMLButtonElement && count > 0) {
            return button.getAttribute("aria-label");
          }
        }
        const fallback = document.querySelector('button[aria-label^="Open findings for scan "]');
        return fallback instanceof HTMLButtonElement ? fallback.getAttribute("aria-label") : null;
      });
      if (!findingsActionLabel) throw new Error("Could not find a scan findings action to validate");
      await page.getByRole("button", { name: findingsActionLabel }).click();
      await waitForHash(page, "#findings");
      const scanFilterChipVisible = await page.locator(".scan-id-badge").count();
      if (scanFilterChipVisible < 1) throw new Error("Scan findings action did not surface the scan filter chip");

      await clickNav(page, "Scans");
      const comparePair = await page.evaluate(() => {
        const rows = Array.from(document.querySelectorAll("tbody tr.row-clickable"));
        const grouped = new Map();
        for (const row of rows) {
          const checkbox = row.querySelector('input[type="checkbox"][value]');
          const targetPrimary = row.querySelector(".table-primary-stack-scan .table-primary");
          const id = checkbox instanceof HTMLInputElement ? checkbox.value : "";
          const target = (targetPrimary?.textContent || "").trim();
          if (!id || !target) continue;
          if (!grouped.has(target)) grouped.set(target, []);
          grouped.get(target).push(id);
        }
        for (const ids of grouped.values()) {
          if (ids.length >= 2) return ids.slice(0, 2);
        }
        const fallback = [];
        for (const row of rows.slice(0, 4)) {
          const checkbox = row.querySelector('input[type="checkbox"][value]');
          const id = checkbox instanceof HTMLInputElement ? checkbox.value : "";
          if (id) fallback.push(id);
          if (fallback.length === 2) break;
        }
        return fallback;
      });
      if (comparePair.length < 2) throw new Error("Unable to find two scan rows on the current page for compare selection");
      await page.locator(`input[type="checkbox"][value="${comparePair[0]}"]`).check();
      await page.locator(`input[type="checkbox"][value="${comparePair[1]}"]`).check();
      await Promise.all([
        waitForHash(page, "#compare"),
        page.getByRole("button", { name: /compare selected/i }).click(),
      ]);

      const compareIds = {
        a: await page.inputValue("#compare-scan-a"),
        b: await page.inputValue("#compare-scan-b"),
      };
      if (seedMode !== "edge" && (compareIds.a !== comparePair[0] || compareIds.b !== comparePair[1])) {
        throw new Error(`Compare selection did not carry IDs correctly: ${JSON.stringify(compareIds)}`);
      }
      await page.screenshot({ path: resolve(artifactsDir, "03-scans.png"), fullPage: true });

      markStep("findings-workflow");
      await clickNav(page, "Findings");
      await page.locator("tbody tr.row-clickable").first().waitFor({ timeout: 10000 });
      const firstFinding = {
        id: await page.locator('tbody tr.row-clickable input[type="checkbox"]').first().getAttribute("value"),
        title: ((await page.locator(".finding-title").first().textContent()) || "").trim(),
        severity: ((await page.locator("tbody tr.row-clickable .severity-badge").first().textContent()) || "").trim(),
      };
      if (!firstFinding?.id) throw new Error("Findings page did not load rows for workflow validation");
      await page.fill("#findings-filter-search", String(firstFinding.title).slice(0, 16));
      await page.waitForTimeout(700);
      await page.selectOption("#findings-filter-severity", firstFinding.severity);
      await page.waitForTimeout(500);
      const findingRowsAfterFilter = await page.locator("tbody tr.row-clickable").count();
      if (!findingRowsAfterFilter || findingRowsAfterFilter < 1) {
        throw new Error("Findings combined search/severity filter returned no rows");
      }
      await page.getByRole("button", { name: "Reset" }).click();
      await page.waitForTimeout(700);
      await page.locator("tr.row-clickable").nth(1).focus();
      await page.keyboard.press("Enter");
      await waitForModal(page, "#finding-modal-title");
      await page.locator(".modal-close").first().click();
      await page.waitForTimeout(300);
      await assertModalClosed(page, "#finding-modal-title");

      await page.getByRole("button", { name: "Details" }).first().click();
      await waitForModal(page, "#finding-modal-title");
      await page.getByRole("tab", { name: /Remediation/i }).click();
      await page.waitForTimeout(200);
      await page.getByRole("tab", { name: /Management/i }).click();
      await page.waitForTimeout(200);
      await page.getByRole("tab", { name: /Comments/i }).click();
      await page.fill("#new-comment", "Browser smoke validation comment");
      markStep("findings-add-comment");
      await Promise.all([
        page.waitForResponse((res) => /\/comment(s)?$/.test(new URL(res.url()).pathname) && res.status() < 400, { timeout: 15000 }),
        page.getByRole("button", { name: /add comment/i }).click(),
      ]);
      await waitForToast(page, /Comment added/i);
      await waitForToastsCleared(page);
      await page.locator(".modal-close").first().click();
      await page.waitForTimeout(300);
      await assertModalClosed(page, "#finding-modal-title");

      const selectedFindingIds = [];
      const findingCheckboxes = page.locator('tbody tr.row-clickable input[type="checkbox"][value]');
      for (let i = 0; i < Math.min(await findingCheckboxes.count(), 2); i += 1) {
        const value = await findingCheckboxes.nth(i).getAttribute("value");
        if (value) selectedFindingIds.push(value);
      }
      if (selectedFindingIds.length < 2) throw new Error("Need at least two findings to validate bulk actions");
      await page.locator(`input[type="checkbox"][value="${selectedFindingIds[0]}"]`).check();
      await page.locator(`input[type="checkbox"][value="${selectedFindingIds[1]}"]`).check();
      await page.selectOption("#bulk-status", "acknowledged");
      markStep("findings-bulk-update");
      await page.getByRole("button", { name: /^Apply$/ }).click();
      await waitForToast(page, /Status updated/i);
      await page.selectOption("#findings-filter-status", "acknowledged");
      await page.waitForTimeout(700);
      const acknowledgedCount = await page.locator("tbody tr.row-clickable .status-pill.status-acknowledged").count();
      if (acknowledgedCount < 1) throw new Error("Bulk status update did not surface acknowledged findings");

      await page.locator("tr.row-clickable").nth(1).focus();
      await page.keyboard.press("Enter");
      await waitForModal(page, "#finding-modal-title");
      await page.locator(".modal-close").first().click();
      await page.waitForTimeout(300);
      await assertModalClosed(page, "#finding-modal-title");
      await page.getByRole("button", { name: "Details" }).first().click();
      await waitForModal(page, "#finding-modal-title");
      await page.screenshot({ path: resolve(artifactsDir, "04-findings-modal.png"), fullPage: true });
      await page.locator(".modal-close").first().click();
      await page.waitForTimeout(400);
      await page.screenshot({ path: resolve(artifactsDir, "05-findings.png"), fullPage: true });

      markStep("analytics-workflow");
      await clickNav(page, "Analytics");
      await Promise.all([
        page.waitForResponse((res) => res.url().includes("/api/analytics/") && res.status() < 400, { timeout: 15000 }),
        page.getByRole("button", { name: /^Refresh$/ }).click(),
      ]);
      await page.waitForTimeout(1800);
      await page.screenshot({ path: resolve(artifactsDir, "06-analytics.png"), fullPage: true });
      if (seedMode === "edge") {
        const emptyChartCount = await page.locator(".chart-empty-state").count();
        if (emptyChartCount < 1) throw new Error("Edge analytics mode expected at least one chart empty state");
        await page.screenshot({ path: resolve(artifactsDir, "16-analytics-edge.png"), fullPage: true });
      }

      markStep("compare-workflow");
      await clickNav(page, "Compare");
      if (seedMode === "edge") {
        const noDiffPair = await page.evaluate(() => {
          const select = document.querySelector("#compare-scan-a");
          if (!(select instanceof HTMLSelectElement)) return null;
          const optionValues = new Set(Array.from(select.options).map((option) => option.value).filter(Boolean));
          if (optionValues.has("edge-compare-match-a") && optionValues.has("edge-compare-match-b")) {
            return { a: "edge-compare-match-a", b: "edge-compare-match-b" };
          }
          const grouped = new Map();
          for (const option of Array.from(select.options)) {
            if (!option.value) continue;
            const text = (option.textContent || "").trim().toLowerCase();
            if (!grouped.has(text)) grouped.set(text, []);
            grouped.get(text).push(option.value);
          }
          for (const [text, values] of grouped.entries()) {
            if (text.includes("identical-edge") && values.length >= 2) {
              return { a: values[0], b: values[1] };
            }
          }
          return null;
        });
        if (!noDiffPair) throw new Error("Edge compare mode could not find a no-drift pair");
        await page.selectOption("#compare-scan-a", noDiffPair.a);
        await page.waitForTimeout(300);
        await page.selectOption("#compare-scan-b", noDiffPair.b);
        await Promise.all([
          page.waitForResponse((res) => res.url().includes("/api/scans/compare") && res.status() < 400, { timeout: 15000 }),
          page.getByRole("button", { name: /analyze drift/i }).click(),
        ]);
        await page.locator(".compare-no-diff-card").waitFor({ timeout: 8000 });
        await page.screenshot({ path: resolve(artifactsDir, "17-compare-no-drift.png"), fullPage: true });
      } else {
        await ensureCompareSelection(page);
      }
      await page.screenshot({ path: resolve(artifactsDir, "07-compare.png"), fullPage: true });

      markStep("settings-workflow");
      await clickNav(page, "Settings");
      await page.waitForTimeout(700);
      await page.screenshot({ path: resolve(artifactsDir, "08-settings-apikeys.png"), fullPage: true });
      await page.getByRole("button", { name: /create key|new key/i }).click();
      await page.waitForTimeout(500);
      await page.screenshot({ path: resolve(artifactsDir, "08-settings-apikeys-modal.png"), fullPage: true });
      await page.locator(".modal-close").first().click();
      await page.waitForTimeout(300);
      await page.getByRole("tab", { name: "Webhooks" }).click();
      await page.waitForTimeout(500);
      await page.screenshot({ path: resolve(artifactsDir, "09-settings-webhooks.png"), fullPage: true });
      await page.locator("#settings-panel-webhooks").getByRole("button", { name: /create webhook|new webhook/i }).first().click();
      await page.waitForTimeout(500);
      await page.screenshot({ path: resolve(artifactsDir, "09-settings-webhooks-modal.png"), fullPage: true });
      await page.locator(".modal-close").first().click();
      await page.waitForTimeout(300);
      await page.getByRole("tab", { name: "Notifications" }).click();
      await page.waitForTimeout(500);
      await page.fill("#notif-email", seedMode === "edge" ? "edge-ops@example.com" : "ops@example.com");
      const weeklyRow = page.locator(".notif-row").filter({ hasText: "Weekly digest" }).first();
      const scanSummaryRow = page.locator(".notif-row").filter({ hasText: "Scan completion summary" }).first();
      const weeklyCheckbox = weeklyRow.getByRole("checkbox", { name: "Enable weekly digest emails" });
      const summaryCheckbox = scanSummaryRow.getByRole("checkbox", { name: "Enable scan summary emails" });
      if (!(await weeklyCheckbox.isChecked())) {
        await weeklyRow.locator(".toggle-slider").click();
      }
      if (!(await summaryCheckbox.isChecked())) {
        await scanSummaryRow.locator(".toggle-slider").click();
      }
      await page.waitForTimeout(200);
      const uiNotifPrefs = {
        weekly_digest: await weeklyCheckbox.isChecked(),
        scan_summaries: await summaryCheckbox.isChecked(),
      };
      if (!uiNotifPrefs.weekly_digest || !uiNotifPrefs.scan_summaries) {
        throw new Error(`Notification toggles did not update in UI controls: ${JSON.stringify(uiNotifPrefs)}`);
      }
      await page.getByRole("button", { name: /save notification settings/i }).click();
      await waitForToast(page, /Preferences saved/i);
      const savedNotifPrefs = await page.evaluate(async () => {
        const res = await fetch("/api/notifications/preferences", { credentials: "same-origin" });
        return res.json();
      });
      if (!savedNotifPrefs?.preferences?.weekly_digest || !savedNotifPrefs?.preferences?.scan_summaries) {
        throw new Error(`Notification preferences did not persist via UI submit: ${JSON.stringify(savedNotifPrefs)}`);
      }
      await page.screenshot({ path: resolve(artifactsDir, "10-settings-notifications.png"), fullPage: true });

      markStep("theme-persistence");
      await clickNav(page, "Dashboard");
      await page.waitForTimeout(700);
      await page.getByRole("button", { name: "Toggle theme" }).click();
      await page.waitForTimeout(900);
      await expectTheme(page, "light");
      await page.screenshot({ path: resolve(artifactsDir, "11-dashboard-light.png"), fullPage: true });
      await clickNav(page, "Scans");
      await expectTheme(page, "light");
      await clickNav(page, "Dashboard");
      await page.getByRole("button", { name: "Toggle theme" }).click();
      await page.waitForTimeout(900);
      await expectTheme(page, "dark");

      markStep("mobile-nav");
      await page.setViewportSize({ width: 430, height: 932 });
      await page.waitForTimeout(700);
      await page.getByRole("button", { name: "Open navigation menu" }).click();
      await page.waitForTimeout(600);
      await page.getByRole("button", { name: "Close navigation menu" }).click();
      await page.waitForTimeout(400);
      await page.getByRole("button", { name: "Open navigation menu" }).click();
      await page.waitForTimeout(400);
      await page.screenshot({ path: resolve(artifactsDir, "12-mobile-nav.png"), fullPage: true });
      await page.locator(".mobile-nav-backdrop").click({ force: true });
      await page.waitForTimeout(400);
      await page.setViewportSize({ width: 1280, height: 720 });
      await page.waitForTimeout(600);

      markStep("scans-launch-modal");
      await clickNav(page, "Scans");
      await page.getByRole("button", { name: /launch scan/i }).first().click();
      await waitForModal(page, "#new-scan-name");
      await page.screenshot({ path: resolve(artifactsDir, "13-scan-modal.png"), fullPage: true });
      await page.keyboard.press("Escape");
      await page.waitForTimeout(400);

      markStep("dashboard-refresh");
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

      markStep("logout");
      await page.getByRole("button", { name: "Sign out" }).click();
      await page.waitForURL((url) => url.href.startsWith(`${baseUrl}/login`), { timeout: 15000 });
      await page.waitForTimeout(500);
      await page.screenshot({ path: resolve(artifactsDir, "15-logout.png"), fullPage: true });
    } else {
      await page.waitForTimeout(5000);
    }
    markStep("browser-close");
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
      console.log(serverLogs.trim());
    }
  }
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
