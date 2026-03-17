# Development and Verification Guide

This document captures the current verification flow for the repository after the audit, CI hardening, and SOC UI redesign work.

---

## Local environment

Create the local virtualenv in the path expected by the smoke tooling:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r dashboard/requirements-test.txt
pip install -r orchestrator/requirements-test.txt
```

Node dependencies are expected to be installed for the browser smoke flow.

---

## Core verification commands

### Python test suite

```bash
pytest -q
```

Expected result:
- full repository suite green from repo root (`627` tests in the current baseline)

### Frontend syntax check

```bash
node --check dashboard/static/app.js
```

### Browser smoke

```bash
node scripts/browser_smoke.mjs
```

The smoke flow:
- seeds a runtime database
- starts the dashboard on a temporary port
- exercises login, navigation, compare, settings, theme toggle, modals, mobile nav, keyboard row activation, and `Escape`-driven modal close
- rewrites screenshots in `artifacts/browser-smoke/` so the directory reflects the latest run only

---

## Screenshot review checklist

Review at least:
- `02-dashboard.png`
- `03-scans.png`
- `05-findings.png`
- `06-analytics.png`
- `07-compare.png`
- `08-settings-apikeys.png`
- `11-dashboard-light.png`
- `12-mobile-nav.png`
- one modal screenshot
- the refreshed dashboard screenshot

Look for:
- above-the-fold density
- chart readability
- broken truncation
- modal polish
- mobile nav quality
- light theme regressions

---

## Minimum pre-push checklist

- `pytest -q` green
- `node --check dashboard/static/app.js` green
- `node scripts/browser_smoke.mjs` green
- no obvious console/page errors in smoke output
- no ugly overflow in smoke screenshots
- docs updated if the change affects:
  - runtime behavior
  - workflows
  - CI/security scan semantics
  - operator-facing UI

---

## UI-focused review checklist

For dashboard/scans/findings/analytics/compare/settings:
- functional correctness
- layout density
- long-value handling
- light/dark readability
- modal quality
- mobile behavior
- live refresh stability

Severity buckets used during audit:
- `blocking`
- `high`
- `medium`
- `polish`

If a real bug is found in one of these paths, fix it before treating the pass as complete.

---

## CI notes

Current CI baseline:
- tests for orchestrator and dashboard on Python `3.11` and `3.12`
- `pip-audit`
- Bandit
- Docker image builds
- Trivy image scans
- reusable `Security Scan` workflow

Current `Security Scan` behavior:
- remote platform scan when secrets exist
- local Gitleaks fallback otherwise

Do not document or assume "remote scan only" unless the workflow has actually been changed.

---

## Artifacts and paths

Important locations:

```text
artifacts/browser-smoke/
docs/
dashboard/static/
dashboard/templates/
.github/workflows/
docker/scanner-tools.Dockerfile
```

If the browser smoke changes in a meaningful way, keep the saved screenshots and README/docs aligned with the new flow.
