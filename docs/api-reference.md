# API Reference

This is a practical reference for the dashboard APIs exposed by the FastAPI service.

All `/api/*` endpoints require authentication unless explicitly noted otherwise.

Authentication modes:
- session-based browser auth
- bearer API key auth (`Authorization: Bearer ssp_...`)

---

## Auth

Routes:
- `GET /login`
- `POST /login`
- `POST /logout`
- `GET /logout`
- `GET /api/csrf-token`

Notes:
- browser clients should use the CSRF token for mutating requests
- API key callers bypass CSRF only after key verification
- `GET /logout` exists only to reject logout-via-GET and returns `405`

---

## Scans

Routes:
- `GET /api/scans`
- `GET /api/scans/paginated`
- `GET /api/scans/compare`
- `GET /api/scans/events`
- `GET /api/scans/{scan_id}`
- `POST /api/scan/trigger`

Main use cases:
- scan listing
- paginated queue view
- compare of two scan baselines
- server-sent events for scan updates
- scan detail view
- scan-triggering from UI or CI

---

## Findings

Routes:
- `GET /api/findings`
- `GET /api/findings/paginated`
- `GET /api/findings/status-counts`
- `GET /api/findings/triage-summary`
- `GET /api/findings/{finding_id}`
- `GET /api/findings/{finding_id}/state`
- `GET /api/findings/{finding_id}/comments`
- `PATCH /api/findings/{finding_id}/status`
- `POST /api/findings/{finding_id}/assign`
- `POST /api/findings/{finding_id}/false-positive`
- `POST /api/findings/{finding_id}/accept-risk`
- `POST /api/findings/{finding_id}/comment`
- `POST /api/findings/bulk/update-status`
- `GET /api/badge/{target_name}.svg`

Main use cases:
- triage
- assignment
- comments
- risk acceptance
- bulk operations
- status/count summary
- badge generation for external surfaces

---

## Analytics and charts

Routes:
- `GET /api/analytics/risk-distribution`
- `GET /api/analytics/compliance`
- `GET /api/analytics/trends`
- `GET /api/analytics/target-risk`
- `GET /api/analytics/tool-effectiveness`
- `GET /api/analytics/finding-risk/{finding_id}`
- `GET /api/remediation/{finding_id}`

Chart-oriented helpers:
- `GET /api/chart/severity-distribution`
- `GET /api/chart/tool-effectiveness`
- `GET /api/chart/target-risk-heatmap`
- `GET /api/chart/scan-trend`
- `GET /api/chart/remediation-progress`
- `GET /api/chart/severity-breakdown`
- `GET /api/chart/cve-distribution`

General dashboard helpers:
- `GET /api/kpi`
- `GET /api/trends`
- `GET /api/cache-hits`
- `GET /api/cache-hit-trend`
- `GET /api/cache-hit-trend.csv`

---

## Export and reporting

Routes:
- `GET /api/export/findings`
- `GET /api/audit/export`

Supported export styles in current UI/backend:
- CSV
- JSON
- SARIF
- HTML
- PDF

---

## Settings and automation

API keys:
- `GET /api/keys`
- `POST /api/keys`
- `DELETE /api/keys/{key_prefix}`

Webhooks:
- `GET /api/webhooks`
- `POST /api/webhooks`
- `PATCH /api/webhooks/{webhook_id}`
- `DELETE /api/webhooks/{webhook_id}`
- `POST /api/webhooks/{webhook_id}/rotate-secret`

Webhook runtime events:
- `scan.completed`
- `scan.failed`
- `finding.high`
- `finding.critical`

Notifications:
- `POST /api/notifications/send-alert`
- `POST /api/notifications/preferences`
- `GET /api/notifications/preferences`

Notes:
- notification preferences are JSON-body based
- `send-alert` is a targeted operational action, not a general outbound mail gateway
- runtime scan completion/failure and high/critical finding alerts are emitted automatically from `scan_runner.py`

Audit:
- `GET /api/audit`
- `POST /api/audit/purge`

---

## Monitoring

Routes:
- `GET /api/health`
- `GET /api/ready`
- `GET /api/metrics/json`
- `GET /api/metrics`
- `GET /metrics`

Notes:
- `/metrics` is the Prometheus scrape endpoint exposed by the app and requires authentication
- `/api/health` and `/api/ready` are the preferred liveness/readiness checks for operational tooling

---

## Pages served by the dashboard app

Routes:
- `GET /`
- `GET /scans`
- `GET /findings`

These serve the SPA entrypoint or server-side page aliases used by the operator UI.

Notes:
- `analytics`, `compare`, and `settings` are hash-routed SPA states, not separate server routes
- the operator UI primarily navigates with `#dashboard`, `#scans`, `#findings`, `#analytics`, `#compare`, and `#settings`

---

## Permission model

The exact enforcement is defined in `dashboard/rbac.py`, but the practical model is:
- `viewer`: read-only dashboards, findings, scans, analytics
- `operator`: scan execution and day-to-day operational actions
- `admin`: API key management, audit management, and full access

For the broader security model, see [security-model.md](security-model.md).
