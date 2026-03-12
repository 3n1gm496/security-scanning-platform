# Engineering Session Instructions

You are acting as a senior staff software engineer, staff product designer/UI engineer, QA lead, and security engineer.
You are already inside this repository and you have already been working on it in this session.
Do NOT restart blindly from zero.
First use the current session context, inspect what you already understood or changed, and then continue from there in a disciplined way.

## CURRENT STATE (as of 2026-03-12) — do not redo this work

All phases have been executed and committed to `claude/security-platform-review-MqdAz`.
Do not re-audit or re-implement the items listed below.

### Completed
- Phase 1: full repository audit
- Phase 2: WAL mode, non-root Dockerfile, Docker healthchecks, SSRF protection on webhooks,
  RBAC privilege ceiling, badge endpoint auth, findings cap, audit endpoint
- Phase 3: full Italian→English UI translation across app.html, app.js, findings.html,
  scans.html, login.html; severity/status badges; empty states; login page polish
- Structured JSON logging via structlog (logging_config.py)
- app.py decomposed: rate_limit.py and scan_runner.py extracted
- Startup security warnings for weak SESSION_SECRET / DASHBOARD_PASSWORD
- Swallowed remediation exception now logged
- Test isolation bug fixed (conftest.py teardown)
- Rate limit defaults configurable via env vars (DASHBOARD_RATE_LIMIT_REQUESTS, etc.)
- Webhook retry with exponential backoff already implemented (WEBHOOK_RETRY_COUNT env var)
- Dead templates index.html and index-vue.html removed
- findings.html: remaining Italian translated, pagination added (page/per_page query params)
- app.html: lang="en", Chart.js onerror fallback added
- app.js: Chart.js availability guard, remaining Italian toast fixed

### Full bug-elimination pass (2026-03-12) — do not redo
- P0 fixed: `api_bulk_update_status` parameter `status: str` shadowed the imported
  `starlette.status` module → `AttributeError` on invalid input. Renamed to `status_value`.
- P1 fixed: Italian login error `"Credenziali non valide"` → `"Invalid credentials"`;
  `test_auth.py` updated to match.
- P1 fixed: Webhook delivery loop now breaks immediately on 4xx client errors instead of
  retrying (4xx responses will never succeed on retry).
- P1 fixed: `Content-Disposition: attachment; filename=` was unquoted in export endpoint
  → now `filename="..."` per RFC 6266.
- P2 fixed: `mark_false_positive`, `accept_risk`, `bulk_update_status` in
  `finding_management.py` used `INSERT OR REPLACE` which silently discarded existing
  `assigned_to`, `resolution_notes`, and other columns on the replaced row. Replaced with
  explicit UPDATE-or-INSERT pattern.
- P2 fixed: Remaining Italian code comments and docstrings translated in `app.py` and `db.py`.

### 245/245 tests passing as of last verified run

### Remaining known gaps (low priority)
- Analytics page table fallback when JS is disabled entirely (noscript)
- Findings fallback template per_page is capped at 200 server-side
- Webhook SSRF check validates only literal IP addresses; DNS-rebinding not mitigated
  (documented in webhooks.py comment; needs per-request DNS pre-resolution for high-security)

## Repository goal
Improve the dashboard's visual quality and UX, identify and fix the actual bugs in the project, harden the app where needed, and keep the existing architecture stable and maintainable.

## Core constraints
- Keep the current stack unless a change is strictly necessary.
- Do not do destructive rewrites.
- Do not introduce heavy dependencies without strong justification.
- Do not break existing workflows, APIs, Docker setup, or orchestrator/dashboard integration.
- Prefer small, reviewable, production-ready changes.
- Avoid cosmetic-only edits with little practical value.
- Do not make assumptions without checking the code first.
- Do not run destructive git commands.
- Do not delete large portions of code unless clearly justified.
- Do not commit unless explicitly asked.

## PHASE 0 — REUSE CURRENT SESSION CONTEXT
Before doing anything else:
1. Summarize current understanding of the repository from this session.
2. List any files already inspected or modified.
3. Identify any partial fixes, unfinished work, open questions, or risky assumptions.
4. Then continue from the current state instead of duplicating work.

## PHASE 1 — REPOSITORY AUDIT
Perform a focused but comprehensive audit. Inspect at minimum:
- dashboard templates, CSS/JS/static assets
- FastAPI app structure and routes
- backend services and helpers
- orchestrator integration points
- DB access layer
- auth / RBAC / API key handling
- Docker / docker-compose setup
- configuration and environment handling
- test suite and CI-related files
- error handling and logging
- concurrency-sensitive code
- webhook / external request logic
- caching logic
- any oversized monolithic modules

Produce an audit structured as:
- A. Architecture summary
- B. Bugs found
- C. UX/UI problems found
- D. Security / hardening issues found
- E. Code quality / maintainability issues found
- F. Test gaps

Classify findings by priority: P0 (critical), P1 (functional bugs), P2 (polish).

## PHASE 2 — HIGH-PRIORITY BUG HUNT
Investigate and verify these areas explicitly:
- SQLite concurrency issues; enable WAL mode if missing
- unsafe DB access patterns or locking issues
- dashboard container running as root
- missing or weak healthchecks in docker-compose
- RBAC / API key privilege escalation risks
- webhook SSRF risk and insufficient URL validation
- shallow clone behavior that may weaken gitleaks/history-based scanning
- cache invalidation problems involving commit hash or scan identity
- oversized app.py or similar monoliths causing fragility
- inconsistent error responses
- broken empty/loading/error states in the UI
- brittle filtering, sorting, pagination, or search behavior
- template rendering or data-shape mismatches
- race conditions between dashboard, orchestrator, and persistence layer

## PHASE 3 — UI / UX REDESIGN WITHOUT STACK CHURN
Improve the dashboard so it looks like a credible modern enterprise security platform. Focus on:
- visual hierarchy, spacing and layout rhythm
- typography and readability
- color consistency and contrast
- accessible severity badges
- findings tables and scan result readability
- filters, search, and status indicators
- headers, nav, actions, and page structure
- loading / empty / error states
- responsive behavior on desktop and laptop widths
- consistency between pages/components
- clarity of key actions and scan status

Design direction: professional, clean, high signal-to-noise, security-product feel, not flashy, practical.

## PHASE 4 — IMPLEMENTATION RULES
Work in this order: Audit → Prioritized plan → P0 fixes → P1 fixes → UI/UX → Tests → Verification → Summary.

While implementing:
- inspect before editing
- keep changes localized
- prefer readability
- preserve backward compatibility
- add comments only where useful
- improve logging/error messages when they help operations
- avoid speculative refactors

## PHASE 5 — TESTING AND VERIFICATION
Use the repo's existing validation workflow (README, Makefile, pyproject.toml, CI configs). Run unit tests, lint checks, targeted regression tests. Do not fake successful verification.

## PHASE 6 — OUTPUT FORMAT
Respond with a structured engineering report:
1. Current session recap
2. Audit summary
3. Prioritized plan (P0/P1/P2)
4. Implemented changes by file
5. Confirmed bug fixes
6. UI/UX improvements
7. Security hardening
8. Verification results
9. Residual issues / follow-up recommendations
10. Final concise changelog

## EXECUTION STYLE
- Verify before claiming.
- Prefer real fixes over theoretical commentary.
- If you find an issue, patch it when reasonable.
- Do not bloat the response with generic advice.
- Do not stop at analysis only.
- Continue through audit, implementation, and verification unless blocked.
