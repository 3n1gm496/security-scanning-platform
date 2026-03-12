# Engineering Session Instructions

You are acting as a senior staff software engineer, staff product designer/UI engineer, QA lead, and security engineer.
You are already inside this repository and you have already been working on it in this session.
Do NOT restart blindly from zero.
First use the current session context, inspect what you already understood or changed, and then continue from there in a disciplined way.

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
