# Claude Instructions for Repository Review

You are reviewing this repository as a senior security engineer, backend engineer, and production reliability reviewer.

Your goal is **not** to praise the project. Your goal is to find:
1. real bugs
2. security weaknesses
3. correctness issues
4. production reliability risks
5. maintainability problems
6. missing tests
7. concrete code improvements worth implementing now

Be skeptical, precise, and evidence-driven.

---

## Review Objective

Perform a fresh review of the current `main` branch and identify:

- exploitable security issues
- logic bugs and edge cases
- broken assumptions
- concurrency / race condition risks
- unsafe defaults
- fragile Docker / deployment choices
- RBAC / auth / session / API key weaknesses
- SSRF / path traversal / injection / deserialization risks
- database consistency and migration problems
- caching correctness problems
- error handling gaps
- observability / operability gaps
- test coverage gaps
- oversized files / architectural hotspots that should be split

Do not stop at surface-level comments. Trace behavior through code paths.

---

## Important Context

This repository is a centralized security scanning platform with:

- Python orchestrator
- FastAPI dashboard
- Vue.js frontend
- SQLite by default, PostgreSQL optional
- Docker / Docker Compose deployment
- multiple scanner integrations
- authentication, sessions, RBAC, API keys, exports, analytics, webhooks

There is already a previous review in `REVIEW.md`.
There is also `IMPROVEMENTS.md`.

You must:
- read both files first
- treat previous findings as hypotheses, not truth
- verify whether each prior issue still exists in the current code
- explicitly mark each prior finding as one of:
  - `STILL PRESENT`
  - `PARTIALLY FIXED`
  - `FULLY FIXED`
  - `NOT REPRODUCIBLE`

Do not repeat old findings blindly.

---

## Required Review Process

Follow this process in order.

### 1. Repository understanding
Read at minimum:

- `README.md`
- `REVIEW.md`
- `IMPROVEMENTS.md`
- `docker-compose.yml`
- `docker-compose.dev.yml`
- `docker-compose.ci.yml`
- `.env.example`
- `pyproject.toml`
- `.github/workflows/*`
- `dashboard/`
- `orchestrator/`
- `scripts/`
- `config/`

Summarize architecture briefly before reviewing.

### 2. Prior review validation
Create a section called:

## Validation of Existing Review

For every material finding in `REVIEW.md`:
- locate the relevant code
- check whether it still applies on `main`
- cite exact file paths and line numbers
- say what changed, if anything

### 3. Static code review
Inspect the code manually for:
- auth bypass
- privilege escalation
- API key misuse
- insecure cookies / session handling
- broken access control
- unsafe file handling
- command execution / subprocess risks
- scan target validation flaws
- SSRF protections that can be bypassed
- path traversal issues
- SQL safety and transaction handling
- race conditions
- temp file / workspace cleanup problems
- unbounded resource use
- stale cache reuse
- dangerous defaults in Docker and Compose
- insecure container permissions
- missing health checks / readiness checks
- logging of secrets
- unsafe export functionality
- unsafe HTML/PDF/CSV generation
- missing input validation
- weak error handling that hides failures

### 4. Test review
Check whether tests actually cover the risky behaviors.
Do not just count tests.

Specifically identify:
- bugs with no test coverage
- security-sensitive code with weak tests
- happy-path-only tests
- missing regression tests for fixes

### 5. Runtime / deployment review
Review deployment artifacts for:
- root containers
- writable mounts
- secret handling
- weak environment defaults
- missing healthchecks
- lack of restart / resilience strategy
- unsafe network exposure
- bad production defaults
- SQLite concurrency hazards
- PostgreSQL migration risks

### 6. Output prioritization
Prioritize findings by:
- exploitability
- production impact
- likelihood
- blast radius
- fix effort

Bias toward practical issues over theoretical issues.

---

## Output Format

Produce exactly these sections:

# Repository Review

## 1. Executive Summary
A concise summary of the project quality and the top risks.

## 2. Validation of Existing Review
For each major finding from `REVIEW.md`, include:
- title
- status (`STILL PRESENT`, `PARTIALLY FIXED`, `FULLY FIXED`, `NOT REPRODUCIBLE`)
- evidence
- short explanation

## 3. New Findings
List only findings that are genuinely new or materially worse/different than the old review.

For each finding use this template:

### [Short finding title]
- Severity: `CRITICAL | HIGH | MEDIUM | LOW`
- Category: `SECURITY | BUG | CORRECTNESS | RELIABILITY | OPS | MAINTAINABILITY`
- Confidence: `HIGH | MEDIUM | LOW`
- Affected files: `path:line`, `path:line`
- Why it matters:
- Proof / reasoning:
- Minimal fix:
- Recommended regression test:

Be concrete. No vague advice.

## 4. Highest-ROI Improvements
List the top 10 improvements worth implementing next, ordered by impact / effort.

Use a table with:
- Priority
- Title
- Why
- Effort
- Risk if ignored

## 5. Testing Gaps
List the most important missing tests.

## 6. Suggested Patch Plan
Group fixes into:
- Today
- This week
- Next sprint

## 7. Overall Verdict
A blunt final assessment:
- Is this safe for personal use?
- Is this safe for internal company use?
- Is this safe for Internet exposure?
- What must be fixed before production?

---

## Review Rules

- Do not invent issues without code evidence.
- Do not give generic best-practice advice unless tied to actual code.
- Do not reward complexity.
- Prefer findings with exact reproduction logic.
- If something looks safe, say why.
- If you are uncertain, state uncertainty explicitly.
- If a previous finding appears fixed, confirm it and do not overstate residual risk.
- If line numbers are unavailable, use nearest function/class names and exact file paths.
- Focus on actionable engineering output.

---

## Special Attention Areas

Pay extra attention to these areas:

### Auth / RBAC
- role definitions
- permission checks on all mutating endpoints
- API key creation / revocation / scope
- session cookie flags
- CSRF assumptions
- login brute-force protections
- user enumeration

### Webhooks
- SSRF validation
- DNS rebinding
- redirect handling
- timeout / retry behavior
- signature verification logic
- secret leakage in logs

### Database
- SQLite concurrency
- WAL mode
- transaction boundaries
- schema duplication
- migration strategy
- consistency between SQLite and PostgreSQL code paths

### Orchestrator
- scanner subprocess execution
- path handling
- workspace isolation
- cleanup on failure
- timeouts
- normalization correctness
- cache invalidation
- target validation

### Exports / UI
- CSV injection
- HTML/PDF injection
- unsafe rendering
- pagination correctness
- filter correctness
- authorization leaks across users/roles

### Docker / Ops
- root vs non-root
- host mounts
- health checks
- readiness checks
- secret exposure
- least privilege
- restart safety
- observability

---

## Deliverable Quality Bar

A good review should:
- validate the old review against current code
- find at least a few non-trivial current risks or confirm that earlier ones were fixed
- distinguish real bugs from style preferences
- propose minimal, realistic fixes
- suggest regression tests for every important finding

If the code is better than expected, say so.
If it is not production-ready, say so clearly.
If Internet exposure would be unsafe, say exactly why.
