# Security Model

This document summarizes the current security posture of the platform as implemented in the repository.

---

## Authentication

Supported modes:
- session-based login
- bearer API keys

Session auth:
- form login
- cookie-based session
- secure session secret required
- `DASHBOARD_HTTPS_ONLY=1` enables the secure cookie posture for TLS deployments

API keys:
- generated and stored through RBAC flows
- roles:
  - `viewer`
  - `operator`
  - `admin`

---

## Authorization

Authorization is role-based and enforced in the dashboard routers.

Representative permission domains:
- read findings
- modify findings
- run scans
- manage API keys

The source of truth is `dashboard/rbac.py`.

---

## Browser protections

Current protections include:
- CSRF tokens for browser-based mutating requests
- CSP with nonce-based script handling
- HSTS
- X-Frame-Options
- X-Content-Type-Options
- Permissions-Policy
- Referrer-Policy
- rate limiting for login and API traffic

Important nuance:
- the application itself defaults `DASHBOARD_CSP_ALLOW_UNSAFE_EVAL` to off
- the shipped `docker-compose.yml` currently turns it on by default unless you override it in `.env`
- treat that Compose default as a compatibility choice, not as the hardened target posture

---

## Closed security posture

Security controls already implemented in the current baseline:
- role-based authorization in dashboard routers
- CSRF tokens for browser-based mutating requests
- authenticated Prometheus scrape endpoint
- SSRF validation for webhook targets and URL scanning
- path traversal defenses around scan/file handling
- rate limiting for login and API traffic
- scanner target compatibility routing
- image build scanning in CI with Trivy

---

## Input and target safety

Important protections already implemented:
- path traversal defense on scan id / file path handling
- SSRF protections for scan targets and webhook URLs
- DNS rebinding-aware validation for webhook delivery and URL scanning
- target compatibility routing to avoid invalid scanner-target combinations

---

## Scanner execution safety

The orchestrator:
- validates target types before routing
- runs scanner subprocesses with a reduced environment model
- checks binary presence
- supports caching without trusting scanner availability blindly

Critical runtime directories:
- report directory
- workspaces
- cache directory

These should remain writable only to the expected runtime user/context.

---

## Data and reporting

Security-relevant data handled by the platform:
- scan metadata
- normalized findings
- finding triage state
- API key metadata
- audit log
- notification preferences
- webhook definitions

Exports exist in multiple formats, so operators should treat exported files as potentially sensitive artifacts.

---

## Operational security expectations

For production:
- set strong `DASHBOARD_PASSWORD`
- set strong `DASHBOARD_SESSION_SECRET`
- prefer HTTPS with secure cookies
- use least-privilege API keys
- review webhook targets carefully
- protect backup artifacts
- review policy rules before treating the platform as a hard gate

---

## Operationally dependent hardening

Some hardening is intentionally dependent on deployment choices rather than forced at runtime:
- strong operator secrets supplied through environment variables
- secure cookies only when TLS deployment sets `DASHBOARD_HTTPS_ONLY=1`
- reverse proxy posture and forwarded-header correctness
- whether `DASHBOARD_CSP_ALLOW_UNSAFE_EVAL` is overridden away from the Compose compatibility default
- whether the `Security Scan` workflow is running in remote-scan mode or local Gitleaks fallback mode

---

## CI security scan posture

Current behavior:
- remote platform scan when `SECURITY_SCANNER_URL` and `SECURITY_SCANNER_API_KEY` are configured
- local Gitleaks fallback otherwise

That means the exact security meaning of a green run depends on workflow mode. This is operationally acceptable only if your team understands that distinction.

---

## Accepted risks still present by choice

These are not hidden; they remain because they were consciously deferred:
- insecure Compose fallback values still exist in `docker-compose.yml`
- insecure runtime fallback auth values still exist in `dashboard/app.py`
- webhook cipher fallback behavior has not been reworked yet
- some deployment hardening still depends on operator-supplied environment values

If those risks are reopened later, this document should be updated together with the implementation.
