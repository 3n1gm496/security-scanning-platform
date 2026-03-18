# UI Validation Matrix

This matrix is the source of truth for the workflow-grade browser validation pass.
It complements `scripts/browser_smoke.mjs` and the repository test suite by
stating which operator-facing flows are exercised directly.

## Seed modes

### `normal`

Validates the mainline operator experience with representative data:
- multiple completed scans
- findings across severities and tools
- compare workflow with drift
- settings and modal flows
- dashboard refresh and logout

### `edge`

Validates stress and edge-state handling:
- long target names
- long finding titles and file paths
- findings with `CWE` values
- analytics empty states for selected charts
- compare workflow with an intentional no-drift pair

## Validation matrix

### Dashboard

- `blocking`
  - login redirect and initial dashboard bootstrap
  - `Review queue`, `Review scans`, and `View analytics` CTA navigation
  - `Launch scan` opens the correct modal
  - topbar refresh updates KPI state without page breakage
- `high`
  - sidebar collapse and expand
  - dark and light theme rendering
  - refreshed dashboard screenshot generation
- `medium`
  - watchlist readability with longer targets in `edge`
- `polish`
  - surface alignment, spacing, and CTA hierarchy

### Scans

- `blocking`
  - search filter
  - status and policy filtering
  - row click opens scan detail
  - action icon opens scan detail
  - findings drill-down from a row with findings
  - compare selection from visible scans
- `high`
  - visible-columns strip interaction
  - reset flow after filtering
- `medium`
  - long target handling in `edge`
- `polish`
  - density, action-cell spacing, and toolbar balance

### Findings

- `blocking`
  - search and severity filtering
  - row activation by keyboard
  - finding modal open
  - modal tab switching: `Overview`, `Remediation`, `Management`, `Comments`
  - comment submission
  - bulk status update
  - acknowledged filter after bulk update
- `high`
  - `CVE`/`CWE`/title/file rendering on long values
  - modal close controls and focus return
- `medium`
  - empty filtered state behavior
- `polish`
  - column hierarchy and triage rhythm

### Analytics

- `blocking`
  - chart fetches after navigation
  - chart refresh path
  - target risk board render
- `high`
  - empty-state rendering in `edge`
  - dark/light parity
- `medium`
  - long target ranking readability
- `polish`
  - chart framing, hints, and subtitle clarity

### Compare

- `blocking`
  - compare path from scans selection
  - compare request with drift in `normal`
  - compare request with no drift in `edge`
- `high`
  - baseline/comparison selector population and summary context
- `medium`
  - no-drift copy and result framing
- `polish`
  - setup density and selector ergonomics

### Settings

- `blocking`
  - settings tab switching
  - notification preference save
  - create key modal open
  - create webhook modal open
- `high`
  - focus behavior during tab changes
  - webhook and API key empty-state presentation
- `medium`
  - desktop layout balance in `Notifications`
- `polish`
  - modal shell rhythm and CTA hierarchy

### Theme and mobile

- `blocking`
  - theme toggle persistence across navigation
  - mobile nav open from toggle
  - mobile nav close from button
  - mobile nav close from backdrop
- `high`
  - mobile footer and logout readability
  - light-theme contrast on dashboard surfaces
- `medium`
  - overlay polish and responsive spacing
- `polish`
  - premium parity between desktop and mobile

### Logout

- `blocking`
  - authenticated logout POST
  - redirect back to `/login`

## Supporting verification

Run all of the following for a full pass:

```bash
PYTHONPATH=. ./venv/bin/pytest -q
node --check dashboard/static/app.js
node --check scripts/browser_smoke.mjs
BROWSER_SMOKE_SEED_MODE=normal node scripts/browser_smoke.mjs
BROWSER_SMOKE_SEED_MODE=edge node scripts/browser_smoke.mjs
```

Review screenshots in `artifacts/browser-smoke/` after each smoke run. The
directory is rewritten on each execution so it always reflects the latest pass.

## Residual expectations

After a green pass:
- primary operator actions are exercised, not just rendered
- edge datasets do not produce ugly overflow or broken empty states
- any remaining UI debt should be classified as `polish`, not functional breakage

This matrix does **not** claim the UI is perfect. It defines the evidence needed
to say the validated workflows currently behave as expected.
