# UI Operations Guide

This guide describes the current operator-facing dashboard after the SOC command center redesign.

---

## Visual model

- Dark mode is the primary visual mode.
- Light mode remains supported and is smoke-tested.
- The UI is organized as a command center, not a generic admin panel.
- Live refresh is intentionally restrained: the goal is situational awareness without UI jitter.

---

## Navigation model

Primary SPA sections:
- `Dashboard`
- `Scans`
- `Findings`
- `Analytics`
- `Compare`
- `Settings`

Global controls in the top bar:
- telemetry mode (`Live` or `Manual`)
- current scan state
- operator role label
- manual refresh
- theme toggle

Mobile uses an overlay sidebar instead of the desktop rail.

---

## Dashboard

Purpose:
- give a rapid posture read
- surface critical pressure
- summarize scan cadence and target coverage

Main areas:
- hero posture panel
- live threat rail
- severity chart
- trend chart
- remediation chart
- recent scan watchlist

Expected behavior:
- the page should feel live but not constantly rerender
- chart motion should be visible on initial load and user-driven changes, not on every background tick

---

## Scans

Purpose:
- queue and execution workspace
- operator entry point for compare and scan detail

Main areas:
- compact workspace intro
- filter ribbon
- scans table
- compare selection entry

Expected behavior:
- active scans can update in-place without destroying table context
- row click and action buttons should remain visually distinct

---

## Findings

Purpose:
- triage and remediation workspace

Main areas:
- compact workspace intro
- filter ribbon
- export controls
- bulk/status actions
- findings table
- finding detail modal

Expected behavior:
- no disruptive auto-refresh while the user is actively triaging
- long titles, file paths, and targets should truncate cleanly
- modal should feel like an investigation panel, not a generic form popup

---

## Analytics

Purpose:
- exposure and trend intelligence

Main areas:
- summary tiles
- risk distribution
- OWASP exposure map
- trend intelligence
- tool effectiveness
- target risk ranking

Expected behavior:
- charts should be readable in dark and light themes
- summary tiles must not overpower the charts
- labels and long target names must not break layout

---

## Compare

Purpose:
- compare two runs of the same target

Main areas:
- compact diff intro
- two scan selectors
- summary cards (`New`, `Resolved`, `Unchanged`)
- diff result sections

Expected behavior:
- the page should read like a baseline diff workstation
- empty state must remain informative, not generic

---

## Settings

Sections:
- API Keys
- Webhooks
- Notifications

Expected behavior:
- all sections inherit the same visual language as the rest of the command center
- forms, tables, and destructive actions should remain obvious and readable

---

## Modals

Key modal types:
- finding detail
- scan detail
- new scan
- new API key
- new webhook

Expected behavior:
- strong header hierarchy
- dark layered surfaces
- clear footer actions
- keyboard focus remains visible
- `Escape` closes the active modal without dropping the operator into a broken focus state

---

## Theme behavior

- Dark is the default mental model for design and QA.
- Light mode is a compatibility mode, but it should still look intentional and readable.
- Theme switching should not break charts, tables, or modal state.

---

## Live refresh behavior

Current principles:
- scan-state polling is separate from heavy page refresh
- analytics does not aggressively rerender on every scan tick
- findings refresh is conservative to preserve analyst context
- charts use restrained motion based on update context
- keyboard operators can sort tables, open row details, and move through modal flows without relying on the mouse

This is deliberate. If you see a page constantly jumping, treat it as a regression.

---

## Browser smoke screenshots

The smoke flow saves reference screenshots to:

```text
artifacts/browser-smoke/
```

Typical outputs include:
- login
- dashboard
- scans
- findings
- analytics
- compare
- settings
- modals
- light theme
- mobile navigation

Use them as a regression aid, not as the only acceptance signal.
