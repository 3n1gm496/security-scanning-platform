# UI Audit Matrix

This matrix is the shared checklist for systematic UI and workflow audits.

---

## Severity convention

- `blocking`: production-breaking, major workflow failure, console/runtime crash
- `high`: serious usability or correctness issue with clear operator impact
- `medium`: meaningful UX, layout, refresh, or consistency issue
- `polish`: refinement that improves quality without blocking workflows

---

## Cluster checklist

| Cluster | Functional correctness | UX / density | Refresh / state | Theme / mobile / modal | Docs alignment |
|---|---|---|---|---|---|
| Dashboard | KPIs, charts, watchlist, CTA | Above-the-fold quality, hero balance | Soft-live behavior | Theme parity, modal interactions if invoked | README + UI guide |
| Scans | Filters, sorting, row actions, compare entry | Table readability, ribbon clarity | In-place scan updates | Mobile table/readability | UI guide |
| Findings | Filters, triage, export, bulk actions | Table density, severity/title priority | Context preservation | Finding modal, long text, mobile | UI guide |
| Analytics | Summary tiles, charts, ranking | Hierarchy, label balance, chart quality | Background refresh discipline | Dark/light chart legibility | UI guide + README |
| Compare | A/B selectors, summary counts, result sections | Workstation feel, empty state | State continuity | Mobile selector behavior | UI guide |
| Settings | API keys, webhooks, notifications | Form/table visual consistency | Tab persistence | Modal polish, theme consistency | README + docs |
| Login | Auth form | Balance, hierarchy, clarity | n/a | Dark/light readiness, smaller widths | README |

---

## Standard audit questions

Apply these to each cluster:

1. Does the view function correctly with realistic data?
2. Is the most important information visible without unnecessary chrome?
3. Are long labels, IDs, paths, and targets handled gracefully?
4. Does background refresh preserve context instead of fighting the user?
5. Does dark mode look intentional and light mode remain readable?
6. Do modal and secondary states match the quality of primary pages?
7. Is the documentation still true after the change?

---

## Exit criteria for a cluster

A cluster is considered closed only when:
- no known `blocking` or `high` issue remains
- smoke/runtime behavior is stable
- no obvious overflow or broken responsive state remains
- documentation affected by the cluster is updated
