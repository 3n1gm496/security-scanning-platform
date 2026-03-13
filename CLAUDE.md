# Claude task: UI/UX bug fixing and refinement review

You are acting as a **senior frontend + full-stack engineer** reviewing and improving this repository:

https://github.com/3n1gm496/security-scanning-platform

The project already works, but several **UX bugs, inconsistencies, and missing capabilities** have been identified after real usage.

Your task is to:

1. Diagnose the likely cause of each issue in the codebase
2. Identify the relevant files
3. Propose concrete fixes
4. Suggest improved UX behavior where appropriate
5. Provide patch-style or code-level suggestions where possible

Do not answer generically.  
Base your reasoning on the repository structure and code.

Write the answer in **Italian**.

---

# Issues to investigate and fix

## 1 — Scan progress bar still visible after scan completed

Observed behavior:

- A scan was executed and completed successfully.
- After returning to the **Dashboard**, the UI still shows the **scan progress/loading bar** as if the scan were still running.

Your tasks:

1. Identify where scan status is fetched and displayed in the dashboard.
2. Determine why the UI may keep showing "running" state.
3. Investigate possible causes:
   - stale cached data
   - polling logic not refreshing correctly
   - status mapping mismatch
   - scan completion not updating frontend state
4. Propose a fix.

Provide:
- likely root cause
- files involved
- recommended code change.

---

# 2 — Problems in the "Scans" tab

Several UI/UX issues exist in the **Scans tab**.

### 2.1 Button styling inconsistency

Buttons:

- `Reset`
- `+ New Scan`

Problems:

- Different dimensions compared to other buttons in the app
- Different color palette
- Visual inconsistency with rest of UI

Tasks:

- Identify the button styling source
- Explain why they differ
- Propose consistent styling aligned with the rest of the UI
- Suggest reusable button classes if missing

---

### 2.2 Column label problem

In the scans table:

- The column **Critical** appears as **"crit"**

Tasks:

- Identify where column headers are defined
- Fix the label
- Ensure consistent naming with other severity columns

---

### 2.3 Sorting problems

Sorting by **Findings** does not work.

Additionally, the following columns **should be sortable but currently are not**:

- type
- status
- policy
- high

Tasks:

1. Identify how sorting is implemented in the table
2. Explain why "findings" sorting is broken
3. Implement sortable behavior for the additional columns
4. Ensure sorting is:
   - stable
   - consistent with numeric vs text values

---

# 3 — Findings tab improvements

## 3.1 Remediation RAW link not clickable

Inside **Finding details**, the field:

Remediation (raw)

is not clickable.

Tasks:

- Find where remediation text is rendered
- Convert URLs into clickable links
- Ensure long URLs wrap properly
- Avoid XSS issues when rendering links

---

## 3.2 Findings pagination size

Currently the findings table does not allow choosing **how many findings per page**.

Add:

- a page size selector (example: 10 / 25 / 50 / 100)
- persistent user preference if possible

Explain:

- where pagination logic lives
- how to add configurable page size cleanly

---

## 3.3 Export/download ignores filters

When exporting findings:

- the download **exports all findings**
- it **ignores the currently active filters**

Desired behavior:

The download must respect:

- severity filters
- status filters
- search filters
- pagination filters if applicable

Tasks:

- locate export implementation
- ensure export uses current filtered dataset
- propose backend vs frontend implementation if needed

---

## 3.4 Broken CVE links

Often clicking a link in column **CVE / ID** leads to an NVD error:

Invalid Parameters  
cveId: must match "(cve|CVE)-[0-9]{4}-[0-9]{4,}$"

This suggests malformed CVE values.

Tasks:

1. Identify where the CVE link is constructed
2. Detect possible causes:
   - malformed CVE values
   - missing prefix
   - truncated strings
3. Implement validation before generating NVD link
4. Ensure correct format:

CVE-YYYY-NNNN

5. Provide fallback behavior if the CVE is invalid.

---

# 4 — New chart near "Tool Effectiveness"

In the dashboard there is already a chart:

Tool Effectiveness

Add another chart **next to it**.

Tasks:

1. Identify the dashboard chart layout
2. Propose a **useful complementary chart**

Examples could include:

- Findings by severity
- Scan success vs failure rate
- Findings trend by scanner
- Risk distribution

Explain:

- why this chart adds value
- where to insert it
- required data source
- implementation approach

---

# 5 — Dark theme issue with "Trend Risk Score"

In **dark mode**, the chart:

Trend Risk Score

is hard to read.

Likely issues:

- low contrast
- axis colors
- grid visibility
- line colors

Tasks:

1. Identify chart configuration
2. Fix dark theme styling:
   - axis labels
   - grid lines
   - line colors
   - tooltip colors
3. Ensure both themes render correctly.

---

# Output format

Respond with this structure:

## 1. Root cause analysis
For each problem explain why it happens.

## 2. Files involved
List relevant files in the repo.

## 3. Recommended fixes
Provide concrete solutions.

## 4. Code-level suggestions
Where possible provide patch-style or example code.

## 5. UX improvements
Suggest better UX behavior where applicable.

Focus on **practical improvements**, not theory.
