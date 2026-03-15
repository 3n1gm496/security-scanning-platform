/**
 * Security Scanning Platform — SPA Vue.js
 * Version 2.0 — Complete SPA architecture with pagination, triage and analytics
 */

const { createApp, ref, reactive, computed, onMounted, nextTick, watch } = Vue;

// ─── Constants ───────────────────────────────────────────────────────────────

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'];

const SEVERITY_COLORS = {
  CRITICAL: '#dc2626', HIGH: '#f97316', MEDIUM: '#f59e0b',
  LOW: '#3b82f6', INFO: '#6b7280', UNKNOWN: '#9ca3af',
};

const STATUS_LABELS = ['New', 'Acknowledged', 'In Progress', 'Resolved', 'False Positive', 'Risk Accepted'];
const STATUS_KEYS   = ['new', 'acknowledged', 'in_progress', 'resolved', 'false_positive', 'risk_accepted'];
const STATUS_COLORS = ['#6b7280', '#f59e0b', '#3b82f6', '#10b981', '#8b5cf6', '#ec4899'];

const OWASP_COLORS = ['#ef4444', '#f97316', '#f59e0b', '#14b8a6', '#3b82f6', '#8b5cf6'];
const RISK_COLORS  = ['#10b981', '#f59e0b', '#f97316', '#dc2626'];

// ─── Utility ──────────────────────────────────────────────────────────────────

function debounce(fn, delay) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}

function normalizePerPage(value, fallback = 50) {
  const parsed = parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

// CSRF token cache — fetched once, reused for all mutating requests.
let _csrfToken = null;

async function getCsrfToken(forceRefresh = false) {
  if (forceRefresh) {
    _csrfToken = null;
  }
  if (!_csrfToken) {
    const res = await fetch('/api/csrf-token');
    if (res.ok) {
      const data = await res.json();
      _csrfToken = data.csrf_token || '';
    }
  }
  return _csrfToken;
}

async function _fetchWithCsrfRetry(url, options, timeoutMs, parseJson) {
  const attempt = async (forceRefresh = false) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const requestOptions = { ...options };
      if (_MUTATING_METHODS.has((requestOptions.method || 'GET').toUpperCase())) {
        const token = await getCsrfToken(forceRefresh);
        requestOptions.headers = { 'X-CSRF-Token': token, ...requestOptions.headers };
      }
      const res = await fetch(url, { signal: controller.signal, ...requestOptions });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        const message = err.detail || `HTTP ${res.status}`;
        if (!forceRefresh && res.status === 403 && /csrf/i.test(message)) {
          return attempt(true);
        }
        throw new Error(message);
      }
      return parseJson ? res.json() : res;
    } catch (err) {
      if (err.name === 'AbortError') {
        throw new Error(`Request timed out after ${timeoutMs / 1000}s: ${url}`);
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  };
  return attempt(false);
}

const _MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

async function apiFetch(url, options = {}, timeoutMs = 30000) {
  return _fetchWithCsrfRetry(url, options, timeoutMs, true);
}

/** Like apiFetch but does not parse JSON — validates res.ok and returns the raw Response. */
async function apiSend(url, options = {}) {
  return _fetchWithCsrfRetry(url, options, 30000, false);
}

function formatDate(iso) {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    return d.toLocaleString('en-GB', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit'
    });
  } catch {
    return iso;
  }
}

// ─── App ──────────────────────────────────────────────────────────────────────

createApp({
  data() {
    const init = window.__INIT_DATA__ || {};
    return {
      // ── Auth / User
      currentUser: init.user || 'unknown',
      currentUserRole: String(init.userRole || 'admin').toLowerCase(),

      // ── Navigation
      currentPage: 'dashboard',
      sidebarCollapsed: false,
      mobileNavOpen: false,

      // ── Global state
      loading: false,
      autoRefresh: true,
      chartsAvailable: typeof window.Chart !== 'undefined' && !window.__CHARTJS_FAILED,
      refreshInterval: null,
      toasts: [],
      toastCounter: 0,

      // ── Dashboard data
      kpis: init.kpis || {},
      recentScans: init.recentScans || [],
      severityBreakdown: init.severityBreakdown || {},
      toolBreakdown: init.toolBreakdown || {},
      trend: init.trend || [],
      availableTargets: init.availableTargets || [],
      availableTools: init.availableTools || [],
      availableUsers: [],

      // ── Toggle scan table columns
      scanColumns: [
        { key: 'id', label: 'ID', visible: false },
        { key: 'target_name', label: 'Target', visible: true },
        { key: 'target_type', label: 'Type', visible: true },
        { key: 'status', label: 'Status', visible: true },
        { key: 'policy_status', label: 'Policy', visible: true },
        { key: 'findings_count', label: 'Findings', visible: true },
        { key: 'critical_count', label: 'Critical', visible: true },
        { key: 'high_count', label: 'High', visible: true },
        { key: 'created_at', label: 'Date', visible: true },
      ],

      // ── Charts refs (managed via $refs)
      charts: {},

      // ── Scans page
      scans: [],
      scansLoading: false,
      scansTotal: 0,
      scansPage: 1,
      scansCursor: null,
      scansCursorStack: [],
      scansSort: { by: 'created_at', order: 'DESC' },
      scansFilter: { search: '', target: '', status: '', policy: '' },
      scansPerPage: 20,
      filteredScansTargets: null,

      // ── Findings page
      findings: [],
      findingsLoading: false,
      findingsTotal: 0,
      findingsPage: 1,
      findingsCursor: null,
      findingsCursorStack: [],
      findingsFilter: { search: '', severity: '', tool: '', target: '', status: '', scan_id: '' },
      findingsSort: { by: 'id', order: 'ASC' },
      findingsColumns: [
        { key: 'severity', label: 'Severity', visible: true },
        { key: 'tool', label: 'Tool', visible: true },
        { key: 'target', label: 'Target', visible: true },
        { key: 'title', label: 'Title', visible: true },
        { key: 'cve', label: 'CVE/ID', visible: true },
        { key: 'file', label: 'File', visible: true },
        { key: 'status', label: 'Status', visible: true },
      ],
      filteredFindingsTargets: null,
      filteredFindingsTools: null,
      selectedFindings: [],
      bulkStatus: '',

      // ── Finding detail modal
      selectedFinding: null,
      findingState: {},
      findingComments: [],
      newFindingStatus: '',
      assignTo: '',
      newComment: '',

      // ── Scan detail modal
      selectedScan: null,

      // ── Analytics page
      analyticsData: {
        riskDistribution: null,
        compliance: null,
        trends: null,
        targetRisk: null,
        toolEffectiveness: null,
      },
      analyticsDays: 30,
      analyticsRefreshing: false,
      _analyticsRefreshSeq: 0,

      // ── Settings page
      settingsTab: 'apikeys',
      apiKeys: [],
      webhooks: [],
      showCreateKeyModal: false,
      showCreateWebhookModal: false,
      newKeyForm: { name: '', role: 'operator', expires_days: null },
      newKeyResult: '',
      newWebhookForm: { name: '', url: '', events: 'scan.completed', secret: '' },

      // ── Notifications settings
      notifPrefs: {
        user_email: '',
        critical_alerts: true,
        high_alerts: false,
        weekly_digest: false,
        scan_summaries: false,
        preferred_channel: 'email',
      },

      // ── Compare page
        compareIdA: '',
        compareIdB: '',
        compareScanList: [],
        // compareScanListB is a computed property — see computed section below
      compareResult: null,
      compareLoading: false,
      selectedScans: [],

      // ── New Scan modal
      showScanModal: false,
      scanTriggering: false,
      newScanForm: { name: '', target: '', target_type: 'local' },
      scanPollingInterval: null,
      hasRunningScans: false,
      findingsPerPage: normalizePerPage(localStorage.getItem('ssp-findings-per-page'), 50),

      // ── Finding modal tabs
      findingModalTab: 'info',
      findingStatusNotes: '',
      showAcceptRiskForm: false,
      acceptRiskJustification: '',
      acceptRiskExpiry: '',

      // ── Dark mode
      darkMode: false,

      // ── UI overlays
      showFindingModal: false,
    };
  },

  computed: {
    pageTitle() {
      const titles = {
        dashboard: 'Dashboard',
        scans: 'Scans',
        findings: 'Findings',
        analytics: 'Analytics',
        compare: 'Compare Scans',
        settings: 'Settings',
      };
      return titles[this.currentPage] || '';
    },
    pageSubtitle() {
      const subs = {
        dashboard: 'Security posture overview',
        scans: 'History of all scan executions',
        findings: 'Detected vulnerabilities and lifecycle management',
        analytics: 'Risk scoring, compliance and trends',
        compare: 'Differential analysis between two scans',
        settings: 'API keys, webhooks and configuration',
      };
      return subs[this.currentPage] || '';
    },
    currentUserRoleLabel() {
      const labels = { admin: 'Administrator', operator: 'Operator', viewer: 'Viewer' };
      return labels[this.currentUserRole] || 'User';
    },
    allSelected() {
      return this.findings.length > 0 && this.findings.every(f => this.selectedFindings.includes(f.id));
    },
    // Scan B list: only scans with the same target_name as scan A (excluding scan A itself)
    compareScanListB() {
      if (!this.compareIdA) return this.compareScanList;
      const scanA = this.compareScanList.find(s => s.id === this.compareIdA);
      if (!scanA) return this.compareScanList;
      return this.compareScanList.filter(s => s.id !== this.compareIdA && s.target_name === scanA.target_name);
    },
  },

   async mounted() {
    this._remediationChartVersion = 0;
    this.debouncedLoadFindings = debounce(() => this.loadFindings(true), 400);
    this.debouncedLoadScans = debounce(() => this.loadScans(true), 400);

    // ── URL Routing: read initial page + filter params from URL hash
    const validPages = ['dashboard', 'scans', 'findings', 'analytics', 'settings', 'compare'];
    const rawHash = window.location.hash.replace('#', '');
    const [hashPage, hashQuery] = rawHash.split('?');
    const initialPage = validPages.includes(hashPage) ? hashPage : 'dashboard';
    if (initialPage !== 'dashboard') this.currentPage = initialPage;

    // Apply filter params from hash (e.g. #findings?severity=HIGH&tool=semgrep)
    if (hashQuery && initialPage === 'findings') {
      const hp = new URLSearchParams(hashQuery);
      for (const key of ['search', 'severity', 'tool', 'target', 'status', 'scan_id']) {
        if (hp.has(key)) this.findingsFilter[key] = hp.get(key);
      }
    }
    history.replaceState({ page: initialPage }, '', '#' + initialPage);

    // ── History API: back/forward button support
    this._popstateHandler = async (e) => {
      const page = (e.state && e.state.page) ? e.state.page : 'dashboard';
      if (validPages.includes(page) && page !== this.currentPage) {
        await this.navigate(page, { pushHistory: false });
      }
    };
    window.addEventListener('popstate', this._popstateHandler);

    // ── Dark mode: restore preference from localStorage
    const savedTheme = localStorage.getItem('ssp-theme');
    if (savedTheme === 'dark') {
      this.darkMode = true;
      document.documentElement.setAttribute('data-theme', 'dark');
    }

    // ── Keyboard: Escape to close modals + Tab focus trap
    this._keyHandler = (e) => {
      if (e.key === 'Escape') {
        this.showFindingModal = false;
        this.showScanModal = false;
        this.selectedFinding = null;
        this.selectedScan = null;
        this.showCreateKeyModal = false;
        this.showCreateWebhookModal = false;
      }
      // Focus trap: keep Tab within the active modal
      if (e.key === 'Tab') {
        const overlay = document.querySelector('.modal-overlay[role="dialog"]');
        if (!overlay) return;
        const focusable = overlay.querySelectorAll(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );
        if (focusable.length === 0) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (e.shiftKey) {
          if (document.activeElement === first) { e.preventDefault(); last.focus(); }
        } else {
          if (document.activeElement === last) { e.preventDefault(); first.focus(); }
        }
      }
    };
    document.addEventListener('keydown', this._keyHandler);

    // Load the user list for the assignment datalist
    this.loadAvailableUsers();

    // If trend data was not server-injected, fetch it from the API
    if (!this.trend || this.trend.length === 0) {
      try {
        const trendResp = await apiFetch('/api/trends?days=14').catch(() => null);
        if (trendResp && trendResp.trend) this.trend = trendResp.trend;
        else if (Array.isArray(trendResp)) this.trend = trendResp;
      } catch (e) {
        console.debug('[mount] trend fetch failed:', e.message);
      }
    }

    // Yield to the browser so CSS custom properties are fully computed before
    // reading them via getComputedStyle (important when dark mode is restored
    // from localStorage before the first paint).
    await nextTick();
    this.applyChartDefaults();
    await this.initDashboardCharts();
    if (initialPage !== 'dashboard') {
      // Force data loading for the initial page.  navigate() would bail out
      // because currentPage was already set above — so use refreshCurrentPage().
      await this.refreshCurrentPage();
    }
    this.startAutoRefresh();

    this._resizeHandler = () => this.forceResizeCharts();
    window.addEventListener('resize', this._resizeHandler);

    // Check for running scans on mount — resume polling if any are active
    try {
      const result = await apiFetch('/api/scans/paginated?per_page=10&sort_by=created_at&sort_order=DESC');
      const items = result.items || [];
      const runningScans = items.filter(s => s.status === 'RUNNING');
      if (runningScans.length > 0) {
        this.startScanPolling(runningScans[0].id);
      }
    } catch (_) {}

    // Pre-warm the analytics backend cache in the background so the first
    // visit to the Analytics tab doesn't trigger 6 un-cached DB queries.
    if (initialPage !== 'analytics') {
      const warmup = [
        '/api/analytics/risk-distribution',
        '/api/analytics/compliance',
        '/api/analytics/trends?days=30',
        '/api/analytics/target-risk',
        '/api/analytics/tool-effectiveness',
        '/api/chart/severity-breakdown',
      ];
      Promise.allSettled(warmup.map(u => fetch(u))).catch(() => {});
    }
  },
  beforeUnmount() {
    if (this.refreshInterval) clearInterval(this.refreshInterval);
    this.stopScanPolling();
    if (this._resizeHandler) window.removeEventListener('resize', this._resizeHandler);
    if (this._popstateHandler) window.removeEventListener('popstate', this._popstateHandler);
    Object.values(this.charts).forEach(c => c && c.destroy());
    if (this._keyHandler) document.removeEventListener('keydown', this._keyHandler);
    if (this._toastTimers) {
      this._toastTimers.forEach(timer => clearTimeout(timer));
      this._toastTimers.clear();
    }
  },

  methods: {
    // ── Modal accessibility ───────────────────────────────────────────────────

    async focusModal() {
      await nextTick();
      const overlay = document.querySelector('.modal-overlay[role="dialog"]');
      if (!overlay) return;
      const first = overlay.querySelector(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      );
      if (first) first.focus();
    },

    // ── Chart theme helpers ────────────────────────────────────────────────────

    applyChartDefaults() {
      if (!this.chartsAvailable) return;
      const s = getComputedStyle(document.documentElement);
      Chart.defaults.color = s.getPropertyValue('--chart-tick').trim() || '#6b7280';
      Chart.defaults.borderColor = s.getPropertyValue('--chart-grid').trim() || 'rgba(0,0,0,0.06)';
    },

    // Read a CSS variable from :root — used by all chart builders for consistent theming
    cssVar(name) {
      return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    },

    forceResizeCharts() {
      if (!this.chartsAvailable) return;
      requestAnimationFrame(() => {
        Object.values(this.charts).forEach(chart => {
          if (!chart) return;
          chart.resize();
          chart.update('none');
        });
      });
    },

    // ── Toggle columns ───────────────────────────────────────────────────────────────────────────────────
    colVisible(key) {
      const col = this.scanColumns.find(c => c.key === key);
      return col ? col.visible : true;
    },
    colVisibleF(key) {
      const col = this.findingsColumns.find(c => c.key === key);
      return col ? col.visible : true;
    },
    sortFindings(col) {
      if (this.findingsSort.by === col) {
        this.findingsSort.order = this.findingsSort.order === 'ASC' ? 'DESC' : 'ASC';
      } else {
        this.findingsSort.by = col;
        this.findingsSort.order = 'DESC';
      }
      this.loadFindings(true);
    },

    // ── Navigation ─────────────────────────────────────────────────────────────────────────────────────

    async navigate(page, { pushHistory = true } = {}) {
      // Skip redundant navigation to the same page (prevents chart destruction)
      if (page === this.currentPage && !this._refreshing) return;

      // Destroy chart instances when leaving a chart page — the v-if directive
      // removes the canvas elements from the DOM so old instances become stale.
      const prevPage = this.currentPage;
      if (prevPage !== page) {
        if (prevPage === 'dashboard') {
          ['severity', 'trend', 'remediation'].forEach(k => {
            if (this.charts[k]) { this.charts[k].destroy(); this.charts[k] = null; }
          });
        } else if (prevPage === 'analytics') {
          ['risk', 'owasp', 'analyticsTrend', 'toolEff', 'severityDist'].forEach(k => {
            if (this.charts[k]) { this.charts[k].destroy(); this.charts[k] = null; }
          });
        }
      }

      this.currentPage = page;
      this.mobileNavOpen = false;
      // Update URL hash for bookmarkability and back/forward support
      if (pushHistory) history.pushState({ page }, '', '#' + page);
      window.scrollTo(0, 0);
      await nextTick();
      if (page === 'dashboard') await this.initDashboardCharts();
      if (page === 'scans') await this.loadScans(true);
      if (page === 'findings') await this.loadFindings(true);
      if (page === 'analytics') await this.loadAnalytics();
      if (page === 'settings') {
        this.settingsTab = 'apikeys';
        await this.loadApiKeys();
      }
      if (page === 'compare') {
        await this.loadCompareScanList();
      }
      // Attach resize handles to any tables that appeared after navigation
      // (scans/findings call this themselves; other pages need it here)
      if (!['scans', 'findings'].includes(page)) this.initResizableColumns();
    },

    async refreshCurrentPage() {
      if (this._refreshing) return;
      this._refreshing = true;
      try {
        await this.navigate(this.currentPage);
      } finally {
        this._refreshing = false;
      }
    },

    // ── Toast ─────────────────────────────────────────────────────────────────

    showToast(message, type = 'success') {
      const id = ++this.toastCounter;
      this.toasts.push({ id, message, type });
      if (!this._toastTimers) this._toastTimers = new Set();
      const timer = setTimeout(() => {
        this.toasts = this.toasts.filter(t => t.id !== id);
        this._toastTimers.delete(timer);
      }, 4000);
      this._toastTimers.add(timer);
    },

    toggleMobileNav() {
      this.mobileNavOpen = !this.mobileNavOpen;
    },

    closeMobileNav() {
      this.mobileNavOpen = false;
    },

    // ── Auto-refresh ──────────────────────────────────────────────────────────

    startAutoRefresh() {
      this.refreshInterval = setInterval(async () => {
        if (!this.autoRefresh) return;
        try {
          // Always refresh KPIs
          this.kpis = await apiFetch('/api/kpi');
        } catch (e) {
          console.debug('[autoRefresh] KPI poll failed:', e.message);
        }
        // Refresh data for the currently visible page
        try {
          if (this.currentPage === 'dashboard') {
            await this.initDashboardCharts();
          } else if (this.currentPage === 'scans') {
            await this.loadScans(false, true);
          } else if (this.currentPage === 'findings') {
            await this.loadFindings(false, true);
          } else if (this.currentPage === 'analytics') {
            await this._refreshAnalyticsData();
          }
        } catch (e) {
          console.debug('[autoRefresh] page refresh failed:', e.message);
        }
      }, 30000);
    },

    startScanPolling(scanId) {
      this.hasRunningScans = true;
      this._pollScanId = scanId || null;
      this._pollDeadline = Date.now() + 37 * 60 * 1000; // 37 min (> 30 min subprocess timeout)
      if (this.scanPollingInterval) return;
      this.scanPollingInterval = setInterval(async () => {
        try {
          const result = await apiFetch('/api/scans/paginated?per_page=20&sort_by=created_at&sort_order=DESC');
          const items = result.items || [];
          this.recentScans = items.slice(0, 12);

          // Refresh KPIs and current page data on every poll tick
          try { this.kpis = await apiFetch('/api/kpi'); } catch (_) {}
          if (this.currentPage === 'dashboard') { await nextTick(); await this.initDashboardCharts(); }
          else if (this.currentPage === 'scans') { await this.loadScans(false, true); }
          else if (this.currentPage === 'findings') { await this.loadFindings(false, true); }
          else if (this.currentPage === 'analytics') { try { await this._refreshAnalyticsData(); } catch (_) {} }

          // Check if the tracked scan is still RUNNING
          const stillRunning = this._pollScanId
            ? items.some(s => s.id === this._pollScanId && s.status === 'RUNNING')
            : items.some(s => s.status === 'RUNNING');
          if (!stillRunning || Date.now() > this._pollDeadline) {
            this.hasRunningScans = false;
            this.stopScanPolling();
            // Notify user
            const targetScan = this._pollScanId
              ? items.find(s => s.id === this._pollScanId)
              : null;
            if (targetScan && targetScan.status === 'FAILED') {
              this.showToast('Scan failed: ' + (targetScan.error_message || 'unknown error'), 'error');
            } else if (targetScan && (targetScan.status === 'COMPLETED_WITH_FINDINGS' || targetScan.status === 'COMPLETED_CLEAN')) {
              this.showToast('Scan completed successfully');
            } else if (!this._pollScanId) {
              // Mount-time recovery: no specific scan tracked, generic message
              this.showToast('Scan completed successfully');
            }
            // Final refresh to ensure everything is fully up-to-date
            try { this.kpis = await apiFetch('/api/kpi'); } catch (_) {}
            if (this.currentPage === 'dashboard') { await nextTick(); await this.initDashboardCharts(); }
            else if (this.currentPage === 'scans') { await this.loadScans(false, true); }
            else if (this.currentPage === 'findings') { await this.loadFindings(false, true); }
            else if (this.currentPage === 'analytics') { try { await this._refreshAnalyticsData(); } catch (_) {} }
          }
        } catch (e) {
          console.debug('[scanPolling] poll failed:', e.message);
        }
      }, 5000);
    },

    stopScanPolling() {
      if (this.scanPollingInterval) {
        clearInterval(this.scanPollingInterval);
        this.scanPollingInterval = null;
      }
    },

    // ── Dashboard Charts ──────────────────────────────────────────────────────

    async initDashboardCharts() {
      if (!this.chartsAvailable) return;
      if (this._chartsBuilding) return;
      this._chartsBuilding = true;
      try {
        // Pre-fetch severity data so the chart builder does not make its own
        // request (avoids destroy-then-wait-for-fetch blank canvas flicker).
        let sevData = {};
        try {
          const fresh = await apiFetch('/api/chart/severity-breakdown');
          if (fresh && Array.isArray(fresh.labels)) {
            fresh.labels.forEach((k, i) => { sevData[k.toUpperCase()] = fresh.values[i]; });
          } else if (fresh && typeof fresh === 'object') {
            Object.assign(sevData, fresh);
          }
        } catch (_) {
          sevData = this.severityBreakdown || {};
        }
        await nextTick();
        this.buildTrendChart();
        this.buildSeverityChart(sevData);
        this.buildRemediationChart();
      } finally {
        this._chartsBuilding = false;
      }
    },

    buildRemediationChart() {
      const canvas = this.$refs.remediationChart;
      if (!canvas) return;
      if (this.charts.remediation && this.charts.remediation.canvas !== canvas) {
        this.charts.remediation.destroy(); this.charts.remediation = null;
      }
      const labels = STATUS_LABELS;
      const colors = STATUS_COLORS;
      if (!this.charts.remediation) {
        this.charts.remediation = new Chart(canvas.getContext('2d'), {
          type: 'bar',
          data: {
            labels,
            datasets: [{
              label: 'Findings',
              data: [0, 0, 0, 0, 0, 0],
              backgroundColor: colors,
              borderRadius: 6,
              borderSkipped: false,
            }],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: { display: false },
              tooltip: { callbacks: { label: ctx => ` ${ctx.parsed.y} findings` } },
            },
            scales: {
              x: { grid: { display: false }, ticks: { font: { size: 11 } } },
              y: { beginAtZero: true, grid: { color: this.cssVar('--chart-grid') }, ticks: { precision: 0 } },
            },
          },
        });
      }
      // Load real data from the single status-counts endpoint
      const chartId = ++this._remediationChartVersion;
      apiFetch('/api/findings/status-counts').then(statusMap => {
        const counts = STATUS_KEYS.map(s => statusMap[s] || 0);
        return counts;
      }).catch(() => STATUS_KEYS.map(() => 0)).then(counts => {
        // Discard stale response if chart was rebuilt or user navigated away
        if (!this.charts.remediation || this._remediationChartVersion !== chartId) return;
        // Filter out categories with zero findings to reduce visual noise
        const nonZeroIdx = counts.map((c, i) => c > 0 ? i : -1).filter(i => i >= 0);
        if (nonZeroIdx.length > 0) {
          this.charts.remediation.data.labels = nonZeroIdx.map(i => labels[i]);
          this.charts.remediation.data.datasets[0].data = nonZeroIdx.map(i => counts[i]);
          this.charts.remediation.data.datasets[0].backgroundColor = nonZeroIdx.map(i => colors[i]);
        } else {
          this.charts.remediation.data.labels = labels;
          this.charts.remediation.data.datasets[0].data = counts;
          this.charts.remediation.data.datasets[0].backgroundColor = colors;
        }
        this.charts.remediation.update();
      });
    },

    buildSeverityChart(data) {
      const canvas = this.$refs.severityChart;
      if (!canvas) return;
      // If chart instance points to a canvas removed by v-if, discard it.
      if (this.charts.severity && this.charts.severity.canvas !== canvas) {
        this.charts.severity.destroy(); this.charts.severity = null;
      }
      // Use provided data (pre-fetched by caller) or fall back to init data.
      if (!data || Object.keys(data).length === 0) data = this.severityBreakdown || {};
      const labels = SEVERITY_ORDER.filter(k => data[k] !== undefined && data[k] > 0);
      const values = labels.map(k => data[k]);
      const colors = labels.map(k => SEVERITY_COLORS[k] || '#9ca3af');
      if (this.charts.severity) {
        this.charts.severity.data.labels = labels;
        this.charts.severity.data.datasets[0].data = values;
        this.charts.severity.data.datasets[0].backgroundColor = colors;
        this.charts.severity.update();
        return;
      }
      const legendColor = () => this.cssVar('--chart-legend') || '#374151';
      this.charts.severity = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: {
          labels,
          datasets: [{
            label: 'Findings',
            data: values,
            backgroundColor: colors,
            borderRadius: 6,
            borderSkipped: false,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: {
            legend: {
              display: true,
              position: 'bottom',
              labels: {
                boxWidth: 12,
                font: { size: 11 },
                padding: 12,
                usePointStyle: false,
                color: this.cssVar('--chart-legend'),
                generateLabels: (chart) => {
                  return chart.data.labels.map((label, i) => ({
                    text: `${label}  (${chart.data.datasets[0].data[i]})`,
                    fillStyle: chart.data.datasets[0].backgroundColor[i],
                    fontColor: legendColor(),
                    lineWidth: 0,
                    hidden: false,
                    index: i,
                  }));
                },
              },
            },
            tooltip: {
              callbacks: {
                label: ctx => ` ${ctx.parsed.x} findings`,
              },
            },
          },
          scales: {
            x: { beginAtZero: true, grid: { color: this.cssVar('--chart-grid') }, ticks: { precision: 0, color: this.cssVar('--chart-tick') } },
            y: { grid: { display: false }, ticks: { font: { weight: '600' }, color: this.cssVar('--chart-tick') } },
          },
        },
      });
    },

    buildTrendChart() {
      const canvas = this.$refs.trendChart;
      if (!canvas) return;
      if (this.charts.trend && this.charts.trend.canvas !== canvas) {
        this.charts.trend.destroy(); this.charts.trend = null;
      }

      const scans = (this.recentScans || []).slice(0, 12);
      if (scans.length === 0) {
        if (this.charts.trend) {
          this.charts.trend.destroy();
          this.charts.trend = null;
        }
        return;
      }

      const labels = scans.map(s => {
        const name = s.target_name || s.id || '?';
        return name.length > 18 ? name.slice(0, 16) + '…' : name;
      });

      const dsData = [
        scans.map(s => s.critical_count || 0),
        scans.map(s => s.high_count || 0),
        scans.map(s => s.medium_count || 0),
        scans.map(s => s.low_count || 0),
        scans.map(s => s.info_count || 0),
      ];

      if (this.charts.trend) {
        this.charts.trend.data.labels = labels;
        dsData.forEach((d, i) => {
          if (this.charts.trend.data.datasets[i]) this.charts.trend.data.datasets[i].data = d;
        });
        this.charts.trend.update();
        return;
      }

      this.charts.trend = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: {
          labels,
          datasets: [
            { label: 'Critical', data: scans.map(s => s.critical_count || 0), backgroundColor: SEVERITY_COLORS.CRITICAL, borderRadius: 3 },
            { label: 'High', data: scans.map(s => s.high_count || 0), backgroundColor: SEVERITY_COLORS.HIGH, borderRadius: 3 },
            { label: 'Medium', data: scans.map(s => s.medium_count || 0), backgroundColor: SEVERITY_COLORS.MEDIUM, borderRadius: 3 },
            { label: 'Low', data: scans.map(s => s.low_count || 0), backgroundColor: SEVERITY_COLORS.LOW, borderRadius: 3 },
            { label: 'Info', data: scans.map(s => s.info_count || 0), backgroundColor: SEVERITY_COLORS.INFO, borderRadius: 3 },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: { mode: 'index', intersect: false },
          plugins: {
            legend: {
              display: true,
              position: 'bottom',
              labels: { boxWidth: 12, font: { size: 11 }, padding: 20, usePointStyle: false },
            },
            tooltip: {
              callbacks: {
                footer: (items) => {
                  const total = items.reduce((sum, i) => sum + (i.raw || 0), 0);
                  return 'Total: ' + total;
                },
              },
            },
          },
          scales: {
            x: {
              stacked: false,
              grid: { display: false },
              ticks: { font: { size: 11 }, maxRotation: 45, color: this.cssVar('--chart-tick') },
            },
            y: {
              stacked: false,
              type: 'linear',
              grid: { color: this.cssVar('--chart-grid') },
              ticks: {
                font: { size: 11 },
                color: this.cssVar('--chart-tick'),
                precision: 0,
              },
              title: { display: true, text: 'Findings', font: { size: 10 }, color: this.cssVar('--chart-tick') },
            },
          },
        },
      });
    },

    // ── Scans ─────────────────────────────────────────────────────────────────

    async loadScans(reset = false, preservePage = false) {
      if (reset) {
        this.scansPage = 1;
        this.scansCursor = null;
        this.scansCursorStack = [];
        this._scansPageCursor = null;
      }
      this.scansLoading = true;
      try {
        const params = new URLSearchParams({
          per_page: this.scansPerPage,
          sort_by: this.scansSort.by,
          sort_order: this.scansSort.order,
        });
        if (this.scansFilter.search) params.set('search', this.scansFilter.search);
        if (this.scansFilter.target) params.set('target', this.scansFilter.target);
        if (this.scansFilter.status) params.set('status', this.scansFilter.status);
        if (this.scansFilter.policy) params.set('policy', this.scansFilter.policy);
        const requestCursor = preservePage ? (this._scansPageCursor || null) : this.scansCursor;
        if (requestCursor) params.set('cursor', requestCursor);
        const result = await apiFetch(`/api/scans/paginated?${params}`);
        this.scans = result.items || [];
        const scanPag = result.pagination || {};
        this.scansTotal = scanPag.total_count ?? scanPag.count ?? this.scans.length;
        this.scansCursor = scanPag.next_cursor || null;

        // Update available targets/tools from scan data for adaptive filtering
        this._updateScansFilterOptions();

        this.initResizableColumns();
      } catch (e) {
        this.showToast('Failed to load scans: ' + e.message, 'error');
      } finally {
        this.scansLoading = false;
      }
    },

    // Build filtered dropdown options based on current search text for scans
    _updateScansFilterOptions() {
      // If there's a search query, filter the available targets to show only matching ones
      // This makes the dropdowns context-aware
      if (this.scansFilter.search) {
        const searchLower = this.scansFilter.search.toLowerCase();
        this.filteredScansTargets = this.availableTargets.filter(
          t => t.toLowerCase().includes(searchLower) ||
               this.scans.some(s => s.target_name === t)
        );
      } else {
        this.filteredScansTargets = null; // null = show all
      }
    },

    sortScans(col) {
      if (this.scansSort.by === col) {
        this.scansSort.order = this.scansSort.order === 'ASC' ? 'DESC' : 'ASC';
      } else {
        this.scansSort.by = col;
        this.scansSort.order = 'DESC';
      }
      this.loadScans(true);
    },

    sortIcon(table, col) {
      const sort = table === 'scans' ? this.scansSort : this.findingsSort;
      if (!sort || sort.by !== col) return '↕';
      return sort.order === 'ASC' ? '↑' : '↓';
    },

    async nextScansPage() {
      if (!this.scansCursor) return;
      // Push the cursor that fetched the *current* page so prevPage can restore it.
      this.scansCursorStack.push(this._scansPageCursor || null);
      this._scansPageCursor = this.scansCursor;
      this.scansPage++;
      await this.loadScans();
    },

    async prevScansPage() {
      if (this.scansPage <= 1) return;
      this.scansPage--;
      this._scansPageCursor = this.scansCursorStack.pop() || null;
      this.scansCursor = this._scansPageCursor;
      await this.loadScans();
    },

    resetScansFilter() {
      this.scansFilter = { search: '', target: '', status: '', policy: '' };
      this.filteredScansTargets = null;
      this.loadScans(true);
    },

    openScanDetail(scan) {
      this.selectedScan = scan;
      this.focusModal();
    },

    viewScanFindings(scan) {
      this.selectedScan = null;
      // Reset all filters and set scan_id + auto-select the scan's target
      this.findingsFilter = {
        search: '', severity: '', tool: '',
        target: scan.target_name || '',
        status: '', scan_id: scan.id,
      };
      this.navigate('findings');
    },

    // ── Findings ──────────────────────────────────────────────────────────────

    _syncFindingsHash() {
      const f = this.findingsFilter;
      const hp = new URLSearchParams();
      for (const key of ['search', 'severity', 'tool', 'target', 'status', 'scan_id']) {
        if (f[key]) hp.set(key, f[key]);
      }
      const qs = hp.toString();
      const hash = '#findings' + (qs ? '?' + qs : '');
      history.replaceState({ page: 'findings' }, '', hash);
    },

    async loadFindings(reset = false, preservePage = false) {
      if (reset) {
        this.findingsPage = 1;
        this.findingsCursor = null;
        this.findingsCursorStack = [];
        this._findingsPageCursor = null;
        this.selectedFindings = [];
      }
      this.findingsLoading = true;
      try {
        const params = new URLSearchParams({ per_page: this.findingsPerPage });
        if (this.findingsFilter.search) params.set('search', this.findingsFilter.search);
        if (this.findingsFilter.severity) params.set('severity', this.findingsFilter.severity);
        if (this.findingsFilter.tool) params.set('tool', this.findingsFilter.tool);
        const requestCursor = preservePage ? (this._findingsPageCursor || null) : this.findingsCursor;
        if (requestCursor) params.set('cursor', requestCursor);
        // Always use cursor-based pagination endpoint (supports status filter via LEFT JOIN)
        if (this.findingsFilter.status) params.set('status', this.findingsFilter.status);
        if (this.findingsFilter.target) params.set('target', this.findingsFilter.target);
        if (this.findingsFilter.scan_id) params.set('scan_id', this.findingsFilter.scan_id);
        params.set('sort_by', this.findingsSort.by);
        params.set('sort_order', this.findingsSort.order);
        const result = await apiFetch(`/api/findings/paginated?${params}`);

        this.findings = result.items || [];
        this.selectedFindings = this.selectedFindings.filter(id => this.findings.some(f => f.id === id));
        const pag = result.pagination || {};
        this.findingsTotal = pag.total_count ?? pag.count ?? this.findings.length;
        this.findingsCursor = pag.next_cursor || null;
        if (this.currentPage === 'findings') this._syncFindingsHash();

        // Update available filter options based on current search context
        this._updateFindingsFilterOptions();

        this.initResizableColumns();
      } catch (e) {
        this.showToast('Failed to load findings: ' + e.message, 'error');
      } finally {
        this.findingsLoading = false;
      }
    },

    async nextFindingsPage() {
      if (!this.findingsCursor) return;
      // Push the cursor that fetched the *current* page so prevPage can restore it.
      this.findingsCursorStack.push(this._findingsPageCursor || null);
      this._findingsPageCursor = this.findingsCursor;
      this.findingsPage++;
      await this.loadFindings();
    },

    async prevFindingsPage() {
      if (this.findingsPage <= 1) return;
      this.findingsPage--;
      this._findingsPageCursor = this.findingsCursorStack.pop() || null;
      this.findingsCursor = this._findingsPageCursor;
      await this.loadFindings();
    },

    resetFindingsFilter() {
      this.findingsFilter = { search: '', severity: '', tool: '', target: '', status: '', scan_id: '' };
      this.filteredFindingsTargets = null;
      this.filteredFindingsTools = null;
      this.loadFindings(true);
    },

    // Build filtered dropdown options based on current search/filters for findings
    _updateFindingsFilterOptions() {
      if (this.findingsFilter.search) {
        const searchLower = this.findingsFilter.search.toLowerCase();
        this.filteredFindingsTargets = this.availableTargets.filter(
          t => t.toLowerCase().includes(searchLower) ||
               this.findings.some(f => f.target_name === t)
        );
        this.filteredFindingsTools = this.availableTools.filter(
          t => t.toLowerCase().includes(searchLower) ||
               this.findings.some(f => f.tool === t)
        );
      } else {
        this.filteredFindingsTargets = null;
        this.filteredFindingsTools = null;
      }
    },

    onFindingsPerPageChange() {
      localStorage.setItem('ssp-findings-per-page', String(this.findingsPerPage));
      this.loadFindings(true);
    },

    toggleSelectAll(e) {
      if (e.target.checked) {
        this.selectedFindings = this.findings.map(f => f.id);
      } else {
        this.selectedFindings = [];
      }
    },

    async applyBulkStatus() {
      if (!this.bulkStatus || this.selectedFindings.length === 0) return;
      try {
        await apiFetch('/api/findings/bulk/update-status', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ finding_ids: this.selectedFindings, status: this.bulkStatus }),
        });
        this.showToast(`Status updated for ${this.selectedFindings.length} findings`);
        this.selectedFindings = [];
        this.bulkStatus = '';
        await this.loadFindings(true);
      } catch (e) {
        this.showToast('Bulk update failed: ' + e.message, 'error');
      }
    },

    // ── Finding Detail ────────────────────────────────────────────────────────

    async openFindingDetail(finding) {
      this.selectedFinding = finding;
      this.focusModal();
      this.findingModalTab = 'info';
      this.newFindingStatus = '';
      this.findingStatusNotes = '';
      this.assignTo = '';
      this.newComment = '';
      this.findingState = {};
      this.findingComments = [];
      this.showAcceptRiskForm = false;
      this.acceptRiskJustification = '';
      this.acceptRiskExpiry = '';
      try {
        const [state, comments] = await Promise.all([
          apiFetch(`/api/findings/${finding.id}/state`),
          apiFetch(`/api/findings/${finding.id}/comments`),
        ]);
        this.findingState = state;
        this.findingComments = comments;
        // Try to load full finding detail with remediation guide
        try {
          const fullFinding = await apiFetch(`/api/findings/${finding.id}`);
          this.selectedFinding = { ...finding, ...fullFinding };
        } catch (e) {
          console.debug('[openFindingModal] Could not load full finding detail, using partial data:', e.message);
        }
      } catch (e) {
        console.debug('[openFindingModal] Non-critical error, showing modal with available data:', e.message);
      }
    },

    closeFindingModal() {
      this.selectedFinding = null;
    },

    async updateFindingStatus() {
      if (!this.newFindingStatus || !this.selectedFinding) return;
      try {
        const fd = new FormData();
        fd.append('status', this.newFindingStatus);
        if (this.findingStatusNotes) fd.append('notes', this.findingStatusNotes);
        await apiSend(`/api/findings/${this.selectedFinding.id}/status`, { method: 'PATCH', body: fd });
        this.findingState.status = this.newFindingStatus;
        this.findingState.updated_at = new Date().toISOString();
        this.newFindingStatus = '';
        this.findingStatusNotes = '';
        this.showToast('Status updated');
        await this.loadFindings(true);
      } catch (e) {
        this.showToast('Error: ' + e.message, 'error');
      }
    },

    async markFalsePositive() {
      if (!this.selectedFinding) return;
      try {
        const fd = new FormData();
        fd.append('status', 'false_positive');
        await apiSend(`/api/findings/${this.selectedFinding.id}/status`, { method: 'PATCH', body: fd });
        this.findingState.status = 'false_positive';
        this.showToast('Finding marked as false positive');
        await this.loadFindings(true);
      } catch (e) {
        this.showToast('Error: ' + e.message, 'error');
      }
    },

    async acceptRisk() {
      if (!this.selectedFinding || !this.acceptRiskJustification || !this.acceptRiskExpiry) return;
      try {
        const fd = new FormData();
        fd.append('status', 'risk_accepted');
        fd.append('notes', `Justification: ${this.acceptRiskJustification} | Expiry: ${this.acceptRiskExpiry}`);
        await apiSend(`/api/findings/${this.selectedFinding.id}/status`, { method: 'PATCH', body: fd });
        this.findingState.status = 'risk_accepted';
        this.showAcceptRiskForm = false;
        this.acceptRiskJustification = '';
        this.acceptRiskExpiry = '';
        this.showToast('Risk accepted');
        await this.loadFindings(true);
      } catch (e) {
        this.showToast('Error: ' + e.message, 'error');
      }
    },

    async assignFinding() {
      if (!this.assignTo || !this.selectedFinding) return;
      try {
        const fd = new FormData();
        fd.append('assigned_to', this.assignTo);
        await apiSend(`/api/findings/${this.selectedFinding.id}/assign`, { method: 'POST', body: fd });
        this.findingState.assigned_to = this.assignTo;
        this.assignTo = '';
        this.showToast('Finding assigned');
      } catch (e) {
        this.showToast('Error: ' + e.message, 'error');
      }
    },

    async addComment() {
      if (!this.newComment.trim() || !this.selectedFinding) return;
      try {
        const fd = new FormData();
        fd.append('comment', this.newComment);
        await apiSend(`/api/findings/${this.selectedFinding.id}/comment`, { method: 'POST', body: fd });
        this.findingComments = await apiFetch(`/api/findings/${this.selectedFinding.id}/comments`);
        this.newComment = '';
        this.showToast('Comment added');
      } catch (e) {
        this.showToast('Error: ' + e.message, 'error');
      }
    },

    async viewCriticalFindings() {
      this.findingsFilter = {
        search: '',
        severity: 'CRITICAL',
        tool: '',
        target: '',
        status: '',
        scan_id: '',
      };
      await this.navigate('findings');
    },

    safeExternalUrl(value) {
      if (!value) return '#';
      try {
        const url = new URL(String(value), window.location.origin);
        if (!['http:', 'https:'].includes(url.protocol)) return '#';
        return url.href;
      } catch (_) {
        return '#';
      }
    },

    // ── Analytics ─────────────────────────────────────────────────────────────

    async loadAnalytics() {
      // Show loading overlay only on first load; for subsequent loads the
      // analyticsRefreshing flag drives a subtle inline indicator instead.
      const isFirstLoad = !this.analyticsData.riskDistribution;
      if (isFirstLoad) this.loading = true;
      try {
        await this._refreshAnalyticsData();
      } catch (e) {
        this.showToast('Failed to load analytics: ' + e.message, 'error');
      } finally {
        this.loading = false;
      }
    },

    /** Build analytics charts if the analytics page is currently visible. */
    _buildAnalyticsCharts(sevData) {
      if (!this.chartsAvailable) return;
      if (this.currentPage !== 'analytics') return;
      this.buildRiskChart();
      this.buildOwaspChart();
      this.buildAnalyticsTrendChart();
      this.buildToolEffChart();
      this.buildSeverityDistChart(sevData);
    },

    async _refreshAnalyticsData() {
      // Cancel any in-flight refresh — always use the latest request so that
      // chart builders run with fresh $refs after navigation.
      const refreshSeq = ++this._analyticsRefreshSeq;
      this.analyticsRefreshing = true;

      const stale = () => refreshSeq !== this._analyticsRefreshSeq;

      // Helper: parse severity-breakdown response into { CRITICAL: N, ... }
      const parseSev = (fresh) => {
        const d = {};
        if (fresh && Array.isArray(fresh.labels)) {
          fresh.labels.forEach((k, i) => { d[k.toUpperCase()] = fresh.values[i]; });
        } else if (fresh && typeof fresh === 'object') {
          Object.assign(d, fresh);
        }
        return d;
      };

      try {
        // Fire all requests in parallel.
        let sevData = {};
        const results = await Promise.allSettled([
          apiFetch('/api/analytics/risk-distribution').then(d => {
            if (!stale()) this.analyticsData.riskDistribution = d;
          }),
          apiFetch('/api/analytics/compliance').then(d => {
            if (!stale()) this.analyticsData.compliance = d;
          }),
          apiFetch(`/api/analytics/trends?days=${this.analyticsDays}`).then(d => {
            if (!stale()) this.analyticsData.trends = d;
          }),
          apiFetch('/api/analytics/target-risk').then(d => {
            if (!stale()) this.analyticsData.targetRisk = d;
          }),
          apiFetch('/api/analytics/tool-effectiveness').then(d => {
            if (!stale()) this.analyticsData.toolEffectiveness = d;
          }),
          apiFetch('/api/chart/severity-breakdown').then(fresh => {
            if (!stale()) sevData = parseSev(fresh);
          }),
        ]);

        if (stale()) return;

        // Dismiss the loading overlay BEFORE building charts so canvases
        // are fully visible and have correct dimensions.
        this.loading = false;

        const failedCount = results.filter(r => r.status === 'rejected').length;
        if (failedCount > 0) {
          console.debug(`[analytics] ${failedCount} endpoint(s) failed during refresh`);
        }

        // Wait for Vue to flush the DOM (remove overlay) and the browser to
        // complete layout so canvases have correct dimensions.
        await nextTick();
        await new Promise(resolve => requestAnimationFrame(resolve));

        if (!stale()) this._buildAnalyticsCharts(sevData);
      } finally {
        if (refreshSeq === this._analyticsRefreshSeq) this.analyticsRefreshing = false;
      }
    },

    buildToolEffChart() {
      const canvas = this.$refs.toolEffChart;
      if (!canvas || !this.analyticsData.toolEffectiveness) return;
      if (this.charts.toolEff && this.charts.toolEff.canvas !== canvas) {
        this.charts.toolEff.destroy(); this.charts.toolEff = null;
      }
      const tools = this.analyticsData.toolEffectiveness;
      if (!Array.isArray(tools) || tools.length === 0) {
        if (this.charts.toolEff) {
          this.charts.toolEff.destroy();
          this.charts.toolEff = null;
        }
        return;
      }
      const newLabels = tools.map(t => t.tool);
      const dsData = [
        tools.map(t => t.critical_count || 0),
        tools.map(t => t.high_count || 0),
        tools.map(t => t.medium_count || 0),
        tools.map(t => t.low_count || 0),
        tools.map(t => t.info_count || 0),
      ];
      if (this.charts.toolEff) {
        this.charts.toolEff.data.labels = newLabels;
        dsData.forEach((d, i) => {
          if (this.charts.toolEff.data.datasets[i]) this.charts.toolEff.data.datasets[i].data = d;
        });
        this.charts.toolEff.update();
        return;
      }
      this.charts.toolEff = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: {
          labels: tools.map(t => t.tool),
          datasets: [
            { label: 'Critical', data: tools.map(t => t.critical_count || 0), backgroundColor: SEVERITY_COLORS.CRITICAL, borderRadius: 4 },
            { label: 'High', data: tools.map(t => t.high_count || 0), backgroundColor: SEVERITY_COLORS.HIGH, borderRadius: 4 },
            { label: 'Medium', data: tools.map(t => t.medium_count || 0), backgroundColor: SEVERITY_COLORS.MEDIUM, borderRadius: 4 },
            { label: 'Low', data: tools.map(t => t.low_count || 0), backgroundColor: SEVERITY_COLORS.LOW, borderRadius: 4 },
            { label: 'Info', data: tools.map(t => t.info_count || 0), backgroundColor: SEVERITY_COLORS.INFO, borderRadius: 4 },
          ],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: {
            legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 11 }, color: this.cssVar('--chart-legend'), usePointStyle: false } },
            tooltip: {
              callbacks: {
                footer: (items) => {
                  const total = items.reduce((sum, i) => sum + (i.raw || 0), 0);
                  return 'Total: ' + total;
                },
              },
            },
          },
          scales: {
            x: { stacked: false, grid: { display: false }, ticks: { color: this.cssVar('--chart-tick') } },
            y: {
              stacked: false,
              type: 'linear',
              grid: { color: this.cssVar('--chart-grid') },
              ticks: {
                color: this.cssVar('--chart-tick'),
                precision: 0,
              },
              title: { display: true, text: 'Findings', font: { size: 10 }, color: this.cssVar('--chart-tick') },
            },
          },
        },
      });
    },

    buildSeverityDistChart(data) {
      const canvas = this.$refs.severityDistChart;
      if (!canvas) return;
      if (this.charts.severityDist && this.charts.severityDist.canvas !== canvas) {
        this.charts.severityDist.destroy(); this.charts.severityDist = null;
      }
      if (!data || Object.keys(data).length === 0) data = this.severityBreakdown || {};
      const labels = SEVERITY_ORDER.filter(k => data[k] !== undefined && data[k] > 0);
      const values = labels.map(k => data[k]);
      const colors = labels.map(k => SEVERITY_COLORS[k] || '#9ca3af');
      if (labels.length === 0) {
        if (this.charts.severityDist) {
          this.charts.severityDist.destroy();
          this.charts.severityDist = null;
        }
        return;
      }
      if (this.charts.severityDist) {
        this.charts.severityDist.data.labels = labels;
        this.charts.severityDist.data.datasets[0].data = values;
        this.charts.severityDist.data.datasets[0].backgroundColor = colors;
        this.charts.severityDist.update();
        return;
      }
      const legendColor = () => this.cssVar('--chart-legend') || '#374151';
      this.charts.severityDist = new Chart(canvas.getContext('2d'), {
        type: 'doughnut',
        data: {
          labels,
          datasets: [{
            data: values,
            backgroundColor: colors,
            borderWidth: 2,
            borderColor: this.cssVar('--chart-border'),
          }],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                boxWidth: 12,
                font: { size: 11 },
                color: this.cssVar('--chart-legend'),
                padding: 12,
                usePointStyle: false,
                generateLabels: (chart) => {
                  return chart.data.labels.map((label, i) => ({
                    text: `${label}  (${chart.data.datasets[0].data[i]})`,
                    fillStyle: chart.data.datasets[0].backgroundColor[i],
                    fontColor: legendColor(),
                    lineWidth: 0,
                    hidden: false,
                    index: i,
                  }));
                },
              },
            },
            tooltip: {
              callbacks: {
                label: ctx => ` ${ctx.parsed} findings (${ctx.label})`,
              },
            },
          },
        },
      });
    },

    buildRiskChart() {
      const canvas = this.$refs.riskChart;
      if (!canvas || !this.analyticsData.riskDistribution) return;
      if (this.charts.risk && this.charts.risk.canvas !== canvas) {
        this.charts.risk.destroy(); this.charts.risk = null;
      }
      const dist = this.analyticsData.riskDistribution.distribution || {};
      if (Object.keys(dist).length === 0) {
        if (this.charts.risk) {
          this.charts.risk.destroy();
          this.charts.risk = null;
        }
        return;
      }
      const RISK_LABEL_MAP = { '0-25': 'Low Risk (0-25)', '25-50': 'Medium Risk (25-50)', '50-75': 'High Risk (50-75)', '75-100': 'Critical Risk (75-100)' };
      const rawLabels = Object.keys(dist);
      const labels = rawLabels.map(l => RISK_LABEL_MAP[l] || l);
      const values = Object.values(dist);
      if (this.charts.risk) {
        this.charts.risk.data.labels = labels;
        this.charts.risk.data.datasets[0].data = values;
        this.charts.risk.update();
        return;
      }
      this.charts.risk = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: {
          labels,
          datasets: [{
            label: 'Findings', data: values,
            backgroundColor: RISK_COLORS,
            borderRadius: 6,
          }],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: {
              callbacks: {
                label: ctx => ` ${ctx.parsed.y} findings in this risk range`,
              },
            },
          },
          scales: {
            y: { beginAtZero: true, grid: { color: this.cssVar('--chart-grid') }, ticks: { color: this.cssVar('--chart-tick') } },
            x: { grid: { display: false }, ticks: { color: this.cssVar('--chart-tick') } },
          },
        },
      });
    },

    buildOwaspChart() {
      const canvas = this.$refs.owaspChart;
      if (!canvas || !this.analyticsData.compliance) return;
      if (this.charts.owasp && this.charts.owasp.canvas !== canvas) {
        this.charts.owasp.destroy(); this.charts.owasp = null;
      }
      const owasp = (this.analyticsData.compliance.owasp_top_10 || []).slice(0, 6);
      if (owasp.length === 0) {
        if (this.charts.owasp) {
          this.charts.owasp.destroy();
          this.charts.owasp = null;
        }
        return;
      }
      const labels = owasp.map(o => o.category.split(' - ')[0]);
      const values = owasp.map(o => o.count);
      if (this.charts.owasp) {
        this.charts.owasp.data.labels = labels;
        this.charts.owasp.data.datasets[0].data = values;
        this.charts.owasp.update();
        return;
      }
      this.charts.owasp = new Chart(canvas.getContext('2d'), {
        type: 'pie',
        data: {
          labels,
          datasets: [{
            data: values,
            backgroundColor: OWASP_COLORS,
            borderWidth: 2, borderColor: this.cssVar('--chart-border'),
          }],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 11 }, usePointStyle: false } } },
        },
      });
    },

    buildAnalyticsTrendChart() {
      const canvas = this.$refs.analyticsTrendChart;
      if (!canvas || !this.analyticsData.trends) return;
      if (this.charts.analyticsTrend && this.charts.analyticsTrend.canvas !== canvas) {
        this.charts.analyticsTrend.destroy(); this.charts.analyticsTrend = null;
      }
      const trendData = this.analyticsData.trends.trend || [];
      if (trendData.length === 0) {
        if (this.charts.analyticsTrend) {
          this.charts.analyticsTrend.destroy();
          this.charts.analyticsTrend = null;
        }
        return;
      }
      const labels = trendData.map(t => t.date);
      const avgData = trendData.map(t => t.average_risk);
      const maxData = trendData.map(t => t.max_risk);
      if (this.charts.analyticsTrend) {
        this.charts.analyticsTrend.data.labels = labels;
        this.charts.analyticsTrend.data.datasets[0].data = avgData;
        this.charts.analyticsTrend.data.datasets[1].data = maxData;
        this.charts.analyticsTrend.update();
        return;
      }
      const gridColor = this.cssVar('--chart-grid');
      const tickColor = this.cssVar('--chart-tick');
      const primaryColor = this.cssVar('--color-primary');
      const dangerColor = this.cssVar('--color-danger');
      this.charts.analyticsTrend = new Chart(canvas.getContext('2d'), {
        type: 'line',
        data: {
          labels: trendData.map(t => t.date),
          datasets: [
            {
              label: 'Avg Risk', data: trendData.map(t => t.average_risk),
              borderColor: primaryColor,
              backgroundColor: primaryColor + '18',
              tension: 0.3, fill: true, borderWidth: 2,
            },
            {
              label: 'Max Risk', data: trendData.map(t => t.max_risk),
              borderColor: dangerColor,
              backgroundColor: dangerColor + '10',
              tension: 0.3, fill: false, borderDash: [4, 4], borderWidth: 2,
            },
          ],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'bottom',
              labels: { color: this.cssVar('--chart-legend'), font: { size: 11 }, usePointStyle: false },
            },
            tooltip: {
              backgroundColor: this.cssVar('--chart-tooltip-bg'),
              titleColor: this.cssVar('--chart-tooltip-title'),
              bodyColor: this.cssVar('--chart-tooltip-body'),
              borderColor: this.cssVar('--chart-tooltip-border'),
              borderWidth: 1,
            },
          },
          scales: {
            y: {
              beginAtZero: true, max: 100,
              grid: { color: gridColor },
              ticks: { color: tickColor, font: { size: 11 } },
            },
            x: {
              grid: { display: false },
              ticks: { color: tickColor, font: { size: 11 } },
            },
          },
        },
      });
    },

    owaspBarWidth(count, series = 'owasp') {
      if (!this.analyticsData.compliance) return 0;
      const owasp = Array.isArray(this.analyticsData.compliance.owasp_top_10)
        ? this.analyticsData.compliance.owasp_top_10
        : [];
      const cwe = Array.isArray(this.analyticsData.compliance.cwe_top)
        ? this.analyticsData.compliance.cwe_top
        : [];
      const source = series === 'cwe' ? cwe : owasp;
      const numericCount = Number(count) || 0;
      const max = Math.max(...source.map(o => o.count), 1);
      return Math.round(((numericCount || 0) / max) * 100);
    },

    riskBarClass(risk) {
      if (risk >= 75) return 'risk-critical';
      if (risk >= 50) return 'risk-high';
      if (risk >= 25) return 'risk-medium';
      return 'risk-low';
    },

    // ── Compare ───────────────────────────────────────────────────────────────

    async loadCompareScanList() {
      try {
        const result = await apiFetch('/api/scans/paginated?per_page=50&sort_by=created_at&sort_order=DESC');
        this.compareScanList = result.items || [];
        // Pre-fill from selectedScans if coming from scans page
        if (this.selectedScans.length === 2) {
          this.compareIdA = this.selectedScans[0];
          this.compareIdB = this.selectedScans[1];
        }
      } catch (e) {
        this.showToast('Failed to load scan list: ' + e.message, 'error');
      }
    },

    goToCompare() {
      if (this.selectedScans.length !== 2) return;
      this.compareIdA = this.selectedScans[0];
      this.compareIdB = this.selectedScans[1];
      this.navigate('compare');
    },

    async runCompare() {
      if (!this.compareIdA || !this.compareIdB || this.compareIdA === this.compareIdB) return;
      this.compareLoading = true;
      this.compareResult = null;
      try {
        const result = await apiFetch(`/api/scans/compare?scan_id_1=${this.compareIdA}&scan_id_2=${this.compareIdB}`);
        // Normalize API response: the API returns { scan_1, scan_2, diff: { new_count, ... } }
        // The template expects { summary: { new, resolved, unchanged }, new_findings, resolved_findings }
        if (result && result.diff) {
          this.compareResult = {
            scan_1: result.scan_1,
            scan_2: result.scan_2,
            summary: {
              new: result.diff.new_count || 0,
              resolved: result.diff.resolved_count || 0,
              unchanged: result.diff.unchanged_count || 0,
            },
            new_findings: result.diff.new_findings || [],
            resolved_findings: result.diff.resolved_findings || [],
            new_by_severity: result.diff.new_by_severity || {},
            resolved_by_severity: result.diff.resolved_by_severity || {},
          };
        } else {
          this.compareResult = result;
        }
      } catch (e) {
        this.showToast('Comparison failed: ' + e.message, 'error');
      } finally {
        this.compareLoading = false;
      }
    },

    // ── New Scan ──────────────────────────────────────────────────────────────

    async triggerScan() {
      if (!this.newScanForm.name || !this.newScanForm.target) return;
      this.scanTriggering = true;
      try {
        // Backend uses Form(...) parameters — must send as application/x-www-form-urlencoded
        const formData = new URLSearchParams();
        formData.append('name', this.newScanForm.name);
        formData.append('target', this.newScanForm.target);
        formData.append('target_type', this.newScanForm.target_type);
        formData.append('async_mode', 'true');
        const resp = await apiFetch('/api/scan/trigger', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: formData.toString(),
        });
        // Close modal and reset form on success
        this.showScanModal = false;
        this.newScanForm = { name: '', target: '', target_type: 'local' };
        this.showToast('Scan started successfully');
        await this.loadScans(true);
        this.startScanPolling(resp.scan_id);
      } catch (e) {
        // Keep modal open on error so user can fix the input
        this.showToast('Failed to start scan: ' + e.message, 'error');
      } finally {
        this.scanTriggering = false;
      }
    },

    // ── Notification Preferences ──────────────────────────────────────────────

    async loadNotificationPrefs() {
      try {
        const resp = await apiFetch('/api/notifications/preferences').catch(() => null);
        if (resp && resp.preferences) {
          // Do not overwrite user_email with an internal identifier (e.g. "admin"):
          // the user_email field in the DB is used as a lookup key, not an email recipient.
          // If the value does not contain "@" it is not a valid email and should be ignored.
          const prefs = { ...resp.preferences };
          if (prefs.user_email && !prefs.user_email.includes('@')) {
            delete prefs.user_email;
          }
          this.notifPrefs = { ...this.notifPrefs, ...prefs };
        }
      } catch (e) {
        console.debug('[loadNotificationPrefs] Could not load preferences, using defaults:', e.message);
      }
    },

    async saveNotificationPrefs() {
      try {
        await apiFetch('/api/notifications/preferences', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(this.notifPrefs),
        });
        this.showToast('Preferences saved');
      } catch (e) {
        this.showToast('Failed to save preferences: ' + e.message, 'error');
      }
    },

    // ── Settings ──────────────────────────────────────────────────────────────

    async loadApiKeys() {
      try {
        this.apiKeys = await apiFetch('/api/keys');
      } catch (e) {
        this.showToast('Failed to load API keys: ' + e.message, 'error');
      }
    },

    async createApiKey() {
      try {
        const fd = new FormData();
        fd.append('name', this.newKeyForm.name);
        fd.append('role', this.newKeyForm.role);
        if (this.newKeyForm.expires_days) fd.append('expires_days', this.newKeyForm.expires_days);
        const res = await apiSend('/api/keys', { method: 'POST', body: fd });
        const data = await res.json();
        this.newKeyResult = data.key;
        await this.loadApiKeys();
        this.showToast('API key created');
      } catch (e) {
        this.showToast('Failed to create key: ' + e.message, 'error');
      }
    },

    async revokeApiKey(prefix) {
      if (!confirm(`Revoke key ${prefix}?`)) return;
      try {
        await apiFetch(`/api/keys/${prefix}`, { method: 'DELETE' });
        await this.loadApiKeys();
        this.showToast('API key revoked');
      } catch (e) {
        this.showToast('Failed to revoke key: ' + e.message, 'error');
      }
    },

    async loadWebhooks() {
      try {
        this.webhooks = await apiFetch('/api/webhooks');
      } catch (e) {
        this.showToast('Failed to load webhooks: ' + e.message, 'error');
      }
    },

    async createWebhook() {
      try {
        const fd = new FormData();
        fd.append('name', this.newWebhookForm.name);
        fd.append('url', this.newWebhookForm.url);
        fd.append('events', this.newWebhookForm.events);
        if (this.newWebhookForm.secret) fd.append('secret', this.newWebhookForm.secret);
        await apiSend('/api/webhooks', { method: 'POST', body: fd });
        this.showCreateWebhookModal = false;
        this.newWebhookForm = { name: '', url: '', events: 'scan.completed', secret: '' };
        await this.loadWebhooks();
        this.showToast('Webhook created');
      } catch (e) {
        this.showToast('Failed to create webhook: ' + e.message, 'error');
      }
    },

    async toggleWebhook(id, isActive) {
      try {
        const fd = new FormData();
        fd.append('is_active', isActive);
        await apiSend(`/api/webhooks/${id}`, { method: 'PATCH', body: fd });
        await this.loadWebhooks();
      } catch (e) {
        this.showToast('Failed to toggle webhook: ' + e.message, 'error');
      }
    },

    async deleteWebhook(id) {
      if (!confirm('Delete this webhook?')) return;
      try {
        await apiFetch(`/api/webhooks/${id}`, { method: 'DELETE' });
        await this.loadWebhooks();
        this.showToast('Webhook deleted');
      } catch (e) {
        this.showToast('Failed to delete webhook: ' + e.message, 'error');
      }
    },

    // ── Users ─────────────────────────────────────────────────────────────────

    async loadAvailableUsers() {
      try {
        const resp = await apiFetch('/api/users').catch(() => null);
        if (resp && Array.isArray(resp.users)) {
          this.availableUsers = resp.users.map(u => u.username || u);
        }
      } catch (e) {
        console.debug('[loadAvailableUsers] failed:', e.message);
      }
    },

    async logout() {
      try {
        await apiSend('/logout', { method: 'POST' });
      } catch (e) {
        console.debug('[logout] failed:', e.message);
      } finally {
        window.location.href = '/login';
      }
    },

    // ── Export ────────────────────────────────────────────────────────────────

    _downloadBlob(res, filename) {
      const blob = res;
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      URL.revokeObjectURL(url);
      document.body.removeChild(a);
    },

    _checkExportTruncation(res) {
      const total = parseInt(res.headers.get('X-Total-Count') || '0', 10);
      const exported = parseInt(res.headers.get('X-Exported-Count') || '0', 10);
      if (total > exported) {
        this.showToast(`Warning: exported ${exported} of ${total} findings. Increase the limit or apply filters to export all.`, 'error');
      }
    },

    async exportScanFindings(scanId, format) {
      try {
        const params = new URLSearchParams({ format, scan_id: scanId, limit: 1000 });
        const res = await fetch(`/api/export/findings?${params}`);
        if (!res.ok) throw new Error('Export failed');
        this._checkExportTruncation(res);
        const blob = await res.blob();
        const scanIdLabel = String(scanId || 'scan').slice(0, 8);
        this._downloadBlob(blob, `scan_${scanIdLabel}_${Date.now()}.${format}`);
        this.showToast(`Export ${format.toUpperCase()} completed`);
      } catch (e) {
        this.showToast('Export failed: ' + e.message, 'error');
      }
    },

    async exportFindings(format, includeAnalytics = false) {
      try {
        const params = new URLSearchParams({ format, limit: 5000 });
        if (includeAnalytics) params.set('include_analytics', true);
        // Pass current filters to export
        const f = this.findingsFilter;
        if (f.severity) params.set('severity', f.severity);
        if (f.tool) params.set('tool', f.tool);
        if (f.status) params.set('status', f.status);
        if (f.target) params.set('target', f.target);
        if (f.search) params.set('search', f.search);
        if (f.scan_id) params.set('scan_id', f.scan_id);
        const res = await fetch(`/api/export/findings?${params}`);
        if (!res.ok) throw new Error('Export failed');
        this._checkExportTruncation(res);
        const blob = await res.blob();
        this._downloadBlob(blob, `findings_${Date.now()}.${format}`);
        this.showToast(`Export ${format.toUpperCase()} completed`);
      } catch (e) {
        this.showToast('Export failed: ' + e.message, 'error');
      }
    },

    // ── UI Helpers ────────────────────────────────────────────────────────────

    formatDate,

    statusBadgeClass(status) {
      const map = {
        COMPLETED_CLEAN: 'badge-success',
        COMPLETED_WITH_FINDINGS: 'badge-warning',
        PARTIAL_FAILED: 'badge-danger',
        FAILED: 'badge-danger',
        RUNNING: 'badge-info',
      };
      return map[status] || 'badge-neutral';
    },

    statusLabel(status) {
      const labels = {
        COMPLETED_CLEAN: 'Clean',
        COMPLETED_WITH_FINDINGS: 'With Findings',
        PARTIAL_FAILED: 'Partial',
        FAILED: 'Failed',
        RUNNING: 'Running',
      };
      return labels[status] || status;
    },

    policyBadgeClass(policy) {
      const normalized = (policy || '').toUpperCase();
      const map = {
        PASS: 'badge-success',
        BLOCK: 'badge-danger',
        FAIL: 'badge-danger',
        WARN: 'badge-warning',
        WARNING: 'badge-warning',
        UNKNOWN: 'badge-neutral',
      };
      return map[normalized] || 'badge-neutral';
    },

    linkifyText(text) {
      if (!text) return '';
      // Escape HTML to prevent XSS, then convert URLs to clickable links
      const escaped = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
      return escaped.replace(
        /(https?:\/\/[^\s<>"')\]]+)/g,
        '<a href="$1" target="_blank" rel="noopener noreferrer" class="cve-link">$1</a>'
      );
    },

    isValidCve(cve) {
      return /^CVE-\d{4}-\d{4,}$/i.test(cve);
    },

    cveUrl(cve) {
      if (this.isValidCve(cve)) return 'https://nvd.nist.gov/vuln/detail/' + cve;
      return null;
    },

    // Truncate long CWE/OWASP strings for table display.
    // e.g. "CWE-22: Improper Limitation of a Pathname..." → "CWE-22"
    // e.g. "A01:2021 - Broken Access Control" → "A01:2021"
    truncateCve(value) {
      if (!value) return value;
      // Extract just the ID part before any colon, dash or space separator
      const m = value.match(/^(CWE-\d+|CVE-\d{4}-\d+|A\d{2}:\d{4}|[A-Z]+-\d+)/i);
      if (m) return m[1];
      // Fallback: truncate to 20 chars with ellipsis
      return value.length > 20 ? value.slice(0, 20) + '…' : value;
    },

    copyToClipboard(text) {
      navigator.clipboard.writeText(text)
        .then(() => this.showToast('Copied to clipboard'))
        .catch((error) => {
          console.debug('[clipboard] failed:', error?.message || error);
          this.showToast('Copy failed', 'error');
        });
    },

    // ── Resizable columns ────────────────────────────────────────────────────────
    // Attach drag-to-resize handles to all <th> inside tables.
    // Safe to call multiple times — skips th that already have a handle.
    initResizableColumns() {
      nextTick(() => {
        document.querySelectorAll('table').forEach((table) => {
          table.classList.add('resizable-table');
          table.querySelectorAll('thead th').forEach((th) => {
            if (th.querySelector('.resize-handle')) return;
            const handle = document.createElement('div');
            handle.className = 'resize-handle';
            th.appendChild(handle);
            let startX = 0, startW = 0;
            handle.addEventListener('mousedown', (e) => {
              e.preventDefault();
              startX = e.pageX;
              startW = th.offsetWidth;
              handle.classList.add('resizing');
              table.classList.add('col-resizing');
              const onMove = (ev) => {
                const newW = Math.max(50, startW + ev.pageX - startX);
                th.style.width = newW + 'px';
                th.style.minWidth = newW + 'px';
              };
              const onUp = () => {
                handle.classList.remove('resizing');
                table.classList.remove('col-resizing');
                document.removeEventListener('mousemove', onMove);
                document.removeEventListener('mouseup', onUp);
              };
              document.addEventListener('mousemove', onMove);
              document.addEventListener('mouseup', onUp);
            });
          });
        });
      });
    },

    // ── Dark Mode ────────────────────────────────────────────────────────────────
    toggleDarkMode() {
      this.darkMode = !this.darkMode;
      if (this.darkMode) {
        document.documentElement.setAttribute('data-theme', 'dark');
        localStorage.setItem('ssp-theme', 'dark');
      } else {
        document.documentElement.removeAttribute('data-theme');
        localStorage.setItem('ssp-theme', 'light');
      }
      // Wait for the browser to recalculate CSS custom properties before reading
      // them via getComputedStyle — setAttribute is synchronous but computed styles
      // may not be flushed until the next animation frame.
      requestAnimationFrame(() => {
        this.applyChartDefaults();
        // Destroy existing charts so they get recreated with new CSS variable
        // values for grid, tick, and legend colors.
        Object.keys(this.charts).forEach(k => {
          if (this.charts[k]) { this.charts[k].destroy(); this.charts[k] = null; }
        });
        // Rebuild visible charts so legend/tick colors update immediately
        if (this.currentPage === 'dashboard') this.initDashboardCharts();
        else if (this.currentPage === 'analytics') this.loadAnalytics();
      });
    },

  },
}).mount('#app');
