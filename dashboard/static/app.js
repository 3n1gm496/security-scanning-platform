/**
 * Security Scanning Platform — SPA Vue.js
 * Version 2.0 — Complete SPA architecture with pagination, triage and analytics
 */

const { createApp, ref, reactive, computed, onMounted, nextTick, watch } = Vue;

// ─── Constants ───────────────────────────────────────────────────────────────

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'];

const SEVERITY_COLORS = {
  CRITICAL: '#ff5b5b', HIGH: '#ff9b3d', MEDIUM: '#f6c15d',
  LOW: '#34d5ff', INFO: '#70819d', UNKNOWN: '#4b5563',
};

const STATUS_LABELS = ['New', 'Acknowledged', 'In Progress', 'Resolved', 'False Positive', 'Risk Accepted'];
const STATUS_KEYS   = ['new', 'acknowledged', 'in_progress', 'resolved', 'false_positive', 'risk_accepted'];
const STATUS_COLORS = ['#64748b', '#f6c15d', '#34d5ff', '#29d391', '#6b7a90', '#ff9b3d'];

const OWASP_COLORS = ['#34d5ff', '#57c8ff', '#7eb5ff', '#f6c15d', '#ff9b3d', '#ff5b5b'];
const RISK_COLORS  = ['#29d391', '#34d5ff', '#f6c15d', '#ff5b5b'];

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

function stableSerialize(value) {
  try {
    return JSON.stringify(value);
  } catch (_) {
    return '';
  }
}

function formatCompactNumber(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return '—';
  return new Intl.NumberFormat('en', {
    notation: 'compact',
    maximumFractionDigits: numeric >= 1000 ? 1 : 0,
  }).format(numeric);
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
    const externalSignal = options?.signal;
    const controller = new AbortController();
    const abortFromExternalSignal = () => controller.abort(externalSignal?.reason);
    if (externalSignal) {
      if (externalSignal.aborted) {
        controller.abort(externalSignal.reason);
      } else {
        externalSignal.addEventListener('abort', abortFromExternalSignal, { once: true });
      }
    }
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const requestOptions = { ...options };
      delete requestOptions.signal;
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
      if (externalSignal) {
        externalSignal.removeEventListener('abort', abortFromExternalSignal);
      }
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
      hasPendingScanUpdates: false,
      hasPendingFindingUpdates: false,
      scanLiveMessage: '',
      findingsLiveMessage: '',

      // ── Dashboard data
      kpis: init.kpis || {},
      recentScans: init.recentScans || [],
      severityBreakdown: init.severityBreakdown || {},
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
      analyticsRefreshingMode: 'silent-sync',
      _analyticsRefreshSeq: 0,
      _analyticsWarmupDone: false,

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
      darkMode: true,

      _lastFocusBeforeOverlay: null,
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
        dashboard: 'Live security posture',
        scans: 'Queue and execution history',
        findings: 'Triage and remediation operations',
        analytics: 'Risk, compliance and trend intelligence',
        compare: 'Baseline diff intelligence',
        settings: 'Access and automation controls',
      };
      return subs[this.currentPage] || '';
    },
    currentUserRoleLabel() {
      const labels = { admin: 'Administrator', operator: 'Operator', viewer: 'Viewer' };
      return labels[this.currentUserRole] || 'User';
    },
    currentUserInitials() {
      const base = String(this.currentUser || 'U')
        .split(/[\s._-]+/)
        .filter(Boolean)
        .slice(0, 2)
        .map(part => part[0]?.toUpperCase())
        .join('');
      return base || 'U';
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
    dashboardSignalTiles() {
      return [
        {
          key: 'total-scans',
          label: 'Total Scans',
          value: formatCompactNumber(this.kpis.total_scans),
          hint: 'Historical executions indexed in platform',
          tone: 'signal-cyan',
        },
        {
          key: 'total-findings',
          label: 'Total findings',
          value: formatCompactNumber(this.kpis.total_findings),
          hint: 'Across all indexed scan results',
          tone: 'signal-amber',
        },
        {
          key: 'critical',
          label: 'Critical',
          value: formatCompactNumber(this.kpis.critical_findings),
          hint: 'Immediate operator attention',
          tone: 'signal-danger',
        },
        {
          key: 'high',
          label: 'High',
          value: formatCompactNumber(this.kpis.high_findings),
          hint: 'Elevated remediation queue',
          tone: 'signal-warning',
        },
        {
          key: 'targets',
          label: 'Observed targets',
          value: formatCompactNumber(this.kpis.open_targets),
          hint: 'Assets currently under watch',
          tone: 'signal-cyan',
        },
        {
          key: 'velocity',
          label: 'Scan velocity',
          value: formatCompactNumber(this.kpis.last_7d_scans),
          hint: 'Completed in the last 7 days',
          tone: 'signal-green',
        },
      ];
    },
    scansActiveFilters() {
      const chips = [];
      if (this.scansFilter.search) chips.push({ key: 'search', label: 'Search', value: this.scansFilter.search });
      if (this.scansFilter.target) chips.push({ key: 'target', label: 'Target', value: this.scansFilter.target });
      if (this.scansFilter.status) chips.push({ key: 'status', label: 'Status', value: this.statusLabel(this.scansFilter.status) });
      if (this.scansFilter.policy) chips.push({ key: 'policy', label: 'Policy', value: this.scansFilter.policy });
      return chips;
    },
    findingsActiveFilters() {
      const chips = [];
      if (this.findingsFilter.search) chips.push({ key: 'search', label: 'Search', value: this.findingsFilter.search });
      if (this.findingsFilter.severity) chips.push({ key: 'severity', label: 'Severity', value: this.findingsFilter.severity });
      if (this.findingsFilter.tool) chips.push({ key: 'tool', label: 'Tool', value: this.findingsFilter.tool });
      if (this.findingsFilter.target) chips.push({ key: 'target', label: 'Target', value: this.findingsFilter.target });
      if (this.findingsFilter.status) chips.push({ key: 'status', label: 'Status', value: this.findingsFilter.status.replace(/_/g, ' ') });
      if (this.findingsFilter.scan_id) chips.push({ key: 'scan_id', label: 'Scan', value: String(this.findingsFilter.scan_id).slice(0, 12) });
      return chips;
    },
    analyticsSummaryTiles() {
      const riskDistribution = this.analyticsData.riskDistribution || {};
      const distribution = riskDistribution.distribution || {};
      const total = Object.values(distribution).reduce((sum, count) => sum + (Number(count) || 0), 0);
      const highRiskShare = total > 0 ? Math.round(((Number(riskDistribution.high_risk_count) || 0) / total) * 100) : 0;
      const targetRisk = Array.isArray(this.analyticsData.targetRisk) ? this.analyticsData.targetRisk : [];
      const highestTarget = targetRisk.slice().sort((a, b) => (b.average_risk || 0) - (a.average_risk || 0))[0];
      const hotspotTarget = highestTarget?.target || '—';
      const hotspotShort = hotspotTarget.length > 44 ? hotspotTarget.slice(0, 42) + '…' : hotspotTarget;
      const hotspotCount = Number(highestTarget?.findings_count || 0);
      return [
        {
          key: 'avg-risk',
          label: 'Average risk',
          value: Number.isFinite(Number(riskDistribution.average_risk)) ? `${riskDistribution.average_risk}/100` : '—',
          hint: 'Cross-finding blended risk posture',
          tone: 'signal-cyan',
        },
        {
          key: 'high-risk-share',
          label: 'High-risk share',
          value: total > 0 ? `${highRiskShare}%` : '—',
          hint: 'Portion of findings in the upper risk bands',
          tone: 'signal-danger',
        },
        {
          key: 'hotspot',
          label: 'Most exposed target',
          value: hotspotShort,
          fullValue: hotspotTarget,
          wrapValue: hotspotTarget.length > 22,
          hint: highestTarget
            ? `${highestTarget.average_risk}/100 average risk · ${formatCompactNumber(hotspotCount)} findings`
            : 'No analytics hotspot yet',
          tone: 'signal-amber',
        },
      ];
    },
    compareContext() {
      const scanA = this.compareScanList.find(s => s.id === this.compareIdA);
      const scanB = this.compareScanList.find(s => s.id === this.compareIdB);
      return { scanA, scanB };
    },
    findingsTableHasLongValues() {
      return this.findings.some((finding) => {
        const title = String(finding.title || '');
        const file = String(finding.file || '');
        const target = String(finding.target_name || '');
        return title.length > 80 || file.length > 44 || target.length > 32;
      });
    },
    analyticsHasRiskData() {
      const dist = this.analyticsData.riskDistribution?.distribution || {};
      return Object.keys(dist).length > 0;
    },
    analyticsHasComplianceData() {
      return Array.isArray(this.analyticsData.compliance?.owasp_top_10) && this.analyticsData.compliance.owasp_top_10.length > 0;
    },
    analyticsHasToolData() {
      return Array.isArray(this.analyticsData.toolEffectiveness) && this.analyticsData.toolEffectiveness.length > 0;
    },
    analyticsHasSeverityData() {
      return this.analyticsHasRiskData;
    },
    analyticsHasTrendData() {
      return Array.isArray(this.analyticsData.trends?.trend) && this.analyticsData.trends.trend.length > 0;
    },
  },

   async mounted() {
    this._remediationChartVersion = 0;
    this._lastKpiRefreshAt = 0;
    this._recentScansSignature = stableSerialize(this._scanSignaturePayload(this.recentScans || []));
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
    if (hashQuery && initialPage === 'scans') {
      const hp = new URLSearchParams(hashQuery);
      for (const key of ['search', 'target', 'status', 'policy']) {
        if (hp.has(key)) this.scansFilter[key] = hp.get(key);
      }
    }
    history.replaceState({ page: initialPage }, '', '#' + initialPage);

    // ── History API: back/forward button support
    this._popstateHandler = async (e) => {
      const page = (e.state && e.state.page) ? e.state.page : 'dashboard';
      if (validPages.includes(page) && page !== this.currentPage) {
        await this.navigate(page, { pushHistory: false, force: true });
      }
    };
    window.addEventListener('popstate', this._popstateHandler);

    // ── Dark mode: restore preference from localStorage
    const savedTheme = localStorage.getItem('ssp-theme');
    this.darkMode = savedTheme !== 'light';
    if (this.darkMode) {
      document.documentElement.removeAttribute('data-theme');
    } else {
      document.documentElement.setAttribute('data-theme', 'light');
    }

    // ── Keyboard: Escape to close modals + Tab focus trap
    this._keyHandler = (e) => {
      if (e.key === 'Escape') {
        this.closeMobileNav();
        this.closeFindingModal();
        this.closeScanDetail();
        this.closeScanModal();
        this.closeCreateKeyModal();
        this.closeCreateWebhookModal();
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
    await this.initDashboardCharts('mount');
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

    this.scheduleAnalyticsWarmup();
  },
  beforeUnmount() {
    this.stopAutoRefresh();
    this.stopScanPolling();
    this.cancelAnalyticsWarmup();
    if (this._analyticsAbortController) this._analyticsAbortController.abort();
    if (this._resizeFrame) cancelAnimationFrame(this._resizeFrame);
    if (this._resizeHandler) window.removeEventListener('resize', this._resizeHandler);
    if (this._popstateHandler) window.removeEventListener('popstate', this._popstateHandler);
    Object.keys(this.charts).forEach((key) => this.safeDestroyChart(key));
    if (this._keyHandler) document.removeEventListener('keydown', this._keyHandler);
    if (this._toastTimers) {
      this._toastTimers.forEach(timer => clearTimeout(timer));
      this._toastTimers.clear();
    }
  },

  methods: {
    // ── Modal accessibility ───────────────────────────────────────────────────

    rememberOverlayFocus() {
      if (document.activeElement instanceof HTMLElement) {
        this._lastFocusBeforeOverlay = document.activeElement;
      }
    },

    restoreOverlayFocus() {
      const target = this._lastFocusBeforeOverlay;
      this._lastFocusBeforeOverlay = null;
      if (target && target.isConnected) {
        requestAnimationFrame(() => target.focus());
      }
    },

    async focusModal(preferredRef = null) {
      await nextTick();
      const container = preferredRef && this.$refs[preferredRef]
        ? this.$refs[preferredRef]
        : document.querySelector('.modal-overlay[role="dialog"] .modal');
      if (!container) return;
      const first = container.querySelector(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      );
      if (first) first.focus();
      else if (typeof container.focus === 'function') container.focus();
    },

    // ── Chart theme helpers ────────────────────────────────────────────────────

    applyChartDefaults() {
      if (!this.chartsAvailable) return;
      const s = getComputedStyle(document.documentElement);
      Chart.defaults.color = s.getPropertyValue('--chart-tick').trim() || '#6b7280';
      Chart.defaults.borderColor = s.getPropertyValue('--chart-grid').trim() || 'rgba(0,0,0,0.06)';
      Chart.defaults.font.family = s.getPropertyValue('--font-ui').trim() || 'IBM Plex Sans, system-ui, sans-serif';
      if (!Chart.__sspDetachedCanvasGuardInstalled) {
        ['clear', 'draw', 'render'].forEach((method) => {
          const original = Chart.prototype[method];
          if (typeof original !== 'function' || original.__sspDetachedCanvasGuard) return;
          const guarded = function sspGuardedChartMethod(...args) {
            if (!this || !this.canvas || !this.ctx || this.canvas.isConnected === false) {
              return this;
            }
            return original.apply(this, args);
          };
          guarded.__sspDetachedCanvasGuard = true;
          Chart.prototype[method] = guarded;
        });
        Chart.__sspDetachedCanvasGuardInstalled = true;
      }
      if (Chart.defaults.transitions) {
        if (Chart.defaults.transitions.active) {
          Chart.defaults.transitions.active.animation = { duration: 0 };
        }
        if (Chart.defaults.transitions.resize) {
          Chart.defaults.transitions.resize.animation = { duration: 0 };
        }
      }
    },

    // Read a CSS variable from :root — used by all chart builders for consistent theming
    cssVar(name) {
      return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    },

    isDocumentVisible() {
      return document.visibilityState !== 'hidden';
    },

    chartIsUsable(chart) {
      return !!(chart && chart.canvas && chart.ctx && chart.canvas.isConnected !== false);
    },

    _scanSignaturePayload(scans) {
      return (scans || []).map(scan => [
        scan.id,
        scan.status,
        scan.policy_status,
        scan.findings_count,
        scan.critical_count,
        scan.high_count,
        scan.medium_count,
        scan.low_count,
        scan.info_count,
        scan.created_at,
      ]);
    },

    chartMotion(mode = 'background-refresh') {
      if (mode === 'mount') return { duration: 420, easing: 'easeOutCubic' };
      if (mode === 'user-change') return { duration: 240, easing: 'easeOutQuad' };
      return false;
    },

    withChartMotion(options, mode = 'mount') {
      return {
        ...options,
        animation: this.chartMotion(mode),
        transitions: {
          ...(options.transitions || {}),
          active: { animation: { duration: 0 } },
          resize: { animation: { duration: 0 } },
        },
      };
    },

    updateChartWithMode(chart, mode = 'background-refresh') {
      if (!chart) return;
      if (!this.chartIsUsable(chart)) {
        this.safeDestroyChart(chart);
        return;
      }
      chart.options.animation = this.chartMotion(mode);
      chart.options.transitions = {
        ...(chart.options.transitions || {}),
        active: { animation: { duration: 0 } },
        resize: { animation: { duration: 0 } },
      };
      const updateMode = ['background-refresh', 'resize', 'silent-sync'].includes(mode) ? 'none' : undefined;
      try {
        chart.update(updateMode);
      } catch (error) {
        console.debug('[charts] update skipped:', error?.message || error);
        this.safeDestroyChart(chart);
      }
    },

    safeDestroyChart(keyOrChart) {
      const chart = typeof keyOrChart === 'string' ? this.charts[keyOrChart] : keyOrChart;
      if (!chart) return;
      try { chart.stop(); } catch (_) {}
      try { chart.destroy(); } catch (_) {}
      if (typeof keyOrChart === 'string') this.charts[keyOrChart] = null;
    },

    isDefaultScansLiveView() {
      return (
        this.currentPage === 'scans' &&
        this.scansPage === 1 &&
        this.scansSort.by === 'created_at' &&
        this.scansSort.order === 'DESC' &&
        !this.scansFilter.search &&
        !this.scansFilter.target &&
        !this.scansFilter.status &&
        !this.scansFilter.policy
      );
    },

    hasActiveFindingsInteraction() {
      return this.selectedFindings.length > 0 || !!this.selectedFinding || !!this.bulkStatus;
    },

    canAutoRefreshFindingsView() {
      return this.currentPage === 'findings' && this.findingsPage === 1 && !this.hasActiveFindingsInteraction();
    },

    clearPendingScanUpdates() {
      this.hasPendingScanUpdates = false;
      this.scanLiveMessage = '';
    },

    queuePendingScanUpdates(message = 'New scan data available. Refresh to update the table.') {
      this.hasPendingScanUpdates = true;
      this.scanLiveMessage = message;
    },

    clearPendingFindingUpdates() {
      this.hasPendingFindingUpdates = false;
      this.findingsLiveMessage = '';
    },

    queuePendingFindingUpdates(message = 'New findings are ready. Refresh to load them.') {
      this.hasPendingFindingUpdates = true;
      this.findingsLiveMessage = message;
    },

    applyRecentScans(items) {
      const nextScans = (items || []).slice(0, 12);
      const nextSignature = stableSerialize(this._scanSignaturePayload(nextScans));
      if (nextSignature === this._recentScansSignature) return false;
      this.recentScans = nextScans;
      this._recentScansSignature = nextSignature;
      return true;
    },

    async refreshKpis(force = false) {
      const now = Date.now();
      if (!force && now - this._lastKpiRefreshAt < 20000) return false;
      try {
        this.kpis = await apiFetch('/api/kpi');
        this._lastKpiRefreshAt = now;
        return true;
      } catch (e) {
        console.debug('[refreshKpis] KPI refresh failed:', e.message);
        return false;
      }
    },

    syncVisibleScansFromLatest(items, { final = false } = {}) {
      if (this.currentPage !== 'scans') return;
      if (!this.isDefaultScansLiveView()) {
        this.queuePendingScanUpdates(
          final ? 'Scan list changed while you were browsing. Refresh to load the latest rows.' : 'New scan data is available. Refresh when ready.'
        );
        return;
      }

      const latestPage = (items || []).slice(0, Math.max(this.scansPerPage, 20));
      const latestById = new Map(latestPage.map(scan => [scan.id, scan]));
      const hasNewRows = latestPage.some(scan => !this.scans.some(current => current.id === scan.id));
      let changed = false;
      const nextRows = this.scans.map(scan => {
        const fresh = latestById.get(scan.id);
        if (!fresh) return scan;
        const merged = { ...scan, ...fresh };
        if (stableSerialize(scan) !== stableSerialize(merged)) changed = true;
        return merged;
      });

      if (changed) this.scans = nextRows;
      if (hasNewRows) {
        this.queuePendingScanUpdates('New scans are available. Refresh to insert them at the top.');
      } else if (changed) {
        this.clearPendingScanUpdates();
      }
    },

    async refreshScansNow() {
      this.clearPendingScanUpdates();
      await this.loadScans(false, true);
    },

    async refreshFindingsNow() {
      this.clearPendingFindingUpdates();
      await this.loadFindings(false, true);
    },

    async syncCurrentPageAfterScanCompletion() {
      if (this.currentPage === 'dashboard') {
        await this.refreshDashboardData();
        await nextTick();
        await this.initDashboardCharts('background-refresh');
        return;
      }
      if (this.currentPage === 'scans') {
        try {
          const result = await apiFetch('/api/scans/paginated?per_page=20&sort_by=created_at&sort_order=DESC');
          this.syncVisibleScansFromLatest(result.items || [], { final: true });
        } catch (e) {
          console.debug('[scanCompletion] scans sync failed:', e.message);
        }
        return;
      }
      if (this.currentPage === 'findings') {
        if (this.canAutoRefreshFindingsView()) {
          await this.loadFindings(false, true);
          this.clearPendingFindingUpdates();
        } else {
          this.queuePendingFindingUpdates('Scan finished. Refresh when you are ready to review the new results.');
        }
        return;
      }
      if (this.currentPage === 'analytics') {
        try {
          await this._refreshAnalyticsData('background-refresh');
        } catch (e) {
          console.debug('[scanCompletion] analytics sync failed:', e.message);
        }
      }
    },

    forceResizeCharts() {
      if (!this.chartsAvailable) return;
      if (this._resizeFrame) cancelAnimationFrame(this._resizeFrame);
      this._resizeFrame = requestAnimationFrame(() => {
        this._resizeFrame = null;
        Object.values(this.charts).forEach(chart => {
          if (!this.chartIsUsable(chart)) return;
          try {
            chart.options.animation = false;
            chart.resize();
          } catch (error) {
            console.debug('[charts] resize skipped:', error?.message || error);
            this.safeDestroyChart(chart);
          }
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

    async navigate(page, { pushHistory = true, force = false } = {}) {
      // Skip redundant navigation to the same page (prevents chart destruction)
      if (page === this.currentPage && !force) return;

      // Destroy chart instances when leaving a chart page — the v-if directive
      // removes the canvas elements from the DOM so old instances become stale.
      const prevPage = this.currentPage;
      if (prevPage !== page) {
        if (prevPage === 'dashboard') {
          ['severity', 'trend', 'remediation'].forEach(k => {
            this.safeDestroyChart(k);
          });
        } else if (prevPage === 'analytics') {
          ['risk', 'owasp', 'analyticsTrend', 'toolEff', 'severityDist'].forEach(k => {
            this.safeDestroyChart(k);
          });
        }
      }

      this.currentPage = page;
      this.mobileNavOpen = false;
      // Update URL hash for bookmarkability and back/forward support
      if (pushHistory) history.pushState({ page }, '', '#' + page);
      window.scrollTo(0, 0);
      await nextTick();
      if (page === 'dashboard') {
        await this.refreshDashboardData();
        await this.initDashboardCharts('mount');
      }
      if (page === 'scans') await this.loadScans(true);
      if (page === 'findings') await this.loadFindings(true);
      if (page === 'analytics') await this.loadAnalytics('mount');
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
      if (this.currentPage !== 'dashboard') {
        try {
          this.kpis = await apiFetch('/api/kpi');
        } catch (e) {
          console.debug('[refreshCurrentPage] KPI refresh failed:', e.message);
        }
      }
      await this.navigate(this.currentPage, { force: true });
    },

    async refreshDashboardData() {
      const [kpiRes, scansRes] = await Promise.allSettled([
        apiFetch('/api/kpi'),
        apiFetch('/api/scans/paginated?per_page=12&sort_by=created_at&sort_order=DESC'),
      ]);
      if (kpiRes.status === 'fulfilled') {
        this.kpis = kpiRes.value || {};
      } else {
        console.debug('[refreshDashboardData] KPI refresh failed:', kpiRes.reason?.message || kpiRes.reason);
      }
      if (scansRes.status === 'fulfilled') {
        const items = scansRes.value?.items || [];
        this.applyRecentScans(items);
      } else {
        console.debug('[refreshDashboardData] Recent scans refresh failed:', scansRes.reason?.message || scansRes.reason);
      }
      this._lastKpiRefreshAt = Date.now();
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
      if (!this.mobileNavOpen) this.rememberOverlayFocus();
      this.mobileNavOpen = !this.mobileNavOpen;
      if (!this.mobileNavOpen) this.restoreOverlayFocus();
    },

    closeMobileNav() {
      const wasOpen = this.mobileNavOpen;
      this.mobileNavOpen = false;
      if (wasOpen) this.restoreOverlayFocus();
    },

    cancelAnalyticsWarmup() {
      if (this._analyticsWarmupCleanup) {
        this._analyticsWarmupCleanup();
        this._analyticsWarmupCleanup = null;
      }
    },

    scheduleAnalyticsWarmup() {
      this.cancelAnalyticsWarmup();
      if (this.currentPage === 'analytics' || this._analyticsWarmupDone || !this.isDocumentVisible()) return;

      const runWarmup = async () => {
        this._analyticsWarmupCleanup = null;
        if (
          this.currentPage === 'analytics' ||
          this._analyticsWarmupDone ||
          !this.isDocumentVisible() ||
          this.hasRunningScans
        ) {
          return;
        }
        try {
          await this._refreshAnalyticsData('silent-sync');
          this._analyticsWarmupDone = true;
        } catch (e) {
          console.debug('[analyticsWarmup] warmup skipped:', e.message);
        }
      };

      if (typeof window.requestIdleCallback === 'function') {
        const idleId = window.requestIdleCallback(() => {
          const timerId = window.setTimeout(runWarmup, 1500);
          this._analyticsWarmupCleanup = () => window.clearTimeout(timerId);
        }, { timeout: 5000 });
        this._analyticsWarmupCleanup = () => window.cancelIdleCallback(idleId);
        return;
      }

      const timerId = window.setTimeout(runWarmup, 4000);
      this._analyticsWarmupCleanup = () => window.clearTimeout(timerId);
    },

    // ── Auto-refresh ──────────────────────────────────────────────────────────

    startAutoRefresh() {
      this.stopAutoRefresh();
      this._autoRefreshStopped = false;

      const run = async () => {
        if (this._autoRefreshStopped) return;
        try {
          if (!this.autoRefresh || !this.isDocumentVisible()) return;
          if (this.currentPage === 'dashboard') {
            await this.refreshDashboardData();
            await this.initDashboardCharts('background-refresh');
          } else if (this.currentPage === 'analytics') {
            await this.refreshKpis();
            await this._refreshAnalyticsData('background-refresh');
          } else {
            await this.refreshKpis();
          }
        } catch (e) {
          console.debug('[autoRefresh] page refresh failed:', e.message);
        } finally {
          if (!this._autoRefreshStopped) {
            this.refreshInterval = setTimeout(run, 30000);
          }
        }
      };

      this.refreshInterval = setTimeout(run, 30000);
    },

    stopAutoRefresh() {
      this._autoRefreshStopped = true;
      if (this.refreshInterval) {
        clearTimeout(this.refreshInterval);
        this.refreshInterval = null;
      }
    },

    startScanPolling(scanId) {
      this.hasRunningScans = true;
      this._pollScanId = scanId || null;
      this._pollDeadline = Date.now() + 37 * 60 * 1000; // 37 min (> 30 min subprocess timeout)
      if (this.scanPollingInterval) return;
      this._scanPollingStopped = false;

      const run = async () => {
        if (this._scanPollingStopped) return;
        try {
          if (!this.isDocumentVisible()) return;
          const result = await apiFetch('/api/scans/paginated?per_page=20&sort_by=created_at&sort_order=DESC');
          const items = result.items || [];
          const recentChanged = this.applyRecentScans(items);

          await this.refreshKpis();
          if (this.currentPage === 'dashboard' && recentChanged) {
            await nextTick();
            this.buildTrendChart('background-refresh');
          } else if (this.currentPage === 'scans') {
            this.syncVisibleScansFromLatest(items);
          } else if (this.currentPage === 'findings' && !this.hasPendingFindingUpdates) {
            this.findingsLiveMessage = 'Scan running. Results will update when ready.';
          }

          const stillRunning = this._pollScanId
            ? items.some(s => s.id === this._pollScanId && s.status === 'RUNNING')
            : items.some(s => s.status === 'RUNNING');
          if (!stillRunning || Date.now() > this._pollDeadline) {
            this.hasRunningScans = false;
            this.stopScanPolling();
            const targetScan = this._pollScanId
              ? items.find(s => s.id === this._pollScanId)
              : null;
            if (targetScan && targetScan.status === 'FAILED') {
              this.showToast('Scan failed: ' + (targetScan.error_message || 'unknown error'), 'error');
            } else if (targetScan && (targetScan.status === 'COMPLETED_WITH_FINDINGS' || targetScan.status === 'COMPLETED_CLEAN')) {
              this.showToast('Scan completed successfully');
            } else if (!this._pollScanId) {
              this.showToast('Scan completed successfully');
            }
            await this.refreshKpis(true);
            await this.syncCurrentPageAfterScanCompletion();
          }
        } catch (e) {
          console.debug('[scanPolling] poll failed:', e.message);
        } finally {
          if (!this._scanPollingStopped) {
            this.scanPollingInterval = setTimeout(run, 5000);
          }
        }
      };

      this.scanPollingInterval = setTimeout(run, 5000);
    },

    stopScanPolling() {
      this._scanPollingStopped = true;
      if (this.scanPollingInterval) {
        clearTimeout(this.scanPollingInterval);
        this.scanPollingInterval = null;
      }
    },

    // ── Dashboard Charts ──────────────────────────────────────────────────────

    async initDashboardCharts(mode = 'background-refresh') {
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
        this.buildTrendChart(mode);
        this.buildSeverityChart(sevData, mode);
        await this.buildRemediationChart(mode);
      } finally {
        this._chartsBuilding = false;
      }
    },

    async buildRemediationChart(mode = 'background-refresh') {
      if (this.currentPage !== 'dashboard') return;
      const chartId = ++this._remediationChartVersion;

      let statusMap = {};
      try {
        statusMap = await apiFetch('/api/findings/status-counts');
      } catch (_) {
        statusMap = {};
      }

      // Bail out if a newer refresh started or user navigated away.
      if (this._remediationChartVersion !== chartId || this.currentPage !== 'dashboard') return;

      const counts = STATUS_KEYS.map(s => Number(statusMap[s] || 0));
      const nonZeroIdx = counts.map((c, i) => c > 0 ? i : -1).filter(i => i >= 0);
      const activeIdx = nonZeroIdx.length > 0 ? nonZeroIdx : counts.map((_, i) => i);
      const activeStatuses = activeIdx.map(i => ({
        key: STATUS_KEYS[i],
        label: STATUS_LABELS[i],
        value: counts[i],
        color: STATUS_COLORS[i],
      }));
      const total = activeStatuses.reduce((sum, item) => sum + item.value, 0);
      const onlyNew = total > 0 && activeStatuses.length === 1 && activeStatuses[0].key === 'new';
      const resolvedCount = Number(statusMap.resolved || 0) + Number(statusMap.false_positive || 0) + Number(statusMap.risk_accepted || 0);
      const signature = stableSerialize({ activeStatuses, total, onlyNew, resolvedCount });

      const canvas = this.$refs.remediationChart;
      if (!canvas || !canvas.isConnected) return;
      if (this.charts.remediation && this.charts.remediation.canvas !== canvas) {
        this.safeDestroyChart('remediation');
      }

      const datasets = activeStatuses.map((status) => ({
        label: status.label,
        data: [status.value],
        backgroundColor: status.color,
        borderRadius: activeStatuses.length === 1 ? 10 : 6,
        borderSkipped: false,
        maxBarThickness: 26,
      }));

      if (this.charts.remediation) {
        if (this.charts.remediation.$sspSignature === signature) return;
        this.charts.remediation.data.labels = ['Findings'];
        this.charts.remediation.data.datasets = datasets;
        this.charts.remediation.options.plugins.legend.labels.generateLabels = (chart) => {
          return chart.data.datasets.map((dataset, datasetIndex) => {
            const value = dataset.data[0] || 0;
            const percent = total > 0 ? Math.round((value / total) * 100) : 0;
            return {
              text: `${dataset.label} (${value}, ${percent}%)`,
              fillStyle: dataset.backgroundColor,
              strokeStyle: dataset.backgroundColor,
              hidden: !chart.isDatasetVisible(datasetIndex),
              datasetIndex,
            };
          });
        };
        this.charts.remediation.options.plugins.title.display = onlyNew;
        this.charts.remediation.options.plugins.title.text = 'No remediation started yet';
        this.charts.remediation.options.plugins.subtitle.display = onlyNew;
        this.charts.remediation.options.plugins.subtitle.text = `${total} findings are still in the New state`;
        this.charts.remediation.options.plugins.tooltip.callbacks.label = (ctx) => {
          const value = ctx.parsed.x || 0;
          const percent = total > 0 ? Math.round((value / total) * 100) : 0;
          return ` ${ctx.dataset.label}: ${value} findings (${percent}%)`;
        };
        this.charts.remediation.options.plugins.tooltip.callbacks.footer = () => `Resolved or closed: ${resolvedCount} / ${total}`;
        this.charts.remediation.options.scales.x.title.text = total > 0 ? `Total findings: ${total}` : 'Findings';
        this.charts.remediation.$sspSignature = signature;
        this.updateChartWithMode(this.charts.remediation, mode);
        return;
      }

      this.charts.remediation = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: {
          labels: ['Findings'],
          datasets,
        },
        options: this.withChartMotion({
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                boxWidth: 12,
                padding: 12,
                color: this.cssVar('--chart-legend'),
                generateLabels: (chart) => {
                  return chart.data.datasets.map((dataset, datasetIndex) => {
                    const value = dataset.data[0] || 0;
                    const percent = total > 0 ? Math.round((value / total) * 100) : 0;
                    return {
                      text: `${dataset.label} (${value}, ${percent}%)`,
                      fillStyle: dataset.backgroundColor,
                      strokeStyle: dataset.backgroundColor,
                      hidden: !chart.isDatasetVisible(datasetIndex),
                      datasetIndex,
                    };
                  });
                },
              },
            },
            title: {
              display: onlyNew,
              text: 'No remediation started yet',
              color: this.cssVar('--chart-tick'),
              font: { size: 12, weight: '600' },
              padding: { bottom: 6 },
            },
            subtitle: {
              display: onlyNew,
              text: `${total} findings are still in the New state`,
              color: this.cssVar('--chart-legend'),
              font: { size: 11 },
              padding: { bottom: 10 },
            },
            tooltip: {
              callbacks: {
                label: (ctx) => {
                  const value = ctx.parsed.x || 0;
                  const percent = total > 0 ? Math.round((value / total) * 100) : 0;
                  return ` ${ctx.dataset.label}: ${value} findings (${percent}%)`;
                },
                footer: () => `Resolved or closed: ${resolvedCount} / ${total}`,
              },
            },
          },
          scales: {
            x: {
              stacked: true,
              beginAtZero: true,
              grid: { color: this.cssVar('--chart-grid') },
              ticks: { precision: 0, color: this.cssVar('--chart-tick') },
              title: {
                display: true,
                text: total > 0 ? `Total findings: ${total}` : 'Findings',
                color: this.cssVar('--chart-tick'),
                font: { size: 10 },
              },
            },
            y: {
              stacked: true,
              grid: { display: false },
              ticks: {
                color: this.cssVar('--chart-tick'),
                callback: () => '',
              },
            },
          },
        }, mode),
      });
      this.charts.remediation.$sspSignature = signature;
    },

    buildSeverityChart(data, mode = 'background-refresh') {
      if (this.currentPage !== 'dashboard') return;
      const canvas = this.$refs.severityChart;
      if (!canvas) return;
      // If chart instance points to a canvas removed by v-if, discard it.
      if (this.charts.severity && this.charts.severity.canvas !== canvas) {
        this.safeDestroyChart('severity');
      }
      // Use provided data (pre-fetched by caller) or fall back to init data.
      if (!data || Object.keys(data).length === 0) data = this.severityBreakdown || {};
      const labels = SEVERITY_ORDER.filter(k => data[k] !== undefined && data[k] > 0);
      const values = labels.map(k => data[k]);
      const colors = labels.map(k => SEVERITY_COLORS[k] || '#9ca3af');
      const signature = stableSerialize({ labels, values, colors });
      if (this.charts.severity) {
        if (this.charts.severity.$sspSignature === signature) return;
        this.charts.severity.data.labels = labels;
        this.charts.severity.data.datasets[0].data = values;
        this.charts.severity.data.datasets[0].backgroundColor = colors;
        this.charts.severity.$sspSignature = signature;
        this.updateChartWithMode(this.charts.severity, mode);
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
        options: this.withChartMotion({
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          layout: { padding: { top: 4, right: 8, bottom: 0, left: 0 } },
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
        }, mode),
      });
      this.charts.severity.$sspSignature = signature;
    },

    buildTrendChart(mode = 'background-refresh') {
      if (this.currentPage !== 'dashboard') return;
      const canvas = this.$refs.trendChart;
      if (!canvas) return;
      if (this.charts.trend && this.charts.trend.canvas !== canvas) {
        this.safeDestroyChart('trend');
      }
      if (this.charts.trend && (!this.charts.trend.canvas || !this.charts.trend.canvas.isConnected)) {
        this.safeDestroyChart('trend');
      }

      const scans = (this.recentScans || []).slice(0, 12);
      if (scans.length === 0) {
        if (this.charts.trend) {
          this.safeDestroyChart('trend');
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
      const signature = stableSerialize({ labels, dsData });

      if (this.charts.trend) {
        if (this.charts.trend.$sspSignature === signature) return;
        this.charts.trend.data.labels = labels;
        dsData.forEach((d, i) => {
          if (this.charts.trend.data.datasets[i]) this.charts.trend.data.datasets[i].data = d;
        });
        this.charts.trend.$sspSignature = signature;
        this.updateChartWithMode(this.charts.trend, mode);
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
        options: this.withChartMotion({
          responsive: true,
          maintainAspectRatio: false,
          interaction: { mode: 'index', intersect: false },
          layout: { padding: { top: 2, right: 8, bottom: 4, left: 0 } },
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
        }, mode),
      });
      this.charts.trend.$sspSignature = signature;
    },

    // ── Scans ─────────────────────────────────────────────────────────────────

    _syncScansHash() {
      const f = this.scansFilter;
      const hp = new URLSearchParams();
      for (const key of ['search', 'target', 'status', 'policy']) {
        if (f[key]) hp.set(key, f[key]);
      }
      const qs = hp.toString();
      const hash = '#scans' + (qs ? '?' + qs : '');
      history.replaceState({ page: 'scans' }, '', hash);
    },

    async loadScans(reset = false, preservePage = false) {
      this.clearPendingScanUpdates();
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
        if (this.currentPage === 'scans') this._syncScansHash();

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

    ariaSort(table, col) {
      const sort = table === 'scans' ? this.scansSort : this.findingsSort;
      if (!sort || sort.by !== col) return 'none';
      return sort.order === 'ASC' ? 'ascending' : 'descending';
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
      this.rememberOverlayFocus();
      this.selectedScan = scan;
      this.focusModal('scanDetailModal');
    },

    openScanModalDialog() {
      this.rememberOverlayFocus();
      this.showScanModal = true;
      this.focusModal('scanModal');
    },

    closeScanModal() {
      const wasOpen = this.showScanModal;
      this.showScanModal = false;
      this.scanTriggering = false;
      this.newScanForm = { name: '', target: '', target_type: 'local' };
      if (wasOpen) this.restoreOverlayFocus();
    },

    openCreateKeyModal() {
      this.rememberOverlayFocus();
      this.showCreateKeyModal = true;
      this.newKeyResult = '';
      this.focusModal('createKeyModal');
    },

    closeCreateKeyModal() {
      const wasOpen = this.showCreateKeyModal;
      this.showCreateKeyModal = false;
      this.newKeyResult = '';
      this.newKeyForm = { name: '', role: 'operator', expires_days: '' };
      if (wasOpen) this.restoreOverlayFocus();
    },

    openCreateWebhookModal() {
      this.rememberOverlayFocus();
      this.showCreateWebhookModal = true;
      this.focusModal('createWebhookModal');
    },

    closeCreateWebhookModal() {
      const wasOpen = this.showCreateWebhookModal;
      this.showCreateWebhookModal = false;
      this.newWebhookForm = { name: '', url: '', events: 'scan.completed', secret: '' };
      if (wasOpen) this.restoreOverlayFocus();
    },

    closeScanDetail() {
      const hadSelection = !!this.selectedScan;
      this.selectedScan = null;
      if (hadSelection) this.restoreOverlayFocus();
    },

    viewScanFindings(scan) {
      this.closeScanDetail();
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
      this.clearPendingFindingUpdates();
      if (this.hasRunningScans) {
        this.findingsLiveMessage = 'Scan running. Results will update when ready.';
      }
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
      this.rememberOverlayFocus();
      this.selectedFinding = finding;
      this.focusModal('findingModal');
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
      const hadSelection = !!this.selectedFinding;
      this.selectedFinding = null;
      if (hadSelection) this.restoreOverlayFocus();
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

    async loadAnalytics(mode = 'mount') {
      // Show loading overlay only on first load; for subsequent loads the
      // analyticsRefreshing flag drives a subtle inline indicator instead.
      const isFirstLoad = !this.analyticsData.riskDistribution;
      if (isFirstLoad) this.loading = true;
      try {
        await this._refreshAnalyticsData(isFirstLoad ? 'mount' : mode);
      } catch (e) {
        this.showToast('Failed to load analytics: ' + e.message, 'error');
      } finally {
        this.loading = false;
      }
    },

    /** Build analytics charts if the analytics page is currently visible. */
    _buildAnalyticsCharts(sevData, mode = 'background-refresh') {
      if (!this.chartsAvailable) return;
      if (this.currentPage !== 'analytics') return;
      this.buildRiskChart(mode);
      this.buildOwaspChart(mode);
      this.buildAnalyticsTrendChart(mode);
      this.buildToolEffChart(mode);
      this.buildSeverityDistChart(sevData, mode);
    },

    async refreshAnalyticsNow() {
      await this.loadAnalytics('user-change');
    },

    async _refreshAnalyticsData(mode = 'background-refresh') {
      // Cancel any in-flight refresh — always use the latest request so that
      // chart builders run with fresh $refs after navigation.
      const refreshSeq = ++this._analyticsRefreshSeq;
      if (this._analyticsAbortController) {
        this._analyticsAbortController.abort();
      }
      const controller = new AbortController();
      this._analyticsAbortController = controller;
      this.analyticsRefreshing = true;
      this.analyticsRefreshingMode = mode;

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
          apiFetch('/api/analytics/risk-distribution', { signal: controller.signal }).then(d => {
            if (!stale()) this.analyticsData.riskDistribution = d;
          }),
          apiFetch('/api/analytics/compliance', { signal: controller.signal }).then(d => {
            if (!stale()) this.analyticsData.compliance = d;
          }),
          apiFetch(`/api/analytics/trends?days=${this.analyticsDays}`, { signal: controller.signal }).then(d => {
            if (!stale()) this.analyticsData.trends = d;
          }),
          apiFetch('/api/analytics/target-risk', { signal: controller.signal }).then(d => {
            if (!stale()) this.analyticsData.targetRisk = d;
          }),
          apiFetch('/api/analytics/tool-effectiveness', { signal: controller.signal }).then(d => {
            if (!stale()) this.analyticsData.toolEffectiveness = d;
          }),
          apiFetch('/api/chart/severity-breakdown', { signal: controller.signal }).then(fresh => {
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

        if (!stale()) this._buildAnalyticsCharts(sevData, mode);
      } finally {
        if (this._analyticsAbortController === controller) {
          this._analyticsAbortController = null;
        }
        if (refreshSeq === this._analyticsRefreshSeq) this.analyticsRefreshing = false;
      }
    },

    buildToolEffChart(mode = 'background-refresh') {
      const canvas = this.$refs.toolEffChart;
      if (!canvas || !this.analyticsData.toolEffectiveness) return;
      if (this.charts.toolEff && this.charts.toolEff.canvas !== canvas) {
        this.safeDestroyChart('toolEff');
      }
      if (this.charts.toolEff && (!this.charts.toolEff.canvas || !this.charts.toolEff.canvas.isConnected)) {
        this.safeDestroyChart('toolEff');
      }
      const tools = this.analyticsData.toolEffectiveness;
      if (!Array.isArray(tools) || tools.length === 0) {
        if (this.charts.toolEff) {
          this.safeDestroyChart('toolEff');
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
      const signature = stableSerialize({ labels: newLabels, dsData });
      if (this.charts.toolEff) {
        if (this.charts.toolEff.$sspSignature === signature) return;
        this.charts.toolEff.data.labels = newLabels;
        dsData.forEach((d, i) => {
          if (this.charts.toolEff.data.datasets[i]) this.charts.toolEff.data.datasets[i].data = d;
        });
        this.charts.toolEff.$sspSignature = signature;
        this.updateChartWithMode(this.charts.toolEff, mode);
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
        options: this.withChartMotion({
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
        }, mode),
      });
      this.charts.toolEff.$sspSignature = signature;
    },

    buildSeverityDistChart(data, mode = 'background-refresh') {
      const canvas = this.$refs.severityDistChart;
      if (!canvas) return;
      if (this.charts.severityDist && this.charts.severityDist.canvas !== canvas) {
        this.safeDestroyChart('severityDist');
      }
      if (!data || Object.keys(data).length === 0) data = this.severityBreakdown || {};
      const labels = SEVERITY_ORDER.filter(k => data[k] !== undefined && data[k] > 0);
      const values = labels.map(k => data[k]);
      const colors = labels.map(k => SEVERITY_COLORS[k] || '#9ca3af');
      const signature = stableSerialize({ labels, values, colors });
      if (labels.length === 0) {
        if (this.charts.severityDist) {
          this.safeDestroyChart('severityDist');
        }
        return;
      }
      if (this.charts.severityDist) {
        if (this.charts.severityDist.$sspSignature === signature) return;
        this.charts.severityDist.data.labels = labels;
        this.charts.severityDist.data.datasets[0].data = values;
        this.charts.severityDist.data.datasets[0].backgroundColor = colors;
        this.charts.severityDist.$sspSignature = signature;
        this.updateChartWithMode(this.charts.severityDist, mode);
        return;
      }
      this.charts.severityDist = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: {
          labels,
          datasets: [{
            label: 'Findings',
            data: values,
            backgroundColor: colors,
            borderRadius: 8,
            borderSkipped: false,
          }],
        },
        options: this.withChartMotion({
          responsive: true, maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: {
            legend: { display: false },
            tooltip: {
              callbacks: {
                label: ctx => ` ${ctx.parsed.x} findings (${ctx.label})`,
              },
            },
          },
          scales: {
            x: {
              beginAtZero: true,
              grid: { color: this.cssVar('--chart-grid') },
              ticks: { precision: 0, color: this.cssVar('--chart-tick') },
            },
            y: {
              grid: { display: false },
              ticks: { color: this.cssVar('--chart-tick'), font: { weight: '600' } },
            },
          },
        }, mode),
      });
      this.charts.severityDist.$sspSignature = signature;
    },

    buildRiskChart(mode = 'background-refresh') {
      const canvas = this.$refs.riskChart;
      if (!canvas || !this.analyticsData.riskDistribution) return;
      if (this.charts.risk && this.charts.risk.canvas !== canvas) {
        this.safeDestroyChart('risk');
      }
      const dist = this.analyticsData.riskDistribution.distribution || {};
      if (Object.keys(dist).length === 0) {
        if (this.charts.risk) {
          this.safeDestroyChart('risk');
        }
        return;
      }
      const RISK_LABEL_MAP = {
        '0-25': 'Low · 0-25',
        '25-50': 'Moderate · 25-50',
        '50-75': 'Elevated · 50-75',
        '75-100': 'Severe · 75-100',
      };
      const RISK_TOOLTIP_MAP = {
        '0-25': 'Low exposure band',
        '25-50': 'Moderate exposure band',
        '50-75': 'Elevated exposure band',
        '75-100': 'Severe exposure band',
      };
      const rawLabels = ['0-25', '25-50', '50-75', '75-100'].filter((label) => dist[label] !== undefined);
      const labels = rawLabels.map(l => RISK_LABEL_MAP[l] || l);
      const values = rawLabels.map((label) => dist[label]);
      const signature = stableSerialize({ labels, values });
      if (this.charts.risk) {
        if (this.charts.risk.$sspSignature === signature) return;
        this.charts.risk.data.labels = labels;
        this.charts.risk.data.datasets[0].data = values;
        this.charts.risk.$sspSignature = signature;
        this.updateChartWithMode(this.charts.risk, mode);
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
        options: this.withChartMotion({
          responsive: true, maintainAspectRatio: false,
          layout: { padding: { top: 4, right: 6, bottom: 0, left: 0 } },
          plugins: {
            legend: { display: false },
            tooltip: {
              callbacks: {
                title: (items) => RISK_TOOLTIP_MAP[rawLabels[items[0]?.dataIndex]] || 'Risk band',
                label: ctx => ` ${ctx.parsed.y} findings`,
              },
            },
          },
          scales: {
            y: {
              beginAtZero: true,
              grid: { color: this.cssVar('--chart-grid') },
              ticks: { color: this.cssVar('--chart-tick'), precision: 0, font: { size: 11 } },
              title: { display: true, text: 'Findings', color: this.cssVar('--chart-tick'), font: { size: 10 } },
            },
            x: {
              grid: { display: false },
              ticks: { color: this.cssVar('--chart-tick'), font: { size: 11 }, maxRotation: 0, minRotation: 0 },
            },
          },
        }, mode),
      });
      this.charts.risk.$sspSignature = signature;
    },

    buildOwaspChart(mode = 'background-refresh') {
      const canvas = this.$refs.owaspChart;
      if (!canvas || !this.analyticsData.compliance) return;
      if (this.charts.owasp && this.charts.owasp.canvas !== canvas) {
        this.safeDestroyChart('owasp');
      }
      const owasp = (this.analyticsData.compliance.owasp_top_10 || []).slice(0, 6);
      if (owasp.length === 0) {
        if (this.charts.owasp) {
          this.safeDestroyChart('owasp');
        }
        return;
      }
      const fullLabels = owasp.map(o => o.category);
      const SHORT_OWASP_LABELS = {
        'A01:2021': 'A01 Access',
        'A02:2021': 'A02 Crypto',
        'A03:2021': 'A03 Injection',
        'A05:2021': 'A05 Misconfig',
        'A06:2021': 'A06 Components',
        'A08:2021': 'A08 Integrity',
        'A09:2021': 'A09 Logging',
        'A10:2021': 'A10 SSRF',
      };
      const labels = fullLabels.map((category) => {
        const code = String(category).split(' - ')[0];
        return SHORT_OWASP_LABELS[code] || code || category;
      });
      const values = owasp.map(o => o.count);
      const signature = stableSerialize({ labels, values });
      if (this.charts.owasp) {
        if (this.charts.owasp.$sspSignature === signature) return;
        this.charts.owasp.data.labels = labels;
        this.charts.owasp.data.datasets[0].data = values;
        this.charts.owasp.data.datasets[0].backgroundColor = OWASP_COLORS.slice(0, values.length);
        this.charts.owasp.$sspSignature = signature;
        this.updateChartWithMode(this.charts.owasp, mode);
        return;
      }
      this.charts.owasp = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: {
          labels,
          datasets: [{
            label: 'Findings',
            data: values,
            backgroundColor: OWASP_COLORS.slice(0, values.length),
            borderRadius: 8,
            borderSkipped: false,
          }],
        },
        options: this.withChartMotion({
          responsive: true, maintainAspectRatio: false,
          indexAxis: 'y',
          layout: { padding: { top: 2, right: 10, bottom: 0, left: 0 } },
          plugins: {
            legend: { display: false },
            tooltip: {
              callbacks: {
                title: (items) => fullLabels[items[0]?.dataIndex] || 'OWASP category',
                label: ctx => ` ${ctx.parsed.x} findings`,
              },
            },
          },
          scales: {
            x: {
              beginAtZero: true,
              grid: { color: this.cssVar('--chart-grid') },
              ticks: { precision: 0, color: this.cssVar('--chart-tick') },
            },
            y: {
              grid: { display: false },
              ticks: { color: this.cssVar('--chart-tick'), font: { weight: '600', size: 11 } },
            },
          },
        }, mode),
      });
      this.charts.owasp.$sspSignature = signature;
    },

    buildAnalyticsTrendChart(mode = 'background-refresh') {
      const canvas = this.$refs.analyticsTrendChart;
      if (!canvas || !this.analyticsData.trends) return;
      if (this.charts.analyticsTrend && this.charts.analyticsTrend.canvas !== canvas) {
        this.safeDestroyChart('analyticsTrend');
      }
      const trendData = this.analyticsData.trends.trend || [];
      if (trendData.length === 0) {
        if (this.charts.analyticsTrend) {
          this.safeDestroyChart('analyticsTrend');
        }
        return;
      }
      const labels = trendData.map(t => t.date);
      const avgData = trendData.map(t => t.average_risk);
      const maxData = trendData.map(t => t.max_risk);
      const signature = stableSerialize({ labels, avgData, maxData });
      if (this.charts.analyticsTrend) {
        if (this.charts.analyticsTrend.$sspSignature === signature) return;
        this.charts.analyticsTrend.data.labels = labels;
        this.charts.analyticsTrend.data.datasets[0].data = avgData;
        this.charts.analyticsTrend.data.datasets[1].data = maxData;
        this.charts.analyticsTrend.$sspSignature = signature;
        this.updateChartWithMode(this.charts.analyticsTrend, mode);
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
              label: 'Average risk', data: trendData.map(t => t.average_risk),
              borderColor: primaryColor,
              backgroundColor: primaryColor + '18',
              tension: 0.3, fill: true, borderWidth: 2,
            },
            {
              label: 'Peak risk', data: trendData.map(t => t.max_risk),
              borderColor: dangerColor,
              backgroundColor: dangerColor + '10',
              tension: 0.3, fill: false, borderDash: [4, 4], borderWidth: 2,
            },
          ],
        },
        options: this.withChartMotion({
          responsive: true, maintainAspectRatio: false,
          layout: { padding: { top: 4, right: 8, bottom: 2, left: 0 } },
          plugins: {
            legend: {
              position: 'bottom',
              labels: { color: this.cssVar('--chart-legend'), font: { size: 11 }, usePointStyle: true, boxWidth: 10, padding: 16 },
            },
            tooltip: {
              backgroundColor: this.cssVar('--chart-tooltip-bg'),
              titleColor: this.cssVar('--chart-tooltip-title'),
              bodyColor: this.cssVar('--chart-tooltip-body'),
              borderColor: this.cssVar('--chart-tooltip-border'),
              borderWidth: 1,
              callbacks: {
                label: (ctx) => ` ${ctx.dataset.label}: ${ctx.parsed.y}/100`,
              },
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
              ticks: { color: tickColor, font: { size: 11 }, maxRotation: 0, autoSkip: true, maxTicksLimit: 8 },
            },
          },
        }, mode),
      });
      this.charts.analyticsTrend.$sspSignature = signature;
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

    formatModalTarget(target) {
      const text = String(target || '—');
      return text.length > 54 ? text.slice(0, 52) + '…' : text;
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
        this.closeScanModal();
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
        this.closeCreateWebhookModal();
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
        _csrfToken = null;
        this.toasts = [];
        window.location.replace('/login');
      } catch (e) {
        this.showToast('Sign out failed. Please retry.', 'error');
        console.debug('[logout] failed:', e.message);
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

    clearScanFilter(key) {
      if (!(key in this.scansFilter)) return;
      this.scansFilter[key] = '';
      this.loadScans(true);
    },

    clearFindingFilter(key) {
      if (!(key in this.findingsFilter)) return;
      this.findingsFilter[key] = '';
      this.loadFindings(true);
    },

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
        document.documentElement.removeAttribute('data-theme');
        localStorage.setItem('ssp-theme', 'dark');
      } else {
        document.documentElement.setAttribute('data-theme', 'light');
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
          this.safeDestroyChart(k);
        });
        // Rebuild visible charts so legend/tick colors update immediately
        if (this.currentPage === 'dashboard') this.initDashboardCharts('silent-sync');
        else if (this.currentPage === 'analytics') this.loadAnalytics('silent-sync');
      });
    },

  },
}).mount('#app');
