/**
 * Security Scanning Platform — SPA Vue.js
 * Version 2.0 — Complete SPA architecture with pagination, triage and analytics
 */

const { createApp, ref, reactive, computed, onMounted, nextTick, watch } = Vue;

// ─── Utility ──────────────────────────────────────────────────────────────────

function debounce(fn, delay) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}

async function apiFetch(url, options = {}, timeoutMs = 30000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: controller.signal, ...options });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    return res.json();
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new Error(`Request timed out after ${timeoutMs / 1000}s: ${url}`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
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

      // ── Navigation
      currentPage: 'dashboard',
      sidebarCollapsed: false,

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
      scansFilter: { target: '', status: '', policy: '' },

      // ── Findings page
      findings: [],
      findingsLoading: false,
      findingsTotal: 0,
      findingsPage: 1,
      findingsCursor: null,
      findingsCursorStack: [],
      findingsFilter: { search: '', severity: '', tool: '', target: '', status: '', scan_id: '' },
      findingsSort: { by: 'id', order: 'ASC' },
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
      compareResult: null,
      compareLoading: false,
      selectedScans: [],

      // ── New Scan modal
      showScanModal: false,
      scanTriggering: false,
      newScanForm: { name: '', target: '', target_type: 'local' },
      scanPollingInterval: null,
      hasRunningScans: false,

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
    allSelected() {
      return this.findings.length > 0 && this.selectedFindings.length === this.findings.length;
    },
  },

   async mounted() {
    this.debouncedLoadFindings = debounce(() => this.loadFindings(true), 400);

    // ── URL Routing: read initial page from URL hash
    const validPages = ['dashboard', 'scans', 'findings', 'analytics', 'settings', 'compare'];
    const hashPage = window.location.hash.replace('#', '');
    const initialPage = validPages.includes(hashPage) ? hashPage : 'dashboard';
    if (initialPage !== 'dashboard') this.currentPage = initialPage;
    history.replaceState({ page: initialPage }, '', '#' + initialPage);

    // ── History API: back/forward button support
    window.addEventListener('popstate', (e) => {
      const page = (e.state && e.state.page) ? e.state.page : 'dashboard';
      if (validPages.includes(page)) {
        this.currentPage = page;
        if (page === 'dashboard') this.initDashboardCharts();
        else if (page === 'scans') this.loadScans(true);
        else if (page === 'findings') this.loadFindings(true);
        else if (page === 'analytics') this.loadAnalytics();
        else if (page === 'settings') { this.settingsTab = 'apikeys'; this.loadApiKeys(); }
        else if (page === 'compare') this.loadCompareScanList();
      }
    });

    // ── Dark mode: restore preference from localStorage
    const savedTheme = localStorage.getItem('ssp-theme');
    if (savedTheme === 'dark') {
      this.darkMode = true;
      document.documentElement.setAttribute('data-theme', 'dark');
    }

    // ── Minimal keyboard: Escape to close modals
    this._keyHandler = (e) => {
      if (e.key === 'Escape') {
        this.showFindingModal = false;
        this.showScanModal = false;
        this.selectedFinding = null;
        this.selectedScan = null;
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

    this.applyChartDefaults();
    await this.initDashboardCharts();
    if (initialPage !== 'dashboard') await this.navigate(initialPage);
    this.startAutoRefresh();
  },
  beforeUnmount() {
    if (this.refreshInterval) clearInterval(this.refreshInterval);
    this.stopScanPolling();
    Object.values(this.charts).forEach(c => c && c.destroy());
    if (this._keyHandler) document.removeEventListener('keydown', this._keyHandler);
  },

  methods: {
    // ── Chart theme helpers ────────────────────────────────────────────────────

    applyChartDefaults() {
      const dark = this.darkMode;
      Chart.defaults.color = dark ? '#9ca3af' : '#6b7280';
      Chart.defaults.borderColor = dark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.06)';
    },

    // ── Toggle colonne ───────────────────────────────────────────────────────────────────────────────────

    colVisible(key) {
      const col = this.scanColumns.find(c => c.key === key);
      return col ? col.visible : true;
    },

    // ── Navigation ─────────────────────────────────────────────────────────────────────────────────────

    async navigate(page) {
      this.currentPage = page;
      // Update URL hash for bookmarkability and back/forward support
      history.pushState({ page }, '', '#' + page);
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
      setTimeout(() => {
        this.toasts = this.toasts.filter(t => t.id !== id);
      }, 4000);
    },

    // ── Auto-refresh ──────────────────────────────────────────────────────────

    startAutoRefresh() {
      this.refreshInterval = setInterval(async () => {
        if (!this.autoRefresh) return;
        if (this.currentPage === 'dashboard') {
          try {
            this.kpis = await apiFetch('/api/kpi');
          } catch (e) {
            console.debug('[autoRefresh] KPI poll failed:', e.message);
          }
        }
      }, 30000);
    },

    startScanPolling(triggerTime) {
      this.hasRunningScans = true;
      // Always update so concurrent triggers extend the window
      this._pollTriggerTime = triggerTime || new Date().toISOString();
      this._pollDeadline = Date.now() + 37 * 60 * 1000; // 37 min (> 30 min subprocess timeout)
      if (this.scanPollingInterval) return;
      this.scanPollingInterval = setInterval(async () => {
        try {
          const result = await apiFetch('/api/scans/paginated?per_page=20&sort_by=created_at&sort_order=DESC');
          const items = result.items || [];
          this.recentScans = items.slice(0, 5);
          if (this.currentPage === 'scans') this.scans = items;
          // Stop when a completed scan that started after our trigger appears,
          // or when the deadline is exceeded (scan timed out / failed silently).
          const scanCompleted = items.some(s =>
            s.status !== 'RUNNING' && s.created_at >= this._pollTriggerTime
          );
          if (scanCompleted || Date.now() > this._pollDeadline) {
            this.hasRunningScans = false;
            this.stopScanPolling();
            try { this.kpis = await apiFetch('/api/kpi'); } catch (_) {}
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
        await nextTick();
        this.buildTrendChart();
        this.buildSeverityChart();
        this.buildRemediationChart();
      } finally {
        this._chartsBuilding = false;
      }
    },

    buildRemediationChart() {
      const canvas = this.$refs.remediationChart;
      if (!canvas) return;
      if (this.charts.remediation) this.charts.remediation.destroy();
      const labels = ['New', 'Acknowledged', 'In Progress', 'Resolved', 'False Positive', 'Risk Accepted'];
      const colors = ['#6b7280', '#f59e0b', '#3b82f6', '#10b981', '#8b5cf6', '#ec4899'];
      this.charts.remediation = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: {
          labels,
          datasets: [{
            label: 'Findings',
            data: [0, 0, 0, 0, 0, 0], // updated async
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
            y: { beginAtZero: true, grid: { color: 'rgba(0,0,0,0.05)' }, ticks: { precision: 0 } },
          },
        },
      });
      // Load real data from the API, then hide empty status categories
      const statusKeys = ['new', 'acknowledged', 'in_progress', 'resolved', 'false_positive', 'risk_accepted'];
      Promise.all(statusKeys.map(s =>
        apiFetch(`/api/findings/paginated?status=${s}&per_page=1`)
          .then(r => r.pagination ? r.pagination.count : 0)
          .catch(() => 0)
      )).then(counts => {
        if (!this.charts.remediation) return;
        // Filter out categories with zero findings to reduce visual noise
        const nonZeroIdx = counts.map((c, i) => c > 0 ? i : -1).filter(i => i >= 0);
        if (nonZeroIdx.length > 0) {
          this.charts.remediation.data.labels = nonZeroIdx.map(i => labels[i]);
          this.charts.remediation.data.datasets[0].data = nonZeroIdx.map(i => counts[i]);
          this.charts.remediation.data.datasets[0].backgroundColor = nonZeroIdx.map(i => colors[i]);
        } else {
          // No findings at all — show all with zeros (better than empty chart)
          this.charts.remediation.data.datasets[0].data = counts;
        }
        this.charts.remediation.update();
      });
    },

    buildSeverityChart() {
      const canvas = this.$refs.severityChart;
      if (!canvas) return;
      if (this.charts.severity) this.charts.severity.destroy();
      const data = this.severityBreakdown;
      // Fixed order for readability: most to least severe
      const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'];
      const colorMap = {
        CRITICAL: '#dc2626', HIGH: '#f97316', MEDIUM: '#f59e0b',
        LOW: '#3b82f6', INFO: '#6b7280', UNKNOWN: '#9ca3af',
      };
      const labels = order.filter(k => data[k] !== undefined && data[k] > 0);
      const values = labels.map(k => data[k]);
      const colors = labels.map(k => colorMap[k] || '#9ca3af');
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
            legend: { display: false },
            tooltip: {
              callbacks: {
                label: ctx => ` ${ctx.parsed.x} findings`,
              },
            },
          },
          scales: {
            x: { beginAtZero: true, grid: { color: 'rgba(0,0,0,0.05)' }, ticks: { precision: 0 } },
            y: { grid: { display: false }, ticks: { font: { weight: '600' } } },
          },
        },
      });
    },

    buildToolChart() {
      const canvas = this.$refs.toolChart;
      if (!canvas) return;
      if (this.charts.tool) this.charts.tool.destroy();
      const data = this.toolBreakdown;
      const labels = Object.keys(data).slice(0, 10);
      const values = Object.values(data).slice(0, 10);
      this.charts.tool = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: {
          labels,
          datasets: [{ label: 'Findings', data: values, backgroundColor: '#4f46e5', borderRadius: 6 }],
        },
        options: {
          responsive: true, maintainAspectRatio: false, indexAxis: 'y',
          plugins: { legend: { display: false } },
          scales: { x: { beginAtZero: true, grid: { color: '#f3f4f6' } }, y: { grid: { display: false } } },
        },
      });
    },

    buildTrendChart() {
      const canvas = this.$refs.trendChart;
      if (!canvas) return;
      if (this.charts.trend) this.charts.trend.destroy();
      const trendData = this.trend.slice(-14);

      // Filter out datasets where all values are zero to avoid confusing empty lines
      const scanValues = trendData.map(t => t.scans || 0);
      const findingValues = trendData.map(t => t.findings || 0);
      const hasScans = scanValues.some(v => v > 0);
      const hasFindings = findingValues.some(v => v > 0);

      const datasets = [];
      if (hasScans) {
        datasets.push({
          label: 'Scans',
          data: scanValues,
          borderColor: '#4f46e5',
          backgroundColor: 'rgba(79,70,229,0.08)',
          tension: 0.3,
          fill: true,
          pointRadius: 3,
          pointHoverRadius: 5,
          yAxisID: 'yScans',
        });
      }
      if (hasFindings) {
        datasets.push({
          label: 'Findings',
          data: findingValues,
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239,68,68,0.05)',
          tension: 0.3,
          fill: true,
          pointRadius: 3,
          pointHoverRadius: 5,
          yAxisID: 'yFindings',
        });
      }
      // Fallback if no data yet
      if (datasets.length === 0) {
        datasets.push({
          label: 'Scans', data: trendData.map(() => 0),
          borderColor: '#4f46e5', backgroundColor: 'rgba(79,70,229,0.08)',
          tension: 0.3, fill: true, pointRadius: 3, yAxisID: 'yScans',
        });
      }

      this.charts.trend = new Chart(canvas.getContext('2d'), {
        type: 'line',
        data: {
          labels: trendData.map(t => {
            // Format day labels as short dates (e.g. "12 Mar")
            try {
              const d = new Date(t.day);
              return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' });
            } catch { return t.day; }
          }),
          datasets,
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: { mode: 'index', intersect: false },
          plugins: {
            legend: {
              display: true,
              position: 'bottom',
              labels: { boxWidth: 12, font: { size: 11 }, padding: 20 },
            },
            tooltip: {
              callbacks: {
                title: (items) => items[0]?.label || '',
              },
            },
          },
          scales: {
            x: {
              grid: { display: false },
              ticks: { font: { size: 11 }, maxTicksLimit: 7 },
            },
            yScans: {
              type: 'linear',
              position: 'left',
              beginAtZero: true,
              grid: { color: this.darkMode ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.04)' },
              ticks: { precision: 0, font: { size: 11 }, color: '#4f46e5' },
              title: { display: true, text: 'Scans', font: { size: 10 }, color: '#4f46e5' },
            },
            yFindings: {
              type: 'linear',
              position: 'right',
              beginAtZero: true,
              grid: { drawOnChartArea: false },
              ticks: { precision: 0, font: { size: 11 }, color: '#ef4444' },
              title: { display: true, text: 'Findings', font: { size: 10 }, color: '#ef4444' },
            },
          },
        },
      });
    },

    // ── Scans ─────────────────────────────────────────────────────────────────

    async loadScans(reset = false) {
      if (reset) {
        this.scansPage = 1;
        this.scansCursor = null;
        this.scansCursorStack = [];
      }
      this.scansLoading = true;
      try {
        const params = new URLSearchParams({
          per_page: 20,
          sort_by: this.scansSort.by,
          sort_order: this.scansSort.order,
        });
        if (this.scansFilter.target) params.set('target', this.scansFilter.target);
        if (this.scansFilter.status) params.set('status', this.scansFilter.status);
        if (this.scansFilter.policy) params.set('policy', this.scansFilter.policy);
        if (this.scansCursor) params.set('cursor', this.scansCursor);
        const result = await apiFetch(`/api/scans/paginated?${params}`);
        this.scans = result.items || [];
        const scanPag = result.pagination || {};
        this.scansTotal = scanPag.count || this.scans.length;
        this.scansCursor = scanPag.next_cursor || null;
      } catch (e) {
        this.showToast('Failed to load scans: ' + e.message, 'error');
      } finally {
        this.scansLoading = false;
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
      this.scansCursorStack.push(this.scansCursor);
      this.scansPage++;
      await this.loadScans();
    },

    async prevScansPage() {
      if (this.scansPage <= 1) return;
      this.scansPage--;
      this.scansCursor = this.scansCursorStack.pop() || null;
      await this.loadScans();
    },

    resetScansFilter() {
      this.scansFilter = { target: '', status: '', policy: '' };
      this.loadScans(true);
    },

    openScanDetail(scan) {
      this.selectedScan = scan;
    },

    viewScanFindings(scan) {
      this.selectedScan = null;
      // Reset all filters and set scan_id as dedicated filter
      this.findingsFilter = { search: '', severity: '', tool: '', target: '', status: '', scan_id: scan.id };
      this.navigate('findings');
    },

    // ── Findings ──────────────────────────────────────────────────────────────

    async loadFindings(reset = false) {
      if (reset) {
        this.findingsPage = 1;
        this.findingsCursor = null;
        this.findingsCursorStack = [];
        this.selectedFindings = [];
      }
      this.findingsLoading = true;
      try {
        const params = new URLSearchParams({ per_page: 50 });
        if (this.findingsFilter.search) params.set('search', this.findingsFilter.search);
        if (this.findingsFilter.severity) params.set('severity', this.findingsFilter.severity);
        if (this.findingsFilter.tool) params.set('tool', this.findingsFilter.tool);
        if (this.findingsCursor) params.set('cursor', this.findingsCursor);

        // Always use cursor-based pagination endpoint (supports status filter via LEFT JOIN)
        if (this.findingsFilter.status) params.set('status', this.findingsFilter.status);
        if (this.findingsFilter.target) params.set('target', this.findingsFilter.target);
        if (this.findingsFilter.scan_id) params.set('scan_id', this.findingsFilter.scan_id);
        const result = await apiFetch(`/api/findings/paginated?${params}`);

        this.findings = result.items || [];
        const pag = result.pagination || {};
        this.findingsTotal = pag.count || this.findings.length;
        this.findingsCursor = pag.next_cursor || null;
      } catch (e) {
        this.showToast('Failed to load findings: ' + e.message, 'error');
      } finally {
        this.findingsLoading = false;
      }
    },

    async nextFindingsPage() {
      if (!this.findingsCursor) return;
      this.findingsCursorStack.push(this.findingsCursor);
      this.findingsPage++;
      await this.loadFindings();
    },

    async prevFindingsPage() {
      if (this.findingsPage <= 1) return;
      this.findingsPage--;
      this.findingsCursor = this.findingsCursorStack.pop() || null;
      await this.loadFindings();
    },

    resetFindingsFilter() {
      this.findingsFilter = { search: '', severity: '', tool: '', target: '', status: '', scan_id: '' };
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
        await fetch(`/api/findings/${this.selectedFinding.id}/status`, { method: 'PATCH', body: fd });
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
        await fetch(`/api/findings/${this.selectedFinding.id}/status`, { method: 'PATCH', body: fd });
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
        await fetch(`/api/findings/${this.selectedFinding.id}/status`, { method: 'PATCH', body: fd });
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
        await fetch(`/api/findings/${this.selectedFinding.id}/assign`, { method: 'POST', body: fd });
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
        await fetch(`/api/findings/${this.selectedFinding.id}/comment`, { method: 'POST', body: fd });
        this.findingComments = await apiFetch(`/api/findings/${this.selectedFinding.id}/comments`);
        this.newComment = '';
        this.showToast('Comment added');
      } catch (e) {
        this.showToast('Error: ' + e.message, 'error');
      }
    },

    // ── Analytics ─────────────────────────────────────────────────────────────

    async loadAnalytics() {
      this.loading = true;
      try {
        const [riskDist, compliance, trends, targetRisk, toolEffectiveness] = await Promise.all([
          apiFetch('/api/analytics/risk-distribution'),
          apiFetch('/api/analytics/compliance'),
          apiFetch(`/api/analytics/trends?days=${this.analyticsDays}`),
          apiFetch('/api/analytics/target-risk'),
          apiFetch('/api/analytics/tool-effectiveness'),
        ]);
        this.analyticsData = { riskDistribution: riskDist, compliance, trends, targetRisk, toolEffectiveness };
        if (this.chartsAvailable) {
          await nextTick();
          this.buildRiskChart();
          this.buildOwaspChart();
          this.buildAnalyticsTrendChart();
          this.buildToolEffChart();
        }
      } catch (e) {
        this.showToast('Failed to load analytics: ' + e.message, 'error');
      } finally {
        this.loading = false;
      }
    },

    buildToolEffChart() {
      const canvas = this.$refs.toolEffChart;
      if (!canvas || !this.analyticsData.toolEffectiveness) return;
      if (this.charts.toolEff) this.charts.toolEff.destroy();
      const tools = this.analyticsData.toolEffectiveness.slice(0, 8);
      this.charts.toolEff = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: {
          labels: tools.map(t => t.tool),
          datasets: [
            { label: 'Critical', data: tools.map(t => t.critical_count || 0), backgroundColor: '#dc2626', borderRadius: 4 },
            { label: 'High', data: tools.map(t => t.high_count || 0), backgroundColor: '#f97316', borderRadius: 4 },
            { label: 'Medium', data: tools.map(t => t.medium_count || 0), backgroundColor: '#f59e0b', borderRadius: 4 },
          ],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 11 } } } },
          scales: {
            x: { stacked: true, grid: { display: false } },
            y: { stacked: true, beginAtZero: true, grid: { color: '#f3f4f6' } },
          },
        },
      });
    },

    buildRiskChart() {
      const canvas = this.$refs.riskChart;
      if (!canvas || !this.analyticsData.riskDistribution) return;
      if (this.charts.risk) this.charts.risk.destroy();
      const dist = this.analyticsData.riskDistribution.distribution;
      this.charts.risk = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: {
          labels: Object.keys(dist),
          datasets: [{
            label: 'Findings', data: Object.values(dist),
            backgroundColor: ['#10b981', '#f59e0b', '#f97316', '#dc2626'],
            borderRadius: 6,
          }],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: { y: { beginAtZero: true, grid: { color: '#f3f4f6' } }, x: { grid: { display: false } } },
        },
      });
    },

    buildOwaspChart() {
      const canvas = this.$refs.owaspChart;
      if (!canvas || !this.analyticsData.compliance) return;
      if (this.charts.owasp) this.charts.owasp.destroy();
      const owasp = this.analyticsData.compliance.owasp_top_10.slice(0, 6);
      this.charts.owasp = new Chart(canvas.getContext('2d'), {
        type: 'pie',
        data: {
          labels: owasp.map(o => o.category.split(' - ')[0]),
          datasets: [{
            data: owasp.map(o => o.count),
            backgroundColor: ['#ef4444', '#f97316', '#f59e0b', '#14b8a6', '#3b82f6', '#8b5cf6'],
            borderWidth: 2, borderColor: '#fff',
          }],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { position: 'bottom', labels: { boxWidth: 12, font: { size: 11 } } } },
        },
      });
    },

    buildAnalyticsTrendChart() {
      const canvas = this.$refs.analyticsTrendChart;
      if (!canvas || !this.analyticsData.trends) return;
      if (this.charts.analyticsTrend) this.charts.analyticsTrend.destroy();
      const trendData = this.analyticsData.trends.trend;
      this.charts.analyticsTrend = new Chart(canvas.getContext('2d'), {
        type: 'line',
        data: {
          labels: trendData.map(t => t.date),
          datasets: [
            {
              label: 'Avg Risk', data: trendData.map(t => t.average_risk),
              borderColor: '#4f46e5', backgroundColor: 'rgba(79,70,229,0.08)',
              tension: 0.3, fill: true,
            },
            {
              label: 'Max Risk', data: trendData.map(t => t.max_risk),
              borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.04)',
              tension: 0.3, fill: false, borderDash: [4, 4],
            },
          ],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { position: 'bottom' } },
          scales: {
            y: { beginAtZero: true, max: 100, grid: { color: '#f3f4f6' } },
            x: { grid: { display: false } },
          },
        },
      });
    },

    owaspBarWidth(count) {
      if (!this.analyticsData.compliance) return 0;
      const max = Math.max(...this.analyticsData.compliance.owasp_top_10.map(o => o.count), 1);
      return Math.round((count / max) * 100);
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
        // Normalizza la risposta API: l'API restituisce { scan_1, scan_2, diff: { new_count, ... } }
        // Il template si aspetta { summary: { new, resolved, unchanged }, new_findings, resolved_findings }
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
        const triggerTime = new Date().toISOString();
        await apiFetch('/api/scan/trigger', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: formData.toString(),
        });
        // Close modal and reset form on success
        this.showScanModal = false;
        this.newScanForm = { name: '', target: '', target_type: 'local' };
        this.showToast('Scan started successfully');
        await this.loadScans(true);
        this.startScanPolling(triggerTime);
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
        const res = await fetch('/api/keys', { method: 'POST', body: fd });
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
        await fetch('/api/webhooks', { method: 'POST', body: fd });
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
        await fetch(`/api/webhooks/${id}`, { method: 'PATCH', body: fd });
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

    // ── Export ────────────────────────────────────────────────────────────────

    async exportScanFindings(scanId, format) {
      try {
        const params = new URLSearchParams({ format, scan_id: scanId, limit: 1000 });
        const res = await fetch(`/api/export/findings?${params}`);
        if (!res.ok) throw new Error('Export failed');
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `scan_${scanId.substring(0, 8)}_${Date.now()}.${format}`;
        document.body.appendChild(a);
        a.click();
        URL.revokeObjectURL(url);
        document.body.removeChild(a);
        this.showToast(`Export ${format.toUpperCase()} started`);
      } catch (e) {
        this.showToast('Export failed: ' + e.message, 'error');
      }
    },

    async exportFindings(format, includeAnalytics = false) {
      try {
        const params = new URLSearchParams({ format, limit: 1000 });
        if (includeAnalytics) params.set('include_analytics', true);
        const res = await fetch(`/api/export/findings?${params}`);
        if (!res.ok) throw new Error('Export failed');
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `findings_${Date.now()}.${format}`;
        document.body.appendChild(a);
        a.click();
        URL.revokeObjectURL(url);
        document.body.removeChild(a);
        this.showToast(`Export ${format.toUpperCase()} started`);
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

    copyToClipboard(text) {
      navigator.clipboard.writeText(text).then(() => this.showToast('Copied to clipboard'));
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
      this.applyChartDefaults();
      // Rebuild visible charts so legend/tick colors update immediately
      if (this.currentPage === 'dashboard') this.initDashboardCharts();
      else if (this.currentPage === 'analytics') this.loadAnalytics();
    },

  },
}).mount('#app');
