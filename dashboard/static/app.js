/**
 * Security Scanning Platform — SPA Vue.js
 * Versione 2.0 — Architettura SPA completa con paginazione, triage e analytics
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
    return d.toLocaleString('it-IT', {
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
      newScanForm: { name: '', target: '', target_type: 'local', async_mode: true },

      // ── Finding modal tabs
      findingModalTab: 'info',
      findingStatusNotes: '',
      showAcceptRiskForm: false,
      acceptRiskJustification: '',
      acceptRiskExpiry: '',

      // ── Dark mode
      darkMode: false,

      // ── UI overlays
      showShortcutsHelp: false,
      showFindingModal: false,
    };
  },

  computed: {
    pageTitle() {
      const titles = {
        dashboard: 'Dashboard',
        scans: 'Scansioni',
        findings: 'Findings',
        analytics: 'Analytics',
        compare: 'Confronta Scansioni',
        settings: 'Settings',
      };
      return titles[this.currentPage] || '';
    },
    pageSubtitle() {
      const subs = {
        dashboard: 'Panoramica della postura di sicurezza',
        scans: 'Storico delle esecuzioni di scansione',
        findings: 'Vulnerabilità rilevate e gestione del ciclo di vita',
        analytics: 'Risk scoring, compliance e trend',
        compare: 'Analisi differenziale tra due scansioni',
        settings: 'Gestione API keys, webhooks e configurazione',
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

    // ── Keyboard shortcuts (GitHub-style G+key navigation)
    this._gPressed = false;
    this._gTimer = null;
    this._keyHandler = (e) => {
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) return;
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      if (e.key === '?') { this.showShortcutsHelp = !this.showShortcutsHelp; return; }
      if (e.key === 'Escape') {
        this.showShortcutsHelp = false;
        this.showFindingModal = false;
        this.showScanModal = false;
        return;
      }
      if ((e.key === 'n' || e.key === 'N') && this.currentPage === 'scans') {
        this.showScanModal = true; return;
      }
      if (e.key === 'r' || e.key === 'R') { this.refreshCurrentPage(); return; }
      if (this._gPressed) {
        this._gPressed = false;
        clearTimeout(this._gTimer);
        const navMap = { d: 'dashboard', s: 'scans', f: 'findings', a: 'analytics', x: 'settings', c: 'compare' };
        const target = navMap[e.key.toLowerCase()];
        if (target) this.navigate(target);
        return;
      }
      if (e.key === 'g') {
        this._gPressed = true;
        this._gTimer = setTimeout(() => { this._gPressed = false; }, 1000);
      }
    };
    document.addEventListener('keydown', this._keyHandler);

    await this.initDashboardCharts();
    if (initialPage !== 'dashboard') await this.navigate(initialPage);
    this.startAutoRefresh();
  },
  beforeUnmount() {
    if (this.refreshInterval) clearInterval(this.refreshInterval);
    Object.values(this.charts).forEach(c => c && c.destroy());
    if (this._keyHandler) document.removeEventListener('keydown', this._keyHandler);
  },

  methods: {
    // ── Navigation ────────────────────────────────────────────────────────────

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
      await this.navigate(this.currentPage);
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

    // ── Dashboard Charts ──────────────────────────────────────────────────────

    async initDashboardCharts() {
      await nextTick();
      this.buildSeverityChart();
      this.buildToolChart();
      this.buildTrendChart();
      this.buildRemediationChart();
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
            data: [0, 0, 0, 0, 0, 0], // aggiornato async
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
      // Carica i dati reali dall'API
      const statusKeys = ['new', 'acknowledged', 'in_progress', 'resolved', 'false_positive', 'risk_accepted'];
      Promise.all(statusKeys.map(s =>
        apiFetch(`/api/findings/paginated?status=${s}&page_size=1`)
          .then(r => r.pagination ? r.pagination.total : 0)
          .catch(() => 0)
      )).then(counts => {
        if (this.charts.remediation) {
          this.charts.remediation.data.datasets[0].data = counts;
          this.charts.remediation.update();
        }
      });
    },

    buildSeverityChart() {
      const canvas = this.$refs.severityChart;
      if (!canvas) return;
      if (this.charts.severity) this.charts.severity.destroy();
      const data = this.severityBreakdown;
      // Ordine fisso per leggibilità: dal più grave al meno grave
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
      this.charts.trend = new Chart(canvas.getContext('2d'), {
        type: 'line',
        data: {
          labels: trendData.map(t => t.day),
          datasets: [
            {
              label: 'Scansioni', data: trendData.map(t => t.scans),
              borderColor: '#4f46e5', backgroundColor: 'rgba(79,70,229,0.08)',
              tension: 0.3, fill: true, pointRadius: 4,
            },
            {
              label: 'Findings', data: trendData.map(t => t.findings || 0),
              borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.05)',
              tension: 0.3, fill: true, pointRadius: 4,
            },
          ],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { position: 'bottom' } },
          scales: { y: { beginAtZero: true, grid: { color: '#f3f4f6' } }, x: { grid: { display: false } } },
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
        if (this.scansCursor) params.set('cursor', this.scansCursor);
        const result = await apiFetch(`/api/scans/paginated?${params}`);
        this.scans = result.items || [];
        const scanPag = result.pagination || {};
        this.scansTotal = scanPag.count || this.scans.length;
        this.scansCursor = scanPag.next_cursor || null;
      } catch (e) {
        this.showToast('Errore nel caricamento delle scansioni: ' + e.message, 'error');
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
        this.showToast('Errore nel caricamento dei findings: ' + e.message, 'error');
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
        this.showToast(`Stato aggiornato per ${this.selectedFindings.length} findings`);
        this.selectedFindings = [];
        this.bulkStatus = '';
        await this.loadFindings(true);
      } catch (e) {
        this.showToast('Errore aggiornamento bulk: ' + e.message, 'error');
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
        this.showToast('Stato aggiornato');
        await this.loadFindings(true);
      } catch (e) {
        this.showToast('Errore: ' + e.message, 'error');
      }
    },

    async markFalsePositive() {
      if (!this.selectedFinding) return;
      try {
        const fd = new FormData();
        fd.append('status', 'false_positive');
        await fetch(`/api/findings/${this.selectedFinding.id}/status`, { method: 'PATCH', body: fd });
        this.findingState.status = 'false_positive';
        this.showToast('Finding segnato come false positive');
        await this.loadFindings(true);
      } catch (e) {
        this.showToast('Errore: ' + e.message, 'error');
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
        this.showToast('Rischio accettato');
        await this.loadFindings(true);
      } catch (e) {
        this.showToast('Errore: ' + e.message, 'error');
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
        this.showToast('Finding assegnato');
      } catch (e) {
        this.showToast('Errore: ' + e.message, 'error');
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
        this.showToast('Commento aggiunto');
      } catch (e) {
        this.showToast('Errore: ' + e.message, 'error');
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
        await nextTick();
        this.buildRiskChart();
        this.buildOwaspChart();
        this.buildAnalyticsTrendChart();
        this.buildToolEffChart();
      } catch (e) {
        this.showToast('Errore caricamento analytics: ' + e.message, 'error');
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
        this.showToast('Errore caricamento lista scansioni: ' + e.message, 'error');
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
        this.compareResult = result;
      } catch (e) {
        this.showToast('Errore comparazione: ' + e.message, 'error');
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
        formData.append('async_mode', String(this.newScanForm.async_mode));
        await apiFetch('/api/scan/trigger', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: formData.toString(),
        });
        // Close modal and reset form on success
        this.showScanModal = false;
        this.newScanForm = { name: '', target: '', target_type: 'local', async_mode: true };
        this.showToast('Scansione avviata con successo');
        await this.loadScans(true);
      } catch (e) {
        // Keep modal open on error so user can fix the input
        this.showToast('Errore avvio scansione: ' + e.message, 'error');
      } finally {
        this.scanTriggering = false;
      }
    },

    // ── Notification Preferences ──────────────────────────────────────────────

    async loadNotificationPrefs() {
      try {
        const resp = await apiFetch('/api/notifications/preferences').catch(() => null);
        if (resp && resp.preferences) {
          this.notifPrefs = { ...this.notifPrefs, ...resp.preferences };
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
        this.showToast('Preferenze salvate');
      } catch (e) {
        this.showToast('Errore salvataggio preferenze: ' + e.message, 'error');
      }
    },

    // ── Settings ──────────────────────────────────────────────────────────────

    async loadApiKeys() {
      try {
        this.apiKeys = await apiFetch('/api/keys');
      } catch (e) {
        this.showToast('Errore caricamento API keys: ' + e.message, 'error');
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
        this.showToast('API key creata');
      } catch (e) {
        this.showToast('Errore creazione key: ' + e.message, 'error');
      }
    },

    async revokeApiKey(prefix) {
      if (!confirm(`Revocare la chiave ${prefix}?`)) return;
      try {
        await apiFetch(`/api/keys/${prefix}`, { method: 'DELETE' });
        await this.loadApiKeys();
        this.showToast('API key revocata');
      } catch (e) {
        this.showToast('Errore revoca: ' + e.message, 'error');
      }
    },

    async loadWebhooks() {
      try {
        this.webhooks = await apiFetch('/api/webhooks');
      } catch (e) {
        this.showToast('Errore caricamento webhooks: ' + e.message, 'error');
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
        this.showToast('Webhook creato');
      } catch (e) {
        this.showToast('Errore creazione webhook: ' + e.message, 'error');
      }
    },

    async toggleWebhook(id, isActive) {
      try {
        const fd = new FormData();
        fd.append('is_active', isActive);
        await fetch(`/api/webhooks/${id}`, { method: 'PATCH', body: fd });
        await this.loadWebhooks();
      } catch (e) {
        this.showToast('Errore toggle webhook: ' + e.message, 'error');
      }
    },

    async deleteWebhook(id) {
      if (!confirm('Eliminare questo webhook?')) return;
      try {
        await apiFetch(`/api/webhooks/${id}`, { method: 'DELETE' });
        await this.loadWebhooks();
        this.showToast('Webhook eliminato');
      } catch (e) {
        this.showToast('Errore eliminazione: ' + e.message, 'error');
      }
    },

    // ── Export ────────────────────────────────────────────────────────────────

    async exportFindings(format, includeAnalytics = false) {
      try {
        const params = new URLSearchParams({ format, limit: 1000 });
        if (includeAnalytics) params.set('include_analytics', true);
        const res = await fetch(`/api/export/findings?${params}`);
        if (!res.ok) throw new Error('Export fallito');
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `findings_${Date.now()}.${format}`;
        document.body.appendChild(a);
        a.click();
        URL.revokeObjectURL(url);
        document.body.removeChild(a);
        this.showToast(`Export ${format.toUpperCase()} avviato`);
      } catch (e) {
        this.showToast('Errore export: ' + e.message, 'error');
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

    policyBadgeClass(policy) {
      const map = { PASS: 'badge-success', BLOCK: 'badge-danger', UNKNOWN: 'badge-neutral' };
      return map[policy] || 'badge-neutral';
    },

    copyToClipboard(text) {
      navigator.clipboard.writeText(text).then(() => this.showToast('Copiato negli appunti'));
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
    },

    // ── Export SARIF ────────────────────────────────────────────────────────────
    async exportSarif() {
      await this.exportFindings('sarif');
    },
  },
}).mount('#app');
