/**
 * Vue.js Dashboard for Security Scanning Platform
 * Features: Chart.js integration, analytics, auto-refresh
 */

const { createApp } = Vue;

createApp({
    data() {
        return {
            kpis: window.dashboardData?.kpis || {},
            severityBreakdown: window.dashboardData?.severityBreakdown || {},
            toolBreakdown: window.dashboardData?.toolBreakdown || {},
            trend: window.dashboardData?.trend || [],
            targetBreakdown: window.dashboardData?.targetBreakdown || {},
            
            // Analytics data
            analytics: {
                riskDistribution: null,
                compliance: null,
                trends: null,
                targetRisk: null,
                toolEffectiveness: null,
            },
            
            // UI state
            showAnalytics: false,
            autoRefresh: true,
            refreshCountdown: 30,
            
            // Charts
            charts: {},
        };
    },
    
    async mounted() {
        // Initialize charts
        this.$nextTick(() => {
            this.createSeverityChart();
            this.createToolChart();
        });
        
        // Load analytics data
        await this.loadAnalytics();
        
        // Start auto-refresh
        this.startAutoRefresh();
    },
    
    methods: {
        // Chart creation methods
        createSeverityChart() {
            if (!this.$refs.severityChart) return;
            
            const ctx = this.$refs.severityChart.getContext('2d');
            const data = this.severityBreakdown;
            
            this.charts.severity = new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: Object.keys(data),
                    datasets: [{
                        data: Object.values(data),
                        backgroundColor: [
                            '#dc2626', // CRITICAL
                            '#f97316', // HIGH
                            '#f59e0b', // MEDIUM
                            '#3b82f6', // LOW
                            '#6b7280', // INFO
                        ],
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                        }
                    }
                }
            });
        },
        
        createToolChart() {
            if (!this.$refs.toolChart) return;
            
            const ctx = this.$refs.toolChart.getContext('2d');
            const data = this.toolBreakdown;
            const labels = Object.keys(data).slice(0, 10);
            const values = Object.values(data).slice(0, 10);
            
            this.charts.tool = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Findings',
                        data: values,
                        backgroundColor: '#3b82f6',
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        y: { beginAtZero: true }
                    }
                }
            });
        },
        
        createRiskChart() {
            if (!this.$refs.riskChart || !this.analytics.riskDistribution) return;
            
            const ctx = this.$refs.riskChart.getContext('2d');
            const dist = this.analytics.riskDistribution.distribution;
            
            this.charts.risk = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: Object.keys(dist),
                    datasets: [{
                        label: 'Findings Count',
                        data: Object.values(dist),
                        backgroundColor: [
                            '#10b981',
                            '#f59e0b',
                            '#f97316',
                            '#dc2626',
                        ],
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false },
                        title: {
                            display: true,
                            text: 'Risk Score Distribution'
                        }
                    },
                    scales: {
                        y: { beginAtZero: true }
                    }
                }
            });
        },
        
        createOwaspChart() {
            if (!this.$refs.owaspChart || !this.analytics.compliance) return;
            
            const ctx = this.$refs.owaspChart.getContext('2d');
            const owasp = this.analytics.compliance.owasp_top_10.slice(0, 5);
            
            this.charts.owasp = new Chart(ctx, {
                type: 'pie',
                data: {
                    labels: owasp.map(o => o.category.split(' - ')[0]),
                    datasets: [{
                        data: owasp.map(o => o.count),
                        backgroundColor: [
                            '#ef4444',
                            '#f97316',
                            '#f59e0b',
                            '#14b8a6',
                            '#3b82f6',
                        ],
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                boxWidth: 12,
                                font: { size: 10 }
                            }
                        }
                    }
                }
            });
        },
        
        createTrendChart() {
            if (!this.$refs.trendChart || !this.analytics.trends) return;
            
            const ctx = this.$refs.trendChart.getContext('2d');
            const trendData = this.analytics.trends.trend.slice(-30);
            
            this.charts.trend = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: trendData.map(t => t.date),
                    datasets: [
                        {
                            label: 'Avg Risk',
                            data: trendData.map(t => t.average_risk),
                            borderColor: '#3b82f6',
                            backgroundColor: 'rgba(59, 130, 246, 0.1)',
                            tension: 0.3,
                        },
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: true }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            max: 100
                        }
                    }
                }
            });
        },
        
        // Analytics methods
        async loadAnalytics() {
            try {
                const [riskDist, compliance, trends, targetRisk, toolEffectiveness] = await Promise.all([
                    fetch('/api/analytics/risk-distribution').then(r => r.json()),
                    fetch('/api/analytics/compliance').then(r => r.json()),
                    fetch('/api/analytics/trends?days=30').then(r => r.json()),
                    fetch('/api/analytics/target-risk').then(r => r.json()),
                    fetch('/api/analytics/tool-effectiveness').then(r => r.json()),
                ]);
                
                this.analytics.riskDistribution = riskDist;
                this.analytics.compliance = compliance;
                this.analytics.trends = trends;
                this.analytics.targetRisk = targetRisk;
                this.analytics.toolEffectiveness = toolEffectiveness;
                
                // Create analytics charts if panel is visible
                if (this.showAnalytics) {
                    this.$nextTick(() => {
                        this.createRiskChart();
                        this.createOwaspChart();
                        this.createTrendChart();
                    });
                }
            } catch (error) {
                console.error('Error loading analytics:', error);
            }
        },
        
        // Export methods
        async exportReport(format, includeAnalytics = false) {
            try {
                const params = new URLSearchParams({
                    format: format,
                    limit: 1000,
                    include_analytics: includeAnalytics
                });
                
                const response = await fetch(`/api/export/findings?${params}`);
                
                if (!response.ok) {
                    throw new Error('Export failed');
                }
                
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `findings_${Date.now()}.${format}`;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
                
            } catch (error) {
                console.error('Export error:', error);
                alert('Errore durante l\'export');
            }
        },
        
        // Utility methods
        getRiskClass(risk) {
            if (risk >= 75) return 'risk-critical';
            if (risk >= 50) return 'risk-high';
            if (risk >= 25) return 'risk-medium';
            return 'risk-low';
        },
        
        // Auto-refresh
        startAutoRefresh() {
            setInterval(() => {
                if (this.autoRefresh && this.refreshCountdown > 0) {
                    this.refreshCountdown--;
                    
                    if (this.refreshCountdown === 0) {
                        this.refreshData();
                        this.refreshCountdown = 30;
                    }
                }
            }, 1000);
        },
        
        async refreshData() {
            try {
                const response = await fetch(window.location.href);
                const html = await response.text();
                
                // Extract updated data from response
                const parser = new DOMParser();
                const doc = parser.parseFromString(html, 'text/html');
                const scriptTag = doc.querySelector('script:not([src])');
                
                if (scriptTag) {
                    eval(scriptTag.textContent);
                    
                    // Update data
                    this.kpis = window.dashboardData?.kpis || this.kpis;
                    this.severityBreakdown = window.dashboardData?.severityBreakdown || this.severityBreakdown;
                    this.toolBreakdown = window.dashboardData?.toolBreakdown || this.toolBreakdown;
                    
                    // Update charts
                    if (this.charts.severity) {
                        this.charts.severity.data.datasets[0].data = Object.values(this.severityBreakdown);
                        this.charts.severity.update();
                    }
                    
                    if (this.charts.tool) {
                        this.charts.tool.data.labels = Object.keys(this.toolBreakdown).slice(0, 10);
                        this.charts.tool.data.datasets[0].data = Object.values(this.toolBreakdown).slice(0, 10);
                        this.charts.tool.update();
                    }
                }
            } catch (error) {
                console.error('Refresh error:', error);
            }
        },
    },
    
    watch: {
        showAnalytics(newVal) {
            if (newVal) {
                this.$nextTick(() => {
                    this.createRiskChart();
                    this.createOwaspChart();
                    this.createTrendChart();
                });
            }
        }
    },
    
    beforeUnmount() {
        // Cleanup charts
        Object.values(this.charts).forEach(chart => {
            if (chart) chart.destroy();
        });
    }
}).mount('#app');
