"""
Prometheus Metrics Exporter - Export metrics for Prometheus monitoring.

Metrics:
- Findings count by severity
- Scan execution times
- Tool effectiveness
- Alert generation rates
- System performance
"""

from prometheus_client import Counter, Gauge, Histogram, CollectorRegistry
import time


class MetricsCollector:
    """Collect metrics for prometheus."""

    def __init__(self):
        self.registry = CollectorRegistry()

        # Counters
        self.findings_total = Counter(
            "security_findings_total",
            "Total findings discovered",
            ["severity", "tool"],
            registry=self.registry,
        )

        self.scans_total = Counter(
            "security_scans_total",
            "Total scans executed",
            ["target_type", "status"],
            registry=self.registry,
        )

        # Gauges
        self.findings_current = Gauge(
            "security_findings_current",
            "Current active findings",
            ["severity"],
            registry=self.registry,
        )

        self.scan_queue_size = Gauge(
            "security_scan_queue_size",
            "ScanQueue size",
            registry=self.registry,
        )

        # Histograms
        self.scan_duration = Histogram(
            "security_scan_duration_seconds",
            "Scan execution duration",
            ["tool"],
            registry=self.registry,
        )

        self.findings_per_scan = Histogram(
            "security_findings_per_scan",
            "Findings count per scan",
            ["tool"],
            registry=self.registry,
        )

    def record_finding(self, severity: str, tool: str):
        """Record a finding."""
        self.findings_total.labels(severity=severity, tool=tool).inc()

    def record_scan(self, target_type: str, status: str):
        """Record a scan execution."""
        self.scans_total.labels(target_type=target_type, status=status).inc()

    def set_findings_count(self, severity: str, count: int):
        """Set current findings count."""
        self.findings_current.labels(severity=severity).set(count)

    def set_queue_size(self, size: int):
        """Set scan queue size."""
        self.scan_queue_size.set(size)

    def record_scan_duration(self, tool: str, duration_seconds: float):
        """Record scan duration."""
        self.scan_duration.labels(tool=tool).observe(duration_seconds)

    def record_findings_count(self, tool: str, count: int):
        """Record findings count in scan."""
        self.findings_per_scan.labels(tool=tool).observe(count)

    def generate_text(self) -> str:
        """Generate prometheus text format metrics."""
        from prometheus_client.openmetrics.exposition import generate_latest

        return generate_latest(self.registry).decode("utf-8")


# Global metrics instance
_metrics = MetricsCollector()


def get_metrics() -> MetricsCollector:
    """Get global metrics instance."""
    return _metrics
