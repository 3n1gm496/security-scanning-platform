"""Unit tests for prometheus metrics."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from metrics import MetricsCollector


def test_metrics_collector_init():
    """Test metrics collector initialization."""
    collector = MetricsCollector()
    assert collector.registry is not None
    assert collector.findings_total is not None


def test_record_finding():
    """Test recording findings."""
    collector = MetricsCollector()
    collector.record_finding("CRITICAL", "semgrep")
    collector.record_finding("HIGH", "bandit")
    # Just verify no exceptions
    assert True


def test_record_scan():
    """Test recording scans."""
    collector = MetricsCollector()
    collector.record_scan("repository", "completed")
    collector.record_scan("container", "failed")
    assert True


def test_set_findings_count():
    """Test setting findings count gauge."""
    collector = MetricsCollector()
    collector.set_findings_count("CRITICAL", 5)
    collector.set_findings_count("HIGH", 10)
    assert True


def test_scan_duration():
    """Test recording scan duration."""
    collector = MetricsCollector()
    collector.record_scan_duration("semgrep", 15.5)
    collector.record_scan_duration("bandit", 8.2)
    assert True


def test_generate_text():
    """Test generating prometheus text format."""
    collector = MetricsCollector()
    collector.record_finding("CRITICAL", "semgrep")
    text = collector.generate_text()
    assert isinstance(text, str)
    assert "security_findings_total" in text
