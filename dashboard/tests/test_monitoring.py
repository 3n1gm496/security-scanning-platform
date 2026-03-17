"""Unit tests for monitoring metrics refresh behavior."""

import sys
from pathlib import Path

root = Path(__file__).parent.parent
sys.path.insert(0, str(root))

import monitoring as _monitoring
import db as _db


class _FakeRow(dict):
    pass


class _FakeConnection:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, _query):
        class _Cursor:
            def fetchall(self_inner):
                return [_FakeRow(severity="HIGH", cnt=2), _FakeRow(severity="LOW", cnt=1)]

        return _Cursor()


class _FakeGauge:
    def __init__(self):
        self.cleared = False
        self.values = {}

    def clear(self):
        self.cleared = True
        self.values = {}

    def labels(self, **labels):
        severity = labels["severity"]
        gauge = self

        class _Handle:
            def set(self_inner, value):
                gauge.values[severity] = value

        return _Handle()


def test_prometheus_metrics_clears_findings_gauge_before_refresh(monkeypatch):
    fake_gauge = _FakeGauge()
    monkeypatch.setattr(_monitoring, "SSP_FINDINGS_TOTAL", fake_gauge)
    monkeypatch.setattr(_db, "get_connection", lambda _db_path: _FakeConnection())

    response = __import__("asyncio").run(_monitoring.prometheus_metrics(auth=None))

    assert response.media_type == _monitoring.CONTENT_TYPE_LATEST
    assert fake_gauge.cleared is True
    assert fake_gauge.values == {"HIGH": 2, "LOW": 1}


def test_readiness_check_returns_unready_when_database_connection_fails(monkeypatch):
    class _BrokenConnection:
        def __enter__(self):
            raise RuntimeError("db unavailable")

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setattr(_db, "get_connection", lambda _db_path: _BrokenConnection())
    response = _monitoring.Response()

    payload = __import__("asyncio").run(_monitoring.readiness_check(response))

    assert response.status_code == 503
    assert payload.ready is False
    assert payload.checks["database"]["status"] == "error"
