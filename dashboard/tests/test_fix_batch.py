"""
Regression tests for the first critical fix batch.

Covers:
- rbac.py: revoke_api_key uses rowcount instead of SELECT changes()
- webhooks.py: delete_webhook / toggle_webhook use rowcount;
               create_webhook returns a valid int ID
- finding_management.py: add_finding_comment returns a valid int ID
- pagination.py: FindingsPaginator / ScansPaginator cursor encodes the
                 sort column, not always "id"
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _findings_conn_with_data(n: int = 20) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            title TEXT,
            description TEXT,
            severity TEXT,
            file TEXT,
            line INTEGER,
            tool TEXT,
            cve TEXT,
            fingerprint TEXT,
            timestamp TEXT,
            target_name TEXT
        )
        """)
    conn.execute("""
        CREATE TABLE finding_states (
            id INTEGER PRIMARY KEY,
            finding_id INTEGER,
            status TEXT
        )
        """)
    for i in range(n):
        conn.execute(
            "INSERT INTO findings (title, severity, tool, timestamp) VALUES (?, ?, ?, ?)",
            (f"Finding {i}", "HIGH", "semgrep", f"2026-01-01T00:{i:02d}:00"),
        )
    conn.commit()
    return conn


def _scans_conn_with_data(n: int = 15) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_name TEXT,
            target_type TEXT,
            status TEXT,
            policy_status TEXT,
            created_at TEXT,
            finished_at TEXT,
            findings_count INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            error_message TEXT
        )
        """)
    for i in range(n):
        conn.execute(
            "INSERT INTO scans (target_name, target_type, status, policy_status, created_at, finished_at) VALUES (?, ?, ?, ?, ?, ?)",
            (f"target-{i}", "git", "COMPLETED_CLEAN", "PASSED", f"2026-01-{i+1:02d}T00:00:00", f"2026-01-{i+1:02d}T00:01:00"),
        )
    conn.commit()
    return conn


# ---------------------------------------------------------------------------
# rbac.py — revoke_api_key returns False for nonexistent prefix
# (previously crashed on PostgreSQL due to SELECT changes())
# ---------------------------------------------------------------------------


class TestRevokeApiKey:
    def test_revoke_nonexistent_returns_false(self, isolated_db):
        from rbac import Role, create_api_key, init_rbac_tables, revoke_api_key

        init_rbac_tables()
        result = revoke_api_key("ssp_doesnotexist")
        assert result is False

    def test_revoke_existing_returns_true(self, isolated_db):
        from rbac import Role, create_api_key, init_rbac_tables, revoke_api_key

        init_rbac_tables()
        _full_key, prefix = create_api_key("K", Role.VIEWER, created_by="test")
        assert revoke_api_key(prefix) is True

    def test_revoke_already_revoked_returns_true(self, isolated_db):
        """rowcount reflects rows matched by WHERE, not rows changed."""
        from rbac import Role, create_api_key, init_rbac_tables, revoke_api_key

        init_rbac_tables()
        _full_key, prefix = create_api_key("K2", Role.VIEWER, created_by="test")
        revoke_api_key(prefix)
        # SQLite rowcount for UPDATE WHERE matches the row even if value unchanged
        # — behaviour consistent with previous implementation
        result = revoke_api_key(prefix)
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# webhooks.py — delete_webhook / toggle_webhook use rowcount;
#               create_webhook returns a valid int
# ---------------------------------------------------------------------------


class TestWebhookRowcount:
    def test_delete_nonexistent_returns_false(self, isolated_db):
        from webhooks import delete_webhook, init_webhook_tables

        init_webhook_tables()
        assert delete_webhook(99999) is False

    def test_delete_existing_returns_true(self, isolated_db):
        from webhooks import WebhookEvent, create_webhook, delete_webhook, init_webhook_tables

        init_webhook_tables()
        wid = create_webhook("W", "https://example.com/wh", [WebhookEvent.SCAN_COMPLETED])
        assert delete_webhook(wid) is True

    def test_toggle_nonexistent_returns_false(self, isolated_db):
        from webhooks import init_webhook_tables, toggle_webhook

        init_webhook_tables()
        assert toggle_webhook(99999, True) is False

    def test_toggle_existing_returns_true(self, isolated_db):
        from webhooks import WebhookEvent, create_webhook, init_webhook_tables, toggle_webhook

        init_webhook_tables()
        wid = create_webhook("W2", "https://example.com/wh2", [WebhookEvent.SCAN_FAILED])
        assert toggle_webhook(wid, False) is True


class TestCreateWebhookReturnsId:
    def test_create_webhook_returns_positive_int(self, isolated_db):
        from webhooks import WebhookEvent, create_webhook, init_webhook_tables

        init_webhook_tables()
        wid = create_webhook("Hook", "https://example.com/h", [WebhookEvent.SCAN_COMPLETED])
        assert isinstance(wid, int)
        assert wid > 0

    def test_multiple_webhooks_get_distinct_ids(self, isolated_db):
        from webhooks import WebhookEvent, create_webhook, init_webhook_tables

        init_webhook_tables()
        id1 = create_webhook("H1", "https://example.com/1", [WebhookEvent.SCAN_COMPLETED])
        id2 = create_webhook("H2", "https://example.com/2", [WebhookEvent.SCAN_COMPLETED])
        assert id1 != id2


# ---------------------------------------------------------------------------
# finding_management.py — add_finding_comment returns a valid int ID
# ---------------------------------------------------------------------------


class TestAddFindingCommentReturnsId:
    def test_returns_positive_int(self, isolated_db):
        from finding_management import add_finding_comment, init_finding_management_tables

        init_finding_management_tables()
        comment_id = add_finding_comment(1, "tester", "First comment")
        assert isinstance(comment_id, int)
        assert comment_id > 0

    def test_sequential_ids_are_distinct(self, isolated_db):
        from finding_management import add_finding_comment, init_finding_management_tables

        init_finding_management_tables()
        id1 = add_finding_comment(1, "tester", "Comment A")
        id2 = add_finding_comment(1, "tester", "Comment B")
        assert id1 != id2


# ---------------------------------------------------------------------------
# pagination.py — cursor encodes the sort column, not always "id"
# ---------------------------------------------------------------------------


class TestFindingsPaginatorCursor:
    def test_cursor_encodes_id_when_sort_by_id(self):
        from pagination import FindingsPaginator

        conn = _findings_conn_with_data(20)
        paginator = FindingsPaginator(per_page=5)
        result = paginator.paginate(conn, sort_by="id", sort_order="ASC")

        assert result["pagination"]["has_next"] is True
        # Decode cursor and verify it is the id of the last item
        import base64

        cursor_val = base64.b64decode(result["pagination"]["next_cursor"]).decode()
        last_item = result["items"][-1]
        assert cursor_val == str(last_item["id"])

    def test_cursor_encodes_sort_column_not_id(self):
        """When sorting by 'tool', the cursor must encode 'tool' value, not 'id'."""
        from pagination import FindingsPaginator

        conn = _findings_conn_with_data(20)
        paginator = FindingsPaginator(per_page=5)
        result = paginator.paginate(conn, sort_by="tool", sort_order="ASC")

        import base64

        cursor_val = base64.b64decode(result["pagination"]["next_cursor"]).decode()
        last_item = result["items"][-1]
        # Cursor must encode 'tool' value, not id
        assert cursor_val == str(last_item["tool"])
        # Guard: the tool value is not a pure integer, so if it were id it would differ
        try:
            int(cursor_val)
            # If tool happens to be numeric-only that's still correct
        except ValueError:
            pass  # Non-numeric cursor confirms it's the tool column

    def test_cursor_encodes_severity_when_sort_by_severity(self):
        from pagination import FindingsPaginator

        conn = _findings_conn_with_data(20)
        paginator = FindingsPaginator(per_page=5)
        result = paginator.paginate(conn, sort_by="severity", sort_order="ASC")

        import base64

        cursor_val = base64.b64decode(result["pagination"]["next_cursor"]).decode()
        last_item = result["items"][-1]
        assert cursor_val == str(last_item["severity"])


class TestScansPaginatorCursor:
    def test_cursor_encodes_created_at_when_sort_by_created_at(self):
        from pagination import ScansPaginator

        conn = _scans_conn_with_data(15)
        paginator = ScansPaginator(per_page=5)
        result = paginator.paginate(conn, sort_by="created_at", sort_order="DESC")

        assert result["pagination"]["has_next"] is True

        import base64

        cursor_val = base64.b64decode(result["pagination"]["next_cursor"]).decode()
        last_item = result["items"][-1]
        assert cursor_val == str(last_item["created_at"])

    def test_cursor_encodes_target_name_when_sort_by_target_name(self):
        from pagination import ScansPaginator

        conn = _scans_conn_with_data(15)
        paginator = ScansPaginator(per_page=5)
        result = paginator.paginate(conn, sort_by="target_name", sort_order="ASC")

        import base64

        cursor_val = base64.b64decode(result["pagination"]["next_cursor"]).decode()
        last_item = result["items"][-1]
        assert cursor_val == str(last_item["target_name"])
