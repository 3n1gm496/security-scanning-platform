from __future__ import annotations

import sys
from pathlib import Path

root = Path(__file__).parent.parent
sys.path.insert(0, str(root))

import db_adapter


def test_sqlite_connect_sets_busy_timeout(tmp_path):
    db_path = tmp_path / "runtime.sqlite3"
    conn = db_adapter._sqlite_connect(str(db_path))
    try:
        timeout_ms = conn.execute("PRAGMA busy_timeout").fetchone()[0]
    finally:
        conn.close()

    assert timeout_ms == 5000
