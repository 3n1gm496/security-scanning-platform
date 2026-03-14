"""
Integration test for concurrent SQLite read/write under WAL mode.

Verifies that WAL mode prevents OperationalError when concurrent
readers and writers access the database simultaneously.
"""

import sqlite3
import tempfile
import threading
import time
from pathlib import Path

import pytest


def _init_db(db_path: str):
    """Initialise a test database with WAL mode."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS test_data ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  value TEXT NOT NULL,"
        "  created_at TEXT NOT NULL DEFAULT (datetime('now'))"
        ")"
    )
    conn.commit()
    conn.close()


class TestConcurrentSQLiteWAL:
    """Verify WAL mode allows concurrent readers + writer without errors."""

    def test_concurrent_read_write(self):
        """One writer and multiple readers should not raise OperationalError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "test.db")
            _init_db(db_path)

            errors = []
            write_count = 100
            read_iterations = 200

            def writer():
                try:
                    conn = sqlite3.connect(db_path)
                    conn.execute("PRAGMA journal_mode=WAL")
                    for i in range(write_count):
                        conn.execute(
                            "INSERT INTO test_data (value) VALUES (?)",
                            (f"value_{i}",),
                        )
                        conn.commit()
                    conn.close()
                except Exception as e:
                    errors.append(("writer", e))

            def reader(reader_id):
                try:
                    conn = sqlite3.connect(db_path)
                    conn.execute("PRAGMA journal_mode=WAL")
                    for _ in range(read_iterations):
                        conn.execute("SELECT COUNT(*) FROM test_data").fetchone()
                        conn.execute("SELECT * FROM test_data ORDER BY id DESC LIMIT 10").fetchall()
                    conn.close()
                except Exception as e:
                    errors.append((f"reader_{reader_id}", e))

            # Launch 1 writer + 3 readers concurrently
            threads = [threading.Thread(target=writer)]
            for i in range(3):
                threads.append(threading.Thread(target=reader, args=(i,)))

            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

            assert not errors, f"Concurrent access errors: {errors}"

            # Verify all writes persisted
            conn = sqlite3.connect(db_path)
            count = conn.execute("SELECT COUNT(*) FROM test_data").fetchone()[0]
            conn.close()
            assert count == write_count

    def test_concurrent_writers(self):
        """Multiple concurrent writers under WAL should eventually succeed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = str(Path(tmpdir) / "test_multi_writer.db")
            _init_db(db_path)

            errors = []
            writes_per_thread = 50
            num_writers = 3

            def writer(writer_id):
                try:
                    conn = sqlite3.connect(db_path, timeout=10)
                    conn.execute("PRAGMA journal_mode=WAL")
                    for i in range(writes_per_thread):
                        conn.execute(
                            "INSERT INTO test_data (value) VALUES (?)",
                            (f"writer{writer_id}_val{i}",),
                        )
                        conn.commit()
                    conn.close()
                except Exception as e:
                    errors.append((f"writer_{writer_id}", e))

            threads = [threading.Thread(target=writer, args=(i,)) for i in range(num_writers)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)

            assert not errors, f"Concurrent write errors: {errors}"

            conn = sqlite3.connect(db_path)
            count = conn.execute("SELECT COUNT(*) FROM test_data").fetchone()[0]
            conn.close()
            assert count == writes_per_thread * num_writers
