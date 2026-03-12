"""
Advanced Pagination System - Cursor-based pagination for large result sets.

Supports:
- Cursor-based pagination (scales better than offset)
- Sorting by multiple columns
- Filtering with complex conditions
- Efficient database queries
"""

from __future__ import annotations

from typing import Any

from base64 import b64encode, b64decode


class PaginationCursor:
    """Cursor-based pagination handler."""

    def __init__(self, table: str, per_page: int = 50, sort_by: str = "id", sort_order: str = "asc"):
        """Initialize pagination cursor.

        Args:
            table: Database table name
            per_page: Number of items per page
            sort_by: Column to sort by (default: id)
            sort_order: 'asc' or 'desc' (default: asc)
        """
        allowed_tables = {"findings", "scans"}
        self.table = table if table in allowed_tables else "findings"
        self.per_page = min(per_page, 1000)  # Max 1000 per page
        allowed_sort_columns = {
            "id",
            "scan_id",
            "severity",
            "tool",
            "created_at",
            "target_name",
            "target_type",
            "status",
        }
        self.sort_by = sort_by if sort_by in allowed_sort_columns else "id"
        self.sort_order = sort_order.upper() if sort_order.upper() in ["ASC", "DESC"] else "ASC"

    def encode_cursor(self, item: dict[str, Any]) -> str:
        """Encode cursor from item data."""
        cursor_val = str(item.get(self.sort_by))
        return b64encode(cursor_val.encode()).decode()

    def decode_cursor(self, cursor: str) -> str:
        """Decode cursor to value."""
        try:
            return b64decode(cursor.encode()).decode()
        except Exception:
            return ""

    def build_query(
        self,
        filters: dict[str, Any] | None = None,
        cursor: str | None = None,
    ) -> tuple[str, list[Any]]:
        """Build SQL query with cursor pagination.

        Args:
            filters: Filter conditions {'column': value, ...}
            cursor: Pagination cursor from previous request

        Returns:
            (sql_query, params)
        """
        where_clauses = ["1=1"]
        params: list[Any] = []

        # Apply filters — only allow whitelisted column names to prevent SQL injection
        _allowed_filter_columns = {
            "id",
            "scan_id",
            "severity",
            "tool",
            "created_at",
            "target_name",
            "target_type",
            "status",
            "category",
            "fingerprint",
        }
        if filters:
            for col, val in filters.items():
                if val is not None and col in _allowed_filter_columns:
                    where_clauses.append(f"{col} = ?")
                    params.append(val)

        # Apply cursor (keyset pagination)
        if cursor:
            cursor_val = self.decode_cursor(cursor)
            op = ">" if self.sort_order == "ASC" else "<"
            where_clauses.append(f"{self.sort_by} {op} ?")
            params.append(cursor_val)

        where_sql = " AND ".join(where_clauses)

        query = f"""
            SELECT * FROM {self.table}
            WHERE {where_sql}
            ORDER BY {self.sort_by} {self.sort_order}
            LIMIT ?
            """
        params.append(self.per_page + 1)  # Fetch +1 to detect if there's next page

        return query, params

    def paginate(
        self,
        conn: Any,
        filters: dict[str, Any] | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """Get paginated results.

        Args:
            conn: Database connection
            filters: Filter conditions
            cursor: Pagination cursor

        Returns:
            {items, has_next, next_cursor}
        """
        query, params = self.build_query(filters, cursor)

        rows = conn.execute(query, params).fetchall()
        items = [dict(row) for row in rows]

        # Check if there's a next page
        has_next = len(items) > self.per_page
        if has_next:
            items = items[: self.per_page]

        # Generate next cursor
        next_cursor = None
        if has_next and items:
            next_cursor = self.encode_cursor(items[-1])

        return {
            "items": items,
            "has_next": has_next,
            "next_cursor": next_cursor,
            "count": len(items),
        }


class FindingsPaginator:
    """Specialized paginator for security findings."""

    def __init__(self, per_page: int = 50):
        self.per_page = min(per_page, 1000)

    def paginate(
        self,
        conn: Any,
        search: str = "",
        severity_filter: list[str] | None = None,
        tool_filter: list[str] | None = None,
        scan_id: str | None = None,
        status_filter: str | None = None,
        cursor: str | None = None,
        sort_by: str = "id",
        sort_order: str = "ASC",
    ) -> dict[str, Any]:
        """Paginate findings with advanced filtering.

        Args:
            conn: Database connection
            search: Full-text search query
            severity_filter: List of severities to include
            tool_filter: List of tools to include
            scan_id: Optional scan ID filter
            status_filter: Filter by triage status via finding_states JOIN
            cursor: Pagination cursor
            sort_by: Column to sort by
            sort_order: ASC or DESC

        Returns:
            Paginated findings with cursor
        """
        allowed_sort_columns = {"id", "scan_id", "severity", "tool", "timestamp", "line"}
        # Map legacy column aliases to actual schema column names
        _col_alias = {"created_at": "timestamp", "line_number": "line", "file_path": "file", "cve_id": "cve"}
        sort_by = _col_alias.get(sort_by, sort_by)
        safe_sort_by = sort_by if sort_by in allowed_sort_columns else "id"
        safe_sort_order = "ASC" if sort_order.upper() == "ASC" else "DESC"

        where_clauses = ["1=1"]
        params: list[Any] = []

        # Search filter (OR across multiple columns)
        if search:
            search_param = f"%{search}%"
            where_clauses.append("(title LIKE ? OR description LIKE ? OR file LIKE ? OR cve LIKE ?)")
            params.extend([search_param] * 4)

        # Severity filter
        if severity_filter:
            placeholders = ",".join(["?"] * len(severity_filter))
            where_clauses.append(f"severity IN ({placeholders})")
            params.extend(severity_filter)

        # Tool filter
        if tool_filter:
            placeholders = ",".join(["?"] * len(tool_filter))
            where_clauses.append(f"tool IN ({placeholders})")
            params.extend(tool_filter)

        # Scan filter
        if scan_id is not None:
            where_clauses.append("scan_id = ?")
            params.append(scan_id)

        # Status filter: requires LEFT JOIN with finding_states
        use_status_join = status_filter is not None
        if use_status_join:
            # Treat findings with no state record as 'open'
            where_clauses.append("COALESCE(fs.status, 'open') = ?")
            params.append(status_filter)

        # Cursor — use table-qualified column when JOIN is active
        if cursor:
            cursor_val = self._decode_cursor(cursor)
            op = ">" if safe_sort_order == "ASC" else "<"
            col_ref = f"f.{safe_sort_by}" if use_status_join else safe_sort_by
            where_clauses.append(f"{col_ref} {op} ?")
            params.append(cursor_val)

        where_sql = " AND ".join(where_clauses)

        # Build query — use JOIN only when status filter is active
        if use_status_join:
            query = f"""
                SELECT f.id, f.scan_id, f.title, f.description, f.severity, f.file,
                       f.line, f.tool, f.cve, f.fingerprint, f.timestamp,
                       f.target_name,
                       COALESCE(fs.status, 'open') AS triage_status
                FROM findings f
                LEFT JOIN finding_states fs ON fs.finding_id = f.id
                WHERE {where_sql}
                ORDER BY f.{safe_sort_by} {safe_sort_order}
                LIMIT ?
                """
        else:
            # Standard query without JOIN
            query = f"""
                SELECT id, scan_id, title, description, severity, file,
                       line, tool, cve, fingerprint, timestamp, target_name
                FROM findings
                WHERE {where_sql}
                ORDER BY {safe_sort_by} {safe_sort_order}
                LIMIT ?
                """
        params.append(self.per_page + 1)

        rows = conn.execute(query, params).fetchall()
        items = [dict(row) for row in rows]

        has_next = len(items) > self.per_page
        if has_next:
            items = items[: self.per_page]

        next_cursor = None
        if has_next and items:
            next_cursor = self._encode_cursor(str(items[-1][safe_sort_by]))

        return {
            "items": items,
            "pagination": {
                "count": len(items),
                "has_next": has_next,
                "next_cursor": next_cursor,
                "per_page": self.per_page,
            },
        }

    @staticmethod
    def _encode_cursor(value: str) -> str:
        """Encode cursor."""
        return b64encode(value.encode()).decode()

    @staticmethod
    def _decode_cursor(cursor: str) -> str:
        """Decode cursor."""
        try:
            return b64decode(cursor.encode()).decode()
        except Exception:
            return ""


class ScansPaginator:
    """Specialized paginator for scans."""

    def __init__(self, per_page: int = 20):
        self.per_page = min(per_page, 200)

    def paginate(
        self,
        conn: Any,
        target_filter: str = "",
        status_filter: str = "",
        policy_filter: str = "",
        cursor: str | None = None,
        sort_by: str = "created_at",
        sort_order: str = "DESC",
    ) -> dict[str, Any]:
        """Paginate scans with filters.

        Args:
            conn: Database connection
            target_filter: Filter by target name (partial match)
            status_filter: Filter by status (exact match)
            policy_filter: Filter by policy_status (exact match)
            cursor: Pagination cursor
            sort_by: Column to sort by
            sort_order: ASC or DESC

        Returns:
            Paginated scans
        """
        allowed_sort_columns = {"id", "target_name", "target_type", "status", "created_at", "finished_at"}
        safe_sort_by = sort_by if sort_by in allowed_sort_columns else "created_at"
        safe_sort_order = "ASC" if sort_order.upper() == "ASC" else "DESC"

        where_clauses = ["1=1"]
        params: list[Any] = []

        if target_filter:
            where_clauses.append("target_name LIKE ?")
            params.append(f"%{target_filter}%")

        if status_filter:
            where_clauses.append("status = ?")
            params.append(status_filter)

        if policy_filter:
            where_clauses.append("policy_status = ?")
            params.append(policy_filter.upper())

        if cursor:
            cursor_val = self._decode_cursor(cursor)
            op = ">" if safe_sort_order == "ASC" else "<"
            where_clauses.append(f"{safe_sort_by} {op} ?")
            params.append(cursor_val)

        where_sql = " AND ".join(where_clauses)

        query = f"""
            SELECT id, target_name, target_type, status, policy_status,
                   created_at, finished_at, findings_count, critical_count,
                   high_count, medium_count, low_count, error_message
            FROM scans
            WHERE {where_sql}
            ORDER BY {safe_sort_by} {safe_sort_order}
            LIMIT ?
            """
        params.append(self.per_page + 1)

        rows = conn.execute(query, params).fetchall()
        items = [dict(row) for row in rows]

        has_next = len(items) > self.per_page
        if has_next:
            items = items[: self.per_page]

        next_cursor = None
        if has_next and items:
            next_cursor = self._encode_cursor(str(items[-1][safe_sort_by]))

        return {
            "items": items,
            "pagination": {
                "count": len(items),
                "has_next": has_next,
                "next_cursor": next_cursor,
                "per_page": self.per_page,
            },
        }

    @staticmethod
    def _encode_cursor(value: str) -> str:
        """Encode cursor."""
        return b64encode(value.encode()).decode()

    @staticmethod
    def _decode_cursor(cursor: str) -> str:
        """Decode cursor."""
        try:
            return b64decode(cursor.encode()).decode()
        except Exception:
            return ""
