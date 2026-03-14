"""
Advanced Charting System - Data aggregation for Chart.js visualizations.

Supports:
- Finding distribution by severity
- Tool effectiveness
- Scan trends over time
- Target risk heatmaps
- Remediation progress tracking
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


class ChartingEngine:
    """Generate chart data for visualization."""

    @staticmethod
    def severity_distribution(conn: Any, days: int = 30) -> dict[str, Any]:
        """Get findings distribution by severity over time.

        Returns data for stacked bar chart.
        """
        if days > 0:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            rows = conn.execute(
                """
                SELECT
                    DATE(timestamp) as date,
                    severity,
                    COUNT(*) as count
                FROM findings
                WHERE timestamp >= ?
                GROUP BY DATE(timestamp), severity
                ORDER BY date ASC
                """,
                [cutoff.isoformat()],
            ).fetchall()
        else:
            rows = conn.execute("""
                SELECT
                    DATE(timestamp) as date,
                    severity,
                    COUNT(*) as count
                FROM findings
                GROUP BY DATE(timestamp), severity
                ORDER BY date ASC
                """).fetchall()

        # Organize by date and severity
        data_by_date = {}
        severities = set()

        for row in rows:
            date = row["date"]
            severity = row["severity"]
            count = row["count"]

            if date not in data_by_date:
                data_by_date[date] = {}

            data_by_date[date][severity] = count
            severities.add(severity)

        # Build chart datasets
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        severities_sorted = [s for s in severity_order if s in severities]

        labels = sorted(data_by_date.keys())
        datasets = []

        colors = {
            "CRITICAL": "rgb(255, 0, 0)",
            "HIGH": "rgb(255, 165, 0)",
            "MEDIUM": "rgb(255, 255, 0)",
            "LOW": "rgb(144, 238, 144)",
            "INFO": "rgb(173, 216, 230)",
        }

        for severity in severities_sorted:
            data = [data_by_date.get(date, {}).get(severity, 0) for date in labels]
            datasets.append(
                {
                    "label": severity,
                    "data": data,
                    "backgroundColor": colors.get(severity, "rgb(200, 200, 200)"),
                    "borderColor": colors.get(severity, "rgb(100, 100, 100)"),
                    "borderWidth": 1,
                }
            )

        return {"labels": labels, "datasets": datasets}

    @staticmethod
    def tool_effectiveness(conn: Any) -> dict[str, Any]:
        """Get findings count by tool (effectiveness comparison).

        Returns data for bar chart.
        """
        query = """
            SELECT tool, COUNT(*) as finding_count
            FROM findings
            GROUP BY tool
            ORDER BY finding_count DESC
            LIMIT 10
        """

        rows = conn.execute(query).fetchall()

        labels = [row["tool"] for row in rows]
        data = [row["finding_count"] for row in rows]

        colors = [
            "rgb(75, 192, 192)",
            "rgb(153, 102, 255)",
            "rgb(255, 159, 64)",
            "rgb(54, 162, 235)",
            "rgb(255, 99, 132)",
        ]

        return {
            "labels": labels,
            "datasets": [
                {
                    "label": "Findings Found",
                    "data": data,
                    "backgroundColor": colors,
                    "borderColor": colors,
                    "borderWidth": 1,
                }
            ],
        }

    @staticmethod
    def target_risk_heatmap(conn: Any) -> dict[str, Any]:
        """Get risk scores by target (for heatmap).

        Returns data for heatmap visualization.

        Risk score formula mirrors analytics.SEVERITY_WEIGHTS (scale 0-100):
          CRITICAL=100, HIGH=75, MEDIUM=50, LOW=25, INFO=10
        The per-target score is the average across all findings, capped at 100.
        """
        query = """
            SELECT
                s.target_name,
                COUNT(CASE WHEN f.severity = 'CRITICAL' THEN 1 END) as critical_count,
                COUNT(CASE WHEN f.severity = 'HIGH' THEN 1 END) as high_count,
                COUNT(CASE WHEN f.severity = 'MEDIUM' THEN 1 END) as medium_count,
                COUNT(CASE WHEN f.severity = 'LOW' THEN 1 END) as low_count,
                COUNT(CASE WHEN f.severity = 'INFO' THEN 1 END) as info_count,
                COUNT(f.id) as total_findings,
                ROUND(
                    CASE WHEN COUNT(f.id) = 0 THEN 0
                    ELSE MIN(
                        (
                            COUNT(CASE WHEN f.severity = 'CRITICAL' THEN 1 END) * 100.0 +
                            COUNT(CASE WHEN f.severity = 'HIGH' THEN 1 END) * 75.0 +
                            COUNT(CASE WHEN f.severity = 'MEDIUM' THEN 1 END) * 50.0 +
                            COUNT(CASE WHEN f.severity = 'LOW' THEN 1 END) * 25.0 +
                            COUNT(CASE WHEN f.severity = 'INFO' THEN 1 END) * 10.0
                        ) / NULLIF(COUNT(f.id), 0),
                        100.0
                    ) END,
                    2
                ) as risk_score
            FROM scans s
            LEFT JOIN findings f ON s.id = f.scan_id
            GROUP BY s.target_name
            ORDER BY risk_score DESC
            LIMIT 20
        """

        rows = conn.execute(query).fetchall()

        targets = []
        risk_scores = []

        for row in rows:
            targets.append(row["target_name"])
            risk_scores.append(
                {
                    "target": row["target_name"],
                    "risk_score": row["risk_score"],
                    "critical": row["critical_count"],
                    "high": row["high_count"],
                    "medium": row["medium_count"],
                    "low": row["low_count"],
                    "info": row["info_count"],
                    "total": row["total_findings"],
                }
            )

        return {"targets": [r["target"] for r in risk_scores], "data": risk_scores}

    @staticmethod
    def scan_status_trend(conn: Any, days: int = 90) -> dict[str, Any]:
        """Get scan completion trend.

        Returns data for line chart.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        query = """
            SELECT
                DATE(created_at) as date,
                COUNT(*) as total_scans,
                SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed
            FROM scans
            WHERE created_at >= ?
            GROUP BY DATE(created_at)
            ORDER BY date ASC
        """

        rows = conn.execute(query, [cutoff.isoformat()]).fetchall()

        labels = [row["date"] for row in rows]
        completed_data = [row["completed"] or 0 for row in rows]
        failed_data = [row["failed"] or 0 for row in rows]

        return {
            "labels": labels,
            "datasets": [
                {
                    "label": "Completed",
                    "data": completed_data,
                    "borderColor": "rgb(75, 192, 192)",
                    "backgroundColor": "rgba(75, 192, 192, 0.2)",
                    "tension": 0.1,
                },
                {
                    "label": "Failed",
                    "data": failed_data,
                    "borderColor": "rgb(255, 99, 132)",
                    "backgroundColor": "rgba(255, 99, 132, 0.2)",
                    "tension": 0.1,
                },
            ],
        }

    @staticmethod
    def remediation_progress(conn: Any) -> dict[str, Any]:
        """Get findings remediation progress.

        Returns data for pie/doughnut chart.
        """
        query = """
            SELECT
                COALESCE(status, 'new') as status,
                COUNT(*) as count
            FROM findings f
            LEFT JOIN finding_states fs ON f.id = fs.finding_id
            GROUP BY status
        """

        rows = conn.execute(query).fetchall()

        labels = []
        data = []
        status_colors = {
            "new": "rgb(200, 200, 200)",
            "acknowledged": "rgb(54, 162, 235)",
            "in_progress": "rgb(255, 159, 64)",
            "resolved": "rgb(75, 192, 192)",
            "false_positive": "rgb(153, 102, 255)",
            "risk_accepted": "rgb(255, 193, 7)",
        }

        for row in rows:
            status = row["status"] or "new"
            labels.append(status)
            data.append(row["count"])

        return {
            "labels": labels,
            "datasets": [
                {
                    "data": data,
                    "backgroundColor": [status_colors.get(label, "rgb(100, 100, 100)") for label in labels],
                    "borderColor": [status_colors.get(label, "rgb(50, 50, 50)") for label in labels],
                    "borderWidth": 2,
                }
            ],
        }

    @staticmethod
    def cve_distribution(conn: Any) -> dict[str, Any]:
        """Get top CVEs found.

        Returns data for bar chart.
        """
        query = """
            SELECT
                cve,
                COUNT(*) as count
            FROM findings
            WHERE cve IS NOT NULL AND cve != ''
            GROUP BY cve
            ORDER BY count DESC
            LIMIT 15
        """

        rows = conn.execute(query).fetchall()

        labels = [row["cve"] for row in rows]
        data = [row["count"] for row in rows]

        return {
            "labels": labels,
            "datasets": [
                {
                    "label": "Occurrences",
                    "data": data,
                    "backgroundColor": "rgba(139, 69, 19, 0.8)",
                    "borderColor": "rgba(101, 50, 15, 1)",
                    "borderWidth": 1,
                }
            ],
        }
