"""
Email Notification System - Send alerts for security findings.

Supports:
- SMTP-based email notifications
- Alert templates for different finding types
- Notification preferences per user
- Batch digest emails
- Email verification and unsubscribe
"""

from __future__ import annotations

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import escape as html_escape
from typing import Any
from urllib.parse import quote_plus, urlsplit, urlunsplit

from db_adapter import adapt_schema, is_postgres
from logging_config import get_logger

logger = get_logger(__name__)


def _safe_dashboard_url(dashboard_url: str) -> str:
    """Normalize dashboard URLs used in emails to http/https only."""
    parsed = urlsplit(dashboard_url or "")
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return "http://localhost:8080"
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def _finding_dashboard_path(finding: dict[str, Any]) -> str:
    scan_id = str(finding.get("scan_id") or "").strip()
    title = str(finding.get("title") or "").strip()
    if scan_id:
        path = f"/#findings?scan_id={quote_plus(scan_id)}"
        if title:
            path += f"&search={quote_plus(title)}"
        return path
    return "/#findings"


def _scan_dashboard_path(scan_results: dict[str, Any]) -> str:
    scan_id = str(scan_results.get("scan_id") or scan_results.get("id") or "").strip()
    if scan_id:
        return f"/#scans?search={quote_plus(scan_id)}"
    return "/#scans"


class EmailNotificationEngine:
    """Send email notifications for security findings."""

    def __init__(self):
        self.smtp_server = os.getenv("SMTP_SERVER", "localhost")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_password = os.getenv("SMTP_PASSWORD", "")
        self.from_email = os.getenv("EMAIL_FROM", "security@example.com")
        self.from_name = os.getenv("EMAIL_FROM_NAME", "Security Scanner")

    def send_critical_finding_alert(
        self, to_email: str, finding: dict[str, Any], dashboard_url: str = "http://localhost:8000"
    ) -> bool:
        """Send alert for critical finding."""
        subject = f"[CRITICAL] Security Finding: {finding.get('title', 'Unknown')}"
        base_url = _safe_dashboard_url(dashboard_url)
        file_path = finding.get("file") or finding.get("file_path") or "N/A"
        line_number = finding.get("line") or finding.get("line_number") or "N/A"
        cve_id = finding.get("cve") or finding.get("cve_id") or "N/A"
        cwe_id = finding.get("cwe") or finding.get("cwe_id") or None
        finding_url = html_escape(f"{base_url}{_finding_dashboard_path(finding)}")
        settings_url = html_escape(f"{base_url}/#settings")

        # Escape all user-controlled data for safe HTML embedding
        e = {k: html_escape(str(v)) for k, v in finding.items() if v is not None}
        file_path_html = html_escape(str(file_path))
        line_number_html = html_escape(str(line_number))
        cve_id_html = html_escape(str(cve_id))
        cwe_id_html = html_escape(str(cwe_id)) if cwe_id else None

        html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif;">
                <h2 style="color: #d32f2f;">Critical Security Finding</h2>

                <p><strong>Title:</strong> {e.get('title', 'N/A')}</p>
                <p><strong>Severity:</strong> <span style="color: #d32f2f; font-weight: bold;">CRITICAL</span></p>
                <p><strong>Type:</strong> {e.get('category', 'Unknown')}</p>
                <p><strong>Description:</strong> {e.get('description', 'N/A')}</p>

                <h3>Location</h3>
                <p><strong>File:</strong> {file_path_html}</p>
                <p><strong>Line:</strong> {line_number_html}</p>

                <h3>Details</h3>
                <ul>
                    <li>Tool: {e.get('tool', 'N/A')}</li>
                    <li>CVE: {cve_id_html}</li>
                    {f"<li>CWE: {cwe_id_html}</li>" if cwe_id_html else ""}
                    <li>Fingerprint: {e.get('fingerprint', 'N/A')}</li>
                </ul>

                <p>
                    <a href="{finding_url}"
                       style="background-color: #d32f2f; color: white; padding: 10px 20px;
                              text-decoration: none; border-radius: 5px;">
                        View in Dashboard
                    </a>
                </p>

                <hr>
                <p style="color: #999; font-size: 12px;">
                    This is an automated alert from the Security Scanner.
                    <a href="{settings_url}">Manage notification preferences</a>
                </p>
            </body>
        </html>
        """

        text_body = f"""
        CRITICAL SECURITY FINDING

        Title: {finding.get('title', 'N/A')}
        Severity: CRITICAL
        Type: {finding.get('category', 'Unknown')}
        Description: {finding.get('description', 'N/A')}

        Location:
        File: {file_path}
        Line: {line_number}

        Details:
        Tool: {finding.get('tool', 'N/A')}
        CVE: {cve_id}
        {f"CWE: {cwe_id}" if cwe_id else ""}

        View in dashboard: {base_url}{_finding_dashboard_path(finding)}
        Manage notification preferences: {base_url}/#settings
        """

        return self._send_email(to_email, subject, text_body, html_body)

    def send_scan_summary(
        self,
        to_email: str,
        scan_results: dict[str, Any],
        dashboard_url: str = "http://localhost:8000",
    ) -> bool:
        """Send scan summary digest email."""
        subject = f"Security Scan Summary - {scan_results.get('target_name', 'Unknown')}"
        base_url = _safe_dashboard_url(dashboard_url)

        critical_count = scan_results.get("critical_count", 0)
        high_count = scan_results.get("high_count", 0)
        medium_count = scan_results.get("medium_count", 0)
        total_count = scan_results.get("total_count", scan_results.get("findings_count", 0))
        scan_url = html_escape(f"{base_url}{_scan_dashboard_path(scan_results)}")
        scan_identifier = str(scan_results.get("scan_id", scan_results.get("id", "N/A")))

        # Escape user-controlled strings for safe HTML embedding
        target_name = html_escape(str(scan_results.get("target_name", "N/A")))
        scan_id = html_escape(scan_identifier)
        created_at = html_escape(str(scan_results.get("created_at", "N/A")))

        html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif;">
                <h2>Security Scan Summary</h2>

                <p><strong>Target:</strong> {target_name}</p>
                <p><strong>Scan ID:</strong> {scan_id}</p>
                <p><strong>Date:</strong> {created_at}</p>

                <h3>Findings Summary</h3>
                <table style="border-collapse: collapse; width: 100%;">
                    <tr style="background-color: #f0f0f0;">
                        <th style="border: 1px solid #ddd; padding: 8px;">Severity</th>
                        <th style="border: 1px solid #ddd; padding: 8px;">Count</th>
                    </tr>
                    <tr>
                        <td style="border: 1px solid #ddd; padding: 8px; color: #d32f2f;">CRITICAL</td>
                        <td style="border: 1px solid #ddd; padding: 8px; font-weight: bold;">{critical_count}</td>
                    </tr>
                    <tr>
                        <td style="border: 1px solid #ddd; padding: 8px; color: #f57c00;">HIGH</td>
                        <td style="border: 1px solid #ddd; padding: 8px; font-weight: bold;">{high_count}</td>
                    </tr>
                    <tr>
                        <td style="border: 1px solid #ddd; padding: 8px; color: #fbc02d;">MEDIUM</td>
                        <td style="border: 1px solid #ddd; padding: 8px; font-weight: bold;">{medium_count}</td>
                    </tr>
                    <tr style="background-color: #f0f0f0;">
                        <td style="border: 1px solid #ddd; padding: 8px; font-weight: bold;">TOTAL</td>
                        <td style="border: 1px solid #ddd; padding: 8px; font-weight: bold;">{total_count}</td>
                    </tr>
                </table>

                <p style="margin-top: 20px;">
                    <a href="{scan_url}"
                       style="background-color: #1976d2; color: white; padding: 10px 20px;
                              text-decoration: none; border-radius: 5px;">
                        View Full Report
                    </a>
                </p>

                <hr>
                <p style="color: #999; font-size: 12px;">
                    This is an automated report from the Security Scanner.
                </p>
            </body>
        </html>
        """

        text_body = f"""
        SECURITY SCAN SUMMARY

        Target: {scan_results.get('target_name', 'N/A')}
        Scan ID: {scan_identifier}
        Date: {scan_results.get('created_at', 'N/A')}

        Findings Summary:
        CRITICAL: {critical_count}
        HIGH: {high_count}
        MEDIUM: {medium_count}
        TOTAL: {total_count}

        View full report: {base_url}{_scan_dashboard_path(scan_results)}
        """

        return self._send_email(to_email, subject, text_body, html_body)

    def send_weekly_digest(
        self,
        to_email: str,
        digest_data: dict[str, Any],
        dashboard_url: str = "http://localhost:8000",
    ) -> bool:
        """Send weekly digest email."""
        subject = "Weekly Security Report"
        base_url = _safe_dashboard_url(dashboard_url)

        html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif;">
                <h2>Weekly Security Report</h2>

                <p>Here's your weekly security summary for the past 7 days:</p>

                <h3>Statistics</h3>
                <ul>
                    <li>Total Scans: {digest_data.get('total_scans', 0)}</li>
                    <li>New Findings: {digest_data.get('new_findings', 0)}</li>
                    <li>Resolved Findings: {digest_data.get('resolved_findings', 0)}</li>
                    <li>Critical Findings: {digest_data.get('critical_count', 0)}</li>
                </ul>

                <p>
                    <a href="{base_url}/"
                       style="background-color: #1976d2; color: white; padding: 10px 20px;
                              text-decoration: none; border-radius: 5px;">
                        View Dashboard
                    </a>
                </p>

                <hr>
                <p style="color: #999; font-size: 12px;">
                    This is an automated weekly report from the Security Scanner.
                </p>
            </body>
        </html>
        """

        text_body = f"""
        WEEKLY SECURITY REPORT

        Statistics for the past 7 days:
        Total Scans: {digest_data.get('total_scans', 0)}
        New Findings: {digest_data.get('new_findings', 0)}
        Resolved Findings: {digest_data.get('resolved_findings', 0)}
        Critical Findings: {digest_data.get('critical_count', 0)}

        View dashboard: {base_url}/
        """

        return self._send_email(to_email, subject, text_body, html_body)

    def _send_email(self, to_email: str, subject: str, text_body: str, html_body: str) -> bool:
        """Send SMTP email with both text and HTML."""
        try:
            # Create message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"{self.from_name} <{self.from_email}>"
            msg["To"] = to_email

            # Attach text and HTML parts
            msg.attach(MIMEText(text_body, "plain"))
            msg.attach(MIMEText(html_body, "html"))

            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.ehlo()
                if server.has_extn("starttls"):
                    server.starttls()
                    server.ehlo()
                if self.smtp_user and self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)

            return True
        except Exception as e:
            logger.error("Failed to send email to %s: %s", to_email, e)
            return False


class NotificationPreferencesManager:
    """Manage user notification preferences."""

    @staticmethod
    def _ensure_preferences_table(conn: Any) -> None:
        """Create and repair the notification preferences table across backends."""
        conn.execute(adapt_schema("""
                CREATE TABLE IF NOT EXISTS notification_preferences (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_email TEXT UNIQUE,
                    critical_alerts BOOLEAN DEFAULT 1,
                    high_alerts BOOLEAN DEFAULT 1,
                    scan_summaries BOOLEAN DEFAULT 1,
                    weekly_digest BOOLEAN DEFAULT 0,
                    preferred_channel TEXT DEFAULT 'email',
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """))

        if not is_postgres():
            return

        row = conn.execute(
            """
            SELECT column_default, is_identity
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = ?
              AND column_name = ?
            """,
            ("notification_preferences", "id"),
        ).fetchone()
        if not row:
            return
        if row["is_identity"] == "YES" or row["column_default"]:
            return

        conn.execute("CREATE SEQUENCE IF NOT EXISTS notification_preferences_id_seq")
        conn.execute(
            "SELECT setval("
            "'notification_preferences_id_seq', "
            "COALESCE((SELECT MAX(id) FROM notification_preferences), 0) + 1, "
            "false)"
        )
        conn.execute("""
            ALTER TABLE notification_preferences
            ALTER COLUMN id SET DEFAULT nextval('notification_preferences_id_seq')
            """)

    @staticmethod
    def save_preferences(
        conn: Any,
        user_email: str,
        preferences: dict[str, Any],
    ) -> bool:
        """Save notification preferences for a user."""
        try:
            NotificationPreferencesManager._ensure_preferences_table(conn)

            conn.execute(
                """
                INSERT INTO notification_preferences
                (user_email, critical_alerts, high_alerts, scan_summaries, weekly_digest, preferred_channel)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(user_email) DO UPDATE SET
                    critical_alerts = excluded.critical_alerts,
                    high_alerts = excluded.high_alerts,
                    scan_summaries = excluded.scan_summaries,
                    weekly_digest = excluded.weekly_digest,
                    preferred_channel = excluded.preferred_channel,
                    updated_at = CURRENT_TIMESTAMP
            """,
                (
                    user_email,
                    preferences.get("critical_alerts", True),
                    preferences.get("high_alerts", True),
                    preferences.get("scan_summaries", True),
                    preferences.get("weekly_digest", False),
                    preferences.get("preferred_channel", "email"),
                ),
            )

            conn.commit()
            return True
        except Exception as e:
            logger.error("Failed to save preferences: %s", e)
            return False

    @staticmethod
    def get_preferences(conn: Any, user_email: str) -> dict[str, Any] | None:
        """Get notification preferences for a user."""
        try:
            NotificationPreferencesManager._ensure_preferences_table(conn)
            row = conn.execute(
                "SELECT * FROM notification_preferences WHERE user_email = ?",
                (user_email,),
            ).fetchone()

            if row:
                prefs = dict(row)
                for key in ("critical_alerts", "high_alerts", "scan_summaries", "weekly_digest"):
                    if key in prefs:
                        prefs[key] = bool(prefs[key])
                return prefs
            return None
        except Exception:
            return None

    @staticmethod
    def get_subscribers_for_alerts(
        conn: Any,
        alert_type: str = "critical_alerts",
    ) -> list[str]:
        """Get all email subscribers for a specific alert type."""
        try:
            NotificationPreferencesManager._ensure_preferences_table(conn)
            allowed_alert_types = {
                "critical_alerts": "critical_alerts",
                "high_alerts": "high_alerts",
                "scan_summaries": "scan_summaries",
                "weekly_digest": "weekly_digest",
            }
            alert_column = allowed_alert_types.get(alert_type)
            if not alert_column:
                return []

            if alert_column == "critical_alerts":
                query = (
                    "SELECT user_email FROM notification_preferences "
                    "WHERE critical_alerts = 1 AND preferred_channel = 'email'"
                )
            elif alert_column == "high_alerts":
                query = (
                    "SELECT user_email FROM notification_preferences "
                    "WHERE high_alerts = 1 AND preferred_channel = 'email'"
                )
            elif alert_column == "scan_summaries":
                query = (
                    "SELECT user_email FROM notification_preferences "
                    "WHERE scan_summaries = 1 AND preferred_channel = 'email'"
                )
            else:
                query = (
                    "SELECT user_email FROM notification_preferences "
                    "WHERE weekly_digest = 1 AND preferred_channel = 'email'"
                )
            rows = conn.execute(query).fetchall()
            return [row["user_email"] for row in rows]
        except Exception:
            return []
