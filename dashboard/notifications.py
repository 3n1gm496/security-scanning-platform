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

import logging
import os
import smtplib
from urllib.parse import quote_plus

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Any
from hashlib import sha256

logger = logging.getLogger(__name__)


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
        encoded_email = quote_plus(to_email)

        html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif;">
                <h2 style="color: #d32f2f;">Critical Security Finding</h2>

                <p><strong>Title:</strong> {finding.get('title', 'N/A')}</p>
                <p><strong>Severity:</strong> <span style="color: #d32f2f; font-weight: bold;">CRITICAL</span></p>
                <p><strong>Type:</strong> {finding.get('category', 'Unknown')}</p>
                <p><strong>Description:</strong> {finding.get('description', 'N/A')}</p>

                <h3>Location</h3>
                <p><strong>File:</strong> {finding.get('file_path', 'N/A')}</p>
                <p><strong>Line:</strong> {finding.get('line_number', 'N/A')}</p>

                <h3>Details</h3>
                <ul>
                    <li>Tool: {finding.get('tool', 'N/A')}</li>
                    <li>CVE: {finding.get('cve_id', 'N/A')}</li>
                    <li>Fingerprint: {finding.get('fingerprint', 'N/A')}</li>
                </ul>

                <p>
                    <a href="{dashboard_url}/findings/{finding.get('id', '')}"
                       style="background-color: #d32f2f; color: white; padding: 10px 20px;
                              text-decoration: none; border-radius: 5px;">
                        View in Dashboard
                    </a>
                </p>

                <hr>
                <p style="color: #999; font-size: 12px;">
                    This is an automated alert from the Security Scanner.
                    <a href="{dashboard_url}/notifications/unsubscribe?email={encoded_email}">Unsubscribe</a>
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
        File: {finding.get('file_path', 'N/A')}
        Line: {finding.get('line_number', 'N/A')}

        Details:
        Tool: {finding.get('tool', 'N/A')}
        CVE: {finding.get('cve_id', 'N/A')}

        View in dashboard: {dashboard_url}/findings/{finding.get('id', '')}
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

        critical_count = scan_results.get("critical_count", 0)
        high_count = scan_results.get("high_count", 0)
        medium_count = scan_results.get("medium_count", 0)
        total_count = scan_results.get("total_count", 0)

        html_body = f"""
        <html>
            <body style="font-family: Arial, sans-serif;">
                <h2>Security Scan Summary</h2>

                <p><strong>Target:</strong> {scan_results.get('target_name', 'N/A')}</p>
                <p><strong>Scan ID:</strong> {scan_results.get('scan_id', 'N/A')}</p>
                <p><strong>Date:</strong> {scan_results.get('created_at', 'N/A')}</p>

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
                    <a href="{dashboard_url}/scan/{scan_results.get('scan_id', '')}"
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
        Scan ID: {scan_results.get('scan_id', 'N/A')}
        Date: {scan_results.get('created_at', 'N/A')}

        Findings Summary:
        CRITICAL: {critical_count}
        HIGH: {high_count}
        MEDIUM: {medium_count}
        TOTAL: {total_count}

        View full report: {dashboard_url}/scan/{scan_results.get('scan_id', '')}
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
                    <a href="{dashboard_url}/"
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

        View dashboard: {dashboard_url}/
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
                server.starttls()
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
    def save_preferences(
        conn: Any,
        user_email: str,
        preferences: dict[str, Any],
    ) -> bool:
        """Save notification preferences for a user."""
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS notification_preferences (
                    id INTEGER PRIMARY KEY,
                    user_email TEXT UNIQUE,
                    critical_alerts BOOLEAN DEFAULT 1,
                    high_alerts BOOLEAN DEFAULT 1,
                    scan_summaries BOOLEAN DEFAULT 1,
                    weekly_digest BOOLEAN DEFAULT 0,
                    preferred_channel TEXT DEFAULT 'email',
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            conn.execute(
                """
                INSERT OR REPLACE INTO notification_preferences
                (user_email, critical_alerts, high_alerts, scan_summaries, weekly_digest, preferred_channel)
                VALUES (?, ?, ?, ?, ?, ?)
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
            row = conn.execute(
                "SELECT * FROM notification_preferences WHERE user_email = ?",
                (user_email,),
            ).fetchone()

            if row:
                return dict(row)
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
