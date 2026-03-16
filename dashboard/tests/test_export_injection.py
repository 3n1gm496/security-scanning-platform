"""
Regression tests for export injection sanitisation (CSV, HTML/XSS, PDF markup).
"""

import sys
from pathlib import Path

root = Path(__file__).parent.parent
sys.path.insert(0, str(root))
# Make common package importable
sys.path.insert(0, str(root.parent))

from export import _sanitize_csv_row, _sanitize_csv_value, export_to_csv, export_to_html, export_to_pdf

# ---------------------------------------------------------------------------
# CSV injection tests
# ---------------------------------------------------------------------------


class TestCSVInjectionSanitisation:
    """Verify that formula-starting characters are escaped in CSV output."""

    def test_sanitize_value_equals(self):
        assert _sanitize_csv_value("=1+1") == "'=1+1"

    def test_sanitize_value_plus(self):
        assert _sanitize_csv_value("+1+1") == "'+1+1"

    def test_sanitize_value_minus(self):
        assert _sanitize_csv_value("-2+3") == "'-2+3"

    def test_sanitize_value_at(self):
        assert _sanitize_csv_value("@SUM(A1)") == "'@SUM(A1)"

    def test_sanitize_value_tab(self):
        assert _sanitize_csv_value("\tcmd") == "'\tcmd"

    def test_sanitize_value_cr(self):
        assert _sanitize_csv_value("\rcmd") == "'\rcmd"

    def test_sanitize_value_safe_string(self):
        assert _sanitize_csv_value("normal text") == "normal text"

    def test_sanitize_value_empty(self):
        assert _sanitize_csv_value("") == ""

    def test_sanitize_value_non_string(self):
        assert _sanitize_csv_value(42) == 42
        assert _sanitize_csv_value(None) is None

    def test_sanitize_row(self):
        row = {"message": "=cmd|'/C calc'!A0", "severity": "HIGH", "count": 5}
        sanitized = _sanitize_csv_row(row)
        assert sanitized["message"] == "'=cmd|'/C calc'!A0"
        assert sanitized["severity"] == "HIGH"
        assert sanitized["count"] == 5

    def test_csv_export_escapes_formula(self):
        findings = [{"message": "=1+1", "tool": "+cmd", "severity": "HIGH"}]
        csv_output = export_to_csv(findings)
        lines = csv_output.strip().split("\n")
        # The data row should contain the escaped values
        data_line = lines[1]
        assert "'=1+1" in data_line
        assert "'+cmd" in data_line

    def test_csv_export_cmd_injection_payload(self):
        findings = [{"message": "=cmd|'/C calc'!A0", "severity": "critical"}]
        csv_output = export_to_csv(findings)
        # Should NOT start with = in the cell
        assert "\"'=cmd" in csv_output or "'=cmd" in csv_output


# ---------------------------------------------------------------------------
# HTML/XSS injection tests
# ---------------------------------------------------------------------------


class TestHTMLExportXSSPrevention:
    """Verify that HTML-special characters in findings are escaped."""

    def test_script_tag_escaped(self):
        findings = [
            {
                "message": "<script>alert(document.cookie)</script>",
                "severity": "high",
                "tool": "test",
            }
        ]
        html = export_to_html(findings)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_img_onerror_escaped(self):
        findings = [
            {
                "message": "<img src=x onerror=alert(1)>",
                "severity": "critical",
                "tool": "test",
            }
        ]
        html = export_to_html(findings)
        # The angle brackets must be escaped so the tag is not rendered
        assert "&lt;img" in html
        assert "<img src=x" not in html

    def test_tool_field_escaped(self):
        findings = [
            {
                "message": "test",
                "severity": "high",
                "tool": '<script>alert("xss")</script>',
            }
        ]
        html = export_to_html(findings)
        assert "&lt;script&gt;" in html

    def test_description_field_escaped(self):
        findings = [
            {
                "message": "title",
                "description": "<b onmouseover=alert(1)>hover me</b>",
                "severity": "medium",
                "tool": "test",
            }
        ]
        html = export_to_html(findings)
        # The <b> tag must be escaped so it's not rendered as HTML
        assert "&lt;b onmouseover=" in html
        assert "<b onmouseover=" not in html

    def test_scan_info_escaped(self):
        findings = []
        scan_info = {
            "scan_id": '<img src=x onerror="alert(1)">',
            "target": "<script>xss</script>",
        }
        html = export_to_html(findings, scan_info=scan_info)
        assert "<script>xss</script>" not in html
        assert "&lt;script&gt;" in html

    def test_cve_field_escaped(self):
        findings = [
            {
                "message": "vuln",
                "severity": "high",
                "tool": "test",
                "cve_id": '"><script>alert(1)</script>',
            }
        ]
        html = export_to_html(findings)
        assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# PDF markup injection tests
# ---------------------------------------------------------------------------


class TestPDFMarkupInjection:
    """Verify that ReportLab Paragraph-breaking characters are escaped."""

    def test_pdf_with_xml_in_title(self):
        """PDF generation should not crash with XML-like characters in title."""
        findings = [
            {
                "severity": "HIGH",
                "title": "</b><i>injected</i><para>",
                "tool": "test-tool",
                "category": "Test",
                "description": "Normal description",
            }
        ]
        pdf = export_to_pdf(findings)
        assert isinstance(pdf, bytes)
        assert pdf[:4] == b"%PDF"

    def test_pdf_with_script_in_description(self):
        findings = [
            {
                "severity": "CRITICAL",
                "title": "Normal Title",
                "tool": "<script>alert(1)</script>",
                "category": "Test & <Category>",
                "description": "<b>bold</b> & <i>italic</i> with <para> tag",
            }
        ]
        pdf = export_to_pdf(findings)
        assert isinstance(pdf, bytes)
        assert pdf[:4] == b"%PDF"

    def test_pdf_with_ampersand_in_fields(self):
        findings = [
            {
                "severity": "MEDIUM",
                "title": "Title with & ampersand",
                "tool": "tool & scanner",
                "category": "A & B",
                "file": "path/to/file&more.py",
                "line": 10,
                "description": "Desc with <angle> brackets & ampersands",
            }
        ]
        pdf = export_to_pdf(findings)
        assert isinstance(pdf, bytes)
        assert pdf[:4] == b"%PDF"
