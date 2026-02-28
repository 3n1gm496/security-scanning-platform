"""
Export findings in multiple formats: JSON, CSV, SARIF, HTML, PDF.
"""
import csv
import json
import os
from datetime import datetime, timezone
from io import StringIO, BytesIO
from typing import List, Dict, Any

# SARIF format version
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def export_to_json(findings: List[Dict[str, Any]]) -> str:
    """Export findings to JSON format."""
    output = {
        "version": "1.0",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "findings": findings
    }
    
    return json.dumps(output, indent=2)


def export_to_csv(findings: List[Dict[str, Any]]) -> str:
    """Export findings to CSV format."""
    if not findings:
        return ""
    
    output = StringIO()
    
    # Determine all fields
    all_fields = set()
    for finding in findings:
        all_fields.update(finding.keys())
    
    fieldnames = sorted(all_fields)
    
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    
    for finding in findings:
        writer.writerow(finding)
    
    return output.getvalue()


def export_to_sarif(
    findings: List[Dict[str, Any]],
    tool_name: str = "security-scanner",
    tool_version: str = "1.0.0"
) -> str:
    """
    Export findings to SARIF (Static Analysis Results Interchange Format) v2.1.0.
    https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
    """
    # Map severity to SARIF levels
    severity_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note"
    }
    
    # Group findings by tool
    findings_by_tool: Dict[str, List[Dict]] = {}
    for finding in findings:
        tool = finding.get("tool", "unknown")
        if tool not in findings_by_tool:
            findings_by_tool[tool] = []
        findings_by_tool[tool].append(finding)
    
    # Create SARIF runs (one per tool)
    runs = []
    
    for tool, tool_findings in findings_by_tool.items():
        # Create results
        results = []
        
        for finding in tool_findings:
            severity = finding.get("severity", "info").lower()
            level = severity_map.get(severity, "warning")
            
            # Create result
            result = {
                "ruleId": finding.get("rule_id", finding.get("category", "unknown")),
                "level": level,
                "message": {
                    "text": finding.get("message", finding.get("description", ""))
                },
                "locations": []
            }
            
            # Add location if available
            if "file" in finding or "target" in finding:
                location = {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.get("file", finding.get("target", "unknown"))
                        }
                    }
                }
                
                # Add line number if available
                if "line" in finding:
                    location["physicalLocation"]["region"] = {
                        "startLine": finding.get("line"),
                    }
                
                result["locations"].append(location)
            
            # Add properties with additional metadata
            properties = {}
            for key in ["cve_id", "cwe_id", "cvss_score", "confidence", "scan_id"]:
                if key in finding:
                    properties[key] = finding[key]
            
            if properties:
                result["properties"] = properties
            
            results.append(result)
        
        # Create run
        run = {
            "tool": {
                "driver": {
                    "name": tool,
                    "version": tool_version,
                    "informationUri": f"https://example.com/tools/{tool}"
                }
            },
            "results": results
        }
        
        runs.append(run)
    
    # Create SARIF document
    sarif = {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": runs
    }
    
    return json.dumps(sarif, indent=2)


def export_to_html(findings: List[Dict[str, Any]], scan_info: Dict[str, Any] = None) -> str:
    """
    Export findings to HTML format with styling.
    """
    scan_info = scan_info or {}
    
    # Group findings by severity
    by_severity = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "info": []
    }
    
    for finding in findings:
        severity = finding.get("severity", "info").lower()
        by_severity.get(severity, by_severity["info"]).append(finding)
    
    # Generate HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0 0 10px 0;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            font-size: 14px;
            color: #666;
            text-transform: uppercase;
        }}
        .summary-card .value {{
            font-size: 32px;
            font-weight: bold;
        }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
        .info {{ color: #17a2b8; }}
        .findings {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .findings h2 {{
            margin-top: 0;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }}
        .finding {{
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid;
            background: #f8f9fa;
            border-radius: 4px;
        }}
        .finding.critical {{ border-left-color: #dc3545; }}
        .finding.high {{ border-left-color: #fd7e14; }}
        .finding.medium {{ border-left-color: #ffc107; }}
        .finding.low {{ border-left-color: #28a745; }}
        .finding.info {{ border-left-color: #17a2b8; }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 10px;
        }}
        .finding-title {{
            font-weight: bold;
            font-size: 16px;
        }}
        .severity-badge {{
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
            color: white;
        }}
        .severity-badge.critical {{ background-color: #dc3545; }}
        .severity-badge.high {{ background-color: #fd7e14; }}
        .severity-badge.medium {{ background-color: #ffc107; color: #333; }}
        .severity-badge.low {{ background-color: #28a745; }}
        .severity-badge.info {{ background-color: #17a2b8; }}
        .finding-meta {{
            font-size: 13px;
            color: #666;
            margin-bottom: 10px;
        }}
        .finding-description {{
            margin-top: 10px;
        }}
        .footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Scan Report</h1>
        <p>Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        {f'<p>Scan ID: {scan_info.get("scan_id")}</p>' if scan_info.get("scan_id") else ''}
        {f'<p>Target: {scan_info.get("target")}</p>' if scan_info.get("target") else ''}
    </div>
    
    <div class="summary">
        <div class="summary-card">
            <h3>Total Findings</h3>
            <div class="value">{len(findings)}</div>
        </div>
        <div class="summary-card">
            <h3>Critical</h3>
            <div class="value critical">{len(by_severity['critical'])}</div>
        </div>
        <div class="summary-card">
            <h3>High</h3>
            <div class="value high">{len(by_severity['high'])}</div>
        </div>
        <div class="summary-card">
            <h3>Medium</h3>
            <div class="value medium">{len(by_severity['medium'])}</div>
        </div>
        <div class="summary-card">
            <h3>Low</h3>
            <div class="value low">{len(by_severity['low'])}</div>
        </div>
    </div>
    
"""
    
    # Add findings by severity
    for severity_level in ["critical", "high", "medium", "low", "info"]:
        findings_list = by_severity[severity_level]
        if not findings_list:
            continue
        
        html += f"""
    <div class="findings">
        <h2 class="{severity_level}">{severity_level.upper()} Severity ({len(findings_list)})</h2>
"""
        
        for finding in findings_list:
            title = finding.get("message", finding.get("description", "Unknown issue"))
            tool = finding.get("tool", "unknown")
            target = finding.get("target", finding.get("file", ""))
            category = finding.get("category", "")
            cve_id = finding.get("cve_id", "")
            cwe_id = finding.get("cwe_id", "")
            cvss_score = finding.get("cvss_score", "")
            
            # Build metadata line
            meta_parts = [f"<strong>Tool:</strong> {tool}", f"<strong>Target:</strong> {target}"]
            if category:
                meta_parts.append(f"<strong>Category:</strong> {category}")
            if cve_id:
                meta_parts.append(f"<strong>CVE:</strong> {cve_id}")
            if cwe_id:
                meta_parts.append(f"<strong>CWE:</strong> {cwe_id}")
            if cvss_score:
                meta_parts.append(f"<strong>CVSS:</strong> {cvss_score}")
            
            html += f"""
        <div class="finding {severity_level}">
            <div class="finding-header">
                <div class="finding-title">{title}</div>
                <span class="severity-badge {severity_level}">{severity_level}</span>
            </div>
            <div class="finding-meta">
                {' | '.join(meta_parts)}
            </div>
"""
            
            if "description" in finding and finding["description"] != title:
                html += f"""
            <div class="finding-description">
                {finding["description"]}
            </div>
"""
            
            html += """
        </div>
"""
        
        html += """
    </div>
"""
    
    html += """
    <div class="footer">
        <p>This report was generated by Security Scanning Platform</p>
    </div>
</body>
</html>
"""
    
    return html


def export_to_pdf(
    findings: List[Dict[str, Any]],
    scan_info: Dict[str, Any] = None,
    analytics_data: Dict[str, Any] = None
) -> bytes:
    """
    Export findings to PDF format with charts and analytics.
    
    Args:
        findings: List of finding dictionaries
        scan_info: Optional scan metadata
        analytics_data: Optional analytics data (risk distribution, compliance, etc.)
    
    Returns:
        PDF file content as bytes
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,
            PageBreak, Image
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
    except ImportError:
        raise ImportError("reportlab is required for PDF export. Install with: pip install reportlab")
    
    scan_info = scan_info or {}
    analytics_data = analytics_data or {}
    
    # Create PDF buffer
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    story = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#667eea'),
        spaceAfter=30,
        alignment=TA_CENTER
    )
    
    heading2_style = ParagraphStyle(
        'CustomHeading2',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#764ba2'),
        spaceAfter=12,
        spaceBefore=20
    )
    
    # Title
    story.append(Paragraph("Security Scan Report", title_style))
    story.append(Spacer(1, 0.2 * inch))
    
    # Scan metadata
    if scan_info:
        metadata = [
            ["Scan ID:", scan_info.get("id", "N/A")],
            ["Target:", f"{scan_info.get('target_type', 'N/A')} - {scan_info.get('target_name', 'N/A')}"],
            ["Status:", scan_info.get("status", "N/A")],
            ["Created:", scan_info.get("created_at", "N/A")],
            ["Findings:", str(scan_info.get("findings_count", len(findings)))],
        ]
        
        metadata_table = Table(metadata, colWidths=[1.5 * inch, 4.5 * inch])
        metadata_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        
        story.append(metadata_table)
        story.append(Spacer(1, 0.3 * inch))
    
    # Executive Summary
    story.append(Paragraph("Executive Summary", heading2_style))
    
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for finding in findings:
        sev = finding.get("severity", "INFO").upper()
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    summary_data = [
        ["Severity", "Count"],
        ["CRITICAL", severity_counts["CRITICAL"]],
        ["HIGH", severity_counts["HIGH"]],
        ["MEDIUM", severity_counts["MEDIUM"]],
        ["LOW", severity_counts["LOW"]],
        ["INFO", severity_counts["INFO"]],
        ["TOTAL", len(findings)],
    ]
    
    summary_table = Table(summary_data, colWidths=[3 * inch, 2 * inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -2), colors.beige),
        ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor('#f0f0f0')),
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    
    story.append(summary_table)
    story.append(Spacer(1, 0.4 * inch))
    
    # Analytics data (if provided)
    if analytics_data:
        story.append(Paragraph("Risk Analysis", heading2_style))
        
        risk_dist = analytics_data.get("risk_distribution", {})
        if risk_dist:
            risk_data = [
                ["Metric", "Value"],
                ["Total Findings", risk_dist.get("total_findings", 0)],
                ["Average Risk Score", f"{risk_dist.get('average_risk', 0)}/100"],
                ["Maximum Risk Score", f"{risk_dist.get('max_risk', 0)}/100"],
                ["High Risk Findings (≥50)", risk_dist.get("high_risk_count", 0)],
            ]
            
            risk_table = Table(risk_data, colWidths=[3.5 * inch, 2 * inch])
            risk_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#764ba2')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            
            story.append(risk_table)
            story.append(Spacer(1, 0.3 * inch))
    
    # Detailed Findings
    story.append(PageBreak())
    story.append(Paragraph("Detailed Findings", heading2_style))
    
    # Group by severity
    by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
    for finding in findings:
        sev = finding.get("severity", "INFO").upper()
        if sev in by_severity:
            by_severity[sev].append(finding)
    
    # Display findings by severity
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        findings_list = by_severity[severity]
        if not findings_list:
            continue
        
        story.append(Spacer(1, 0.2 * inch))
        story.append(Paragraph(f"{severity} Severity ({len(findings_list)} findings)", styles['Heading3']))
        story.append(Spacer(1, 0.1 * inch))
        
        for idx, finding in enumerate(findings_list[:50], 1):  # Limit to 50 per severity
            title = finding.get("title", "Untitled")
            tool = finding.get("tool", "unknown")
            category = finding.get("category", "N/A")
            
            finding_text = f"<b>{idx}. {title}</b><br/>"
            finding_text += f"Tool: {tool} | Category: {category}<br/>"
            
            if finding.get("file"):
                finding_text += f"Location: {finding['file']}"
                if finding.get("line"):
                    finding_text += f":{finding['line']}"
                finding_text += "<br/>"
            
            if finding.get("description"):
                desc = finding["description"][:200]
                if len(finding["description"]) > 200:
                    desc += "..."
                finding_text += f"<i>{desc}</i><br/>"
            
            story.append(Paragraph(finding_text, styles['Normal']))
            story.append(Spacer(1, 0.1 * inch))
    
    # Footer
    story.append(Spacer(1, 0.5 * inch))
    footer_text = f"Report generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
    story.append(Paragraph(footer_text, ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, textColor=colors.grey, alignment=TA_CENTER)))
    
    # Build PDF
    doc.build(story)
    pdf_content = buffer.getvalue()
    buffer.close()
    
    return pdf_content
