"""
Export findings in multiple formats: JSON, CSV, SARIF, HTML.
"""
import csv
import json
import os
from datetime import datetime
from io import StringIO
from typing import List, Dict, Any

# SARIF format version
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"


def export_to_json(findings: List[Dict[str, Any]]) -> str:
    """Export findings to JSON format."""
    output = {
        "version": "1.0",
        "exported_at": datetime.utcnow().isoformat(),
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
        <p>Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
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
