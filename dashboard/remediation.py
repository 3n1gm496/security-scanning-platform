"""
Enhanced Remediation System for Security Findings.

Provides AI-assisted remediation suggestions, code fixes, and actionable guidance.
"""

from __future__ import annotations

import re
from typing import Any


class RemediationEngine:
    """Generate actionable remediation guidance for security findings."""

    # CWE -> Remediation templates
    CWE_REMEDIATION = {
        "CWE-79": {
            "title": "Cross-Site Scripting (XSS)",
            "steps": [
                "Sanitize all user input before rendering in HTML",
                "Use context-aware output encoding (HTML, JavaScript, URL)",
                "Implement Content Security Policy (CSP) headers",
                "Use templating engines with auto-escaping enabled",
            ],
            "code_example": """# Python Flask Example
from markupsafe import escape

@app.route('/user/<username>')
def show_user(username):
    # SAFE: Auto-escape user input
    return render_template('user.html', username=escape(username))

# Or use Jinja2 auto-escaping (enabled by default)
{{ username }}  <!-- Auto-escaped -->
{{ username | safe }}  <!-- Only if you trust the source! -->
""",
            "references": [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            ],
        },
        "CWE-89": {
            "title": "SQL Injection",
            "steps": [
                "Use parameterized queries (prepared statements) instead of string concatenation",
                "Use ORM frameworks with built-in protection (Django ORM, SQLAlchemy)",
                "Apply input validation with allowlists",
                "Use least-privilege database accounts",
            ],
            "code_example": """# VULNERABLE
cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")

# SAFE: Parameterized query
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))

# SAFE: SQLAlchemy ORM
user = session.query(User).filter(User.username == username).first()
""",
            "references": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            ],
        },
        "CWE-798": {
            "title": "Hardcoded Credentials",
            "steps": [
                "Remove hardcoded secrets from source code",
                "Use environment variables or secret management systems (Vault, AWS Secrets Manager)",
                "Rotate compromised credentials immediately",
                "Implement secret scanning in CI/CD pipeline",
            ],
            "code_example": """# VULNERABLE
API_KEY = "hardcoded-demo-key-not-for-production"

# SAFE: Environment variables
import os
API_KEY = os.getenv("API_KEY")
if not API_KEY:
    raise ValueError("API_KEY environment variable not set")

# SAFE: Secret management
from vault import VaultClient
vault = VaultClient()
API_KEY = vault.get_secret("api_key")
""",
            "references": [
                "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            ],
        },
        "CWE-22": {
            "title": "Path Traversal",
            "steps": [
                "Validate and sanitize all file paths",
                "Use allowlists for permitted directories",
                "Reject paths containing '../' or absolute paths",
                "Use safe path joining functions (os.path.join, pathlib)",
            ],
            "code_example": """# VULNERABLE
file_path = "/data/" + user_input
with open(file_path, 'r') as f:
    content = f.read()

# SAFE: Path validation
from pathlib import Path

BASE_DIR = Path("/data")
user_file = Path(user_input).name  # Extract filename only
safe_path = (BASE_DIR / user_file).resolve()

# Ensure path is within BASE_DIR
if not str(safe_path).startswith(str(BASE_DIR)):
    raise ValueError("Invalid file path")

with open(safe_path, 'r') as f:
    content = f.read()
""",
            "references": [
                "https://owasp.org/www-community/attacks/Path_Traversal",
                "https://cwe.mitre.org/data/definitions/22.html",
            ],
        },
        "CWE-78": {
            "title": "OS Command Injection",
            "steps": [
                "Avoid shell execution with user input",
                "Use subprocess with argument list (not shell=True)",
                "Validate and sanitize all command arguments",
                "Use safe alternatives (libraries instead of shell commands)",
            ],
            "code_example": """# VULNERABLE
import os
os.system("ping " + user_input)

# SAFE: subprocess with argument list
import subprocess
result = subprocess.run(
    ["ping", "-c", "4", user_input],
    capture_output=True,
    check=True,
    shell=False  # CRITICAL: Never use shell=True with user input
)

# BETTER: Use libraries instead of shell commands
import icmplib
icmplib.ping(user_input, count=4)
""",
            "references": [
                "https://owasp.org/www-community/attacks/Command_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
            ],
        },
    }

    # Severity -> Priority mapping
    SEVERITY_PRIORITY = {
        "CRITICAL": "🔴 URGENT - Fix immediately (within 24h)",
        "HIGH": "🟠 High Priority - Fix within 1 week",
        "MEDIUM": "🟡 Medium Priority - Fix within 1 month",
        "LOW": "🟢 Low Priority - Address in next sprint",
        "INFO": "ℹ️ Informational - Review and document",
    }

    @staticmethod
    def generate_remediation(finding: dict[str, Any]) -> dict[str, Any]:
        """Generate comprehensive remediation guidance for a finding.

        Args:
            finding: Finding dict with keys: severity, category, title, description, cve, file, line

        Returns:
            Dict with: priority, steps, code_example, references, estimated_effort
        """
        severity = finding.get("severity", "MEDIUM").upper()
        category = finding.get("category", "")
        title = finding.get("title", "")
        description = finding.get("description", "")
        cve = finding.get("cve", "")
        explicit_cwe = finding.get("cwe", "")

        # Extract CWE from various fields
        cwe = None
        for field in [explicit_cwe, cve, title, description, category]:
            if field and "CWE-" in str(field).upper():
                match = re.search(r"CWE-(\d+)", str(field).upper())
                if match:
                    cwe = f"CWE-{match.group(1)}"
                    break

        # Get template if CWE matched
        remediation_template = RemediationEngine.CWE_REMEDIATION.get(cwe, None)

        if remediation_template:
            return {
                "priority": RemediationEngine.SEVERITY_PRIORITY.get(severity, "Medium Priority"),
                "cwe": cwe,
                "title": remediation_template["title"],
                "steps": remediation_template["steps"],
                "code_example": remediation_template.get("code_example", ""),
                "references": remediation_template.get("references", []),
                "estimated_effort": RemediationEngine._estimate_effort(severity, finding),
                "automated_fix_available": False,  # Placeholder for future ML-based fixes
            }

        # Fallback generic guidance
        return RemediationEngine._generic_remediation(severity, category, title, description)

    @staticmethod
    def _estimate_effort(severity: str, finding: dict[str, Any]) -> str:
        """Estimate remediation effort based on severity and context."""
        has_location = finding.get("file") and finding.get("line")

        if severity == "CRITICAL":
            return "2-4 hours" if has_location else "4-8 hours"
        elif severity == "HIGH":
            return "4-8 hours" if has_location else "1-2 days"
        elif severity == "MEDIUM":
            return "1-2 days" if has_location else "2-4 days"
        else:
            return "1-4 days"

    @staticmethod
    def _generic_remediation(severity: str, category: str, title: str, description: str) -> dict[str, Any]:
        """Generate generic remediation guidance when no specific template exists."""
        steps = []

        # Category-based generic guidance
        if "secret" in category.lower():
            steps = [
                "Revoke and rotate the exposed secret immediately",
                "Remove secret from git history (git filter-branch or BFG Repo-Cleaner)",
                "Move secret to environment variables or secret manager",
                "Add secret patterns to .gitignore and pre-commit hooks",
            ]
        elif "sca" in category.lower() or "vulnerability" in category.lower():
            steps = [
                "Update the vulnerable dependency to the latest patched version",
                "Check release notes for breaking changes",
                "Run regression tests after update",
                "If update not possible, apply vendor security patch or implement workaround",
            ]
        elif "iac" in category.lower():
            steps = [
                "Review infrastructure-as-code configuration",
                "Apply principle of least privilege",
                "Enable security monitoring and logging",
                "Document exceptions if configuration is intentional",
            ]
        else:
            steps = [
                "Review the finding details and assess exploitability",
                "Consult security team for remediation approach",
                "Implement fix in development environment first",
                "Test thoroughly before deploying to production",
            ]

        return {
            "priority": RemediationEngine.SEVERITY_PRIORITY.get(severity, "Medium Priority"),
            "cwe": None,
            "title": "Generic Security Fix",
            "steps": steps,
            "code_example": "",
            "references": [
                "https://owasp.org/www-project-top-ten/",
                "https://cwe.mitre.org/",
            ],
            "estimated_effort": RemediationEngine._estimate_effort(severity, {}),
            "automated_fix_available": False,
        }


def enrich_finding_with_remediation(finding: dict[str, Any]) -> dict[str, Any]:
    """Enrich a finding dict with remediation guidance.

    Args:
        finding: Original finding dict

    Returns:
        Finding dict with added 'remediation_guide' key
    """
    remediation = RemediationEngine.generate_remediation(finding)
    finding["remediation_guide"] = remediation
    return finding
