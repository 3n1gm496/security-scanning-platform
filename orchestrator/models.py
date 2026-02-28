from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class TargetSpec:
    name: str
    type: str
    path: str | None = None
    repo: str | None = None
    ref: str | None = None
    image: str | None = None
    enabled: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def resolved_target(self) -> str:
        if self.type == "git":
            return self.repo or ""
        if self.type == "local":
            return self.path or ""
        if self.type == "image":
            return self.image or ""
        return ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TargetSpec":
        name = data.get("name") or data.get("target_name") or data.get("repo") or data.get("path") or data.get("image") or "unnamed-target"
        target_type = data.get("type")
        if target_type not in {"git", "local", "image"}:
            raise ValueError(f"Unsupported target type: {target_type}")
        return cls(
            name=name,
            type=target_type,
            path=data.get("path"),
            repo=data.get("repo"),
            ref=data.get("ref"),
            image=data.get("image"),
            enabled=bool(data.get("enabled", True)),
            metadata=data.get("metadata") or {},
        )


@dataclass
class Finding:
    scan_id: str
    timestamp: str
    target_type: str
    target_name: str
    tool: str
    category: str
    severity: str
    title: str
    description: str
    file: str | None = None
    line: int | None = None
    package: str | None = None
    version: str | None = None
    cve: str | None = None
    remediation: str | None = None
    raw_reference: str | None = None
    fingerprint: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolExecutionResult:
    tool: str
    enabled: bool
    success: bool
    exit_code: int
    started_at: str
    finished_at: str
    raw_output_path: str | None = None
    stderr: str | None = None
    error: str | None = None
    finding_count: int = 0
    artifact_paths: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    scan_id: str
    started_at: str
    finished_at: str
    target_name: str
    target_type: str
    target_value: str
    status: str
    policy_status: str
    tools: list[ToolExecutionResult]
    findings: list[Finding]
    artifacts: dict[str, str]
    raw_report_dir: str
    normalized_report_path: str
    error_message: str | None = None

    def severity_counts(self) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "UNKNOWN": 0}
        for finding in self.findings:
            sev = (finding.severity or "UNKNOWN").upper()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "target_name": self.target_name,
            "target_type": self.target_type,
            "target_value": self.target_value,
            "status": self.status,
            "policy_status": self.policy_status,
            "severity_counts": self.severity_counts(),
            "tools": [tool.to_dict() for tool in self.tools],
            "artifacts": self.artifacts,
            "raw_report_dir": self.raw_report_dir,
            "normalized_report_path": self.normalized_report_path,
            "findings": [finding.to_dict() for finding in self.findings],
            "error_message": self.error_message,
        }
