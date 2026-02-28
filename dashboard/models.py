from __future__ import annotations

from pydantic import BaseModel


class ScanRecord(BaseModel):
    id: str
    created_at: str
    finished_at: str
    target_type: str
    target_name: str
    target_value: str
    status: str
    policy_status: str
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    unknown_count: int
    raw_report_dir: str
    normalized_report_path: str
    artifacts_json: str
    tools_json: str
    error_message: str | None = None


class FindingRecord(BaseModel):
    id: int
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


class KpiSummary(BaseModel):
    total_scans: int
    total_findings: int
    critical_findings: int
    high_findings: int
    open_targets: int
    last_7d_scans: int
