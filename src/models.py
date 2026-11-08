from dataclasses import dataclass
from typing import Optional


@dataclass
class Vulnerability:
    rule_id: str
    rule_name: str
    severity: str
    confidence: str
    message: str
    filename: str
    line_number: int
    code: str
    cwe_id: Optional[int] = None
    cwe_link: Optional[str] = None


@dataclass
class ScanResult:
    vulnerabilities: list[Vulnerability]
    total_findings: int
    high_count: int
    medium_count: int
    low_count: int