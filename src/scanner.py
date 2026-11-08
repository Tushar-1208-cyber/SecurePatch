import json
import subprocess
from pathlib import Path

from src.models import Vulnerability, ScanResult


def run_bandit(repo_path: str) -> ScanResult:
    """
    Run Bandit on a repository and convert the results
    into SecurePatch Vulnerability objects.
    """

    report_path = Path("reports/bandit_report.json")

    report_path.parent.mkdir(exist_ok=True)

    # Remove old report so we don't accidentally read stale results
    if report_path.exists():
        report_path.unlink()

    command = [
        "bandit",
        "-r",
        repo_path,
        "-f",
        "json",
        "-o",
        str(report_path),
        "--skip",
        "B101"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    # Bandit returns non-zero when vulnerabilities are found,
    # so we only raise an error if no report was created.
    if not report_path.exists():
        raise RuntimeError(
            f"Bandit report was not generated.\n{result.stderr}"
        )

    with open(report_path, "r") as file:
        report = json.load(file)

    vulnerabilities = []

    for issue in report.get("results", []):

        cwe = issue.get("issue_cwe") or {}

        vulnerability = Vulnerability(
            rule_id=issue.get("test_id", "UNKNOWN"),
            rule_name=issue.get("test_name", "UNKNOWN"),
            severity=issue.get("issue_severity", "UNKNOWN"),
            confidence=issue.get("issue_confidence", "UNKNOWN"),
            message=issue.get("issue_text", ""),
            filename=issue.get("filename", ""),
            line_number=issue.get("line_number", 0),
            code=issue.get("code", ""),
            cwe_id=cwe.get("id"),
            cwe_link=cwe.get("link")
        )

        vulnerabilities.append(vulnerability)

    high_count = sum(
        v.severity == "HIGH"
        for v in vulnerabilities
    )

    medium_count = sum(
        v.severity == "MEDIUM"
        for v in vulnerabilities
    )

    low_count = sum(
        v.severity == "LOW"
        for v in vulnerabilities
    )

    return ScanResult(
        vulnerabilities=vulnerabilities,
        total_findings=len(vulnerabilities),
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count
    )