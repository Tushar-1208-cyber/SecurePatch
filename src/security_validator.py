from src.scanner import run_bandit


def validate_security(
    repo_path: str,
    original_rule_id: str,
    original_filename: str,
    original_line: int
) -> dict:
    """
    Re-scan the patched repository and check whether
    the original security vulnerability still exists.
    """

    result = run_bandit(repo_path)

    matching_findings = []

    for vulnerability in result.vulnerabilities:

        same_rule = (
            vulnerability.rule_id == original_rule_id
        )

        same_file = (
            vulnerability.filename.endswith(
                original_filename.split("/")[-1]
            )
        )

        if same_rule and same_file:

            matching_findings.append(
                vulnerability
            )

    vulnerability_removed = (
        len(matching_findings) == 0
    )

    return {
        "secure": vulnerability_removed,
        "remaining_findings": matching_findings,
        "total_findings": result.total_findings,
        "high_count": result.high_count,
        "medium_count": result.medium_count,
        "low_count": result.low_count
    }
