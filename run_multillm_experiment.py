"""
SecurePatch Multi-LLM Experiment Runner

Runs the SAME Bandit finding through the SAME SecurePatch backend
with:
    - qwen2.5-coder
    - llama3.1
    - codestral

For every model:
    generate patch -> validate in sandbox -> record metrics

Outputs:
    workspace/experiments/multillm_results.json
    workspace/experiments/multillm_results.csv
    workspace/experiments/model_summary.csv

Usage from SecurePatch root:
    python run_multillm_experiment.py --repo sample_repo --max-vulns 3

For a larger benchmark:
    python run_multillm_experiment.py --repo sample_repo --max-vulns 10

The backend must already be running on http://127.0.0.1:8000.
"""

from __future__ import annotations

import argparse
import ast
import csv
import json
import statistics
import time
from pathlib import Path
from typing import Any

import requests


API_DEFAULT = "http://127.0.0.1:8000"

MODELS = [
    ("qwen2.5-coder", "Qwen2.5-Coder 7B"),
    ("llama3.1", "Llama 3.1 8B"),
    ("codestral", "Codestral 22B"),
]

SEVERITY_ORDER = {
    "HIGH": 0,
    "MEDIUM": 1,
    "LOW": 2,
    "UNDEFINED": 3,
}

# These are generally noisy import/dependency findings and are not ideal
# as the first security-patch benchmark targets.
PREFERRED_EXCLUDED_RULES = {
    "B404",  # import subprocess
    "B603",  # subprocess without shell=True
    "B101",  # assert used
}


def request_json(
    session: requests.Session,
    api: str,
    endpoint: str,
    payload: dict[str, Any],
    timeout: int,
) -> tuple[dict[str, Any], float]:
    started = time.perf_counter()
    response = session.post(
        f"{api}{endpoint}",
        json=payload,
        timeout=timeout,
    )
    elapsed = time.perf_counter() - started

    try:
        data = response.json()
    except Exception:
        data = {
            "detail": response.text[:5000],
        }

    if not response.ok:
        message = data.get("detail") or data.get("message") or response.text
        raise RuntimeError(
            f"{endpoint} returned HTTP {response.status_code}: {message}"
        )

    return data, elapsed


def health_check(session: requests.Session, api: str) -> None:
    response = session.get(f"{api}/api/health", timeout=15)
    response.raise_for_status()


def scan_repository(
    session: requests.Session,
    api: str,
    repo_path: str,
) -> dict[str, Any]:
    data, _ = request_json(
        session,
        api,
        "/api/scan",
        {"repo_path": repo_path},
        timeout=120,
    )
    return data


def severity_value(finding: dict[str, Any]) -> str:
    return str(finding.get("issue_severity") or "UNDEFINED").upper()


def select_findings(
    findings: list[dict[str, Any]],
    max_vulns: int,
    include_low: bool,
    only_rule: str | None = None,
) -> list[dict[str, Any]]:
    candidates = []

    for finding in findings:
        rule = str(finding.get("test_id") or "").upper()
        severity = severity_value(finding)

        # If a specific rule was requested, select ONLY that rule.
        if only_rule and rule != only_rule.upper():
            continue

        if not include_low and severity == "LOW":
            continue

        if rule in PREFERRED_EXCLUDED_RULES:
            continue

        if not finding.get("filename") or not finding.get("line_number"):
            continue

        candidates.append(finding)

    candidates.sort(
        key=lambda f: (
            SEVERITY_ORDER.get(severity_value(f), 9),
            str(f.get("filename", "")),
            int(f.get("line_number", 0) or 0),
        )
    )

    selected = []
    seen = set()

    for finding in candidates:
        key = (
            finding.get("test_id"),
            finding.get("filename"),
            finding.get("line_number"),
        )

        if key in seen:
            continue

        seen.add(key)
        selected.append(finding)

        if len(selected) >= max_vulns:
            break

    return selected

def extract_patch(generated: dict[str, Any]) -> str:
    patch = generated.get("patch")

    if isinstance(patch, dict):
        for key in ("function", "patch", "code", "content"):
            value = patch.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

    for key in ("function", "patch", "code", "content"):
        value = generated.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    return ""


def syntax_is_valid(patch_text: str) -> bool:
    if not patch_text.strip():
        return False

    cleaned = patch_text.strip()

    # Be tolerant of fenced output because the backend normally normalizes it.
    if "```" in cleaned:
        cleaned = (
            cleaned.replace("```python", "")
            .replace("```py", "")
            .replace("```", "")
            .strip()
        )

    try:
        tree = ast.parse(cleaned)
    except SyntaxError:
        return False

    functions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]

    return len(functions) == 1


def safe_bool(value: Any) -> bool:
    return bool(value) if value is not None else False


def make_result(
    *,
    model_key: str,
    model_name: str,
    finding: dict[str, Any],
    generated: dict[str, Any] | None,
    generation_seconds: float | None,
    validation: dict[str, Any] | None,
    error: str | None,
) -> dict[str, Any]:
    patch_text = extract_patch(generated or {})

    patch_meta = (
        generated.get("patch")
        if isinstance(generated, dict)
        else {}
    )
    if not isinstance(patch_meta, dict):
        patch_meta = {}

    regression = (
        validation.get("regression", {})
        if isinstance(validation, dict)
        else {}
    )
    security = (
        validation.get("security", {})
        if isinstance(validation, dict)
        else {}
    )

    status = (
        validation.get("status")
        if isinstance(validation, dict)
        else "ERROR"
    )

    return {
        "model": model_key,
        "model_name": model_name,
        "vulnerability": finding.get("test_id"),
        "severity": severity_value(finding),
        "file": finding.get("filename"),
        "line": finding.get("line_number"),
        "issue": finding.get("issue_text"),
        "patch_generated": bool(patch_text),
        "syntax_valid": syntax_is_valid(patch_text),
        "vulnerability_removed": safe_bool(
            security.get("target_removed")
        ),
        "security_passed": safe_bool(security.get("passed")),
        "regression_passed": safe_bool(regression.get("passed")),
        "tests_passed": int(regression.get("passed_count") or 0),
        "tests_failed": int(regression.get("failed_count") or 0),
        "test_errors": int(regression.get("error_count") or 0),
        "bandit_findings_after": int(
            security.get("findings_after") or 0
        ),
        "final_verdict": status,
        "patch_applied": safe_bool(
            (validation or {}).get("patch", {}).get("applied")
            if isinstance((validation or {}).get("patch"), dict)
            else False
        ),
        "generation_latency_seconds": generation_seconds,
        "input_tokens": patch_meta.get("input_tokens"),
        "output_tokens": patch_meta.get("output_tokens"),
        "total_tokens": patch_meta.get("total_tokens"),
        "provider": patch_meta.get("provider"),
        "resolved_model": patch_meta.get("model"),
        "error": error,
        # Keep the raw result so nothing is lost for later analysis.
        "raw_generation": generated,
        "raw_validation": validation,
        "patch_text": patch_text,
    }


def run_experiment(
    repo_path: str,
    api: str,
    max_vulns: int,
    include_low: bool,
    timeout: int,
    output_dir: Path,
    only_rule: str | None = None,
) -> list[dict[str, Any]]:
    session = requests.Session()
    session.headers.update(
        {
            "Content-Type": "application/json",
            "User-Agent": "SecurePatch-MultiLLM-Experiment/1.0",
        }
    )

    print("=" * 72)
    print("SECUREPATCH MULTI-LLM EXPERIMENT")
    print("=" * 72)
    print(f"Backend : {api}")
    print(f"Repository: {repo_path}")
    print(f"Models  : {', '.join(key for key, _ in MODELS)}")
    print()

    print("[1/4] Checking backend...")
    health_check(session, api)
    print("      OK")

    print("[2/4] Running Bandit scan...")
    scan = scan_repository(session, api, repo_path)
    findings = scan.get("findings", [])
    print(f"      Total findings: {len(findings)}")

    selected = select_findings(
        findings,
        max_vulns=max_vulns,
        include_low=include_low,
        only_rule=only_rule,
    )

    if not selected:
        raise RuntimeError(
            "No suitable Bandit findings were found. "
            "Try --include-low or use a repository with security findings."
        )

    print(
        f"      Selected {len(selected)} vulnerabilities for the benchmark:"
    )
    for i, finding in enumerate(selected, 1):
        print(
            f"        {i}. {finding.get('test_id')} "
            f"{severity_value(finding)} "
            f"{finding.get('filename')}:{finding.get('line_number')}"
        )

    print()
    print("[3/4] Generating + validating every model...")
    print()

    results: list[dict[str, Any]] = []

    total_runs = len(selected) * len(MODELS)
    run_number = 0

    for vuln_index, finding in enumerate(selected, 1):
        print("-" * 72)
        print(
            f"VULNERABILITY {vuln_index}/{len(selected)}: "
            f"{finding.get('test_id')} "
            f"({severity_value(finding)}) "
            f"{finding.get('filename')}:{finding.get('line_number')}"
        )
        print("-" * 72)

        for model_key, model_name in MODELS:
            run_number += 1
            print(
                f"[{run_number}/{total_runs}] "
                f"{model_name} -> generate",
                flush=True,
            )

            generated = None
            validation = None
            generation_seconds = None
            error = None

            try:
                generated, generation_seconds = request_json(
                    session,
                    api,
                    "/api/generate-patch",
                    {
                        "repo_path": repo_path,
                        "file_path": finding["filename"],
                        "line": finding["line_number"],
                        "model": model_key,
                    },
                    timeout=timeout,
                )

                patch = extract_patch(generated)
                print(
                    f"      generated={bool(patch)} "
                    f"latency={generation_seconds:.2f}s "
                    f"syntax={syntax_is_valid(patch)}"
                )

                if not patch:
                    raise RuntimeError(
                        "Backend returned no usable patch."
                    )

                print("      validating in isolated sandbox...", flush=True)

                validation, _ = request_json(
                    session,
                    api,
                    "/api/validate",
                    {
                        "repo_path": repo_path,
                        "file_path": finding["filename"],
                        "line": finding["line_number"],
                        "patch": patch,
                    },
                    timeout=timeout,
                )

                print(
                    f"      verdict={validation.get('status')} "
                    f"security={validation.get('security', {}).get('passed')} "
                    f"removed={validation.get('security', {}).get('target_removed')} "
                    f"regression={validation.get('regression', {}).get('passed')}"
                )

            except Exception as exc:
                error = str(exc)
                print(f"      ERROR: {error}")

            result = make_result(
                model_key=model_key,
                model_name=model_name,
                finding=finding,
                generated=generated,
                generation_seconds=generation_seconds,
                validation=validation,
                error=error,
            )
            results.append(result)

    print()
    print("[4/4] Writing experiment results...")
    output_dir.mkdir(parents=True, exist_ok=True)

    json_path = output_dir / "multillm_results.json"
    csv_path = output_dir / "multillm_results.csv"
    summary_path = output_dir / "model_summary.csv"

    json_path.write_text(
        json.dumps(
            {
                "experiment": {
                    "repo_path": repo_path,
                    "backend": api,
                    "models": [
                        {
                            "key": key,
                            "name": name,
                        }
                        for key, name in MODELS
                    ],
                    "vulnerabilities_tested": len(selected),
                    "runs": len(results),
                    "timestamp": time.strftime(
                        "%Y-%m-%dT%H:%M:%S"
                    ),
                },
                "findings": selected,
                "results": results,
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )

    csv_fields = [
        "model",
        "model_name",
        "vulnerability",
        "severity",
        "file",
        "line",
        "patch_generated",
        "syntax_valid",
        "vulnerability_removed",
        "security_passed",
        "regression_passed",
        "tests_passed",
        "tests_failed",
        "test_errors",
        "bandit_findings_after",
        "final_verdict",
        "patch_applied",
        "generation_latency_seconds",
        "input_tokens",
        "output_tokens",
        "total_tokens",
        "provider",
        "resolved_model",
        "error",
    ]

    with csv_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=csv_fields,
            extrasaction="ignore",
        )
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    summary_rows = build_model_summary(results)

    with summary_path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        fields = [
            "model",
            "runs",
            "patch_generation_rate",
            "syntax_valid_rate",
            "security_fix_rate",
            "regression_pass_rate",
            "verified_rate",
            "avg_latency_seconds",
            "median_latency_seconds",
            "avg_output_tokens",
        ]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(summary_rows)

    print()
    print("=" * 72)
    print("EXPERIMENT COMPLETE")
    print("=" * 72)
    print(f"JSON    : {json_path}")
    print(f"CSV     : {csv_path}")
    print(f"SUMMARY : {summary_path}")
    print()
    print_summary(summary_rows)

    return results


def build_model_summary(
    results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = []

    for model_key, _ in MODELS:
        model_rows = [
            r for r in results if r["model"] == model_key
        ]

        if not model_rows:
            continue

        def rate(predicate):
            return round(
                100
                * sum(bool(predicate(r)) for r in model_rows)
                / len(model_rows),
                2,
            )

        latencies = [
            float(r["generation_latency_seconds"])
            for r in model_rows
            if r["generation_latency_seconds"] is not None
        ]

        output_tokens = [
            int(r["output_tokens"])
            for r in model_rows
            if r["output_tokens"] is not None
        ]

        rows.append(
            {
                "model": model_key,
                "runs": len(model_rows),
                "patch_generation_rate": rate(
                    lambda r: r["patch_generated"]
                ),
                "syntax_valid_rate": rate(
                    lambda r: r["syntax_valid"]
                ),
                "security_fix_rate": rate(
                    lambda r: r["vulnerability_removed"]
                ),
                "regression_pass_rate": rate(
                    lambda r: r["regression_passed"]
                ),
                "verified_rate": rate(
                    lambda r: r["final_verdict"] == "VERIFIED"
                ),
                "avg_latency_seconds": round(
                    statistics.mean(latencies), 2
                )
                if latencies
                else None,
                "median_latency_seconds": round(
                    statistics.median(latencies), 2
                )
                if latencies
                else None,
                "avg_output_tokens": round(
                    statistics.mean(output_tokens), 2
                )
                if output_tokens
                else None,
            }
        )

    return rows


def print_summary(rows: list[dict[str, Any]]) -> None:
    if not rows:
        return

    print(
        f"{'MODEL':<20}"
        f"{'RUNS':>6}"
        f"{'SECURITY':>12}"
        f"{'REGRESSION':>13}"
        f"{'VERIFIED':>11}"
        f"{'AVG LATENCY':>15}"
    )
    print("-" * 80)

    labels = {
        "qwen2.5-coder": "Qwen2.5-Coder",
        "llama3.1": "Llama 3.1",
        "codestral": "Codestral",
    }

    for row in rows:
        print(
            f"{labels.get(row['model'], row['model']):<20}"
            f"{row['runs']:>6}"
            f"{row['security_fix_rate']:>11.2f}%"
            f"{row['regression_pass_rate']:>12.2f}%"
            f"{row['verified_rate']:>10.2f}%"
            f"{str(row['avg_latency_seconds']):>14}s"
        )


def main():
    parser = argparse.ArgumentParser(
        description="Run SecurePatch's local multi-LLM security benchmark."
    )
    parser.add_argument(
        "--repo",
        required=True,
        help="Repository path known to SecurePatch, e.g. sample_repo",
    )
    parser.add_argument(
        "--api",
        default=API_DEFAULT,
        help=f"SecurePatch backend URL (default: {API_DEFAULT})",
    )
    parser.add_argument(
        "--max-vulns",
        type=int,
        default=5,
        help="Number of Bandit findings to benchmark (default: 5)",
    )
    parser.add_argument(
        "--include-low",
        action="store_true",
        help="Also include LOW severity findings.",
    )
    parser.add_argument(
        "--only-rule",
        type=str,
        default=None,
        help="Run only one Bandit rule, e.g. B105.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=1800,
        help="Timeout per generation/validation request in seconds.",
    )
    parser.add_argument(
        "--output-dir",
        default="workspace/experiments",
        help="Directory for JSON/CSV experiment results.",
    )

    args = parser.parse_args()

    if args.max_vulns < 1:
        parser.error("--max-vulns must be >= 1")

    run_experiment(
        repo_path=args.repo,
        api=args.api.rstrip("/"),
        max_vulns=args.max_vulns,
        include_low=args.include_low,
        timeout=args.timeout,
        output_dir=Path(args.output_dir),
        only_rule=args.only_rule,
    )


if __name__ == "__main__":
    main()
