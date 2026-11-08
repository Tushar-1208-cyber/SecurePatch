from pathlib import Path
import ast
import csv
import json
import re
import shutil
import subprocess
import tempfile
import time


# ============================================================
# CONFIG
# ============================================================

ROOT = Path(__file__).resolve().parent

REPO = ROOT / "sample_repo"

OUT = (
    ROOT
    / "workspace"
    / "experiments"
    / "final_rule_baseline"
)

OUT.mkdir(parents=True, exist_ok=True)


# ============================================================
# BENCHMARK
# ============================================================

VULNERABILITIES = [
    {
        "rule": "B102",
        "file": "benchmark_vulnerabilities.py",
        "line": 30,
        "severity": "MEDIUM",
    },
    {
        "rule": "B105",
        "file": "benchmark_vulnerabilities.py",
        "line": 111,
        "severity": "LOW",
    },
    {
        "rule": "B108",
        "file": "benchmark_vulnerabilities.py",
        "line": 97,
        "severity": "MEDIUM",
    },
    {
        "rule": "B202",
        "file": "benchmark_vulnerabilities.py",
        "line": 86,
        "severity": "HIGH",
    },
    {
        "rule": "B301",
        "file": "services/file_service.py",
        "line": 33,
        "severity": "MEDIUM",
    },
    {
        "rule": "B307",
        "file": "benchmark_vulnerabilities.py",
        "line": 21,
        "severity": "MEDIUM",
    },
    {
        "rule": "B324",
        "file": "benchmark_vulnerabilities.py",
        "line": 40,
        "severity": "HIGH",
    },
    {
        "rule": "B506",
        "file": "benchmark_vulnerabilities.py",
        "line": 51,
        "severity": "MEDIUM",
    },
    {
        "rule": "B602",
        "file": "services/command_service.py",
        "line": 18,
        "severity": "HIGH",
    },
    {
        "rule": "B608",
        "file": "benchmark_vulnerabilities.py",
        "line": 67,
        "severity": "MEDIUM",
    },
]


# ============================================================
# RULE-BASED PATCH GENERATOR
# ============================================================

def generate_rule_patch(rule, source):
    """
    Deterministic baseline.

    Returns:
        patched_source, generated
    """

    # --------------------------------------------------------
    # B602 — subprocess shell=True
    # --------------------------------------------------------
    if rule == "B602":
        if "shell=True" in source:
            return source.replace(
                "shell=True",
                "shell=False",
                1
            ), True

    # --------------------------------------------------------
    # B324 — MD5
    # --------------------------------------------------------
    if rule == "B324":
        if "hashlib.md5(" in source:
            return source.replace(
                "hashlib.md5(",
                "hashlib.sha256(",
                1
            ), True

    # --------------------------------------------------------
    # B506 — yaml.load
    # --------------------------------------------------------
    if rule == "B506":
        if "yaml.load(" in source:
            return source.replace(
                "yaml.load(",
                "yaml.safe_load(",
                1
            ), True

    # --------------------------------------------------------
    # B307 — eval
    # --------------------------------------------------------
    if rule == "B307":
        if "eval(" in source:
            return source.replace(
                "eval(",
                "ast.literal_eval(",
                1
            ), True

    # --------------------------------------------------------
    # B102 — exec
    #
    # Cannot safely infer intended replacement automatically.
    # Therefore baseline refuses to patch.
    # --------------------------------------------------------
    if rule == "B102":
        return source, False

    # --------------------------------------------------------
    # B202 — tar extraction
    #
    # Requires semantic path validation, so baseline refuses.
    # --------------------------------------------------------
    if rule == "B202":
        return source, False

    # --------------------------------------------------------
    # B301 — pickle
    #
    # Requires understanding of serialization format.
    # --------------------------------------------------------
    if rule == "B301":
        return source, False

    # --------------------------------------------------------
    # B608 — SQL injection
    #
    # Requires restructuring query construction.
    # --------------------------------------------------------
    if rule == "B608":
        return source, False

    # --------------------------------------------------------
    # B108 — insecure temporary file
    # --------------------------------------------------------
    if rule == "B108":
        if '"/tmp/securepatch_temp.txt"' in source:
            return source.replace(
                '"/tmp/securepatch_temp.txt"',
                "tempfile.mkstemp()[1]",
                1
            ), True

    # --------------------------------------------------------
    # B105 — hardcoded password
    #
    # Cannot automatically invent a correct secret-management
    # strategy, so baseline refuses.
    # --------------------------------------------------------
    if rule == "B105":
        return source, False

    return source, False


# ============================================================
# BANDIT
# ============================================================

def run_bandit(repo):
    result = subprocess.run(
        [
            "python",
            "-m",
            "bandit",
            "-r",
            str(repo),
            "-f",
            "json",
        ],
        capture_output=True,
        text=True,
    )

    try:
        return json.loads(result.stdout)
    except Exception:
        return {"results": []}


# ============================================================
# CHECK TARGET VULNERABILITY
# ============================================================

def target_removed(bandit_data, rule, file_name, original_line):
    """
    Checks whether the same Bandit rule still appears
    in approximately the same target file.
    """

    target_name = Path(file_name).as_posix().replace("\\", "/")

    for finding in bandit_data.get("results", []):

        found_rule = finding.get("test_id")

        found_file = (
            Path(finding.get("filename", ""))
            .as_posix()
            .replace("\\", "/")
        )

        if found_rule != rule:
            continue

        if not found_file.endswith(target_name):
            continue

        return False

    return True


# ============================================================
# SYNTAX
# ============================================================

def syntax_valid(repo):
    for py_file in repo.rglob("*.py"):

        try:
            ast.parse(
                py_file.read_text(
                    encoding="utf-8",
                    errors="ignore"
                )
            )
        except Exception:
            return False

    return True


# ============================================================
# PYTEST
# ============================================================

def run_pytest(repo):

    tests_dir = repo / "tests"

    if not tests_dir.exists():
        return {
            "passed": False,
            "tests": 0,
            "errors": 0,
        }

    result = subprocess.run(
        [
            "python",
            "-m",
            "pytest",
            "tests",
            "-q",
        ],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=120,
    )

    output = result.stdout + "\n" + result.stderr

    match = re.search(
        r"(\d+)\s+passed",
        output
    )

    passed_tests = (
        int(match.group(1))
        if match
        else 0
    )

    return {
        "passed": result.returncode == 0,
        "tests": passed_tests,
        "errors": 0 if result.returncode == 0 else 1,
    }


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("SECUREPATCH — RULE-BASED BASELINE")
    print("=" * 70)

    results = []

    for index, vuln in enumerate(VULNERABILITIES, start=1):

        print(
            f"\n[{index}/{len(VULNERABILITIES)}] "
            f"{vuln['rule']} "
            f"{vuln['file']}:{vuln['line']}"
        )

        start = time.perf_counter()

        with tempfile.TemporaryDirectory(
            prefix=f"baseline_{vuln['rule']}_"
        ) as tmp:

            sandbox = Path(tmp) / "repo"

            shutil.copytree(
                REPO,
                sandbox
            )

            target = sandbox / vuln["file"]

            source = target.read_text(
                encoding="utf-8"
            )

            patched_source, generated = (
                generate_rule_patch(
                    vuln["rule"],
                    source
                )
            )

            if generated:

                target.write_text(
                    patched_source,
                    encoding="utf-8"
                )

            valid = syntax_valid(sandbox)

            test_result = {
                "passed": False,
                "tests": 0,
                "errors": 0,
            }

            if valid:
                test_result = run_pytest(
                    sandbox
                )

            bandit_after = run_bandit(
                sandbox
            )

            removed = target_removed(
                bandit_after,
                vuln["rule"],
                vuln["file"],
                vuln["line"]
            )

            verified = (
                generated
                and valid
                and removed
                and test_result["passed"]
            )

            latency = (
                time.perf_counter()
                - start
            )

            result = {
                "baseline": "rule_based",
                "vulnerability": vuln["rule"],
                "severity": vuln["severity"],
                "file": vuln["file"],
                "line": vuln["line"],
                "patch_generated": generated,
                "syntax_valid": valid,
                "vulnerability_removed": removed,
                "regression_passed": test_result["passed"],
                "tests_passed": test_result["tests"],
                "test_errors": test_result["errors"],
                "final_verdict": (
                    "VERIFIED"
                    if verified
                    else "REJECTED"
                ),
                "latency_seconds": round(
                    latency,
                    3
                ),
            }

            results.append(result)

            print(
                f"  generated : {generated}"
            )
            print(
                f"  syntax    : {valid}"
            )
            print(
                f"  removed   : {removed}"
            )
            print(
                f"  regression: {test_result['passed']}"
            )
            print(
                f"  verdict   : {result['final_verdict']}"
            )


    # ========================================================
    # SAVE JSON
    # ========================================================

    with open(
        OUT / "rule_baseline_results.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            results,
            f,
            indent=2
        )


    # ========================================================
    # SAVE CSV
    # ========================================================

    with open(
        OUT / "rule_baseline_results.csv",
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=results[0].keys()
        )

        writer.writeheader()
        writer.writerows(results)


    # ========================================================
    # SUMMARY
    # ========================================================

    total = len(results)

    generated = sum(
        r["patch_generated"]
        for r in results
    )

    removed = sum(
        r["vulnerability_removed"]
        for r in results
    )

    regression = sum(
        r["regression_passed"]
        for r in results
    )

    verified = sum(
        r["final_verdict"] == "VERIFIED"
        for r in results
    )

    print("\n")
    print("=" * 70)
    print("RULE-BASED BASELINE SUMMARY")
    print("=" * 70)

    print(
        f"Runs:                 {total}"
    )

    print(
        f"Patch generated:      {generated}/{total} "
        f"({generated / total * 100:.1f}%)"
    )

    print(
        f"Vulnerability removed:{removed}/{total} "
        f"({removed / total * 100:.1f}%)"
    )

    print(
        f"Regression passed:    {regression}/{total} "
        f"({regression / total * 100:.1f}%)"
    )

    print(
        f"VERIFIED:             {verified}/{total} "
        f"({verified / total * 100:.1f}%)"
    )

    print("\nResults:")
    
    for r in results:
        print(
            f"{r['vulnerability']}: "
            f"{r['final_verdict']}"
        )

    print("\nSaved:")
    print(
        OUT / "rule_baseline_results.csv"
    )
    print(
        OUT / "rule_baseline_results.json"
    )


if __name__ == "__main__":
    main()