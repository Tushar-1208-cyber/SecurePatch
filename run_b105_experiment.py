import json
import csv
import requests
from pathlib import Path

BACKEND = "http://127.0.0.1:8000"

REPO = "sample_repo"

MODELS = [
    ("Qwen2.5-Coder 7B", "qwen2.5-coder"),
    ("Llama 3.1 8B", "llama3.1"),
    ("Codestral 22B", "codestral"),
]

# B105 location from our benchmark file
FINDING = {
    "test_id": "B105",
    "severity": "LOW",
    "file": "benchmark_vulnerabilities.py",
    "line": 111,
}

results = []

print("=" * 72)
print("SECUREPATCH — B105 ONLY EXPERIMENT")
print("=" * 72)

# Check backend
try:
    r = requests.get(f"{BACKEND}/api/health", timeout=10)
    r.raise_for_status()
    print("Backend: OK")
except Exception as e:
    print("Backend ERROR:", e)
    raise SystemExit(1)

print()
print("Target:")
print(f"  {FINDING['test_id']} {FINDING['severity']}")
print(f"  {FINDING['file']}:{FINDING['line']}")
print()
print("Running 3 models...")
print()

for i, (model_name, model_id) in enumerate(MODELS, 1):

    print("-" * 72)
    print(f"[{i}/3] {model_name}")
    print("-" * 72)

    result = {
        "model": model_name,
        "model_id": model_id,
        "vulnerability": FINDING["test_id"],
        "severity": FINDING["severity"],
        "file": FINDING["file"],
        "line": FINDING["line"],
        "generated": False,
        "syntax_valid": False,
        "security_pass": False,
        "vulnerability_removed": False,
        "regression_pass": False,
        "final_verdict": "ERROR",
        "latency_seconds": None,
        "input_tokens": None,
        "output_tokens": None,
        "error": None,
    }

    # ------------------------------------------------------------
    # Generate patch
    # ------------------------------------------------------------
    payload = {
        "repo_path": REPO,
        "file_path": FINDING["file"],
        "line": FINDING["line"],
        "model": model_id,
    }

    try:
        response = requests.post(
            f"{BACKEND}/api/generate-patch",
            json=payload,
            timeout=1800,
        )

        if response.status_code != 200:
            raise RuntimeError(
                f"HTTP {response.status_code}: {response.text}"
            )

        data = response.json()

        result["generated"] = bool(data.get("patch"))

        result["latency_seconds"] = data.get("latency_seconds")
        result["input_tokens"] = data.get("input_tokens")
        result["output_tokens"] = data.get("output_tokens")

        patch = data.get("patch", "")

        # --------------------------------------------------------
        # Syntax check
        # --------------------------------------------------------
        import ast

        try:
            ast.parse(patch)
            result["syntax_valid"] = True
        except Exception:
            result["syntax_valid"] = False

        print(
            f"generated={result['generated']} "
            f"latency={result['latency_seconds']}s "
            f"syntax={result['syntax_valid']}"
        )

        if not result["generated"] or not result["syntax_valid"]:
            result["final_verdict"] = "REJECTED"
            results.append(result)
            continue

        # --------------------------------------------------------
        # Validate patch
        # --------------------------------------------------------
        print("validating in isolated sandbox...")

        validate_payload = {
            "repo_path": REPO,
            "file_path": FINDING["file"],
            "line": FINDING["line"],
            "patch": patch,
        }

        vr = requests.post(
            f"{BACKEND}/api/validate",
            json=validate_payload,
            timeout=1800,
        )

        if vr.status_code != 200:
            raise RuntimeError(
                f"Validation HTTP {vr.status_code}: {vr.text}"
            )

        validation = vr.json()

        result["security_pass"] = bool(
            validation.get("security_pass", False)
        )

        result["vulnerability_removed"] = bool(
            validation.get("target_removed", False)
        )

        result["regression_pass"] = bool(
            validation.get("regression_pass", False)
        )

        result["final_verdict"] = validation.get(
            "verdict",
            "VERIFIED"
            if (
                result["security_pass"]
                and result["regression_pass"]
            )
            else "REJECTED",
        )

        print(
            f"verdict={result['final_verdict']} "
            f"security={result['security_pass']} "
            f"removed={result['vulnerability_removed']} "
            f"regression={result['regression_pass']}"
        )

    except Exception as e:
        result["error"] = str(e)
        result["final_verdict"] = "ERROR"
        print("ERROR:", e)

    results.append(result)


# ================================================================
# Save B105 results separately
# ================================================================

output_dir = Path("workspace/experiments/final_b105")
output_dir.mkdir(parents=True, exist_ok=True)

json_path = output_dir / "b105_results.json"
csv_path = output_dir / "b105_results.csv"

with open(json_path, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)

fieldnames = list(results[0].keys())

with open(csv_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(results)


# ================================================================
# Summary
# ================================================================

print()
print("=" * 72)
print("B105 EXPERIMENT COMPLETE")
print("=" * 72)

for r in results:
    print(
        f"{r['model']:22} "
        f"security={str(r['security_pass']):5} "
        f"regression={str(r['regression_pass']):5} "
        f"verdict={r['final_verdict']}"
    )

print()
print("JSON :", json_path)
print("CSV  :", csv_path)
print("=" * 72)