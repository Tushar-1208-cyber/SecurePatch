import json
import csv
from pathlib import Path

# ============================================================
# PATHS
# ============================================================

BASE = Path("workspace/experiments")

FOLDER_9 = BASE / "final_9_vulns"
FOLDER_B105 = BASE / "final_b105"
OUTPUT = BASE / "final_30_runs"

OUTPUT.mkdir(parents=True, exist_ok=True)

FILE_9 = FOLDER_9 / "multillm_results.json"
FILE_B105 = FOLDER_B105 / "multillm_results.json"

# ============================================================
# LOAD RESULTS
# ============================================================

print("=" * 72)
print("SECUREPATCH — COMBINING FINAL EXPERIMENT RESULTS")
print("=" * 72)

print()
print("Loading 9-vulnerability results...")
print(FILE_9)

if not FILE_9.exists():
    raise FileNotFoundError(f"Missing file: {FILE_9}")

print()
print("Loading B105 results...")
print(FILE_B105)

if not FILE_B105.exists():
    raise FileNotFoundError(f"Missing file: {FILE_B105}")


with open(FILE_9, "r", encoding="utf-8") as f:
    data_9 = json.load(f)

with open(FILE_B105, "r", encoding="utf-8") as f:
    data_b105 = json.load(f)


results_9 = data_9.get("results", [])
results_b105 = data_b105.get("results", [])

print()
print(f"Runs from final_9_vulns : {len(results_9)}")
print(f"Runs from final_b105    : {len(results_b105)}")

# ============================================================
# COMBINE
# ============================================================

all_results = results_9 + results_b105

print()
print(f"TOTAL COMBINED RUNS     : {len(all_results)}")

if len(all_results) != 30:
    print()
    print("WARNING:")
    print(f"Expected 30 runs, but found {len(all_results)}.")
    print("Check the source folders before using the final dataset.")
else:
    print("SUCCESS: 30 runs found.")

# ============================================================
# CHECK VULNERABILITIES
# ============================================================

vulnerabilities = sorted(
    set(
        str(row.get("vulnerability"))
        for row in all_results
        if row.get("vulnerability")
    )
)

models = sorted(
    set(
        str(row.get("model_name"))
        for row in all_results
        if row.get("model_name")
    )
)

print()
print("Vulnerabilities found:")
for v in vulnerabilities:
    print(f"  - {v}")

print()
print("Models found:")
for model in models:
    print(f"  - {model}")

# ============================================================
# CHECK DUPLICATES
# ============================================================

keys = []

for row in all_results:
    key = (
        row.get("model"),
        row.get("vulnerability"),
        row.get("file"),
        row.get("line"),
    )
    keys.append(key)

duplicates = []

seen = set()

for key in keys:
    if key in seen:
        duplicates.append(key)
    else:
        seen.add(key)

print()

if duplicates:
    print("WARNING: Duplicate experiment rows found:")
    for d in duplicates:
        print(" ", d)
else:
    print("Duplicate check: PASSED")

# ============================================================
# SAVE COMBINED JSON
# ============================================================

combined_json = {
    "experiment": {
        "name": "SecurePatch Final Multi-LLM Experiment",
        "total_runs": len(all_results),
        "vulnerabilities": len(vulnerabilities),
        "models": models,
        "source_experiments": [
            "final_9_vulns",
            "final_b105",
        ],
    },
    "results": all_results,
}

json_path = OUTPUT / "all_results.json"

with open(json_path, "w", encoding="utf-8") as f:
    json.dump(
        combined_json,
        f,
        indent=2,
        default=str,
    )

# ============================================================
# SAVE COMBINED CSV
# ============================================================

csv_path = OUTPUT / "all_results.csv"

csv_fields = [
    "model",
    "model_name",
    "vulnerability",
    "severity",
    "file",
    "line",
    "issue",
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

with open(
    csv_path,
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

    for row in all_results:
        writer.writerow(row)

# ============================================================
# MODEL SUMMARY
# ============================================================

summary = []

for model in models:

    model_rows = [
        r
        for r in all_results
        if r.get("model_name") == model
    ]

    total = len(model_rows)

    def percentage(values):
        if total == 0:
            return 0.0
        return round(
            100 * sum(bool(v) for v in values) / total,
            2,
        )

    latencies = [
        float(r["generation_latency_seconds"])
        for r in model_rows
        if r.get("generation_latency_seconds") is not None
    ]

    output_tokens = [
        int(r["output_tokens"])
        for r in model_rows
        if r.get("output_tokens") is not None
    ]

    generation_failures = sum(
        not bool(r.get("patch_generated"))
        for r in model_rows
    )

    summary.append(
        {
            "model": model,
            "runs": total,
            "patch_generation_rate": percentage(
                r.get("patch_generated")
                for r in model_rows
            ),
            "syntax_valid_rate": percentage(
                r.get("syntax_valid")
                for r in model_rows
            ),
            "security_fix_rate": percentage(
                r.get("vulnerability_removed")
                for r in model_rows
            ),
            "regression_pass_rate": percentage(
                r.get("regression_passed")
                for r in model_rows
            ),
            "verified_rate": percentage(
                r.get("final_verdict") == "VERIFIED"
                for r in model_rows
            ),
            "generation_failures": generation_failures,
            "avg_latency_seconds": (
                round(sum(latencies) / len(latencies), 2)
                if latencies
                else None
            ),
            "avg_output_tokens": (
                round(sum(output_tokens) / len(output_tokens), 2)
                if output_tokens
                else None
            ),
        }
    )

summary_path = OUTPUT / "model_summary.csv"

summary_fields = [
    "model",
    "runs",
    "patch_generation_rate",
    "syntax_valid_rate",
    "security_fix_rate",
    "regression_pass_rate",
    "verified_rate",
    "generation_failures",
    "avg_latency_seconds",
    "avg_output_tokens",
]

with open(
    summary_path,
    "w",
    newline="",
    encoding="utf-8",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=summary_fields,
    )

    writer.writeheader()
    writer.writerows(summary)

# ============================================================
# PRINT FINAL SUMMARY
# ============================================================

print()
print("=" * 72)
print("FINAL 30-RUN DATASET CREATED")
print("=" * 72)

print()
print(
    f"{'MODEL':<24}"
    f"{'RUNS':>6}"
    f"{'SECURITY':>12}"
    f"{'REGRESSION':>13}"
    f"{'VERIFIED':>11}"
    f"{'FAILURES':>10}"
)

print("-" * 78)

for row in summary:
    print(
        f"{row['model']:<24}"
        f"{row['runs']:>6}"
        f"{row['security_fix_rate']:>11.2f}%"
        f"{row['regression_pass_rate']:>12.2f}%"
        f"{row['verified_rate']:>10.2f}%"
        f"{row['generation_failures']:>10}"
    )

print()
print("Files created:")
print(f"JSON    : {json_path}")
print(f"CSV     : {csv_path}")
print(f"SUMMARY : {summary_path}")

print()
print("Existing folders were NOT modified.")
print("=" * 72)