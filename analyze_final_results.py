from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np


# ============================================================
# CONFIG
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

INPUT_FILE = (
    BASE_DIR
    / "workspace"
    / "experiments"
    / "final_30_runs"
    / "final_30_results.csv"
)

OUTPUT_DIR = (
    BASE_DIR
    / "workspace"
    / "experiments"
    / "final_30_runs"
    / "analysis"
)

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# LOAD DATA
# ============================================================

print("\nLoading results...")

df = pd.read_csv(INPUT_FILE)

print(f"Rows loaded: {len(df)}")

# Convert boolean-like columns
BOOL_COLS = [
    "patch_generated",
    "syntax_valid",
    "vulnerability_removed",
    "security_passed",
    "regression_passed",
    "patch_applied",
]

for col in BOOL_COLS:
    if col in df.columns:
        df[col] = (
            df[col]
            .astype(str)
            .str.lower()
            .map({
                "true": True,
                "false": False
            })
        )

# Numeric columns
NUMERIC_COLS = [
    "generation_latency_seconds",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "tests_passed",
    "tests_failed",
    "test_errors",
    "bandit_findings_after",
]

for col in NUMERIC_COLS:
    if col in df.columns:
        df[col] = pd.to_numeric(df[col], errors="coerce")

# Calculate total tokens if missing
df["total_tokens"] = (
    df["total_tokens"]
    .fillna(df["input_tokens"].fillna(0) + df["output_tokens"].fillna(0))
)

# Generation success
df["generation_success"] = df["patch_generated"] == True

# Verified
df["verified"] = df["final_verdict"].astype(str).str.upper() == "VERIFIED"

# Runtime error
df["generation_error"] = df["final_verdict"].astype(str).str.upper() == "ERROR"

# Rejected
df["rejected"] = df["final_verdict"].astype(str).str.upper() == "REJECTED"


print("\nModels:")
print(df["model_name"].value_counts())

print("\nVulnerabilities:")
print(df["vulnerability"].value_counts())

print("\nSeverity:")
print(df["severity"].value_counts())


# ============================================================
# 1. OVERALL MODEL SUMMARY
# ============================================================

summary = (
    df.groupby("model_name")
    .agg(
        runs=("model_name", "size"),

        patches_generated=("patch_generated", "sum"),

        generation_failures=("generation_error", "sum"),

        syntax_valid=("syntax_valid", "sum"),

        vulnerability_removed=("vulnerability_removed", "sum"),

        security_passed=("security_passed", "sum"),

        regression_passed=("regression_passed", "sum"),

        verified=("verified", "sum"),

        rejected=("rejected", "sum"),

        avg_latency_seconds=("generation_latency_seconds", "mean"),

        avg_input_tokens=("input_tokens", "mean"),

        avg_output_tokens=("output_tokens", "mean"),

        avg_total_tokens=("total_tokens", "mean"),
    )
    .reset_index()
)

summary["generation_success_rate_%"] = (
    summary["patches_generated"] / summary["runs"] * 100
)

summary["syntax_valid_rate_%"] = (
    summary["syntax_valid"] / summary["runs"] * 100
)

summary["security_fix_rate_%"] = (
    summary["vulnerability_removed"] / summary["runs"] * 100
)

summary["regression_pass_rate_%"] = (
    summary["regression_passed"] / summary["runs"] * 100
)

summary["verified_rate_%"] = (
    summary["verified"] / summary["runs"] * 100
)

# Important:
# success conditional on actually generating a patch
summary["conditional_verified_rate_%"] = np.where(
    summary["patches_generated"] > 0,
    summary["verified"] / summary["patches_generated"] * 100,
    0
)

summary = summary.round(2)

summary.to_csv(
    OUTPUT_DIR / "model_performance_summary.csv",
    index=False
)

print("\n============================================================")
print("MODEL PERFORMANCE SUMMARY")
print("============================================================")
print(summary.to_string(index=False))


# ============================================================
# 2. VULNERABILITY-WISE MODEL RESULTS
# ============================================================

vuln_summary = (
    df.groupby(["vulnerability", "severity", "model_name"])
    .agg(
        runs=("model_name", "size"),
        generated=("patch_generated", "sum"),
        generation_errors=("generation_error", "sum"),
        syntax_valid=("syntax_valid", "sum"),
        vulnerability_removed=("vulnerability_removed", "sum"),
        regression_passed=("regression_passed", "sum"),
        verified=("verified", "sum"),
        avg_latency=("generation_latency_seconds", "mean"),
    )
    .reset_index()
)

vuln_summary["verified_rate_%"] = (
    vuln_summary["verified"]
    / vuln_summary["runs"]
    * 100
)

vuln_summary["conditional_verified_rate_%"] = np.where(
    vuln_summary["generated"] > 0,
    vuln_summary["verified"]
    / vuln_summary["generated"]
    * 100,
    0
)

vuln_summary = vuln_summary.round(2)

vuln_summary.to_csv(
    OUTPUT_DIR / "vulnerability_wise_results.csv",
    index=False
)

print("\n============================================================")
print("VULNERABILITY-WISE RESULTS")
print("============================================================")
print(vuln_summary.to_string(index=False))


# ============================================================
# 3. SEVERITY-WISE RESULTS
# ============================================================

severity_summary = (
    df.groupby(["severity", "model_name"])
    .agg(
        runs=("model_name", "size"),
        generated=("patch_generated", "sum"),
        security_fixed=("vulnerability_removed", "sum"),
        regression_passed=("regression_passed", "sum"),
        verified=("verified", "sum"),
        errors=("generation_error", "sum"),
        avg_latency=("generation_latency_seconds", "mean"),
    )
    .reset_index()
)

severity_summary["verified_rate_%"] = (
    severity_summary["verified"]
    / severity_summary["runs"]
    * 100
)

severity_summary["conditional_verified_rate_%"] = np.where(
    severity_summary["generated"] > 0,
    severity_summary["verified"]
    / severity_summary["generated"]
    * 100,
    0
)

severity_summary = severity_summary.round(2)

severity_summary.to_csv(
    OUTPUT_DIR / "severity_wise_results.csv",
    index=False
)


# ============================================================
# 4. OVERALL VULNERABILITY DIFFICULTY
# ============================================================

vulnerability_difficulty = (
    df.groupby(["vulnerability", "severity"])
    .agg(
        total_runs=("vulnerability", "size"),
        patches_generated=("patch_generated", "sum"),
        verified=("verified", "sum"),
        generation_errors=("generation_error", "sum"),
        avg_latency=("generation_latency_seconds", "mean"),
    )
    .reset_index()
)

vulnerability_difficulty["verified_rate_%"] = (
    vulnerability_difficulty["verified"]
    / vulnerability_difficulty["total_runs"]
    * 100
)

vulnerability_difficulty["generation_success_rate_%"] = (
    vulnerability_difficulty["patches_generated"]
    / vulnerability_difficulty["total_runs"]
    * 100
)

vulnerability_difficulty = vulnerability_difficulty.round(2)

vulnerability_difficulty.to_csv(
    OUTPUT_DIR / "vulnerability_difficulty.csv",
    index=False
)


# ============================================================
# 5. LATENCY + TOKEN ANALYSIS
# ============================================================

efficiency = (
    df.groupby("model_name")
    .agg(
        avg_latency_seconds=("generation_latency_seconds", "mean"),
        median_latency_seconds=("generation_latency_seconds", "median"),
        min_latency_seconds=("generation_latency_seconds", "min"),
        max_latency_seconds=("generation_latency_seconds", "max"),
        avg_input_tokens=("input_tokens", "mean"),
        avg_output_tokens=("output_tokens", "mean"),
        avg_total_tokens=("total_tokens", "mean"),
    )
    .reset_index()
)

efficiency = efficiency.round(2)

efficiency.to_csv(
    OUTPUT_DIR / "model_efficiency.csv",
    index=False
)

print("\n============================================================")
print("EFFICIENCY")
print("============================================================")
print(efficiency.to_string(index=False))


# ============================================================
# 6. GENERATION RELIABILITY
# ============================================================

reliability = (
    df.groupby("model_name")
    .agg(
        total_runs=("model_name", "size"),
        successful_generations=("generation_success", "sum"),
        generation_errors=("generation_error", "sum"),
        rejected_patches=("rejected", "sum"),
        verified_patches=("verified", "sum"),
    )
    .reset_index()
)

reliability["generation_success_rate_%"] = (
    reliability["successful_generations"]
    / reliability["total_runs"]
    * 100
)

reliability["runtime_failure_rate_%"] = (
    reliability["generation_errors"]
    / reliability["total_runs"]
    * 100
)

reliability["conditional_patch_success_%"] = np.where(
    reliability["successful_generations"] > 0,
    reliability["verified_patches"]
    / reliability["successful_generations"]
    * 100,
    0
)

reliability = reliability.round(2)

reliability.to_csv(
    OUTPUT_DIR / "generation_reliability.csv",
    index=False
)

print("\n============================================================")
print("GENERATION RELIABILITY")
print("============================================================")
print(reliability.to_string(index=False))


# ============================================================
# GRAPH 1 — VERIFIED RATE
# ============================================================

plt.figure(figsize=(9, 6))

plt.bar(
    summary["model_name"],
    summary["verified_rate_%"]
)

plt.ylabel("Verified Patch Rate (%)")
plt.xlabel("Model")
plt.title("Verified Security Patch Rate by LLM")

plt.ylim(0, 100)

for i, value in enumerate(summary["verified_rate_%"]):
    plt.text(
        i,
        value + 2,
        f"{value:.1f}%",
        ha="center"
    )

plt.xticks(rotation=15)
plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "01_verified_patch_rate.png",
    dpi=300
)

plt.close()


# ============================================================
# GRAPH 2 — GENERATION SUCCESS
# ============================================================

plt.figure(figsize=(9, 6))

plt.bar(
    summary["model_name"],
    summary["generation_success_rate_%"]
)

plt.ylabel("Generation Success (%)")
plt.xlabel("Model")
plt.title("LLM Patch Generation Success Rate")

plt.ylim(0, 100)

for i, value in enumerate(summary["generation_success_rate_%"]):
    plt.text(
        i,
        value + 2,
        f"{value:.1f}%",
        ha="center"
    )

plt.xticks(rotation=15)
plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "02_generation_success.png",
    dpi=300
)

plt.close()


# ============================================================
# GRAPH 3 — CONDITIONAL VERIFIED RATE
# ============================================================

plt.figure(figsize=(9, 6))

plt.bar(
    summary["model_name"],
    summary["conditional_verified_rate_%"]
)

plt.ylabel("Verified Rate Among Generated Patches (%)")
plt.xlabel("Model")
plt.title("Conditional Patch Success Rate")

plt.ylim(0, 100)

for i, value in enumerate(summary["conditional_verified_rate_%"]):
    plt.text(
        i,
        value + 2,
        f"{value:.1f}%",
        ha="center"
    )

plt.xticks(rotation=15)
plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "03_conditional_success.png",
    dpi=300
)

plt.close()


# ============================================================
# GRAPH 4 — LATENCY
# ============================================================

plt.figure(figsize=(9, 6))

plt.bar(
    summary["model_name"],
    summary["avg_latency_seconds"]
)

plt.ylabel("Average Generation Latency (seconds)")
plt.xlabel("Model")
plt.title("Average LLM Generation Latency")

for i, value in enumerate(summary["avg_latency_seconds"]):
    plt.text(
        i,
        value + 2,
        f"{value:.1f}s",
        ha="center"
    )

plt.xticks(rotation=15)
plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "04_average_latency.png",
    dpi=300
)

plt.close()


# ============================================================
# GRAPH 5 — TOKEN USAGE
# ============================================================

x = np.arange(len(summary))
width = 0.25

plt.figure(figsize=(10, 6))

plt.bar(
    x - width,
    summary["avg_input_tokens"],
    width,
    label="Input Tokens"
)

plt.bar(
    x,
    summary["avg_output_tokens"],
    width,
    label="Output Tokens"
)

plt.bar(
    x + width,
    summary["avg_total_tokens"],
    width,
    label="Total Tokens"
)

plt.xticks(
    x,
    summary["model_name"],
    rotation=15
)

plt.ylabel("Average Tokens")
plt.xlabel("Model")
plt.title("Average Token Usage")

plt.legend()

plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "05_token_usage.png",
    dpi=300
)

plt.close()


# ============================================================
# GRAPH 6 — VULNERABILITY × MODEL HEATMAP
# ============================================================

heatmap_data = df.pivot_table(
    index="vulnerability",
    columns="model_name",
    values="verified",
    aggfunc="mean"
) * 100

# Keep vulnerabilities in logical order
preferred_order = [
    "B102",
    "B105",
    "B108",
    "B202",
    "B301",
    "B307",
    "B324",
    "B506",
    "B602",
    "B608",
]

existing_order = [
    x for x in preferred_order
    if x in heatmap_data.index
]

heatmap_data = heatmap_data.reindex(existing_order)

plt.figure(figsize=(10, 7))

plt.imshow(
    heatmap_data.values,
    aspect="auto"
)

plt.colorbar(
    label="Verified (%)"
)

plt.xticks(
    range(len(heatmap_data.columns)),
    heatmap_data.columns,
    rotation=15
)

plt.yticks(
    range(len(heatmap_data.index)),
    heatmap_data.index
)

plt.xlabel("Model")
plt.ylabel("Bandit Vulnerability")
plt.title("Vulnerability-Level Verified Patch Rate")

for i in range(len(heatmap_data.index)):
    for j in range(len(heatmap_data.columns)):

        value = heatmap_data.iloc[i, j]

        if not pd.isna(value):
            plt.text(
                j,
                i,
                f"{value:.0f}%",
                ha="center",
                va="center"
            )

plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "06_vulnerability_model_heatmap.png",
    dpi=300
)

plt.close()


# ============================================================
# GRAPH 7 — SEVERITY PERFORMANCE
# ============================================================

severity_plot = (
    df.groupby(["model_name", "severity"])["verified"]
    .mean()
    .unstack()
    * 100
)

severity_plot.plot(
    kind="bar",
    figsize=(10, 6)
)

plt.ylabel("Verified Rate (%)")
plt.xlabel("Model")
plt.title("Verified Patch Rate by Vulnerability Severity")

plt.ylim(0, 100)

plt.xticks(rotation=15)

plt.legend(
    title="Severity"
)

plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "07_severity_comparison.png",
    dpi=300
)

plt.close()


# ============================================================
# GRAPH 8 — GENERATION ERRORS
# ============================================================

errors = (
    df.groupby("model_name")["generation_error"]
    .sum()
    .reset_index()
)

plt.figure(figsize=(9, 6))

plt.bar(
    errors["model_name"],
    errors["generation_error"]
)

plt.ylabel("Number of Generation Errors")
plt.xlabel("Model")
plt.title("LLM Generation / Runtime Failures")

for i, value in enumerate(errors["generation_error"]):
    plt.text(
        i,
        value + 0.1,
        str(int(value)),
        ha="center"
    )

plt.xticks(rotation=15)

plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "08_generation_errors.png",
    dpi=300
)

plt.close()


# ============================================================
# GRAPH 9 — FINAL VERDICT COUNTS
# ============================================================

verdict_counts = (
    df.groupby(["model_name", "final_verdict"])
    .size()
    .unstack(fill_value=0)
)

verdict_counts.plot(
    kind="bar",
    figsize=(10, 6)
)

plt.ylabel("Number of Runs")
plt.xlabel("Model")
plt.title("Final Validation Verdicts")

plt.xticks(rotation=15)

plt.legend(
    title="Verdict"
)

plt.tight_layout()

plt.savefig(
    OUTPUT_DIR / "09_final_verdicts.png",
    dpi=300
)

plt.close()


# ============================================================
# 10. BEST MODEL ANALYSIS
# ============================================================

best_verified = summary.loc[
    summary["verified_rate_%"].idxmax()
]

best_conditional = summary.loc[
    summary["conditional_verified_rate_%"].idxmax()
]

fastest = summary.loc[
    summary["avg_latency_seconds"].idxmin()
]

lowest_tokens = summary.loc[
    summary["avg_total_tokens"].idxmin()
]


# ============================================================
# 11. TEXT REPORT
# ============================================================

report = []

report.append("=" * 70)
report.append("SECUREPATCH — FINAL MULTI-LLM EXPERIMENT ANALYSIS")
report.append("=" * 70)

report.append("")

report.append(
    f"Total experimental runs: {len(df)}"
)

report.append(
    f"Unique vulnerabilities: {df['vulnerability'].nunique()}"
)

report.append(
    f"Models evaluated: {df['model_name'].nunique()}"
)

report.append("")

report.append("MODELS")
report.append("-" * 70)

for model in df["model_name"].unique():
    report.append(f"- {model}")

report.append("")

report.append("OVERALL MODEL RESULTS")
report.append("-" * 70)

for _, row in summary.iterrows():

    report.append(
        f"{row['model_name']}: "
        f"Verified={row['verified_rate_%']:.2f}%, "
        f"Security Fix={row['security_fix_rate_%']:.2f}%, "
        f"Regression={row['regression_pass_rate_%']:.2f}%, "
        f"Generation Success={row['generation_success_rate_%']:.2f}%, "
        f"Conditional Verified={row['conditional_verified_rate_%']:.2f}%, "
        f"Avg Latency={row['avg_latency_seconds']:.2f}s"
    )

report.append("")

report.append("KEY FINDINGS")
report.append("-" * 70)

report.append(
    f"1. Highest overall verified rate: "
    f"{best_verified['model_name']} "
    f"({best_verified['verified_rate_%']:.2f}%)."
)

report.append(
    f"2. Highest conditional verified rate among successfully "
    f"generated patches: "
    f"{best_conditional['model_name']} "
    f"({best_conditional['conditional_verified_rate_%']:.2f}%)."
)

report.append(
    f"3. Fastest average generation: "
    f"{fastest['model_name']} "
    f"({fastest['avg_latency_seconds']:.2f}s)."
)

report.append(
    f"4. Lowest average token usage: "
    f"{lowest_tokens['model_name']} "
    f"({lowest_tokens['avg_total_tokens']:.2f} tokens)."
)

report.append("")

report.append("GENERATION RELIABILITY")
report.append("-" * 70)

for _, row in reliability.iterrows():

    report.append(
        f"{row['model_name']}: "
        f"{int(row['successful_generations'])}/"
        f"{int(row['total_runs'])} generations successful, "
        f"{int(row['generation_errors'])} runtime failures, "
        f"{row['conditional_patch_success_%']:.2f}% "
        f"verified among generated patches."
    )

report.append("")

report.append("RESEARCH INTERPRETATION")
report.append("-" * 70)

report.append(
    "The experiment evaluates locally deployed LLMs for automated "
    "Python security vulnerability repair using the same repository, "
    "vulnerability instances, context, and automated validation pipeline."
)

report.append(
    "Final verification requires both successful regression testing "
    "and removal of the targeted Bandit vulnerability."
)

report.append(
    "Therefore, syntactically valid patches or patches that pass "
    "regression tests are not automatically considered secure."
)

report.append(
    "Generation/runtime failures are separated from patch-quality "
    "failures because a model may fail to produce a patch before "
    "its security-repair capability can be evaluated."
)

report.append("")

report.append("IMPORTANT LIMITATION")
report.append("-" * 70)

report.append(
    "This experiment contains 30 runs across 10 vulnerability instances "
    "and 3 locally deployed LLMs. The results indicate performance on "
    "this benchmark and should not be generalized to all Python "
    "vulnerabilities or repositories."
)

report.append("")

report.append("FINAL RESEARCH CONCLUSION")
report.append("-" * 70)

report.append(
    "Across the 30-run evaluation, the models demonstrated different "
    "levels of secure patch generation and runtime reliability. "
    f"{best_verified['model_name']} achieved the highest overall "
    f"verified patch rate at {best_verified['verified_rate_%']:.2f}%. "
    "The comparison shows that model selection affects both the "
    "quality and reliability of automated security patch generation."
)

report.append(
    "The results also demonstrate the importance of automated "
    "security re-scanning. A generated patch may be syntactically "
    "valid and pass regression tests while still failing to remove "
    "the targeted security vulnerability."
)

report.append(
    "Consequently, SecurePatch uses a verification pipeline combining "
    "patch application, regression testing, and Bandit re-scanning "
    "before accepting a patch as VERIFIED."
)

report_text = "\n".join(report)

with open(
    OUTPUT_DIR / "final_analysis_report.txt",
    "w",
    encoding="utf-8"
) as f:
    f.write(report_text)


# ============================================================
# FINAL OUTPUT
# ============================================================

print("\n")
print("=" * 70)
print("DONE!")
print("=" * 70)

print(f"\nAll outputs saved to:")
print(OUTPUT_DIR)

print("\nGenerated tables:")
print("  model_performance_summary.csv")
print("  vulnerability_wise_results.csv")
print("  severity_wise_results.csv")
print("  vulnerability_difficulty.csv")
print("  model_efficiency.csv")
print("  generation_reliability.csv")

print("\nGenerated graphs:")
print("  01_verified_patch_rate.png")
print("  02_generation_success.png")
print("  03_conditional_success.png")
print("  04_average_latency.png")
print("  05_token_usage.png")
print("  06_vulnerability_model_heatmap.png")
print("  07_severity_comparison.png")
print("  08_generation_errors.png")
print("  09_final_verdicts.png")

print("\nGenerated report:")
print("  final_analysis_report.txt")

print("\n" + "=" * 70)