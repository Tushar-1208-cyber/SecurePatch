from pathlib import Path
import pandas as pd


ROOT = Path(__file__).resolve().parent

INPUT = (
    ROOT
    / "workspace"
    / "experiments"
    / "final_30_runs"
    / "final_30_results.csv"
)

OUTPUT = (
    ROOT
    / "workspace"
    / "experiments"
    / "final_30_runs"
    / "analysis"
)

OUTPUT.mkdir(parents=True, exist_ok=True)


df = pd.read_csv(INPUT)


def classify(row):

    verdict = str(row["final_verdict"]).upper()

    if verdict == "ERROR":
        return "Generation/runtime failure"

    if not bool(row["patch_generated"]):
        return "Patch not generated"

    if not bool(row["syntax_valid"]):
        return "Invalid syntax"

    if bool(row["regression_passed"]) and not bool(
        row["vulnerability_removed"]
    ):
        return "Patch generated and tests passed, but vulnerability remained"

    if not bool(row["regression_passed"]):
        return "Regression failure"

    if not bool(row["vulnerability_removed"]):
        return "Security vulnerability not removed"

    return "Other"


df["failure_category"] = df.apply(
    classify,
    axis=1
)


failed = df[
    df["final_verdict"].astype(str).str.upper() != "VERIFIED"
].copy()


columns = [
    "model_name",
    "vulnerability",
    "severity",
    "file",
    "line",
    "final_verdict",
    "patch_generated",
    "syntax_valid",
    "vulnerability_removed",
    "regression_passed",
    "failure_category",
    "error",
]

failed[columns].to_csv(
    OUTPUT / "failure_analysis.csv",
    index=False
)


summary = (
    failed["failure_category"]
    .value_counts()
    .rename_axis("failure_category")
    .reset_index(name="count")
)

summary.to_csv(
    OUTPUT / "failure_category_summary.csv",
    index=False
)


print("\n" + "=" * 70)
print("SECUREPATCH FAILURE ANALYSIS")
print("=" * 70)

print("\nFailure categories:")
print(summary.to_string(index=False))

print("\nDetailed failures:")
print(
    failed[
        [
            "model_name",
            "vulnerability",
            "final_verdict",
            "failure_category",
        ]
    ].to_string(index=False)
)

print("\nSaved:")
print(OUTPUT / "failure_analysis.csv")
print(OUTPUT / "failure_category_summary.csv")