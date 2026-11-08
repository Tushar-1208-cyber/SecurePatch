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


# One row per vulnerability
rows = []

for vulnerability in sorted(
    df["vulnerability"].unique()
):

    subset = df[
        df["vulnerability"] == vulnerability
    ]

    row = {
        "Vulnerability": vulnerability,
        "Severity": subset["severity"].iloc[0],
    }

    for model in [
        "Qwen2.5-Coder 7B",
        "Llama 3.1 8B",
        "Codestral 22B",
    ]:

        item = subset[
            subset["model_name"] == model
        ]

        if item.empty:
            row[model] = "-"
        else:
            verdict = item.iloc[0]["final_verdict"]

            if verdict == "VERIFIED":
                row[model] = "VERIFIED"
            elif verdict == "ERROR":
                row[model] = "ERROR"
            else:
                row[model] = "REJECTED"

    rows.append(row)


table = pd.DataFrame(rows)

table.to_csv(
    OUTPUT / "model_vulnerability_matrix.csv",
    index=False
)

print("\n")
print(table.to_string(index=False))

print(
    "\nSaved:",
    OUTPUT / "model_vulnerability_matrix.csv"
)