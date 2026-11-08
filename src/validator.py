import subprocess
from pathlib import Path


def run_regression_tests(repo_path: str) -> dict:
    """
    Run pytest on the patched sandbox repository
    and return structured test results.
    """

    repo = Path(repo_path)

    result = subprocess.run(
        [
            "pytest",
            str(repo),
            "-v"
        ],
        capture_output=True,
        text=True
    )

    return {
        "passed": result.returncode == 0,
        "return_code": result.returncode,
        "output": result.stdout,
        "errors": result.stderr
    }
