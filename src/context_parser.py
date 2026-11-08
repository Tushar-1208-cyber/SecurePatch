from pathlib import Path


def find_related_files(repo_path, keywords, exclude_file=None):
    """
    Search Python files in the repository for relevant keywords.
    """

    related_files = []

    for file_path in Path(repo_path).rglob("*.py"):

        # Skip virtual environment and cache
        if "venv" in file_path.parts:
            continue

        if "__pycache__" in file_path.parts:
            continue

        if exclude_file and str(file_path) == str(exclude_file):
            continue

        try:
            content = file_path.read_text()

            for keyword in keywords:

                if keyword and keyword in content:
                    related_files.append(str(file_path))
                    break

        except Exception:
            continue

    return related_files


def find_related_tests(repo_path, function_name):
    """
    Find test files that reference the vulnerable function.
    """

    if not function_name:
        return []

    related_tests = []

    for file_path in Path(repo_path).rglob("test_*.py"):

        try:
            content = file_path.read_text()

            if function_name in content:
                related_tests.append(str(file_path))

        except Exception:
            continue

    return related_tests


def extract_context_for_finding(
    repo_path,
    finding,
    analysis
):
    """
    Build repository-aware context using
    the vulnerability finding and file analysis.
    """

    function_name = None

    if analysis["function"]:
        function_name = analysis["function"]["name"]

    imports = analysis["imports"]

    context = {
        "vulnerable_file": finding.filename,
        "function_name": function_name,
        "function_context": (
            analysis["function"]["code"]
            if analysis["function"]
            else None
        ),
        "imports": imports,
        "related_files": [],
        "related_tests": []
    }

    keywords = []

    # Vulnerable function is the strongest signal
    if function_name:
        keywords.append(function_name)

    # Add imported modules as additional signals
    keywords.extend(imports)

    context["related_files"] = find_related_files(
        repo_path,
        keywords,
        exclude_file=finding.filename
    )

    context["related_tests"] = find_related_tests(
        repo_path,
        function_name
    )

    return context