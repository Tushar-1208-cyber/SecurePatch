def build_patch_prompt(
    vulnerability,
    context,
    repo_context,
    graph_context
):
    """
    Build a security-aware prompt for the LLM using
    vulnerability details, repository context, and
    source graph context.
    """

    function_code = "No function context available."

    if context["function"]:
        function_code = context["function"]["code"]

    imports = "\n".join(
        f"- {item}"
        for item in context["imports"]
    )

    related_tests = "\n".join(
        f"- {test}"
        for test in repo_context["related_tests"]
    )

    related_files = "\n".join(
        f"- {file}"
        for file in repo_context["related_files"]
    )

    function_calls = "\n".join(
        f"- {call}"
        for call in graph_context["function_calls"]
    )

    graph_imports = "\n".join(
        f"- {item}"
        for item in graph_context["file_imports"]
    )

    graph_tests = "\n".join(
        f"- {test}"
        for test in graph_context["related_tests"]
    )

    prompt = f"""
You are an expert secure software engineer.

Your task is to generate a minimal security patch for a
vulnerability detected in a Python repository.

SECURITY FINDING
----------------
Rule ID: {vulnerability.rule_id}
Severity: {vulnerability.severity}
CWE: CWE-{vulnerability.cwe_id}
Issue: {vulnerability.message}

VULNERABLE FILE
---------------
{vulnerability.filename}

VULNERABLE LINE
---------------
Line {vulnerability.line_number}

AFFECTED FUNCTION
-----------------
{function_code}

FILE IMPORTS
------------
{imports or "No imports detected"}

RELATED FILES
-------------
{related_files or "None found"}

RELATED TESTS
-------------
{related_tests or "None found"}

SOURCE GRAPH CONTEXT
--------------------
Function Calls:
{function_calls or "None detected"}

Graph-Detected Imports:
{graph_imports or "None detected"}

Connected Tests:
{graph_tests or "None detected"}

PATCH REQUIREMENTS
------------------
1. Fix the reported security vulnerability.
2. Preserve the original functionality.
3. Make the smallest possible code change.
4. Do not modify test files.
5. Do not change unrelated code.
6. Return ONLY the complete corrected function code.
7. Do not include explanations.
8. Do not use markdown code fences.

Generate the secure patched function now.
"""

    return prompt