from src.scanner import run_bandit
from src.context_analyzer import analyze_context
from src.context_parser import extract_context_for_finding
from src.context_enricher import enrich_context
from src.prompt_builder import build_patch_prompt


def main():

    result = run_bandit("sample_repo")

    vulnerability = None

    # Select the B602 vulnerability for testing
    for vuln in result.vulnerabilities:

        if vuln.rule_id == "B602":

            vulnerability = vuln
            break

    if vulnerability is None:

        print("B602 vulnerability not found.")
        return

    # ------------------------------------------
    # 1. Analyze local vulnerability context
    # ------------------------------------------

    context = analyze_context(
        vulnerability.filename,
        vulnerability.line_number
    )

    # ------------------------------------------
    # 2. Find repository-level context
    # ------------------------------------------

    repo_context = extract_context_for_finding(
        "sample_repo",
        vulnerability,
        context
    )

    # ------------------------------------------
    # 3. Get affected function name
    # ------------------------------------------

    function_name = None

    if context["function"]:

        function_name = context["function"]["name"]

    # ------------------------------------------
    # 4. Enrich context using source graph
    # ------------------------------------------

    graph_context = enrich_context(
        "sample_repo",
        vulnerability.filename,
        function_name
    )

    # ------------------------------------------
    # 5. Build AI patch prompt
    # ------------------------------------------

    prompt = build_patch_prompt(
        vulnerability,
        context,
        repo_context,
        graph_context
    )

    print("\n🔒 SECUREPATCH AI PROMPT")
    print("=" * 50)

    print(prompt)


if __name__ == "__main__":
    main()