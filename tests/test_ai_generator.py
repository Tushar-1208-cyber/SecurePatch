from src.scanner import run_bandit
from src.context_analyzer import analyze_context
from src.context_parser import extract_context_for_finding
from src.context_enricher import enrich_context
from src.prompt_builder import build_patch_prompt
from src.ai_generator import generate_security_patch


def main():

    # Run scanner
    result = run_bandit("sample_repo")

    # Select the HIGH severity finding
    vulnerability = next(
        vuln
        for vuln in result.vulnerabilities
        if vuln.rule_id == "B602"
    )

    # Analyze vulnerable code
    context = analyze_context(
        vulnerability.filename,
        vulnerability.line_number
    )

    # Get repository context
    repo_context = extract_context_for_finding(
        "sample_repo",
        vulnerability,
        context
    )

    # Get source graph context
    function_name = None

    if context["function"]:
        function_name = context["function"]["name"]

    graph_context = enrich_context(
        "sample_repo",
        vulnerability.filename,
        function_name
    )

    # Build AI prompt
    prompt = build_patch_prompt(
        vulnerability,
        context,
        repo_context,
        graph_context
    )

    print("\n🤖 GENERATING SECURITY PATCH")
    print("=" * 50)

    # Generate patch
    patch = generate_security_patch(prompt)

    print("\n🔧 GENERATED PATCH")
    print("=" * 50)
    print(patch)


if __name__ == "__main__":
    main()
