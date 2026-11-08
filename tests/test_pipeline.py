from src.scanner import run_bandit
from src.context_analyzer import analyze_context
from src.context_parser import extract_context_for_finding
from src.context_enricher import enrich_context
from src.prompt_builder import build_patch_prompt
from src.ai_generator import generate_security_patch
from src.patcher import create_sandbox, apply_function_patch


def main():

    repo_path = "sample_repo"

    print("\n🚀 SECUREPATCH END-TO-END PIPELINE")
    print("=" * 55)

    # -----------------------------------------
    # STEP 1: SECURITY SCAN
    # -----------------------------------------

    print("\n[1] 🔍 Running security scan...")

    result = run_bandit(repo_path)

    vulnerability = next(
        vuln
        for vuln in result.vulnerabilities
        if vuln.rule_id == "B602"
    )

    print(
        f"Found: {vulnerability.rule_id} "
        f"({vulnerability.severity})"
    )

    # -----------------------------------------
    # STEP 2: CODE CONTEXT ANALYSIS
    # -----------------------------------------

    print("\n[2] 🧠 Analyzing vulnerable code...")

    context = analyze_context(
        vulnerability.filename,
        vulnerability.line_number
    )

    function_name = None

    if context["function"]:
        function_name = context["function"]["name"]

        print(
            f"Function detected: {function_name}"
        )

    # -----------------------------------------
    # STEP 3: REPOSITORY CONTEXT
    # -----------------------------------------

    print("\n[3] 📂 Retrieving repository context...")

    repo_context = extract_context_for_finding(
        repo_path,
        vulnerability,
        context
    )

    print(
        f"Related files: "
        f"{len(repo_context['related_files'])}"
    )

    print(
        f"Related tests: "
        f"{len(repo_context['related_tests'])}"
    )

    # -----------------------------------------
    # STEP 4: SOURCE GRAPH CONTEXT
    # -----------------------------------------

    print("\n[4] 🔗 Navigating source graph...")

    graph_context = enrich_context(
        repo_path,
        vulnerability.filename,
        function_name
    )

    print(
        f"Function calls: "
        f"{len(graph_context['function_calls'])}"
    )

    print(
        f"Connected tests: "
        f"{len(graph_context['related_tests'])}"
    )

    # -----------------------------------------
    # STEP 5: PROMPT ENGINEERING
    # -----------------------------------------

    print("\n[5] ✍️ Building security-aware prompt...")

    prompt = build_patch_prompt(
        vulnerability,
        context,
        repo_context,
        graph_context
    )

    print("Prompt ready.")

    # -----------------------------------------
    # STEP 6: AI PATCH GENERATION
    # -----------------------------------------

    print("\n[6] 🤖 Generating secure patch...")

    patch = generate_security_patch(prompt)

    print("\nGenerated Patch:")
    print("-" * 55)
    print(patch)

    # -----------------------------------------
    # STEP 7: CREATE SANDBOX
    # -----------------------------------------

    print("\n[7] 📦 Creating isolated sandbox...")

    sandbox = create_sandbox(repo_path)

    print(f"Sandbox: {sandbox}")

    # -----------------------------------------
    # STEP 8: APPLY PATCH
    # -----------------------------------------

    print("\n[8] 🔧 Applying patch safely...")

    old_function = context["function"]["code"]

    patched_file = apply_function_patch(
        vulnerability.filename,
        sandbox,
        old_function,
        patch
    )

    print(f"Patched file: {patched_file}")

    print("\n🎉 PATCH APPLIED SUCCESSFULLY")

    print("\nNEXT:")
    print("→ Run regression tests")
    print("→ Re-scan patched repository")
    print("→ Generate final verdict")


if __name__ == "__main__":
    main()
