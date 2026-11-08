from src.scanner import run_bandit
from src.context_analyzer import analyze_context
from src.context_parser import extract_context_for_finding
from src.context_enricher import enrich_context


def main():

    repo_path = "sample_repo"

    result = run_bandit(repo_path)

    print("\n🔒 SECUREPATCH SECURITY SCAN")
    print("=" * 45)

    print(f"\nTotal findings: {result.total_findings}")
    print(f"🔴 High: {result.high_count}")
    print(f"🟠 Medium: {result.medium_count}")
    print(f"🟡 Low: {result.low_count}")

    print("\nVULNERABILITIES")
    print("=" * 45)

    for index, vuln in enumerate(
        result.vulnerabilities,
        start=1
    ):

        print(f"\n[{index}] {vuln.rule_id}")
        print(f"Severity: {vuln.severity}")
        print(f"File: {vuln.filename}")
        print(f"Line: {vuln.line_number}")
        print(f"Issue: {vuln.message}")

        # -----------------------------------------
        # STEP 1: ANALYZE VULNERABLE FILE
        # -----------------------------------------

        analysis = analyze_context(
            vuln.filename,
            vuln.line_number
        )

        function_name = None

        if analysis["function"]:

            function = analysis["function"]

            function_name = function["name"]

            print(
                f"\nAffected Function: "
                f"{function['name']}"
            )

            print(
                f"Lines: "
                f"{function['start_line']}"
                f"-{function['end_line']}"
            )

            print("\nFunction Context:")
            print(function["code"])

        else:
            print(
                "\nAffected Function: "
                "No function detected"
            )

        print("\nFile Imports:")

        if analysis["imports"]:

            for imported_module in analysis["imports"]:
                print(f"- {imported_module}")

        else:
            print("- None")

        # -----------------------------------------
        # STEP 2: REPOSITORY CONTEXT RETRIEVAL
        # -----------------------------------------

        repo_context = extract_context_for_finding(
            repo_path,
            vuln,
            analysis
        )

        print("\nREPOSITORY CONTEXT")
        print("-" * 45)

        if repo_context["related_files"]:

            print("Related Files:")

            for file in repo_context["related_files"]:
                print(f"- {file}")

        else:
            print("Related Files: None found")

        if repo_context["related_tests"]:

            print("\nRelated Tests:")

            for test in repo_context["related_tests"]:
                print(f"- {test}")

        else:
            print("\nRelated Tests: None found")

        # -----------------------------------------
        # STEP 3: SOURCE GRAPH CONTEXT
        # -----------------------------------------

        graph_context = enrich_context(
            repo_path,
            vuln.filename,
            function_name
        )

        print("\nSOURCE GRAPH CONTEXT")
        print("-" * 45)

        print("Function Calls:")

        if graph_context["function_calls"]:

            for call in graph_context["function_calls"]:
                print(f"- {call}")

        else:
            print("- None detected")

        print("\nGraph Imports:")

        if graph_context["file_imports"]:

            for imported_module in graph_context[
                "file_imports"
            ]:
                print(f"- {imported_module}")

        else:
            print("- None detected")

        print("\nConnected Tests:")

        if graph_context["related_tests"]:

            for test in graph_context[
                "related_tests"
            ]:
                print(f"- {test}")

        else:
            print("- None detected")

        # -----------------------------------------
        # CWE INFORMATION
        # -----------------------------------------

        if vuln.cwe_id:
            print(f"\nCWE: CWE-{vuln.cwe_id}")

        print("-" * 45)


if __name__ == "__main__":
    main()