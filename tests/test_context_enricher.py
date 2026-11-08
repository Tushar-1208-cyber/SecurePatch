from src.context_enricher import enrich_context


def main():

    context = enrich_context(
        "sample_repo",
        "sample_repo/vulnerable_app.py",
        "run_command"
    )

    print("\n🧠 SECUREPATCH ENRICHED CONTEXT")
    print("=" * 50)

    print("\nFUNCTION CALLS")

    for call in context["function_calls"]:
        print(f"→ {call}")

    print("\nFILE IMPORTS")

    for imported in context["file_imports"]:
        print(f"→ {imported}")

    print("\nRELATED TESTS")

    for test in context["related_tests"]:
        print(f"→ {test}")


if __name__ == "__main__":
    main()