from src.source_graph import build_source_graph
from src.graph_navigator import get_related_context


def main():

    graph = build_source_graph(
        "sample_repo"
    )

    context = get_related_context(
        graph,
        "sample_repo/vulnerable_app.py",
        "run_command"
    )

    print("\n🧭 SECUREPATCH GRAPH NAVIGATION")
    print("=" * 50)

    if not context:
        print("Function not found.")
        return

    print(
        f"\nVulnerable Function: "
        f"{context['function']}"
    )

    print(
        f"File: "
        f"{context['file']}"
    )

    print(
        f"Line: "
        f"{context['line']}"
    )

    print("\nFUNCTION CALLS")

    if context["calls"]:
        for call in context["calls"]:
            print(f"→ {call}")
    else:
        print("None")

    print("\nFILE IMPORTS")

    if context["imports"]:
        for imported_module in context["imports"]:
            print(f"→ {imported_module}")
    else:
        print("None")

    print("\nRELATED TESTS")

    if context["tests"]:
        for test in context["tests"]:
            print(f"→ {test}")
    else:
        print("None")


if __name__ == "__main__":
    main()