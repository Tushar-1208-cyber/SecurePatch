from src.source_graph import build_source_graph
from src.impact_analyzer import analyze_impact


def main():

    graph = build_source_graph(
        "sample_repo"
    )

    impact = analyze_impact(
        graph,
        "sample_repo/vulnerable_app.py",
        "run_command"
    )

    print("\n🎯 SECUREPATCH IMPACT ANALYSIS")
    print("=" * 55)

    print(
        f"\n🔴 Vulnerable Function: "
        f"{impact['vulnerable_function']}"
    )

    print(
        f"📄 File: "
        f"{impact['vulnerable_file']}"
    )

    print("\n⚙️ FUNCTION CALLS")

    if impact["function_calls"]:

        for call in impact["function_calls"]:

            print(
                f"→ {call.replace('call::', '')}"
            )

    else:

        print("→ None detected")

    print("\n🧪 RELATED TESTS")

    if impact["related_tests"]:

        for test in impact["related_tests"]:

            print(f"→ {test}")

    else:

        print("→ None detected")

    print("\n📂 CONNECTED FILES")

    if impact["connected_files"]:

        for file in impact["connected_files"]:

            print(f"→ {file}")

    else:

        print("→ None detected")

    print("\n🔗 FILE DEPENDENCIES")

    if impact["dependencies"]:

        for dependency in impact["dependencies"]:

            print(f"→ {dependency}")

    else:

        print("→ None detected")


if __name__ == "__main__":
    main()
