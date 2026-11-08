from src.source_graph import build_source_graph


def main():

    graph = build_source_graph("sample_repo")

    print("\n🔗 SECUREPATCH SOURCE GRAPH")
    print("=" * 50)

    print("\nNODES")
    print("-" * 50)

    for node_id, node_data in graph["nodes"].items():

        print(
            f"\n[{node_data['type'].upper()}]"
        )

        print(
            f"ID: {node_id}"
        )

        print(
            f"Name: {node_data['name']}"
        )

        if "file" in node_data:
            print(
                f"File: {node_data['file']}"
            )

        if "line" in node_data:
            print(
                f"Line: {node_data['line']}"
            )

    print("\n\nRELATIONSHIPS")
    print("=" * 50)

    for edge in graph["edges"]:

        print(
            f"{edge['source']}"
        )

        print(
            f"    └── "
            f"{edge['relation']}"
            f" ──►"
        )

        print(
            f"         {edge['target']}"
        )


if __name__ == "__main__":
    main()