from src.source_graph import build_source_graph
from src.graph_navigator import get_related_context


def enrich_context(
    repo_path: str,
    filename: str,
    function_name: str | None
):
    """
    Enrich vulnerability context using the repository
    source graph.
    """

    enriched = {
        "function_calls": [],
        "file_imports": [],
        "related_tests": []
    }

    if not function_name:
        return enriched

    graph = build_source_graph(repo_path)

    graph_context = get_related_context(
        graph,
        filename,
        function_name
    )

    if not graph_context:
        return enriched

    enriched["function_calls"] = (
        graph_context.get("calls", [])
    )

    enriched["file_imports"] = (
        graph_context.get("imports", [])
    )

    enriched["related_tests"] = (
        graph_context.get("tests", [])
    )

    return enriched