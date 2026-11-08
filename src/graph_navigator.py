def get_function_id(filename, function_name):
    return f"function::{filename}::{function_name}"


def get_edge_type(edge):
    """
    Return the relationship/type of an edge.
    Supports different graph edge formats.
    """
    return (
        edge.get("relationship")
        or edge.get("type")
        or edge.get("relation")
    )


def get_vulnerable_function_info(
    graph,
    filename,
    function_name
):
    function_id = get_function_id(
        filename,
        function_name
    )

    if function_id not in graph["nodes"]:
        return None

    function_node = graph["nodes"][function_id]

    info = {
        "function_id": function_id,
        "function_name": function_node["name"],
        "file": function_node["file"],
        "line": function_node["line"],
        "calls": [],
        "imports": [],
        "related_tests": []
    }

    for edge in graph["edges"]:

        edge_type = get_edge_type(edge)

        # Function -> CALLS -> external/internal call
        if (
            edge["source"] == function_id
            and edge_type == "CALLS"
        ):
            target_id = edge["target"]

            if target_id in graph["nodes"]:
                info["calls"].append(
                    graph["nodes"][target_id]["name"]
                )

        # Test -> TESTS -> vulnerable function
        if (
            edge["target"] == function_id
            and edge_type == "TESTS"
        ):
            source_id = edge["source"]

            if source_id in graph["nodes"]:
                info["related_tests"].append(
                    graph["nodes"][source_id]["name"]
                )

    file_id = f"file::{filename}"

    for edge in graph["edges"]:

        edge_type = get_edge_type(edge)

        # File -> IMPORTS -> module
        if (
            edge["source"] == file_id
            and edge_type == "IMPORTS"
        ):
            target_id = edge["target"]

            if target_id in graph["nodes"]:
                info["imports"].append(
                    graph["nodes"][target_id]["name"]
                )

    return info


def get_related_context(
    graph,
    filename,
    function_name
):
    info = get_vulnerable_function_info(
        graph,
        filename,
        function_name
    )

    if not info:
        return None

    return {
        "function": info["function_name"],
        "file": info["file"],
        "line": info["line"],
        "calls": info["calls"],
        "imports": info["imports"],
        "tests": info["related_tests"]
    }