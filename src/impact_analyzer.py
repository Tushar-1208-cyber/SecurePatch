def analyze_impact(
    graph: dict,
    filename: str,
    function_name: str
):
    """
    Analyze the impact and repository relationships of a
    vulnerable function using the SecurePatch source graph.
    """

    result = {
        "vulnerable_function": function_name,
        "vulnerable_file": filename,
        "function_calls": [],
        "related_tests": [],
        "connected_files": [],
        "dependencies": []
    }

    function_id = (
        f"{filename}::{function_name}"
    )

    # -----------------------------------------
    # FIND FUNCTION
    # -----------------------------------------

    function_info = graph.get(
        "functions",
        {}
    ).get(function_id)

    if not function_info:
        return result

    # -----------------------------------------
    # FUNCTION CALLS
    # -----------------------------------------

    result["function_calls"] = (
        function_info.get("calls", [])
    )

    # -----------------------------------------
    # CONNECTED FILE
    # -----------------------------------------

    result["connected_files"].append(
        filename
    )

    # -----------------------------------------
    # FILE DEPENDENCIES / IMPORTS
    # -----------------------------------------

    file_info = graph.get(
        "files",
        {}
    ).get(filename, {})

    result["dependencies"] = (
        file_info.get("imports", [])
    )

    # -----------------------------------------
    # RELATED TESTS
    #
    # Find test functions that are connected
    # to this vulnerable function.
    # -----------------------------------------

    for test_id, test_info in graph.get(
        "tests",
        {}
    ).items():

        test_file = test_info.get("file", "")

        # Look for edges if available
        for edge in graph.get("edges", []):

            source = edge.get("source", "")
            target = edge.get("target", "")

            if (
                source == f"test::{test_id}"
                and target
                == f"function::{filename}::{function_name}"
            ):

                result["related_tests"].append(
                    test_info.get("name")
                )

    # -----------------------------------------
    # FALLBACK TEST DISCOVERY
    #
    # Your existing source graph may store
    # test relationships differently.
    # -----------------------------------------

    if not result["related_tests"]:

        for test_id, test_info in graph.get(
            "tests",
            {}
        ).items():

            test_name = test_info.get(
                "name",
                ""
            )

            # Match vulnerable function name
            # with test function name
            if function_name in test_name:

                result["related_tests"].append(
                    test_name
                )

    # -----------------------------------------
    # REMOVE DUPLICATES
    # -----------------------------------------

    for key in result:

        if isinstance(result[key], list):

            result[key] = list(
                dict.fromkeys(result[key])
            )

    return result