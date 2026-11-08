import ast
from pathlib import Path


def get_call_name(node):
    """
    Extract a readable name from a function call.
    Examples:
        foo()                -> foo
        module.foo()         -> module.foo
        obj.method()         -> obj.method
    """

    if isinstance(node, ast.Name):
        return node.id

    if isinstance(node, ast.Attribute):

        parts = []

        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value

        if isinstance(node, ast.Name):
            parts.append(node.id)

        return ".".join(reversed(parts))

    return None


def build_source_graph(repo_path: str):

    graph = {
        "files": {},
        "functions": {},
        "imports": {},
        "calls": {},
        "tests": {},

        # New graph structures
        "nodes": {},
        "edges": []
    }

    repo = Path(repo_path)

    # ------------------------------------------------
    # PASS 1: PARSE FILES, IMPORTS AND FUNCTIONS
    # ------------------------------------------------

    for file_path in repo.rglob("*.py"):

        relative_path = str(file_path)

        try:
            source = file_path.read_text(
                encoding="utf-8"
            )
            tree = ast.parse(source)

        except (
            SyntaxError,
            UnicodeDecodeError
        ):
            continue

        # FILE NODE
        file_id = f"file::{relative_path}"

        graph["nodes"][file_id] = {
            "type": "file",
            "name": relative_path
        }

        graph["files"][relative_path] = {
            "functions": [],
            "imports": []
        }

        # --------------------------------------------
        # IMPORTS
        # --------------------------------------------

        for node in tree.body:

            if isinstance(node, ast.Import):

                for alias in node.names:

                    import_name = alias.name

                    graph["files"][relative_path][
                        "imports"
                    ].append(import_name)

                    import_id = (
                        f"import::{import_name}"
                    )

                    graph["imports"][import_id] = {
                        "name": import_name
                    }

                    graph["nodes"][import_id] = {
                        "type": "import",
                        "name": import_name
                    }

                    graph["edges"].append({
                        "source": file_id,
                        "relation": "IMPORTS",
                        "target": import_id
                    })

            elif isinstance(node, ast.ImportFrom):

                module = node.module or ""

                for alias in node.names:

                    import_name = (
                        f"{module}.{alias.name}"
                        if module
                        else alias.name
                    )

                    graph["files"][relative_path][
                        "imports"
                    ].append(import_name)

                    import_id = (
                        f"import::{import_name}"
                    )

                    graph["imports"][import_id] = {
                        "name": import_name
                    }

                    graph["nodes"][import_id] = {
                        "type": "import",
                        "name": import_name
                    }

                    graph["edges"].append({
                        "source": file_id,
                        "relation": "IMPORTS",
                        "target": import_id
                    })

        # --------------------------------------------
        # FUNCTIONS
        # --------------------------------------------

        for node in ast.walk(tree):

            if not isinstance(
                node,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef
                )
            ):
                continue

            function_name = node.name

            function_id = (
                f"{relative_path}::{function_name}"
            )

            function_node_id = (
                f"function::{function_id}"
            )

            graph["files"][relative_path][
                "functions"
            ].append(function_name)

            graph["functions"][function_id] = {
                "file": relative_path,
                "name": function_name,
                "line": node.lineno,
                "calls": []
            }

            # FUNCTION NODE
            graph["nodes"][function_node_id] = {
                "type": "function",
                "name": function_name,
                "file": relative_path,
                "line": node.lineno
            }

            # FILE CONTAINS FUNCTION
            graph["edges"].append({
                "source": file_id,
                "relation": "CONTAINS",
                "target": function_node_id
            })

            # FUNCTION DEFINED IN FILE
            graph["edges"].append({
                "source": function_node_id,
                "relation": "DEFINED_IN",
                "target": file_id
            })

            # ----------------------------------------
            # FUNCTION CALLS
            # ----------------------------------------

            for child in ast.walk(node):

                if not isinstance(child, ast.Call):
                    continue

                call_name = get_call_name(
                    child.func
                )

                if not call_name:
                    continue

                graph["functions"][function_id][
                    "calls"
                ].append(call_name)

            # ----------------------------------------
            # TEST FUNCTIONS
            # ----------------------------------------

            if function_name.startswith("test_"):

                graph["tests"][function_id] = {
                    "file": relative_path,
                    "name": function_name
                }

                test_node_id = (
                    f"test::{function_id}"
                )

                graph["nodes"][test_node_id] = {
                    "type": "test",
                    "name": function_name,
                    "file": relative_path
                }

                graph["edges"].append({
                    "source": test_node_id,
                    "relation": "DEFINED_IN",
                    "target": file_id
                })

    # ------------------------------------------------
    # PASS 2: CREATE FUNCTION CALL RELATIONSHIPS
    # ------------------------------------------------

    function_lookup = {}

    for function_id, function_data in (
        graph["functions"].items()
    ):

        function_name = function_data["name"]

        if function_name not in function_lookup:
            function_lookup[function_name] = []

        function_lookup[function_name].append(
            function_id
        )

    for function_id, function_data in (
        graph["functions"].items()
    ):

        source_node = (
            f"function::{function_id}"
        )

        for call_name in function_data["calls"]:

            # Get last part for module.foo()
            simple_name = call_name.split(".")[-1]

            # Internal repository function
            if simple_name in function_lookup:

                for target_function_id in (
                    function_lookup[simple_name]
                ):

                    target_node = (
                        f"function::{target_function_id}"
                    )

                    graph["edges"].append({
                        "source": source_node,
                        "relation": "CALLS",
                        "target": target_node
                    })

            else:

                # External / library call node
                call_node_id = (
                    f"call::{call_name}"
                )

                if call_node_id not in graph["nodes"]:

                    graph["nodes"][call_node_id] = {
                        "type": "external_call",
                        "name": call_name
                    }

                graph["edges"].append({
                    "source": source_node,
                    "relation": "CALLS",
                    "target": call_node_id
                })

    # ------------------------------------------------
    # PASS 3: CONNECT TESTS TO FUNCTIONS
    # ------------------------------------------------

    for test_id, test_data in graph["tests"].items():

        test_node_id = f"test::{test_id}"

        test_name = test_data["name"]

        # Example:
        # test_run_command_exists
        # → run_command

        possible_target = (
            test_name
            .replace("test_", "", 1)
            .replace("_exists", "")
        )

        if possible_target in function_lookup:

            for function_id in (
                function_lookup[possible_target]
            ):

                function_node_id = (
                    f"function::{function_id}"
                )

                graph["edges"].append({
                    "source": test_node_id,
                    "relation": "TESTS",
                    "target": function_node_id
                })

    return graph