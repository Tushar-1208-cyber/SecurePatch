import ast
from pathlib import Path


def get_vulnerable_function(file_path: str, line_number: int):
    """
    Finds the function containing the vulnerable line.
    """

    source = Path(file_path).read_text()

    tree = ast.parse(source)

    for node in ast.walk(tree):

        if isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef)
        ):

            start_line = node.lineno
            end_line = node.end_lineno

            if start_line <= line_number <= end_line:

                lines = source.splitlines()

                function_code = "\n".join(
                    lines[start_line - 1:end_line]
                )

                return {
                    "name": node.name,
                    "start_line": start_line,
                    "end_line": end_line,
                    "code": function_code
                }

    return None


def get_imports(file_path: str):
    """
    Extracts imports from the Python file.
    """

    source = Path(file_path).read_text()

    tree = ast.parse(source)

    imports = []

    for node in ast.walk(tree):

        if isinstance(node, ast.Import):

            for alias in node.names:
                imports.append(alias.name)

        elif isinstance(node, ast.ImportFrom):

            module = node.module or ""

            for alias in node.names:
                imports.append(
                    f"{module}.{alias.name}"
                )

    return imports


def analyze_context(file_path: str, line_number: int):

    function = get_vulnerable_function(
        file_path,
        line_number
    )

    imports = get_imports(file_path)

    return {
        "function": function,
        "imports": imports
    }