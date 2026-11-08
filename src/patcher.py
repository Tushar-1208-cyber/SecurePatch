import shutil
from pathlib import Path


def create_sandbox(repo_path: str) -> Path:
    """
    Create a temporary copy of the repository.
    The original repository is never modified.
    """

    source = Path(repo_path)
    sandbox = Path("workspace/sandbox_repo")

    # Remove previous sandbox
    if sandbox.exists():
        shutil.rmtree(sandbox)

    # Create workspace directory
    sandbox.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # Copy repository
    shutil.copytree(
        source,
        sandbox
    )

    return sandbox


def apply_function_patch(
    original_file: str,
    sandbox_repo: Path,
    old_function: str,
    new_function: str
):
    """
    Replace the vulnerable function with
    the AI-generated patched function.
    """

    original_path = Path(original_file)

    # Convert:
    # sample_repo/vulnerable_app.py
    #
    # into:
    # workspace/sandbox_repo/vulnerable_app.py

    relative_path = original_path.relative_to(
        Path("sample_repo")
    )

    target_file = sandbox_repo / relative_path

    code = target_file.read_text()

    if old_function not in code:
        raise ValueError(
            "Original vulnerable function "
            "was not found in sandbox."
        )

    patched_code = code.replace(
        old_function,
        new_function,
        1
    )

    target_file.write_text(
        patched_code
    )

    return target_file