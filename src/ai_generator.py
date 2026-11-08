from src.llm_client import generate_patch


def generate_security_patch(prompt: str) -> str:
    """
    Send the constructed security prompt to the
    configured LLM and return the generated patch.
    """

    patch = generate_patch(prompt)

    if not patch:
        raise RuntimeError(
            "AI did not generate a security patch."
        )

    return patch.strip()