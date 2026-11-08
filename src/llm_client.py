import os
from dotenv import load_dotenv


load_dotenv()


def get_llm_config():
    """
    Load the selected LLM configuration.

    This abstraction allows SecurePatch to support
    multiple models later.
    """

    provider = os.getenv(
        "LLM_PROVIDER",
        "mock"
    )

    model = os.getenv(
        "LLM_MODEL",
        "mock-model"
    )

    return {
        "provider": provider,
        "model": model
    }


def generate_patch(prompt: str) -> str:
    """
    Generate a security patch.

    Currently uses a mock implementation.
    A real LLM provider will be connected next.
    """

    config = get_llm_config()

    print("\n🤖 AI PATCH GENERATOR")
    print("---------------------------------------------")
    print(f"Provider: {config['provider']}")
    print(f"Model: {config['model']}")

    if config["provider"] == "mock":

        return """def run_command(user_input):
    subprocess.call(user_input.split(), shell=False)
"""

    raise ValueError(
        f"Unsupported LLM provider: "
        f"{config['provider']}"
    )