
import pytest

from backend.main import validate_patch_guardrails


def test_guardrail_accepts_safe_function():
    validate_patch_guardrails(
        "def demo():\n    return 1",
        "demo",
    )


@pytest.mark.parametrize(
    "patch",
    [
        "def demo():\n    return eval('1+1')",
        "def demo():\n    exec('print(1)')",
        "def demo():\n    import os\n    return os.system('whoami')",
        "def demo():\n    import subprocess\n    return subprocess.run('whoami', shell=True)",
    ],
)
def test_guardrail_rejects_unsafe_function(patch):
    with pytest.raises(ValueError, match="Guardrail blocked"):
        validate_patch_guardrails(patch, "demo")


def test_guardrail_rejects_wrong_function_name():
    with pytest.raises(ValueError, match="function name"):
        validate_patch_guardrails(
            "def other():\n    return 1",
            "demo",
        )


def test_guardrail_rejects_invalid_python():
    with pytest.raises(ValueError, match="invalid Python syntax"):
        validate_patch_guardrails(
            "def demo(:\n    return 1",
            "demo",
        )


def test_guardrail_rejects_empty_patch():
    with pytest.raises(ValueError, match="empty patch"):
        validate_patch_guardrails("", "demo")
