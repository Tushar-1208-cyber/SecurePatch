from src.ai_generator import generate_security_patch


def test_patch_generator_returns_patch():
    prompt = "Replace shell=True with a safer subprocess call."
    patch = generate_security_patch(prompt)

    assert isinstance(patch, str)
    assert patch.strip()