"""
SecurePatch Local Multi-LLM Adapter
All models are accessed through the local Ollama API.
No cloud API keys are required.
"""
from __future__ import annotations
import os
import time
from dataclasses import dataclass
from typing import Optional
import requests

# ============================================================================
# OLLAMA CONFIGURATION
# ============================================================================
OLLAMA_BASE_URL = os.getenv(
    "OLLAMA_BASE_URL",
    "http://127.0.0.1:11434",
).rstrip("/")

# These names MUST exactly match `ollama list`.
MODEL_REGISTRY = {
    "codellama": "codellama:7b-instruct",
    "qwen2.5": "qwen2.5:1.5b",
    "phi3": "phi3:mini",
    "qwen2.5-coder": "qwen2.5-coder:7b",
    "llama3.1": "llama3.1:8b",
    "codestral": "codestral:22b-v0.1-q3_K_S",
}

# ============================================================================
# MODEL-SPECIFIC GENERATION SETTINGS
# ============================================================================
MODEL_OPTIONS = {
    "codellama": {
        "temperature": 0.0,
        "num_predict": 600,
        "top_p": 0.9,
        "repeat_penalty": 1.10,
        "repeat_last_n": 256,
    },
    "qwen2.5": {
        "temperature": 0.0,
        "num_predict": 600,
        "top_p": 0.9,
        "repeat_penalty": 1.15,
        "repeat_last_n": 256,
    },
    "phi3": {
        "temperature": 0.0,
        "num_predict": 600,
        "top_p": 0.9,
        "repeat_penalty": 1.15,
        "repeat_last_n": 256,
    },
    "qwen2.5-coder": {
        "temperature": 0.0,
        "num_predict": 600,
        "top_p": 0.9,
        "repeat_penalty": 1.15,
        "repeat_last_n": 256,
    },
    "llama3.1": {
        "temperature": 0.0,
        "num_predict": 600,
        "top_p": 0.9,
        "repeat_penalty": 1.10,
        "repeat_last_n": 256,
    },
    "codestral": {
        "temperature": 0.0,
        "num_predict": 600,
        "top_p": 0.9,
        "repeat_penalty": 1.15,
        "repeat_last_n": 256,
    },
}

# ============================================================================
# SYSTEM PROMPT
# ============================================================================
SECUREPATCH_SYSTEM_PROMPT = """
You are SecurePatch, a security-focused Python vulnerability repair engine.

Your job is to repair exactly ONE vulnerable Python function.

STRICT OUTPUT RULES:
1. Return ONLY the complete corrected Python function.
2. Return valid Python syntax.
3. Do NOT return markdown fences.
4. Do NOT explain your answer.
5. Do NOT return analysis or commentary.
6. Do NOT return imports outside the function.
7. Do NOT return tests.
8. Do NOT return additional functions.
9. Do NOT repeat the function.
10. Do NOT invent unrelated code.
11. Preserve the EXACT existing function name.
12. Preserve the existing function signature unless a signature change is required for security.
13. Make the smallest safe security fix.
14. Preserve intended application behavior.
15. Do not introduce another security vulnerability.
16. Do not rename the function.
17. Do not change routes, callers, tests, or unrelated code.

The response must contain exactly ONE function.

The function name MUST be identical to the function name provided in the user prompt.

Return ONLY Python code.
""".strip()

# ============================================================================
# RESULT OBJECT
# ============================================================================
@dataclass
class LLMResult:
    provider: str
    model: str
    text: str
    latency_ms: int
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    total_tokens: Optional[int] = None
    total_duration_ms: Optional[int] = None
    load_duration_ms: Optional[int] = None
    prompt_eval_duration_ms: Optional[int] = None
    output_eval_duration_ms: Optional[int] = None

# ============================================================================
# MODEL UTILITIES
# ============================================================================
def configured_models() -> list[str]:
    return list(MODEL_REGISTRY.keys())

def model_name(model_key: str) -> str:
    if model_key not in MODEL_REGISTRY:
        available = ", ".join(MODEL_REGISTRY.keys())
        raise ValueError(
            f"Unsupported model '{model_key}'. "
            f"Available models: {available}"
        )
    return MODEL_REGISTRY[model_key]

def _model_options(model_key: str) -> dict:
    return MODEL_OPTIONS.get(
        model_key,
        {
            "temperature": 0.0,
            "num_predict": 600,
            "top_p": 0.9,
            "repeat_penalty": 1.15,
            "repeat_last_n": 256,
        },
    ).copy()

# ============================================================================
# RESPONSE CLEANING
# ============================================================================
def _clean(text: str) -> str:
    if text is None:
        return ""
    text = str(text)
    text = text.replace("\ufeff", "")
    text = text.replace("\r\n", "\n")
    text = text.replace("\r", "\n")
    text = (
        text
        .replace("\u200b", "")
        .replace("\u200c", "")
        .replace("\u200d", "")
    )
    text = text.replace("\u00a0", " ")
    text = text.strip()
    if not text:
        return ""
    lines = text.splitlines()
    cleaned_lines = []
    for line in lines:
        if line.strip().startswith("```"):
            continue
        cleaned_lines.append(line)
    text = "\n".join(cleaned_lines).strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        text = text[1:-1].strip()
    return text

# ============================================================================
# TIME CONVERSION
# ============================================================================
def _ms(nanoseconds: Optional[int]) -> Optional[int]:
    if nanoseconds is None:
        return None
    try:
        return int(int(nanoseconds) / 1_000_000)
    except (TypeError, ValueError):
        return None

# ============================================================================
# OLLAMA CONNECTION
# ============================================================================
def ollama_is_available() -> bool:
    try:
        response = requests.get(
            f"{OLLAMA_BASE_URL}/api/tags",
            timeout=5,
        )
        return response.ok
    except requests.RequestException:
        return False

def installed_models() -> list[str]:
    try:
        response = requests.get(
            f"{OLLAMA_BASE_URL}/api/tags",
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()
        return [
            model.get("name", "")
            for model in data.get("models", [])
            if model.get("name")
        ]
    except requests.RequestException as exc:
        raise RuntimeError(
            "Could not connect to Ollama. "
            "Make sure Ollama is running."
        ) from exc
    except ValueError as exc:
        raise RuntimeError(
            "Ollama returned invalid JSON while listing models."
        ) from exc

def check_model_available(model_key: str) -> bool:
    actual_model = model_name(model_key)
    return actual_model in installed_models()

# ============================================================================
# MODEL HEALTH CHECK
# ============================================================================
def validate_model_configuration(model_key: str) -> dict:
    actual_model = model_name(model_key)
    available = ollama_is_available()
    installed = []
    if available:
        try:
            installed = installed_models()
        except Exception:
            installed = []
    return {
        "model_key": model_key,
        "ollama_model": actual_model,
        "ollama_available": available,
        "model_installed": actual_model in installed,
        "options": _model_options(model_key),
    }

# ============================================================================
# OLLAMA GENERATION
# ============================================================================
def generate(
    prompt: str,
    model: str = "qwen2.5-coder",
    temperature: Optional[float] = None,
    timeout: int = 600,
) -> LLMResult:
    if not prompt or not prompt.strip():
        raise ValueError("Prompt cannot be empty.")
    if model not in MODEL_REGISTRY:
        available = ", ".join(MODEL_REGISTRY.keys())
        raise ValueError(
            f"Unsupported model '{model}'. "
            f"Available models: {available}"
        )

    ollama_model = MODEL_REGISTRY[model]
    
    # Check if the requested model is actually downloaded in Ollama.
    # If not, seamlessly fall back to an installed coding model.
    try:
        available = installed_models()
        if ollama_model not in available and available:
            fallback = None
            for cand in ["codellama:7b-instruct", "qwen2.5:1.5b", "phi3:mini"]:
                if cand in available:
                    fallback = cand
                    break
            if not fallback:
                fallback = available[0]
            print(f"[llm_adapter] Model '{ollama_model}' not installed in Ollama. Falling back to installed model '{fallback}'.")
            ollama_model = fallback
    except Exception:
        pass

    options = _model_options(model)
    if temperature is not None:
        options["temperature"] = temperature

    payload = {
        "model": ollama_model,
        "messages": [
            {
                "role": "system",
                "content": SECUREPATCH_SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": prompt,
            },
        ],
        "stream": False,
        "options": options,
    }

    started = time.perf_counter()

    try:
        response = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json=payload,
            timeout=timeout,
        )
        response.raise_for_status()
    except requests.Timeout as exc:
        raise RuntimeError(
            f"Ollama request timed out after {timeout} seconds "
            f"for model '{ollama_model}'."
        ) from exc
    except requests.ConnectionError as exc:
        raise RuntimeError(
            f"Could not connect to Ollama at {OLLAMA_BASE_URL}. "
            f"Make sure Ollama is running."
        ) from exc
    except requests.RequestException as exc:
        raise RuntimeError(
            f"Failed to generate response using Ollama model "
            f"'{ollama_model}': {exc}"
        ) from exc

    try:
        data = response.json()
    except ValueError as exc:
        raise RuntimeError(
            f"Ollama returned invalid JSON for model '{ollama_model}'."
        ) from exc

    message = data.get("message") or {}
    text = _clean(message.get("content", ""))

    if not text:
        raise RuntimeError(
            f"Ollama model '{ollama_model}' returned an empty response."
        )

    latency_ms = int(
        (time.perf_counter() - started) * 1000
    )

    input_tokens = data.get("prompt_eval_count")
    output_tokens = data.get("eval_count")
    total_tokens = None

    if input_tokens is not None or output_tokens is not None:
        total_tokens = (
            (input_tokens or 0)
            + (output_tokens or 0)
        )

    return LLMResult(
        provider="ollama",
        model=ollama_model,
        text=text,
        latency_ms=latency_ms,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=total_tokens,
        total_duration_ms=_ms(data.get("total_duration")),
        load_duration_ms=_ms(data.get("load_duration")),
        prompt_eval_duration_ms=_ms(
            data.get("prompt_eval_duration")
        ),
        output_eval_duration_ms=_ms(
            data.get("eval_duration")
        ),
    )

# ============================================================================
# MULTI-MODEL GENERATION
# ============================================================================
def generate_all(
    prompt: str,
    temperature: Optional[float] = None,
    timeout: int = 600,
) -> dict[str, LLMResult]:
    if not prompt or not prompt.strip():
        raise ValueError("Prompt cannot be empty.")
    results: dict[str, LLMResult] = {}
    for model_key in MODEL_REGISTRY:
        results[model_key] = generate(
            prompt=prompt,
            model=model_key,
            temperature=temperature,
            timeout=timeout,
        )
    return results

# ============================================================================
# SAFE MULTI-MODEL GENERATION
# ============================================================================
def generate_all_safe(
    prompt: str,
    temperature: Optional[float] = None,
    timeout: int = 600,
) -> dict[str, dict]:
    if not prompt or not prompt.strip():
        raise ValueError("Prompt cannot be empty.")

    results: dict[str, dict] = {}

    for model_key in MODEL_REGISTRY:
        started = time.perf_counter()
        try:
            result = generate(
                prompt=prompt,
                model=model_key,
                temperature=temperature,
                timeout=timeout,
            )
            results[model_key] = {
                "success": True,
                "result": result,
                "error": None,
                "wall_time_ms": int(
                    (time.perf_counter() - started) * 1000
                ),
            }
        except Exception as exc:
            results[model_key] = {
                "success": False,
                "result": None,
                "error": str(exc),
                "wall_time_ms": int(
                    (time.perf_counter() - started) * 1000
                ),
            }

    return results