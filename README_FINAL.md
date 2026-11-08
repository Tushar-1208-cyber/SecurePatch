# SecurePatch

SecurePatch is an AI-assisted security vulnerability detection and automated patch verification system for Python repositories.

## Research Question

How effectively can locally deployed LLMs automatically generate secure patches for Python vulnerabilities, and how does patch quality vary across different LLMs?

## System Pipeline

Python Repository
↓
Bandit Security Scan
↓
Vulnerability Detection
↓
Code Context Analysis
↓
AST Source Graph
↓
Impact Analysis
↓
Repository Context / RAG
↓
Security-Aware Prompt
↓
Local LLM
↓
AI Patch
↓
AST/Syntax Validation
↓
Isolated Sandbox
↓
Pytest Regression Testing
↓
Bandit Re-scan
↓
VERIFIED / REJECTED

## Models

The experiment evaluates:

- Qwen2.5-Coder 7B
- Llama 3.1 8B
- Codestral 22B

Models are deployed locally using Ollama.

## Experimental Setup

- 10 Python security vulnerabilities
- 3 LLMs
- 30 total model-vulnerability runs
- Same repository
- Same vulnerability instances
- Same validation pipeline
- Temperature: 0
- Local inference
- No API keys
- No fine-tuning

## Validation

A patch is classified as VERIFIED only when:

1. The patch is successfully generated.
2. The patched source is syntactically valid.
3. Regression tests pass.
4. The targeted Bandit vulnerability is removed.

## Final Results

| Model | Verified |
|---|---:|
| Llama 3.1 8B | 70% |
| Qwen2.5-Coder 7B | 60% |
| Codestral 22B | 50% |

Llama 3.1 8B achieved the highest overall verified rate.

Codestral achieved an 83.33% verified rate among successfully generated patches, but had four generation/runtime failures.

## Reproducibility

### Create environment

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt