# SecurePatch Prompt Engineering

## 1. Overview

SecurePatch uses prompt engineering to guide an AI model in generating secure and minimal code patches.

The prompt design evolved iteratively as the project pipeline became more repository-aware.

Instead of providing only a vulnerability description, the final prompt combines:

- Security scanner findings
- Vulnerable function code
- File imports
- Related repository files
- Related tests
- Source graph relationships
- Function calls
- Connected dependencies
- Explicit patch constraints

The goal is to provide the AI model with sufficient context to understand both the security issue and the surrounding repository structure before generating a patch.

---

# 2. Prompt Evolution

## Prompt V1: Basic Vulnerability Prompt

The first version provided only:

- Vulnerability type
- Vulnerable code
- Security issue

Conceptually:

```text
Security Finding
+
Vulnerable Function
        ↓
      LLM
        ↓
    Code Patch
