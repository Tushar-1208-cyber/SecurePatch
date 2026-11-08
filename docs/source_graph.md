# SecurePatch Source Graph and Semantic Code Navigation

## 1. Overview

SecurePatch uses an AST-based source graph to understand relationships inside a Python repository.

Instead of relying only on keyword search or file-level matching, the system parses Python source code and represents important repository elements and their relationships.

The source graph helps SecurePatch navigate from a security vulnerability to the relevant code, dependencies, connected files, function calls, and tests.

---

# 2. Why Source Graph Navigation?

A security finding usually points to a specific file and line.

For example:

```text
Security Finding

Rule: B602
File: vulnerable_app.py
Line: 8

Issue:
subprocess call with shell=True
