# SecurePatch Architecture

## 1. Project Overview

SecurePatch is an AI-assisted security vulnerability repair system for Python repositories.

The system identifies security vulnerabilities, analyzes the affected code, retrieves relevant repository context, navigates code relationships using an AST-based source graph, generates a security patch using an AI model, and validates the patch inside an isolated sandbox.

The objective is to move beyond simple AI code generation by providing the model with repository-aware context and validating generated patches before accepting them.

---

# 2. Current End-to-End Pipeline

```text
Python Repository
        |
        v
Security Scanner
(Bandit)
        |
        v
Vulnerability Detection
        |
        v
Code Context Analysis
        |
        +-----------------------------+
        |                             |
        v                             v
Repository Context              Source Graph
Retrieval                       Navigation
        |                             |
        +-------------+---------------+
                      |
                      v
              Context Enrichment
                      |
                      v
            Security-Aware Prompt
                      |
                      v
               AI Patch Generator
                      |
                      v
                 Generated Patch
                      |
                      v
              Isolated Sandbox
                      |
                      v
                 Patch Application
                      |
              +-------+-------+
              |               |
              v               v
       Regression Tests   Security Re-Scan
           (pytest)          (Bandit)
              |               |
              +-------+-------+
                      |
                      v
                 Final Verdict
```

---

# 3. Pipeline Components

## Stage 1: Security Scanning

The repository is scanned using Bandit to identify potential Python security vulnerabilities.

Each vulnerability includes information such as:

- Rule ID
- Severity
- CWE identifier
- File location
- Line number
- Security issue description

Example:

```text
Rule ID: B602
Severity: HIGH
CWE: CWE-78

Issue:
subprocess call with shell=True identified,
security issue.
```

---

## Stage 2: Code Context Analysis

The affected Python file is analyzed using Python's Abstract Syntax Tree (AST).

The system extracts:

- Vulnerable function
- Function boundaries
- Function source code
- Imported modules

This allows SecurePatch to understand the vulnerable code rather than sending only an isolated scanner warning to the AI model.

---

## Stage 3: Repository Context Retrieval

SecurePatch searches the repository for code related to the vulnerability.

The current implementation retrieves:

- Related files
- Related test files
- Functions connected to the vulnerable code

This repository context helps the patch generation stage preserve existing project behavior.

---

## Stage 4: Source Graph Construction

SecurePatch constructs an AST-based source graph representing relationships inside the repository.

The graph contains:

### Nodes

- Files
- Imports
- Functions
- Tests
- External function calls

### Relationships

- File IMPORTS Import
- File CONTAINS Function
- Function DEFINED_IN File
- Function CALLS External Call
- Test TESTS Function

The source graph enables structured navigation of repository relationships.

---

## Stage 5: Semantic Code Navigation and Impact Analysis

For a detected vulnerability, SecurePatch navigates the source graph starting from the affected function.

The analysis identifies:

- Function calls
- File dependencies
- Related tests
- Connected files
- Imported modules

This information is used to understand the possible impact of modifying the vulnerable function.

Example:

```text
Vulnerability
      |
      v
Affected Function
      |
      v
Graph Traversal
      |
      +-------------------+-------------------+
      |                   |                   |
      v                   v                   v
Function Calls       Related Tests      Dependencies
      |
      v
Connected Files
```

---

## Stage 6: Context Enrichment

Information from multiple analysis stages is combined before patch generation.

```text
Vulnerability Information
        +
Affected Function
        +
Repository Context
        +
Source Graph Relationships
        +
Impact Information
        |
        v
Enriched Security Context
```

This creates a richer representation of the repository before sending information to the AI model.

---

## Stage 7: AI Patch Generation

SecurePatch constructs a security-aware prompt containing:

- Vulnerability details
- CWE information
- Vulnerable function
- File imports
- Related repository files
- Related tests
- Function calls
- Source graph context

The AI model is instructed to:

1. Fix the reported vulnerability.
2. Preserve the original functionality.
3. Make the smallest possible code change.
4. Avoid modifying test files.
5. Avoid changing unrelated code.
6. Return only the corrected function.

The current implementation supports a mock AI provider and is designed to support real LLM providers through an abstraction layer.

---

## Stage 8: Isolated Patch Application

The original repository is never modified directly.

SecurePatch:

1. Creates a copy of the repository.
2. Creates an isolated sandbox workspace.
3. Applies the generated patch only inside the sandbox.

This prevents experimental AI-generated code from directly modifying the original repository.

---

## Stage 9: Regression Testing

The patched repository is tested using pytest.

The purpose is to determine whether the generated patch preserves existing functionality.

Possible outcomes:

```text
Tests Passed
      or
Tests Failed
```

---

## Stage 10: Security Validation

The patched sandbox repository is scanned again using Bandit.

The system specifically checks whether the target vulnerability has been removed.

A patch is not considered successful merely because the code executes. It must also remove the targeted security issue.

---

## Stage 11: Final Verdict

The results from regression testing and security validation are combined.

```text
Regression Tests Passed
            +
Target Vulnerability Removed
            |
            v
     SECURE PATCH VERIFIED
```

If either validation fails, the patch is rejected.

---

# 4. Current Implementation Status

The following components are currently implemented and tested:

- Security scanning using Bandit
- Vulnerability parsing
- AST-based code context analysis
- Repository context retrieval
- AST-based source graph construction
- Graph navigation
- Impact analysis
- Context enrichment
- Security-aware prompt generation
- AI patch generation
- Isolated sandbox creation
- Patch application
- Regression testing using pytest
- Security re-scanning
- Final patch verdict

---

# 5. Future Architecture Extensions

The current SecurePatch pipeline is designed to support additional capabilities without replacing the existing architecture.

## 5.1 RAG-Based Repository Understanding

A RAG layer using LangChain or LlamaIndex will enable semantic repository search and repository-aware question answering.

```text
Repository Code
      |
      v
Code Chunking
      |
      v
Embeddings / Vector Index
      |
      v
Semantic Retrieval
      |
      v
Relevant Repository Context
      |
      v
AI Model
```

This will extend the current repository context retrieval mechanism.

---

## 5.2 AI Peer Programming

A bounded AI peer review workflow will be added to the existing patch generation stage.

```text
Vulnerability + Context
        |
        v
AI Developer
        |
        v
Patch V1
        |
        v
AI Security Reviewer
        |
        v
Security Review Feedback
        |
        v
AI Developer Revision
        |
        v
Patch V2
        |
        v
Existing Validation Pipeline
```

The workflow will use one review and one revision cycle to prevent uncontrolled agent loops.

---

## 5.3 Experimental Modes

SecurePatch will support comparison between different repair strategies.

### Mode A: LLM Only

```text
Scanner Finding
      |
      v
LLM
      |
      v
Patch
      |
      v
Validation
```

### Mode B: Repository-Aware LLM + RAG

```text
Scanner Finding
      +
Relevant Repository Context
      |
      v
LLM
      |
      v
Patch
      |
      v
Validation
```

### Mode C: AI Peer Programming

```text
Scanner Finding + RAG
        |
        v
AI Developer
        |
        v
Patch V1
        |
        v
AI Security Reviewer
        |
        v
Feedback
        |
        v
AI Developer Revision
        |
        v
Patch V2
        |
        v
Security + Test Validation
```

---

## 5.4 Multiple Model Comparison

The architecture can support multiple AI models through the existing model abstraction layer.

Possible experiments include:

- LLM Only
- LLM + Repository Context
- LLM + RAG
- LLM + RAG + AI Peer Review
- Comparison across multiple AI models

Evaluation metrics can include:

- Vulnerability removal rate
- Regression test success rate
- Patch generation time
- Number of validation failures

---

## 5.5 Automation and CI/CD

Future versions will integrate:

- GitHub Actions
- Automated security scanning
- Automated patch validation
- Pull request automation
- Sweep.dev workflow integration
- AI-assisted test generation using Codium AI or Codeium

These additions will extend the current SecurePatch pipeline without changing its core design.