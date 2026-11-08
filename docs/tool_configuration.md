# SecurePatch Tool Configuration

## Tools Used

### Python
Main programming language used to build SecurePatch.

### Bandit
Used to scan Python repositories and detect security vulnerabilities.

Examples:
- B602: subprocess with shell=True
- B301: Unsafe pickle usage
- B105: Hardcoded password

### Python AST
Used to parse source code and construct the SecurePatch source graph.

The graph identifies:
- Files
- Imports
- Functions
- Function calls
- Tests
- Relationships between code components

### pytest
Used for regression testing after applying an AI-generated patch inside an isolated sandbox.

### Git
Used for version control and project management.

### Virtual Environment
Used to isolate SecurePatch dependencies.

### Mock / LLM Provider
SecurePatch currently uses a mock AI provider to test the complete pipeline without requiring an external API.

The architecture can later support a real LLM provider without changing the rest of the pipeline.

## Tool Integration

Bandit
→ AST Context Analysis
→ Repository Context Retrieval
→ Source Graph Navigation
→ Prompt Engineering
→ AI Patch Generation
→ Sandbox
→ pytest + Bandit Validation
→ Final Verdict

This demonstrates AI-augmented code understanding, navigation, automated patch generation, and validation.