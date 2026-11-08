# SecurePatch — Eval 2 Implementation

## 1. Repository RAG Q&A
SecurePatch uses ChromaDB for vector storage and Sentence Transformers (`all-MiniLM-L6-v2`) for embeddings. The `/api/ai/index` endpoint indexes repository files, while `/api/ai/query` retrieves relevant code chunks and uses an Ollama-hosted language model to answer questions about the code.

**Verification:** Indexing succeeded for 30 files and 30 chunks. The Q&A endpoint returned relevant code context and an answer with HTTP 200.

## 2. GitHub Actions CI/CD
The `.github/workflows/securepatch.yml` workflow runs on pushes and pull requests. It installs Python dependencies, performs a Bandit scan on `sample_repo`, and runs the regression tests under `tests`.

**Verification:** The GitHub Actions workflow completed successfully after correcting the NumPy dependency version.

## 3. AI-Assisted Test Generation
The `/api/ai/generate-tests` endpoint generates pytest code using an Ollama model and saves the result under `workspace/generated_tests/`.

**Verification:** The endpoint returned HTTP 200, generated a test file, and the file passed `py_compile`. The existing smoke-test suite passed with one test. The generated tests have not yet been executed or validated.

## 4. Limitations and Remaining Work
- The legacy Sweep.dev GitHub automation has not been configured.
- Integration with Codeium/Codium AI has not been verified; the demonstrated generator uses Ollama.
- RAG answer quality and generated-test correctness require further evaluation.
