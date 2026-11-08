
import { useEffect, useMemo, useState } from "react";

const API = "http://127.0.0.1:8000";

const AI_LAB_STORAGE_KEY = "securepatch_ai_lab_state";

function loadAILabState() {
  try {
    const saved = sessionStorage.getItem(
      AI_LAB_STORAGE_KEY
    );

    return saved ? JSON.parse(saved) : null;
  } catch {
    return null;
  }
}

async function request(path, options = {}) {
  const res = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    throw new Error(
      data.detail ||
        data.message ||
        "Request failed"
    );
  }

  return data;
}

function modelLabel(model) {
  const labels = {
    "qwen2.5-coder": "Qwen2.5-Coder 7B",
    "llama3.1": "Llama 3.1 8B",
    "codestral": "Codestral 22B",
  };

  return labels[model] || model;
}

function shortStatus(value) {
  if (value === true) return "PASS";
  if (value === false) return "FAIL";
  return "N/A";
}

export default function AILab({
  repoPath,
  selectedFinding,
  patchData,
}) {
  const [status, setStatus] = useState(null);

  const savedState = loadAILabState();

  const [selectedModel, setSelectedModel] =
    useState(
      savedState?.selectedModel ||
        "qwen2.5-coder"
    );

  const [compare, setCompare] =
    useState(
      savedState?.compare || null
    );

  const [comparisonResults, setComparisonResults] =
    useState(
      savedState?.comparisonResults || []
    );

  const [generated, setGenerated] =
    useState(
      savedState?.generated || null
    );

  const [validationResults, setValidationResults] =
    useState(
      savedState?.validationResults || {}
    );

  // Do NOT restore busy state.
  // It should always start empty when returning to AI Lab.
  const [busy, setBusy] = useState("");

  const [error, setError] =
    useState(
      savedState?.error || ""
    );

  const [query, setQuery] =
    useState(
      savedState?.query || ""
    );

  const [queryResult, setQueryResult] =
    useState(
      savedState?.queryResult || null
    );

  const [indexResult, setIndexResult] =
    useState(
      savedState?.indexResult || null
    );

  const [review, setReview] =
    useState(
      savedState?.review || {}
    );

  const [tests, setTests] =
    useState(
      savedState?.tests || {}
    );

  const hasFinding = Boolean(
    selectedFinding?.filename &&
      selectedFinding?.line_number
  );

  /*
   * =========================================================
   * EXTRACT CURRENT GENERATED PATCH
   * =========================================================
   */

  const patchText = useMemo(() => {
    return (
      generated?.patch?.function ||
      generated?.patch?.patch ||
      generated?.function ||
      generated?.patch ||
      patchData?.patch?.function ||
      patchData?.patch?.patch ||
      ""
    );
  }, [generated, patchData]);

  /*
   * =========================================================
   * LOAD OLLAMA STATUS
   * =========================================================
   */

  useEffect(() => {
    request("/api/ai/status")
      .then(setStatus)
      .catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    try {
      sessionStorage.setItem(
        AI_LAB_STORAGE_KEY,
        JSON.stringify({
          selectedModel,
          compare,
          comparisonResults,
          generated,
          validationResults,
          error,
          query,
          queryResult,
          indexResult,
          review,
          tests,
        })
      );
    } catch (e) {
      console.warn(
        "Could not save AI Lab state:",
        e
      );
    }
  }, [
    selectedModel,
    compare,
    comparisonResults,
    generated,
    validationResults,
    error,
    query,
    queryResult,
    indexResult,
    review,
    tests,
  ]);

  /*
   * =========================================================
   * BUILD RAG INDEX
   * =========================================================
   */

  async function buildIndex() {
    if (!repoPath) {
      setError("Import a repository first.");
      return;
    }

    setBusy("index");
    setError("");

    try {
      const data = await request(
        "/api/ai/index",
        {
          method: "POST",
          body: JSON.stringify({
            repo_path: repoPath,
          }),
        }
      );

      setIndexResult(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy("");
    }
  }

  /*
   * =========================================================
   * RAG QUERY
   * =========================================================
   */

  async function askRepository() {
    if (!repoPath) {
      setError("Import a repository first.");
      return;
    }

    if (!query.trim()) {
      setError("Enter a repository question.");
      return;
    }

    setBusy("query");
    setError("");

    try {
      const data = await request(
        "/api/ai/query",
        {
          method: "POST",
          body: JSON.stringify({
            repo_path: repoPath,
            query: query.trim(),
            k: 6,
            model: selectedModel,
          }),
        }
      );

      setQueryResult(data);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy("");
    }
  }

  /*
   * =========================================================
   * GENERATE PATCH FOR SELECTED MODEL
   * =========================================================
   */

  async function generatePatch(model = selectedModel) {
    if (!repoPath) {
      setError("Import a repository first.");
      return;
    }

    if (!hasFinding) {
      setError("Select a Bandit finding first.");
      return;
    }

    setSelectedModel(model);

    setBusy(`generate-${model}`);
    setError("");

    try {
      const data = await request(
        "/api/ai/generate-patch",
        {
          method: "POST",
          body: JSON.stringify({
            repo_path: repoPath,
            file_path: selectedFinding.filename,
            line: selectedFinding.line_number,
            model,
          }),
        }
      );

      setGenerated(data);

      return data;
    } catch (e) {
      setError(
        `${modelLabel(model)} failed: ${e.message}`
      );

      return null;
    } finally {
      setBusy("");
    }
  }

  /*
   * =========================================================
   * COMPARE MODELS
   * =========================================================
   */

  async function compareModels() {
    if (!repoPath) {
      setError("Import a repository first.");
      return;
    }

    if (!hasFinding) {
      setError("Select a Bandit finding first.");
      return;
    }

    setBusy("compare");
    setError("");

    setComparisonResults([]);
    setValidationResults({});
    setCompare(null);

    try {
      const data = await request(
        "/api/ai/compare",
        {
          method: "POST",
          body: JSON.stringify({
            repo_path: repoPath,
            file_path: selectedFinding.filename,
            line: selectedFinding.line_number,
            models: [
              "qwen2.5-coder",
              "llama3.1",
              "codestral",
            ],
          }),
        }
      );

      setCompare(data);

      if (Array.isArray(data.results)) {
        setComparisonResults(data.results);
      }
    } catch (e) {
      /*
       * Compatibility with backend versions
       * expecting "providers".
       */

      try {
        const data = await request(
          "/api/ai/compare",
          {
            method: "POST",
            body: JSON.stringify({
              repo_path: repoPath,
              file_path:
                selectedFinding.filename,
              line:
                selectedFinding.line_number,
              providers: [
                "qwen2.5-coder",
                "llama3.1",
                "codestral",
              ],
            }),
          }
        );

        setCompare(data);

        if (Array.isArray(data.results)) {
          setComparisonResults(data.results);
        }
      } catch (secondError) {
        setError(secondError.message);
      }
    } finally {
      setBusy("");
    }
  }

  /*
   * =========================================================
   * VALIDATE GENERATED MODEL PATCH
   * =========================================================
   */

  async function validateModelPatch(
    item,
    index
  ) {
    if (!repoPath || !hasFinding) {
      setError(
        "Repository and finding are required."
      );
      return;
    }

    const patch =
      item?.patch ||
      item?.function ||
      item?.generated_patch ||
      "";

    if (!patch) {
      setError(
        `No patch available for ${
          item?.model || "this model"
        }.`
      );
      return;
    }

    const model =
      item?.model ||
      item?.provider ||
      selectedModel;

    setBusy(`validate-${index}`);
    setError("");

    try {
      const data = await request(
        "/api/validate",
        {
          method: "POST",
          body: JSON.stringify({
            repo_path: repoPath,
            file_path:
              selectedFinding.filename,
            line:
              selectedFinding.line_number,
            patch,
          }),
        }
      );

      setValidationResults(
        (previous) => ({
          ...previous,
          [model]: data,
        })
      );
    } catch (e) {
      setValidationResults(
        (previous) => ({
          ...previous,
          [model]: {
            status: "ERROR",
            error: e.message,
          },
        })
      );
    } finally {
      setBusy("");
    }
  }

  /*
   * =========================================================
   * FULL MULTI-LLM EXPERIMENT
   *
   * Same vulnerability
   *       ↓
   * Qwen / Llama / Codestral
   *       ↓
   * Same validation pipeline
   *       ↓
   * pytest + Bandit
   *       ↓
   * VERIFIED / REJECTED
   * =========================================================
   */

  async function runExperiment() {
    if (!repoPath) {
      setError("Import a repository first.");
      return;
    }

    if (!hasFinding) {
      setError("Select a Bandit finding first.");
      return;
    }

    setBusy("experiment");
    setError("");

    setComparisonResults([]);
    setValidationResults({});
    setTests({});
    setReview({});

    const models = [
      "qwen2.5-coder",
      "llama3.1",
      "codestral",
    ];

    const results = [];

    try {
      for (const model of models) {
        try {
          const generatedData =
            await request(
              "/api/ai/generate-patch",
              {
                method: "POST",
                body: JSON.stringify({
                  repo_path: repoPath,
                  file_path:
                    selectedFinding.filename,
                  line:
                    selectedFinding.line_number,
                  model,
                }),
              }
            );

          const patch =
            generatedData?.patch?.function ||
            generatedData?.patch?.patch ||
            generatedData?.function ||
            generatedData?.patch ||
            "";

          const generationMeta =
            generatedData?.patch || {};

          let validation = null;

          if (patch) {
            try {
              validation =
                await request(
                  "/api/validate",
                  {
                    method: "POST",
                    body: JSON.stringify({
                      repo_path: repoPath,
                      file_path:
                        selectedFinding.filename,
                      line:
                        selectedFinding.line_number,
                      patch,
                    }),
                  }
                );
            } catch (validationError) {
              validation = {
                status: "ERROR",
                error:
                  validationError.message,
              };
            }
          }

          results.push({
            model,

            model_name:
              modelLabel(model),

            patch_generated:
              Boolean(patch),

            patch,

            provider:
              generationMeta.provider ||
              "ollama",

            latency_ms:
              generationMeta.latency_ms ??
              generatedData.latency_ms ??
              null,

            input_tokens:
              generationMeta.input_tokens ??
              generatedData.input_tokens ??
              null,

            output_tokens:
              generationMeta.output_tokens ??
              generatedData.output_tokens ??
              null,

            validation,
          });
        } catch (modelError) {
          results.push({
            model,

            model_name:
              modelLabel(model),

            patch_generated: false,

            patch: "",

            provider: "ollama",

            error: modelError.message,

            validation: null,
          });
        }
      }

      setComparisonResults(results);

      const validationMap = {};

      results.forEach((item) => {
        if (item.validation) {
          validationMap[item.model] =
            item.validation;
        }
      });

      setValidationResults(
        validationMap
      );

      setCompare({
        results,
        experiment: true,
      });
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy("");
    }
  }

  /*
   * =========================================================
   * AI TEST GENERATION
   *
   * IMPORTANT:
   * The backend receives the EXACT PATCH generated
   * by the model.
   * =========================================================
   */

  async function generateTests() {
    if (!hasFinding) {
      setError(
        "Select a Bandit finding first."
      );
      return;
    }

    setBusy("tests");
    setError("");

    try {
      /*
       * If Step 4 has results:
       * generate tests for every successful patch.
       */

      if (comparisonResults.length > 0) {
        const generatedItems =
          comparisonResults.filter(
            (item) =>
              item.patch_generated &&
              item.patch
          );

        if (generatedItems.length === 0) {
          setError(
            "No generated patches are available for test generation."
          );
          return;
        }

        const testResults = {};

        for (const item of generatedItems) {
          const model = item.model;

          try {
            const data = await request(
              "/api/ai/generate-tests",
              {
                method: "POST",
                body: JSON.stringify({
                  repo_path: repoPath,

                  file_path:
                    selectedFinding.filename,

                  line:
                    selectedFinding.line_number,

                  /*
                   * EXACT PATCH GENERATED
                   * BY THIS MODEL
                   */
                  patch: item.patch,

                  /*
                   * EXACT MODEL THAT
                   * GENERATED THE PATCH
                   */
                  model,
                }),
              }
            );

            testResults[model] = data;
          } catch (e) {
            testResults[model] = {
              error: e.message,
            };
          }
        }

        setTests(testResults);

        return;
      }

      /*
       * No Step 4 experiment.
       * Use the Step 3 selected-model patch.
       */

      if (!patchText) {
        setError(
          "Generate a patch first in Step 3."
        );
        return;
      }

      const data = await request(
        "/api/ai/generate-tests",
        {
          method: "POST",
          body: JSON.stringify({
            repo_path: repoPath,

            file_path:
              selectedFinding.filename,

            line:
              selectedFinding.line_number,

            /*
             * EXACT STEP 3 PATCH
             */
            patch: patchText,

            /*
             * MODEL THAT GENERATED
             * THE PATCH
             */
            model: selectedModel,
          }),
        }
      );

      setTests({
        [selectedModel]: data,
      });
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy("");
    }
  }

  /*
   * =========================================================
   * AI SECURITY REVIEW
   *
   * IMPORTANT:
   * The backend receives the EXACT PATCH that
   * was generated by the selected model.
   * =========================================================
   */

  async function reviewPatch() {
    if (!hasFinding) {
      setError(
        "Select a Bandit finding first."
      );
      return;
    }

    setBusy("review");
    setError("");

    try {
      /*
       * If Step 4 has results:
       * review every successful generated patch.
       */

      if (comparisonResults.length > 0) {
        const generatedItems =
          comparisonResults.filter(
            (item) =>
              item.patch_generated &&
              item.patch
          );

        if (generatedItems.length === 0) {
          setError(
            "No generated patches are available for security review."
          );
          return;
        }

        const reviewResults = {};

        for (const item of generatedItems) {
          const model = item.model;

          try {
            const data = await request(
              "/api/ai/review",
              {
                method: "POST",
                body: JSON.stringify({
                  repo_path: repoPath,

                  file_path:
                    selectedFinding.filename,

                  line:
                    selectedFinding.line_number,

                  /*
                   * EXACT PATCH GENERATED
                   * BY THIS MODEL
                   */
                  patch: item.patch,

                  /*
                   * REVIEW USING THE
                   * SAME MODEL
                   */
                  model,
                }),
              }
            );

            reviewResults[model] = data;
          } catch (e) {
            reviewResults[model] = {
              error: e.message,
            };
          }
        }

        setReview(reviewResults);

        return;
      }

      /*
       * Individual Step 3 review.
       */

      if (!patchText) {
        setError(
          "Generate an AI patch first."
        );
        return;
      }

      const data = await request(
        "/api/ai/review",
        {
          method: "POST",
          body: JSON.stringify({
            repo_path: repoPath,

            file_path:
              selectedFinding.filename,

            line:
              selectedFinding.line_number,

            /*
             * EXACT STEP 3 PATCH
             */
            patch: patchText,

            /*
             * MODEL THAT GENERATED
             * THE PATCH
             */
            model: selectedModel,
          }),
        }
      );

      setReview({
        [selectedModel]: data,
      });
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy("");
    }
  }

  /*
   * =========================================================
   * MODEL STATUS
   * =========================================================
   */

  const configuredModels =
    status?.configured_models || [
      "qwen2.5-coder",
      "llama3.1",
      "codestral",
    ];

  const installedModels =
    status?.installed_models || [];

  /*
   * =========================================================
   * UI
   * =========================================================
   */

  return (
    <div className="detail-stack">

      {/* HEADER */}

      <div className="detail-header">
        <div>
          <div className="section-kicker">
            MID-SEM · AI LAB
          </div>

          <h2>
            Multi-LLM Security Repair
          </h2>

          <p>
            Same vulnerability, same
            repository context and same
            validation pipeline across
            multiple local Ollama coding
            models.
          </p>
        </div>

        <div className="stage-status">
          OLLAMA · LOCAL LLM
        </div>
      </div>

      {/* ERROR */}

      {error && (
        <div
          className="panel"
          style={{
            borderColor: "#7b3131",
            marginBottom: 16,
          }}
        >
          <b>AI Lab Error</b>

          <p>{error}</p>
        </div>
      )}

      {/* STATUS */}

      <div className="validation-grid">

        <div className="panel validation-card">
          <div>
            <div className="section-kicker">
              OLLAMA
            </div>

            <h3>
              {status?.ollama_available
                ? "CONNECTED"
                : "NOT AVAILABLE"}
            </h3>

            <p>
              Local model inference
            </p>
          </div>
        </div>

        <div className="panel validation-card">
          <div>
            <div className="section-kicker">
              CONFIGURED MODELS
            </div>

            <h3>
              {configuredModels.length}
            </h3>

            <p>
              Qwen · Llama 3.1 · Codestral
            </p>
          </div>
        </div>

        <div className="panel validation-card">
          <div>
            <div className="section-kicker">
              RAG
            </div>

            <h3>
              {status?.rag
                ? "ENABLED"
                : "DISABLED"}
            </h3>

            <p>
              {status?.embedding_model ||
                "Repository retrieval"}
            </p>
          </div>
        </div>

      </div>

      {/* LOCAL MODEL REGISTRY */}

      <div
        className="panel"
        style={{ padding: 22 }}
      >
        <div className="section-kicker">
          LOCAL MODEL REGISTRY
        </div>

        <h3>
          Ollama Coding Models
        </h3>

        <div
          style={{
            display: "grid",
            gap: 10,
            marginTop: 14,
          }}
        >
          {configuredModels.map(
            (model) => (
              <div
                key={model}
                style={{
                  display: "flex",
                  justifyContent:
                    "space-between",
                  alignItems: "center",
                  padding: 12,
                  border:
                    "1px solid rgba(255,255,255,0.08)",
                  borderRadius: 10,
                }}
              >
                <div>
                  <b>
                    {modelLabel(model)}
                  </b>

                  <div
                    style={{
                      fontSize: 12,
                      opacity: 0.65,
                      marginTop: 4,
                    }}
                  >
                    {status?.model_registry?.[
                      model
                    ] || model}
                  </div>
                </div>

                <span>
                  {installedModels.some(
                    (installed) =>
                      String(installed)
                        .toLowerCase()
                        .startsWith(
                          String(
                            status
                              ?.model_registry?.[
                              model
                            ] || model
                          ).toLowerCase()
                        )
                  )
                    ? "INSTALLED"
                    : "CONFIGURED"}
                </span>
              </div>
            )
          )}
        </div>
      </div>

      {/* GLOBAL MODEL SELECTION */}

      <div
        className="panel"
        style={{ padding: 22 }}
      >
        <div className="section-kicker">
          MODEL SELECTION
        </div>

        <h3>
          Choose Local LLM
        </h3>

        <div
          style={{
            display: "flex",
            gap: 10,
            marginTop: 14,
            flexWrap: "wrap",
          }}
        >
          {configuredModels.map(
            (model) => (
              <button
                key={model}
                className={
                  selectedModel === model
                    ? "primary-button"
                    : "secondary-btn"
                }
                onClick={() => {
                  setSelectedModel(model);

                  /*
                   * Clear results belonging to
                   * the previously selected model.
                   */
                  setGenerated(null);
                  setTests({});
                  setReview({});
                  setError("");
                }}
              >
                {modelLabel(model)}
              </button>
            )
          )}
        </div>

        <div
          style={{
            marginTop: 12,
            fontSize: 13,
            opacity: 0.7,
          }}
        >
          Selected model:{" "}
          <b>
            {modelLabel(selectedModel)}
          </b>
        </div>
      </div>

      {/* RAG INDEX */}

      <div
        className="panel"
        style={{ padding: 22 }}
      >
        <div className="section-kicker">
          1 · REPOSITORY RAG
        </div>

        <h3>
          Build Code Index
        </h3>

        <p>
          Indexes Python source, tests,
          configuration and documentation so
          the AI can retrieve repository
          context.
        </p>

        <button
          className="primary-button"
          onClick={buildIndex}
          disabled={busy === "index"}
        >
          {busy === "index"
            ? "INDEXING..."
            : "BUILD RAG INDEX"}
        </button>

        {indexResult && (
          <div
            style={{
              marginTop: 14,
            }}
          >
            <b>
              RAG Index Ready
            </b>

            <p>
              {indexResult.files_indexed ??
                indexResult.files ??
                0}{" "}
              files ·{" "}
              {indexResult.chunks_indexed ??
                indexResult.chunks ??
                0}{" "}
              chunks
            </p>
          </div>
        )}
      </div>

      {/* RAG Q&A */}

      <div
        className="panel"
        style={{ padding: 22 }}
      >
        <div className="section-kicker">
          2 · RAG CODE Q&A
        </div>

        <h3>
          Ask About This Repository
        </h3>

        <div
          style={{
            display: "flex",
            gap: 10,
            marginTop: 12,
            flexWrap: "wrap",
          }}
        >
          <input
            value={query}
            onChange={(e) =>
              setQuery(e.target.value)
            }
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                askRepository();
              }
            }}
            placeholder="Where is CommandService.execute() used?"
            style={{
              flex: 1,
              minWidth: 250,
              padding: 12,
            }}
          />

          <button
            className="primary-button"
            onClick={askRepository}
            disabled={busy === "query"}
          >
            {busy === "query"
              ? "ASKING..."
              : "ASK"}
          </button>
        </div>

        {queryResult && (
          <div
            style={{
              marginTop: 18,
            }}
          >
            <b>
              {queryResult.model ||
                selectedModel}
            </b>

            <p
              style={{
                whiteSpace: "pre-wrap",
              }}
            >
              {queryResult.answer ||
                queryResult.response ||
                "No answer returned."}
            </p>

            <small>
              {queryResult.retrieved
                ?.length || 0}{" "}
              evidence chunks retrieved
            </small>
          </div>
        )}
      </div>

      {/* =====================================================
          AI PATCH GENERATION
          ===================================================== */}

      <div
        className="panel"
        style={{ padding: 22 }}
      >
        <div className="section-kicker">
          3 · AI PATCH GENERATION
        </div>

        <h3>
          Generate Patch with Selected Model
        </h3>

        <p>
          {hasFinding
            ? `${selectedFinding.test_id || "Bandit finding"} · ${selectedFinding.filename}:${selectedFinding.line_number}`
            : "Select a Bandit finding in Overview first."}
        </p>

        {/* MODEL SELECTOR */}

        <div
          style={{
            marginTop: 18,
            padding: 16,
            border:
              "1px solid rgba(255,255,255,0.08)",
            borderRadius: 10,
          }}
        >
          <div
            className="section-kicker"
            style={{
              marginBottom: 10,
            }}
          >
            SELECT MODEL FOR PATCH
          </div>

          <div
            style={{
              display: "flex",
              gap: 10,
              flexWrap: "wrap",
            }}
          >
            {configuredModels.map(
              (model) => (
                <button
                  key={model}
                  className={
                    selectedModel === model
                      ? "primary-button"
                      : "secondary-btn"
                  }
                  onClick={() => {
                    setSelectedModel(model);
                    setGenerated(null);
                    setTests({});
                    setReview({});
                    setError("");
                  }}
                >
                  {modelLabel(model)}
                </button>
              )
            )}
          </div>

          <div
            style={{
              marginTop: 10,
              fontSize: 13,
              opacity: 0.7,
            }}
          >
            Selected:{" "}
            <b>
              {modelLabel(selectedModel)}
            </b>
          </div>
        </div>

        {/* GENERATE */}

        <button
          className="primary-button"
          style={{
            marginTop: 16,
          }}
          onClick={() =>
            generatePatch(selectedModel)
          }
          disabled={
            busy ===
              `generate-${selectedModel}` ||
            !hasFinding
          }
        >
          {busy ===
          `generate-${selectedModel}`
            ? "GENERATING..."
            : `GENERATE WITH ${modelLabel(
                selectedModel
              ).toUpperCase()}`}
        </button>

        {/* GENERATED PATCH */}

        {generated && (
          <div
            style={{
              marginTop: 18,
            }}
          >
            <div
              style={{
                display: "flex",
                justifyContent:
                  "space-between",
                alignItems: "center",
                gap: 12,
                flexWrap: "wrap",
              }}
            >
              <div>
                <div className="section-kicker">
                  GENERATED PATCH
                </div>

                <b>
                  {generated?.patch?.model ||
                    generated?.model ||
                    modelLabel(
                      selectedModel
                    )}
                </b>
              </div>

              <div>
                <small>
                  Latency:{" "}
                  {generated?.patch
                    ?.latency_ms ??
                    generated?.latency_ms ??
                    "N/A"}{" "}
                  ms
                </small>
              </div>
            </div>

            <pre
              style={{
                whiteSpace: "pre-wrap",
                maxHeight: 350,
                overflow: "auto",
                marginTop: 12,
              }}
            >
              {patchText}
            </pre>
          </div>
        )}
      </div>

      {/* =====================================================
          MULTI-LLM EXPERIMENT
          ===================================================== */}

      <div
        className="panel"
        style={{ padding: 22 }}
      >
      <div className="section-kicker">
        4 · MULTI-LLM EXPERIMENT · LIVE
      </div>

      <h3>
        Same Finding · Same Context ·
        Different Models
      </h3>

      <p>
        SecurePatch sends the same security
        repair task to Qwen2.5-Coder,
        Llama 3.1 and Codestral. Every
        generated patch is then passed
        through the existing sandbox →
        pytest → Bandit validation pipeline.
      </p>

      <p
        style={{
          fontSize: 12,
          opacity: 0.55,
          marginTop: 6,
          lineHeight: 1.5,
        }}
      >
        Live experiment on the currently selected
        vulnerability. Final research results are
        reported separately in Evaluation.
      </p>

        <button
          className="primary-button"
          onClick={runExperiment}
          disabled={
            busy === "experiment" ||
            !hasFinding
          }
        >
          {busy === "experiment"
            ? "RUNNING 3 MODELS..."
            : "RUN FULL MULTI-LLM EXPERIMENT"}
        </button>

        {!hasFinding && (
          <p
            style={{
              marginTop: 10,
            }}
          >
            Select a Bandit finding first.
          </p>
        )}
      </div>

      {/* =====================================================
          EXPERIMENT RESULTS
          ===================================================== */}

      {comparisonResults.length > 0 && (
        <div
          className="panel"
          style={{ padding: 22 }}
        >
          <div className="section-kicker">
            EXPERIMENT RESULTS
          </div>

          <h3>
            Model-by-Model Security Validation
          </h3>

          <div
            style={{
              display: "grid",
              gap: 16,
              marginTop: 18,
            }}
          >
            {comparisonResults.map(
              (item, index) => {
                const model =
                  item.model ||
                  item.provider ||
                  `model-${index}`;

                const validation =
                  item.validation ||
                  validationResults[model];

                const verdict =
                  validation?.status ||
                  "NOT VALIDATED";

                const patch =
                  item.patch ||
                  item.function ||
                  item.generated_patch ||
                  "";

                return (
                  <div
                    key={`${model}-${index}`}
                    className="panel"
                    style={{
                      padding: 18,
                      border:
                        "1px solid rgba(255,255,255,0.08)",
                    }}
                  >

                    {/* MODEL HEADER */}

                    <div
                      style={{
                        display: "flex",
                        justifyContent:
                          "space-between",
                        alignItems: "center",
                        gap: 12,
                        flexWrap: "wrap",
                      }}
                    >
                      <div>
                        <div className="section-kicker">
                          MODEL
                        </div>

                        <h3>
                          {item.model_name ||
                            modelLabel(model)}
                        </h3>

                        <small>
                          Ollama ·{" "}
                          {item.provider ||
                            "local"}
                        </small>
                      </div>

                      <div
                        style={{
                          fontWeight: 700,
                          padding: "8px 14px",
                          borderRadius: 8,
                          background:
                            verdict ===
                            "VERIFIED"
                              ? "rgba(40,180,100,0.15)"
                              : verdict ===
                                "REJECTED"
                              ? "rgba(220,70,70,0.15)"
                              : "rgba(255,255,255,0.06)",
                        }}
                      >
                        {verdict}
                      </div>
                    </div>

                    {/* METRICS */}

                    <div
                      className="validation-grid"
                      style={{
                        marginTop: 16,
                      }}
                    >
                      <div className="panel validation-card">
                        <div>
                          <div className="section-kicker">
                            PATCH
                          </div>

                          <h3>
                            {item.patch_generated
                              ? "GENERATED"
                              : patch
                              ? "GENERATED"
                              : "FAILED"}
                          </h3>
                        </div>
                      </div>

                      <div className="panel validation-card">
                        <div>
                          <div className="section-kicker">
                            LATENCY
                          </div>

                          <h3>
                            {item.latency_ms !=
                            null
                              ? `${(
                                  item.latency_ms /
                                  1000
                                ).toFixed(1)}s`
                              : "N/A"}
                          </h3>
                        </div>
                      </div>

                      <div className="panel validation-card">
                        <div>
                          <div className="section-kicker">
                            TOKENS
                          </div>

                          <h3>
                            {item.output_tokens ??
                              "N/A"}
                          </h3>

                          <p>
                            output
                          </p>
                        </div>
                      </div>
                    </div>

                    {/* VALIDATION */}

                    {validation && (
                      <div
                        style={{
                          marginTop: 16,
                        }}
                      >
                        <div
                          style={{
                            display: "grid",
                            gridTemplateColumns:
                              "repeat(auto-fit,minmax(150px,1fr))",
                            gap: 10,
                          }}
                        >
                          <MetricBox
                            title="REGRESSION"
                            value={shortStatus(
                              validation
                                ?.regression
                                ?.passed
                            )}
                          />

                          <MetricBox
                            title="SECURITY"
                            value={shortStatus(
                              validation
                                ?.security
                                ?.passed
                            )}
                          />

                          <MetricBox
                            title="TARGET REMOVED"
                            value={shortStatus(
                              validation
                                ?.security
                                ?.target_removed
                            )}
                          />

                          <MetricBox
                            title="BANDIT FINDINGS AFTER"
                            value={
                              validation
                                ?.security
                                ?.findings_after ??
                              "N/A"
                            }
                          />
                        </div>
                      </div>
                    )}

                    {/* PATCH */}

                    {patch && (
                      <details
                        style={{
                          marginTop: 16,
                        }}
                      >
                        <summary
                          style={{
                            cursor: "pointer",
                            fontWeight: 600,
                          }}
                        >
                          View Generated Patch
                        </summary>

                        <pre
                          style={{
                            whiteSpace:
                              "pre-wrap",
                            maxHeight: 350,
                            overflow: "auto",
                            marginTop: 12,
                          }}
                        >
                          {patch}
                        </pre>
                      </details>
                    )}

                    {/* MANUAL VALIDATION */}

                    {!validation &&
                      patch && (
                        <button
                          className="secondary-btn"
                          style={{
                            marginTop: 14,
                          }}
                          onClick={() =>
                            validateModelPatch(
                              item,
                              index
                            )
                          }
                          disabled={
                            busy ===
                            `validate-${index}`
                          }
                        >
                          {busy ===
                          `validate-${index}`
                            ? "VALIDATING..."
                            : "VALIDATE PATCH"}
                        </button>
                      )}

                    {/* ERRORS */}

                    {item.error && (
                      <p
                        style={{
                          marginTop: 12,
                        }}
                      >
                        Error: {item.error}
                      </p>
                    )}

                    {validation?.error && (
                      <p
                        style={{
                          marginTop: 12,
                        }}
                      >
                        Validation error:{" "}
                        {validation.error}
                      </p>
                    )}

                  </div>
                );
              }
            )}
          </div>
        </div>
      )}

      {/* =====================================================
          TEST GENERATION + SECURITY REVIEW
          ===================================================== */}

      <div className="validation-grid">

        {/* =====================================================
            STEP 5 · AI TEST GENERATION
            ===================================================== */}

        <div
          className="panel"
          style={{
            padding: 22,
            minWidth: 0,
            width: "100%",
            maxWidth: "100%",
            boxSizing: "border-box",
            overflow: "hidden",
          }}
        >

          <div className="section-kicker">
            5 · AI TEST GENERATION · EXPERIMENTAL
          </div>

          <h3>
            Generate Security / Regression Tests
          </h3>

          <p
            style={{
              opacity: 0.7,
              lineHeight: 1.5,
              marginBottom: 14,
            }}
          >
           {comparisonResults.length > 0
            ? "Generates experimental pytest test drafts separately for each successfully generated model patch."
            : "Generates an experimental pytest test draft for the selected model patch."}
          </p>

          <p
          style={{
            fontSize: 12,
            opacity: 0.55,
            lineHeight: 1.5,
            marginTop: -6,
            marginBottom: 14,
          }}
        >
          These AI-generated tests are advisory and are
          not part of the final SecurePatch validation verdict.
        </p>

          <button
            className="primary-button"
            onClick={generateTests}
            disabled={
              busy === "tests" ||
              !hasFinding
            }
            style={{
              maxWidth: "100%",
            }}
          >
            {busy === "tests"
              ? "GENERATING..."
              : comparisonResults.length > 0
                ? "GENERATE TESTS FOR ALL PATCHES"
                : `GENERATE TESTS FOR ${modelLabel(
                    selectedModel
                  ).toUpperCase()} PATCH`}
          </button>

          {/* GENERATED TESTS */}

          {Object.keys(tests || {}).length > 0 && (
            <div
              style={{
                marginTop: 18,
                width: "100%",
                maxWidth: "100%",
                minWidth: 0,
              }}
            >
              {Object.entries(tests).map(
                ([model, result]) => (
                  <div
                    key={model}
                    className="panel"
                    style={{
                      padding: 14,
                      marginBottom: 12,
                      width: "100%",
                      maxWidth: "100%",
                      minWidth: 0,
                      boxSizing: "border-box",
                      overflow: "hidden",
                    }}
                  >

                    <div className="section-kicker">
                      PATCH UNDER TEST
                    </div>

                    <h4>
                      {modelLabel(model)}
                    </h4>

                    {result?.error ? (
                      <p
                        style={{
                          marginTop: 10,
                          color: "#ff8b8b",
                          lineHeight: 1.5,
                          wordBreak: "break-word",
                        }}
                      >
                        Tests skipped/failed:{" "}
                        {result.error}
                      </p>
                    ) : (
                      <pre
                        style={{
                          marginTop: 10,
                          width: "100%",
                          maxWidth: "100%",
                          minWidth: 0,
                          maxHeight: 300,
                          boxSizing: "border-box",
                          whiteSpace: "pre-wrap",
                          overflowX: "auto",
                          overflowY: "auto",
                          wordBreak: "break-word",
                          overflowWrap: "anywhere",
                          fontSize: 10,
                          lineHeight: 1.6,
                        }}
                      >
                        {result.tests ||
                          result.test_code ||
                          "No tests returned."}
                      </pre>
                    )}

                  </div>
                )
              )}
            </div>
          )}

        </div>

        {/* =====================================================
            STEP 6 · AI SECURITY REVIEWER
            ===================================================== */}

        <div
          className="panel"
          style={{
            padding: 22,
            minWidth: 0,
            width: "100%",
            maxWidth: "100%",
            boxSizing: "border-box",
            overflow: "hidden",
          }}
        >

        <div className="section-kicker">
          6 · AI SECURITY REVIEWER · ADVISORY
        </div>

        <h3>
          Review Generated Patch
        </h3>

        <p
          style={{
            opacity: 0.7,
            lineHeight: 1.5,
            marginBottom: 8,
          }}
        >
          {comparisonResults.length > 0
            ? "Reviews each successfully generated model patch independently."
            : "Reviews the generated patch for security and functional risks."}
        </p>

        <p
          style={{
            fontSize: 12,
            opacity: 0.55,
            lineHeight: 1.5,
            marginBottom: 14,
          }}
        >
          AI review is advisory only. It does not affect
          the final SecurePatch validation verdict.
        </p>

          <button
            className="primary-button"
            onClick={reviewPatch}
            disabled={
              busy === "review" ||
              !hasFinding ||
              (
                comparisonResults.length === 0 &&
                !patchText
              )
            }
            style={{
              maxWidth: "100%",
            }}
          >
            {busy === "review"
              ? "REVIEWING..."
              : comparisonResults.length > 0
                ? "REVIEW ALL PATCHES"
                : "REVIEW PATCH"}
          </button>

          {/* REVIEW RESULTS */}

          {Object.keys(review || {}).length > 0 && (
            <div
              style={{
                marginTop: 18,
                width: "100%",
                maxWidth: "100%",
                minWidth: 0,
              }}
            >
              {Object.entries(review).map(
                ([model, result]) => (
                  <div
                    key={model}
                    className="panel"
                    style={{
                      padding: 14,
                      marginBottom: 12,
                      width: "100%",
                      maxWidth: "100%",
                      minWidth: 0,
                      boxSizing: "border-box",
                      overflow: "hidden",
                    }}
                  >

                    <div className="section-kicker">
                      PATCH UNDER REVIEW
                    </div>

                    <h4>
                      {modelLabel(model)}
                    </h4>

                    {result?.error ? (
                      <p
                        style={{
                          marginTop: 10,
                          color: "#ff8b8b",
                          lineHeight: 1.5,
                          wordBreak: "break-word",
                        }}
                      >
                        Review failed:{" "}
                        {result.error}
                      </p>
                    ) : (
                      <pre
                        style={{
                          marginTop: 10,
                          width: "100%",
                          maxWidth: "100%",
                          minWidth: 0,
                          maxHeight: 320,
                          boxSizing: "border-box",
                          whiteSpace: "pre-wrap",
                          overflowX: "auto",
                          overflowY: "auto",
                          wordBreak: "break-word",
                          overflowWrap: "anywhere",
                          fontSize: 10,
                          lineHeight: 1.6,
                        }}
                      >
                        {
                          typeof result?.review ===
                          "string"
                            ? result.review
                            : result?.review
                              ? JSON.stringify(
                                  result.review,
                                  null,
                                  2
                                )
                              : result?.response
                                ? typeof result.response ===
                                  "string"
                                  ? result.response
                                  : JSON.stringify(
                                      result.response,
                                      null,
                                      2
                                    )
                                : result?.text
                                  ? result.text
                                  : JSON.stringify(
                                      result,
                                      null,
                                      2
                                    )
                        }
                      </pre>
                    )}

                  </div>
                )
              )}
            </div>
          )}

        </div>

      </div>

    
      {/* =====================================================
          VALIDATION CONTRACT
          ===================================================== */}

      <div
        className="panel"
        style={{ padding: 22 }}
      >
        <div className="section-kicker">
          VALIDATION CONTRACT
        </div>

        <h3>
          AI generation does NOT mean acceptance
        </h3>

        <p>
          Every generated patch is evaluated independently
          using the same deterministic SecurePatch validation gate:
        </p>

        <p>
          <b>
            Generated Patch → Sandbox → pytest →
            Bandit Re-scan → VERIFIED / REJECTED
          </b>
        </p>

        <p
          style={{
            fontSize: 12,
            opacity: 0.6,
            lineHeight: 1.5,
          }}
        >
          The LLM generates the patch, pytest checks
          regression behaviour, and Bandit checks whether
          the targeted security vulnerability was removed.
          Only the automated validation pipeline determines
          the final verdict.
        </p>

        <p
          style={{
            fontSize: 12,
            opacity: 0.6,
            lineHeight: 1.5,
          }}
        >
          AI-generated test drafts and AI security reviews
          are supplementary features and do not override
          the automated SecurePatch verdict.
        </p>
      </div>

    </div>
  );
}

/*
 * =========================================================
 * SMALL METRIC CARD
 * =========================================================
 */

function MetricBox({ title, value }) {
  return (
    <div
      style={{
        padding: 12,
        border:
          "1px solid rgba(255,255,255,0.08)",
        borderRadius: 8,
      }}
    >
      <div
        style={{
          fontSize: 11,
          opacity: 0.65,
          marginBottom: 5,
        }}
      >
        {title}
      </div>

      <strong>{value}</strong>
    </div>
  );
}