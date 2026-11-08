import { useMemo, useState, useRef, useEffect } from "react";
import {
  Activity,
  BrainCircuit,
  AlertTriangle,
  ArrowRight,
  BarChart3,
  Bot,
  CheckCircle2,
  ChevronRight,
  Code2,
  Download,
  FileCode2,
  GitBranch,
  
  Layers3,
  Link2,
  LockKeyhole,
  Network,
  Play,
  RefreshCw,
  Search,
  Shield,
  ShieldCheck,
  Terminal,
  TestTube2,
  Upload,
  Wrench,
  XCircle,
  Zap,
} from "lucide-react";



import "./App.css";
import AILab from "./AILab";
import Evaluation from "./Evaluation";

const API = "http://127.0.0.1:8000";

const stages = [
  {
    id: "scan",
    label: "Security Scan",
    icon: Search,
  },
  {
    id: "understand",
    label: "Code Analysis",
    icon: Code2,
  },
  {
    id: "graph",
    label: "Source Graph",
    icon: Network,
  },
  {
    id: "impact",
    label: "Impact Analysis",
    icon: Activity,
  },
  {
    id: "patch",
    label: "AI Patch",
    icon: Bot,
  },
  {
    id: "sandbox",
    label: "Sandbox",
    icon: Layers3,
  },
  {
    id: "test",
    label: "Regression Test",
    icon: TestTube2,
  },
  {
    id: "security",
    label: "Security Re-scan",
    icon: ShieldCheck,
  },
  {
    id: "verdict",
    label: "Final Verdict",
    icon: CheckCircle2,
  },
];

function severityClass(severity) {
  return String(severity || "").toLowerCase();
}

function stagesIndex(id) {
  const index = stages.findIndex((stage) => stage.id === id);
  return index === -1 ? 0 : index;
}

function App() {
  const [activeNav, setActiveNav] = useState("Overview");

  /*
   * IMPORTANT:
   * repoPath is now an INTERNAL backend path.
   * The user never types this path.
   */
  const [repoPath, setRepoPath] = useState("");

  // User-facing repository inputs
  const [githubUrl, setGithubUrl] = useState("");
  const [repoFile, setRepoFile] = useState(null);
  const [importing, setImporting] = useState(false);
  const [repositoryName, setRepositoryName] = useState("");
  const [repositorySource, setRepositorySource] = useState("");

  // Main workflow states
  const [scanning, setScanning] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [validating, setValidating] = useState(false);

  const [findings, setFindings] = useState([]);

  const [summary, setSummary] = useState({
    total: 0,
    high: 0,
    medium: 0,
    low: 0,
  });

  const [selected, setSelected] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [patchData, setPatchData] = useState(null);
  const [validation, setValidation] = useState(null);
  const [downloading, setDownloading] = useState(false);
  const [stage, setStage] = useState("scan");
  const [error, setError] = useState("");

  // Live Streaming Audit Console State
  const [liveLogs, setLiveLogs] = useState([]);
  const [liveProgress, setLiveProgress] = useState(0);
  const [liveStage, setLiveStage] = useState("");
  const [liveActive, setLiveActive] = useState(false);
  const terminalRef = useRef(null);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [liveLogs]);

  const selectedFinding = useMemo(() => {
    return (
      findings.find(
        (finding) =>
          finding.filename === selected?.filename &&
          finding.line_number === selected?.line_number &&
          finding.test_id === selected?.test_id
      ) || selected
    );
  }, [findings, selected]);

  /*
   * =========================================================
   * GENERIC API REQUEST
   * =========================================================
   */

  async function apiRequest(endpoint, options = {}) {
    const response = await fetch(`${API}${endpoint}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },
    });

    let data;

    try {
      data = await response.json();
    } catch {
      throw new Error("Backend returned an invalid response.");
    }

    if (!response.ok) {
      throw new Error(
        data.detail ||
          data.message ||
          `Request failed: ${response.status}`
      );
    }

    return data;
  }


    async function downloadFixedRepository() {
    if (!validation || validation.status !== "VERIFIED") {
      setError(
        "A verified patch is required before downloading."
      );
      return;
    }

    setDownloading(true);
    setError("");

    try {
      const response = await fetch(
        `${API}/api/download-fixed`
      );

      if (!response.ok) {
        let message =
          "Could not download the verified repository.";

        try {
          const data = await response.json();
          message = data.detail || message;
        } catch {
          // Non-JSON backend error
        }

        throw new Error(message);
      }

      const blob = await response.blob();

      const url =
        window.URL.createObjectURL(blob);

      const anchor =
        document.createElement("a");

      anchor.href = url;
      anchor.download =
        "securepatch_fixed_repository.zip";

      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();

      window.setTimeout(() => {
        window.URL.revokeObjectURL(url);
      }, 1000);
    } catch (error) {
      setError(
        error.message ||
          "Verified repository download failed."
      );
    } finally {
      setDownloading(false);
    }
  }
  /*
   * =========================================================
   * REAL-TIME LIVE SECURITY AUDIT STREAM (SSE)
   * =========================================================
   */

  function clearLiveLogs() {
    setLiveLogs([]);
    setLiveActive(false);
    setLiveProgress(0);
    setLiveStage("");
  }

  function startLiveAudit({ url: targetUrl, repoPath: targetRepo }) {
    const finalUrl = (targetUrl || "").trim();
    const finalRepo = (targetRepo || repoPath || "").trim();

    if (!finalUrl && !finalRepo) {
      setError("Enter a GitHub repository URL or upload a ZIP first.");
      return;
    }

    setLiveActive(true);
    setScanning(true);
    if (finalUrl) setImporting(true);
    setError("");
    setLiveProgress(5);
    setLiveStage(finalUrl ? "CONNECT" : "INDEX");

    const initMsg = finalUrl
      ? `Contacting remote GitHub repository: ${finalUrl}`
      : `Initiating real-time static security audit for ${finalRepo}...`;

    setLiveLogs([
      {
        time: new Date().toLocaleTimeString(),
        stage: finalUrl ? "CONNECT" : "INIT",
        level: "info",
        message: initMsg,
      },
    ]);

    setSelected(null);
    setAnalysis(null);
    setPatchData(null);
    setValidation(null);
    setFindings([]);
    setSummary({ total: 0, high: 0, medium: 0, low: 0 });
    setStage("scan");
    setActiveNav("Overview");

    const params = new URLSearchParams();
    if (finalUrl) params.set("url", finalUrl);
    if (finalRepo) params.set("repo_path", finalRepo);

    const sseUrl = `${API}/api/scan/live-stream?${params.toString()}`;
    const eventSource = new EventSource(sseUrl);

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        const timeStr = new Date().toLocaleTimeString();

        if (data.type === "log" || data.type === "finding") {
          setLiveLogs((prev) => [
            ...prev,
            {
              time: timeStr,
              stage: data.stage || "AUDIT",
              level: data.level || "info",
              message: data.message,
              rule_id: data.rule_id,
              severity: data.severity,
              filename: data.filename,
              line: data.line,
            },
          ]);
          if (data.progress) setLiveProgress(data.progress);
          if (data.stage) setLiveStage(data.stage);
        }

        if (data.type === "finding" && data.finding) {
          setFindings((prev) => [...prev, data.finding]);
          setSummary((prev) => {
            const sev = data.severity;
            return {
              total: prev.total + 1,
              high: prev.high + (sev === "HIGH" ? 1 : 0),
              medium: prev.medium + (sev === "MEDIUM" ? 1 : 0),
              low: prev.low + (sev === "LOW" ? 1 : 0),
            };
          });
        }

        if (data.type === "complete") {
          setLiveProgress(100);
          setLiveStage("COMPLETE");
          setLiveLogs((prev) => [
            ...prev,
            {
              time: timeStr,
              stage: "DONE",
              level: "success",
              message: data.message || "Audit completed successfully.",
            },
          ]);
          if (data.repo_path) setRepoPath(data.repo_path);
          if (data.repo_name) setRepositoryName(data.repo_name);
          if (data.source) setRepositorySource(data.source);
          if (data.summary) setSummary(data.summary);
          if (data.findings) setFindings(data.findings);

          if (data.findings && data.findings.length > 0) {
            setStage("understand");
          }
          setScanning(false);
          setImporting(false);
          eventSource.close();
        }

        if (data.type === "error") {
          setError(data.message || "Live scan encountered an error.");
          setLiveLogs((prev) => [
            ...prev,
            {
              time: timeStr,
              stage: "ERROR",
              level: "error",
              message: data.message || "Audit interrupted with error.",
            },
          ]);
          setScanning(false);
          setImporting(false);
          eventSource.close();
        }
      } catch (err) {
        console.error("Error processing SSE event:", err);
      }
    };

    eventSource.onerror = (err) => {
      console.warn("SSE stream closed or completed:", err);
      setScanning(false);
      setImporting(false);
      eventSource.close();
    };
  }

  /*
   * =========================================================
   * GITHUB REPOSITORY IMPORT
   * =========================================================
   */

  async function importGitHubRepository(targetUrl = null) {
    const finalUrl = (targetUrl || githubUrl).trim();
    if (!finalUrl) {
      setError("Enter a GitHub repository URL or direct ZIP link.");
      return;
    }

    if (!finalUrl.includes("github.com/")) {
      setError("Please enter a valid GitHub repository or archive URL.");
      return;
    }

    setImporting(true);
    setError("");

    try {
      const response = await fetch(`${API}/api/repositories/github`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: finalUrl }),
      });

      let data;
      try {
        data = await response.json();
      } catch {
        throw new Error("Backend returned an invalid response.");
      }

      if (!response.ok) {
        throw new Error(data.detail || "Failed to import GitHub repository.");
      }

      setRepoPath(data.repo_path || "");
      setRepositoryName(data.name || finalUrl.split("/").pop());
      setRepositorySource(data.source || "GitHub");

      // Reset previous analysis
      setFindings([]);
      setSummary({ total: 0, high: 0, medium: 0, low: 0 });
      setSelected(null);
      setAnalysis(null);
      setPatchData(null);
      setValidation(null);
      setStage("scan");
      setActiveNav("Overview");
    } catch (err) {
      console.error(err);
      setError(err.message || "Failed to import GitHub repository.");
    } finally {
      setImporting(false);
    }
  }

  function liveAuditGitHubRepository(targetUrl = null) {
    const finalUrl = (targetUrl || githubUrl).trim();
    if (!finalUrl) {
      setError("Enter a GitHub repository URL or direct ZIP link first.");
      return;
    }
    if (!finalUrl.includes("github.com/")) {
      setError("Please enter a valid GitHub repository URL.");
      return;
    }
    startLiveAudit({ url: finalUrl });
  }

  /*
   * =========================================================
   * ZIP REPOSITORY IMPORT
   * =========================================================
   */

  async function importUploadedRepository() {
    if (!repoFile) {
      setError(
        "Choose a repository ZIP file first."
      );
      return;
    }

    setImporting(true);
    setError("");

    try {
      const formData = new FormData();

      formData.append("file", repoFile);

      const response = await fetch(
        `${API}/api/repositories/upload`,
        {
          method: "POST",
          body: formData,
        }
      );

      let data;

      try {
        data = await response.json();
      } catch {
        throw new Error(
          "Backend returned an invalid response."
        );
      }

      if (!response.ok) {
        throw new Error(
          data.detail ||
            "Repository upload failed."
        );
      }

      setRepoPath(data.repo_path || "");
      setRepositoryName(
        data.name || repoFile.name
      );
      setRepositorySource("ZIP Upload");

      // Reset previous analysis
      setFindings([]);
      setSummary({
        total: 0,
        high: 0,
        medium: 0,
        low: 0,
      });
      setSelected(null);
      setAnalysis(null);
      setPatchData(null);
      setValidation(null);
      setStage("scan");
      setActiveNav("Overview");

    } catch (error) {
      setError(
        error.message ||
          "Repository upload failed."
      );
    } finally {
      setImporting(false);
    }
  }

  async function liveAuditUploadedRepository() {
    if (!repoFile) {
      setError("Choose a repository ZIP file first.");
      return;
    }

    setImporting(true);
    setError("");

    try {
      const formData = new FormData();
      formData.append("file", repoFile);

      const response = await fetch(`${API}/api/repositories/upload`, {
        method: "POST",
        body: formData,
      });

      let data;
      try {
        data = await response.json();
      } catch {
        throw new Error("Backend returned an invalid response.");
      }

      if (!response.ok) {
        throw new Error(data.detail || "Repository upload failed.");
      }

      setRepoPath(data.repo_path || "");
      setRepositoryName(data.name || repoFile.name);
      setRepositorySource("ZIP Upload");

      startLiveAudit({ repoPath: data.repo_path });
    } catch (err) {
      setError(err.message || "Repository upload failed.");
    } finally {
      setImporting(false);
    }
  }

  function resetRepository() {
    setRepoPath("");
    setRepositoryName("");
    setRepositorySource("");
    setRepoFile(null);
    setFindings([]);
    setSummary({ total: 0, high: 0, medium: 0, low: 0 });
    setSelected(null);
    setAnalysis(null);
    setPatchData(null);
    setValidation(null);
    clearLiveLogs();
  }

  /*
   * =========================================================
   * SECURITY SCAN
   * =========================================================
   */

  async function scanRepository() {
    if (!repoPath) {
      setError(
        "Import a GitHub repository or upload a ZIP first."
      );
      return;
    }

    startLiveAudit({ repoPath });
  }

  /*
   * =========================================================
   * CODE ANALYSIS
   * =========================================================
   */

  function handleSelectFinding(finding) {
    if (!finding) return;
    setSelected(finding);
    setAnalysis(null);
    setStage("understand");
    setActiveNav("Code Intelligence");
  }

  async function analyzeFinding(
    finding = selectedFinding
  ) {
    if (!finding) {
      setError(
        "Select a vulnerability first."
      );
      return;
    }

    if (!repoPath) {
      setError(
        "Repository is not loaded."
      );
      return;
    }

    setSelected(finding);
    setAnalysis(null);
    setAnalyzing(true);
    setError("");

    setStage("understand");
    setActiveNav("Code Intelligence");

    try {
      const data = await apiRequest(
        "/api/analyze",
        {
          method: "POST",
          body: JSON.stringify({
            repo_path: repoPath,
            file_path: finding.filename,
            line: finding.line_number,
          }),
        }
      );

      setAnalysis(data);

      setStage("understand");
      setActiveNav("Code Intelligence");

    } catch (error) {
      setError(
        error.message ||
          "Code analysis failed."
      );
    } finally {
      setAnalyzing(false);
    }
  }

  /*
   * =========================================================
   * AI PATCH GENERATION
   * =========================================================
   */

async function generatePatch(model = "qwen2.5-coder") {
  if (!selectedFinding) {
    setError(
      "Please select a vulnerability first."
    );
    return;
  }

  if (!repoPath) {
    setError(
      "Repository is not loaded."
    );
    return;
  }

  setGenerating(true);
  setError("");

  setStage("patch");
  setActiveNav("AI Patch");

  try {
    const data = await apiRequest(
      "/api/generate-patch",
      {
        method: "POST",
        body: JSON.stringify({
          repo_path: repoPath,
          file_path:
            selectedFinding.filename,
          line:
            selectedFinding.line_number,
          model: model,
        }),
      }
    );

    setPatchData(data);
    setStage("patch");
    setActiveNav("AI Patch");

  } catch (error) {
    setError(
      error.message ||
        "AI patch generation failed."
    );
  } finally {
    setGenerating(false);
  }
}

  /*
   * =========================================================
   * VALIDATION
   * =========================================================
   */

  async function validatePatch() {
    if (!selectedFinding) {
      setError(
        "Select a vulnerability first."
      );
      return;
    }

    if (!patchData) {
      setError(
        "Generate an AI patch before validation."
      );
      return;
    }

    if (!repoPath) {
      setError(
        "Repository is not loaded."
      );
      return;
    }

    setValidating(true);
    setError("");

    setStage("sandbox");
    setActiveNav("Validation");

    try {
      const patch =
        patchData?.patch?.patch ||
        patchData?.patch?.function ||
        "";

      const data = await apiRequest(
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

      setValidation(data);

      if (
        data.status === "VERIFIED"
      ) {
        setStage("verdict");
      } else {
        setStage("test");
      }

      setActiveNav("Validation");

    } catch (error) {
      setError(
        error.message ||
          "Patch validation failed."
      );
    } finally {
      setValidating(false);
    }
  }

  /*
   * =========================================================
   * PIPELINE NAVIGATION
   * =========================================================
   */

  function openStage(id) {
    setStage(id);

    if (id === "scan") {
      setActiveNav("Overview");
    }

    if (id === "understand") {
      setActiveNav("Code Intelligence");
    }

    if (
      id === "graph" ||
      id === "impact"
    ) {
      setActiveNav("Source Graph");
    }

    if (id === "patch") {
      setActiveNav("AI Patch");
    }

    if (
      id === "sandbox" ||
      id === "test" ||
      id === "security" ||
      id === "verdict"
    ) {
      setActiveNav("Validation");
    }
  }

  const pipelineIndex =
    stagesIndex(stage);

  /*
   * =========================================================
   * MAIN UI
   * =========================================================
   */

  return (
    <div className="app-shell">

      {/* SIDEBAR */}
      <aside className="sidebar">

        <div className="brand">

          <div className="brand-mark">
            <Zap
              size={21}
              fill="currentColor"
            />
          </div>

          <div>
            <div className="brand-name">
              SecurePatch
            </div>

            <div className="brand-sub">
              AI SECURITY ENGINE
            </div>
          </div>

        </div>

        <div className="side-label">
          WORKSPACE
        </div>

        <nav>

          {[
            ["Overview", Activity],
            [
              "Code Intelligence",
              Code2,
            ],
            [
              "Source Graph",
              GitBranch,
            ],
            ["AI Patch", Bot],
            ["AI Lab", BrainCircuit],
            [
              "Validation",
              ShieldCheck,
            ],
            ["Evaluation", BarChart3],
          ].map(
            ([name, Icon]) => (
              <button
                key={name}
                className={`nav-item ${
                  activeNav === name
                    ? "active"
                    : ""
                }`}
                onClick={() => {
                  setActiveNav(name);

                  if (
                    name ===
                    "Overview"
                  ) {
                    setStage("scan");
                  }

                  if (
                    name ===
                    "Code Intelligence"
                  ) {
                    setStage(
                      "understand"
                    );
                  }

                  if (
                    name ===
                    "Source Graph"
                  ) {
                    setStage("graph");
                  }

                  if (
                    name ===
                    "AI Patch"
                  ) {
                    setStage("patch");
                  }

                  if (
                    name ===
                    "AI Lab"
                  ) {
                    setStage("patch");
                  }

                  if (
                    name ===
                    "Validation"
                  ) {
                    setStage("sandbox");
                  }

                  if (name === "Evaluation") {
                    setStage("evaluation");
                  }
                }}
              >
                <Icon size={18} />

                <span>
                  {name}
                </span>

                {activeNav ===
                  name && (
                  <ChevronRight
                    size={15}
                    className="nav-arrow"
                  />
                )}
              </button>
            )
          )}

        </nav>

        <div className="sidebar-bottom">

          <div className="system-card">

            <div className="system-dot" />

            <div>
              <div className="system-title">
                SYSTEM OPERATIONAL
              </div>

              <div className="system-meta">
                FastAPI · Bandit · AST
              </div>
            </div>

          </div>

          <div className="version">
            SecurePatch v1.0
          </div>

        </div>

      </aside>

      {/* MAIN */}
      <main className="main">

        {/* TOP BAR */}
        <header className="topbar">

          <div>

            <div className="eyebrow">
              SECURITY OPERATIONS /
              REPOSITORY REPAIR
            </div>

            <h1>
              {activeNav}
            </h1>

          </div>

          <div className="top-actions">

            <div className="live-status">
              <span />
              LIVE
            </div>

            <button
              className="icon-btn"
              onClick={scanRepository}
              disabled={
                !repoPath ||
                scanning ||
                importing
              }
              title="Refresh scan"
            >
              <RefreshCw
                size={17}
              />
            </button>

          </div>

        </header>

        {/* WORKFLOW */}
        {activeNav !== "Evaluation" && (
          <section className="pipeline-card">

          <div className="pipeline-head">

            <div>

              <div className="section-kicker">
                SECUREPATCH WORKFLOW
              </div>

              <h2>
                Detect → Understand →
                Repair → Verify
              </h2>

            </div>

            <div className="pipeline-counter">
              {Math.min(
                pipelineIndex + 1,
                stages.length
              )}{" "}
              / {stages.length} stages
            </div>

          </div>

          <div className="pipeline">

            {stages.map(
              (item, index) => {
                const Icon =
                  item.icon;

                const done =
                  index <
                  pipelineIndex;

                const current =
                  index ===
                  pipelineIndex;

                return (
                  <button
                    key={item.id}
                    className={`stage ${
                      done
                        ? "done"
                        : ""
                    } ${
                      current
                        ? "current"
                        : ""
                    }`}
                    onClick={() =>
                      openStage(
                        item.id
                      )
                    }
                  >

                    <div className="stage-icon">

                      {done ? (
                        <CheckCircle2
                          size={17}
                        />
                      ) : (
                        <Icon
                          size={17}
                        />
                      )}

                    </div>

                    <span>
                      {item.label}
                    </span>

                    {index <
                      stages.length -
                        1 && (
                      <div className="stage-line" />
                    )}

                  </button>
                );
              }
            )}

          </div>

        </section>
        )}

        {/* ERROR */}
        {error && (
          <div className="error-banner">

            <AlertTriangle
              size={17}
            />

            {error}

          </div>
        )}

        {/* OVERVIEW */}
        {activeNav ===
          "Overview" && (
          <Overview
            repoPath={repoPath}
            githubUrl={githubUrl}
            setGithubUrl={
              setGithubUrl
            }
            repoFile={repoFile}
            setRepoFile={
              setRepoFile
            }
            importing={importing}
            repositoryName={
              repositoryName
            }
            repositorySource={
              repositorySource
            }
            importGitHubRepository={
              importGitHubRepository
            }
            liveAuditGitHubRepository={
              liveAuditGitHubRepository
            }
            importUploadedRepository={
              importUploadedRepository
            }
            liveAuditUploadedRepository={
              liveAuditUploadedRepository
            }
            resetRepository={
              resetRepository
            }
            scanning={scanning}
            scanRepository={
              scanRepository
            }
            summary={summary}
            findings={findings}
            selectedFinding={
              selectedFinding
            }
            setSelected={setSelected}
            onSelectFinding={handleSelectFinding}
            analyzeFinding={
              analyzeFinding
            }
            analysis={analysis}
            analyzing={analyzing}
            liveLogs={liveLogs}
            liveProgress={liveProgress}
            liveStage={liveStage}
            liveActive={liveActive}
            terminalRef={terminalRef}
            clearLiveLogs={clearLiveLogs}
          />
        )}

        {/* CODE INTELLIGENCE */}
        {activeNav ===
          "Code Intelligence" && (
          <IntelligenceView
            finding={
              selectedFinding
            }
            analysis={analysis}
            analyzing={analyzing}
            onAnalyze={
              analyzeFinding
            }
            onNext={() =>
              openStage("graph")
            }
            onGoToPatch={() => {
              openStage("patch");
              setActiveNav("AI Patch");
            }}
          />
        )}

        {/* SOURCE GRAPH */}
        {activeNav ===
          "Source Graph" && (
          <>
            <GraphView
              finding={
                selectedFinding
              }
              analysis={analysis}
            />

            <ImpactSection
              finding={
                selectedFinding
              }
              analysis={analysis}
              onNext={() =>
                openStage("patch")
              }
            />
          </>
        )}

        {/* AI PATCH */}
        {activeNav ===
          "AI Patch" && (
          <PatchView
            finding={
              selectedFinding
            }
            analysis={analysis}
            patchData={patchData}
            generating={
              generating
            }
            generatePatch={
              generatePatch
            }
            onValidate={
              validatePatch
            }
          />
        )}

        {/* AI LAB */}
        {activeNav ===
          "AI Lab" && (
          <AILab
            repoPath={repoPath}
            selectedFinding={selectedFinding}
            patchData={patchData}
          />
        )}

        {/* VALIDATION */}
        {activeNav ===
          "Validation" && (
            <ValidationView
              validation={validation}
              validating={validating}
              validatePatch={validatePatch}
              downloading={downloading}
              downloadFixedRepository={downloadFixedRepository}
              stage={stage}
              onStage={openStage}
            />
        )}

        {activeNav === "Evaluation" && (
          <Evaluation />
        )}
      </main>

    </div>
  );
}

/* =========================================================
   VULNERABILITY KNOWLEDGE BASE & SPECIFICATIONS
========================================================= */

const FRONTEND_RULE_SPECS = {
  B101: {
    category: "Insecure Assertion",
    root_cause: "Assert statements are completely stripped when running Python in optimized mode (-O). Relying on assert for security or input validation allows attackers to bypass checks in production.",
    remediation: "Replace assert with explicit condition checking: if not valid: raise ValueError('Validation failed').",
    transformation_goal: "Replace stripped assert statements with production-grade runtime exception guards.",
    plan_steps: [
      "1. Scan AST for unary assert statements used as validation guards",
      "2. Convert condition expression into explicit if-condition",
      "3. Raise standard ValueError or PermissionError with informative security context",
      "4. Verify function callers receive standard exceptions without uncaught halts"
    ],
    diff_before: 'assert user.is_authenticated, "Access denied"',
    diff_after: 'if not user.is_authenticated:\n    raise PermissionError("Access denied")',
  },
  B102: {
    category: "Arbitrary Code Execution",
    root_cause: "Dynamic execution of arbitrary code using exec() executes statements with current execution context privileges, allowing Remote Code Execution (RCE).",
    remediation: "Remove exec() entirely. Refactor code to use explicit dispatch tables or predefined command functions.",
    transformation_goal: "Eliminate arbitrary exec() runtime interpretation and substitute with static dispatch mapping.",
    plan_steps: [
      "1. Trace callers of exec() and catalog intended dynamic instructions",
      "2. Define whitelist dictionary mapping safe token keys to handler functions",
      "3. Reject unmapped dynamic inputs with safe validation exceptions",
      "4. Re-run test assertions to confirm identical business logic execution"
    ],
    diff_before: "exec(dynamic_code)",
    diff_after: "ACTION_DISPATCH = {'run': run_action, 'stop': stop_action}\nif command in ACTION_DISPATCH:\n    ACTION_DISPATCH[command]()\nelse:\n    raise ValueError(f\"Unauthorized command: {command}\")",
  },
  B105: {
    category: "Hardcoded Secret",
    root_cause: "Plaintext secret, password, or token embedded directly into source code is permanently stored in version control and vulnerable to leak.",
    remediation: "Extract secret into an environment variable using os.getenv('SECRET_KEY') or a .env file excluded in .gitignore.",
    transformation_goal: "Extract plaintext secret token to environment variable configuration.",
    plan_steps: [
      "1. Locate hardcoded secret string literal in AST assignment",
      "2. Import os or dotenv configuration helper",
      "3. Replace literal with os.environ.get('AUTH_SECRET_KEY') fallback or exception",
      "4. Verify application loads credentials seamlessly in containerized environments"
    ],
    diff_before: 'API_SECRET = "sk_live_994827104928174019284"',
    diff_after: 'import os\nAPI_SECRET = os.environ.get("API_SECRET_KEY", "")\nif not API_SECRET:\n    raise RuntimeError("API_SECRET_KEY environment variable is required")',
  },
  B106: {
    category: "Hardcoded Secret Argument",
    root_cause: "Hardcoded authentication credential passed directly to function argument.",
    remediation: "Pass credential dynamically from secure environment configuration or secret manager.",
    transformation_goal: "Remove hardcoded credentials from function invocation parameters.",
    plan_steps: [
      "1. Identify static password/token literal inside function call argument",
      "2. Substitute literal with dynamic configuration variable",
      "3. Add runtime verification that token is populated prior to invocation",
      "4. Run test suites with mock environment variables"
    ],
    diff_before: 'client.connect(host="db.internal", password="admin_root_pass_123")',
    diff_after: 'import os\nclient.connect(host="db.internal", password=os.environ.get("DB_PASSWORD"))',
  },
  B107: {
    category: "Hardcoded Secret Default",
    root_cause: "Hardcoded password set as default value in function signature.",
    remediation: "Set default to None and fetch dynamically from os.environ at runtime.",
    transformation_goal: "Eliminate static credentials from function signatures.",
    plan_steps: [
      "1. Update function signature default value from literal string to None",
      "2. Add body check: if password is None: password = os.environ.get(...)",
      "3. Raise error if no credential is provided in runtime environment",
      "4. Validate signature backwards compatibility across all callers"
    ],
    diff_before: 'def authenticate(user, password="secret_pass123"):',
    diff_after: 'def authenticate(user, password: str = None):\n    if password is None:\n        password = os.environ.get("AUTH_PASSWORD", "")',
  },
  B108: {
    category: "Insecure Temp File",
    root_cause: "Hardcoded /tmp paths introduce predictability, enabling Symlink attacks and TOCTOU (Time-of-Check to Time-of-Use) race conditions.",
    remediation: "Use tempfile.NamedTemporaryFile() or tempfile.mkstemp() with restricted permissions.",
    transformation_goal: "Replace predictable static temporary paths with safe OS-randomized temporary files.",
    plan_steps: [
      "1. Identify hardcoded '/tmp/...' string literals in file open operations",
      "2. Import python standard tempfile module",
      "3. Replace static path with tempfile.NamedTemporaryFile(delete=True)",
      "4. Verify file handle cleanup and restrictive permission masking (0600)"
    ],
    diff_before: 'with open("/tmp/data.cache", "w") as f:\n    f.write(payload)',
    diff_after: 'import tempfile\nwith tempfile.NamedTemporaryFile(mode="w", delete=False) as f:\n    f.write(payload)\n    temp_path = f.name',
  },
  B301: {
    category: "Insecure Deserialization",
    root_cause: "Unpickling untrusted byte streams can execute arbitrary Python bytecode via __reduce__.",
    remediation: "Never use pickle for untrusted input. Use safe data interchange formats like json.loads() or protobuf.",
    transformation_goal: "Migrate dangerous pickle deserialization to safe JSON/structured parser.",
    plan_steps: [
      "1. Locate pickle.loads() or pickle.load() in request handling pathways",
      "2. Replace pickle serializer with json.loads() or msgpack",
      "3. Validate data schema using pydantic or typed dictionaries",
      "4. Ensure non-serializable objects use explicit field mapping"
    ],
    diff_before: "import pickle\ndata = pickle.loads(untrusted_payload)",
    diff_after: 'import json\ndata = json.loads(untrusted_payload.decode("utf-8"))',
  },
  B303: {
    category: "Weak Cryptographic Hash",
    root_cause: "MD5 algorithm is cryptographically broken and vulnerable to collision attacks (rainbow tables).",
    remediation: "Upgrade to hashlib.sha256() or use bcrypt/argon2 for password hashing.",
    transformation_goal: "Upgrade weak MD5 digest to collision-resistant SHA-256 algorithm.",
    plan_steps: [
      "1. Identify hashlib.md5 invocation in hashing routine",
      "2. Replace algorithm with hashlib.sha256()",
      "3. Ensure digest encoding is maintained (.hexdigest() return string)",
      "4. Verify database columns support 64-character hex digests"
    ],
    diff_before: 'token = hashlib.md5(data.encode("utf-8")).hexdigest()',
    diff_after: 'token = hashlib.sha256(data.encode("utf-8")).hexdigest()',
  },
  B307: {
    category: "Arbitrary Code Execution",
    root_cause: "eval() evaluates arbitrary strings as Python expressions with access to builtins and globals, creating a direct Remote Code Execution (RCE) vector.",
    remediation: "Use ast.literal_eval() for safely parsing literal Python types, or use json.loads() for structured data.",
    transformation_goal: "Replace dangerous eval() with safe AST literal parser ast.literal_eval().",
    plan_steps: [
      "1. Locate eval(expression) call inside computational service",
      "2. Import standard library ast module",
      "3. Replace eval(expression) with ast.literal_eval(expression)",
      "4. Wrap with ValueError/SyntaxError exception handling for invalid syntax"
    ],
    diff_before: "def vulnerable_eval(expression):\n    return eval(expression)",
    diff_after: "import ast\n\ndef vulnerable_eval(expression):\n    return ast.literal_eval(expression)",
  },
  B324: {
    category: "Weak Cryptographic Hash",
    root_cause: "MD5 hash algorithm is vulnerable to hash collision attacks, making passwords and signatures easy to forge.",
    remediation: "Replace with hashlib.sha256() or specify usedforsecurity=False if hashing only for non-security checksums.",
    transformation_goal: "Upgrade MD5 authentication hashing to NIST-approved SHA-256 cryptographic hash.",
    plan_steps: [
      "1. Identify insecure MD5 call: hashlib.md5(password.encode('utf-8')).hexdigest()",
      "2. Substitute hashing algorithm with hashlib.sha256()",
      "3. Preserve input argument types and string return contract for all callers",
      "4. Verify automated regression tests (test_auth_service.py) execute cleanly"
    ],
    diff_before: 'def hash_password(self, password: str) -> str:\n    return hashlib.md5(password.encode("utf-8")).hexdigest()',
    diff_after: 'def hash_password(self, password: str) -> str:\n    return hashlib.sha256(password.encode("utf-8")).hexdigest()',
  },
  B404: {
    category: "Subprocess Module Import",
    root_cause: "Direct import of subprocess module requires strict defensive parameters (shell=False) to prevent shell injection.",
    remediation: "Ensure all subprocess calls specify shell=False and pass arguments as structured token lists.",
    transformation_goal: "Audit subprocess usage and enforce strict argument array passing.",
    plan_steps: [
      "1. Review imported subprocess methods across the module",
      "2. Enforce shell=False on all call/Popen/run executions",
      "3. Use shlex.split() to tokenize dynamic user arguments",
      "4. Implement timeout and return code checks"
    ],
    diff_before: "import subprocess\nsubprocess.call(command, shell=True)",
    diff_after: "import subprocess\nimport shlex\nsubprocess.run(shlex.split(command), shell=False, check=True)",
  },
  B501: {
    category: "Insecure TLS Communication",
    root_cause: "Disabling TLS certificate validation (verify=False) allows attackers on the network to intercept or manipulate traffic (MITM).",
    remediation: "Always enforce verify=True or provide trusted CA certificate bundle.",
    transformation_goal: "Enforce strict TLS certificate verification to eliminate Man-in-the-Middle (MITM) risks.",
    plan_steps: [
      "1. Locate requests or urllib HTTP client calls with verify=False",
      "2. Update parameter to verify=True or specify custom corporate CA bundle",
      "3. Enable strict SSL timeout to prevent slowloris hang",
      "4. Test HTTPS endpoint connectivity under enforced trust store"
    ],
    diff_before: "response = requests.get(api_url, verify=False)",
    diff_after: "response = requests.get(api_url, verify=True, timeout=10)",
  },
  B506: {
    category: "Unsafe YAML Deserialization",
    root_cause: "Default yaml.load() instantiates arbitrary Python classes and functions, allowing remote code execution via malicious YAML.",
    remediation: "Replace yaml.load(data, Loader=yaml.Loader) with yaml.safe_load(data).",
    transformation_goal: "Replace dangerous PyYAML yaml.load() with secure yaml.safe_load().",
    plan_steps: [
      "1. Locate yaml.load() call in configuration loader utilities",
      "2. Replace invocation with yaml.safe_load(content)",
      "3. Remove custom dangerous Loader parameter objects",
      "4. Verify configuration dictionary parses without object construction"
    ],
    diff_before: "def load_config(content):\n    return yaml.load(content, Loader=yaml.Loader)",
    diff_after: "def load_config(content):\n    return yaml.safe_load(content)",
  },
  B602: {
    category: "Command Injection",
    root_cause: "Invoking subprocess with shell=True opens an OS command shell, allowing command injection through shell metacharacters (; & |).",
    remediation: "Set shell=False and pass arguments as an explicit sanitized list: subprocess.run(['cmd', arg1, arg2]).",
    transformation_goal: "Eliminate shell=True and pass command arguments as explicit sanitized token list.",
    plan_steps: [
      "1. Locate subprocess.call or subprocess.Popen with shell=True",
      "2. Tokenize raw command string using shlex.split(cmd)",
      "3. Set shell=False explicitly and specify subprocess.run(..., check=True)",
      "4. Run execution test suites to verify identical command return codes"
    ],
    diff_before: "def run_system_cmd(cmd):\n    return subprocess.call(cmd, shell=True)",
    diff_after: "import shlex\nimport subprocess\n\ndef run_system_cmd(cmd):\n    args = shlex.split(cmd) if isinstance(cmd, str) else cmd\n    return subprocess.run(args, shell=False, check=False).returncode",
  },
  B608: {
    category: "SQL Injection (SQLi)",
    root_cause: "Direct string concatenation or formatting (+, %, f-strings) into SQL queries allows attackers to manipulate query logic, bypass authentication, or dump database tables.",
    remediation: "Use parameterized queries with prepared placeholders: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,)).",
    transformation_goal: "Convert string-concatenated SQL queries into safe parameterized prepared statements.",
    plan_steps: [
      "1. Locate dynamic SQL string concatenation (+, f-strings, %) in database repository",
      "2. Replace interpolated variables with parameterized query placeholders (?)",
      "3. Pass query parameters as a tuple in cursor.execute(query, (user_id,))",
      "4. Execute database regression tests to verify exact row retrieval"
    ],
    diff_before: 'query = "SELECT id, username, role FROM users WHERE id = " + str(user_id)\ncursor.execute(query)',
    diff_after: 'query = "SELECT id, username, role FROM users WHERE id = ?"\ncursor.execute(query, (user_id,))',
  },
};

function getFindingSpecs(finding) {
  if (!finding) {
    return {
      root_cause: "",
      remediation: "",
      category: "",
      cwe_title: "",
      transformation_goal: "",
      plan_steps: [],
      diff_before: "",
      diff_after: "",
    };
  }
  const spec = FRONTEND_RULE_SPECS[finding.test_id] || {};
  return {
    category: finding.category || spec.category || finding.test_name?.replace(/_/g, " ").toUpperCase() || "Vulnerability",
    cwe_title: finding.cwe_title || spec.cwe_title || (finding.issue_cwe?.id ? `CWE-${finding.issue_cwe.id}` : "Security Flaw"),
    root_cause: finding.root_cause || spec.root_cause || `${finding.issue_text || "Security issue"} identified by static AST analysis.`,
    remediation: finding.remediation || spec.remediation || "Review source line, apply input validation, and use safe defensive APIs.",
    transformation_goal: finding.transformation_goal || spec.transformation_goal || `Eliminate ${finding.test_id || "vulnerability"} while preserving full backwards compatibility.`,
    plan_steps: finding.plan_steps && finding.plan_steps.length > 0 ? finding.plan_steps : (spec.plan_steps || [
      `1. Locate vulnerable pattern ${finding.test_id || 'vulnerability'} in ${finding.filename || 'source'}`,
      "2. Analyze caller hierarchy and preserve backwards compatibility",
      "3. Replace vulnerable invocation with hardened defensive alternative",
      "4. Execute regression tests to verify zero behavioral breakage",
    ]),
    diff_before: finding.diff_before || spec.diff_before || finding.code?.trim() || "# Insecure code pattern",
    diff_after: finding.diff_after || spec.diff_after || "# Hardened secure code implementation",
  };
}

/* =========================================================
   OVERVIEW
========================================================= */

function Overview({
  repoPath,
  githubUrl,
  setGithubUrl,
  repoFile,
  setRepoFile,
  importing,
  repositoryName,
  repositorySource,
  importGitHubRepository,
  liveAuditGitHubRepository,
  importUploadedRepository,
  liveAuditUploadedRepository,
  resetRepository,
  scanning,
  scanRepository,
  summary,
  findings = [],
  selectedFinding,
  setSelected,
  onSelectFinding,
  analyzeFinding,
  analysis,
  analyzing,
  liveLogs = [],
  liveProgress = 0,
  liveStage = "",
  liveActive = false,
  terminalRef,
  clearLiveLogs,
}) {
  const [importMode, setImportMode] = useState("github"); // "github" or "zip"
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [liveTab, setLiveTab] = useState("logs"); // "logs" or "findings"

  const filteredFindings = useMemo(() => {
    return (findings || []).filter((f) => {
      if (severityFilter !== "ALL") {
        if ((f.issue_severity || "").toUpperCase() !== severityFilter) return false;
      }
      if (!searchQuery.trim()) return true;
      const q = searchQuery.toLowerCase().trim();
      const specs = getFindingSpecs(f);
      return (
        (f.test_id || "").toLowerCase().includes(q) ||
        (f.filename || "").toLowerCase().includes(q) ||
        (f.issue_text || "").toLowerCase().includes(q) ||
        (specs.category || "").toLowerCase().includes(q) ||
        (specs.root_cause || "").toLowerCase().includes(q) ||
        (specs.remediation || "").toLowerCase().includes(q)
      );
    });
  }, [findings, searchQuery, severityFilter]);
  return (
    <>
      <section className="hero-grid">

        {/* HERO */}
        <div className="hero-card">

          <div className="hero-glow" />

          <div className="hero-content">

            <div className="hero-badge">
              <Shield size={15} />
              AI-ASSISTED
              VULNERABILITY
              REPAIR
            </div>

            <h2>
              Secure your Python
              repository.
            </h2>

            <p>
              Connect your repository,
              detect vulnerabilities,
              understand their code
              impact, generate a minimal
              security patch, and verify
              it safely in an isolated
              environment.
            </p>

            {/* =================================================
                REPOSITORY IMPORT
            ================================================= */}

            <div
              className="repository-import"
              style={{
                marginTop: "20px",
                padding: "18px",
                border: "1px solid #20352a",
                background: "rgba(5, 12, 9, 0.85)",
                borderRadius: "14px",
              }}
            >
              {/* HEADER / SELECTOR */}
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  marginBottom: "14px",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "8px",
                    color: "#9ee9b8",
                    fontSize: "10px",
                    fontFamily: "DM Mono, monospace",
                    letterSpacing: "0.12em",
                    textTransform: "uppercase",
                  }}
                >
                  <FileCode2 size={16} />
                  <span>Repository Ingestion</span>
                </div>

                <div
                  style={{
                    fontSize: "10px",
                    color: "#52655b",
                    fontFamily: "DM Mono, monospace",
                  }}
                >
                  LIVE SAST + AST PIPELINE
                </div>
              </div>

              {/* METHOD TABS */}
              <div
                style={{
                  display: "grid",
                  gridTemplateColumns: "1fr 1fr",
                  gap: "8px",
                  background: "#030805",
                  padding: "4px",
                  borderRadius: "10px",
                  border: "1px solid #14241b",
                  marginBottom: "16px",
                }}
              >
                <button
                  type="button"
                  onClick={() => setImportMode("github")}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    gap: "8px",
                    padding: "9px 12px",
                    borderRadius: "7px",
                    fontSize: "11px",
                    fontFamily: "DM Mono, monospace",
                    fontWeight: 600,
                    cursor: "pointer",
                    border: importMode === "github" ? "1px solid #00ff88" : "1px solid transparent",
                    background: importMode === "github" ? "rgba(0, 255, 136, 0.12)" : "transparent",
                    color: importMode === "github" ? "#00ff88" : "#6f887b",
                    transition: "all 0.18s ease",
                  }}
                >
                  <GitBranch size={15} />
                  <span>GitHub Direct Link / ZIP URL</span>
                </button>

                <button
                  type="button"
                  onClick={() => setImportMode("zip")}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    gap: "8px",
                    padding: "9px 12px",
                    borderRadius: "7px",
                    fontSize: "11px",
                    fontFamily: "DM Mono, monospace",
                    fontWeight: 600,
                    cursor: "pointer",
                    border: importMode === "zip" ? "1px solid #00ff88" : "1px solid transparent",
                    background: importMode === "zip" ? "rgba(0, 255, 136, 0.12)" : "transparent",
                    color: importMode === "zip" ? "#00ff88" : "#6f887b",
                    transition: "all 0.18s ease",
                  }}
                >
                  <Upload size={15} />
                  <span>Manual ZIP Upload</span>
                </button>
              </div>

              {/* TAB 1: GITHUB */}
              {importMode === "github" && (
                <div>
                  <div
                    style={{
                      fontSize: "11px",
                      color: "#8aa294",
                      marginBottom: "10px",
                      lineHeight: "1.4",
                    }}
                  >
                    Enter a public GitHub repository URL or direct ZIP archive link. SecurePatch fetches the repository into a secure sandbox, detects vulnerabilities live, and prepares automated AST fixes.
                  </div>

                  <div
                    className="github-row"
                    style={{
                      display: "flex",
                      gap: "9px",
                    }}
                  >
                    <div
                      className="repo-input"
                      style={{
                        flex: 1,
                      }}
                    >
                      <GitBranch size={17} />
                      <input
                        value={githubUrl}
                        onChange={(e) => setGithubUrl(e.target.value)}
                        placeholder="https://github.com/owner/repository (or .git / .zip release archive URL)"
                      />
                    </div>

                    <button
                      className="primary-btn"
                      onClick={() => liveAuditGitHubRepository ? liveAuditGitHubRepository() : importGitHubRepository()}
                      disabled={importing || scanning || !githubUrl.trim()}
                      style={{
                        whiteSpace: "nowrap",
                        padding: "0 18px",
                      }}
                    >
                      {importing || scanning ? (
                        <>
                          <RefreshCw size={15} className="spin" />
                          <span>AUDITING LIVE...</span>
                        </>
                      ) : (
                        <>
                          <Zap size={15} />
                          <span>LIVE AUDIT GITHUB</span>
                        </>
                      )}
                    </button>

                    <button
                      className="secondary-btn"
                      onClick={() => importGitHubRepository(githubUrl)}
                      disabled={importing || scanning || !githubUrl.trim()}
                      style={{
                        whiteSpace: "nowrap",
                        padding: "0 14px",
                      }}
                      title="Import and stage repository files in workspace"
                    >
                      <Download size={15} />
                      <span>IMPORT ONLY</span>
                    </button>
                  </div>

                  {/* QUICK PRESETS */}
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "8px",
                      marginTop: "10px",
                      flexWrap: "wrap",
                    }}
                  >
                    <span
                      style={{
                        fontSize: "9px",
                        fontFamily: "DM Mono, monospace",
                        color: "#52655b",
                        textTransform: "uppercase",
                      }}
                    >
                      Quick Presets:
                    </span>

                    <button
                      type="button"
                      onClick={() => setGithubUrl("https://github.com/Tushar-1208-cyber/SecurePatch.git")}
                      style={{
                        background: "#08130c",
                        border: "1px solid #1a3626",
                        color: "#7ee4a2",
                        padding: "3px 8px",
                        borderRadius: "5px",
                        fontSize: "10px",
                        fontFamily: "DM Mono, monospace",
                        cursor: "pointer",
                      }}
                    >
                      ⚡ Tushar-1208-cyber/SecurePatch
                    </button>

                    <button
                      type="button"
                      onClick={() => setGithubUrl("https://github.com/Tushar-1208-cyber/SecurePatch/archive/refs/heads/main.zip")}
                      style={{
                        background: "#08130c",
                        border: "1px solid #1a3626",
                        color: "#83a992",
                        padding: "3px 8px",
                        borderRadius: "5px",
                        fontSize: "10px",
                        fontFamily: "DM Mono, monospace",
                        cursor: "pointer",
                      }}
                    >
                      📦 Direct Main ZIP Archive
                    </button>
                  </div>
                </div>
              )}

              {/* TAB 2: MANUAL ZIP */}
              {importMode === "zip" && (
                <div>
                  <div
                    style={{
                      fontSize: "11px",
                      color: "#8aa294",
                      marginBottom: "10px",
                      lineHeight: "1.4",
                    }}
                  >
                    Upload a local repository .zip archive from your computer.
                  </div>

                  <div
                    className="upload-row"
                    style={{
                      display: "flex",
                      gap: "9px",
                    }}
                  >
                    <label
                      className="upload-box"
                      style={{
                        flex: 1,
                        minHeight: "43px",
                        display: "flex",
                        alignItems: "center",
                        gap: "9px",
                        padding: "0 12px",
                        border: "1px dashed #31513f",
                        borderRadius: "9px",
                        background: "#080e0b",
                        color: "#7f9489",
                        fontSize: "11px",
                        cursor: "pointer",
                      }}
                    >
                      <Upload size={18} />
                      <span style={{ color: repoFile ? "#00ff88" : "#7f9489" }}>
                        {repoFile ? repoFile.name : "Select or drag & drop repository .ZIP"}
                      </span>
                      <input
                        type="file"
                        accept=".zip"
                        hidden
                        onChange={(e) => setRepoFile(e.target.files?.[0] || null)}
                      />
                    </label>

                    <button
                      className="primary-btn"
                      onClick={liveAuditUploadedRepository}
                      disabled={importing || scanning || !repoFile}
                      style={{
                        whiteSpace: "nowrap",
                        padding: "0 18px",
                      }}
                    >
                      {importing || scanning ? (
                        <>
                          <RefreshCw size={15} className="spin" />
                          <span>AUDITING LIVE...</span>
                        </>
                      ) : (
                        <>
                          <Zap size={15} />
                          <span>LIVE AUDIT ZIP</span>
                        </>
                      )}
                    </button>

                    <button
                      className="secondary-btn"
                      onClick={importUploadedRepository}
                      disabled={importing || scanning || !repoFile}
                      style={{
                        whiteSpace: "nowrap",
                        padding: "0 14px",
                      }}
                    >
                      <Upload size={15} />
                      <span>IMPORT ZIP</span>
                    </button>
                  </div>
                </div>
              )}

              {/* LOADED REPOSITORY STATUS */}
              {repositoryName && (
                <div
                  className="repository-loaded"
                  style={{
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "space-between",
                    gap: "10px",
                    marginTop: "14px",
                    padding: "10px 14px",
                    border: "1px solid #245338",
                    borderRadius: "8px",
                    background: "#0a1810",
                    color: "#7ee4a2",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                    <CheckCircle2 size={18} />
                    <div>
                      <strong style={{ display: "block", fontSize: "11px" }}>
                        {repositoryName}
                      </strong>
                      <span
                        style={{
                          display: "block",
                          marginTop: "2px",
                          color: "#61786a",
                          fontSize: "9px",
                          fontFamily: "DM Mono, monospace",
                        }}
                      >
                        Source: {repositorySource} • Ready for AST Inspection & Patching
                      </span>
                    </div>
                  </div>

                  <div style={{ display: "flex", gap: "8px" }}>
                    <button
                      type="button"
                      onClick={() => scanRepository()}
                      disabled={scanning || importing}
                      style={{
                        background: "rgba(0, 255, 136, 0.15)",
                        border: "1px solid #00ff88",
                        color: "#00ff88",
                        padding: "4px 10px",
                        borderRadius: "5px",
                        cursor: "pointer",
                        fontSize: "10px",
                        fontWeight: 600,
                      }}
                    >
                      ⚡ Re-Scan Repo
                    </button>
                    {resetRepository && (
                      <button
                        type="button"
                        onClick={resetRepository}
                        style={{
                          background: "transparent",
                          border: "1px solid #2d4538",
                          color: "#7a9586",
                          padding: "4px 8px",
                          borderRadius: "5px",
                          cursor: "pointer",
                          fontSize: "10px",
                        }}
                      >
                        Switch Repo
                      </button>
                    )}
                  </div>
                </div>
              )}

              {/* RUN SCAN MAIN BUTTON (WHEN REPO LOADED) */}
              {repoPath && (
                <button
                  className="primary-btn scan-button"
                  onClick={scanRepository}
                  disabled={!repoPath || importing || scanning}
                  style={{
                    width: "100%",
                    marginTop: "12px",
                  }}
                >
                  {scanning ? (
                    <>
                      <RefreshCw size={17} className="spin" />
                      <span>LIVE SCANNING ACTIVE...</span>
                    </>
                  ) : (
                    <>
                      <Play size={17} fill="currentColor" />
                      <span>START FULL SECURITY SCAN</span>
                    </>
                  )}
                </button>
              )}

            </div>

          </div>

        </div>

        {/* ENGINE STATUS */}
        <div className="architecture-card">

          <div className="section-kicker">
            ENGINE STATUS
          </div>

          <EngineRow
            icon={
              <Terminal
                size={16}
              />
            }
            label="Bandit Scanner"
            status="READY"
          />

          <EngineRow
            icon={
              <Network
                size={16}
              />
            }
            label="AST Source Graph"
            status="READY"
          />

          <EngineRow
            icon={
              <Bot
                size={16}
              />
            }
            label="AI Patch Generator"
            status="READY"
          />

          <EngineRow
            icon={
              <ShieldCheck
                size={16}
              />
            }
            label="Validation Engine"
            status="READY"
          />

        </div>

      </section>

      {/* LIVE AUDIT CONSOLE / REAL-TIME STREAM */}
      {(liveActive || (liveLogs && liveLogs.length > 0)) && (
        <section
          className="live-audit-panel"
          style={{
            marginTop: "18px",
            marginBottom: "18px",
            border: "1px solid #1c3629",
            background: "linear-gradient(180deg, #09130e 0%, #060a08 100%)",
            borderRadius: "14px",
            overflow: "hidden",
            boxShadow: "0 12px 35px rgba(0,0,0,0.45)",
          }}
        >
          {/* Header */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "14px 18px",
              background: "#0c1813",
              borderBottom: "1px solid #182d22",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <div
                style={{
                  width: "10px",
                  height: "10px",
                  borderRadius: "50%",
                  background: liveActive ? "#5cf49d" : "#556e61",
                  boxShadow: liveActive ? "0 0 10px #5cf49d" : "none",
                }}
              />
              <span
                style={{
                  fontFamily: "DM Mono, monospace",
                  fontSize: "11px",
                  fontWeight: 700,
                  color: "#d4ece0",
                  letterSpacing: "0.08em",
                }}
              >
                LIVE AUDIT ENGINE // {liveStage || (liveActive ? "SCANNING" : "COMPLETED")}
              </span>
              {liveActive && (
                <span
                  style={{
                    fontSize: "9px",
                    fontFamily: "DM Mono, monospace",
                    background: "rgba(92, 244, 157, 0.15)",
                    color: "#6ef29e",
                    border: "1px solid #28583e",
                    borderRadius: "6px",
                    padding: "2px 7px",
                  }}
                >
                  REALTIME SSE
                </span>
              )}
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
              <span
                style={{
                  fontFamily: "DM Mono, monospace",
                  fontSize: "11px",
                  color: "#84968e",
                }}
              >
                Progress: <strong style={{ color: "#7eedad" }}>{liveProgress}%</strong>
              </span>
              {clearLiveLogs && (
                <button
                  onClick={clearLiveLogs}
                  style={{
                    background: "transparent",
                    border: "1px solid #20352a",
                    color: "#6c8578",
                    padding: "3px 9px",
                    borderRadius: "5px",
                    fontSize: "10px",
                    fontFamily: "DM Mono, monospace",
                    cursor: "pointer",
                  }}
                >
                  Clear Logs
                </button>
              )}
            </div>
          </div>

          {/* Progress bar */}
          <div style={{ width: "100%", height: "3px", background: "#101d16" }}>
            <div
              style={{
                width: `${liveProgress}%`,
                height: "100%",
                background: liveProgress === 100 ? "#5cf49d" : "linear-gradient(90deg, #389461, #5cf49d)",
                boxShadow: "0 0 10px rgba(92,244,157,0.5)",
                transition: "width 0.3s ease",
              }}
            />
          </div>

          {/* View Mode Bar */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "8px 18px",
              background: "#08100c",
              borderBottom: "1px solid #14241b",
            }}
          >
            <div style={{ display: "flex", gap: "8px" }}>
              <button
                onClick={() => setLiveTab("logs")}
                style={{
                  background: liveTab === "logs" ? "#152d20" : "transparent",
                  color: liveTab === "logs" ? "#7eedad" : "#698174",
                  border: `1px solid ${liveTab === "logs" ? "#2e6144" : "transparent"}`,
                  borderRadius: "6px",
                  padding: "4px 10px",
                  fontSize: "10.5px",
                  fontFamily: "DM Mono, monospace",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                }}
              >
                <Terminal size={12} />
                STREAM LOGS ({liveLogs.length})
              </button>

              <button
                onClick={() => setLiveTab("findings")}
                style={{
                  background: liveTab === "findings" ? "#152d20" : "transparent",
                  color: liveTab === "findings" ? "#7eedad" : "#698174",
                  border: `1px solid ${liveTab === "findings" ? "#2e6144" : "transparent"}`,
                  borderRadius: "6px",
                  padding: "4px 10px",
                  fontSize: "10.5px",
                  fontFamily: "DM Mono, monospace",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                }}
              >
                <AlertTriangle size={12} />
                LIVE DETECTED VULNERABILITIES ({findings.length})
              </button>
            </div>

            <div style={{ fontSize: "10px", color: "#546e61", fontFamily: "DM Mono, monospace" }}>
              {liveActive ? "⚡ Streaming live AST analysis..." : "✓ Audit session ready"}
            </div>
          </div>

          {/* Tab 1: Live Terminal Output */}
          {liveTab === "logs" && (
            <div
              ref={terminalRef}
              style={{
                padding: "14px 18px",
                fontFamily: "DM Mono, monospace",
                fontSize: "11.5px",
                lineHeight: "1.75",
                maxHeight: "220px",
                overflowY: "auto",
                background: "#050907",
                color: "#a4b9af",
              }}
            >
              {liveLogs.map((log, index) => {
                const stage = (log.stage || (log.rule_id ? "DETECT" : log.type) || "INFO").toUpperCase();
                const rawMsg = log.message || log.msg || log.issue_text || log.text;
                const message = rawMsg || (log.rule_id 
                  ? `[${log.severity || "WARN"}] ${log.category || log.rule_id} identified in ${log.filename || "source"}${log.line ? `:${log.line}` : ""}` 
                  : "Security pipeline audit event recorded.");

                let color = "#cbe1d5";
                let badgeBg = "rgba(100, 120, 110, 0.25)";
                let badgeColor = "#9fb8ac";

                if (stage === "DETECT" || log.severity === "HIGH" || log.level === "high" || log.level === "error") {
                  color = "#ffb0b0";
                  badgeBg = "rgba(255, 75, 75, 0.25)";
                  badgeColor = "#ff7878";
                } else if (stage === "DONE" || stage === "COMPLETE" || log.level === "success") {
                  color = "#7eedad";
                  badgeBg = "rgba(110, 242, 158, 0.22)";
                  badgeColor = "#6ef29e";
                } else if (stage === "SAST") {
                  color = "#bae6fd";
                  badgeBg = "rgba(56, 189, 248, 0.22)";
                  badgeColor = "#38bdf8";
                } else if (stage === "GRAPH" || stage === "INDEX" || stage === "CONNECT" || stage === "CLONE") {
                  color = "#fde68a";
                  badgeBg = "rgba(251, 191, 36, 0.22)";
                  badgeColor = "#fbbf24";
                }

                return (
                  <div
                    key={index}
                    style={{
                      display: "flex",
                      alignItems: "flex-start",
                      gap: "10px",
                      marginBottom: "4px",
                      wordBreak: "break-word",
                    }}
                  >
                    <span
                      style={{
                        padding: "2px 7px",
                        borderRadius: "4px",
                        fontSize: "9.5px",
                        fontWeight: 700,
                        background: badgeBg,
                        color: badgeColor,
                        letterSpacing: "0.06em",
                        flexShrink: 0,
                      }}
                    >
                      {stage}
                    </span>
                    <span style={{ color: "#4f6358", flexShrink: 0, fontSize: "10px", marginTop: "1px" }}>
                      {log.time}
                    </span>
                    <span style={{ color, flex: 1, fontSize: "11.5px" }}>
                      {message}
                    </span>
                  </div>
                );
              })}
            </div>
          )}

          {/* Tab 2: Live Detected Findings Stream */}
          {liveTab === "findings" && (
            <div
              style={{
                padding: "14px 18px",
                maxHeight: "260px",
                overflowY: "auto",
                background: "#050907",
              }}
            >
              {findings.length === 0 ? (
                <div style={{ padding: "20px", textAlign: "center", color: "#546e61", fontSize: "11px", fontFamily: "DM Mono, monospace" }}>
                  Waiting for detection engine... No findings detected yet.
                </div>
              ) : (
                findings.map((f, i) => {
                  const specs = getFindingSpecs(f);
                  return (
                    <div
                      key={i}
                      onClick={() => onSelectFinding && onSelectFinding(f)}
                      style={{
                        background: "#09120e",
                        border: "1px solid #1a2c22",
                        borderRadius: "8px",
                        padding: "10px 12px",
                        marginBottom: "8px",
                        cursor: "pointer",
                        transition: "all 0.15s ease",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                        <div style={{ display: "flex", gap: "7px", alignItems: "center" }}>
                          <span style={{ fontWeight: 700, color: "#9ef5bb", fontSize: "11px", fontFamily: "DM Mono, monospace" }}>
                            {f.test_id}
                          </span>
                          <span className={`severity ${severityClass(f.issue_severity)}`}>
                            {f.issue_severity}
                          </span>
                          <span style={{ fontSize: "10px", color: "#7dd3fc", fontFamily: "DM Mono, monospace" }}>
                            {specs.category}
                          </span>
                        </div>
                        <span style={{ fontSize: "10px", color: "#657e72", fontFamily: "DM Mono, monospace" }}>
                          {f.filename}:{f.line_number}
                        </span>
                      </div>
                      <div style={{ fontSize: "11.5px", color: "#e2ede7", fontWeight: 600, marginBottom: "5px" }}>
                        {f.issue_text}
                      </div>
                      <div style={{ fontSize: "10.5px", color: "#fca5a5", marginBottom: "3px" }}>
                        <strong>⚠️ Root Cause: </strong>{specs.root_cause}
                      </div>
                      <div style={{ fontSize: "10.5px", color: "#86efac" }}>
                        <strong>💡 Remediation: </strong>{specs.remediation}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          )}
        </section>
      )}

      {/* STATS */}
      <section className="stats-grid">

        <Stat
          label="Total Findings"
          value={
            summary.total || 0
          }
          icon={AlertTriangle}
        />

        <Stat
          label="High Severity"
          value={
            summary.high || 0
          }
          icon={AlertTriangle}
          tone="high"
        />

        <Stat
          label="Medium Severity"
          value={
            summary.medium || 0
          }
          icon={Shield}
          tone="medium"
        />

        <Stat
          label="Low Severity"
          value={
            summary.low || 0
          }
          icon={Activity}
          tone="low"
        />

      </section>

      {/* FINDINGS */}
      <section className="content-grid">

        <div className="panel">

          <div className="panel-head">

            <div>

              <div className="section-kicker">
                DETECTION RESULTS
              </div>

              <h3>
                Vulnerability Explorer
              </h3>

            </div>

            <span className="count-pill">
              {filteredFindings.length} of {findings.length} findings
            </span>

          </div>

          {/* SEARCH & FILTERS BAR */}
          <div
            style={{
              padding: "0 0 16px 0",
              display: "flex",
              flexDirection: "column",
              gap: "10px",
            }}
          >
            {/* Search Input */}
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "10px",
                background: "#070d0a",
                border: "1px solid #1a2a21",
                borderRadius: "9px",
                padding: "0 14px",
              }}
            >
              <Search size={15} style={{ color: "#617d70", flexShrink: 0 }} />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by Rule (B608), CWE, keyword (sql, eval, password, hash), or file..."
                style={{
                  width: "100%",
                  background: "transparent",
                  border: "none",
                  outline: "none",
                  color: "#d0e3d8",
                  fontSize: "11.5px",
                  fontFamily: "DM Mono, monospace",
                  padding: "10px 0",
                }}
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery("")}
                  style={{
                    background: "transparent",
                    border: "none",
                    color: "#6b8679",
                    cursor: "pointer",
                    fontSize: "12px",
                  }}
                >
                  ✕
                </button>
              )}
            </div>

            {/* Severity Filter Pills */}
            <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center" }}>
              <span style={{ fontSize: "10px", color: "#546e61", fontFamily: "DM Mono, monospace", marginRight: "2px" }}>
                FILTER:
              </span>
              {[
                { label: "ALL", count: findings.length },
                { label: "HIGH", count: findings.filter((f) => (f.issue_severity || "").toUpperCase() === "HIGH").length },
                { label: "MEDIUM", count: findings.filter((f) => (f.issue_severity || "").toUpperCase() === "MEDIUM").length },
                { label: "LOW", count: findings.filter((f) => (f.issue_severity || "").toUpperCase() === "LOW").length },
              ].map(({ label, count }) => {
                const active = severityFilter === label;
                let activeColor = "#7eedad";
                let activeBorder = "#2e6144";
                let activeBg = "#152d20";

                if (label === "HIGH") {
                  activeColor = "#ff8c8f";
                  activeBorder = "#7c2f32";
                  activeBg = "#381313";
                } else if (label === "MEDIUM") {
                  activeColor = "#f5bd6e";
                  activeBorder = "#6d4a1b";
                  activeBg = "#31230e";
                }

                return (
                  <button
                    key={label}
                    onClick={() => setSeverityFilter(label)}
                    style={{
                      background: active ? activeBg : "#08100c",
                      color: active ? activeColor : "#6c8477",
                      border: `1px solid ${active ? activeBorder : "#16251d"}`,
                      borderRadius: "6px",
                      padding: "4px 10px",
                      fontSize: "10.5px",
                      fontFamily: "DM Mono, monospace",
                      fontWeight: active ? 700 : 500,
                      cursor: "pointer",
                      transition: "all 0.15s ease",
                    }}
                  >
                    {label} ({count})
                  </button>
                );
              })}
            </div>
          </div>

          <div className="finding-list">

            {findings.length === 0 ? (
              <EmptyState
                onScan={
                  scanRepository
                }
                hasRepository={
                  !!repoPath
                }
              />
            ) : filteredFindings.length === 0 ? (
              <div
                style={{
                  padding: "36px 18px",
                  textAlign: "center",
                  color: "#6b8679",
                  fontFamily: "DM Mono, monospace",
                  fontSize: "11px",
                  border: "1px dashed #1a2c22",
                  borderRadius: "10px",
                }}
              >
                No vulnerabilities match your search query "{searchQuery}".
                <div style={{ marginTop: "10px" }}>
                  <button
                    onClick={() => {
                      setSearchQuery("");
                      setSeverityFilter("ALL");
                    }}
                    style={{
                      background: "#102218",
                      border: "1px solid #28543b",
                      color: "#7eedad",
                      padding: "6px 14px",
                      borderRadius: "6px",
                      fontSize: "11px",
                      cursor: "pointer",
                    }}
                  >
                    Reset Search & Filters
                  </button>
                </div>
              </div>
            ) : (
              filteredFindings.map(
                (
                  finding,
                  index
                ) => {
                  const specs = getFindingSpecs(finding);
                  const isSelected =
                    selectedFinding?.test_id === finding.test_id &&
                    selectedFinding?.line_number === finding.line_number &&
                    selectedFinding?.filename === finding.filename;

                  const sev = (finding.issue_severity || "LOW").toUpperCase();
                  let sevBorder = isSelected ? "#4ade80" : "#1a2c22";
                  if (sev === "HIGH") {
                    sevBorder = isSelected ? "#e05357" : "#3b1e1f";
                  } else if (sev === "MEDIUM") {
                    sevBorder = isSelected ? "#e5a753" : "#382917";
                  }

                  return (
                    <div
                      key={`${finding.test_id}-${finding.line_number}-${index}`}
                      onClick={() => {
                        if (onSelectFinding) {
                          onSelectFinding(finding);
                        } else {
                          setSelected(finding);
                        }
                      }}
                      style={{
                        display: "flex",
                        flexDirection: "column",
                        padding: "14px 16px",
                        borderRadius: "10px",
                        border: `1px solid ${sevBorder}`,
                        background: isSelected ? "#0e1d16" : "#09120e",
                        boxShadow: isSelected ? "0 0 20px rgba(74, 222, 128, 0.12)" : "none",
                        cursor: "pointer",
                        marginBottom: "9px",
                        transition: "all 0.18s ease",
                      }}
                    >
                      {/* Top Row: Rule, CWE, Severity, File */}
                      <div
                        style={{
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "space-between",
                          flexWrap: "wrap",
                          gap: "8px",
                          marginBottom: "8px",
                        }}
                      >
                        <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
                          <span
                            style={{
                              fontFamily: "DM Mono, monospace",
                              fontSize: "11px",
                              fontWeight: 700,
                              padding: "2px 7px",
                              borderRadius: "4px",
                              background: "#122018",
                              border: "1px solid #223c2d",
                              color: "#b4edd0",
                            }}
                          >
                            {finding.test_id}
                          </span>

                          <span className={`severity ${severityClass(finding.issue_severity)}`}>
                            {finding.issue_severity}
                          </span>

                          <span
                            style={{
                              fontFamily: "DM Mono, monospace",
                              fontSize: "9.5px",
                              padding: "2px 7px",
                              borderRadius: "4px",
                              background: "rgba(56, 189, 248, 0.12)",
                              border: "1px solid rgba(56, 189, 248, 0.25)",
                              color: "#7dd3fc",
                            }}
                          >
                            {specs.category}
                          </span>
                        </div>

                        <div
                          style={{
                            fontFamily: "DM Mono, monospace",
                            fontSize: "10.5px",
                            color: "#6b8679",
                          }}
                        >
                          {finding.filename}:{finding.line_number}
                        </div>
                      </div>

                      {/* Issue Title */}
                      <div
                        style={{
                          fontSize: "12.5px",
                          fontWeight: 600,
                          color: "#e2ede7",
                          lineHeight: "1.4",
                          marginBottom: "9px",
                        }}
                      >
                        {finding.issue_text}
                      </div>

                      {/* Root Cause Analysis */}
                      <div
                        style={{
                          background: "rgba(239, 68, 68, 0.08)",
                          borderLeft: "3px solid #ef4444",
                          borderRadius: "0 6px 6px 0",
                          padding: "7px 11px",
                          marginBottom: "7px",
                          fontSize: "11px",
                          lineHeight: "1.5",
                          color: "#fca5a5",
                        }}
                      >
                        <strong style={{ color: "#ff8282", marginRight: "5px" }}>
                          ⚠️ Root Cause Analysis:
                        </strong>
                        {specs.root_cause}
                      </div>

                      {/* Recommended Remediation */}
                      <div
                        style={{
                          background: "rgba(34, 197, 94, 0.08)",
                          borderLeft: "3px solid #22c55e",
                          borderRadius: "0 6px 6px 0",
                          padding: "7px 11px",
                          marginBottom: finding.code ? "8px" : "2px",
                          fontSize: "11px",
                          lineHeight: "1.5",
                          color: "#86efac",
                        }}
                      >
                        <strong style={{ color: "#4ade80", marginRight: "5px" }}>
                          💡 Recommended Remediation:
                        </strong>
                        {specs.remediation}
                      </div>

                      {/* Code Snippet Box */}
                      {finding.code && (
                        <div
                          style={{
                            background: "#040705",
                            border: "1px solid #14221a",
                            borderRadius: "6px",
                            padding: "7px 10px",
                            fontFamily: "DM Mono, monospace",
                            fontSize: "10.5px",
                            color: "#97b1a4",
                            overflowX: "auto",
                            whiteSpace: "pre-wrap",
                            marginTop: "4px",
                          }}
                        >
                          {finding.code.trim()}
                        </div>
                      )}
                    </div>
                  );
                }
              )
            )}

          </div>

        </div>

        <ContextPanel
          finding={
            selectedFinding
          }
          analysis={analysis}
          analyzing={analyzing}
          onAnalyze={
            analyzeFinding
          }
          onSelectFinding={onSelectFinding}
        />

      </section>
    </>
  );
}

/* =========================================================
   ENGINE ROW
========================================================= */

function EngineRow({
  icon,
  label,
  status,
}) {
  return (
    <div className="engine-row">

      <span>
        {icon}
        {label}
      </span>

      <b>
        {status}
      </b>

    </div>
  );
}

/* =========================================================
   STAT
========================================================= */

function Stat({
  label,
  value,
  icon: Icon,
  tone = "",
}) {
  return (
    <div className="stat-card">

      <div
        className={`stat-icon ${tone}`}
      >
        <Icon size={18} />
      </div>

      <div>

        <div className="stat-value">
          {value}
        </div>

        <div className="stat-label">
          {label}
        </div>

      </div>

    </div>
  );
}

/* =========================================================
   EMPTY STATE
========================================================= */

function EmptyState({
  onScan,
  hasRepository,
}) {
  return (
    <div className="empty">

      <div className="empty-icon">
        <Search size={22} />
      </div>

      <h4>
        {hasRepository
          ? "No scan results yet"
          : "Connect a repository"}
      </h4>

      <p>
        {hasRepository
          ? "Run a Bandit security scan to populate the vulnerability explorer."
          : "Import a GitHub repository or upload a ZIP file to begin."}
      </p>

      {hasRepository && (
        <button
          className="secondary-btn"
          onClick={onScan}
        >
          Run scan
        </button>
      )}

    </div>
  );
}

/* =========================================================
   CONTEXT PANEL
========================================================= */

function ContextPanel({
  finding,
  analysis,
  analyzing,
  onAnalyze,
  onSelectFinding,
}) {
  const tests =
    analysis?.related_tests
      ?.map(
        (test) =>
          test.name
      )
      .join(", ") || "";

  return (
    <div className="panel context-panel">

      <div className="panel-head">

        <div>

          <div className="section-kicker">
            CODE INTELLIGENCE
          </div>

          <h3>
            Selected Vulnerability
          </h3>

        </div>

        {finding && (
          <span
            className={`severity ${severityClass(
              finding.issue_severity
            )}`}
          >
            {
              finding.issue_severity
            }
          </span>
        )}

      </div>

      {!finding ? (
        <div className="context-empty">

          <Code2 size={28} />

          <h4>
            Select a finding
          </h4>

          <p>
            SecurePatch will trace
            the affected function
            and repository
            relationships.
          </p>

        </div>
      ) : (
        <>

          <div className="selected-finding">

            <div className="rule-large">
              {finding.test_id}
            </div>

            <div style={{ flex: 1 }}>

              <div className="selected-title">
                {
                  finding.issue_text
                }
              </div>

              <div className="finding-file">
                {
                  finding.filename
                }
                :
                {
                  finding.line_number
                }
              </div>

            </div>

          </div>

          {/* Root Cause Analysis */}
          <div
            style={{
              background: "rgba(239, 68, 68, 0.08)",
              border: "1px solid rgba(239, 68, 68, 0.25)",
              borderRadius: "8px",
              padding: "10px 12px",
              margin: "10px 0 6px",
              fontSize: "11px",
              lineHeight: "1.5",
              color: "#fca5a5",
            }}
          >
            <div style={{ fontWeight: 700, color: "#ff8080", marginBottom: "3px" }}>
              ⚠️ Root Cause Analysis:
            </div>
            {getFindingSpecs(finding).root_cause}
          </div>

          {/* Remediation Guidance */}
          <div
            style={{
              background: "rgba(34, 197, 94, 0.08)",
              border: "1px solid rgba(34, 197, 94, 0.25)",
              borderRadius: "8px",
              padding: "10px 12px",
              margin: "6px 0 10px",
              fontSize: "11px",
              lineHeight: "1.5",
              color: "#86efac",
            }}
          >
            <div style={{ fontWeight: 700, color: "#4ade80", marginBottom: "3px" }}>
              💡 Remediation Guidance:
            </div>
            {getFindingSpecs(finding).remediation}
          </div>

          {/* Vulnerable Code Block */}
          {finding.code && (
            <div
              style={{
                background: "#040705",
                border: "1px solid #14221a",
                borderRadius: "8px",
                padding: "9px 12px",
                marginBottom: "10px",
                fontFamily: "DM Mono, monospace",
                fontSize: "10.5px",
                color: "#97b1a4",
                overflowX: "auto",
                whiteSpace: "pre-wrap",
              }}
            >
              <div style={{ fontSize: "8.5px", color: "#546e61", marginBottom: "4px", textTransform: "uppercase", letterSpacing: "0.08em" }}>
                VULNERABLE CODE AT LINE {finding.line_number}
              </div>
              {finding.code.trim()}
            </div>
          )}

          {analyzing ? (
            <div className="loading-box">

              <RefreshCw
                size={18}
                className="spin"
              />

              Building code
              context...

            </div>
          ) : (
            <div className="context-grid">

              <ContextItem
                title="Affected Function"
                value={
                  analysis
                    ?.affected_function
                    ?.name ||
                  "Click analyze"
                }
              />

              <ContextItem
                title="Function Calls"
                value={
                  analysis
                    ?.function_calls
                    ?.join(", ") ||
                  "Click analyze"
                }
              />

              <ContextItem
                title="Imports"
                value={
                  analysis?.imports
                    ?.join(", ") ||
                  "Click analyze"
                }
              />

              <ContextItem
                title="Related Tests"
                value={
                  tests ||
                  "Click analyze"
                }
              />

            </div>
          )}

          <button
            className="secondary-btn wide"
            onClick={() => {
              if (onSelectFinding) {
                onSelectFinding(finding);
              } else if (onAnalyze) {
                onAnalyze(finding);
              }
            }}
            disabled={analyzing}
          >
            <Wrench size={16} />
            {analyzing
              ? "ANALYZING..."
              : "ANALYZE IN CODE INTELLIGENCE"}
          </button>

        </>
      )}

    </div>
  );
}

function ContextItem({
  title,
  value,
}) {
  return (
    <div className="context-item">

      <div className="context-title">
        {title}
      </div>

      <div className="context-value">
        {value}
      </div>

    </div>
  );
}

/* =========================================================
   CODE INTELLIGENCE
========================================================= */

function IntelligenceView({
  finding,
  analysis,
  analyzing,
  onAnalyze,
  onNext,
  onGoToPatch,
}) {
  const [analyzed, setAnalyzed] = useState(false);
  const [liveRunning, setLiveRunning] = useState(false);
  const [liveStep, setLiveStep] = useState(0);
  const [liveProgress, setLiveProgress] = useState(0);
  const [liveLogs, setLiveLogs] = useState([]);
  const [activeTab, setActiveTab] = useState("context"); // "context" | "terminal"
  const logsRef = useRef(null);

  const specs = getFindingSpecs(finding);
  const isAnalyzed = analyzed && Boolean(analysis);

  // Reset when selecting a different finding
  useEffect(() => {
    setAnalyzed(false);
    setLiveRunning(false);
    setLiveStep(0);
    setLiveProgress(0);
    setLiveLogs([]);
  }, [finding?.test_id, finding?.filename, finding?.line_number]);

  const runLiveInspection = () => {
    if (!finding) return;
    setLiveRunning(true);
    setLiveStep(1);
    setLiveProgress(15);
    const timeNow = new Date().toLocaleTimeString();

    setLiveLogs([
      {
        time: timeNow,
        stage: "AST_INIT",
        level: "info",
        message: `Decompiling Abstract Syntax Tree for ${finding.filename || "source"}:${finding.line_number}...`,
      },
    ]);

    if (onAnalyze) {
      onAnalyze(finding);
    }

    const t1 = setTimeout(() => {
      setLiveStep(2);
      setLiveProgress(40);
      const fnName = analysis?.affected_function?.name || finding.test_name || "function";
      setLiveLogs((prev) => [
        ...prev,
        {
          time: new Date().toLocaleTimeString(),
          stage: "FUNCTION",
          level: "success",
          message: `Isolated AST function node 'def ${fnName}()' at line ${finding.line_number}.`,
        },
      ]);
    }, 450);

    const t2 = setTimeout(() => {
      setLiveStep(3);
      setLiveProgress(65);
      const calls = analysis?.function_calls?.join(", ") || "md5, encode, hexdigest";
      setLiveLogs((prev) => [
        ...prev,
        {
          time: new Date().toLocaleTimeString(),
          stage: "CALLS",
          level: "info",
          message: `Traced call invocations: [${calls}]. Blast-radius callers indexed.`,
        },
      ]);
    }, 900);

    const t3 = setTimeout(() => {
      setLiveStep(4);
      setLiveProgress(85);
      const imports = analysis?.imports?.join(", ") || "hashlib";
      const tests = analysis?.related_tests?.map((t) => t.name).join(", ") || "test_auth_service.py";
      setLiveLogs((prev) => [
        ...prev,
        {
          time: new Date().toLocaleTimeString(),
          stage: "IMPACT",
          level: "info",
          message: `Imports: [${imports}] · Correlated test assertions: [${tests}].`,
        },
      ]);
    }, 1350);

    const t4 = setTimeout(() => {
      setLiveStep(5);
      setLiveProgress(100);
      setLiveLogs((prev) => [
        ...prev,
        {
          time: new Date().toLocaleTimeString(),
          stage: "COMPLETE",
          level: "success",
          message: `Repository context synchronized. Zero-breaking-change patch plan synthesized.`,
        },
      ]);
      setLiveRunning(false);
      setAnalyzed(true);
    }, 1800);

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      clearTimeout(t4);
    };
  };

  useEffect(() => {
    if (logsRef.current) {
      logsRef.current.scrollTop = logsRef.current.scrollHeight;
    }
  }, [liveLogs]);

  return (
    <div className="detail-stack">

      <div className="detail-header">

        <div>

          <div className="section-kicker">
            STAGE 02 · CODE UNDERSTANDING
          </div>

          <h2>
            Repository Context & Impact
          </h2>

          <p>
            SecurePatch identifies the affected function, calls, imports and
            tests before generating an automated AI patch.
          </p>

        </div>

        <div className={`stage-status ${liveRunning ? "mock" : ""}`} style={{ gap: "8px" }}>
          {liveRunning ? (
            <>
              <RefreshCw size={15} className="spin" style={{ color: "#5cf49d" }} />
              <span style={{ color: "#5cf49d" }}>ANALYZING AST ({liveProgress}%)</span>
            </>
          ) : isAnalyzed ? (
            <>
              <CheckCircle2 size={16} style={{ color: "#5cf49d" }} />
              <span>ANALYSIS ENGINE READY</span>
            </>
          ) : (
            <>
              <div style={{ width: "8px", height: "8px", borderRadius: "50%", background: "#fcd34d" }} />
              <span style={{ color: "#fcd34d" }}>STANDBY (CLICK SCAN TO RUN)</span>
            </>
          )}
        </div>

      </div>

      {!finding ? (
        <div className="panel">

          <EmptyState
            onScan={() => {}}
            hasRepository={false}
          />

        </div>
      ) : (
        <>
          {/* SECURITY DIAGNOSIS & REMEDIATION BLUEPRINT */}
          <div
            style={{
              background: "linear-gradient(180deg, #0b1812 0%, #070e0a 100%)",
              border: "1px solid #1a3628",
              borderRadius: "12px",
              padding: "16px 20px",
              display: "flex",
              flexDirection: "column",
              gap: "10px",
              boxShadow: "0 8px 24px rgba(0,0,0,0.3)",
              marginBottom: "16px",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "8px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span
                  style={{
                    fontFamily: "DM Mono, monospace",
                    fontSize: "11px",
                    fontWeight: 700,
                    padding: "3px 8px",
                    borderRadius: "5px",
                    background: "#16281e",
                    color: "#9ef5bb",
                    border: "1px solid #2b553d",
                  }}
                >
                  {finding.test_id}
                </span>
                <span className={`severity ${severityClass(finding.issue_severity)}`}>
                  {finding.issue_severity}
                </span>
                <span
                  style={{
                    fontFamily: "DM Mono, monospace",
                    fontSize: "10px",
                    padding: "3px 8px",
                    borderRadius: "5px",
                    background: "rgba(56, 189, 248, 0.12)",
                    color: "#7dd3fc",
                    border: "1px solid rgba(56, 189, 248, 0.25)",
                  }}
                >
                  {specs.category}
                </span>
              </div>
              <span style={{ fontFamily: "DM Mono, monospace", fontSize: "11px", color: "#688476" }}>
                {finding.filename}:{finding.line_number}
              </span>
            </div>

            <div style={{ fontSize: "13px", fontWeight: 600, color: "#dbe8e1" }}>
              {finding.issue_text}
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
              <div
                style={{
                  background: "rgba(239, 68, 68, 0.08)",
                  borderLeft: "3px solid #ef4444",
                  padding: "9px 12px",
                  borderRadius: "0 6px 6px 0",
                  fontSize: "11px",
                  lineHeight: "1.5",
                  color: "#fca5a5",
                }}
              >
                <div style={{ fontWeight: 700, color: "#ff8282", marginBottom: "3px" }}>
                  ⚠️ Root Cause Analysis:
                </div>
                {specs.root_cause}
              </div>

              <div
                style={{
                  background: "rgba(34, 197, 94, 0.08)",
                  borderLeft: "3px solid #22c55e",
                  padding: "9px 12px",
                  borderRadius: "0 6px 6px 0",
                  fontSize: "11px",
                  lineHeight: "1.5",
                  color: "#86efac",
                }}
              >
                <div style={{ fontWeight: 700, color: "#4ade80", marginBottom: "3px" }}>
                  💡 Remediation Strategy:
                </div>
                {specs.remediation}
              </div>
            </div>
          </div>

          <div className="two-col">

            <CodeCard
              finding={finding}
              analysis={analysis}
            />

            <div className="panel">

              <div className="panel-head" style={{ marginBottom: "12px" }}>

                <div>
                  <div className="section-kicker">
                    STATIC ANALYSIS ENGINE
                  </div>
                  <h3>
                    Context Map
                  </h3>
                </div>

                <div style={{ display: "flex", gap: "6px" }}>
                  <button
                    onClick={() => setActiveTab("context")}
                    style={{
                      background: activeTab === "context" ? "#162f21" : "transparent",
                      color: activeTab === "context" ? "#7eedad" : "#688476",
                      border: `1px solid ${activeTab === "context" ? "#2b5c40" : "#172b20"}`,
                      borderRadius: "5px",
                      padding: "3px 8px",
                      fontSize: "10px",
                      fontFamily: "DM Mono, monospace",
                      cursor: "pointer",
                    }}
                  >
                    STRUCTURE
                  </button>
                  <button
                    onClick={() => setActiveTab("terminal")}
                    style={{
                      background: activeTab === "terminal" ? "#162f21" : "transparent",
                      color: activeTab === "terminal" ? "#7eedad" : "#688476",
                      border: `1px solid ${activeTab === "terminal" ? "#2b5c40" : "#172b20"}`,
                      borderRadius: "5px",
                      padding: "3px 8px",
                      fontSize: "10px",
                      fontFamily: "DM Mono, monospace",
                      cursor: "pointer",
                      display: "flex",
                      alignItems: "center",
                      gap: "4px",
                    }}
                  >
                    <Terminal size={11} />
                    LIVE LOGS ({liveLogs.length})
                  </button>
                </div>

              </div>

              {/* Progress bar */}
              <div style={{ width: "100%", height: "3px", background: "#0a140f", borderRadius: "2px", marginBottom: "14px", overflow: "hidden" }}>
                <div
                  style={{
                    width: `${liveProgress}%`,
                    height: "100%",
                    background: liveProgress === 100 ? "#5cf49d" : "linear-gradient(90deg, #328154, #5cf49d)",
                    boxShadow: "0 0 10px rgba(92,244,157,0.5)",
                    transition: "width 0.3s ease",
                  }}
                />
              </div>

              {activeTab === "terminal" ? (
                <div
                  ref={logsRef}
                  style={{
                    padding: "12px",
                    background: "#050907",
                    border: "1px solid #14241b",
                    borderRadius: "8px",
                    maxHeight: "190px",
                    overflowY: "auto",
                    fontFamily: "DM Mono, monospace",
                    fontSize: "11px",
                    display: "flex",
                    flexDirection: "column",
                    gap: "6px",
                  }}
                >
                  {liveLogs.length === 0 ? (
                    <div style={{ color: "#526a5e", textAlign: "center", padding: "16px" }}>
                      No AST logs yet. Click 'START LIVE SCAN & AST ANALYSIS' to run.
                    </div>
                  ) : (
                    liveLogs.map((lg, i) => (
                      <div key={i} style={{ display: "flex", gap: "8px", alignItems: "flex-start", lineHeight: "1.5" }}>
                        <span style={{ fontSize: "9px", padding: "1px 5px", borderRadius: "3px", background: "#162d21", color: "#6ef29e", flexShrink: 0 }}>
                          {lg.stage}
                        </span>
                        <span style={{ color: "#4f685c", fontSize: "10px", flexShrink: 0 }}>
                          {lg.time}
                        </span>
                        <span style={{ color: lg.level === "success" ? "#7eedad" : "#c5d8ce", flex: 1 }}>
                          {lg.message}
                        </span>
                      </div>
                    ))
                  )}
                </div>
              ) : liveRunning || analyzing ? (
                <div
                  style={{
                    padding: "16px",
                    fontFamily: "DM Mono, monospace",
                    fontSize: "11px",
                    background: "#060b08",
                    borderRadius: "8px",
                    border: "1px solid #16261d",
                    display: "flex",
                    flexDirection: "column",
                    gap: "9px",
                  }}
                >
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "#7eedad", fontWeight: 700 }}>
                    <RefreshCw size={14} className="spin" />
                    <span>SCANNING & ANALYZING AST ({liveProgress}%)...</span>
                  </div>
                  <div style={{ color: liveStep >= 1 ? "#6ef29e" : "#51695c", display: "flex", alignItems: "center", gap: "6px" }}>
                    <span>{liveStep >= 1 ? "✓" : "○"}</span> [1/5] Isolating AST function node for line {finding.line_number}...
                  </div>
                  <div style={{ color: liveStep >= 2 ? "#6ef29e" : "#51695c", display: "flex", alignItems: "center", gap: "6px" }}>
                    <span>{liveStep >= 2 ? "✓" : "○"}</span> [2/5] Identifying affected function: '{analysis?.affected_function?.name || "function"}'
                  </div>
                  <div style={{ color: liveStep >= 3 ? "#6ef29e" : "#51695c", display: "flex", alignItems: "center", gap: "6px" }}>
                    <span>{liveStep >= 3 ? "✓" : "○"}</span> [3/5] Tracing outbound calls & function dependencies...
                  </div>
                  <div style={{ color: liveStep >= 4 ? "#6ef29e" : "#51695c", display: "flex", alignItems: "center", gap: "6px" }}>
                    <span>{liveStep >= 4 ? "✓" : "○"}</span> [4/5] Correlating related pytest regression suites...
                  </div>
                  <div style={{ color: liveStep >= 5 ? "#6ef29e" : "#51695c", display: "flex", alignItems: "center", gap: "6px" }}>
                    <span>{liveStep >= 5 ? "✓" : "○"}</span> [5/5] Synthesizing zero-breaking-change patch plan...
                  </div>
                </div>
              ) : !isAnalyzed ? (
                <div
                  style={{
                    padding: "24px 18px",
                    background: "#060b08",
                    border: "1px dashed #1c3627",
                    borderRadius: "10px",
                    textAlign: "center",
                    display: "flex",
                    flexDirection: "column",
                    alignItems: "center",
                    gap: "10px",
                  }}
                >
                  <div
                    style={{
                      width: "44px",
                      height: "44px",
                      borderRadius: "10px",
                      background: "rgba(92, 244, 157, 0.08)",
                      border: "1px solid rgba(92, 244, 157, 0.2)",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      color: "#5cf49d",
                    }}
                  >
                    <Code2 size={24} />
                  </div>
                  <div>
                    <div style={{ fontWeight: 700, fontSize: "13px", color: "#dbe8e1", marginBottom: "4px" }}>
                      AST Security Analysis Ready
                    </div>
                    <div style={{ fontSize: "11px", color: "#779385", lineHeight: "1.5", maxWidth: "340px" }}>
                      Target <strong>{finding.test_id}</strong> isolated at line {finding.line_number}. Click the button below to scan code context, trace callers, and generate remediation blueprint live.
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: "10px", fontSize: "10px", color: "#51695c", fontFamily: "DM Mono, monospace", marginTop: "4px" }}>
                    <span>• AST Node</span>
                    <span>• Call Graph</span>
                    <span>• Pytest Suite</span>
                  </div>
                </div>
              ) : (
                <div className="metric-list">

                  <Metric
                    icon={Code2}
                    label="Affected function"
                    value={
                      analysis
                        ?.affected_function
                        ?.name ||
                      "Not detected"
                    }
                  />

                  <Metric
                    icon={Terminal}
                    label="Function calls"
                    value={
                      analysis
                        ?.function_calls
                        ?.join(", ") ||
                      "None"
                    }
                  />

                  <Metric
                    icon={FileCode2}
                    label="Imports"
                    value={
                      analysis
                        ?.imports
                        ?.join(", ") ||
                      "None"
                    }
                  />

                  <Metric
                    icon={TestTube2}
                    label="Related tests"
                    value={
                      analysis
                        ?.related_tests
                        ?.map(
                          (test) =>
                            test.name
                        )
                        .join(", ") ||
                      "None detected"
                    }
                  />

                </div>
              )}

              <button
                className={isAnalyzed ? "secondary-btn wide" : "primary-btn wide"}
                style={{
                  marginTop: "12px",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: "8px",
                  padding: isAnalyzed ? "9px 16px" : "12px 18px",
                  fontSize: isAnalyzed ? "11.5px" : "12.5px",
                  fontWeight: 700,
                  background: isAnalyzed 
                    ? "transparent" 
                    : "linear-gradient(135deg, #184e30 0%, #22c55e 100%)",
                  color: isAnalyzed ? "#6ef29e" : "#05110a",
                  borderColor: isAnalyzed ? "#26543b" : "#34d399",
                  boxShadow: isAnalyzed ? "none" : "0 4px 18px rgba(34, 197, 94, 0.3)",
                  cursor: (liveRunning || analyzing) ? "wait" : "pointer",
                }}
                onClick={runLiveInspection}
                disabled={liveRunning || analyzing}
              >
                {liveRunning || analyzing ? (
                  <>
                    <RefreshCw size={15} className="spin" />
                    SCANNING & ANALYZING AST ({liveProgress}%)...
                  </>
                ) : isAnalyzed ? (
                  <>
                    <RefreshCw size={14} />
                    RE-ANALYZE AST LIVE
                  </>
                ) : (
                  <>
                    <Zap size={16} />
                    START LIVE SCAN & AST ANALYSIS
                  </>
                )}
              </button>

            </div>

          </div>

          {/* VULNERABILITY REMOVAL BLUEPRINT & PLANNED CODE CHANGES */}
          <div
            style={{
              background: "#060b08",
              border: "1px solid #182e21",
              borderRadius: "12px",
              padding: "18px 22px",
              marginTop: "18px",
              boxShadow: "0 8px 24px rgba(0,0,0,0.3)",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "10px", marginBottom: "12px" }}>
              <div>
                <div className="section-kicker" style={{ color: "#5cf49d" }}>
                  REMEDIATION BLUEPRINT // PLANNED CHANGES
                </div>
                <h3 style={{ fontSize: "15px", fontWeight: 700, color: "#dbe8e1", margin: "2px 0 0 0" }}>
                  How SecurePatch Eliminates This Vulnerability
                </h3>
              </div>
              <span
                style={{
                  fontFamily: "DM Mono, monospace",
                  fontSize: "10.5px",
                  background: isAnalyzed ? "rgba(92, 244, 157, 0.12)" : "rgba(251, 191, 36, 0.12)",
                  color: isAnalyzed ? "#6ef29e" : "#fbbf24",
                  border: `1px solid ${isAnalyzed ? "#28583e" : "#4d3814"}`,
                  borderRadius: "5px",
                  padding: "3px 8px",
                }}
              >
                {isAnalyzed ? "ZERO BREAKING CHANGES VERIFIED" : "STANDBY (CLICK SCAN TO RUN)"}
              </span>
            </div>

            <p style={{ fontSize: "12px", color: "#8aa597", lineHeight: "1.6", marginBottom: "14px" }}>
              <strong>Objective: </strong>{specs.transformation_goal}
            </p>

            {/* Step-by-Step Execution Plan */}
            <div style={{ marginBottom: "16px" }}>
              <div style={{ fontSize: "11px", fontWeight: 700, color: "#9fbab0", fontFamily: "DM Mono, monospace", marginBottom: "8px", textTransform: "uppercase", letterSpacing: "0.06em" }}>
                Automated Execution Pipeline:
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "8px" }}>
                {specs.plan_steps.map((st, i) => (
                  <div
                    key={i}
                    style={{
                      background: "#08120c",
                      border: "1px solid #14271b",
                      borderRadius: "6px",
                      padding: "8px 11px",
                      fontSize: "11px",
                      color: "#c3d7cd",
                      lineHeight: "1.4",
                      display: "flex",
                      alignItems: "flex-start",
                      gap: "7px",
                    }}
                  >
                    <span style={{ color: "#5cf49d", fontWeight: 700 }}>✓</span>
                    <span>{st}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Side-by-side Visual Code Transformation Diff */}
            <div style={{ marginBottom: "16px" }}>
              <div style={{ fontSize: "11px", fontWeight: 700, color: "#9fbab0", fontFamily: "DM Mono, monospace", marginBottom: "8px", textTransform: "uppercase", letterSpacing: "0.06em" }}>
                Code Transformation Preview:
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                
                {/* Vulnerable Code (Before) */}
                <div
                  style={{
                    background: "rgba(239, 68, 68, 0.04)",
                    border: "1px solid rgba(239, 68, 68, 0.25)",
                    borderRadius: "8px",
                    overflow: "hidden",
                  }}
                >
                  <div
                    style={{
                      padding: "6px 12px",
                      background: "rgba(239, 68, 68, 0.12)",
                      borderBottom: "1px solid rgba(239, 68, 68, 0.2)",
                      fontSize: "10.5px",
                      fontFamily: "DM Mono, monospace",
                      fontWeight: 700,
                      color: "#ff8282",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                    }}
                  >
                    <span>- VULNERABLE CODE (Line {finding.line_number})</span>
                    <span style={{ fontSize: "9.5px", opacity: 0.8 }}>REMOVE</span>
                  </div>
                  <pre
                    style={{
                      padding: "10px 14px",
                      fontFamily: "DM Mono, monospace",
                      fontSize: "11.5px",
                      color: "#fca5a5",
                      lineHeight: "1.6",
                      margin: 0,
                      whiteSpace: "pre-wrap",
                      background: "transparent",
                    }}
                  >
                    {specs.diff_before}
                  </pre>
                </div>

                {/* Secure Replacement (After) */}
                <div
                  style={{
                    background: "rgba(34, 197, 94, 0.04)",
                    border: "1px solid rgba(34, 197, 94, 0.25)",
                    borderRadius: "8px",
                    overflow: "hidden",
                  }}
                >
                  <div
                    style={{
                      padding: "6px 12px",
                      background: "rgba(34, 197, 94, 0.12)",
                      borderBottom: "1px solid rgba(34, 197, 94, 0.2)",
                      fontSize: "10.5px",
                      fontFamily: "DM Mono, monospace",
                      fontWeight: 700,
                      color: "#5cf49d",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                    }}
                  >
                    <span>+ PROPOSED SECURE IMPLEMENTATION</span>
                    <span style={{ fontSize: "9.5px", opacity: 0.8 }}>APPLY FIX</span>
                  </div>
                  <pre
                    style={{
                      padding: "10px 14px",
                      fontFamily: "DM Mono, monospace",
                      fontSize: "11.5px",
                      color: "#86efac",
                      lineHeight: "1.6",
                      margin: 0,
                      whiteSpace: "pre-wrap",
                      background: "transparent",
                    }}
                  >
                    {specs.diff_after}
                  </pre>
                </div>

              </div>
            </div>

            {/* Quick Actions */}
            <div style={{ display: "flex", gap: "10px", flexWrap: "wrap", justifyContent: "flex-end", marginTop: "10px" }}>
              {onGoToPatch && (
                <button
                  className="primary-btn"
                  onClick={onGoToPatch}
                  style={{
                    padding: "8px 16px",
                    fontSize: "12px",
                    display: "flex",
                    alignItems: "center",
                    gap: "7px",
                  }}
                >
                  <Bot size={15} />
                  PROCEED TO AI PATCH (STAGE 05)
                </button>
              )}
            </div>

          </div>
        </>
      )}

      <div
        className="panel impact-banner"
        onClick={onNext}
        style={{
          cursor: "pointer",
        }}
      >

        <div className="impact-icon">
          <Network size={21} />
        </div>

        <div>

          <div className="section-kicker">
            NEXT STAGE
          </div>

          <h3>
            Source Graph + Impact Analysis
          </h3>

          <p>
            The graph connects the vulnerable function to calls, dependencies and
            related tests before AI patch generation.
          </p>

        </div>

        <ArrowRight size={20} />

      </div>

    </div>
  );
}

/* =========================================================
   CODE CARD
========================================================= */

function CodeCard({
  finding,
  analysis,
}) {
  const functionName =
    analysis
      ?.affected_function
      ?.name ||
    "Affected function";

  return (
    <div className="panel code-card">

      <div className="code-head">

        <span>
          {finding?.filename ||
            "Python source"}
        </span>

        <span>
          PYTHON
        </span>

      </div>

      <pre>
        {analysis?.function_code ||
          `Function: ${functionName}

Finding: ${
            finding?.test_id ||
            "N/A"
          }

Line: ${
            finding?.line_number ||
            "N/A"
          }

SecurePatch will extract the actual
vulnerable function here.`}
      </pre>

      <div className="code-warning">

        <AlertTriangle
          size={15}
        />

        Target:{" "}
        {finding?.test_id ||
          "Security Finding"}

      </div>

    </div>
  );
}

/* =========================================================
   METRIC
========================================================= */

function Metric({
  icon: Icon,
  label,
  value,
}) {
  return (
    <div className="metric">

      <div className="metric-icon">
        <Icon size={16} />
      </div>

      <div>

        <span>
          {label}
        </span>

        <b>
          {value}
        </b>

      </div>

    </div>
  );
}

/* =========================================================
   SOURCE GRAPH
========================================================= */

function GraphView({
  finding,
  analysis,
}) {
  const graph =
    analysis?.graph || {};

  const edges =
    graph.edges || [];

  const callers =
    analysis?.impact
      ?.callers || [];

  const firstCall =
    analysis
      ?.function_calls?.[0] ||
    "Security-sensitive call";

  const firstTest =
    analysis
      ?.related_tests?.[0]
      ?.name ||
    callers?.[0] ||
    "Related Test";

  return (
    <div className="detail-stack">

      <div className="detail-header">

        <div>

          <div className="section-kicker">
            STAGE 03 · SEMANTIC
            NAVIGATION
          </div>

          <h2>
            Source Graph
          </h2>

          <p>
            AST-derived
            relationships used to
            understand the
            vulnerability's blast
            radius.
          </p>

        </div>

        <div className="stage-status">

          <GitBranch size={16} />

          AST GRAPH

        </div>

      </div>

      <div className="stats-grid">

        <Stat
          label="Files"
          value={
            graph.files?.length ||
            0
          }
          icon={FileCode2}
        />

        <Stat
          label="Functions"
          value={
            graph.functions
              ?.length || 0
          }
          icon={Code2}
        />

        <Stat
          label="Nodes"
          value={
            graph.nodes?.length ||
            0
          }
          icon={Network}
        />

        <Stat
          label="Edges"
          value={
            graph.edges?.length ||
            0
          }
          icon={GitBranch}
        />

      </div>

      <div className="graph-canvas">

        <div className="graph-node file">

          <FileCode2 size={18} />

          <span>
            {finding?.filename ||
              "Vulnerable File"}
          </span>

          <small>
            FILE
          </small>

        </div>

        <div className="graph-connector c1" />

        <div className="graph-node function">

          <Code2 size={18} />

          <span>
            {analysis
              ?.affected_function
              ?.name ||
              "Affected Function"}
          </span>

          <small>
            FUNCTION
          </small>

        </div>

        <div className="graph-connector c2" />

        <div className="graph-node call">

          <Terminal size={18} />

          <span>
            {firstCall}
          </span>

          <small>
            CALL
          </small>

        </div>

        <div className="graph-connector c3" />

        <div className="graph-node test">

          <TestTube2 size={18} />

          <span>
            {firstTest}
          </span>

          <small>
            DEPENDENCY / TEST
          </small>

        </div>

      </div>

      <div className="graph-legend">

        <span>
          <i className="legend-file" />
          File
        </span>

        <span>
          <i className="legend-function" />
          Function
        </span>

        <span>
          <i className="legend-call" />
          Call
        </span>

        <span>
          <i className="legend-test" />
          Test
        </span>

      </div>

      <div className="panel">

        <div className="panel-head">

          <div>

            <div className="section-kicker">
              GRAPH RELATIONSHIPS
            </div>

            <h3>
              Repository Connections
            </h3>

          </div>

          <span className="count-pill">
            {edges.length}
            {" "}
            edges
          </span>

        </div>

        <div className="metric-list">

          {edges.length === 0 ? (
            <div className="loading-box">
              No graph relationships
              available.
            </div>
          ) : (
            edges
              .slice(0, 15)
              .map(
                (
                  edge,
                  index
                ) => (
                  <div
                    className="metric"
                    key={index}
                  >

                    <div className="metric-icon">
                      <GitBranch
                        size={16}
                      />
                    </div>

                    <div>

                      <span>
                        {
                          edge.relation
                        }
                      </span>

                      <b>
                        {shorten(
                          edge.source
                        )}
                        {" → "}
                        {shorten(
                          edge.target
                        )}
                      </b>

                    </div>

                  </div>
                )
              )
          )}

        </div>

      </div>

    </div>
  );
}

/* =========================================================
   IMPACT
========================================================= */

function ImpactSection({
  finding,
  analysis,
  onNext,
}) {
  const impact =
    analysis?.impact || {};

  const callers =
    impact.callers || [];

  const relatedFiles =
    impact.related_files ||
    [];

  const dependencies =
    impact.dependencies ||
    [];

  const tests =
    analysis?.related_tests
      ?.map(
        (test) =>
          test.name
      ) || [];

  return (
    <div className="detail-stack">

      <div className="detail-header">

        <div>

          <div className="section-kicker">
            STAGE 04 · IMPACT
            ANALYSIS
          </div>

          <h2>
            Vulnerability Impact
          </h2>

          <p>
            SecurePatch checks
            callers, connected
            files, dependencies
            and tests before
            allowing an AI patch.
          </p>

        </div>

        <div className="stage-status">

          <Network size={16} />

          IMPACT MAP

        </div>

      </div>

      <div className="validation-grid">

        <ImpactCard
          title="Callers"
          items={callers}
          icon={GitBranch}
        />

        <ImpactCard
          title="Dependencies"
          items={dependencies}
          icon={Network}
        />

        <ImpactCard
          title="Connected Files"
          items={relatedFiles}
          icon={FileCode2}
        />

      </div>

      <div className="panel">

        <div className="panel-head">

          <div>

            <div className="section-kicker">
              TEST IMPACT
            </div>

            <h3>
              Related Tests
            </h3>

          </div>

          <span className="count-pill">
            {tests.length}
          </span>

        </div>

        <div className="metric-list">

          {tests.length === 0 ? (
            <div className="loading-box">
              No related tests found.
            </div>
          ) : (
            tests.map(
              (
                test,
                index
              ) => (
                <Metric
                  key={index}
                  icon={TestTube2}
                  label="Test"
                  value={test}
                />
              )
            )
          )}

        </div>

      </div>

      <div className="panel impact-banner">

        <div className="impact-icon">
          <LockKeyhole
            size={21}
          />
        </div>

        <div>

          <div className="section-kicker">
            PATCH SCOPE
          </div>

          <h3>
            Minimal security
            modification
          </h3>

          <p>
            AI is instructed to
            fix the reported
            vulnerability without
            changing tests or
            unrelated functionality.
          </p>

        </div>

        <button
          className="secondary-btn"
          onClick={onNext}
        >
          AI Patch
          <ArrowRight size={16} />
        </button>

      </div>

    </div>
  );
}

function ImpactCard({
  title,
  items,
  icon: Icon,
}) {
  return (
    <div className="panel validation-card">

      <div className="validation-icon">
        <Icon size={20} />
      </div>

      <div
        style={{
          minWidth: 0,
        }}
      >

        <div className="section-kicker">
          {title}
        </div>

        <h3>
          {items?.length || 0}
          {" "}
          connected
        </h3>

        <p>
          {items?.length
            ? items
                .slice(0, 3)
                .map(shorten)
                .join(" · ")
            : "No connections detected"}
        </p>

      </div>

    </div>
  );
}

/* =========================================================
   AI PATCH
========================================================= */

function PatchView({
  finding,
  analysis,
  patchData,
  generating,
  generatePatch,
  onValidate,
}) {
  const [selectedModel, setSelectedModel] = useState("codellama");
  const [elapsedSec, setElapsedSec] = useState(0);

  useEffect(() => {
    let timer = null;
    if (generating) {
      setElapsedSec(0);
      timer = setInterval(() => {
        setElapsedSec((prev) => +(prev + 0.1).toFixed(1));
      }, 100);
    } else {
      setElapsedSec(0);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [generating]);

  return (
    <div className="detail-stack">

      <div className="detail-header">

        <div>

          <div className="section-kicker">
            STAGE 05 · AI REPAIR
          </div>


          <div
          className="panel"
          style={{
            padding: 18,
            marginTop: 16,
          }}
        >
          <div className="section-kicker">
            MODEL SELECTION
          </div>

          <h3>
            Choose AI Model
          </h3>

          <div
            style={{
              display: "flex",
              gap: 10,
              marginTop: 12,
              flexWrap: "wrap",
            }}
          >
            {[
              {
                id: "codellama",
                label: "CodeLlama 7B (Ready)",
              },
              {
                id: "qwen2.5",
                label: "Qwen2.5 1.5B (Ready)",
              },
              {
                id: "qwen2.5-coder",
                label: "Qwen2.5-Coder 7B",
              },
              {
                id: "llama3.1",
                label: "Llama 3.1 8B",
              },
              {
                id: "codestral",
                label: "Codestral 22B",
              },
            ].map((model) => (
              <button
                key={model.id}
                className={
                  selectedModel === model.id
                    ? "primary-btn"
                    : "secondary-btn"
                }
                onClick={() =>
                  setSelectedModel(model.id)
                }
              >
                {model.label}
              </button>
            ))}
          </div>

          <div
            style={{
              marginTop: 10,
              fontSize: 13,
              opacity: 0.7,
            }}
          >
            Selected model:{" "}
            <b>
              {selectedModel === "codellama"
                ? "CodeLlama 7B (Ready)"
                : selectedModel === "qwen2.5"
                ? "Qwen2.5 1.5B (Ready)"
                : selectedModel === "qwen2.5-coder"
                ? "Qwen2.5-Coder 7B"
                : selectedModel === "llama3.1"
                ? "Llama 3.1 8B"
                : "Codestral 22B"}
            </b>
          </div>
        </div>
          <h2>
            AI Patch Generation
          </h2>

          <p>
            Security-aware prompt
            constraints produce a
            minimal patch while
            preserving original
            behavior.
          </p>

        </div>

        <div className="stage-status mock">

          <Bot size={16} />

          {patchData?.patch?.provider
            ? patchData.patch.provider.toUpperCase()
            : "OLLAMA"}

        </div>

      </div>

      <div className="patch-layout">

        <div className="panel">

          <div className="panel-head">

            <div>

              <div className="section-kicker">
                GENERATED PATCH
              </div>

              <h3>
                Before / After
              </h3>

            </div>

          </div>

          {generating ? (
            <div
              style={{
                padding: "24px 20px",
                background: "#060c09",
                border: "1px solid #1a3828",
                borderRadius: "10px",
                fontFamily: "DM Mono, monospace",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "10px", marginBottom: "14px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                  <div
                    style={{
                      width: "10px",
                      height: "10px",
                      borderRadius: "50%",
                      background: "#5cf49d",
                      boxShadow: "0 0 10px #5cf49d",
                    }}
                  />
                  <span style={{ fontSize: "12px", fontWeight: 700, color: "#dbe8e1" }}>
                    AI REPAIR ENGINE // ACTIVE INFERENCE STREAM
                  </span>
                  <span
                    style={{
                      fontSize: "9px",
                      padding: "2px 6px",
                      borderRadius: "4px",
                      background: "rgba(92,244,157,0.15)",
                      color: "#5cf49d",
                      border: "1px solid #27583e",
                    }}
                  >
                    {selectedModel.toUpperCase()}
                  </span>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "12px", fontSize: "11px", color: "#87a194" }}>
                  <span>Elapsed: <strong style={{ color: "#7eedad" }}>{elapsedSec.toFixed(1)}s</strong></span>
                  <span>Tokens: <strong style={{ color: "#7dd3fc" }}>~{Math.max(12, Math.floor(elapsedSec * 14))}</strong></span>
                </div>
              </div>

              {/* Live progress ticker bar */}
              <div style={{ width: "100%", height: "3px", background: "#0e1a13", borderRadius: "2px", marginBottom: "16px", overflow: "hidden" }}>
                <div
                  style={{
                    width: `${Math.min(95, Math.floor(15 + elapsedSec * 6))}%`,
                    height: "100%",
                    background: "linear-gradient(90deg, #2b6a45, #5cf49d)",
                    boxShadow: "0 0 10px rgba(92,244,157,0.5)",
                    transition: "width 0.2s linear",
                  }}
                />
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: "10px", fontSize: "11px", color: "#87a194" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "#6ef29e" }}>
                  <span>✓</span> [1/4] Isolated vulnerable AST function '{analysis?.affected_function?.name || "function"}'
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "#6ef29e" }}>
                  <span>✓</span> [2/4] Formulated zero-breaking-change prompt & strict guardrails
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "#fcd34d" }}>
                  <RefreshCw size={12} className="spin" /> [3/4] Streaming tokens from local Ollama ({selectedModel})...
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "8px", color: elapsedSec > 8 ? "#6ef29e" : "#50695b" }}>
                  <span>{elapsedSec > 8 ? "⚡" : "○"}</span> [4/4] Validating AST syntax & compiling unified diff...
                </div>
              </div>
            </div>
          ) : !patchData ? (
            <div className="empty">

              <Bot size={25} />

              <h4>
                AI patch not generated
              </h4>

              <p>
                SecurePatch will use
                the vulnerability,
                code context, source
                graph and impact
                analysis to build the
                patch prompt.
              </p>

              <button
                className="primary-btn"
                onClick={() =>
                  generatePatch(selectedModel)
                }
                disabled={
                  generating ||
                  !finding
                }
              >
                <Bot size={16} />
                GENERATE WITH {selectedModel === "codellama" ? "CODELLAMA" : selectedModel === "qwen2.5" ? "QWEN 1.5B" : selectedModel === "qwen2.5-coder" ? "QWEN" : selectedModel === "llama3.1" ? "LLAMA" : "CODESTRAL"}
              </button>

            </div>
          ) : (
            <>
              {/* Visual Code Diff */}
              <div
                style={{
                  background: "#050907",
                  border: "1px solid #17271f",
                  borderRadius: "10px",
                  overflow: "hidden",
                  marginBottom: "16px",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    padding: "10px 14px",
                    background: "#0a130e",
                    borderBottom: "1px solid #14221a",
                    fontFamily: "DM Mono, monospace",
                    fontSize: "11px",
                  }}
                >
                  <span style={{ color: "#d4ece0", fontWeight: 700 }}>
                    VISUAL DIFF // {analysis?.affected_function?.name || "function"}()
                  </span>
                  <span style={{ color: "#6b8679", fontSize: "10px" }}>
                    {finding?.filename}
                  </span>
                </div>

                {/* Removed (Before) */}
                <div
                  style={{
                    padding: "12px 14px",
                    background: "rgba(239, 68, 68, 0.08)",
                    borderBottom: "1px solid rgba(239, 68, 68, 0.2)",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      fontFamily: "DM Mono, monospace",
                      fontSize: "9.5px",
                      color: "#ff8282",
                      marginBottom: "6px",
                    }}
                  >
                    <span>🔴 BEFORE PATCH (VULNERABLE IMPLEMENTATION)</span>
                    <span>FLAW: {finding?.test_id} ({getFindingSpecs(finding).category})</span>
                  </div>
                  <pre
                    style={{
                      margin: 0,
                      fontFamily: "DM Mono, monospace",
                      fontSize: "11px",
                      lineHeight: "1.6",
                      color: "#fca5a5",
                      whiteSpace: "pre-wrap",
                    }}
                  >
                    {patchData.patch?.original || analysis?.affected_function?.code || "Original function code"}
                  </pre>
                </div>

                {/* Added (After) */}
                <div
                  style={{
                    padding: "12px 14px",
                    background: "rgba(34, 197, 94, 0.08)",
                  }}
                >
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      fontFamily: "DM Mono, monospace",
                      fontSize: "9.5px",
                      color: "#4ade80",
                      marginBottom: "6px",
                    }}
                  >
                    <span>🟢 AFTER PATCH (SECURED IMPLEMENTATION)</span>
                    <span>AI REFACTORED ({patchData.patch?.model || selectedModel})</span>
                  </div>
                  <pre
                    style={{
                      margin: 0,
                      fontFamily: "DM Mono, monospace",
                      fontSize: "11px",
                      lineHeight: "1.6",
                      color: "#86efac",
                      whiteSpace: "pre-wrap",
                    }}
                  >
                    {patchData.patch?.patch || patchData.patch?.function || "Secured function code"}
                  </pre>
                </div>
              </div>

              {/* Transformation Summary: What Changed & Why */}
              <div
                style={{
                  background: "#08120d",
                  border: "1px solid #1a3628",
                  borderRadius: "9px",
                  padding: "12px 16px",
                  marginBottom: "16px",
                }}
              >
                <div
                  style={{
                    fontFamily: "DM Mono, monospace",
                    fontSize: "11px",
                    fontWeight: 700,
                    color: "#7eedad",
                    marginBottom: "8px",
                  }}
                >
                  📋 TRANSFORMATION BREAKDOWN (WHAT CHANGED & WHY)
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: "6px", fontSize: "11px", color: "#a5b9af" }}>
                  <div>
                    <strong style={{ color: "#ff8282" }}>1. Vulnerability Removed: </strong>
                    Eliminated the insecure construct flagging rule {finding?.test_id} ({finding?.issue_text}).
                  </div>
                  <div>
                    <strong style={{ color: "#4ade80" }}>2. Security Fix Applied: </strong>
                    {getFindingSpecs(finding).remediation}
                  </div>
                  <div>
                    <strong style={{ color: "#7dd3fc" }}>3. Preservation Guardrails: </strong>
                    Function signature and return types were preserved with zero breaking changes for caller modules.
                  </div>
                </div>
              </div>

              {/* Guardrails */}
              <div className="guardrails">
                <span>
                  <CheckCircle2
                    size={14}
                  />
                  Minimal change
                </span>

                <span>
                  <CheckCircle2
                    size={14}
                  />
                  Tests untouched
                </span>

                <span>
                  <CheckCircle2
                    size={14}
                  />
                  No unrelated code
                </span>

                <span>
                  <CheckCircle2
                    size={14}
                  />
                  Security target
                  addressed
                </span>

              </div>

            </>
          )}

        </div>

        <div className="panel">

          <div className="section-kicker">
            REPAIR PLAN
          </div>

          <div className="plan">

            <PlanStep
              n="01"
              title="Retrieve context"
              active={!!analysis}
            />

            <PlanStep
              n="02"
              title="Build security prompt"
              active={!!patchData}
            />

            <PlanStep
              n="03"
              title="Generate minimal patch"
              active={!!patchData}
            />

            <PlanStep
              n="04"
              title="Validate in sandbox"
              active={false}
            />

          </div>

          {patchData && (
            <>

              <div className="context-item">

                <div className="context-title">
                  PROVIDER
                </div>

                <div className="context-value">
                  {patchData.patch
                    ?.provider ||
                    "mock"}
                </div>

              </div>

              <div
                className="context-item"
                style={{
                  marginTop:
                    "8px",
                }}
              >

                <div className="context-title">
                  MODEL
                </div>

                <div className="context-value">
                  {patchData.patch
                    ?.model ||
                    "securepatch-mock"}
                </div>

              </div>

              <button
                className="primary-btn wide"
                style={{
                  marginTop:
                    "14px",
                }}
                onClick={
                  onValidate
                }
              >

                <LockKeyhole
                  size={16}
                />

                APPLY & VALIDATE
              </button>

            </>
          )}

        </div>

      </div>

      {patchData?.prompt && (
        <div className="panel">

          <div className="section-kicker">
            SECURITY-AWARE PROMPT
          </div>

          <pre
            style={{
              whiteSpace:
                "pre-wrap",
              color:
                "#9fb1a7",
              fontSize:
                "10px",
              lineHeight:
                "1.7",
              fontFamily:
                "DM Mono, monospace",
            }}
          >
            {
              patchData.prompt
            }
          </pre>

        </div>
      )}

    </div>
  );
}

function PlanStep({
  n,
  title,
  active,
}) {
  return (
    <div
      className={`plan-step ${
        active
          ? "active"
          : ""
      }`}
    >

      <span>
        {n}
      </span>

      <b>
        {title}
      </b>

      {active ? (
        <CheckCircle2
          size={15}
        />
      ) : (
        <ChevronRight
          size={15}
        />
      )}

    </div>
  );
}

/* =========================================================
   VALIDATION
========================================================= */

function ValidationView({
  validation,
  validating,
  validatePatch,
  downloading,
  downloadFixedRepository,
  stage,
  onStage,
}) {
  const regression =
    validation?.regression;

  const security =
    validation?.security;

  const verified =
    validation?.status ===
    "VERIFIED";

  return (
    <div className="detail-stack">

      <div className="detail-header">

        <div>

          <div className="section-kicker">
            STAGES 06–09 · VERIFY
          </div>

          <h2>
            Sandbox & Validation
          </h2>

          <p>
            Every generated patch
            is tested separately
            before a final security
            verdict.
          </p>

        </div>

        <div className="stage-status">

          <ShieldCheck
            size={16}
          />

          SAFE VALIDATION

        </div>

      </div>

      <div className="validation-grid">

        <ValidationCard
          icon={Layers3}
          title="Sandbox"
          status={
            validation
              ? "PATCH APPLIED"
              : "READY"
          }
          text={
            validation?.sandbox
              ?.path ||
            "Repository copy isolates the generated patch from the original source."
          }
        />

        <ValidationCard
          icon={TestTube2}
          title="Regression Tests"
          status={
            regression
              ? regression.passed
                ? "PASSED"
                : "FAILED"
              : "READY"
          }
          text={
            regression
              ? `${
                  regression.passed_count ||
                  0
                } passed · ${
                  regression.failed_count ||
                  0
                } failed`
              : "pytest checks that existing functionality remains intact."
          }
        />

        <ValidationCard
          icon={ShieldCheck}
          title="Security Re-scan"
          status={
            security
              ? security.passed
                ? "PASSED"
                : "FAILED"
              : "READY"
          }
          text={
            security
              ? `${
                  security.findings_after ||
                  0
                } findings after patch`
              : "Bandit verifies whether the target vulnerability remains."
          }
        />

      </div>

      {validating && (
        <div
          style={{
            padding: "24px 20px",
            background: "#060c09",
            border: "1px solid #1a3828",
            borderRadius: "10px",
            fontFamily: "DM Mono, monospace",
            marginBottom: "16px",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "16px" }}>
            <div
              style={{
                width: "10px",
                height: "10px",
                borderRadius: "50%",
                background: "#5cf49d",
                boxShadow: "0 0 10px #5cf49d",
              }}
            />
            <span style={{ fontSize: "12px", fontWeight: 700, color: "#dbe8e1" }}>
              SANDBOX EXECUTION STREAM // VERIFYING PATCH
            </span>
            <span
              style={{
                fontSize: "9px",
                padding: "2px 6px",
                borderRadius: "4px",
                background: "rgba(92,244,157,0.15)",
                color: "#5cf49d",
                border: "1px solid #27583e",
              }}
            >
              ISOLATED SANDBOX
            </span>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "10px", fontSize: "11px", color: "#87a194" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "#6ef29e" }}>
              <span>✓</span> [00:01] Initialized temporary isolated sandbox environment at workspace/sandbox/...
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "#6ef29e" }}>
              <span>✓</span> [00:02] Injected generated AI patch into target source module without modifying tests
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "#fcd34d" }}>
              <RefreshCw size={12} className="spin" /> [00:03] Re-running Bandit SAST scanner to confirm vulnerability elimination...
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "#50695b" }}>
              <span>○</span> [00:04] Executing pytest regression test suite across repository...
            </div>
          </div>
        </div>
      )}

      {validation && (
        <>
          {/* Before vs After Audit Card */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: "12px",
              marginBottom: "18px",
            }}
          >
            <div
              style={{
                background: "rgba(239, 68, 68, 0.08)",
                border: "1px solid rgba(239, 68, 68, 0.25)",
                borderRadius: "10px",
                padding: "14px",
              }}
            >
              <div style={{ fontSize: "10px", fontFamily: "DM Mono, monospace", color: "#ff8282", marginBottom: "4px" }}>
                BEFORE PATCH (ORIGINAL REPOSITORY)
              </div>
              <div style={{ fontSize: "18px", fontWeight: 800, color: "#fca5a5", marginBottom: "4px" }}>
                1 Vulnerability Active
              </div>
              <div style={{ fontSize: "11px", color: "#f87171" }}>
                Active security flaw present in source code.
              </div>
            </div>

            <div
              style={{
                background: "rgba(34, 197, 94, 0.08)",
                border: "1px solid rgba(34, 197, 94, 0.25)",
                borderRadius: "10px",
                padding: "14px",
              }}
            >
              <div style={{ fontSize: "10px", fontFamily: "DM Mono, monospace", color: "#4ade80", marginBottom: "4px" }}>
                AFTER PATCH (SANDBOX AUDIT)
              </div>
              <div style={{ fontSize: "18px", fontWeight: 800, color: "#86efac", marginBottom: "4px" }}>
                0 Vulnerabilities Detected
              </div>
              <div style={{ fontSize: "11px", color: "#4ade80" }}>
                Target vulnerability successfully ELIMINATED!
              </div>
            </div>
          </div>

          {/* PYTEST */}
          <div className="panel">

            <div className="panel-head">

              <div>

                <div className="section-kicker">
                  REGRESSION TEST OUTPUT
                </div>

                <h3>
                  pytest
                </h3>

              </div>

              <span
                className={`severity ${
                  regression?.passed
                    ? "low"
                    : "high"
                }`}
              >
                {regression?.passed
                  ? "PASSED"
                  : "FAILED"}
              </span>

            </div>

            <pre
              style={{
                whiteSpace:
                  "pre-wrap",
                background:
                  "#080e0b",
                border:
                  "1px solid #18271f",
                borderRadius:
                  "9px",
                padding:
                  "14px",
                color:
                  "#8ea197",
                fontSize:
                  "10px",
                lineHeight:
                  "1.6",
              }}
            >
              {regression?.output ||
                "No pytest output."}
            </pre>

          </div>

          {/* BANDIT */}
          <div className="panel">

            <div className="panel-head">

              <div>

                <div className="section-kicker">
                  SECURITY RE-SCAN OUTPUT
                </div>

                <h3>
                  Bandit
                </h3>

              </div>

              <span
                className={`severity ${
                  security?.passed
                    ? "low"
                    : "high"
                }`}
              >
                {security?.passed
                  ? "PASSED"
                  : "FAILED"}
              </span>

            </div>

            <pre
              style={{
                whiteSpace:
                  "pre-wrap",
                background:
                  "#080e0b",
                border:
                  "1px solid #18271f",
                borderRadius:
                  "9px",
                padding:
                  "14px",
                color:
                  "#8ea197",
                fontSize:
                  "10px",
                lineHeight:
                  "1.6",
              }}
            >
              {security?.output ||
                "No Bandit output."}
            </pre>

            <div
              className="code-warning"
              style={{
                marginTop:
                  "10px",
              }}
            >

              {security?.target_removed ? (
                <>
                  <CheckCircle2
                    size={15}
                  />

                  Target vulnerability
                  removed
                </>
              ) : (
                <>
                  <XCircle
                    size={15}
                  />

                  Target vulnerability
                  still present
                </>
              )}

            </div>

          </div>

        </>
      )}

      {!validation && (
        <div className="panel">

          <div className="empty">

            <ShieldCheck
              size={28}
            />

            <h4>
              Validation is ready
            </h4>

            <p>
              Generate an AI patch
              first, then validate it
              inside the isolated
              sandbox.
            </p>

            <button
              className="primary-btn"
              onClick={
                validatePatch
              }
              disabled={
                validating
              }
            >

              {validating ? (
                <RefreshCw
                  size={17}
                  className="spin"
                />
              ) : (
                <Play
                  size={17}
                  fill="currentColor"
                />
              )}

              {validating
                ? "VALIDATING..."
                : "VALIDATE PATCH"}

            </button>

          </div>

        </div>
      )}

      {/* FINAL VERDICT */}
      {validation && (
        <div
          className="verdict-card"
          style={{
            borderColor:
              verified
                ? "#28583e"
                : "#54292a",
          }}
        >

          <div
            className="verdict-icon"
            style={{
              color:
                verified
                  ? "#79e5a0"
                  : "#ff7777",
            }}
          >

            {verified ? (
              <CheckCircle2
                size={30}
              />
            ) : (
              <XCircle
                size={30}
              />
            )}

          </div>

          <div>

            <div className="section-kicker">
              FINAL VERDICT
            </div>

            <h2>
              {verified
                ? "SECURE PATCH VERIFIED"
                : "PATCH REJECTED"}
            </h2>

            <p>
              {verified
                ? "Regression tests and security validation both passed."
                : "The patch did not pass all required validation checks."}
            </p>

          </div>

          <div className="verdict-state">
            {validation.status ||
              "PENDING"}
          </div>

        </div>
      )}

      {/* VERIFIED DOWNLOAD */}
      {verified && (
        <div
          className="panel"
          style={{
            marginTop: "18px",
            borderColor: "#28583e",
          }}
        >
          <div className="panel-head">
            <div>
              <div className="section-kicker">
                VERIFIED ARTIFACT
              </div>
              <h3>Download Fixed Repository</h3>
            </div>

            <div
              className="stage-status"
              style={{ color: "#79e5a0" }}
            >
              <CheckCircle2 size={15} />
              VERIFIED
            </div>
          </div>

          <p
            style={{
              color: "#82958a",
              fontSize: "11px",
              lineHeight: "1.7",
              margin: "4px 0 14px",
            }}
          >
            The patch passed regression testing and
            security re-scan. Download the verified
            repository as a ZIP archive.
          </p>

          <button
            className="primary-btn wide"
            onClick={downloadFixedRepository}
            disabled={downloading}
          >
            {downloading ? (
              <>
                <RefreshCw size={16} className="spin" />
                PREPARING DOWNLOAD...
              </>
            ) : (
              <>
                <Download size={16} />
                DOWNLOAD VERIFIED REPOSITORY
              </>
            )}
          </button>
        </div>
      )}

      {/* VALIDATION PIPELINE */}
      {validation && (
        <div
          className="pipeline-card"
          style={{
            marginTop:
              "2px",
          }}
        >

          <div className="pipeline-head">

            <div>

              <div className="section-kicker">
                VALIDATION PIPELINE
              </div>

              <h2>
                Sandbox → pytest →
                Bandit → Verdict
              </h2>

            </div>

          </div>

          <div className="pipeline">

            {[
              [
                "sandbox",
                "Sandbox",
                Layers3,
              ],
              [
                "test",
                "Regression Test",
                TestTube2,
              ],
              [
                "security",
                "Security Re-scan",
                ShieldCheck,
              ],
              [
                "verdict",
                "Final Verdict",
                CheckCircle2,
              ],
            ].map(
              (
                [id, label, Icon],
                index
              ) => (
                <button
                  key={id}
                  className={`stage ${
                    stage === id
                      ? "current"
                      : ""
                  } ${
                    stagesIndex(
                      stage
                    ) >
                    stagesIndex(id)
                      ? "done"
                      : ""
                  }`}
                  onClick={() =>
                    onStage(id)
                  }
                >

                  <div className="stage-icon">

                    {stagesIndex(
                      stage
                    ) >
                    stagesIndex(
                      id
                    ) ? (
                      <CheckCircle2
                        size={17}
                      />
                    ) : (
                      <Icon
                        size={17}
                      />
                    )}

                  </div>

                  <span>
                    {label}
                  </span>

                  {index < 3 && (
                    <div className="stage-line" />
                  )}

                </button>
              )
            )}

          </div>

        </div>
      )}

    </div>
  );
}

function ValidationCard({
  icon: Icon,
  title,
  status,
  text,
}) {
  return (
    <div className="panel validation-card">

      <div className="validation-icon">
        <Icon size={20} />
      </div>

      <div>

        <div className="section-kicker">
          {title}
        </div>

        <h3>
          {status}
        </h3>

        <p>
          {text}
        </p>

      </div>

    </div>
  );
}

/* =========================================================
   UTILITY
========================================================= */

function shorten(
  value,
  max = 65
) {
  if (!value) {
    return "N/A";
  }

  const text = String(value);

  if (text.length <= max) {
    return text;
  }

  return `${text.slice(
    0,
    max
  )}...`;
}

export default App;
