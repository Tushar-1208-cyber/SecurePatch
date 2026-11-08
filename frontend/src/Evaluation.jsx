import React from "react";
import {
  BarChart3,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock3,
  Zap,
  ShieldCheck,
  Activity,
} from "lucide-react";

const models = [
  {
    name: "Llama 3.1 8B",
    verified: 70,
    verifiedCount: "7/10",
    generation: "100%",
    regression: "100%",
    latency: "34.58s",
    conditional: "70%",
    rank: 1,
  },
  {
    name: "Qwen2.5-Coder 7B",
    verified: 60,
    verifiedCount: "6/10",
    generation: "100%",
    regression: "100%",
    latency: "38.92s",
    conditional: "60%",
    rank: 2,
  },
  {
    name: "Codestral 22B",
    verified: 50,
    verifiedCount: "5/10",
    generation: "60%",
    regression: "100%",
    latency: "86.29s",
    conditional: "83.33%",
    rank: 3,
  },
  {
    name: "Rule-based baseline",
    verified: 50,
    verifiedCount: "5/10",
    generation: "N/A",
    regression: "N/A",
    latency: "3.3s",
    conditional: "N/A",
    rank: null,
  },
];

const vulnerabilities = [
  ["B102", "MEDIUM", "REJECTED", "VERIFIED", "ERROR"],
  ["B105", "LOW", "REJECTED", "REJECTED", "REJECTED"],
  ["B108", "MEDIUM", "VERIFIED", "VERIFIED", "ERROR"],
  ["B202", "HIGH", "REJECTED", "REJECTED", "VERIFIED"],
  ["B301", "MEDIUM", "REJECTED", "REJECTED", "VERIFIED"],
  ["B307", "MEDIUM", "VERIFIED", "VERIFIED", "ERROR"],
  ["B324", "HIGH", "VERIFIED", "VERIFIED", "VERIFIED"],
  ["B506", "MEDIUM", "VERIFIED", "VERIFIED", "VERIFIED"],
  ["B602", "HIGH", "VERIFIED", "VERIFIED", "VERIFIED"],
  ["B608", "MEDIUM", "VERIFIED", "VERIFIED", "ERROR"],
];

const failures = [
  ["B202", "Qwen2.5-Coder 7B", "Security failure"],
  ["B202", "Llama 3.1 8B", "Security failure"],
  ["B102", "Qwen2.5-Coder 7B", "Security failure"],
  ["B301", "Qwen2.5-Coder 7B", "Security failure"],
  ["B301", "Llama 3.1 8B", "Security failure"],
  ["B105", "Qwen2.5-Coder 7B", "Security failure"],
  ["B105", "Llama 3.1 8B", "Security failure"],
  ["B105", "Codestral 22B", "Security failure"],
  ["B307", "Codestral 22B", "Generation/runtime failure"],
  ["B102", "Codestral 22B", "Generation/runtime failure"],
  ["B608", "Codestral 22B", "Generation/runtime failure"],
  ["B108", "Codestral 22B", "Generation/runtime failure"],
];

function StatusBadge({ status }) {
  if (status === "VERIFIED") {
    return (
      <span className="ev-status ev-verified">
        <CheckCircle2 size={13} />
        VERIFIED
      </span>
    );
  }

  if (status === "ERROR") {
    return (
      <span className="ev-status ev-error">
        <AlertTriangle size={13} />
        ERROR
      </span>
    );
  }

  return (
    <span className="ev-status ev-rejected">
      <XCircle size={13} />
      REJECTED
    </span>
  );
}

function MetricCard({ icon: Icon, label, value, detail }) {
  return (
    <div className="ev-metric">
      <div className="ev-metric-icon">
        <Icon size={19} />
      </div>

      <div>
        <div className="ev-metric-label">{label}</div>
        <div className="ev-metric-value">{value}</div>
        <div className="ev-metric-detail">{detail}</div>
      </div>
    </div>
  );
}

export default function Evaluation() {
  return (
    <>
      <style>{`

        .evaluation-page {
          display: flex;
          flex-direction: column;
          gap: 20px;
          padding-bottom: 40px;
        }

        .ev-hero {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          gap: 20px;
          padding: 25px;
          border: 1px solid #263041;
          background: #111722;
          border-radius: 16px;
        }

        .ev-kicker {
          color: #7d8ba0;
          font-size: 10px;
          font-weight: 800;
          letter-spacing: 1px;
        }

        .ev-hero h2 {
          margin: 7px 0;
          font-size: 27px;
          letter-spacing: -0.5px;
        }

        .ev-hero p {
          margin: 0;
          color: #8792a4;
          font-size: 13px;
          line-height: 1.6;
        }

        .ev-run-badge {
          display: flex;
          align-items: center;
          gap: 7px;
          padding: 9px 12px;
          white-space: nowrap;
          border-radius: 999px;
          background: #102319;
          border: 1px solid #294e3a;
          color: #72d89a;
          font-size: 10px;
          font-weight: 800;
        }

        .ev-metrics {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 13px;
        }

        .ev-metric {
          display: flex;
          gap: 13px;
          padding: 18px;
          background: #111722;
          border: 1px solid #263041;
          border-radius: 14px;
        }

        .ev-metric-icon {
          width: 38px;
          height: 38px;
          display: grid;
          place-items: center;
          flex-shrink: 0;
          border-radius: 10px;
          background: #182131;
          color: #91a8ff;
        }

        .ev-metric-label {
          color: #788496;
          font-size: 10px;
          text-transform: uppercase;
          letter-spacing: .7px;
        }

        .ev-metric-value {
          margin-top: 4px;
          font-size: 25px;
          font-weight: 800;
        }

        .ev-metric-detail {
          margin-top: 3px;
          color: #707c8d;
          font-size: 10px;
        }

        .ev-section {
          padding: 23px;
          background: #111722;
          border: 1px solid #263041;
          border-radius: 16px;
        }

        .ev-section-head {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          margin-bottom: 19px;
        }

        .ev-section-head h3 {
          margin: 5px 0;
          font-size: 19px;
        }

        .ev-section-head p {
          margin: 0;
          color: #7d899a;
          font-size: 12px;
        }

        .ev-note {
          color: #7d899a;
          font-size: 11px;
        }

        .ev-model-grid {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 13px;
        }

        .ev-model {
          position: relative;
          padding: 19px;
          border: 1px solid #293342;
          border-radius: 14px;
          background: #0f151f;
        }

        .ev-model.best {
          border-color: #405a9e;
          background: #111a2a;
        }

        .ev-best {
          position: absolute;
          top: 0;
          right: 0;
          padding: 5px 8px;
          border-radius: 0 0 0 8px;
          background: #263c78;
          color: #b8c7ff;
          font-size: 8px;
          font-weight: 800;
        }

        .ev-model-name {
          font-size: 13px;
          font-weight: 750;
        }

        .ev-model-runs {
          margin-top: 4px;
          color: #707c8d;
          font-size: 10px;
        }

        .ev-score {
          margin-top: 18px;
          font-size: 33px;
          font-weight: 800;
        }

        .ev-score small {
          margin-left: 6px;
          color: #778395;
          font-size: 10px;
          font-weight: 500;
        }

        .ev-progress {
          height: 6px;
          margin-top: 12px;
          overflow: hidden;
          border-radius: 999px;
          background: #202936;
        }

        .ev-progress-fill {
          height: 100%;
          border-radius: inherit;
          background: #687de0;
        }

        .ev-model-stats {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 7px;
          margin-top: 16px;
        }

        .ev-model-stat {
          padding-top: 9px;
          border-top: 1px solid #242d3a;
        }

        .ev-model-stat span {
          display: block;
          color: #717d8e;
          font-size: 9px;
        }

        .ev-model-stat strong {
          display: block;
          margin-top: 3px;
          font-size: 11px;
        }

        .ev-chart {
          display: flex;
          flex-direction: column;
          gap: 17px;
        }

        .ev-chart-row {
          display: grid;
          grid-template-columns: 180px 1fr 55px;
          align-items: center;
          gap: 13px;
        }

        .ev-chart-label {
          font-size: 12px;
          font-weight: 650;
        }

        .ev-chart-track {
          height: 20px;
          overflow: hidden;
          border-radius: 6px;
          background: #202936;
        }

        .ev-chart-fill {
          height: 100%;
          border-radius: 6px;
          background: #596bba;
        }

        .ev-chart-best {
          background: #6e82e4;
        }

        .ev-chart-value {
          text-align: right;
          font-size: 12px;
          font-weight: 800;
        }

        .ev-table-wrap {
          overflow-x: auto;
          border: 1px solid #252e3b;
          border-radius: 12px;
        }

        .ev-table {
          width: 100%;
          min-width: 760px;
          border-collapse: collapse;
        }

        .ev-table th {
          padding: 12px 14px;
          background: #0d131c;
          color: #7c8798;
          font-size: 9px;
          text-transform: uppercase;
          letter-spacing: .6px;
          text-align: left;
          white-space: nowrap;
        }

        .ev-table td {
          padding: 13px 14px;
          border-top: 1px solid #202936;
          color: #b4bdca;
          font-size: 11px;
        }

        .ev-table tr:hover td {
          background: #121a25;
        }

        .ev-highlight {
          color: #91a8ff;
          font-weight: 800;
        }

        .ev-table-icon {
          margin-right: 5px;
          vertical-align: -3px;
          color: #8995a6;
        }

        .ev-footnote {
          margin-top: 10px;
          color: #778395;
          font-size: 10px;
          line-height: 1.5;
        }

        .ev-status {
          display: inline-flex;
          align-items: center;
          gap: 5px;
          padding: 5px 8px;
          border-radius: 7px;
          font-size: 8px;
          font-weight: 800;
          letter-spacing: .4px;
        }

        .ev-verified {
          color: #78dda0;
          background: #10261a;
          border: 1px solid #234b32;
        }

        .ev-rejected {
          color: #ee8790;
          background: #291519;
          border: 1px solid #54252b;
        }

        .ev-error {
          color: #efbd6d;
          background: #2b2112;
          border: 1px solid #59431f;
        }

        .ev-severity {
          display: inline-block;
          padding: 4px 7px;
          border-radius: 5px;
          font-size: 8px;
          font-weight: 800;
        }

        .ev-high {
          color: #f08c95;
          background: #2b161a;
        }

        .ev-medium {
          color: #efbd70;
          background: #2a2113;
        }

        .ev-low {
          color: #8da0ff;
          background: #171e35;
        }

        .ev-failure-summary {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 13px;
          margin-bottom: 15px;
        }

        .ev-failure-card {
          display: flex;
          gap: 14px;
          padding: 17px;
          border-radius: 12px;
        }

        .ev-failure-card.security {
          background: #251619;
          border: 1px solid #51252b;
        }

        .ev-failure-card.runtime {
          background: #292013;
          border: 1px solid #58431f;
        }

        .ev-failure-number {
          font-size: 27px;
          font-weight: 800;
        }

        .ev-failure-card.security .ev-failure-number {
          color: #ef858e;
        }

        .ev-failure-card.runtime .ev-failure-number {
          color: #e9b768;
        }

        .ev-failure-card strong {
          font-size: 12px;
        }

        .ev-failure-card p {
          margin: 6px 0 0;
          color: #7f8a9b;
          font-size: 10px;
          line-height: 1.5;
        }

        .ev-failure-list {
          display: flex;
          flex-direction: column;
        }

        .ev-failure-row {
          display: grid;
          grid-template-columns: 55px 190px 190px 1fr;
          gap: 13px;
          align-items: center;
          padding: 11px 0;
          border-top: 1px solid #222b37;
          font-size: 10px;
        }

        .ev-failure-rule {
          font-weight: 800;
        }

        .ev-failure-model {
          color: #aab4c2;
        }

        .ev-failure-type {
          color: #d39d52;
        }

        .ev-failure-desc {
          color: #737f90;
        }

        .ev-conclusion {
          display: flex;
          gap: 16px;
          padding: 23px;
          border: 1px solid #304475;
          background: #111a2b;
          border-radius: 16px;
        }

        .ev-conclusion-icon {
          width: 42px;
          height: 42px;
          display: grid;
          place-items: center;
          flex-shrink: 0;
          border-radius: 11px;
          background: #243762;
          color: #9db0ff;
        }

        .ev-conclusion h3 {
          margin: 5px 0 8px;
          font-size: 17px;
        }

        .ev-conclusion p {
          margin: 0;
          color: #8793a5;
          font-size: 11px;
          line-height: 1.7;
        }

        @media (max-width: 1200px) {
          .ev-metrics,
          .ev-model-grid {
            grid-template-columns: repeat(2, 1fr);
          }
        }

        @media (max-width: 760px) {
          .ev-hero {
            flex-direction: column;
          }

          .ev-metrics,
          .ev-model-grid,
          .ev-failure-summary {
            grid-template-columns: 1fr;
          }

          .ev-chart-row {
            grid-template-columns: 120px 1fr 45px;
          }

          .ev-failure-row {
            grid-template-columns: 50px 1fr;
          }
        }

      `}</style>

      <div className="evaluation-page">

        {/* HERO */}
        <section className="ev-hero">
          <div>
            <div className="ev-kicker">
              EXPERIMENTAL EVALUATION
            </div>

            <h2>
              LLM Security Patch Benchmark
            </h2>

            <p>
              Comparative evaluation of locally deployed
              LLMs for automated Python vulnerability repair.
            </p>
          </div>

          <div className="ev-run-badge">
            <Activity size={15} />
            30 RUNS COMPLETED
          </div>
        </section>

        {/* SUMMARY */}
        <section className="ev-metrics">

          <MetricCard
            icon={BarChart3}
            label="Total runs"
            value="30"
            detail="10 vulnerabilities × 3 models"
          />

          <MetricCard
            icon={ShieldCheck}
            label="Best verified rate"
            value="70%"
            detail="Llama 3.1 8B · 7/10"
          />

          <MetricCard
            icon={CheckCircle2}
            label="Verified patches"
            value="18 / 30"
            detail="60% overall"
          />

          <MetricCard
            icon={AlertTriangle}
            label="Failures"
            value="12"
            detail="8 security + 4 runtime"
          />

        </section>

        {/* MODEL CARDS */}
        <section className="ev-section">

          <div className="ev-section-head">
            <div>
              <div className="ev-kicker">
                MODEL COMPARISON
              </div>

              <h3>
                Verified patch performance
              </h3>

              <p>
                Overall system-level performance across
                the 10-vulnerability benchmark.
              </p>
            </div>

            <div className="ev-note">
              10 vulnerabilities per model
            </div>
          </div>

          <div className="ev-model-grid">

            {models.map((model) => (
              <div
                key={model.name}
                className={`ev-model ${
                  model.rank === 1 ? "best" : ""
                }`}
              >

                {model.rank === 1 && (
                  <div className="ev-best">
                    BEST OVERALL
                  </div>
                )}

                <div className="ev-model-name">
                  {model.name}
                </div>

                <div className="ev-model-runs">
                  10 experimental runs
                </div>

                <div className="ev-score">
                  {model.verified}%
                  <small>verified</small>
                </div>

                <div className="ev-progress">
                  <div
                    className="ev-progress-fill"
                    style={{
                      width: `${model.verified}%`,
                    }}
                  />
                </div>

                <div className="ev-model-stats">

                  <div className="ev-model-stat">
                    <span>Verified</span>
                    <strong>
                      {model.verifiedCount}
                    </strong>
                  </div>

                  <div className="ev-model-stat">
                    <span>Generation</span>
                    <strong>
                      {model.generation}
                    </strong>
                  </div>

                  <div className="ev-model-stat">
                    <span>Latency</span>
                    <strong>
                      {model.latency}
                    </strong>
                  </div>

                </div>

              </div>
            ))}

          </div>

        </section>

        {/* BAR CHART */}
        <section className="ev-section">

          <div className="ev-section-head">
            <div>
              <div className="ev-kicker">
                VERIFIED PATCH RATE
              </div>

              <h3>
                Model vs baseline
              </h3>
            </div>
          </div>

          <div className="ev-chart">

            {models.map((model) => (
              <div
                className="ev-chart-row"
                key={model.name}
              >
                <div className="ev-chart-label">
                  {model.name}
                </div>

                <div className="ev-chart-track">
                  <div
                    className={`ev-chart-fill ${
                      model.rank === 1
                        ? "ev-chart-best"
                        : ""
                    }`}
                    style={{
                      width: `${model.verified}%`,
                    }}
                  />
                </div>

                <div className="ev-chart-value">
                  {model.verified}%
                </div>
              </div>
            ))}

          </div>

        </section>

        {/* METRICS TABLE */}
        <section className="ev-section">

          <div className="ev-section-head">
            <div>
              <div className="ev-kicker">
                QUANTITATIVE METRICS
              </div>

              <h3>
                Experimental performance
              </h3>
            </div>
          </div>

          <div className="ev-table-wrap">

            <table className="ev-table">

              <thead>
                <tr>
                  <th>Model</th>
                  <th>Verified</th>
                  <th>Generation success</th>
                  <th>Regression pass</th>
                  <th>Avg latency</th>
                  <th>Conditional verified</th>
                </tr>
              </thead>

              <tbody>

                {models.map((model) => (
                  <tr key={model.name}>

                    <td>
                      <strong>
                        {model.name}
                      </strong>
                    </td>

                    <td>
                      <span className="ev-highlight">
                        {model.verified}%
                      </span>
                    </td>

                    <td>
                      {model.generation}
                    </td>

                    <td>
                      {model.regression}
                    </td>

                    <td>
                      <Clock3
                        size={13}
                        className="ev-table-icon"
                      />
                      {model.latency}
                    </td>

                    <td>
                      {model.conditional}
                    </td>

                  </tr>
                ))}

              </tbody>

            </table>

          </div>

          <div className="ev-footnote">
            * Codestral regression testing passed for all 6 runs
            that successfully generated a patch. Four runs failed
            during generation/runtime and therefore did not reach
            regression testing. Its 83.33% conditional verified
            rate applies only to successful generations.
          </div>

        </section>

        {/* VULNERABILITY MATRIX */}
        <section className="ev-section">

          <div className="ev-section-head">

            <div>
              <div className="ev-kicker">
                VULNERABILITY ANALYSIS
              </div>

              <h3>
                Vulnerability × model matrix
              </h3>

              <p>
                Performance on each Bandit vulnerability.
              </p>
            </div>

          </div>

          <div className="ev-table-wrap">

            <table className="ev-table">

              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Severity</th>
                  <th>Qwen2.5-Coder 7B</th>
                  <th>Llama 3.1 8B</th>
                  <th>Codestral 22B</th>
                </tr>
              </thead>

              <tbody>

                {vulnerabilities.map(
                  ([rule, severity, qwen, llama, codestral]) => (
                    <tr key={rule}>

                      <td>
                        <strong>{rule}</strong>
                      </td>

                      <td>
                        <span
                          className={`ev-severity ev-${severity.toLowerCase()}`}
                        >
                          {severity}
                        </span>
                      </td>

                      <td>
                        <StatusBadge status={qwen} />
                      </td>

                      <td>
                        <StatusBadge status={llama} />
                      </td>

                      <td>
                        <StatusBadge status={codestral} />
                      </td>

                    </tr>
                  )
                )}

              </tbody>

            </table>

          </div>

        </section>

        {/* FAILURE ANALYSIS */}
        <section className="ev-section">

          <div className="ev-section-head">

            <div>
              <div className="ev-kicker">
                FAILURE ANALYSIS
              </div>

              <h3>
                What did not work?
              </h3>

              <p>
                Security failures are separated from
                generation/runtime failures.
              </p>
            </div>

          </div>

          <div className="ev-failure-summary">

            <div className="ev-failure-card security">

              <div className="ev-failure-number">
                8
              </div>

              <div>
                <strong>
                  Security failures
                </strong>

                <p>
                  The patch was generated and tests passed,
                  but the targeted Bandit vulnerability
                  remained.
                </p>
              </div>

            </div>

            <div className="ev-failure-card runtime">

              <div className="ev-failure-number">
                4
              </div>

              <div>
                <strong>
                  Generation/runtime failures
                </strong>

                <p>
                  Codestral failed to generate a response
                  because Ollama returned an internal error.
                </p>
              </div>

            </div>

          </div>

          <div className="ev-failure-list">

            {failures.map(
              ([rule, model, type], index) => (
                <div
                  className="ev-failure-row"
                  key={`${rule}-${model}-${index}`}
                >

                  <div className="ev-failure-rule">
                    {rule}
                  </div>

                  <div className="ev-failure-model">
                    {model}
                  </div>

                  <div className="ev-failure-type">
                    {type}
                  </div>

                  <div className="ev-failure-desc">
                    {type === "Security failure"
                      ? "Patch passed regression tests but did not remove the target vulnerability."
                      : "Ollama returned an internal generation error."}
                  </div>

                </div>
              )
            )}

          </div>

        </section>

        {/* CONCLUSION */}
        <section className="ev-conclusion">

          <div className="ev-conclusion-icon">
            <Zap size={21} />
          </div>

          <div>

            <div className="ev-kicker">
              EXPERIMENTAL CONCLUSION
            </div>

            <h3>
              Llama 3.1 8B achieved the strongest
              overall system performance.
            </h3>

            <p>
              Llama achieved a 70% verified patch rate,
              followed by Qwen2.5-Coder at 60% and Codestral
              at 50%. The rule-based baseline also achieved
              50%. The results demonstrate that generated
              code must be independently security-scanned
              before acceptance because regression-test
              success alone does not guarantee vulnerability
              removal.
            </p>

          </div>

        </section>

      </div>
    </>
  );
}