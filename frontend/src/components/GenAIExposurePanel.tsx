import type { GenAIExposure, GenAIFingerprinting } from "../types";

interface Props {
  exposure?: GenAIExposure;
  fingerprinting?: GenAIFingerprinting;
}

export function GenAIExposurePanel({ exposure, fingerprinting }: Props) {
  if (!exposure || !fingerprinting || exposure.score === 0) return null;

  const levelClass = `level-${exposure.level}`;

  return (
    <section className={`genai-panel ${levelClass}`}>
      <div className="genai-header">
        <span className="genai-tag">GENAI FINGERPRINTING</span>
        <span className={`threat-level-pill ${levelClass}`}>
          {exposure.level.toUpperCase()}
        </span>
      </div>

      <div className="genai-score-row">
        <span className={`genai-score-big ${levelClass}`}>{exposure.score}</span>
        <span className="threat-out-of">/ 100</span>
        <span className="genai-score-label">AI traffic exposure</span>
      </div>

      <div className="threat-bar">
        <div
          className={`threat-bar-fill ${levelClass}`}
          style={{ width: `${exposure.score}%` }}
        />
      </div>

      {/* Components breakdown */}
      <ul className="threat-components">
        <li>
          <span className="comp-label">Route exposure</span>
          <span className="comp-bar">
            <span style={{ width: `${exposure.routing_exposure * 100}%` }} />
          </span>
          <span className="comp-val">
            {(exposure.routing_exposure * 100).toFixed(0)}%
          </span>
        </li>
        <li>
          <span className="comp-label">Adversary DPI</span>
          <span className="comp-bar">
            <span style={{ width: `${exposure.dpi_capability_score}%` }} />
          </span>
          <span className="comp-val">
            {exposure.dpi_capability_score}
            <span className="comp-max">/100</span>
          </span>
        </li>
        <li>
          <span className="comp-label">ML accuracy</span>
          <span className="comp-bar">
            <span style={{ width: `${exposure.fingerprint_accuracy * 100}%` }} />
          </span>
          <span className="comp-val">
            {(exposure.fingerprint_accuracy * 100).toFixed(1)}%
          </span>
        </li>
      </ul>

      {/* DPI system */}
      {exposure.adversary_dpi && (
        <div className="genai-dpi-info">
          <span className="genai-dpi-label">Intercept system</span>
          <span className="genai-dpi-value">{exposure.dpi_system}</span>
        </div>
      )}

      {/* Threat vectors */}
      {exposure.threat_vectors.length > 0 && (
        <div className="genai-threats">
          <span className="genai-threats-label">Threat vectors</span>
          <ul className="genai-threat-list">
            {exposure.threat_vectors.map((v) => (
              <li key={v}>{v}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Detectable platforms */}
      <div className="genai-platforms">
        <span className="genai-platforms-label">Detectable platforms</span>
        <div className="genai-platform-tags">
          {fingerprinting.detectable_platforms.map((p) => (
            <span key={p} className="genai-platform-tag">{p}</span>
          ))}
        </div>
      </div>

    </section>
  );
}
