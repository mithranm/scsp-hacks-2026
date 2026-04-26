import type { ChokepointAnalysis } from "../types";

interface Props {
  data?: ChokepointAnalysis;
}

export function ChokepointPanel({ data }: Props) {
  if (!data) return null;

  const top = data.top_chokepoints.slice(0, 8);
  const adv = data.adversarial_chokepoints;

  return (
    <section className="chokepoint-panel">
      <h3>Network Resilience — Top Chokepoints</h3>
      <p className="chokepoint-blurb">
        Betweenness centrality across {data.graph_stats.paths_observed} observed
        BGP paths · {data.graph_stats.ases} ASes · {data.graph_stats.edges} edges
      </p>

      <ol className="chokepoint-list">
        {top.map((c) => (
          <li
            key={c.asn}
            className={`chokepoint-row ${c.is_adversarial ? "adversarial" : ""}`}
          >
            <span className="cp-rank">{c.is_adversarial ? "⚠" : ""}</span>
            <span className="cp-asn">AS{c.asn}</span>
            <span className="cp-bar">
              <span
                className={`cp-bar-fill ${c.is_adversarial ? "adv" : ""}`}
                style={{ width: `${c.centrality}%` }}
              />
            </span>
            <span className="cp-score">{c.centrality.toFixed(1)}</span>
            <span className="cp-holder" title={c.holder}>
              {shortHolder(c.holder)}
            </span>
            <span className="cp-country">{c.country}</span>
          </li>
        ))}
      </ol>

      {adv.length > 0 && (
        <div className="chokepoint-resilience">
          <strong>Adversarial chokepoint:</strong> Removing the {adv.length}{" "}
          Russian-routed AS{adv.length > 1 ? "es" : ""} on this map would force{" "}
          <strong>{Math.round(adv.reduce((s, c) => s + c.raw_score, 0))}</strong>{" "}
          peer→target shortest-paths to re-route. Highest-impact:{" "}
          <strong>AS{adv[0].asn}</strong> ({shortHolder(adv[0].holder)}).
        </div>
      )}
    </section>
  );
}

function shortHolder(s: string): string {
  // Trim e.g. "LEVEL3 - Level 3 Parent, LLC" → "Level 3"
  const parts = s.split(/\s*-\s*/);
  if (parts.length >= 2) {
    return parts[1].split(",")[0].split(/\s+/).slice(0, 2).join(" ");
  }
  return s.split(",")[0].slice(0, 24);
}
