import type { Scenario } from "../types";

interface Props {
  scenario?: Scenario;
}

export function USRelevancePanel({ scenario }: Props) {
  if (!scenario) return null;

  return (
    <section className="us-relevance-panel">
      <div className="usrel-header">
        <span className="usrel-tag">US RELEVANCE</span>
        <h3>{scenario.scenario_name}</h3>
      </div>

      <p className="usrel-question">{scenario.scenario_question}</p>

      <div className="usrel-totals">
        <div className="usrel-stat">
          <div className="usrel-num">{scenario.totals.exposed_targets}</div>
          <div className="usrel-cap">/ {scenario.cities.length} targets exposed</div>
        </div>
        <div className="usrel-stat">
          <div className="usrel-num">{scenario.totals.total_prc_adjacencies}</div>
          <div className="usrel-cap">PRC adjacencies</div>
        </div>
        <div className="usrel-stat">
          <div className="usrel-num">{scenario.totals.max_exposure}</div>
          <div className="usrel-cap">peak score</div>
        </div>
      </div>

      <table className="usrel-table">
        <thead>
          <tr>
            <th>City</th>
            <th>AS</th>
            <th>Score</th>
            <th>Level</th>
            <th>PRC peers</th>
          </tr>
        </thead>
        <tbody>
          {scenario.cities.map((c) => (
            <tr key={c.asn} className={`usrel-row level-${c.exposure_level}`}>
              <td>{c.city}</td>
              <td className="usrel-asn">AS{c.asn}</td>
              <td className="usrel-score">{c.exposure_score}</td>
              <td className={`level-${c.exposure_level}`}>
                {c.exposure_level.toUpperCase()}
              </td>
              <td>
                {c.prc_count ?? 0} of {c.neighbours_total}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <p className="usrel-method">
        <strong>Method:</strong> {scenario.method}
      </p>
    </section>
  );
}
