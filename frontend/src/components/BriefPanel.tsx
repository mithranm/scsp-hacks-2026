import type { Bundle, City } from "../types";
import { daysBetween, formatHumanDate } from "../lib/dates";

interface Props {
  city: City;
  period: string;
  date: string;
  bundle: Bundle;
}

export function BriefPanel({ city, period, date, bundle }: Props) {
  const periodData = city.periods[period];
  const periodMeta = bundle.periods.find((p) => p.label === period);

  // ACLED events near the SCRUBBER date (live-updates as user drags)
  const nearbyEvents = city.events.filter(
    (e) => Math.abs(daysBetween(date, e.event_date)) <= 14,
  );

  // Live peer count for current scrubber date
  let livePeers: number | null = null;
  let liveDayDelta = 0;
  if (city.peer_timeline.length > 0) {
    let best = city.peer_timeline[0];
    let bestAbs = Infinity;
    for (const p of city.peer_timeline) {
      const d = Math.abs(daysBetween(date, p.date));
      if (d < bestAbs) {
        bestAbs = d;
        best = p;
      }
    }
    livePeers = best.peers;
    liveDayDelta = bestAbs;
  }

  return (
    <div className="brief-panel">
      <h2>Cyber Terrain Brief</h2>
      <div className="brief-meta">
        <div><strong>{city.name}</strong> · AS{city.asn}</div>
        <div className="brief-period">{formatHumanDate(date)}</div>
        <div className="brief-date">
          nearest BGP sample: {periodMeta?.description} ({periodMeta?.date})
        </div>
      </div>

      <section>
        <h3>Live signal at {formatHumanDate(date)}</h3>
        {livePeers !== null ? (
          <ul>
            <li>
              RIPE peer visibility:{" "}
              <strong className={livePeers < 100 ? "danger" : ""}>
                {livePeers} peers
              </strong>
              {liveDayDelta > 0 && (
                <span className="hint"> (nearest sample {liveDayDelta}d away)</span>
              )}
            </li>
            {periodData && (
              <li>
                Nearest BGP sample: {periodData.update_count} UPDATE messages,{" "}
                {Object.entries(periodData.classifications)
                  .map(([k, v]) => `${v} ${k}`)
                  .join(", ")}
              </li>
            )}
          </ul>
        ) : (
          <p>No live data for this date.</p>
        )}
      </section>

      <section>
        <h3>Kinetic events (±14d)</h3>
        {nearbyEvents.length > 0 ? (
          <ul>
            {nearbyEvents.map((e, i) => (
              <li key={i}>
                <div className="event-date">{e.event_date}</div>
                <div className="event-type">
                  <strong>{e.event_type}</strong> — {e.sub_event}
                </div>
                <div className="event-notes">{e.notes}</div>
              </li>
            ))}
          </ul>
        ) : (
          <p>No kinetic events recorded in this window.</p>
        )}
      </section>

      <section>
        <h3>Sample AS paths</h3>
        {periodData?.sample_paths.length ? (
          <ul className="path-list">
            {periodData.sample_paths.slice(0, 3).map((p, i) => (
              <li key={i} className="path">{p}</li>
            ))}
          </ul>
        ) : (
          <p>—</p>
        )}
      </section>

      <section className="brief-narrative">
        <h3>
          Cyber Terrain Narrative
          {bundle.briefs_mode && (
            <span className={`brief-mode-badge ${bundle.briefs_mode}`}>
              {bundle.briefs_mode === "llm" ? "Claude Opus 4.7" : "template"}
            </span>
          )}
        </h3>
        <p className="brief-text">
          {bundle.briefs?.[city.name]?.[period] ??
            "No brief available for this period."}
        </p>
      </section>
    </div>
  );
}
