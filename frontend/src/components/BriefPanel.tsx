import type { Bundle, City, GlobalScenario, GlobalScenarioCity } from "../types";
import { daysBetween, formatHumanDate } from "../lib/dates";
import { ChokepointPanel } from "./ChokepointPanel";
import { ExportButton } from "./ExportButton";
import { MitigationPanel } from "./MitigationPanel";

function advRouteLabel(id?: string): string {
  switch (id) {
    case "russia_ukraine":    return "Russian-routed";
    case "sudan_civil_war":   return "Cross-border re-route";
    case "myanmar_civil_war": return "Junta-routed";
    case "iran_yemen_houthi": return "Iran-state routed";
    case "china_taiwan":      return "PRC-routed";
    default:                  return "Adv. routing";
  }
}

function interceptLabel(id?: string): string {
  switch (id) {
    case "russia_ukraine":    return "SORM exposure";
    case "iran_yemen_houthi": return "DPI exposure";
    case "china_taiwan":      return "MSS exposure";
    case "myanmar_civil_war": return "Junta intercept";
    default:                  return "Intercept exp.";
  }
}

interface Props {
  city: City;
  period: string;
  date: string;
  bundle: Bundle;
  scenario?: GlobalScenario;
}

export function BriefPanel({ city, period, date, bundle, scenario }: Props) {
  const periodData: any = (city as any).periods?.[period];

  // Resolve period metadata: prefer scenario's own periods over the legacy bundle.periods
  const scenarioPeriodMeta =
    scenario?.cities?.[0]
      ? Object.entries(((scenario.cities[0] as any).periods ?? {}) as Record<string, any>)
          .find(([label]) => label === period)?.[1]
      : undefined;
  const periodMeta = scenarioPeriodMeta ?? bundle.periods.find((p) => p.label === period);

  // Kinetic events near the SCRUBBER date (live-updates as user drags)
  const nearbyEvents = (city.events || []).filter(
    (e) => Math.abs(daysBetween(date, (e as any).event_date)) <= 14,
  );

  // Live peer count for current scrubber date
  let livePeers: number | null = null;
  let liveDayDelta = 0;
  if (city.peer_timeline && city.peer_timeline.length > 0) {
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

  // Find the matching city in the active scenario for mitigations
  const scenarioCity: GlobalScenarioCity | undefined =
    scenario?.cities.find((c) => c.city === city.name);

  // Adversarial neighbours (scenario-specific)
  const advNeighbours = (city.threat?.evidence as any)?.adversarial_neighbours ?? [];

  const t = city.threat;
  return (
    <div className="brief-panel">
      <div className="brief-panel-header">
        <h2>Cyber Terrain Brief</h2>
        <ExportButton city={city} period={period} date={date} bundle={bundle} />
      </div>
      <div className="brief-meta">
        <div><strong>{city.name}</strong> · AS{city.asn}</div>
        <div className="brief-period">{formatHumanDate(date)}</div>
        <div className="brief-date">
          {scenario ? `${scenario.name} · ` : ""}
          {(periodMeta as any)?.description ?? ""}
          {(periodMeta as any)?.date ? ` (${(periodMeta as any).date})` : ""}
        </div>
      </div>

      {/* Threat score — the BLUF (Bottom Line Up Front) */}
      <section className={`threat-section level-${t.level}`}>
        <div className="threat-header">
          <span className="threat-label">Cyber-Terrain Threat Score</span>
          <span className={`threat-level-pill level-${t.level}`}>
            {t.level.toUpperCase()}
          </span>
        </div>
        <div className="threat-score-row">
          <span className={`threat-score-big level-${t.level}`}>{t.score}</span>
          <span className="threat-out-of">/ 100</span>
        </div>
        <div className="threat-bar">
          <div
            className={`threat-bar-fill level-${t.level}`}
            style={{ width: `${t.score}%` }}
          />
        </div>
        <ul className="threat-components">
          <li>
            <span className="comp-label">Blackout</span>
            <span className="comp-bar"><span style={{ width: `${(t.components.blackout / 40) * 100}%` }} /></span>
            <span className="comp-val">{t.components.blackout.toFixed(1)} <span className="comp-max">/40</span></span>
          </li>
          <li>
            <span className="comp-label">Instability / kinetic</span>
            <span className="comp-bar"><span style={{ width: `${(t.components.instability / 25) * 100}%` }} /></span>
            <span className="comp-val">{t.components.instability.toFixed(1)} <span className="comp-max">/25</span></span>
          </li>
          <li>
            <span className="comp-label">{advRouteLabel(scenario?.id)}</span>
            <span className="comp-bar"><span style={{ width: `${(t.components.russian_route / 25) * 100}%` }} /></span>
            <span className="comp-val">{t.components.russian_route.toFixed(1)} <span className="comp-max">/25</span></span>
          </li>
          <li>
            <span className="comp-label">{interceptLabel(scenario?.id)}</span>
            <span className="comp-bar"><span style={{ width: `${(t.components.sorm_exposure / 10) * 100}%` }} /></span>
            <span className="comp-val">{t.components.sorm_exposure.toFixed(1)} <span className="comp-max">/10</span></span>
          </li>
        </ul>
      </section>

      <section>
        <h3>Live signal at {formatHumanDate(date)}</h3>
        {livePeers !== null ? (
          <ul>
            <li>
              RIPE peer visibility:{" "}
              <strong className={livePeers < 100 ? "danger" : ""}>
                {livePeers.toFixed(0)} peers
              </strong>
              {liveDayDelta > 0 && (
                <span className="hint"> (nearest sample {liveDayDelta}d away)</span>
              )}
            </li>
            {periodData && (
              <li>
                Period: {periodData.update_count} kinetic/BGP events ·{" "}
                {Object.entries(periodData.classifications ?? {})
                  .map(([k, v]) => `${v} ${k}`)
                  .join(", ")}
              </li>
            )}
          </ul>
        ) : (
          <p>No live data for this date.</p>
        )}
      </section>

      {/* Adversarial adjacencies (scenario-specific) */}
      {advNeighbours.length > 0 && (
        <section>
          <h3>Adversarial adjacencies</h3>
          <ul className="adv-adj-list">
            {advNeighbours.map((n: any) => (
              <li key={n.asn} className="adv-adj-row">
                <span className="adv-asn">AS{n.asn}</span>
                <span className="adv-op">{n.operator}</span>
                <span className="adv-role">{n.role}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section>
        <h3>Kinetic events (±14d from {formatHumanDate(date)})</h3>
        {nearbyEvents.length > 0 ? (
          <ul>
            {nearbyEvents.slice(0, 5).map((e, i) => (
              <li key={i}>
                <div className="event-date">{(e as any).event_date}</div>
                <div className="event-type">
                  <strong>{(e as any).event_type}</strong>
                  {(e as any).sub_event && ` — ${(e as any).sub_event}`}
                  {(e as any).fatalities > 0 && (
                    <span className="event-fatalities"> · {(e as any).fatalities} fatalities</span>
                  )}
                </div>
                <div className="event-notes">{((e as any).notes ?? "").slice(0, 140)}</div>
              </li>
            ))}
            {nearbyEvents.length > 5 && (
              <li className="event-more">+ {nearbyEvents.length - 5} more events in window</li>
            )}
          </ul>
        ) : (
          <p>No kinetic events recorded in this window.</p>
        )}
      </section>

      <section>
        <h3>Sample AS paths</h3>
        {periodData?.sample_paths?.length ? (
          <ul className="path-list">
            {periodData.sample_paths.slice(0, 4).map((p: string, i: number) => (
              <li key={i} className="path">{p}</li>
            ))}
          </ul>
        ) : (
          <p>—</p>
        )}
      </section>

      {/* LLM/template narrative — Ukraine has these; show only if available */}
      {bundle.briefs?.[city.name] && (
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
            {bundle.briefs[city.name]?.[period] ?? Object.values(bundle.briefs[city.name] ?? {})[0] ?? ""}
          </p>
        </section>
      )}

      {/* Chokepoint panel — uses scenario's chokepoints when available */}
      <ChokepointPanel data={scenario?.chokepoints ?? bundle.chokepoints} />

      {/* Mitigation panel — every scenario, every city */}
      {scenarioCity && <MitigationPanel city={scenarioCity} />}
    </div>
  );
}
