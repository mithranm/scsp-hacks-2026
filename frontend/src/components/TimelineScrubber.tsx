import { useMemo } from "react";
import type { PeriodMeta, City, ASN } from "../types";
import {
  TIMELINE_START,
  TIMELINE_END,
  dateToDayIndex,
  dayIndexToDate,
  timelineDayCount,
  formatHumanDate,
} from "../lib/dates";

interface Props {
  periods: PeriodMeta[];
  date: string;
  onDateChange: (date: string) => void;
  city: City;
  asns: Record<string, ASN>;
  sormAses: Record<string, string>;
  /** Scenario date bounds — falls back to Ukraine 2021-09 → 2022-06 */
  windowStart?: string;
  windowEnd?: string;
  /** Scenario-specific adversary AS list & display label */
  adversarySet?: Set<string>;
  adversaryLabel?: string;
}

interface ThreatMarker {
  date: string;
  pct: number;
  type: "adversary-path" | "high-volume";
  label: string;
}

// Compact display labels so adjacent ticks have room. Handles known Ukraine
// labels and generic synthesized period labels from build_global_scenarios.py.
function shortenPeriodLabel(desc: string): string {
  return desc
    .replace(/^Pre-invasion baseline$/,             "Baseline")
    .replace(/^Invasion start$/,                    "Invasion")
    .replace(/^Kherson occupation$/,                "Kherson falls")
    .replace(/^Mariupol siege peak$/,               "Mariupol siege")
    .replace(/^Conflict baseline.*$/,               "Baseline")
    .replace(/^Peak kinetic intensity$/,            "Peak kinetic")
    .replace(/^Peer visibility cliff.*$/,           "Peer cliff")
    .replace(/^Recent observation.*$/,              "Recent");
}

export function TimelineScrubber({
  periods, date, onDateChange, city, asns, sormAses,
  windowStart = TIMELINE_START, windowEnd = TIMELINE_END,
  adversarySet, adversaryLabel = "Adversary",
}: Props) {
  const totalDays = timelineDayCount(windowStart, windowEnd);
  const dayIdx    = dateToDayIndex(date, windowStart, windowEnd);
  const advSet    = adversarySet ?? new Set<string>();

  // Compute BGP threat markers for the current city.
  // - adversary-path: any sample path in this period traverses an adversarial AS
  // - high-volume:  update_count > 100 (routing instability spike)
  const threatMarkers: ThreatMarker[] = useMemo(() => {
    const out: ThreatMarker[] = [];
    for (const p of periods) {
      const data = (city as any).periods?.[p.label];
      if (!data) continue;
      const pct = (dateToDayIndex(p.date, windowStart, windowEnd) / totalDays) * 100;

      // Detect SCENARIO-specific adversarial AS in any sample path
      const advHops = new Set<string>();
      for (const path of data.sample_paths ?? []) {
        for (const hop of path.split(" → ")) {
          const a = hop.trim();
          if (!/^\d+$/.test(a)) continue;
          if (advSet.has(a) || sormAses[a]) advHops.add(a);
        }
      }
      if (advHops.size > 0) {
        const hopLabels = Array.from(advHops)
          .map((h) => {
            const a = asns[h];
            const role = sormAses[h];
            return role
              ? `AS${h} (${role})`
              : `AS${h}${a ? ` (${a.holder})` : ""}`;
          })
          .join(", ");
        out.push({
          date: p.date,
          pct,
          type: "adversary-path",
          label: `${p.description} — ${adversaryLabel}-routed path: ${hopLabels}`,
        });
      }

      if (data.update_count > 100) {
        out.push({
          date: p.date,
          pct,
          type: "high-volume",
          label: `${p.description} — ${data.update_count} updates / events in window (high activity)`,
        });
      }
    }
    return out;
  }, [periods, city, asns, sormAses, totalDays, advSet, adversaryLabel, windowStart, windowEnd]);

  // Peer-count sparkline path — visualizes "when the city went dark"
  const sparklinePath = useMemo(() => {
    const series = city.peer_timeline
      .filter((p) => p.date >= windowStart && p.date <= windowEnd)
      .slice()
      .sort((a, b) => a.date.localeCompare(b.date));
    if (series.length === 0) return "";

    const maxPeers = Math.max(...series.map((p) => p.peers), 400);
    const w = 1000;
    const h = 36;
    const pts = series.map((p) => {
      const x = (dateToDayIndex(p.date, windowStart, windowEnd) / totalDays) * w;
      const y = h - (p.peers / maxPeers) * h;
      return [x, y] as const;
    });
    return (
      "M" +
      pts.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" L")
    );
  }, [city, totalDays, windowStart, windowEnd]);

  // Event markers — vertical pips along the timeline
  const eventMarkers = city.events
    .filter((e) => (e as any).event_date >= windowStart && (e as any).event_date <= windowEnd)
    .map((e) => ({
      pct: (dateToDayIndex((e as any).event_date, windowStart, windowEnd) / totalDays) * 100,
      label: `${(e as any).event_date} · ${(e as any).sub_event ?? (e as any).event_type}`,
    }));

  // Period markers — large clickable ticks. Sorted by position so the
  // zebra stagger always alternates left-to-right.
  const periodMarkers = periods
    .map((p) => ({
      label: p.label,
      description: p.description,
      shortLabel: shortenPeriodLabel(p.description),
      pct: (dateToDayIndex(p.date, windowStart, windowEnd) / totalDays) * 100,
      date: p.date,
    }))
    .sort((a, b) => a.pct - b.pct);

  return (
    <div className="timeline-scrubber">
      <div className="timeline-readout">
        <span className="timeline-date">{formatHumanDate(date)}</span>
        <span className="timeline-period-hint">
          ← drag to scrub · click any marker to snap
        </span>
      </div>

      <div className="timeline-track-wrap">
        {/* Peer-count sparkline behind the slider */}
        <svg
          className="timeline-sparkline"
          viewBox="0 0 1000 36"
          preserveAspectRatio="none"
        >
          {sparklinePath && (
            <>
              <path d={sparklinePath} className="sparkline-line" />
              <path
                d={sparklinePath + ` L1000,36 L0,36 Z`}
                className="sparkline-fill"
              />
            </>
          )}
        </svg>

        {/* Event pips */}
        <div className="timeline-events">
          {eventMarkers.map((m, i) => (
            <button
              key={i}
              className="timeline-event-pip"
              style={{ left: `${m.pct}%` }}
              title={m.label}
              onClick={() =>
                onDateChange(
                  dayIndexToDate(Math.round((m.pct / 100) * totalDays), windowStart),
                )
              }
            />
          ))}
        </div>

        {/* BGP threat markers — chevrons above the sparkline */}
        <div className="timeline-threats">
          {threatMarkers.map((m, i) => (
            <button
              key={i}
              className={`timeline-threat-marker ${m.type}`}
              style={{ left: `${m.pct}%` }}
              title={m.label}
              onClick={() => onDateChange(m.date)}
            >
              {m.type === "adversary-path" ? "▼" : "◆"}
            </button>
          ))}
        </div>

        {/* Period ticks — zebra-staggered onto two rows so adjacent labels can't collide */}
        <div className="timeline-periods">
          {periodMarkers.map((m, i) => (
            <button
              key={m.label}
              className={`timeline-period-tick ${i % 2 ? "row-bottom" : "row-top"}`}
              style={{ left: `${m.pct}%` }}
              onClick={() => onDateChange(m.date)}
              title={`${m.description} (${m.date})`}
            >
              <span className="tick-line" />
              <span className="tick-label">{m.shortLabel}</span>
            </button>
          ))}
        </div>

        {/* The actual slider */}
        <input
          type="range"
          className="timeline-slider"
          min={0}
          max={totalDays}
          value={dayIdx}
          onChange={(e) => onDateChange(dayIndexToDate(Number(e.target.value), windowStart))}
        />
      </div>

      <div className="timeline-legend">
        <span className="legend-pip" /> kinetic event
        <span className="legend-spark" /> peer visibility
        <span className="legend-tick" /> BGP sample
        <span className="legend-threat adversary-path">▼</span> {adversaryLabel}-routed path
        <span className="legend-threat high-volume">◆</span> high-activity period
      </div>
    </div>
  );
}
