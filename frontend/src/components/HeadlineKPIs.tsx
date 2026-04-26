import { useMemo } from "react";
import type { Bundle } from "../types";

interface GlobalStats {
  total_conflicts: number;
  total_cities: number;
  total_events: number;
  exposed_cities: number;
  critical_cities: number;
  max_threat: number;
  total_adv_links: number;
}

interface Props {
  bundle: Bundle;
  globalStats?: GlobalStats;
}

export function HeadlineKPIs({ bundle, globalStats }: Props) {
  const ukraineKpis = useMemo(() => {
    const cities = Object.values(bundle.cities);
    let russianPaths = 0, totalPaths = 0, totalUpdates = 0, darkCities = 0;
    for (const c of cities) {
      russianPaths += c.threat.evidence.russian_paths_count;
      for (const p of Object.values(c.periods)) {
        totalUpdates += p.update_count;
        totalPaths   += p.sample_paths.length;
      }
      const minPeers = c.peer_timeline.reduce(
        (acc, p) => Math.min(acc, p.peers), Infinity,
      );
      if (isFinite(minPeers) && minPeers < 100) darkCities++;
    }
    return { russianPaths, totalPaths, totalUpdates, darkCities };
  }, [bundle]);

  if (globalStats) {
    return (
      <div className="kpi-bar">
        <KPI
          label="Active conflicts"
          value={String(globalStats.total_conflicts)}
          tone="neutral"
        />
        <KPI
          label="Cities monitored"
          value={String(globalStats.total_cities)}
          tone="neutral"
        />
        <KPI
          label="Cities exposed"
          value={String(globalStats.exposed_cities)}
          suffix={`/${globalStats.total_cities}`}
          tone={globalStats.exposed_cities > 8 ? "danger" : "warn"}
        />
        <KPI
          label="Peak threat score"
          value={String(globalStats.max_threat)}
          suffix="/100"
          tone={globalStats.max_threat >= 60 ? "danger" : "warn"}
        />
        <KPI
          label="Adversarial AS links"
          value={String(globalStats.total_adv_links)}
          tone={globalStats.total_adv_links > 0 ? "warn" : "neutral"}
        />
        <KPI
          label="Kinetic events (global)"
          value={globalStats.total_events.toLocaleString()}
          tone="neutral"
        />
      </div>
    );
  }

  return (
    <div className="kpi-bar">
      <KPI
        label="BGP UPDATEs (Ukraine)"
        value={ukraineKpis.totalUpdates.toLocaleString()}
        tone="neutral"
      />
      <KPI
        label="Cities dark"
        value={String(ukraineKpis.darkCities)}
        suffix={`/${Object.keys(bundle.cities).length}`}
        tone={ukraineKpis.darkCities >= 1 ? "danger" : "neutral"}
      />
      <KPI
        label="Russian-routed paths"
        value={String(ukraineKpis.russianPaths)}
        suffix={`/${ukraineKpis.totalPaths}`}
        tone={ukraineKpis.russianPaths > 0 ? "warn" : "neutral"}
      />
      <KPI label="ASes tracked"   value={String(bundle.stats.asn_count)} tone="neutral" />
      <KPI label="UCDP events"    value={bundle.stats.event_count.toLocaleString()} tone="neutral" />
      <KPI label="RIPE datapoints" value={bundle.stats.ripe_entries.toLocaleString()} tone="neutral" />
    </div>
  );
}

interface KPIProps {
  label: string;
  value: string;
  suffix?: string;
  tone: "neutral" | "warn" | "danger";
}

function KPI({ label, value, suffix, tone }: KPIProps) {
  return (
    <div className={`kpi tone-${tone}`}>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">
        {value}
        {suffix && <span className="kpi-suffix">{suffix}</span>}
      </div>
    </div>
  );
}
