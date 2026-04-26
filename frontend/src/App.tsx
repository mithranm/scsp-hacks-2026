import { useEffect, useMemo, useState } from "react";
import type { Bundle, City, GlobalScenario } from "./types";
import { CityPicker } from "./components/CityPicker";
import { MapView } from "./components/MapView";
import { TimelineScrubber } from "./components/TimelineScrubber";
import { BriefPanel } from "./components/BriefPanel";
import { HeadlineKPIs } from "./components/HeadlineKPIs";
import { ScenarioPicker } from "./components/ScenarioPicker";
import { GlobalOverview } from "./components/GlobalOverview";
import { nearestPeriod } from "./lib/dates";
import "./App.css";

function scenarioAdversaryLabel(id: string): string {
  switch (id) {
    case "russia_ukraine":     return "Russian";
    case "sudan_civil_war":    return "Cross-border";
    case "myanmar_civil_war":  return "Junta";
    case "iran_yemen_houthi":  return "Iranian-state";
    case "china_taiwan":       return "PRC-state";
    default:                   return "Adversary";
  }
}

export default function App() {
  const [bundle,    setBundle]    = useState<Bundle | null>(null);
  const [error,     setError]     = useState<string | null>(null);
  const [selectedScenario, setSelectedScenario] = useState<string>("__overview__");
  const [selectedCity,     setSelectedCity]     = useState<string>("");
  const [selectedDate,     setSelectedDate]     = useState<string>("2022-02-24");

  useEffect(() => {
    fetch("/cyber_terrain.json")
      .then((r) => r.json())
      .then((data: Bundle) => setBundle(data))
      .catch((e) => setError(String(e)));
  }, []);

  // ── Aggregated KPIs across every scenario (must come before early return) ──
  const globalStats = useMemo(() => {
    const all = Object.values(bundle?.global_scenarios ?? {});
    if (all.length === 0) return undefined;
    return {
      total_conflicts: all.length,
      total_cities:    all.reduce((s, sc) => s + sc.totals.city_count,           0),
      total_events:    all.reduce((s, sc) => s + sc.totals.total_events,          0),
      exposed_cities:  all.reduce((s, sc) => s + sc.totals.exposed_cities,        0),
      critical_cities: all.reduce((s, sc) => s + sc.totals.critical_cities,       0),
      max_threat:      Math.max(...all.map((sc) => sc.totals.max_threat)),
      total_adv_links: all.reduce((s, sc) => s + sc.totals.total_adversarial_adjacencies, 0),
    };
  }, [bundle]);

  // ── Build a {cityName: City} map for the active scenario ──
  const sceneCities = useMemo(() => {
    if (!bundle) return {} as Record<string, City>;
    const sc = bundle.global_scenarios?.[selectedScenario];
    if (!sc) return {} as Record<string, City>;
    const out: Record<string, City> = {};
    for (const c of sc.cities) {
      // Each scenario city has all the fields we need; cast through unknown to satisfy TS
      out[c.city] = c as unknown as City;
    }
    return out;
  }, [bundle, selectedScenario]);

  // ── Active scenario object ──
  const scenario: GlobalScenario | undefined = bundle?.global_scenarios?.[selectedScenario];

  // ── Period selection: nearest BGP/synthetic period to the scrubber date ──
  const scenarioPeriods = useMemo(() => {
    if (!scenario || !scenario.cities[0]) return [];
    // Periods are per-city in the scenario, but they all share the same dates,
    // so we read from the first city.
    const periodsObj: Record<string, { date: string; description: string }> =
      (scenario.cities[0] as any).periods ?? {};
    return Object.entries(periodsObj).map(([label, p]) => ({
      label,
      description: p.description,
      date:        p.date,
    }));
  }, [scenario]);

  const selectedPeriod = useMemo(() => {
    if (scenarioPeriods.length === 0) {
      // Fall back to legacy bundle.periods (Ukraine only)
      return bundle ? nearestPeriod(selectedDate, bundle.periods).label : "scenario_start";
    }
    return nearestPeriod(selectedDate, scenarioPeriods).label;
  }, [bundle, selectedDate, scenarioPeriods]);

  // ── Auto-pick first city when scenario changes, and snap date to its window ──
  useEffect(() => {
    if (!scenario) return;
    const sortedCities = scenario.cities
      .slice()
      .sort((a, b) => b.threat.score - a.threat.score);
    const top = sortedCities[0];
    if (top && !sceneCities[selectedCity]) {
      setSelectedCity(top.city);
    }
    // Snap scrubber date to the scenario's window
    const sceneStart = scenario.date_start;
    const sceneEnd   = scenario.date_end;
    if (selectedDate < sceneStart || selectedDate > sceneEnd) {
      // Pick a date with peak kinetic intensity if possible, else mid-window
      const periods = (top as any)?.periods ?? {};
      const peakP = periods.peak_kinetic ?? periods.scenario_start;
      setSelectedDate(peakP?.date ?? sceneStart);
    }
  }, [scenario, sceneCities, selectedCity, selectedDate]);

  // Adversary set — must be before early returns (Rules of Hooks)
  const advSet = useMemo(() => {
    if (!scenario) return new Set<string>();
    return new Set(Object.keys(scenario.adversarial_ases ?? {}));
  }, [scenario]);

  if (error)  return <div className="loading-screen">Error: {error}</div>;
  if (!bundle) return <div className="loading-screen">Loading cyber terrain data…</div>;

  const scenarios  = bundle.global_scenarios ?? {};
  const isOverview = selectedScenario === "__overview__";
  const city       = sceneCities[selectedCity];
  const advLabel   = scenario ? scenarioAdversaryLabel(scenario.id) : "Adversary";

  return (
    <div className="app">
      <header className="app-header">
        <h1>Cyber Terrain Mapper</h1>
        <span className="subtitle">
          Global BGP routing × kinetic conflict intelligence
        </span>
        <span className="stats">
          {globalStats
            ? `${globalStats.total_conflicts} conflicts · ${globalStats.total_cities} cities · ${globalStats.total_events.toLocaleString()} kinetic events · ${globalStats.total_adv_links} adversarial AS links`
            : `${bundle.stats.bgp_records} BGP updates · ${bundle.stats.asn_count} ASes · ${bundle.stats.event_count} kinetic events`
          }
        </span>
      </header>

      <ScenarioPicker
        scenarios={scenarios}
        selected={selectedScenario}
        onSelect={(id) => {
          setSelectedScenario(id);
          setSelectedCity("");   // re-pick after scenario change
        }}
      />

      <HeadlineKPIs bundle={bundle} globalStats={globalStats} />

      {isOverview ? (
        <GlobalOverview
          scenarios={scenarios}
          onSelectScenario={(id) => {
            setSelectedScenario(id);
            setSelectedCity("");
          }}
        />
      ) : scenario && city ? (
        <div className="app-body">
          <aside className="sidebar-left">
            <CityPicker
              cities={sceneCities}
              selected={selectedCity}
              onSelect={setSelectedCity}
            />
          </aside>
          <main className="map-area">
            <MapView
              city={city}
              asns={bundle.asns}
              period={selectedPeriod}
              date={selectedDate}
              sormAses={bundle.sorm_ases}
              scenario={scenario}
            />
            <TimelineScrubber
              periods={scenarioPeriods.length > 0 ? scenarioPeriods : bundle.periods}
              date={selectedDate}
              onDateChange={setSelectedDate}
              city={city}
              asns={bundle.asns}
              sormAses={bundle.sorm_ases}
              windowStart={scenario.date_start}
              windowEnd={scenario.date_end}
              adversarySet={advSet}
              adversaryLabel={advLabel}
            />
          </main>
          <aside className="sidebar-right">
            <BriefPanel
              city={city}
              period={selectedPeriod}
              date={selectedDate}
              bundle={bundle}
              scenario={scenario}
            />
          </aside>
        </div>
      ) : (
        <div className="loading-screen">Selecting first city…</div>
      )}
    </div>
  );
}
