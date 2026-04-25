import { useEffect, useMemo, useState } from "react";
import type { Bundle } from "./types";
import { CityPicker } from "./components/CityPicker";
import { MapView } from "./components/MapView";
import { TimelineScrubber } from "./components/TimelineScrubber";
import { BriefPanel } from "./components/BriefPanel";
import { nearestPeriod } from "./lib/dates";
import "./App.css";

export default function App() {
  const [bundle, setBundle] = useState<Bundle | null>(null);
  const [selectedCity, setSelectedCity] = useState<string>("Kherson");
  const [selectedDate, setSelectedDate] = useState<string>("2022-02-24");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/cyber_terrain.json")
      .then((r) => r.json())
      .then((data: Bundle) => setBundle(data))
      .catch((e) => setError(String(e)));
  }, []);

  // Derive the BGP period from the scrubber date — always nearest sample.
  const selectedPeriod = useMemo(() => {
    if (!bundle) return "invasion_start_2022";
    return nearestPeriod(selectedDate, bundle.periods).label;
  }, [bundle, selectedDate]);

  if (error) {
    return <div className="loading-screen">Error loading bundle: {error}</div>;
  }
  if (!bundle) {
    return <div className="loading-screen">Loading cyber terrain data…</div>;
  }

  const city = bundle.cities[selectedCity];

  return (
    <div className="app">
      <header className="app-header">
        <h1>Cyber Terrain Mapper</h1>
        <span className="subtitle">
          BGP routing × kinetic conflict — Ukraine, 2022
        </span>
        <span className="stats">
          {bundle.stats.bgp_records} BGP updates · {bundle.stats.asn_count} ASes ·{" "}
          {bundle.stats.event_count} kinetic events
        </span>
      </header>

      <div className="app-body">
        <aside className="sidebar-left">
          <CityPicker
            cities={bundle.cities}
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
          />
          <TimelineScrubber
            periods={bundle.periods}
            date={selectedDate}
            onDateChange={setSelectedDate}
            city={city}
            asns={bundle.asns}
            sormAses={bundle.sorm_ases}
          />
        </main>

        <aside className="sidebar-right">
          <BriefPanel
            city={city}
            period={selectedPeriod}
            date={selectedDate}
            bundle={bundle}
          />
        </aside>
      </div>
    </div>
  );
}
