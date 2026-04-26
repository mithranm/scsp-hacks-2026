import { useState } from "react";
import { MapContainer, TileLayer, CircleMarker, Tooltip } from "react-leaflet";
import type { GlobalScenario, GlobalScenarioCity } from "../types";
import { MitigationPanel } from "./MitigationPanel";
import "leaflet/dist/leaflet.css";

interface Props {
  scenario: GlobalScenario;
}

const LEVEL_COLOR: Record<string, string> = {
  critical: "#d63838",
  severe:   "#ff9b1c",
  elevated: "#ffd400",
  nominal:  "#6b9bd1",
};

// Centre-of-gravity per region
const REGION_CENTRE: Record<string, [number, number]> = {
  "Eastern Europe":  [49.0,  33.0],
  "Middle East":     [31.0,  35.0],
  "East Asia":       [24.0, 121.5],
  "Southeast Asia":  [19.5,  96.0],
  "East Africa":     [16.0,  32.5],
};
const REGION_ZOOM: Record<string, number> = {
  "Eastern Europe": 5,
  "Middle East":    6,
  "East Asia":      7,
  "Southeast Asia": 7,
  "East Africa":    6,
};

export function GlobalScenarioView({ scenario }: Props) {
  const [selectedCity, setSelectedCity] = useState<GlobalScenarioCity>(
    scenario.cities.slice().sort((a, b) => b.threat.score - a.threat.score)[0],
  );

  const centre = REGION_CENTRE[scenario.region] ?? [20, 0];
  const zoom   = REGION_ZOOM[scenario.region] ?? 5;

  return (
    <div className="global-scenario-view">
      {/* Left sidebar — city list */}
      <aside className="sidebar-left">
        <div className="scenario-sidebar-header">
          <div className="scenario-sidebar-name">{scenario.name}</div>
          <div className="scenario-sidebar-region">{scenario.region}</div>
          <div className="scenario-sidebar-meta">
            <span>{scenario.totals.city_count} cities</span>
            <span>{scenario.totals.total_events.toLocaleString()} events</span>
            <span>{scenario.totals.total_adversarial_adjacencies} adv. links</span>
          </div>
          {scenario.data_source === "contingency" && (
            <div className="scenario-contingency-badge">
              CONTINGENCY SCENARIO — no active conflict
            </div>
          )}
        </div>

        <ul className="global-city-list">
          {scenario.cities
            .slice()
            .sort((a, b) => b.threat.score - a.threat.score)
            .map((c) => (
              <li
                key={`${c.asn}-${c.city}`}
                className={`global-city-row ${
                  selectedCity.asn === c.asn && selectedCity.city === c.city ? "active" : ""
                }`}
                onClick={() => setSelectedCity(c)}
              >
                <div className="global-city-top">
                  <span className="global-city-name">{c.city}</span>
                  <span
                    className={`threat-badge level-${c.threat.level}`}
                  >
                    {c.threat.score}
                  </span>
                </div>
                <div className="global-city-meta">
                  <span>AS{c.asn}</span>
                  <span>{c.kinetic_event_count} events near city</span>
                </div>
                <div className={`threat-level-text level-${c.threat.level}`}>
                  {c.threat.level.toUpperCase()}
                </div>
              </li>
            ))}
        </ul>
      </aside>

      {/* Map */}
      <main className="global-map-area">
        <MapContainer
          center={centre}
          zoom={zoom}
          className="leaflet-map"
          style={{ height: "100%" }}
        >
          <TileLayer
            attribution="Imagery &copy; Esri, Maxar, Earthstar Geographics"
            url="https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}"
            maxZoom={18}
          />
          <TileLayer
            attribution=""
            url="https://server.arcgisonline.com/ArcGIS/rest/services/Reference/World_Boundaries_and_Places/MapServer/tile/{z}/{y}/{x}"
            maxZoom={18}
            opacity={0.85}
          />

          {scenario.cities.map((c) => {
            const color = LEVEL_COLOR[c.threat.level];
            const isSelected =
              c.asn === selectedCity.asn && c.city === selectedCity.city;
            return (
              <CircleMarker
                key={`${c.asn}-${c.city}`}
                center={[c.lat, c.lon]}
                radius={isSelected ? 14 : 9}
                pathOptions={{
                  color,
                  fillColor: color,
                  fillOpacity: 0.85,
                  weight: isSelected ? 3 : 1.5,
                }}
                eventHandlers={{ click: () => setSelectedCity(c) }}
              >
                <Tooltip permanent={isSelected} direction="top">
                  <strong>{c.city}</strong><br />
                  Threat: {c.threat.score}/100 ({c.threat.level})<br />
                  AS{c.asn}
                </Tooltip>
              </CircleMarker>
            );
          })}
        </MapContainer>
      </main>

      {/* Right sidebar — city brief + mitigations */}
      <aside className="sidebar-right">
        <div className="brief-panel">
          <h2>{selectedCity.city}</h2>
          <div className="brief-meta">
            <div><strong>AS{selectedCity.asn}</strong> · {scenario.name}</div>
            <div className="brief-period">{scenario.primary_actor}</div>
          </div>

          {/* Threat score */}
          <section className={`threat-section level-${selectedCity.threat.level}`}>
            <div className="threat-header">
              <span className="threat-label">Cyber-Terrain Threat Score</span>
              <span className={`threat-level-pill level-${selectedCity.threat.level}`}>
                {selectedCity.threat.level.toUpperCase()}
              </span>
            </div>
            <div className="threat-score-row">
              <span className={`threat-score-big level-${selectedCity.threat.level}`}>
                {selectedCity.threat.score}
              </span>
              <span className="threat-out-of">/ 100</span>
            </div>
            <div className="threat-bar">
              <div
                className={`threat-bar-fill level-${selectedCity.threat.level}`}
                style={{ width: `${selectedCity.threat.score}%` }}
              />
            </div>
            <ul className="threat-components">
              {[
                ["Blackout signal",  selectedCity.threat.components.blackout,      40],
                ["Kinetic intensity", selectedCity.threat.components.instability,  25],
                ["Adv. adjacency",   selectedCity.threat.components.russian_route,  25],
                ["Intercept exp.",   selectedCity.threat.components.sorm_exposure,  10],
              ].map(([label, val, max]) => (
                <li key={String(label)}>
                  <span className="comp-label">{label}</span>
                  <span className="comp-bar">
                    <span style={{ width: `${((val as number) / (max as number)) * 100}%` }} />
                  </span>
                  <span className="comp-val">
                    {(val as number).toFixed(1)}
                    <span className="comp-max">/{max}</span>
                  </span>
                </li>
              ))}
            </ul>
          </section>

          {/* Adversarial adjacencies */}
          {(selectedCity.threat.evidence.adversarial_neighbours?.length ?? 0) > 0 && (
            <section>
              <h3>Adversarial adjacencies</h3>
              <ul className="adv-adj-list">
                {selectedCity.threat.evidence.adversarial_neighbours!.map((n) => (
                  <li key={n.asn} className="adv-adj-row">
                    <span className="adv-asn">AS{n.asn}</span>
                    <span className="adv-op">{n.operator}</span>
                    <span className="adv-role">{n.role}</span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {/* Recent kinetic events */}
          {selectedCity.events.length > 0 && (
            <section>
              <h3>Kinetic events ({selectedCity.kinetic_event_count})</h3>
              <ul className="scenario-events-list">
                {selectedCity.events.slice(0, 4).map((e, i) => (
                  <li key={i}>
                    <div className="event-date">{e.event_date}</div>
                    <div className="event-type">
                      <strong>{e.event_type}</strong>
                      {(e as any).fatalities > 0 && (
                        <span className="event-fatalities">
                          {" "}· {(e as any).fatalities} fatalities
                        </span>
                      )}
                    </div>
                    <div className="event-notes">{e.notes?.slice(0, 120)}</div>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {/* BGP Mitigations — the key deliverable */}
          <MitigationPanel city={selectedCity} />

          {/* Adversarial AS context */}
          <section className="adv-as-context">
            <h3>Threat actor ASes ({Object.keys(scenario.adversarial_ases).length})</h3>
            <ul className="adv-as-list">
              {Object.entries(scenario.adversarial_ases)
                .slice(0, 6)
                .map(([asn, info]) => (
                  <li key={asn}>
                    <span className="adv-asn">AS{asn}</span>
                    <span className="adv-op">{info.operator}</span>
                    <span className="adv-role">{info.role}</span>
                  </li>
                ))}
            </ul>
          </section>
        </div>
      </aside>
    </div>
  );
}
