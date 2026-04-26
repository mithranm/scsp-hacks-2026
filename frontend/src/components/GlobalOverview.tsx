import { MapContainer, TileLayer, CircleMarker, Tooltip } from "react-leaflet";
import type { GlobalScenario } from "../types";
import "leaflet/dist/leaflet.css";

interface Props {
  scenarios: Record<string, GlobalScenario>;
  onSelectScenario: (id: string) => void;
}

const LEVEL_COLOR: Record<string, string> = {
  critical: "#d63838",
  severe:   "#ff9b1c",
  elevated: "#ffd400",
  nominal:  "#6b9bd1",
};

export function GlobalOverview({ scenarios, onSelectScenario }: Props) {
  const allCities = Object.entries(scenarios).flatMap(([sid, s]) =>
    s.cities.map((c) => ({
      ...c,
      scenario_id: sid,
      scenario_name: s.name,
      scenario_actor: s.primary_actor,
    })),
  );

  // Stats for the legend overlay
  const totalCritical = allCities.filter((c) => c.threat.level === "critical").length;
  const totalSevere   = allCities.filter((c) => c.threat.level === "severe").length;
  const totalElevated = allCities.filter((c) => c.threat.level === "elevated").length;
  const totalCities   = allCities.length;
  const peakThreat    = Math.max(...allCities.map((c) => c.threat.score));
  const totalEvents   = Object.values(scenarios).reduce((s, sc) => s + sc.totals.total_events, 0);

  return (
    <div className="global-overview">
      <MapContainer
        center={[25, 50]}
        zoom={3}
        className="leaflet-map"
        style={{ height: "100%" }}
        worldCopyJump={true}
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

        {allCities.map((c) => {
          const color = LEVEL_COLOR[c.threat.level];
          // Critical cities pulse
          const radius =
            c.threat.level === "critical" ? 12 :
            c.threat.level === "severe"   ? 9  :
            c.threat.level === "elevated" ? 7  : 5;
          return (
            <CircleMarker
              key={`${c.scenario_id}-${c.asn}-${c.city}`}
              center={[c.lat, c.lon]}
              radius={radius}
              pathOptions={{
                color,
                fillColor:   color,
                fillOpacity: c.threat.level === "critical" ? 0.9 : 0.7,
                weight:      c.threat.level === "critical" ? 3 : 1.5,
              }}
              eventHandlers={{ click: () => onSelectScenario(c.scenario_id) }}
            >
              <Tooltip direction="top">
                <div style={{ fontWeight: 700 }}>
                  {c.city} — {c.threat.score}/100
                </div>
                <div style={{ fontSize: 10, opacity: 0.85 }}>
                  AS{c.asn} · {c.scenario_name}
                </div>
                <div style={{ fontSize: 10, opacity: 0.7, marginTop: 2 }}>
                  {c.threat.level.toUpperCase()} · click to inspect
                </div>
              </Tooltip>
            </CircleMarker>
          );
        })}
      </MapContainer>

      {/* Floating legend / KPIs over the map */}
      <div className="global-overview-legend">
        <div className="overview-title">
          <div className="overview-title-main">Global cyber-terrain monitor</div>
          <div className="overview-title-sub">
            {Object.keys(scenarios).length} active conflicts · {totalCities} cities · {totalEvents.toLocaleString()} kinetic events
          </div>
        </div>

        <div className="overview-stats">
          <div className="overview-stat">
            <span className="overview-stat-num" style={{ color: LEVEL_COLOR.critical }}>{totalCritical}</span>
            <span className="overview-stat-label">CRITICAL</span>
          </div>
          <div className="overview-stat">
            <span className="overview-stat-num" style={{ color: LEVEL_COLOR.severe }}>{totalSevere}</span>
            <span className="overview-stat-label">SEVERE</span>
          </div>
          <div className="overview-stat">
            <span className="overview-stat-num" style={{ color: LEVEL_COLOR.elevated }}>{totalElevated}</span>
            <span className="overview-stat-label">ELEVATED</span>
          </div>
          <div className="overview-stat">
            <span className="overview-stat-num">{peakThreat}</span>
            <span className="overview-stat-label">PEAK SCORE</span>
          </div>
        </div>

        <div className="overview-scenarios">
          {Object.entries(scenarios)
            .sort(([, a], [, b]) => b.totals.max_threat - a.totals.max_threat)
            .map(([sid, s]) => (
              <button
                key={sid}
                className="overview-scenario-row"
                onClick={() => onSelectScenario(sid)}
              >
                <span className="ovs-name">{s.name}</span>
                <span className="ovs-region">{s.region}</span>
                <span
                  className={`ovs-score level-${
                    s.totals.max_threat >= 80 ? "critical" :
                    s.totals.max_threat >= 60 ? "severe" :
                    s.totals.max_threat >= 30 ? "elevated" : "nominal"
                  }`}
                >
                  {s.totals.max_threat}
                </span>
              </button>
            ))}
        </div>

        <div className="overview-method">
          Click any marker or scenario to drill in. Same methodology — RIPE Stat
          BGP routing × UCDP GED kinetic events × adversarial-AS classification
          — applied uniformly across every conflict.
        </div>
      </div>
    </div>
  );
}
