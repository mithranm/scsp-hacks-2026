import { useMemo } from "react";
import { MapContainer, TileLayer, CircleMarker, Polyline, Tooltip, useMap } from "react-leaflet";
import { useEffect } from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import type { City, ASN, GlobalScenario } from "../types";
import { daysBetween, formatHumanDate } from "../lib/dates";

interface Props {
  city: City;
  asns: Record<string, ASN>;
  period: string;
  date: string;
  sormAses: Record<string, string>;
  scenario?: GlobalScenario;
}

const COLORS = {
  TARGET:           "#ffd400",   // city under analysis (yellow ring)
  HOST_LOCAL:       "#fff494",   // ASes in target's country (yellow-tinted)
  ADVERSARY:        "#d63838",   // ASes in scenario.adversarial_ases
  ADVERSARY_STATE:  "#8b0000",   // adversaries with intercept/DPI capability
  TAINTED_TRANSIT:  "#ff9b1c",   // neutral AS on a path that crosses an adversary
  CLEAN_TRANSIT:    "#888",
};

// Region centroids for map perspective per scenario
const REGION_VIEW: Record<string, { center: L.LatLngTuple; zoom: number }> = {
  "Eastern Europe":  { center: [49.0,  33.0], zoom: 5 },
  "Middle East":     { center: [31.0,  36.0], zoom: 5 },
  "East Asia":       { center: [25.0, 122.0], zoom: 5 },
  "Southeast Asia":  { center: [19.5,  96.0], zoom: 5 },
  "East Africa":     { center: [16.0,  32.5], zoom: 5 },
};

// Demonyms — derived once per scenario for legend & tooltip text
function scenarioLexicon(scenario?: GlobalScenario) {
  if (!scenario) {
    return {
      hostLabel:        "Target",
      adversaryLabel:   "Adversary",
      adversaryState:   "State-controlled",
      regionLabel:      "Region",
    };
  }
  switch (scenario.id) {
    case "russia_ukraine":
      return {
        hostLabel: "Ukrainian", adversaryLabel: "Russian",
        adversaryState: "SORM-capable",     regionLabel: "Ukraine",
      };
    case "sudan_civil_war":
      return {
        hostLabel: "Sudanese", adversaryLabel: "Regional re-route",
        adversaryState: "Cross-border transit", regionLabel: "Sudan",
      };
    case "myanmar_civil_war":
      return {
        hostLabel: "Myanmar civilian", adversaryLabel: "Junta-controlled",
        adversaryState: "Military telecom", regionLabel: "Myanmar",
      };
    case "iran_yemen_houthi":
      return {
        hostLabel: "Yemeni", adversaryLabel: "Iranian state",
        adversaryState: "DPI/intercept gateway", regionLabel: "Yemen/Iran",
      };
    case "china_taiwan":
      return {
        hostLabel: "Taiwanese", adversaryLabel: "PRC state-controlled",
        adversaryState: "MSS-mandated access", regionLabel: "Taiwan/China",
      };
  }
  return {
    hostLabel: "Local", adversaryLabel: "Adversary",
    adversaryState: "State-controlled", regionLabel: scenario.region,
  };
}

// Helper component to recenter map when scenario changes
function MapRecentre({ center, zoom }: { center: L.LatLngTuple; zoom: number }) {
  const map = useMap();
  useEffect(() => {
    map.flyTo(center, zoom, { duration: 1.2 });
  }, [map, center, zoom]);
  return null;
}

export function MapView({ city, asns, period, date, sormAses, scenario }: Props) {
  const periodData = (city as any).periods?.[period];
  const lex = scenarioLexicon(scenario);

  // Adversary AS set comes from the active scenario, not global classification
  const adversaryAses: Record<string, { operator: string; role: string }> =
    scenario?.adversarial_ases ?? {};
  const adversarySet = new Set(Object.keys(adversaryAses));
  const hostCountry = scenario?.cities[0]
    ? (asns[String(scenario.cities[0].asn)]?.country ?? "")
    : "";

  // Categorize an AS for this scenario
  function categorize(asn: string, asnRecord: ASN | undefined, tainted: boolean): {
    color: string;
    category: "target" | "adversary" | "adversary_state" | "host_local" | "tainted_transit" | "clean_transit";
    label: string;
  } {
    if (asnRecord && asnRecord.asn === city.asn) {
      return { color: COLORS.TARGET, category: "target", label: `Target — ${city.name}` };
    }
    if (adversarySet.has(asn)) {
      const role = adversaryAses[asn]?.role ?? "";
      if (/intercept|dpi|state|surveil|mandate/i.test(role)) {
        return { color: COLORS.ADVERSARY_STATE, category: "adversary_state", label: lex.adversaryState };
      }
      return { color: COLORS.ADVERSARY, category: "adversary", label: lex.adversaryLabel };
    }
    if (asnRecord && hostCountry && asnRecord.country === hostCountry) {
      return { color: COLORS.HOST_LOCAL, category: "host_local", label: lex.hostLabel };
    }
    if (tainted) {
      return { color: COLORS.TAINTED_TRANSIT, category: "tainted_transit",
               label: `Transit on ${lex.adversaryLabel.toLowerCase()} path` };
    }
    return { color: COLORS.CLEAN_TRANSIT, category: "clean_transit", label: "Clean transit" };
  }

  // For each sample path, classify it; mark which ASes appear on tainted paths
  const { visibleAsns, polylines, taintedAsns } = useMemo(() => {
    const set = new Set<string>([String(city.asn)]);
    const tainted = new Set<string>();
    const lines: { coords: L.LatLngTuple[]; key: string; color: string }[] = [];

    if (!periodData) {
      return {
        visibleAsns: Array.from(set).map((a) => asns[a]).filter(Boolean),
        polylines:   lines,
        taintedAsns: tainted,
      };
    }

    (periodData.sample_paths ?? []).forEach((path: string, idx: number) => {
      const hops = path
        .split(" → ")
        .map((a) => a.trim())
        .filter((a) => /^\d+$/.test(a));
      hops.forEach((h) => set.add(h));

      // Path is tainted if any hop is in the SCENARIO's adversary list
      // (or the legacy SORM list — used for Ukraine richness)
      const isTainted = hops.some(
        (h) => adversarySet.has(h) || sormAses[h],
      );
      if (isTainted) hops.forEach((h) => tainted.add(h));

      const coords: L.LatLngTuple[] = hops
        .map((a) => asns[a])
        .filter(Boolean)
        .map((a): L.LatLngTuple => [a.lat, a.lon]);
      if (coords.length >= 2) {
        lines.push({
          coords,
          key: `path-${idx}`,
          color: isTainted ? "#d63838" : "#4aa3ff",
        });
      }
    });

    return {
      visibleAsns: Array.from(set).map((a) => asns[a]).filter(Boolean),
      polylines:   lines,
      taintedAsns: tainted,
    };
  }, [periodData, asns, sormAses, city.asn, adversarySet]);

  // Live peer count for the scrubber's exact date
  const livePeerSnapshot = useMemo(() => {
    if (!city.peer_timeline || city.peer_timeline.length === 0) return null;
    let best = city.peer_timeline[0];
    let bestAbs = Infinity;
    for (const p of city.peer_timeline) {
      const d = Math.abs(daysBetween(date, p.date));
      if (d < bestAbs) {
        bestAbs = d;
        best = p;
      }
    }
    return { ...best, daysAway: bestAbs };
  }, [city, date]);

  // Kinetic event happening within ±3 days → flash a pulse marker
  const activeEvents = useMemo(() => {
    return (city.events || []).filter(
      (e) => Math.abs(daysBetween(date, (e as any).event_date)) <= 3,
    );
  }, [city, date]);

  const isDark = livePeerSnapshot && livePeerSnapshot.peers < 100;
  const view = REGION_VIEW[scenario?.region ?? ""] ?? { center: [49, 32] as L.LatLngTuple, zoom: 5 };

  return (
    <div className="map-view">
      <MapContainer center={view.center} zoom={view.zoom} className="leaflet-map">
        <MapRecentre center={view.center} zoom={view.zoom} />
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

        {polylines.map((p) => (
          <Polyline
            key={p.key}
            positions={p.coords}
            pathOptions={{ color: p.color, weight: 2, opacity: 0.65 }}
          />
        ))}

        {visibleAsns.map((a) => {
          const isCity = a.asn === city.asn;
          const tainted = taintedAsns.has(String(a.asn));
          const cat = categorize(String(a.asn), a, tainted);
          const isAdv = adversarySet.has(String(a.asn));
          return (
            <CircleMarker
              key={a.asn}
              center={[a.lat, a.lon]}
              radius={isCity ? 10 : isAdv ? 8 : 6}
              pathOptions={{
                color: cat.color,
                fillColor: cat.color,
                fillOpacity: 0.85,
                weight: isCity ? 3 : 1,
              }}
            >
              <Tooltip>
                <div style={{ fontWeight: 600 }}>AS{a.asn}</div>
                <div>{a.holder}</div>
                <div>{a.country_name || a.country} · {cat.label}</div>
                {isAdv && adversaryAses[String(a.asn)] && (
                  <div style={{ color: COLORS.ADVERSARY }}>
                    ⚠ {adversaryAses[String(a.asn)].role}
                  </div>
                )}
                {tainted && !isAdv && !isCity && (
                  <div style={{ color: COLORS.TAINTED_TRANSIT }}>
                    ⚠ On {lex.adversaryLabel.toLowerCase()}-routed path
                  </div>
                )}
                {a.ua_city && <div>City: {a.ua_city}</div>}
              </Tooltip>
            </CircleMarker>
          );
        })}

        {/* Active kinetic event ring */}
        {activeEvents.length > 0 && (
          <CircleMarker
            center={[city.lat, city.lon]}
            radius={28}
            pathOptions={{
              color: "#ff5a5a", fillColor: "transparent",
              weight: 2, opacity: 0.9, dashArray: "4 6",
            }}
          />
        )}

        {/* City marker (top layer) */}
        <CircleMarker
          center={[city.lat, city.lon]}
          radius={14}
          pathOptions={{
            color: isDark ? "#ff5a5a" : COLORS.TARGET,
            fillColor: "transparent",
            weight: 3,
          }}
        >
          <Tooltip permanent direction="top">
            {city.name}{isDark ? " · DARK" : ""}
          </Tooltip>
        </CircleMarker>
      </MapContainer>

      <div className="map-legend">
        <h3>{city.name}</h3>
        <div className="legend-date">{formatHumanDate(date)}</div>
        {scenario && (
          <div className="legend-scenario-tag">{scenario.name}</div>
        )}

        {livePeerSnapshot && (
          <div className={`legend-peers ${isDark ? "dark" : ""}`}>
            <strong>{livePeerSnapshot.peers.toFixed(0)}</strong> peers seeing prefix
            {isDark && <span className="legend-blackout"> · BLACKOUT</span>}
          </div>
        )}

        {periodData && (
          <div>
            <strong>{periodData.update_count}</strong> events / updates
            <span className="legend-period-tag"> · {periodData.description}</span>
          </div>
        )}

        {activeEvents.length > 0 && (
          <div className="legend-active-event">
            ⚠ {activeEvents.length} kinetic event{activeEvents.length > 1 ? "s" : ""} ±3d
          </div>
        )}

        <div className="legend-key">
          <span style={{ color: COLORS.TARGET }}>● Target city</span>
          <span style={{ color: COLORS.HOST_LOCAL }}>● {lex.hostLabel} ASes</span>
          <span style={{ color: COLORS.ADVERSARY }}>● {lex.adversaryLabel}</span>
          <span style={{ color: COLORS.ADVERSARY_STATE }}>● {lex.adversaryState}</span>
          <span style={{ color: COLORS.TAINTED_TRANSIT }}>● Transit on adv. path</span>
          <span style={{ color: COLORS.CLEAN_TRANSIT }}>● Clean transit</span>
        </div>
      </div>
    </div>
  );
}
