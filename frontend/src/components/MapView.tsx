import { useMemo } from "react";
import { MapContainer, TileLayer, CircleMarker, Polyline, Tooltip } from "react-leaflet";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import type { City, ASN } from "../types";
import { daysBetween, formatHumanDate } from "../lib/dates";

interface Props {
  city: City;
  asns: Record<string, ASN>;
  period: string;
  date: string;
  sormAses: Record<string, string>;
}

const CLASS_COLORS: Record<string, string> = {
  "UA-target":   "#ffd400",
  "Ukrainian":   "#fff494",
  "Russian":     "#d63838",
  "SORM":        "#8b0000",
  "Belarusian":  "#c97070",
  "Transit":     "#888",
};

// "Russian-routed" path = path contains any adversarial-country AS
const ADVERSARIAL_CLASSES = new Set(["Russian", "SORM", "Belarusian"]);

// Color for a transit AS that is itself neutral, but happens to sit on a
// path that traverses adversarial infrastructure. Visually distinct from
// both "clean transit" gray and "Russian" red.
const TAINTED_TRANSIT_COLOR = "#ff9b1c";

export function MapView({ city, asns, period, date, sormAses }: Props) {
  const periodData = city.periods[period];

  // For each sample path, classify it and mark which ASes appear on tainted paths
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

    periodData.sample_paths.forEach((path, idx) => {
      const hops = path
        .split(" → ")
        .map((a) => a.trim())
        .filter((a) => /^\d+$/.test(a));
      hops.forEach((h) => set.add(h));

      // Path is tainted if any hop is adversarial (Russian / SORM / Belarusian) — by registration OR by SORM list
      const isTainted = hops.some((h) => {
        if (sormAses[h]) return true;
        const a = asns[h];
        return a && ADVERSARIAL_CLASSES.has(a.classification);
      });

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
  }, [periodData, asns, sormAses, city.asn]);

  // Choose a marker color for an AS:
  //   1. Adversarial (Russian/SORM/Belarusian) → its registration color (red/dark red)
  //   2. UA-target / Ukrainian → yellow family
  //   3. Transit on a tainted path → orange ("compromised by association")
  //   4. Transit on clean paths only → gray
  function colorForAsn(a: ASN): string {
    if (a.asn === city.asn) return CLASS_COLORS["UA-target"];
    if (ADVERSARIAL_CLASSES.has(a.classification)) {
      return CLASS_COLORS[a.classification];
    }
    if (a.classification === "Ukrainian" || a.classification === "UA-target") {
      return CLASS_COLORS[a.classification];
    }
    if (taintedAsns.has(String(a.asn))) {
      return TAINTED_TRANSIT_COLOR;
    }
    return CLASS_COLORS["Transit"];
  }

  // Live peer count for the scrubber's exact date — uses nearest peer-timeline sample
  const livePeerSnapshot = useMemo(() => {
    if (city.peer_timeline.length === 0) return null;
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

  // Kinetic event happening within ±3 days of scrubber → flash a pulse marker
  const activeEvents = useMemo(() => {
    return city.events.filter(
      (e) => Math.abs(daysBetween(date, e.event_date)) <= 3,
    );
  }, [city, date]);

  // Communications-blackout signal: peer count below 100 = effectively dark
  const isDark = livePeerSnapshot && livePeerSnapshot.peers < 100;

  const center: L.LatLngTuple = [49, 32];

  return (
    <div className="map-view">
      <MapContainer center={center} zoom={5} className="leaflet-map">
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
          const color = colorForAsn(a);
          const tainted = taintedAsns.has(String(a.asn));
          const isAdversarial = ADVERSARIAL_CLASSES.has(a.classification);
          return (
            <CircleMarker
              key={a.asn}
              center={[a.lat, a.lon]}
              radius={isCity ? 10 : 6}
              pathOptions={{
                color,
                fillColor: color,
                fillOpacity: 0.85,
                weight: isCity ? 3 : 1,
              }}
            >
              <Tooltip>
                <div style={{ fontWeight: 600 }}>AS{a.asn}</div>
                <div>{a.holder}</div>
                <div>{a.country_name} · {a.classification}</div>
                {a.sorm_role && <div style={{ color: "#d63838" }}>⚠ {a.sorm_role}</div>}
                {tainted && !isAdversarial && !isCity && (
                  <div style={{ color: TAINTED_TRANSIT_COLOR }}>
                    ⚠ on Russian-routed path
                  </div>
                )}
                {a.ua_city && <div>City: {a.ua_city}</div>}
              </Tooltip>
            </CircleMarker>
          );
        })}

        {/* Active kinetic event ring — pulses around the city when scrubber sits within ±3d */}
        {activeEvents.length > 0 && (
          <CircleMarker
            center={[city.lat, city.lon]}
            radius={28}
            pathOptions={{
              color: "#ff5a5a",
              fillColor: "transparent",
              weight: 2,
              opacity: 0.9,
              dashArray: "4 6",
            }}
          />
        )}

        {/* City marker (top layer) */}
        <CircleMarker
          center={[city.lat, city.lon]}
          radius={14}
          pathOptions={{
            color: isDark ? "#ff5a5a" : "#ffd400",
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

        {/* LIVE — updates every drag tick */}
        {livePeerSnapshot && (
          <div className={`legend-peers ${isDark ? "dark" : ""}`}>
            <strong>{livePeerSnapshot.peers}</strong> peers seeing prefix
            {isDark && <span className="legend-blackout"> · BLACKOUT</span>}
          </div>
        )}

        {/* Period-aggregated BGP signal */}
        {periodData && (
          <>
            <div>
              <strong>{periodData.update_count}</strong> BGP updates
              <span className="legend-period-tag"> · {periodData.description}</span>
            </div>
          </>
        )}

        {/* Live kinetic events */}
        {activeEvents.length > 0 && (
          <div className="legend-active-event">
            ⚠ {activeEvents.length} kinetic event{activeEvents.length > 1 ? "s" : ""} ±3d
          </div>
        )}

        <div className="legend-key">
          <span style={{ color: CLASS_COLORS["UA-target"] }}>● UA target</span>
          <span style={{ color: CLASS_COLORS["Ukrainian"] }}>● Ukrainian</span>
          <span style={{ color: CLASS_COLORS["Russian"] }}>● Russian</span>
          <span style={{ color: CLASS_COLORS["SORM"] }}>● SORM</span>
          <span style={{ color: TAINTED_TRANSIT_COLOR }}>● transit on Ru path</span>
          <span style={{ color: CLASS_COLORS["Transit"] }}>● clean transit</span>
        </div>
      </div>
    </div>
  );
}
