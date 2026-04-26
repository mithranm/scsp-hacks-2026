import type { GlobalScenario } from "../types";

interface Props {
  scenarios: Record<string, GlobalScenario>;
  selected: string;
  onSelect: (id: string) => void;
}

// Per-scenario flag pair representing the actual conflict participants.
// Adversary first, target/host second.
const SCENARIO_FLAGS: Record<string, string> = {
  russia_ukraine:    "🇷🇺🇺🇦",
  sudan_civil_war:   "🇸🇩",
  myanmar_civil_war: "🇲🇲",
  iran_yemen_houthi: "🇮🇷🇾🇪",
  china_taiwan:      "🇨🇳🇹🇼",
};

export function ScenarioPicker({ scenarios, selected, onSelect }: Props) {
  // Sort scenarios by max threat — most critical first
  const ordered = Object.entries(scenarios).sort(
    ([, a], [, b]) => b.totals.max_threat - a.totals.max_threat,
  );

  return (
    <div className="scenario-picker">
      <button
        className={`scenario-tab ${selected === "__overview__" ? "active" : ""} tone-neutral`}
        onClick={() => onSelect("__overview__")}
        title="World-map view of every conflict"
      >
        <span className="s-flag">🌐</span>
        <span className="s-name">Global Overview</span>
      </button>

      {ordered.map(([id, s]) => {
        const flag = SCENARIO_FLAGS[id] ?? "🌐";
        const isActive = id === selected;
        const hasCritical = s.totals.critical_cities > 0;
        const hasSevere   = s.totals.max_threat >= 60;
        const tone = hasCritical ? "danger" : hasSevere ? "warn" : "neutral";
        return (
          <button
            key={id}
            className={`scenario-tab ${isActive ? "active" : ""} tone-${tone}`}
            onClick={() => onSelect(id)}
            title={s.summary}
          >
            <span className="s-flag">{flag}</span>
            <span className="s-name">{s.name}</span>
            <span className={`s-score tone-${tone}`}>
              {s.totals.max_threat}
            </span>
          </button>
        );
      })}
    </div>
  );
}
