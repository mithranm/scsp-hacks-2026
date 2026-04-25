import type { City } from "../types";

interface Props {
  cities: Record<string, City>;
  selected: string;
  onSelect: (name: string) => void;
}

export function CityPicker({ cities, selected, onSelect }: Props) {
  const names = Object.keys(cities);

  return (
    <div className="city-picker">
      <h2>Cities</h2>
      <ul>
        {names.map((name) => {
          const city = cities[name];
          const totalUpdates = Object.values(city.periods).reduce(
            (sum, p) => sum + p.update_count,
            0
          );
          const peerDrop = city.summary.peer_count_drop ?? 0;
          return (
            <li
              key={name}
              className={selected === name ? "active" : ""}
              onClick={() => onSelect(name)}
            >
              <div className="city-name">{name}</div>
              <div className="city-meta">
                <span>AS{city.asn}</span>
                <span>{city.events.length} events</span>
                <span>{totalUpdates} BGP</span>
              </div>
              {peerDrop > 5 && (
                <div className="city-warning">⚠ peer drop {peerDrop.toFixed(1)}</div>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
