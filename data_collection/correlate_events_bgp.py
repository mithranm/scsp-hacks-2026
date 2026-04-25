"""
Correlate ACLED kinetic events with BGP routing changes.
For each city, computes:
  - Conflict events on a date
  - BGP UPDATE volume (proxy for routing instability) on/around that date
  - Peer visibility (from RIPE Stat) for that city's prefixes around that date
  - Time delta between kinetic event and BGP signal

Output:
  correlation_timeline.csv     — Joint timeline: kinetic + cyber, one row per (city, date)
  correlation_summary.json     — Per-city aggregate (events, BGP volume, peer trend)
"""

import os
import csv
import json
import datetime
from collections import defaultdict

DATA_DIR = os.path.dirname(os.path.abspath(__file__))
ACLED_CSV = os.path.join(DATA_DIR, "acled_data", "acled_ukraine_events.csv")
BGP_CSV   = os.path.join(DATA_DIR, "bgp_paths_all_periods.csv")
RIPE_CSV  = os.path.join(DATA_DIR, "ripe_stat_routing_history.csv")

OUT_TIMELINE = os.path.join(DATA_DIR, "correlation_timeline.csv")
OUT_SUMMARY  = os.path.join(DATA_DIR, "correlation_summary.json")


def load_csv(path):
    if not os.path.exists(path):
        print(f"[warn] missing {path}")
        return []
    with open(path) as f:
        return list(csv.DictReader(f))


def parse_date(s):
    """Accept 'YYYY-MM-DD' or 'YYYY-MM-DDTHH:MM:SS'."""
    if not s:
        return None
    try:
        return datetime.datetime.fromisoformat(s.split("T")[0]).date()
    except Exception:
        try:
            return datetime.datetime.strptime(s[:10], "%Y-%m-%d").date()
        except Exception:
            return None


def main():
    print("=== Correlate ACLED ↔ BGP ===\n")

    acled = load_csv(ACLED_CSV)
    bgp   = load_csv(BGP_CSV)
    ripe  = load_csv(RIPE_CSV)

    print(f"[load] ACLED: {len(acled)} events")
    print(f"[load] BGP:   {len(bgp)} update records")
    print(f"[load] RIPE:  {len(ripe)} timeline entries")

    # ----------------------------------------------------------------
    # Index BGP records by (city, date)
    # ----------------------------------------------------------------
    bgp_by_city_date = defaultdict(list)
    for r in bgp:
        d = parse_date(r.get("datetime", ""))
        if d:
            bgp_by_city_date[(r["city"], d)].append(r)

    # ----------------------------------------------------------------
    # Index RIPE Stat peer-counts by (city, date)
    # ----------------------------------------------------------------
    ripe_by_city_date = defaultdict(list)
    for r in ripe:
        d = parse_date(r.get("starttime", ""))
        if d:
            try:
                peers = float(r.get("full_peers_seeing") or 0)
            except (ValueError, TypeError):
                peers = 0
            ripe_by_city_date[(r["city"], d)].append(peers)

    # ----------------------------------------------------------------
    # Build joint timeline rows from ACLED
    # ----------------------------------------------------------------
    timeline = []
    for e in acled:
        city = e.get("city", "")
        d = parse_date(e.get("event_date", ""))
        if not d:
            continue

        # Find BGP volume in ±1 day window
        bgp_window_count = 0
        sample_paths = []
        for delta in (-1, 0, 1):
            d2 = d + datetime.timedelta(days=delta)
            recs = bgp_by_city_date.get((city, d2), [])
            bgp_window_count += len(recs)
            for r in recs[:2]:
                sample_paths.append(r.get("as_path", ""))

        # Peer count snapshot (mean over ±3 days)
        peer_samples = []
        for delta in range(-3, 4):
            d2 = d + datetime.timedelta(days=delta)
            peer_samples.extend(ripe_by_city_date.get((city, d2), []))
        peer_mean = round(sum(peer_samples) / len(peer_samples), 1) if peer_samples else None

        timeline.append({
            "date":           d.isoformat(),
            "city":           city,
            "kinetic_event":  f"{e.get('event_type','')}: {e.get('sub_event','')}",
            "actor1":         e.get("actor1", ""),
            "fatalities":     e.get("fatalities", ""),
            "notes":          e.get("notes", "")[:140],
            "bgp_updates_in_window": bgp_window_count,
            "ripe_peers_mean":      peer_mean if peer_mean is not None else "",
            "sample_as_paths":      " || ".join(sample_paths[:2]),
        })

    timeline.sort(key=lambda r: (r["date"], r["city"]))

    # ----------------------------------------------------------------
    # Per-city aggregates
    # ----------------------------------------------------------------
    summary = {}
    for city in {r["city"] for r in timeline}:
        rows = [r for r in timeline if r["city"] == city]
        peer_vals = [r["ripe_peers_mean"] for r in rows if r["ripe_peers_mean"] != ""]
        bgp_vals  = [r["bgp_updates_in_window"] for r in rows]
        summary[city] = {
            "kinetic_event_count":   len(rows),
            "first_event":           rows[0]["date"] if rows else None,
            "last_event":            rows[-1]["date"] if rows else None,
            "max_bgp_updates_in_day": max(bgp_vals) if bgp_vals else 0,
            "peer_count_min":        min(peer_vals) if peer_vals else None,
            "peer_count_max":        max(peer_vals) if peer_vals else None,
            "peer_count_drop":       (
                round(max(peer_vals) - min(peer_vals), 1)
                if peer_vals and len(peer_vals) > 1 else 0
            ),
        }

    # ----------------------------------------------------------------
    # Write outputs
    # ----------------------------------------------------------------
    with open(OUT_TIMELINE, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(timeline[0].keys()) if timeline else [])
        w.writeheader()
        w.writerows(timeline)
    print(f"\n[saved] correlation_timeline.csv ({len(timeline)} joint rows)")

    with open(OUT_SUMMARY, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"[saved] correlation_summary.json")

    # ----------------------------------------------------------------
    # Print correlation report
    # ----------------------------------------------------------------
    print("\n=== Joint timeline (kinetic + cyber) ===")
    print(f"{'Date':<12} {'City':<11} {'Kinetic event':<48} {'BGP updates':>11} {'Peers':>8}")
    print("-" * 100)
    for r in timeline:
        ev = r["kinetic_event"][:46]
        peers = r["ripe_peers_mean"] if r["ripe_peers_mean"] != "" else "—"
        print(f"{r['date']:<12} {r['city']:<11} {ev:<48} {r['bgp_updates_in_window']:>11} {str(peers):>8}")

    print("\n=== Per-city summary ===")
    for city, s in summary.items():
        print(f"\n  {city}")
        print(f"    Events:                  {s['kinetic_event_count']}")
        print(f"    Max BGP updates / day:   {s['max_bgp_updates_in_day']}")
        if s['peer_count_max']:
            print(f"    Peer count range:        {s['peer_count_min']} → {s['peer_count_max']}")
            print(f"    Peer drop:               {s['peer_count_drop']}")


if __name__ == "__main__":
    main()
