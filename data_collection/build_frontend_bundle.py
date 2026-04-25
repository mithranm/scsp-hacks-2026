"""
Build the static JSON bundle the React frontend will consume.
Combines all collected CSVs into one self-contained data file.

Output:
  ../frontend/public/cyber_terrain.json   (created if frontend dir exists)
  ./frontend_bundle.json                  (always written here as backup)

Bundle shape:
  {
    "generated_at": "...",
    "cities": {
      "Kherson": {
         "asn": 21219, "lat": ..., "lon": ...,
         "events": [ ACLED rows ... ],
         "bgp_periods": { "baseline_2021": {...}, "kherson_dark_2022": {...}, ... },
         "as_paths_sample": [ ... ],
         "peer_timeline": [ {date, peers} ... ],
         "summary": { kinetic_event_count, max_bgp_updates_in_day, peer_count_drop, ... }
      },
      ...
    },
    "asns": { "174": {asn, holder, country, lat, lon, classification, ...}, ... },
    "periods": [ {label, description, date} ... ],
    "sorm_ases": { "8359": "MTS Russia", ... }
  }
"""

import os
import csv
import json
import datetime
from collections import defaultdict

DATA_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(DATA_DIR)

ACLED_CSV       = os.path.join(DATA_DIR, "acled_data", "acled_ukraine_events.csv")
BGP_CSV         = os.path.join(DATA_DIR, "bgp_paths_all_periods.csv")
RIPE_CSV        = os.path.join(DATA_DIR, "ripe_stat_routing_history.csv")
ASN_JSON        = os.path.join(DATA_DIR, "asn_geolocation.json")
CORR_TIMELINE   = os.path.join(DATA_DIR, "correlation_timeline.csv")
CORR_SUMMARY    = os.path.join(DATA_DIR, "correlation_summary.json")

LOCAL_OUT  = os.path.join(DATA_DIR, "frontend_bundle.json")
FRONTEND_OUT = os.path.join(ROOT_DIR, "frontend", "public", "cyber_terrain.json")

# Cities to include in the demo (matches BGP/ACLED targets)
CITIES = {
    "Kherson":    {"asn": 21219, "lat": 46.6354, "lon": 32.6169},
    "Mariupol":   {"asn": 6849,  "lat": 47.0971, "lon": 37.5434},
    "Kharkiv":    {"asn": 13188, "lat": 49.9935, "lon": 36.2304},
    "Zaporizhia": {"asn": 34700, "lat": 47.8388, "lon": 35.1396},
    "Donetsk":    {"asn": 48593, "lat": 48.0159, "lon": 37.8028},
    "Luhansk":    {"asn": 34867, "lat": 48.5740, "lon": 39.3078},
}

PERIODS = [
    {"label": "baseline_2021",       "description": "Pre-invasion baseline", "date": "2021-10-01"},
    {"label": "invasion_start_2022", "description": "Invasion start",        "date": "2022-02-24"},
    {"label": "kherson_dark_2022",   "description": "Kherson occupation",    "date": "2022-03-02"},
    {"label": "mariupol_siege_2022", "description": "Mariupol siege peak",   "date": "2022-04-15"},
]

SORM_ASES = {
    "8359":  "MTS Russia",
    "12389": "Rostelecom",
    "31257": "Vimpelcom/Beeline",
    "8641":  "Naukanet (FSB-linked)",
    "25159": "Rostelecom backbone",
    "20485": "TTNET Russia",
    "9049":  "JSC Ertetel (occupied territory)",
    "50010": "Miranda-Media (Crimea, post-2014)",
    "34879": "NetArt Group (Crimea reassigned)",
}


def load_csv(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return list(csv.DictReader(f))


def load_json(path, default=None):
    if not os.path.exists(path):
        return default if default is not None else {}
    with open(path) as f:
        return json.load(f)


def build_bundle():
    print("[build] loading source data")
    acled    = load_csv(ACLED_CSV)
    bgp      = load_csv(BGP_CSV)
    ripe     = load_csv(RIPE_CSV)
    corr_tl  = load_csv(CORR_TIMELINE)
    asn_geo  = load_json(ASN_JSON)
    summary  = load_json(CORR_SUMMARY)

    # Index BGP records by city + period
    bgp_by_city = defaultdict(lambda: defaultdict(list))
    for r in bgp:
        bgp_by_city[r["city"]][r["period"]].append(r)

    # Index ACLED by city
    acled_by_city = defaultdict(list)
    for e in acled:
        acled_by_city[e["city"]].append(e)

    # Build peer timeline per city (date → mean peers across all sub_prefixes)
    peer_timeline = defaultdict(lambda: defaultdict(list))
    for r in ripe:
        date = (r.get("starttime") or "")[:10]
        if not date:
            continue
        try:
            peer_timeline[r["city"]][date].append(float(r.get("full_peers_seeing") or 0))
        except (ValueError, TypeError):
            pass

    cities_out = {}
    for city, base in CITIES.items():
        # Aggregate peer timeline (one point per date with mean peer count)
        pt_raw = peer_timeline.get(city, {})
        pt = sorted(
            [{"date": d, "peers": round(sum(vals)/len(vals), 1)}
             for d, vals in pt_raw.items() if vals],
            key=lambda x: x["date"]
        )

        # BGP per period: count + sample paths + classification breakdown
        periods_out = {}
        for p in PERIODS:
            recs = bgp_by_city[city].get(p["label"], [])
            classifications = defaultdict(int)
            for r in recs:
                classifications[r.get("classification", "neutral")] += 1
            periods_out[p["label"]] = {
                "description":      p["description"],
                "date":             p["date"],
                "update_count":     len(recs),
                "classifications":  dict(classifications),
                "sample_paths":     [r["as_path"] for r in recs[:5]],
            }

        cities_out[city] = {
            "name":          city,
            "asn":           base["asn"],
            "lat":           base["lat"],
            "lon":           base["lon"],
            "events":        acled_by_city.get(city, []),
            "periods":       periods_out,
            "peer_timeline": pt,
            "summary":       summary.get(city, {}),
        }

    # Joint correlation timeline (cross-city)
    correlation_rows = corr_tl

    bundle = {
        "generated_at":       datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "cities":             cities_out,
        "asns":               asn_geo,
        "periods":            PERIODS,
        "sorm_ases":          SORM_ASES,
        "correlation":        correlation_rows,
        "stats": {
            "city_count":     len(cities_out),
            "asn_count":      len(asn_geo),
            "event_count":    len(acled),
            "bgp_records":    len(bgp),
            "ripe_entries":   len(ripe),
        },
    }
    return bundle


def main():
    print("=== Build frontend bundle ===\n")
    bundle = build_bundle()

    with open(LOCAL_OUT, "w") as f:
        json.dump(bundle, f, indent=2)
    print(f"[saved] {LOCAL_OUT}")

    if os.path.isdir(os.path.dirname(FRONTEND_OUT)):
        with open(FRONTEND_OUT, "w") as f:
            json.dump(bundle, f, indent=2)
        print(f"[saved] {FRONTEND_OUT}")
    else:
        print(f"[skip] frontend/ not yet scaffolded — bundle stored locally only")

    s = bundle["stats"]
    print(f"\n=== Bundle stats ===")
    print(f"  Cities:       {s['city_count']}")
    print(f"  ASNs:         {s['asn_count']}")
    print(f"  ACLED events: {s['event_count']}")
    print(f"  BGP records:  {s['bgp_records']}")
    print(f"  RIPE entries: {s['ripe_entries']}")

    print(f"\n=== Per-city quick view ===")
    for city, c in bundle["cities"].items():
        peer_pts = len(c["peer_timeline"])
        ev_count = len(c["events"])
        bgp_total = sum(p["update_count"] for p in c["periods"].values())
        print(f"  {city:<12} AS{c['asn']:<7} events={ev_count:<3} bgp_records={bgp_total:<4} peer_timeline_pts={peer_pts}")


if __name__ == "__main__":
    main()
