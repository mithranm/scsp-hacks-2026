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
CHOKEPOINTS     = os.path.join(DATA_DIR, "chokepoints.json")
SCENARIO_TW     = os.path.join(DATA_DIR, "scenario_taiwan.json")
SCENARIOS_DIR   = os.path.join(DATA_DIR, "scenarios_data")

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

ADVERSARIAL_CLASSIFICATIONS = {"Russian", "SORM", "Belarusian"}

# ── GenAI Fingerprinting model performance (from ensemble training results) ──
GENAI_FINGERPRINTING = {
    "model_name": "Ensemble (CNN-LSTM + Gradient Boosting stacking)",
    "accuracy": 0.894,
    "f1": 0.893,
    "accuracy_std": 0.028,
    "folds": 5,
    "dataset_size": 179,
    "features_count": 233,
    "detectable_platforms": ["ChatGPT", "Gemini", "Grok", "Perplexity"],
    "modalities": ["text", "audio", "video"],
    "top_features": [
        {"name": "burst_mean_size",  "description": "Average packets per burst"},
        {"name": "iat_p95",          "description": "95th percentile inter-arrival time"},
        {"name": "unique_dst_ips",   "description": "Distinct servers contacted"},
        {"name": "unique_connections","description": "Flow count diversity"},
        {"name": "bwd_iat_p95",      "description": "Server-side IAT 95th percentile"},
    ],
    "description": (
        "Machine learning system that detects GenAI application traffic from network "
        "packet captures. When traffic traverses adversary-controlled infrastructure "
        "with DPI capability, this fingerprinting proves AI tool usage is identifiable "
        "and targetable — not just theoretically intercepted."
    ),
}

# Per-scenario adversary DPI/intercept capability assessment
ADVERSARY_DPI_CAPABILITY = {
    "russia_ukraine":    {"has_dpi": True,  "system": "SORM/SORM-2", "capability_score": 95,
                          "notes": "Legally mandated DPI on all Russian carriers; FSB real-time access"},
    "china_taiwan":      {"has_dpi": True,  "system": "Great Firewall / MSS",  "capability_score": 98,
                          "notes": "Most advanced national DPI; already blocks GenAI platforms"},
    "myanmar_civil_war": {"has_dpi": True,  "system": "Junta telecom control", "capability_score": 60,
                          "notes": "Limited but growing DPI via Chinese-supplied equipment"},
    "sudan_civil_war":   {"has_dpi": False, "system": "Fragmented", "capability_score": 25,
                          "notes": "Limited infrastructure; DPI capability degraded by conflict"},
    "iran_yemen_houthi": {"has_dpi": True,  "system": "TCI/DPI filtering",    "capability_score": 85,
                          "notes": "Iran operates national-level DPI; extends to proxy networks"},
}


def compute_genai_exposure(city_threat, scenario_id):
    """
    Compute GenAI traffic exposure risk for a city based on:
    1. Does traffic route through adversary? (adversarial_route component)
    2. Does adversary have DPI capability? (per-scenario)
    3. Can DPI fingerprint GenAI? (proven at 89.4% accuracy)
    """
    components = city_threat.get("components", {})
    adv_route = components.get("russian_route", 0)
    intercept = components.get("sorm_exposure", 0)

    dpi = ADVERSARY_DPI_CAPABILITY.get(scenario_id, {})
    dpi_score = dpi.get("capability_score", 0) / 100.0

    # Exposure = routing_exposure * dpi_capability * fingerprint_accuracy
    routing_exposure = min(1.0, (adv_route / 25.0 + intercept / 10.0) / 2.0)
    raw = routing_exposure * dpi_score * GENAI_FINGERPRINTING["accuracy"] * 100

    score = round(min(100, raw))
    if score >= 70:
        level = "critical"
    elif score >= 45:
        level = "severe"
    elif score >= 20:
        level = "elevated"
    else:
        level = "nominal"

    threat_vectors = []
    if dpi.get("has_dpi"):
        threat_vectors.append("AI traffic identification via DPI")
    if adv_route > 10:
        threat_vectors.append("Selective GenAI service blocking")
    if intercept > 0:
        threat_vectors.append("AI query content surveillance")
    if adv_route > 0:
        threat_vectors.append("AI-assisted planning detection")

    return {
        "score": score,
        "level": level,
        "routing_exposure": round(routing_exposure, 2),
        "adversary_dpi": dpi.get("has_dpi", False),
        "dpi_system": dpi.get("system", "Unknown"),
        "dpi_capability_score": dpi.get("capability_score", 0),
        "fingerprint_accuracy": GENAI_FINGERPRINTING["accuracy"],
        "threat_vectors": threat_vectors,
    }


def compute_threat_score(city_data, asn_geo, sorm_aset):
    """
    Cyber-Terrain Threat Score (0-100).

    Composite of four sub-scores, each weighted to sum to 100:
      blackout_subscore       max 40 pts — communications-blackout signal
      instability_subscore    max 25 pts — BGP UPDATE volume (routing flux)
      russian_route_subscore  max 25 pts — observed Russian-routed paths
      sorm_exposure_subscore  max 10 pts — SORM-capable ASes in any path

    Levels:
      0–29   nominal     city operating normally
      30–59  elevated    instability or partial degradation observed
      60–79  severe      sustained degradation or adversarial routing
      80–100 critical    city effectively cyber-isolated or surveilled
    """
    summary = city_data.get("summary", {})
    peer_drop = summary.get("peer_count_drop") or 0
    max_bgp_per_day = summary.get("max_bgp_updates_in_day") or 0

    # 1. Blackout: peer count drop ≥ 300 = full 40 pts (Mariupol-tier)
    blackout = min(40, (peer_drop / 300.0) * 40)

    # 2. Instability: 200+ updates/hour-window = full 25 pts
    instability = min(25, (max_bgp_per_day / 200.0) * 25)

    # 3. Russian-routed paths: scan every period's sample paths
    russian_paths_count = 0
    sorm_ases_seen = set()
    for period_data in city_data.get("periods", {}).values():
        for path in period_data.get("sample_paths", []):
            hops = [h.strip() for h in path.split("→") if h.strip().isdigit()]
            adv_hop = False
            for h in hops:
                if h in sorm_aset:
                    sorm_ases_seen.add(h)
                    adv_hop = True
                else:
                    a = asn_geo.get(h)
                    if a and a.get("classification") in ADVERSARIAL_CLASSIFICATIONS:
                        adv_hop = True
            if adv_hop:
                russian_paths_count += 1

    # Each Russian-routed path adds 5 pts, capped at 25
    russian_route = min(25, russian_paths_count * 5)

    # 4. SORM exposure: each unique SORM AS observed adds 5 pts, capped at 10
    sorm_exposure = min(10, len(sorm_ases_seen) * 5)

    total = round(blackout + instability + russian_route + sorm_exposure)
    if total >= 80:
        level = "critical"
    elif total >= 60:
        level = "severe"
    elif total >= 30:
        level = "elevated"
    else:
        level = "nominal"

    return {
        "score":    total,
        "level":    level,
        "components": {
            "blackout":       round(blackout, 1),
            "instability":    round(instability, 1),
            "russian_route":  round(russian_route, 1),
            "sorm_exposure":  round(sorm_exposure, 1),
        },
        "evidence": {
            "peer_count_drop":         peer_drop,
            "max_bgp_updates_in_day":  max_bgp_per_day,
            "russian_paths_count":     russian_paths_count,
            "sorm_ases_observed":      sorted(sorm_ases_seen),
        },
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

    # Index ACLED by city. With the live API we can pull 100K+ events; downsample
    # to a representative subset per city to keep the frontend bundle small.
    # Strategy: top 80 by fatalities + 100 most recent + 80 temporally-distributed.
    acled_by_city_all = defaultdict(list)
    for e in acled:
        acled_by_city_all[e["city"]].append(e)

    def _ev_int(e, k):
        try: return int(e.get(k) or 0)
        except (ValueError, TypeError): return 0

    acled_by_city = {}
    for city, events_list in acled_by_city_all.items():
        events_list.sort(key=lambda e: e.get("event_date", ""))
        n = len(events_list)
        if n <= 300:
            acled_by_city[city] = events_list
            continue
        # 80 highest-fatality events
        top_fatal = sorted(events_list, key=lambda e: -_ev_int(e, "fatalities"))[:80]
        # 100 most recent
        recent = events_list[-100:]
        # 80 evenly spaced across the timeline
        step = max(1, n // 80)
        spaced = events_list[::step][:80]
        # Dedupe by (date, location, event_type)
        seen = set()
        keep = []
        for e in (top_fatal + recent + spaced):
            key = (e.get("event_date"), e.get("location"), e.get("event_type"))
            if key in seen: continue
            seen.add(key)
            keep.append(e)
        keep.sort(key=lambda e: e.get("event_date", ""))
        acled_by_city[city] = keep
        print(f"  [downsample] {city}: {n} → {len(keep)} events for bundle")

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

        city_record = {
            "name":          city,
            "asn":           base["asn"],
            "lat":           base["lat"],
            "lon":           base["lon"],
            "events":        acled_by_city.get(city, []),
            "periods":       periods_out,
            "peer_timeline": pt,
            "summary":       summary.get(city, {}),
        }
        # Threat score depends on summary + periods being populated
        city_record["threat"] = compute_threat_score(
            city_record, asn_geo, set(SORM_ASES.keys())
        )
        cities_out[city] = city_record

    # Joint correlation timeline (cross-city) — cap at 500 most-significant rows
    # to keep the bundle small. Sort by BGP volume descending, keep top.
    def _corr_score(r):
        try: return int(r.get("bgp_updates_in_window") or 0)
        except (ValueError, TypeError): return 0
    correlation_rows = sorted(corr_tl, key=lambda r: -_corr_score(r))[:500]
    correlation_rows.sort(key=lambda r: r.get("date", ""))

    chokepoints = load_json(CHOKEPOINTS, default={})
    scenario_tw = load_json(SCENARIO_TW, default={})

    # Load all global scenarios from build_global_scenarios output
    global_scenarios = {}
    if os.path.isdir(SCENARIOS_DIR):
        for fname in sorted(os.listdir(SCENARIOS_DIR)):
            if fname == "_index.json" or not fname.endswith(".json"):
                continue
            sid = fname[:-5]
            with open(os.path.join(SCENARIOS_DIR, fname)) as f:
                global_scenarios[sid] = json.load(f)

    # Country centroid lookup so we can plot adversarial ASes from any scenario
    # at their country's location (same approach as lookup_asn_geolocation.py)
    COUNTRY_FOR_AS = {
        # Russian SORM/transit
        "8359":  ("RU", "Russia"),       "12389": ("RU", "Russia"),
        "31257": ("RU", "Russia"),       "8641":  ("RU", "Russia"),
        "25159": ("RU", "Russia"),       "20485": ("RU", "Russia"),
        "9049":  ("RU", "Russia"),       "50010": ("RU", "Russia"),
        "34879": ("RU", "Russia"),       "9002":  ("RU", "Russia"),
        # Israeli carriers
        "8551":  ("IL", "Israel"),       "1680":  ("IL", "Israel"),
        "12849": ("IL", "Israel"),
        # Egyptian/UAE transit (Sudan adv list)
        "36992": ("EG", "Egypt"),        "5384":  ("AE", "United Arab Emirates"),
        # Myanmar junta
        "9988":   ("MM", "Myanmar"),     "136255": ("MM", "Myanmar"),
        # Iranian state
        "12880": ("IR", "Iran"),         "44244": ("IR", "Iran"),
        "58224": ("IR", "Iran"),         "16735": ("IR", "Iran"),
        # PRC state operators
        "4134":  ("CN", "China"),        "4837":  ("CN", "China"),
        "9808":  ("CN", "China"),        "4538":  ("CN", "China"),
        "7497":  ("CN", "China"),        "9929":  ("CN", "China"),
        "58453": ("CN", "China"),        "23724": ("CN", "China"),
    }
    COUNTRY_CENTROID = {
        "RU": (55.7,  37.6),  "IL": (31.0,  34.9),  "EG": (26.8,  30.8),
        "AE": (23.4,  53.8),  "MM": (21.9,  95.9),  "IR": (32.4,  53.6),
        "CN": (35.9, 104.2),  "BR": (-14.2, -51.9), "DE": (51.2,  10.4),
        "US": (39.8, -98.6),  "GB": (54.4,  -2.4),  "FR": (46.2,   2.2),
        "NL": (52.1,   5.3),  "SE": (60.1,  18.6),  "PL": (51.9,  19.1),
        "UA": (49.0,  32.0),  "BY": (53.7,  27.9),  "TR": (38.9,  35.2),
        "JP": (36.2, 138.3),  "HK": (22.3, 114.2),  "SG": ( 1.4, 103.8),
        "TW": (23.7, 121.0),  "KR": (35.9, 127.8),  "IN": (20.6,  78.9),
        "TH": (15.9, 100.9),  "VN": (14.1, 108.3),  "MY": ( 4.2, 101.9),
        "PK": (30.4,  69.3),  "BD": (23.7,  90.4),  "PH": (12.9, 121.8),
        "ID": (-0.8, 113.9),  "AU": (-25.3, 133.8),
        "SA": (23.9,  45.1),  "KW": (29.3,  47.5),  "QA": (25.4,  51.2),
        "OM": (21.5,  55.9),  "YE": (15.6,  48.5),  "IQ": (33.2,  43.7),
        "JO": (30.6,  36.2),  "LB": (33.9,  35.5),  "SY": (34.8,  38.9),
        "PS": (31.9,  35.3),  "AF": (33.9,  67.7),
        "ET": ( 9.1,  40.5),  "KE": ( 0.0,  37.9),  "NG": ( 9.1,   8.7),
        "ZA": (-30.6,  22.9), "MA": (31.8,  -7.1),  "DZ": (28.0,   1.6),
        "TN": (33.9,   9.6),  "LY": (26.3,  17.2),  "DJ": (11.8,  42.6),
        "ER": (15.2,  39.8),  "CD": (-4.0,  21.8),  "TD": (15.5,  18.7),
        "SS": ( 6.9,  31.3),  "CF": ( 6.6,  20.9),
        "ES": (40.5,  -3.7),  "IT": (41.9,  12.6),  "AT": (47.5,  14.5),
        "BE": (50.5,   4.5),  "CH": (46.8,   8.2),  "DK": (56.3,   9.5),
        "NO": (60.5,   8.5),  "FI": (61.9,  25.7),  "IE": (53.4,  -8.2),
        "PT": (39.4,  -8.2),  "GR": (39.1,  21.8),  "RO": (45.9,  24.9),
        "HU": (47.1,  19.5),  "CZ": (49.8,  15.5),  "SK": (48.7,  19.7),
        "BG": (42.7,  25.5),  "MD": (47.4,  28.4),  "EE": (58.6,  25.0),
        "LV": (56.9,  24.6),  "LT": (55.2,  23.9),  "GE": (42.3,  43.4),
        "AM": (40.1,  45.0),  "AZ": (40.1,  47.6),  "KZ": (48.0,  66.9),
        "MX": (23.6, -102.6), "CA": (56.1, -106.3), "AR": (-38.4, -63.6),
    }

    # Augment asn_geo with every scenario's adversarial ASes + target ASes
    import hashlib
    def jitter(asn, base_lat, base_lon):
        h = int(hashlib.md5(str(asn).encode()).hexdigest()[:8], 16)
        dx = ((h % 200) - 100) / 50.0
        dy = (((h >> 8) % 200) - 100) / 50.0
        return round(base_lat + dy, 4), round(base_lon + dx, 4)

    # Country/holder lookup pulled from RIPE Stat for every neighbour AS
    # (build_global_scenarios.py persists these on each city's top_neighbours)
    for sid, sc in global_scenarios.items():
        # Top neighbour ASes (transit / carrier ASes that the city directly peers)
        for c in sc.get("cities", []):
            for n in c.get("top_neighbours", []):
                asn_str = str(n["asn"])
                if asn_str in asn_geo:
                    continue
                cc   = n.get("country", "")
                lat, lon = COUNTRY_CENTROID.get(cc, (0, 0))
                if lat or lon:
                    lat, lon = jitter(asn_str, lat, lon)
                if n.get("is_adversary"):
                    classification = "Russian"   # SCENARIO-context: adversary
                else:
                    classification = "Transit"
                asn_geo[asn_str] = {
                    "asn":            n["asn"],
                    "holder":         n.get("holder", ""),
                    "type":           "",
                    "country":        cc,
                    "country_name":   cc,
                    "lat":            lat,
                    "lon":            lon,
                    "classification": classification,
                    "sorm_role":      "",
                    "ua_city":        "",
                    "v4_peers":       n.get("v4_peers", 0),
                }

        # Adversarial ASes (some may overlap with top neighbours; existing entries kept)
        for asn_str, info in sc.get("adversarial_ases", {}).items():
            if asn_str not in asn_geo:
                cc, name = COUNTRY_FOR_AS.get(asn_str, ("", "Unknown"))
                lat, lon = COUNTRY_CENTROID.get(cc, (0, 0))
                if lat or lon:
                    lat, lon = jitter(asn_str, lat, lon)
                asn_geo[asn_str] = {
                    "asn":            int(asn_str),
                    "holder":         info["operator"],
                    "type":           "",
                    "country":        cc,
                    "country_name":   name,
                    "lat":            lat,
                    "lon":            lon,
                    "classification": "Russian"   if cc == "RU"
                                       else "Belarusian" if cc == "BY"
                                       else "SORM"  if "intercept" in info["role"].lower()
                                                       or "DPI" in info["role"]
                                       else "Russian",
                    "sorm_role":      info["role"],
                    "ua_city":        "",
                }
        # Target ASes (cities)
        for c in sc.get("cities", []):
            asn_str = str(c["asn"])
            if asn_str not in asn_geo:
                asn_geo[asn_str] = {
                    "asn":            c["asn"],
                    "holder":         c["city"] + " ISP",
                    "type":           "",
                    "country":        "",
                    "country_name":   "",
                    "lat":            c["lat"],
                    "lon":            c["lon"],
                    "classification": "UA-target",
                    "sorm_role":      "",
                    "ua_city":        c["city"],
                }

    # Normalize every scenario city so it has the same fields as legacy City type.
    # This lets the same React components render any scenario.
    from mitigations import recommend_for_city
    for sid, sc in global_scenarios.items():
        for c in sc.get("cities", []):
            c["name"] = c.get("city")           # CityPicker uses .name
            # Ensure all expected fields exist
            c.setdefault("periods",       {})
            c.setdefault("peer_timeline", [])
            c.setdefault("events",        [])
            c.setdefault("summary",       {})
            # Compute GenAI exposure per city
            c["genai_exposure"] = compute_genai_exposure(
                c.get("threat", {}), sid
            )
            # Recompute mitigations to pick up latest playbook (incl. GenAI defenses)
            c["mitigations"] = recommend_for_city(c)

    # Merge existing detailed Ukraine BGP/threat data into the russia_ukraine scenario
    if "russia_ukraine" in global_scenarios:
        ru = global_scenarios["russia_ukraine"]
        # Build a {city_name: detailed_city_record} from the legacy cities_out
        for sc_city in ru["cities"]:
            legacy = cities_out.get(sc_city["city"])
            if legacy:
                # Carry over the rich threat score (computed from MRT data)
                sc_city["threat"]   = legacy["threat"]
                sc_city["periods"]  = legacy["periods"]
                sc_city["events"]   = legacy["events"]
                sc_city["peer_timeline"] = legacy["peer_timeline"]
                sc_city["summary"]  = legacy["summary"]
                # Recompute mitigations against the richer threat profile
                from mitigations import recommend_for_city
                sc_city["mitigations"] = recommend_for_city(sc_city)
        # Recompute scenario totals after merge
        ru["totals"]["max_threat"]      = max((c["threat"]["score"]
                                               for c in ru["cities"]), default=0)
        ru["totals"]["mean_threat"]     = round(sum(c["threat"]["score"]
                                               for c in ru["cities"]) / max(1, len(ru["cities"])))
        ru["totals"]["exposed_cities"]  = sum(1 for c in ru["cities"]
                                              if c["threat"]["score"] >= 30)
        ru["totals"]["critical_cities"] = sum(1 for c in ru["cities"]
                                              if c["threat"]["score"] >= 60)
        ru["chokepoints"] = chokepoints  # Ukraine's BGP-graph centrality lives here
        # Recompute GenAI exposure now that rich MRT-based threat data is in place
        for sc_city in ru["cities"]:
            sc_city["genai_exposure"] = compute_genai_exposure(
                sc_city.get("threat", {}), "russia_ukraine"
            )

    bundle = {
        "generated_at":       datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "cities":             cities_out,         # legacy — Ukraine-specific
        "asns":               asn_geo,
        "periods":            PERIODS,
        "sorm_ases":          SORM_ASES,
        "correlation":        correlation_rows,
        "chokepoints":        chokepoints,
        "global_scenarios":   global_scenarios,   # NEW — every scenario
        "default_scenario":   "russia_ukraine",
        "genai_fingerprinting": GENAI_FINGERPRINTING,
        "scenarios": {
            "taiwan_china":   scenario_tw,        # legacy single-scenario panel
        },
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
