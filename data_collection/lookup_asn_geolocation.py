"""
ASN → Geolocation Lookup
Resolves every ASN that appears in our BGP data to (country, holder, coordinates)
so the frontend can plot AS nodes on a map.

Sources:
  - RIPE Stat as-overview API (no auth) — country code + holder name
  - Hardcoded country centroids — coordinates per ISO country code
  - Manual classification — UA / RU / SORM / Transit / Other

Output:
  asn_geolocation.csv  — One row per ASN with full metadata
  asn_geolocation.json — Same data, frontend-friendly indexed by ASN
"""

import os
import csv
import json
import time
import urllib.request
import urllib.error
from collections import defaultdict

DATA_DIR = os.path.dirname(os.path.abspath(__file__))
BGP_CSV  = os.path.join(DATA_DIR, "bgp_paths_all_periods.csv")
CACHE_FILE = os.path.join(DATA_DIR, "ripe_stat_cache", "asn_overview_cache.json")
OUT_CSV  = os.path.join(DATA_DIR, "asn_geolocation.csv")
OUT_JSON = os.path.join(DATA_DIR, "asn_geolocation.json")

# Country centroids (lat, lon) for visualisation. We jitter ASes within
# the same country so they don't all stack on a single point.
COUNTRY_CENTROIDS = {
    "UA": (49.0,  32.0,  "Ukraine"),
    "RU": (55.7,  37.6,  "Russia"),     # Moscow-biased, fine for our purposes
    "US": (39.8, -98.6,  "United States"),
    "DE": (51.2,  10.4,  "Germany"),
    "NL": (52.1,   5.3,  "Netherlands"),
    "GB": (54.4,  -2.4,  "United Kingdom"),
    "FR": (46.2,   2.2,  "France"),
    "PL": (51.9,  19.1,  "Poland"),
    "RO": (45.9,  24.9,  "Romania"),
    "HU": (47.1,  19.5,  "Hungary"),
    "CZ": (49.8,  15.5,  "Czech Republic"),
    "SK": (48.7,  19.7,  "Slovakia"),
    "AT": (47.5,  14.5,  "Austria"),
    "CH": (46.8,   8.2,  "Switzerland"),
    "BE": (50.5,   4.5,  "Belgium"),
    "SE": (60.1,  18.6,  "Sweden"),
    "FI": (61.9,  25.7,  "Finland"),
    "NO": (60.5,   8.5,  "Norway"),
    "DK": (56.3,   9.5,  "Denmark"),
    "IT": (41.9,  12.6,  "Italy"),
    "ES": (40.5,  -3.7,  "Spain"),
    "PT": (39.4,  -8.2,  "Portugal"),
    "IE": (53.4,  -8.2,  "Ireland"),
    "BG": (42.7,  25.5,  "Bulgaria"),
    "GR": (39.1,  21.8,  "Greece"),
    "TR": (38.9,  35.2,  "Turkey"),
    "BY": (53.7,  27.9,  "Belarus"),
    "MD": (47.4,  28.4,  "Moldova"),
    "LT": (55.2,  23.9,  "Lithuania"),
    "LV": (56.9,  24.6,  "Latvia"),
    "EE": (58.6,  25.0,  "Estonia"),
    "GE": (42.3,  43.4,  "Georgia"),
    "AM": (40.1,  45.0,  "Armenia"),
    "AZ": (40.1,  47.6,  "Azerbaijan"),
    "KZ": (48.0,  66.9,  "Kazakhstan"),
    "BR": (-14.2, -51.9, "Brazil"),
    "JP": (36.2, 138.3,  "Japan"),
    "CN": (35.9, 104.2,  "China"),
    "IN": (20.6,  78.9,  "India"),
    "CA": (56.1, -106.3, "Canada"),
    "AU": (-25.3, 133.8, "Australia"),
    "ZA": (-30.6,  22.9, "South Africa"),
    "KE": ( -0.0,  37.9, "Kenya"),
    "AE": ( 23.4,  53.8, "United Arab Emirates"),
    "SG": (  1.4, 103.8, "Singapore"),
    "HK": ( 22.3, 114.2, "Hong Kong"),
    "TW": ( 23.7, 121.0, "Taiwan"),
    "KR": ( 35.9, 127.8, "South Korea"),
    "IL": ( 31.0,  34.9, "Israel"),
    "MX": ( 23.6, -102.6, "Mexico"),
    "AR": (-38.4, -63.6, "Argentina"),
    # Russia-occupied / Crimean reassignments use RU centroid
}

# Russian ASes operating SORM legal-intercept infrastructure
SORM_ASES = {
    8359:  "MTS Russia",
    12389: "Rostelecom",
    31257: "Vimpelcom/Beeline",
    8641:  "Naukanet (FSB-linked)",
    25159: "Rostelecom backbone",
    20485: "TTNET Russia",
    9049:  "JSC Ertetel (occupied territory)",
    50010: "Miranda-Media (Crimea, post-2014)",
    34879: "NetArt Group (Crimea reassigned)",
}

# Ukrainian ASNs we deliberately track for the demo
UA_TARGET_ASES = {
    21219: "Kherson",
    6849:  "Mariupol",
    13188: "Kharkiv",
    34700: "Zaporizhia",
    48593: "Donetsk",
    34867: "Luhansk",
}

# Russian / Russia-CIS transit operators that RIR registration alone misclassifies.
# Sources: Doug Madory (Kentik), RIPE NCC research, public BGP-hijack analyses.
# These ASes route the bulk of Russia<->Ukraine traffic and operate primarily
# under Russian operational control regardless of legal registration country.
RUSSIAN_TRANSIT_OVERRIDE = {
    9002:  "RETN — Russia-CIS backbone (op. HQ St. Petersburg)",
    3216:  "SOVAM-AS / Vimpelcom subsidiary (Russia)",
    2854:  "RTComm.RU (Russia)",
    20764: "RASCOM — Russia-CIS transit",
    29076: "Citytelecom Moscow (Russia)",
    35598: "INETCOM-AS (Russia)",
    8732:  "Comcor / Akado (Moscow)",
    8997:  "North-West Telecom (Russia, now Rostelecom-NW)",
    13238: "Yandex (Russia)",
}


# ---------------------------------------------------------------------------
# RIPE Stat lookup
# ---------------------------------------------------------------------------

def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE) as f:
            return json.load(f)
    return {}


def save_cache(cache):
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


def fetch_as_overview(asn, cache):
    """Query RIPE Stat for ASN holder + country."""
    key = str(asn)
    if key in cache:
        return cache[key]

    url = f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CyberTerrainMapper/1.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.load(r)
        d = data.get("data", {})
        result = {
            "holder":  d.get("holder", "") or "",
            "block":   d.get("block", {}).get("name", "") if isinstance(d.get("block"), dict) else "",
            "type":    d.get("type", "") or "",
            "announced": d.get("announced", False),
        }
        cache[key] = result
        time.sleep(0.15)  # gentle rate-limit
        return result
    except Exception as e:
        print(f"  [err] AS{asn}: {e}")
        cache[key] = {"holder": "", "block": "", "type": "", "announced": False}
        return cache[key]


def fetch_country(asn, cache):
    """Use RIPE Stat geoloc/whois to derive country code."""
    key = f"country_{asn}"
    if key in cache:
        return cache[key]

    url = f"https://stat.ripe.net/data/rir-stats-country/data.json?resource=AS{asn}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CyberTerrainMapper/1.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.load(r)
        located = data.get("data", {}).get("located_resources", [])
        if located:
            cc = located[0].get("location", "")
            cache[key] = cc
            time.sleep(0.15)
            return cc
    except Exception as e:
        print(f"  [country-err] AS{asn}: {e}")

    cache[key] = ""
    return ""


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def classify_asn(asn, country):
    if asn in SORM_ASES:
        return "SORM"
    if asn in UA_TARGET_ASES:
        return "UA-target"
    if asn in RUSSIAN_TRANSIT_OVERRIDE:
        return "Russian"     # override RIR registration for known Russia-CIS transit
    if country == "RU":
        return "Russian"
    if country == "UA":
        return "Ukrainian"
    if country == "BY":
        return "Belarusian"
    return "Transit"


def jitter_coordinates(lat, lon, asn):
    """Spread ASes around their country centroid using ASN as deterministic seed."""
    h = hash(("jitter", asn))
    dx = ((h % 200) - 100) / 50.0           # ±2 deg
    dy = (((h >> 8) % 200) - 100) / 50.0    # ±2 deg
    return round(lat + dy, 4), round(lon + dx, 4)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def collect_unique_asns():
    """Walk the BGP CSV and collect every ASN we've seen in any AS path."""
    asns = set()
    with open(BGP_CSV) as f:
        for r in csv.DictReader(f):
            for a in r["as_path"].split(" → "):
                a = a.strip()
                if a.isdigit():
                    asns.add(int(a))
    return sorted(asns)


def main():
    print("=== ASN Geolocation Lookup ===\n")

    asns = collect_unique_asns()
    print(f"[scan] {len(asns)} unique ASNs found in BGP data")

    cache = load_cache()
    rows = []

    for i, asn in enumerate(asns, 1):
        if i % 10 == 0 or i == len(asns):
            print(f"  [progress] {i}/{len(asns)}")

        overview = fetch_as_overview(asn, cache)
        country = fetch_country(asn, cache)

        # For known Russia-CIS transit operators, force geolocation to Russia
        # regardless of RIR registration (RETN is "GB" on paper, runs from RU).
        effective_country = "RU" if asn in RUSSIAN_TRANSIT_OVERRIDE else country
        centroid = COUNTRY_CENTROIDS.get(effective_country, (0, 0, "Unknown"))
        base_lat, base_lon, country_name = centroid
        lat, lon = jitter_coordinates(base_lat, base_lon, asn)

        classification = classify_asn(asn, country)
        sorm_role = SORM_ASES.get(asn, "")
        ua_city   = UA_TARGET_ASES.get(asn, "")

        rows.append({
            "asn":            asn,
            "holder":         overview.get("holder", ""),
            "type":           overview.get("type", ""),
            "country":        country,
            "country_name":   country_name,
            "lat":            lat,
            "lon":            lon,
            "classification": classification,
            "sorm_role":      sorm_role,
            "ua_city":        ua_city,
        })

    save_cache(cache)

    # CSV output
    with open(OUT_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"\n[saved] asn_geolocation.csv ({len(rows)} ASNs)")

    # JSON output indexed by ASN (frontend convenience)
    indexed = {str(r["asn"]): r for r in rows}
    with open(OUT_JSON, "w") as f:
        json.dump(indexed, f, indent=2)
    print(f"[saved] asn_geolocation.json")

    # Classification summary
    counts = defaultdict(int)
    for r in rows:
        counts[r["classification"]] += 1
    print("\n=== Classification distribution ===")
    for cls, n in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {cls:<14} {n}")

    # Highlight: any SORM hits?
    sorm_hits = [r for r in rows if r["classification"] == "SORM"]
    if sorm_hits:
        print(f"\n⚠  SORM-capable ASes found in transit paths:")
        for r in sorm_hits:
            print(f"    AS{r['asn']:<8}  {r['sorm_role']}  ({r['holder']})")
    else:
        print(f"\n   No SORM ASes in transit paths from this collection window.")
        print(f"   (Expected — RIPE NCC's rrc15/rrc16 see neutral transit views.)")

    # Country breakdown
    country_counts = defaultdict(int)
    for r in rows:
        country_counts[r["country"] or "??"] += 1
    print("\n=== Top 10 countries ===")
    for cc, n in sorted(country_counts.items(), key=lambda x: -x[1])[:10]:
        name = COUNTRY_CENTROIDS.get(cc, (0, 0, cc))[2]
        print(f"  {cc:<4} {name:<22} {n} ASes")


if __name__ == "__main__":
    main()
