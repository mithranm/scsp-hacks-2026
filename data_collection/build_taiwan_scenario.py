"""
Domestic-relevance scenario: Taiwan ↔ China BGP cyber-terrain.

Demonstrates the same methodology applied to a scenario US policymakers,
NSA/CISA/State Dept analysts, and DoD wargames care about:

  Could China weaponize BGP routing the way Russia did against Ukraine?
  How exposed are Taiwanese ASes to Chinese-controlled transit?
  What undersea-cable/AS chokepoints would matter in a contingency?

This script reuses the same RIPE Stat APIs and classification logic, with
a Taiwan/China target list and adversarial overrides for known PRC
state-operated transit (China Telecom AS4134, China Unicom AS4837, CSTNET
AS7497, etc.).

Outputs into the bundle as bundle.scenarios["taiwan_china"].
"""

import os
import csv
import json
import time
import urllib.request
import urllib.parse

DATA_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_JSON = os.path.join(DATA_DIR, "scenario_taiwan.json")
CACHE    = os.path.join(DATA_DIR, "ripe_stat_cache", "taiwan_routing.json")

# Taiwanese target ASes — major operators for the cyber-terrain analog
TW_TARGETS = [
    {"asn": 3462,  "city": "Taipei",      "name": "HiNet (Chunghwa Telecom)",
     "lat": 25.0330, "lon": 121.5654},
    {"asn": 17421, "city": "Kaohsiung",   "name": "Taiwan Mobile",
     "lat": 22.6273, "lon": 120.3014},
    {"asn": 4780,  "city": "Taichung",    "name": "Sparq / Digital United",
     "lat": 24.1477, "lon": 120.6736},
    {"asn": 9924,  "city": "Hsinchu",     "name": "Taiwan Fixed Network",
     "lat": 24.8138, "lon": 120.9675},
    {"asn": 7539,  "city": "New Taipei",  "name": "ASNet — National Centre for HPC",
     "lat": 25.0120, "lon": 121.4658},
]

# PRC adversarial / state-operated transit ASes
# (China's "Great Firewall" and lawful-intercept infrastructure)
PRC_ADVERSARIAL = {
    4134:  "China Telecom (state-controlled)",
    4837:  "China Unicom (state-controlled)",
    9808:  "China Mobile (state-controlled)",
    4538:  "CERNET (Education and Research, state-controlled)",
    7497:  "CSTNET — Computer Network Information Center, CAS",
    9929:  "China Netcom (now Unicom subsidiary)",
    58453: "China Mobile International",
    23724: "ChinaNet IDC",
    4847:  "China Networks Inter-Exchange",
}


def fetch_ripe_routing_history(prefix):
    cache_dir = os.path.dirname(CACHE)
    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, prefix.replace("/", "_") + ".json")
    if os.path.exists(cache_file):
        with open(cache_file) as f:
            return json.load(f)

    url = (
        "https://stat.ripe.net/data/routing-history/data.json"
        f"?resource={urllib.parse.quote(prefix)}"
        "&starttime=2024-01-01T00:00:00&endtime=2024-12-31T00:00:00"
    )
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CyberTerrainMapper/1.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.load(r)
        with open(cache_file, "w") as f:
            json.dump(data, f)
        time.sleep(0.4)
        return data
    except Exception as e:
        print(f"  [err] {prefix}: {e}")
        return {}


def fetch_announced_prefixes(asn):
    cache_file = os.path.join(os.path.dirname(CACHE), f"AS{asn}_prefixes.json")
    os.makedirs(os.path.dirname(cache_file), exist_ok=True)
    if os.path.exists(cache_file):
        with open(cache_file) as f:
            return json.load(f)
    url = (
        f"https://stat.ripe.net/data/announced-prefixes/data.json"
        f"?resource=AS{asn}&starttime=2024-06-01T00:00:00&endtime=2024-09-01T00:00:00"
    )
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CyberTerrainMapper/1.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.load(r)
        with open(cache_file, "w") as f:
            json.dump(data, f)
        time.sleep(0.4)
        return data
    except Exception as e:
        print(f"  [err] AS{asn}: {e}")
        return {}


def fetch_neighbours(asn):
    """Use RIPE Stat asn-neighbours to get directly-peering ASes — proxy for adjacency."""
    cache_file = os.path.join(os.path.dirname(CACHE), f"AS{asn}_neighbours.json")
    if os.path.exists(cache_file):
        with open(cache_file) as f:
            return json.load(f)
    url = f"https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS{asn}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CyberTerrainMapper/1.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.load(r)
        with open(cache_file, "w") as f:
            json.dump(data, f)
        time.sleep(0.3)
        return data
    except Exception as e:
        print(f"  [err] neighbours AS{asn}: {e}")
        return {}


def main():
    print("=== US-Relevance Scenario: Taiwan ↔ China cyber terrain ===\n")
    cities = []
    total_prc_neighbours = 0

    for tgt in TW_TARGETS:
        asn = tgt["asn"]
        print(f"[probe] AS{asn} ({tgt['name']}, {tgt['city']})")

        # Get this AS's directly peering neighbours
        nb_data = fetch_neighbours(asn)
        neighbours = nb_data.get("data", {}).get("neighbours", [])
        prc_neighbours = []
        for n in neighbours:
            n_asn = n.get("asn")
            if n_asn in PRC_ADVERSARIAL:
                prc_neighbours.append({
                    "asn": n_asn,
                    "role": PRC_ADVERSARIAL[n_asn],
                    "v4_peers":  n.get("v4_peers", 0),
                    "type":      n.get("type", ""),
                })
        total_prc_neighbours += len(prc_neighbours)

        # Sample one announced prefix and check routing history breadth
        ap = fetch_announced_prefixes(asn).get("data", {}).get("prefixes", [])
        sample_prefix = ap[0]["prefix"] if ap else None
        peer_count = None
        if sample_prefix:
            hist = fetch_ripe_routing_history(sample_prefix)
            tlines = []
            for o in hist.get("data", {}).get("by_origin", []):
                for sp in o.get("prefixes", []):
                    for tl in sp.get("timelines", []):
                        tlines.append(tl.get("full_peers_seeing", 0))
            peer_count = round(sum(tlines) / len(tlines), 1) if tlines else None

        # Tally exposure
        exposure_score = min(100, len(prc_neighbours) * 25)
        cities.append({
            **tgt,
            "neighbours_total":  len(neighbours),
            "prc_neighbours":    prc_neighbours,
            "prc_count":         len(prc_neighbours),
            "exposure_score":    exposure_score,
            "exposure_level":    (
                "critical" if exposure_score >= 75 else
                "severe"   if exposure_score >= 50 else
                "elevated" if exposure_score >= 25 else "nominal"
            ),
            "sample_prefix":     sample_prefix,
            "mean_peer_count":   peer_count,
        })

    out = {
        "scenario_name":     "Taiwan ↔ China",
        "scenario_question": "If a Taiwan Strait contingency triggered Chinese BGP-routing measures similar to Russia's against Ukraine, what cyber-terrain exposure would Taiwan face?",
        "method":            "Same methodology as the Ukraine analysis: identify state-operated PRC transit ASes (China Telecom AS4134, Unicom AS4837, Mobile AS9808, etc.), measure direct adjacency to Taiwanese target ASes, score exposure.",
        "adversarial_ases":  PRC_ADVERSARIAL,
        "cities":            cities,
        "totals": {
            "total_prc_adjacencies":  total_prc_neighbours,
            "exposed_targets":        sum(1 for c in cities if c["prc_count"] > 0),
            "max_exposure":           max((c["exposure_score"] for c in cities), default=0),
            "mean_exposure":          round(sum(c["exposure_score"] for c in cities) / len(cities)) if cities else 0,
        },
    }

    with open(OUT_JSON, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n[saved] {OUT_JSON}")

    print(f"\n=== Taiwan exposure summary ===")
    print(f"{'City':<14} {'AS':<8} {'Score':>5}  {'Level':<10}  {'PRC peers':<10}")
    print("-" * 60)
    for c in cities:
        print(f"{c['city']:<14} AS{c['asn']:<6} {c['exposure_score']:>5}  "
              f"{c['exposure_level']:<10}  {c['prc_count']:<3} of {c['neighbours_total']:<5}")
    print(f"\n  Total PRC-adjacency events across all targets: {total_prc_neighbours}")
    print(f"  Mean exposure score: {out['totals']['mean_exposure']}")


if __name__ == "__main__":
    main()
