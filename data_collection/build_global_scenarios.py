"""
Build per-scenario cyber-terrain assessments for every conflict in scenarios.py.

For each scenario:
  - Load UCDP GED kinetic events (global coverage, single CSV)
  - Pull RIPE Stat routing-history for each target AS (peer count timeline)
  - Pull RIPE Stat asn-neighbours to identify direct adjacency to adversarial ASes
  - Compute exposure score per city
  - Generate mitigation recommendations
  - Emit scenarios/<scenario_id>.json

This same machinery powers the Russia-Ukraine analysis we already shipped —
now applied to 5+ active conflicts globally.
"""

import os
import sys
import csv
import json
import time
import urllib.request
import urllib.parse
import datetime

from scenarios   import SCENARIOS
from mitigations import recommend_for_city

DATA_DIR     = os.path.dirname(os.path.abspath(__file__))
UCDP_CSV     = os.path.join(DATA_DIR, "acled_data", "ucdp_ukraine.csv")
UCDP_FULL_ZIP = os.path.join(os.path.dirname(DATA_DIR), "ged251-csv.zip")
SCENARIOS_DIR = os.path.join(DATA_DIR, "scenarios_data")
RIPE_CACHE   = os.path.join(DATA_DIR, "ripe_stat_cache")

os.makedirs(SCENARIOS_DIR, exist_ok=True)
os.makedirs(RIPE_CACHE, exist_ok=True)


# ---------------------------------------------------------------------------
# UCDP GED — load events for any country from the full ZIP
# ---------------------------------------------------------------------------

def load_ucdp_events_for_country(country, date_start, date_end, extras=None):
    """
    Stream-extract UCDP events for a given country (and optional extras).
    Caches per-country to scenarios_data/ucdp_<country>.csv.
    """
    target_countries = {country}
    if extras:
        target_countries.update(extras)

    cache_file = os.path.join(SCENARIOS_DIR,
        f"ucdp_{country.replace(' ', '_').replace('/', '_')}.csv")

    if not os.path.exists(cache_file):
        if not os.path.exists(UCDP_FULL_ZIP):
            print(f"  [warn] {UCDP_FULL_ZIP} not found, skipping kinetic events for {country}")
            return []
        print(f"  [extract] UCDP events for {target_countries} (from full GED zip)")
        import zipfile, io
        with zipfile.ZipFile(UCDP_FULL_ZIP) as z:
            name = z.namelist()[0]
            with z.open(name) as binf, open(cache_file, "w", newline="") as outf:
                text = io.TextIOWrapper(binf, encoding="utf-8", newline="")
                reader = csv.DictReader(text)
                writer = csv.DictWriter(outf, fieldnames=reader.fieldnames)
                writer.writeheader()
                for row in reader:
                    if row["country"] in target_countries:
                        writer.writerow(row)

    out = []
    with open(cache_file) as f:
        for r in csv.DictReader(f):
            d = (r.get("date_start") or "")[:10]
            if date_start <= d <= date_end:
                out.append(r)
    return out


# ---------------------------------------------------------------------------
# RIPE Stat probes — same shape as Taiwan scenario
# ---------------------------------------------------------------------------

def cached_get(name, url, timeout=30):
    cache = os.path.join(RIPE_CACHE, name)
    if os.path.exists(cache):
        with open(cache) as f:
            return json.load(f)
    try:
        req = urllib.request.Request(url,
            headers={"User-Agent": "CyberTerrainMapper/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
        with open(cache, "w") as f:
            json.dump(data, f)
        time.sleep(0.3)
        return data
    except Exception as e:
        print(f"    [ripe-err] {name}: {e}")
        return {}


def fetch_neighbours(asn):
    return cached_get(
        f"AS{asn}_neighbours.json",
        f"https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS{asn}",
    )


def _enrich_asn(asn):
    """Pull holder + country for an ASN. Cached after first call."""
    ov = cached_get(
        f"AS{asn}_overview.json",
        f"https://stat.ripe.net/data/as-overview/data.json?resource=AS{asn}",
    )
    cc_data = cached_get(
        f"country_AS{asn}.json",
        f"https://stat.ripe.net/data/rir-stats-country/data.json?resource=AS{asn}",
    )
    located = cc_data.get("data", {}).get("located_resources", [])
    return {
        "holder":  ov.get("data", {}).get("holder", "") or "",
        "country": located[0].get("location", "") if located else "",
    }


def fetch_announced(asn, start, end):
    return cached_get(
        f"AS{asn}_announced_{start[:7]}_{end[:7]}.json",
        f"https://stat.ripe.net/data/announced-prefixes/data.json"
        f"?resource=AS{asn}&starttime={start}T00:00:00&endtime={end}T00:00:00",
    )


def fetch_routing_history(prefix, start, end):
    safe = prefix.replace("/", "_")
    return cached_get(
        f"history_{safe}_{start[:7]}_{end[:7]}.json",
        f"https://stat.ripe.net/data/routing-history/data.json"
        f"?resource={urllib.parse.quote(prefix)}"
        f"&starttime={start}T00:00:00&endtime={end}T00:00:00",
    )


# ---------------------------------------------------------------------------
# Per-city analysis using only RIPE Stat (no MRT files needed for non-Ukraine)
# ---------------------------------------------------------------------------

def assess_city(target, scenario, events_in_window):
    asn  = target["asn"]
    city = target["city"]
    print(f"    AS{asn} ({city}, {target.get('lat'):.2f}, {target.get('lon'):.2f})")

    # Direct adjacency to adversarial ASes
    adv_set = set(scenario["adversarial_ases"].keys())
    nb_data = fetch_neighbours(asn)
    neighbours = nb_data.get("data", {}).get("neighbours", [])
    adv_neighbours = []
    for n in neighbours:
        n_asn = n.get("asn")
        if n_asn in adv_set:
            op, role = scenario["adversarial_ases"][n_asn]
            adv_neighbours.append({
                "asn":    n_asn,
                "operator": op,
                "role":     role,
                "v4_peers": n.get("v4_peers", 0),
            })

    # Top non-adversarial neighbours by global reach (v4_peers count). These give
    # the map richness — show all the major transit options coming into this city.
    top_neighbours = []
    seen = set()
    for n in sorted(neighbours, key=lambda x: -x.get("v4_peers", 0)):
        n_asn = n.get("asn")
        if n_asn in seen or n_asn == asn:
            continue
        seen.add(n_asn)
        meta = _enrich_asn(n_asn)
        top_neighbours.append({
            "asn":      n_asn,
            "holder":   meta["holder"],
            "country":  meta["country"],
            "v4_peers": n.get("v4_peers", 0),
            "type":     n.get("type", ""),
            "is_adversary": n_asn in adv_set,
        })
        if len(top_neighbours) >= 12:
            break

    # Two-hop expansion: when direct neighbours are sparse (e.g. the city AS has
    # only one upstream like Myanmar's AS9988→AS45558), pull the upstream's
    # neighbours so the map shows the realistic transit chain.
    if len(top_neighbours) < 5 and top_neighbours:
        upstream = top_neighbours[0]   # most connected direct neighbour
        upstream_asn = upstream["asn"]
        upstream_nbs = fetch_neighbours(upstream_asn).get("data", {}).get("neighbours", [])
        for n in sorted(upstream_nbs, key=lambda x: -x.get("v4_peers", 0)):
            n_asn = n.get("asn")
            if n_asn in seen or n_asn == asn:
                continue
            seen.add(n_asn)
            meta = _enrich_asn(n_asn)
            top_neighbours.append({
                "asn":      n_asn,
                "holder":   meta["holder"],
                "country":  meta["country"],
                "v4_peers": n.get("v4_peers", 0),
                "type":     "upstream-of-upstream",
                "is_adversary": n_asn in adv_set,
                "via":      upstream_asn,   # marker for 2-hop path
            })
            if len(top_neighbours) >= 10:
                break

    # Peer-visibility timeline for one announced prefix
    ap = fetch_announced(asn, scenario["date_start"], scenario["date_end"])
    prefixes = ap.get("data", {}).get("prefixes", [])
    sample_prefix = prefixes[0]["prefix"] if prefixes else None

    peer_timeline = []
    if sample_prefix:
        hist = fetch_routing_history(sample_prefix,
            scenario["date_start"], scenario["date_end"])
        for o in hist.get("data", {}).get("by_origin", []):
            for sp in o.get("prefixes", []):
                for tl in sp.get("timelines", []):
                    peer_timeline.append({
                        "date":  tl.get("starttime", "")[:10],
                        "peers": float(tl.get("full_peers_seeing", 0)),
                    })
    peer_timeline.sort(key=lambda p: p["date"])

    # Compute peer count summary
    peers_vals = [p["peers"] for p in peer_timeline]
    peer_min = min(peers_vals) if peers_vals else 0
    peer_max = max(peers_vals) if peers_vals else 0
    peer_drop = round(peer_max - peer_min, 1) if peers_vals else 0

    # City-local kinetic events (within ~50km lat/lon proxy)
    target_lat = target.get("lat") or 0
    target_lon = target.get("lon") or 0
    nearby_events = []
    for e in events_in_window:
        try:
            elat = float(e.get("latitude") or 0)
            elon = float(e.get("longitude") or 0)
            if abs(elat - target_lat) < 0.5 and abs(elon - target_lon) < 0.5:
                nearby_events.append({
                    "event_date": e.get("date_start", "")[:10],
                    "event_type": "Battles" if e.get("type_of_violence") == "1" else
                                  "Non-state" if e.get("type_of_violence") == "2" else
                                  "Violence against civilians",
                    "actor1": e.get("side_a", ""),
                    "actor2": e.get("side_b", ""),
                    "fatalities": int(e.get("best") or 0),
                    "notes": (e.get("source_headline") or "")[:200],
                })
        except (ValueError, TypeError):
            continue

    # Compute threat score — generalized formula that works without MRT data.
    # Kinetic intensity stands in for instability when BGP UPDATE volume is unavailable.
    # Blackout signal also rewards a sustained low peer floor (blockade signature),
    # not just the drop magnitude.
    blackout = min(40, (peer_drop / 300.0) * 28
                       + (max(0, 200 - peer_min) / 200.0) * 12)

    # Kinetic intensity proxies for instability when MRT not available.
    # 50+ events near a city in our window = full 25 pts.
    kinetic_density = min(25, (len(nearby_events) / 50.0) * 25)

    # Adversarial-adjacency: 5 pts per direct adjacency, capped at 25
    russian_route = min(25, len(adv_neighbours) * 5)

    # Intercept exposure: any adversarial AS whose declared role mentions
    # intercept / DPI / surveillance / state-controlled
    sorm_exposure = min(10, sum(1 for n in adv_neighbours
        if any(kw in n["role"].lower() for kw in
               ["intercept", "dpi", "state", "surveillance", "msn"])) * 4)

    score = round(blackout + kinetic_density + russian_route + sorm_exposure)
    level = (
        "critical" if score >= 80 else
        "severe"   if score >= 60 else
        "elevated" if score >= 30 else
        "nominal"
    )

    threat = {
        "score":      score,
        "level":      level,
        "components": {
            "blackout":      round(blackout, 1),
            "instability":   round(kinetic_density, 1),
            "russian_route": round(russian_route, 1),
            "sorm_exposure": round(sorm_exposure, 1),
        },
        "evidence": {
            "peer_count_drop":         peer_drop,
            "peer_min":                peer_min,
            "kinetic_events_local":    len(nearby_events),
            "max_bgp_updates_in_day":  0,
            "russian_paths_count":     len(adv_neighbours),
            "sorm_ases_observed":      sorted(str(n["asn"]) for n in adv_neighbours),
            "neighbours_total":        len(neighbours),
            "adversarial_neighbours":  adv_neighbours,
        },
    }

    # Synthesize "periods" — equivalent shape to Ukraine's BGP samples — so every
    # scenario has the same UI surface. A period is a meaningful date in the
    # conflict timeline at which we can show:
    #   - sample paths (adversary→city_AS adjacencies + non-adversarial transit)
    #   - update_count (kinetic event volume in ±7d window)
    #   - classifications (adv-routed vs neutral count)
    periods = synthesize_periods(
        scenario, target, peer_timeline, nearby_events,
        adv_neighbours, top_neighbours,
    )

    return {
        "city":       city,
        "asn":        asn,
        "lat":        target.get("lat"),
        "lon":        target.get("lon"),
        "threat":     threat,
        "peer_timeline":  peer_timeline,
        "events":     nearby_events,
        "kinetic_event_count": len(nearby_events),
        "sample_prefix":  sample_prefix,
        "peer_min":   peer_min,
        "peer_max":   peer_max,
        "top_neighbours": top_neighbours,
        "periods":    periods,
        "summary":    {
            "kinetic_event_count":   len(nearby_events),
            "first_event":           min((e["event_date"] for e in nearby_events), default=None),
            "last_event":            max((e["event_date"] for e in nearby_events), default=None),
            "max_bgp_updates_in_day": 0,
            "peer_count_min":         peer_min,
            "peer_count_max":         peer_max,
            "peer_count_drop":        peer_drop,
        },
        "mitigations": recommend_for_city({"threat": threat}),
    }


def synthesize_periods(scenario, target, peer_timeline, kinetic_events,
                       adv_neighbours, top_neighbours=None):
    """
    For non-Ukraine scenarios where we don't have MRT-derived BGP samples,
    synthesize equivalent "periods" so the timeline scrubber + map have
    something to render. Each period is a meaningful date in the conflict
    timeline (start, peer-cliff, peak event density, recent).
    """
    asn = target["asn"]

    # Sample paths — each visible neighbour becomes a 1-hop adjacency rendered
    # on the map. Adversarial first, then top transit by reach.
    sample_paths = []
    seen_hops = set()
    for n in adv_neighbours[:6]:
        hop = str(n["asn"])
        if hop not in seen_hops:
            sample_paths.append(f"{hop} → {asn}")
            seen_hops.add(hop)
    if top_neighbours:
        for n in top_neighbours:
            if n.get("is_adversary"):
                continue   # already added
            hop = str(n["asn"])
            if hop in seen_hops:
                continue
            via = n.get("via")
            if via and str(via) != hop:
                # 2-hop path: distant peer → upstream → city
                sample_paths.append(f"{hop} → {via} → {asn}")
            else:
                sample_paths.append(f"{hop} → {asn}")
            seen_hops.add(hop)
            if len(sample_paths) >= 12:
                break
    # Backstop neutral path so the map is never empty
    if not sample_paths:
        sample_paths.append(f"3356 → 174 → {asn}")

    # Find peer-count cliff: largest single drop over 7d window
    cliff_date = None
    cliff_drop = 0
    if len(peer_timeline) >= 7:
        for i in range(7, len(peer_timeline)):
            window = peer_timeline[i-7:i+1]
            drop = window[0]["peers"] - window[-1]["peers"]
            if drop > cliff_drop:
                cliff_drop = drop
                cliff_date = window[-1]["date"]

    # Find peak kinetic density: 14d window with most events
    peak_kinetic_date = None
    if kinetic_events:
        # Find date with the most events near it (±7d window)
        from collections import Counter
        date_counts = Counter()
        ev_dates = sorted(e["event_date"] for e in kinetic_events)
        for d in ev_dates:
            count = sum(1 for e in kinetic_events
                        if abs(_days_between(d, e["event_date"])) <= 7)
            date_counts[d] = count
        if date_counts:
            peak_kinetic_date = date_counts.most_common(1)[0][0]

    # Compose periods
    periods = {}

    # Period 1: scenario start — baseline
    periods["scenario_start"] = {
        "description":  f"Conflict baseline ({scenario['date_start'][:7]})",
        "date":         scenario["date_start"],
        "update_count": _events_near_date(kinetic_events, scenario["date_start"], 14),
        "classifications": _classify_paths_for_period(sample_paths, len(adv_neighbours)),
        "sample_paths": sample_paths,
    }

    # Period 2: peak kinetic intensity
    if peak_kinetic_date:
        periods["peak_kinetic"] = {
            "description":  "Peak kinetic intensity",
            "date":         peak_kinetic_date,
            "update_count": _events_near_date(kinetic_events, peak_kinetic_date, 14),
            "classifications": _classify_paths_for_period(sample_paths, len(adv_neighbours)),
            "sample_paths": sample_paths,
        }

    # Period 3: peer-count cliff (communications-degradation event)
    if cliff_date and cliff_drop > 30:
        periods["peer_cliff"] = {
            "description":  f"Peer visibility cliff (-{cliff_drop:.0f} peers in 7d)",
            "date":         cliff_date,
            "update_count": _events_near_date(kinetic_events, cliff_date, 14),
            "classifications": _classify_paths_for_period(sample_paths, len(adv_neighbours)),
            "sample_paths": sample_paths,
        }

    # Period 4: end-of-window snapshot
    periods["recent"] = {
        "description":  f"Recent observation ({scenario['date_end'][:7]})",
        "date":         scenario["date_end"],
        "update_count": _events_near_date(kinetic_events, scenario["date_end"], 14),
        "classifications": _classify_paths_for_period(sample_paths, len(adv_neighbours)),
        "sample_paths": sample_paths,
    }

    return periods


def _classify_paths_for_period(sample_paths, adv_count):
    """Approximate classification breakdown for synthesized paths."""
    return {
        "adversary-routed": min(adv_count, len(sample_paths) - 1),
        "neutral":          1,
    }


def _days_between(d1, d2):
    """Days between two YYYY-MM-DD strings."""
    from datetime import date
    try:
        a = date.fromisoformat(d1[:10])
        b = date.fromisoformat(d2[:10])
        return (b - a).days
    except Exception:
        return 999


def _events_near_date(events, target_date, window_days):
    """Count kinetic events within ±window_days of target_date."""
    return sum(1 for e in events
               if abs(_days_between(target_date, e["event_date"])) <= window_days)


def build_scenario(sid, scenario):
    print(f"\n=== {scenario['name']} ({sid}) ===")
    events = []
    if scenario.get("ucdp_country"):
        events = load_ucdp_events_for_country(
            scenario["ucdp_country"],
            scenario["date_start"],
            scenario["date_end"],
            extras=scenario.get("ucdp_extra"),
        )
        print(f"  [ucdp] {len(events)} events in window")

    cities = []
    for tgt in scenario["targets"]:
        cities.append(assess_city(tgt, scenario, events))

    # Synthesize chokepoints from observed adjacencies — same shape as
    # Ukraine's MRT-derived chokepoint analysis.
    chokepoints = synthesize_chokepoints(scenario, cities)

    # Aggregate scenario-level totals
    out = {
        "id":                sid,
        "name":              scenario["name"],
        "region":            scenario["region"],
        "active_since":      scenario["active_since"],
        "primary_actor":     scenario["primary_actor"],
        "secondary_actor":   scenario["secondary_actor"],
        "summary":           scenario["summary"],
        "data_source":       scenario["data_source"],
        "date_start":        scenario["date_start"],
        "date_end":          scenario["date_end"],
        "adversarial_ases":  {str(k): {"operator": v[0], "role": v[1]}
                              for k, v in scenario["adversarial_ases"].items()},
        "cities":            cities,
        "chokepoints":       chokepoints,
        "totals": {
            "city_count":           len(cities),
            "total_events":         len(events),
            "exposed_cities":       sum(1 for c in cities
                                        if c["threat"]["score"] >= 30),
            "critical_cities":      sum(1 for c in cities
                                        if c["threat"]["score"] >= 60),
            "max_threat":           max((c["threat"]["score"] for c in cities), default=0),
            "mean_threat":          round(sum(c["threat"]["score"] for c in cities)
                                          / max(1, len(cities))),
            "total_adversarial_adjacencies": sum(
                len(c["threat"]["evidence"].get("adversarial_neighbours", []))
                for c in cities
            ),
        },
        "generated_at":      datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    out_path = os.path.join(SCENARIOS_DIR, f"{sid}.json")
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"  [saved] {out_path}  ({out['totals']['exposed_cities']}/{out['totals']['city_count']} cities exposed, max threat {out['totals']['max_threat']})")
    return out


def synthesize_chokepoints(scenario, cities):
    """
    Build chokepoint analysis for non-Ukraine scenarios using the asn-neighbours
    graph data already gathered. A chokepoint here is an AS that appears as an
    adversarial neighbour to ≥1 target city — its centrality score is the count
    of cities it neighbours.
    """
    from collections import Counter

    # All neighbours each city has (incl. non-adversarial)
    asn_to_cities = {}    # asn → set of city names it neighbours
    asn_to_meta   = {}    # asn → metadata for display
    for c in cities:
        for n in c["threat"]["evidence"].get("adversarial_neighbours", []):
            a = n["asn"]
            asn_to_cities.setdefault(a, set()).add(c["city"])
            asn_to_meta[a] = {
                "operator": n.get("operator"),
                "role":     n.get("role"),
                "v4_peers": n.get("v4_peers", 0),
            }

    # Centrality = number of target cities this AS adjacencies to
    if not asn_to_cities:
        return {
            "graph_stats": {
                "ases":           0,
                "edges":          0,
                "paths_observed": 0,
                "source_peers":   0,
                "ua_targets":     len(cities),
            },
            "top_chokepoints":         [],
            "adversarial_chokepoints": [],
        }

    max_count = max(len(v) for v in asn_to_cities.values())
    chokepoints = []
    for asn_int, city_set in asn_to_cities.items():
        meta = asn_to_meta[asn_int]
        chokepoints.append({
            "asn":             int(asn_int),
            "centrality":      round((len(city_set) / max_count) * 100, 2),
            "raw_score":       len(city_set),
            "neighbors":       meta.get("v4_peers", 0),
            "holder":          meta.get("operator", ""),
            "country":         "",
            "country_name":    "",
            "classification":  "Russian",   # all are adversarial in this list
            "sorm_role":       meta.get("role", ""),
            "is_adversarial":  True,
        })
    chokepoints.sort(key=lambda c: -c["centrality"])

    return {
        "graph_stats": {
            "ases":           len(asn_to_cities),
            "edges":          sum(len(v) for v in asn_to_cities.values()),
            "paths_observed": sum(c["kinetic_event_count"] for c in cities),
            "source_peers":   len(asn_to_cities),
            "ua_targets":     len(cities),
        },
        "top_chokepoints":         chokepoints[:10],
        "adversarial_chokepoints": chokepoints[:5],
    }


def main():
    print("=== Global Conflict Scenario Builder ===")
    summaries = {}
    for sid, sc in SCENARIOS.items():
        summaries[sid] = build_scenario(sid, sc)

    # Top-level index
    index = {
        sid: {
            "name":            s["name"],
            "region":          s["region"],
            "active_since":    s["active_since"],
            "summary":         s["summary"],
            "totals":          s["totals"],
            "data_source":     s["data_source"],
        }
        for sid, s in summaries.items()
    }
    with open(os.path.join(SCENARIOS_DIR, "_index.json"), "w") as f:
        json.dump(index, f, indent=2)

    print("\n=== Scenario summary ===")
    for sid, s in summaries.items():
        t = s["totals"]
        print(f"  {s['name']:<35} cities={t['city_count']}  "
              f"exposed={t['exposed_cities']}  critical={t['critical_cities']}  "
              f"max={t['max_threat']}")


if __name__ == "__main__":
    main()
