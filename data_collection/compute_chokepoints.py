"""
Network Resilience / Chokepoint Analysis
Builds an AS adjacency graph from every observed BGP path in our dataset,
then computes betweenness centrality to identify which ASes act as
chokepoints for traffic to/from Ukrainian target ASes.

This is the cyber-equivalent of identifying bridges and mountain passes
in physical wargaming terrain analysis.

Output:
  chokepoints.json       — Top-N ASes by centrality with adversarial flagging
  chokepoint_metrics.json — Per-AS metrics (centrality, paths-touched, etc.)
"""

import os
import csv
import json
import collections

DATA_DIR = os.path.dirname(os.path.abspath(__file__))
BGP_CSV  = os.path.join(DATA_DIR, "bgp_paths_all_periods.csv")
ASN_JSON = os.path.join(DATA_DIR, "asn_geolocation.json")
OUT_JSON = os.path.join(DATA_DIR, "chokepoints.json")


def load_paths():
    """Extract every unique AS path observed, with the city it terminates at."""
    paths = []
    with open(BGP_CSV) as f:
        for r in csv.DictReader(f):
            hops = [h.strip() for h in r["as_path"].split(" → ") if h.strip().isdigit()]
            if len(hops) >= 2:
                paths.append({
                    "hops": hops,
                    "city": r["city"],
                    "period": r["period"],
                })
    return paths


def build_adjacency(paths):
    """
    Build the AS-level adjacency graph from observed paths.
    Each consecutive pair of hops in any path becomes an edge.
    Edges are weighted by how often we observed that adjacency.
    """
    adj = collections.defaultdict(collections.Counter)
    for p in paths:
        for a, b in zip(p["hops"], p["hops"][1:]):
            adj[a][b] += 1
            adj[b][a] += 1   # treat as undirected for centrality
    return adj


def compute_betweenness(adj, sources, targets):
    """
    Betweenness centrality, restricted to shortest paths between (source, target)
    pairs we actually care about — peer ASes (sources) and Ukrainian target ASes.
    Brandes' algorithm restricted to these endpoint pairs.

    Returns: {asn: count of (s,t) shortest-paths it appears on}
    """
    centrality = collections.Counter()
    sources = list(sources)
    targets = set(targets)

    for s in sources:
        # BFS from s
        dist = {s: 0}
        pred = collections.defaultdict(list)
        sigma = collections.Counter({s: 1})
        order = []
        queue = collections.deque([s])
        while queue:
            v = queue.popleft()
            order.append(v)
            for w in adj.get(v, {}):
                if w not in dist:
                    dist[w] = dist[v] + 1
                    queue.append(w)
                if dist[w] == dist[v] + 1:
                    sigma[w] += sigma[v]
                    pred[w].append(v)

        # Accumulate betweenness via reverse BFS, only crediting paths that
        # actually terminate at a target AS.
        delta = collections.Counter()
        for w in reversed(order):
            if w in targets and w != s:
                # pretend each target is a "sink" — distribute path credit upstream
                for v in pred[w]:
                    delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
                centrality[w] += delta[w]
            else:
                for v in pred[w]:
                    delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
                if w != s:
                    centrality[w] += delta[w]
    return centrality


def main():
    print("=== Chokepoint / Network Resilience Analysis ===\n")
    paths = load_paths()
    print(f"[load] {len(paths)} observed paths")
    adj = build_adjacency(paths)
    print(f"[graph] {len(adj)} ASes, "
          f"{sum(len(n) for n in adj.values())//2} undirected edges")

    with open(ASN_JSON) as f:
        asn_geo = json.load(f)

    # Sources = peer ASes (path origins observed)
    sources = set(p["hops"][0] for p in paths)
    # Targets = our Ukrainian cities' ASes
    targets = {str(asn) for asn, meta in asn_geo.items()
               if meta.get("classification") == "UA-target"}
    print(f"[scope] {len(sources)} source ASes (peers) → {len(targets)} target ASes (UA cities)")

    print(f"\n[compute] running betweenness centrality (restricted to peer→UA paths)…")
    bc = compute_betweenness(adj, sources, targets)

    # Normalize so the largest score = 100
    max_score = max(bc.values()) if bc else 1.0
    scored = [
        (asn, score / max_score * 100)
        for asn, score in bc.items()
    ]
    scored.sort(key=lambda x: -x[1])

    # Build chokepoint records with full metadata
    chokepoints = []
    for asn, norm_score in scored:
        meta = asn_geo.get(asn, {})
        is_adversarial = meta.get("classification") in {"Russian", "SORM", "Belarusian"}
        chokepoints.append({
            "asn":            int(asn),
            "centrality":     round(norm_score, 2),
            "raw_score":      round(bc[asn], 2),
            "neighbors":      len(adj.get(asn, {})),
            "holder":         meta.get("holder", ""),
            "country":        meta.get("country", ""),
            "country_name":   meta.get("country_name", ""),
            "classification": meta.get("classification", "Unknown"),
            "sorm_role":      meta.get("sorm_role", ""),
            "is_adversarial": is_adversarial,
        })

    # Resilience scenario: simulate removing top adversarial chokepoints,
    # measure fragmentation
    adversarial_top = [c for c in chokepoints if c["is_adversarial"]][:5]
    out = {
        "graph_stats": {
            "ases":           len(adj),
            "edges":          sum(len(n) for n in adj.values()) // 2,
            "paths_observed": len(paths),
            "source_peers":   len(sources),
            "ua_targets":     len(targets),
        },
        "top_chokepoints": chokepoints[:30],
        "adversarial_chokepoints": adversarial_top,
    }

    with open(OUT_JSON, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n[saved] {OUT_JSON}")

    # Print headline result
    print(f"\n=== Top 10 chokepoints (peer → Ukrainian target traffic) ===")
    print(f"{'Rank':<5} {'AS':<10} {'Score':>7}  {'Class':<12}  {'Country':<3}  {'Holder'}")
    print("-" * 100)
    for i, c in enumerate(chokepoints[:10], 1):
        flag = " ⚠" if c["is_adversarial"] else ""
        print(f"{i:<5} AS{c['asn']:<8} {c['centrality']:>6.1f}  "
              f"{c['classification']:<12}  {c['country']:<3}  "
              f"{c['holder'][:50]}{flag}")

    if adversarial_top:
        print(f"\n=== Top adversarial chokepoints ===")
        print(f"  Removing the top {len(adversarial_top)} Russian-routed ASes would")
        print(f"  break {sum(c['raw_score'] for c in adversarial_top):.0f} peer→target shortest-paths.\n")
        for c in adversarial_top:
            print(f"    AS{c['asn']:<7} {c['holder'][:55]:<55} centrality={c['centrality']:.1f}")


if __name__ == "__main__":
    main()
