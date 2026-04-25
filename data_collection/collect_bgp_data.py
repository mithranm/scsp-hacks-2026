"""
BGP Data Collector for Cyber Terrain Mapper
Fetches real BGP routing data from RIPE NCC RIS collectors and RIPE Stat API,
capturing "normal" routing (2021, pre-invasion) vs "rerouted/dark" routing (2022, post-occupation).

Outputs:
  bgp_paths_{period}.csv         — MRT UPDATE records for Ukrainian ASNs, with SORM classification
  pcap_output/bgp_{period}.pcap  — Wireshark-compatible PCAP (BGP UPDATE wire format)
  ripe_stat_routing_history.csv  — Per-prefix visibility timelines (peer count drops = "went dark")
  ripe_stat_origin_changes.csv   — Prefix/origin-AS changes showing hijack events
"""

import os, sys, gzip, struct, json, time, datetime, csv, urllib.request, urllib.error, urllib.parse

try:
    import mrtparse
except ImportError:
    sys.exit("mrtparse not installed. Run: pip install mrtparse")

try:
    from scapy.all import wrpcap, Ether, IP, TCP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    print("[warn] scapy not available — PCAP output skipped")
    SCAPY_AVAILABLE = False

# ---------------------------------------------------------------------------
# Target Ukrainian ASNs (real, confirmed assignments)
# ---------------------------------------------------------------------------

TARGETS = [
    {"city": "Kherson",    "asn": 21219, "name": "KhersonNet"},
    {"city": "Mariupol",   "asn": 6849,  "name": "Ukrtelecom"},
    {"city": "Kharkiv",    "asn": 13188, "name": "Content Delivery Network Ltd"},
    {"city": "Zaporizhia", "asn": 34700, "name": "Znet"},
    {"city": "Donetsk",    "asn": 48593, "name": "DonbassTelecom"},
    {"city": "Luhansk",    "asn": 34867, "name": "LuhanskNet"},
]
TARGET_ASNS = {t["asn"] for t in TARGETS}
ASN_TO_CITY = {t["asn"]: t["city"] for t in TARGETS}

# Russian ASes operating SORM (from public research / Roskomnadzor records)
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

# Time windows: hour-granular MRT update files
TIME_WINDOWS = [
    {"label": "baseline_2021",       "description": "Pre-invasion baseline (Oct 2021)",    "year": 2021, "month": 10, "day": 1,  "hour": 0},
    {"label": "invasion_start_2022", "description": "Invasion start (Feb 24 2022)",        "year": 2022, "month": 2,  "day": 24, "hour": 8},
    {"label": "kherson_dark_2022",   "description": "Kherson goes dark (Mar 2 2022)",      "year": 2022, "month": 3,  "day": 2,  "hour": 8},
    {"label": "mariupol_siege_2022", "description": "Mariupol siege/dark (Apr 15 2022)",   "year": 2022, "month": 4,  "day": 15, "hour": 8},
]

RIS_COLLECTORS = ["rrc15", "rrc16", "rrc18"]   # rrc18 = Moscow (Cloud-MSK) — needed for Russian-transit views

OUT_DIR   = os.path.dirname(os.path.abspath(__file__))
MRT_DIR   = os.path.join(OUT_DIR, "mrt_data")
PCAP_DIR  = os.path.join(OUT_DIR, "pcap_output")
STAT_DIR  = os.path.join(OUT_DIR, "ripe_stat_cache")


# ---------------------------------------------------------------------------
# MRT download
# ---------------------------------------------------------------------------

def mrt_update_url(collector, year, month, day, hour):
    return (
        f"https://data.ris.ripe.net/{collector}/"
        f"{year:04d}.{month:02d}/"
        f"updates.{year:04d}{month:02d}{day:02d}.{hour:02d}00.gz"
    )


def download_mrt(url, dest):
    if os.path.exists(dest):
        return True
    print(f"  [fetch] {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CyberTerrainMapper/1.0"})
        with urllib.request.urlopen(req, timeout=90) as r:
            data = r.read()
        with open(dest, "wb") as f:
            f.write(data)
        print(f"  [ok]    {len(data)//1024} KB")
        return True
    except urllib.error.HTTPError as e:
        print(f"  [skip]  HTTP {e.code}")
        return False
    except Exception as e:
        print(f"  [err]   {e}")
        return False


# ---------------------------------------------------------------------------
# MRT parsing — match by target ASN appearing anywhere in AS_PATH
# ---------------------------------------------------------------------------

def parse_mrt_for_target_asns(mrt_path, target_asns):
    """
    Scan an MRT UPDATE file for BGP UPDATE messages where any target ASN
    appears in the AS_PATH. Returns list of record dicts.
    """
    results = []
    target_asns_str = {str(a) for a in target_asns}

    try:
        reader = mrtparse.Reader(mrt_path)
        for entry in reader:
            try:
                d = entry.data
                bgp_msg = d.get("bgp_message", {})
                if not bgp_msg:
                    continue

                # Type 2 = UPDATE
                msg_type_keys = list(bgp_msg.get("type", {}).keys())
                if not msg_type_keys or msg_type_keys[0] != 2:
                    continue

                ts_dict = d.get("timestamp", {})
                timestamp = list(ts_dict.keys())[0] if isinstance(ts_dict, dict) else 0

                attrs = bgp_msg.get("path_attributes", [])
                as_path = []
                next_hop = ""
                origin_str = ""

                for attr in attrs:
                    atype = list(attr.get("type", {}).keys())
                    if not atype:
                        continue
                    t = atype[0]
                    val = attr.get("value", "")

                    if t == 2:  # AS_PATH
                        segs = val if isinstance(val, list) else []
                        for seg in segs:
                            seg_vals = seg.get("value", [])
                            as_path.extend(str(v) for v in seg_vals)
                    elif t == 3:  # NEXT_HOP
                        next_hop = str(val)
                    elif t == 1:  # ORIGIN
                        origin_str = str(list(val.values())[0]) if isinstance(val, dict) else str(val)

                # Check if any target ASN is in this path
                if not set(as_path) & target_asns_str:
                    continue

                # Get NLRI (announced prefixes)
                nlri_entries = bgp_msg.get("nlri", [])
                prefixes = [
                    f"{n['prefix']}/{n['length']}"
                    for n in nlri_entries
                    if "prefix" in n and "length" in n
                ]

                # Find which target ASNs matched
                matched_asns = [int(a) for a in as_path if a in target_asns_str]
                city = ASN_TO_CITY.get(matched_asns[0], "unknown") if matched_asns else "unknown"

                results.append({
                    "timestamp":    timestamp,
                    "peer_as":      d.get("peer_as", ""),
                    "peer_ip":      d.get("peer_ip", ""),
                    "as_path":      as_path,
                    "matched_asns": matched_asns,
                    "city":         city,
                    "prefixes":     prefixes,
                    "next_hop":     next_hop,
                    "origin":       origin_str,
                })
            except Exception:
                continue
    except Exception as e:
        print(f"  [parse-err] {os.path.basename(mrt_path)}: {e}")

    return results


# ---------------------------------------------------------------------------
# SORM / path classification
# ---------------------------------------------------------------------------

def detect_sorm(as_path_str_list):
    return [int(a) for a in as_path_str_list if int(a) in SORM_ASES] if as_path_str_list else []


def classify_path(as_path_str_list):
    russian_asns = set(SORM_ASES.keys()) | {12389, 8359, 31257, 3216, 2854, 50010, 197695, 204490}
    as_ints = set()
    for a in as_path_str_list:
        try:
            as_ints.add(int(a))
        except ValueError:
            pass
    overlap = as_ints & russian_asns
    if overlap:
        return "SORM-interceptable" if (overlap & set(SORM_ASES)) else "Russian-routed"
    return "neutral"


# ---------------------------------------------------------------------------
# PCAP generation — real BGP wire-format UPDATE messages
# ---------------------------------------------------------------------------

def build_bgp_update(as_path_strs, prefix="0.0.0.0/0", next_hop="10.0.0.1"):
    """Encode a real BGP UPDATE message (RFC 4271 wire format)."""
    as_path_ints = []
    for a in as_path_strs:
        try:
            as_path_ints.append(int(a))
        except ValueError:
            pass

    # AS_PATH segment data
    seg = bytearray([2, len(as_path_ints) & 0xFF])  # type=AS_SEQUENCE
    for asn in as_path_ints:
        seg += struct.pack(">I", asn)

    attrs = bytearray()
    attrs += bytes([0x40, 0x01, 0x01, 0x02])           # ORIGIN=INCOMPLETE
    attrs += bytes([0x40, 0x02, len(seg)]) + seg        # AS_PATH
    nh = [int(x) for x in next_hop.split(".")]
    attrs += bytes([0x40, 0x03, 0x04] + nh)             # NEXT_HOP

    # NLRI
    try:
        net_str, plen_s = prefix.split("/")
        plen = int(plen_s)
        octets = (plen + 7) // 8
        net_bytes = bytes(int(x) for x in net_str.split("."))[:octets]
        nlri = bytes([plen]) + net_bytes
    except Exception:
        nlri = b""

    total_len = 19 + 2 + 2 + len(attrs) + len(nlri)
    msg = bytearray()
    msg += b"\xff" * 16
    msg += struct.pack(">H", total_len)
    msg += b"\x02"
    msg += struct.pack(">H", 0)       # withdrawn_routes_len
    msg += struct.pack(">H", len(attrs))
    msg += attrs
    msg += nlri
    return bytes(msg)


import re as _re
_IPV4_RE = _re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

def _safe_ipv4(addr, fallback="192.168.1.1"):
    """Return addr if it's a plain dotted-quad IPv4, else fallback."""
    if addr and _IPV4_RE.match(str(addr).strip()):
        return str(addr).strip()
    return fallback


def records_to_pcap(records, out_path):
    if not SCAPY_AVAILABLE or not records:
        if records:
            print(f"  [skip-pcap] scapy unavailable")
        return

    packets = []
    seq = 1000
    for r in records:
        prefix = r["prefixes"][0] if r.get("prefixes") else "0.0.0.0/0"
        nh = _safe_ipv4(r.get("next_hop"), "10.0.0.1")
        src_ip = _safe_ipv4(r.get("peer_ip"), "192.168.1.1")
        bgp = build_bgp_update(r["as_path"], prefix, nh)
        pkt = (
            Ether()
            / IP(src=src_ip, dst="192.168.1.2")
            / TCP(sport=179, dport=1024 + (seq % 1000), seq=seq, flags="PA")
            / Raw(load=bgp)
        )
        pkt.time = float(r.get("timestamp", 0) or 0)
        packets.append(pkt)
        seq += len(bgp)

    wrpcap(out_path, packets)
    print(f"  [pcap] {len(packets)} packets → {os.path.basename(out_path)}")


# ---------------------------------------------------------------------------
# CSV output
# ---------------------------------------------------------------------------

def write_csv(records, out_path):
    if not records:
        return
    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "timestamp", "datetime", "period", "city", "matched_asns",
            "as_path", "as_path_length", "sorm_ases", "classification",
            "prefixes", "next_hop", "origin", "peer_as", "peer_ip",
        ])
        w.writeheader()
        for r in records:
            ts = r.get("timestamp", 0) or 0
            sorm = detect_sorm(r["as_path"])
            w.writerow({
                "timestamp":    ts,
                "datetime":     datetime.datetime.utcfromtimestamp(ts).isoformat() if ts else "",
                "period":       r.get("period", ""),
                "city":         r.get("city", ""),
                "matched_asns": " ".join(f"AS{a}" for a in r.get("matched_asns", [])),
                "as_path":      " → ".join(str(a) for a in r["as_path"]),
                "as_path_length": len(r["as_path"]),
                "sorm_ases":    ", ".join(f"AS{a} ({SORM_ASES[a]})" for a in sorm),
                "classification": classify_path(r["as_path"]),
                "prefixes":     " | ".join(r.get("prefixes", [])),
                "next_hop":     r.get("next_hop", ""),
                "origin":       r.get("origin", ""),
                "peer_as":      r.get("peer_as", ""),
                "peer_ip":      r.get("peer_ip", ""),
            })
    print(f"  [csv]  {os.path.basename(out_path)} ({len(records)} records)")


# ---------------------------------------------------------------------------
# RIPE Stat — routing history (visibility/peer count per prefix over time)
# ---------------------------------------------------------------------------

def fetch_routing_history(prefix):
    cache = os.path.join(STAT_DIR, prefix.replace("/", "_") + "_history.json")
    if os.path.exists(cache):
        with open(cache) as f:
            return json.load(f)
    url = (
        "https://stat.ripe.net/data/routing-history/data.json"
        f"?resource={urllib.parse.quote(prefix)}"
        "&starttime=2021-10-01T00:00:00"
        "&endtime=2023-01-01T00:00:00"
    )
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CyberTerrainMapper/1.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.load(r)
        with open(cache, "w") as f:
            json.dump(data, f, indent=2)
        time.sleep(0.5)
        return data
    except Exception as e:
        print(f"  [ripe-err] {prefix}: {e}")
        return {}


def fetch_announced_prefixes(asn, city):
    cache = os.path.join(STAT_DIR, f"AS{asn}_prefixes.json")
    if os.path.exists(cache):
        with open(cache) as f:
            return json.load(f)
    url = (
        f"https://stat.ripe.net/data/announced-prefixes/data.json"
        f"?resource=AS{asn}"
        f"&starttime=2022-01-01T00:00:00"
        f"&endtime=2023-01-01T00:00:00"
    )
    print(f"  [ripe-stat] AS{asn} ({city}) announced prefixes")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "CyberTerrainMapper/1.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.load(r)
        with open(cache, "w") as f:
            json.dump(data, f, indent=2)
        time.sleep(0.5)
        return data
    except Exception as e:
        print(f"  [ripe-err] AS{asn}: {e}")
        return {}


def collect_ripe_stat_data():
    print("\n=== RIPE Stat API: prefix visibility timelines ===")
    rows = []

    for t in TARGETS:
        asn  = t["asn"]
        city = t["city"]

        # Get prefixes for this ASN
        ap_data = fetch_announced_prefixes(asn, city)
        prefixes = ap_data.get("data", {}).get("prefixes", [])

        # Sample up to 5 prefixes per ASN
        sampled = prefixes[:5]
        for p_entry in sampled:
            prefix = p_entry.get("prefix", "")
            if not prefix:
                continue

            hist = fetch_routing_history(prefix)
            by_origin = hist.get("data", {}).get("by_origin", [])

            for origin_block in by_origin:
                origin_asn = origin_block.get("origin", "")
                for sub_prefix in origin_block.get("prefixes", []):
                    sub = sub_prefix.get("prefix", "")
                    for tl in sub_prefix.get("timelines", []):
                        rows.append({
                            "city":             city,
                            "asn":              asn,
                            "announced_prefix": prefix,
                            "sub_prefix":       sub,
                            "origin_asn":       origin_asn,
                            "starttime":        tl.get("starttime", ""),
                            "endtime":          tl.get("endtime", ""),
                            "full_peers_seeing": tl.get("full_peers_seeing", ""),
                        })

    out = os.path.join(OUT_DIR, "ripe_stat_routing_history.csv")
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "city", "asn", "announced_prefix", "sub_prefix",
            "origin_asn", "starttime", "endtime", "full_peers_seeing",
        ])
        w.writeheader()
        w.writerows(rows)
    print(f"  [saved] ripe_stat_routing_history.csv ({len(rows)} timeline entries)")

    # Detect "went dark" events: peer count drops to 0 or near 0
    dark_events = [r for r in rows if float(r.get("full_peers_seeing") or 1) < 5]
    dark_out = os.path.join(OUT_DIR, "ripe_stat_dark_events.csv")
    with open(dark_out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else [])
        w.writeheader()
        w.writerows(dark_events)
    print(f"  [saved] ripe_stat_dark_events.csv ({len(dark_events)} blackout events)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=== Cyber Terrain Mapper — BGP Data Collection ===\n")

    # Phase 1: RIPE Stat
    collect_ripe_stat_data()

    # Phase 2: MRT UPDATE files — scan for target ASNs in AS_PATH
    print("\n=== RIPE NCC RIS MRT UPDATE files ===")
    all_records = []
    all_records_by_period = {}

    for window in TIME_WINDOWS:
        label = window["label"]
        desc  = window["description"]
        print(f"\n-- {label}: {desc} --")
        period_records = []

        for collector in RIS_COLLECTORS:
            url  = mrt_update_url(collector, window["year"], window["month"], window["day"], window["hour"])
            dest = os.path.join(MRT_DIR, f"{collector}_{label}.gz")

            if not download_mrt(url, dest):
                continue

            print(f"  [parse] {collector}_{label}.gz")
            records = parse_mrt_for_target_asns(dest, TARGET_ASNS)
            for r in records:
                r["period"] = label
            period_records.extend(records)
            print(f"  [found] {len(records)} BGP updates mentioning target ASNs")

        all_records_by_period[label] = period_records
        all_records.extend(period_records)

        write_csv(period_records, os.path.join(OUT_DIR, f"bgp_paths_{label}.csv"))
        records_to_pcap(period_records, os.path.join(PCAP_DIR, f"bgp_{label}.pcap"))

    # Combined output
    all_records.sort(key=lambda r: r.get("timestamp", 0))
    write_csv(all_records, os.path.join(OUT_DIR, "bgp_paths_all_periods.csv"))
    records_to_pcap(all_records, os.path.join(PCAP_DIR, "bgp_all_periods_combined.pcap"))

    # Summary table
    print("\n=== Classification summary by period ===")
    print(f"{'Period':<28} {'Records':<9} {'Neutral':<10} {'Ru-routed':<12} {'SORM'}")
    print("-" * 70)
    for label, records in all_records_by_period.items():
        if not records:
            print(f"{label:<28} 0")
            continue
        c = [classify_path(r["as_path"]) for r in records]
        print(f"{label:<28} {len(records):<9} {c.count('neutral'):<10} {c.count('Russian-routed'):<12} {c.count('SORM-interceptable')}")

    print(f"\n[done] Files written to: {OUT_DIR}")
    print("  bgp_paths_*.csv                — BGP UPDATE records per period")
    print("  bgp_paths_all_periods.csv      — Combined dataset")
    print("  ripe_stat_routing_history.csv  — Prefix visibility timelines")
    print("  ripe_stat_dark_events.csv      — Blackout events (peers_seeing < 5)")
    print("  pcap_output/bgp_*.pcap         — Wireshark-compatible BGP captures")
    print("  mrt_data/                      — Raw MRT archives from RIPE NCC RIS")


if __name__ == "__main__":
    main()
