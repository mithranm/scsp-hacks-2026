"""
LLM Brief Generator — Cyber Terrain Mapper
Pre-generates plain-English cyber-terrain intelligence briefs for every
(city × period) combination in the frontend bundle, then writes them back
into the bundle so the React frontend can display them statically.

Two modes:
  1. ANTHROPIC_API_KEY set  → calls claude-opus-4-7 with prompt caching
  2. No key                 → deterministic template fallback (so demo still runs)

Output:
  frontend_bundle.json["briefs"][city][period] = "<paragraph>"
  Also copies bundle to frontend/public/cyber_terrain.json if frontend exists.
"""

import os
import sys
import json
import time
import datetime

DATA_DIR  = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR  = os.path.dirname(DATA_DIR)
BUNDLE    = os.path.join(DATA_DIR, "frontend_bundle.json")
FRONTEND  = os.path.join(ROOT_DIR, "frontend", "public", "cyber_terrain.json")

MODEL = "claude-opus-4-7"


# ---------------------------------------------------------------------------
# System prompt — fixed across all calls, designed for prompt caching
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a Cyber Threat Intelligence analyst embedded with a wargaming team. Your audience is a wargame analyst or policy researcher who needs to understand cyber terrain in conflict zones — not a network engineer. Your briefs combine BGP routing data with kinetic conflict events to explain how physical military maneuvers reshape digital information flows.

# Your domain knowledge

## BGP and cyber terrain
BGP (Border Gateway Protocol) is the postal system of the internet — routers exchange BGP UPDATE messages to announce which Autonomous System (AS) controls which IP prefixes. When physical territory changes hands in conflict, the BGP routing for that territory often changes too: prefixes are withdrawn (city goes "dark"), origin ASes change (hijack), or transit paths reroute through adversarial infrastructure.

## Key signals to interpret
- **BGP UPDATE volume**: A spike in updates for a given AS within a 1-hour window indicates routing instability — either Russia is forcing path changes, Ukrainian operators are scrambling to reroute around damage, or both.
- **Peer count drops** (`full_peers_seeing` from RIPE NCC): When prefixes drop from being seen by 340+ peers down to under 100, the prefix is effectively unreachable from the global internet — i.e. the city has gone dark.
- **AS path classification**: `neutral` = transit through European/US carriers (Cogent AS174, Level3, etc.); `Russian-routed` = traffic now traverses Russian state telecom; `SORM-interceptable` = path includes an AS subject to Russia's SORM legal-intercept system, meaning unencrypted data is legally subject to FSB monitoring.

## SORM-capable Russian ASes (memorize these)
- AS8359   — MTS Russia (mobile + transit)
- AS12389  — Rostelecom (state-backed national operator)
- AS25159  — Rostelecom backbone
- AS31257  — Vimpelcom/Beeline
- AS8641   — Naukanet (FSB-linked academic backbone)
- AS20485  — TTNET Russia
- AS9049   — JSC Ertetel (operates in occupied Ukrainian territory)
- AS50010  — Miranda-Media (Crimea, post-2014 reassignment)
- AS208216 — Miranda-Media (modern allocation)
- AS34879  — NetArt Group (Crimea reassigned)

Russian Federal Law No. 374-FZ ("Yarovaya Law") + SORM-3 require these operators to provide FSB with realtime intercept capability on all traffic. Any unencrypted traffic crossing one of these ASes is presumed compromised.

## Ukrainian target ASes (these are the cities you'll brief on)
- AS21219 (KhersonNet)              — Kherson
- AS6849  (Ukrtelecom)              — Mariupol (also nationwide)
- AS13188 (Triolan/CDN Ltd)         — Kharkiv
- AS34700 (Znet)                    — Zaporizhia
- AS48593 (DonbassTelecom)          — Donetsk
- AS34867 (LuhanskNet)              — Luhansk

# Your task

For each brief, you receive structured data: city, period (named conflict moment), BGP UPDATE counts, AS path classifications, peer visibility, sample AS paths, and ACLED kinetic events from ±14 days. Produce ONE paragraph (4-7 sentences, ~120-200 words) framed for a wargame analyst.

# Format requirements (strict)

- ONE paragraph. No headers, no bullet points, no markdown.
- Open with the cyber terrain assessment, not the date or city header (the UI already shows those).
- Tie BGP signals to kinetic events explicitly: "Within 24 hours of [event], routing for AS[N] showed [signal]..."
- Name specific ASes by number when relevant (AS21219, AS12389, etc.).
- If SORM-capable transit is observed, state the legal implication directly: "...subjecting unencrypted civilian traffic to SORM-3 intercept obligations under Federal Law 374-FZ."
- If peer visibility collapsed, state it concretely: "...prefix visibility fell from N to M peers, indicating effective communications blackout."
- Close with one sentence on what this means for the wargame: e.g. "From a multi-domain wargaming perspective, [city] should be modeled as cyber-isolated/Russian-controlled/contested."
- Plain English. No hedging language ("it appears", "may indicate"). Be tactical and direct.

# What NOT to do

- Do not invent details not present in the input data.
- Do not speculate about civilian casualties or political consequences beyond what the kinetic data provides.
- Do not use the word "cyber" more than twice.
- Do not start every brief with "Following..." — vary your opening structure across briefs.
"""


# ---------------------------------------------------------------------------
# Build per-call user message
# ---------------------------------------------------------------------------

def build_user_message(city_name, city_data, period_label, period_meta):
    period_data = city_data["periods"].get(period_label, {})
    events = [
        e for e in city_data.get("events", [])
        if abs((datetime.date.fromisoformat(e["event_date"])
              - datetime.date.fromisoformat(period_meta["date"])).days) <= 14
    ]

    # Peer count snapshot (mean over ±7d of period date)
    period_date = datetime.date.fromisoformat(period_meta["date"])
    peer_window = [
        p for p in city_data.get("peer_timeline", [])
        if abs((datetime.date.fromisoformat(p["date"]) - period_date).days) <= 7
    ]
    peer_mean = (
        round(sum(p["peers"] for p in peer_window) / len(peer_window), 1)
        if peer_window else None
    )

    # Pre-period peer baseline (30 days before)
    baseline_window = [
        p for p in city_data.get("peer_timeline", [])
        if 14 <= (period_date - datetime.date.fromisoformat(p["date"])).days <= 44
    ]
    peer_baseline = (
        round(sum(p["peers"] for p in baseline_window) / len(baseline_window), 1)
        if baseline_window else None
    )

    return f"""Brief request:

City: {city_name}
City AS: AS{city_data['asn']}
Period: {period_meta['description']} ({period_meta['date']})

BGP signal in 1-hour observation window:
- BGP UPDATE messages observed: {period_data.get('update_count', 0)}
- AS path classifications: {json.dumps(period_data.get('classifications', {}))}
- Sample AS paths (transit shown left-to-right toward city AS):
{chr(10).join(f"  • {p}" for p in period_data.get('sample_paths', [])[:4]) or "  (none)"}

Peer visibility (RIPE NCC):
- ~14 days before period: {peer_baseline if peer_baseline is not None else 'unknown'} peers
- During period (±7d):    {peer_mean if peer_mean is not None else 'unknown'} peers

Kinetic events from ACLED (±14 days from period date):
{chr(10).join(f"  • {e['event_date']}: {e['event_type']} / {e['sub_event']} — {e['notes'][:160]}" for e in events) or "  (no kinetic events recorded in window)"}

Generate the brief paragraph now."""


# ---------------------------------------------------------------------------
# LLM mode — Anthropic API with prompt caching
# ---------------------------------------------------------------------------

def generate_via_api(bundle):
    try:
        import anthropic
    except ImportError:
        sys.exit("anthropic SDK not installed. Run: pip install anthropic")

    client = anthropic.Anthropic()
    briefs = {}
    total_cache_reads = 0
    total_cache_writes = 0
    total_input = 0
    total_output = 0

    cities  = list(bundle["cities"].items())
    periods = bundle["periods"]
    n_total = len(cities) * len(periods)
    i = 0

    for city_name, city_data in cities:
        briefs[city_name] = {}
        for period_meta in periods:
            i += 1
            label = period_meta["label"]
            print(f"  [{i}/{n_total}] {city_name} / {label}")

            user_msg = build_user_message(city_name, city_data, label, period_meta)

            try:
                resp = client.messages.create(
                    model=MODEL,
                    max_tokens=512,
                    output_config={"effort": "medium"},
                    cache_control={"type": "ephemeral"},
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": user_msg}],
                )
            except Exception as e:
                print(f"  [api-err] {e}")
                briefs[city_name][label] = f"[Brief generation failed: {e}]"
                continue

            text = next(
                (b.text for b in resp.content if b.type == "text"),
                ""
            ).strip()
            briefs[city_name][label] = text

            u = resp.usage
            total_cache_reads  += getattr(u, "cache_read_input_tokens",     0) or 0
            total_cache_writes += getattr(u, "cache_creation_input_tokens", 0) or 0
            total_input  += u.input_tokens
            total_output += u.output_tokens

            time.sleep(0.2)  # gentle pacing

    print(f"\n[token usage]")
    print(f"  uncached input:    {total_input}")
    print(f"  cache writes:      {total_cache_writes}")
    print(f"  cache reads:       {total_cache_reads}")
    print(f"  output tokens:     {total_output}")
    if total_cache_reads > 0:
        print(f"  ✓ caching active — saved ~{total_cache_reads} tokens at ~10x discount")
    elif total_cache_writes > 0:
        print(f"  ⚠ system prompt below cache threshold (need ~4096 tokens for Opus); "
              f"first call wrote cache but subsequent didn't read")
    else:
        print(f"  ⚠ no caching observed")

    return briefs


# ---------------------------------------------------------------------------
# Template mode — deterministic fallback if no API key
# ---------------------------------------------------------------------------

def generate_via_template(bundle):
    """Produce structured briefs from data alone — no LLM needed."""
    briefs = {}
    for city_name, city_data in bundle["cities"].items():
        briefs[city_name] = {}
        for period_meta in bundle["periods"]:
            label = period_meta["label"]
            pd = city_data["periods"].get(label, {})
            updates = pd.get("update_count", 0)
            classes = pd.get("classifications", {})

            period_date = datetime.date.fromisoformat(period_meta["date"])
            peer_window = [
                p for p in city_data.get("peer_timeline", [])
                if abs((datetime.date.fromisoformat(p["date"]) - period_date).days) <= 7
            ]
            peer_mean = (
                round(sum(p["peers"] for p in peer_window) / len(peer_window), 0)
                if peer_window else None
            )

            events = [
                e for e in city_data.get("events", [])
                if abs((datetime.date.fromisoformat(e["event_date"]) - period_date).days) <= 14
            ]

            asn = city_data["asn"]
            ev_summary = (
                f"Kinetic activity ({len(events)} ACLED events in ±14d window) "
                f"includes: " + "; ".join(f"{e['event_date']} {e['sub_event']}" for e in events[:2])
                if events else
                "No kinetic events recorded in this window."
            )
            peer_str = (
                f"RIPE NCC peer visibility averaged ~{peer_mean:.0f} peers."
                if peer_mean else "Peer visibility data unavailable."
            )

            paragraph = (
                f"During the '{period_meta['description']}' window ({period_meta['date']}), "
                f"AS{asn} ({city_name}) registered {updates} BGP UPDATE messages in a 1-hour "
                f"observation period. AS path classification breakdown: "
                f"{', '.join(f'{v} {k}' for k,v in classes.items()) or 'no records'}. "
                f"{peer_str} {ev_summary} "
                f"From a wargaming perspective, this period should be modeled as a "
                f"{'high-instability cyber-contested' if updates > 100 else 'low-activity'} "
                f"window for {city_name}."
            )
            briefs[city_name][label] = paragraph
    return briefs


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=== LLM Brief Generator ===\n")

    if not os.path.exists(BUNDLE):
        sys.exit(f"Bundle not found: {BUNDLE}\nRun build_frontend_bundle.py first.")
    with open(BUNDLE) as f:
        bundle = json.load(f)

    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()

    if api_key:
        print(f"[mode] LLM via Anthropic API ({MODEL})\n")
        briefs = generate_via_api(bundle)
    else:
        print("[mode] Deterministic template (no ANTHROPIC_API_KEY set)")
        print("       To use the LLM: export ANTHROPIC_API_KEY=sk-ant-... and re-run\n")
        briefs = generate_via_template(bundle)

    bundle["briefs"] = briefs
    bundle["briefs_generated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    bundle["briefs_mode"] = "llm" if api_key else "template"

    with open(BUNDLE, "w") as f:
        json.dump(bundle, f, indent=2)
    print(f"\n[saved] {BUNDLE}")

    if os.path.isdir(os.path.dirname(FRONTEND)):
        with open(FRONTEND, "w") as f:
            json.dump(bundle, f, indent=2)
        print(f"[saved] {FRONTEND}")

    n = sum(len(v) for v in briefs.values())
    print(f"\n[done] generated {n} briefs across {len(briefs)} cities")
    print(f"\n=== Sample brief (Mariupol / mariupol_siege_2022) ===")
    sample = briefs.get("Mariupol", {}).get("mariupol_siege_2022", "")
    print(sample if sample else "  (no sample available)")


if __name__ == "__main__":
    main()
