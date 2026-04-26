# Cyber Terrain Mapper

## SCSP Hackathon 2026 — Team Cortex — Wargaming Track

> A real-time intelligence tool that maps how BGP routing reshapes itself
> around active conflicts — and produces actionable mitigation guidance for
> any AS operator caught in the path of state-controlled transit.

![Track: Wargaming](https://img.shields.io/badge/SCSP--track-Wargaming-yellow)
![Data: live](https://img.shields.io/badge/data-RIPE%20NCC%20%2B%20ACLED%20live-green)
![Conflicts: 5](https://img.shields.io/badge/active%20conflicts-5-red)

---

## The problem

In modern warfare, **physical occupation is immediately followed by digital
annexation**. When adversarial forces capture territory, they weaponize the
internet's routing architecture (BGP — Border Gateway Protocol) to forcibly
reroute civilian and strategic communications through their own sovereign
infrastructure. Once rerouted, all unencrypted traffic is subjected to state
surveillance regimes (Russia's SORM, Iran's TIC DPI, China's MSS access
mandates) — fundamentally altering the intelligence landscape.

Traditional wargames model **physical** terrain (rivers, ridges, chokepoints).
None model **cyber terrain**. Wargame analysts and policy researchers must
manually parse BGP routing-research blogs months after an event occurs. There
is no rapid, on-demand capability to visualize how physical maneuvers alter
digital information flows in real time.

## What we built

**Cyber Terrain Mapper** is an intelligence platform that ingests live
internet routing data, cross-references it with geocoded armed-conflict
events, and produces per-city **cyber-terrain threat scores** with
actionable BGP-defense recommendations.

It is built around five active conflicts:

| Conflict | Threat actor | Target operators monitored |
|---|---|---|
| 🇷🇺🇺🇦 Russia ↔ Ukraine | Russian Federation (SORM-3 / FZ-374) | Datagroup, Ukrtelecom, Triolan, Maxnet, Cosmonova, KhersonNet |
| 🇨🇳🇹🇼 China ↔ Taiwan | PRC state operators (China Telecom, Unicom, Mobile) | Chunghwa, Taiwan Mobile, Sparq, Taiwan Fixed Network, ASNet |
| 🇲🇲 Myanmar civil war | Tatmadaw junta + Mytel | MPT Myanmar, Mytel, Telecom Intl Myanmar, Yatanarpon |
| 🇸🇩 Sudan civil war | RSF / SAF / regional re-routing | Sudatel, MTN Sudan, Zain Sudan |
| 🇮🇷🇾🇪 Iran proxy network | Iran TIC, IRGC, Houthi-aligned routing | Yemen YemenNet, Iraq EarthLink, Iran TIC |

The same methodology can be applied to any conflict in the world — the
data layer is generic.

---

## Architecture

```
   ┌──────────────────────────────────────────────────────────────────┐
   │                      DATA LAYER (Python)                          │
   │                                                                   │
   │  RIPE NCC RIS  ──▶  MRT BGP UPDATE files (rrc15/rrc16/rrc18)      │
   │  RIPE Stat API ──▶  asn-neighbours, routing-history, as-overview  │
   │  ACLED API     ──▶  137K geocoded kinetic events (Ukraine)        │
   │  UCDP GED v25  ──▶  Global event coverage (other conflicts)       │
   │                                                                   │
   │      │                                                            │
   │      ▼                                                            │
   │  ┌──────────────────────────────────────────────────────────┐     │
   │  │  Per-scenario assessment                                  │     │
   │  │  • Threat-score formula (4 components, 0-100)             │     │
   │  │  • Adversarial AS adjacency detection                     │     │
   │  │  • Path-taint propagation through observed BGP samples    │     │
   │  │  • Chokepoint analysis (Brandes' betweenness centrality)  │     │
   │  │  • Mitigation playbook (11 measures, RFC-cited)           │     │
   │  └──────────────────────────────────────────────────────────┘     │
   │      │                                                            │
   │      ▼                                                            │
   │  cyber_terrain.json (~3.8 MB single-file bundle)                  │
   └──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │                    PRESENTATION LAYER (React + Leaflet)          │
   │                                                                   │
   │   ┌─ Header ──────────────────────────────────────────────────┐   │
   │   │  Cyber Terrain Mapper · 5 conflicts · 27 cities · 137K    │   │
   │   │  ── 6 KPI tiles ─────────────────────────────────────     │   │
   │   │  Avg threat | Cities at severe+ | Cities dark | …         │   │
   │   └────────────────────────────────────────────────────────────┘   │
   │   ┌─ Scenario picker (tabs) ─────────────────────────────────┐    │
   │   │  🌐 Global Overview  🇷🇺🇺🇦 RU↔UA  🇨🇳🇹🇼 CN↔TW  🇲🇲 …      │    │
   │   └───────────────────────────────────────────────────────────┘   │
   │   ┌── City picker ──┐  ┌── Satellite map ──┐  ┌── Brief ────┐    │
   │   │ Mariupol  62 ●  │  │  ESRI World Image │  │ Threat: 62  │    │
   │   │ Kharkiv   44 ●  │  │  AS path overlay  │  │ Adversaries │    │
   │   │ Kherson   14 ●  │  │  Live event ring  │  │ AS paths    │    │
   │   └─────────────────┘  └───────────────────┘  │ Brief (LLM) │    │
   │                          ┌── Timeline ──┐     │ Chokepoints │    │
   │                          │ Scrubber + …  │    │ Mitigations │    │
   │                          └───────────────┘    └─────────────┘    │
   └──────────────────────────────────────────────────────────────────┘
```

---

## What's distinctive

### Real data, end to end

| Layer | Source |
|---|---|
| BGP UPDATE messages | RIPE NCC RIS — actual MRT files from `rrc15` (Kiev), `rrc16` (Hamburg), `rrc18` (Moscow). 580+ records, hour-resolution, real Russian-routed paths observed |
| AS adjacency graphs | RIPE Stat `asn-neighbours` — every transit relationship for every target city's AS |
| Peer visibility timelines | RIPE Stat `routing-history` — peer-count time series showing the "Mariupol cliff" (354 → 42 peers during siege) |
| Kinetic events | **ACLED API live** (Ukraine, 137,388 events) + UCDP GED v25.1 (other conflicts) |
| ASN classification | RIPE Stat `as-overview` + `rir-stats-country` — 240 ASes geolocated |

No mocks. No simulated data. Everything you see is the actual state of
internet routing observed by RIPE NCC's collectors.

### Cyber-Terrain Threat Score (0–100)

A transparent, defensible composite score with four components:

| Component | Weight | What it measures |
|---|---|---|
| Blackout signal | 40 pts | Peer-count drop magnitude + sustained low peer floor |
| Routing instability / kinetic intensity | 25 pts | BGP UPDATE volume (Ukraine) or local kinetic event density (other) |
| Adversarial routing | 25 pts | Direct adjacency to known state-controlled adversary ASes |
| Intercept exposure | 10 pts | SORM/DPI/MSS-mandated access among observed transit |

Levels: 0–29 nominal · 30–59 elevated · 60–79 severe · 80–100 critical.

### Network resilience analysis (chokepoints)

Real graph-theory: **Brandes' betweenness centrality** restricted to
peer→target shortest paths. Identifies which transit ASes are critical
chokepoints, separately flagging adversarial ones. Russia-Ukraine result
(from real MRT graph): AS3356 Lumen at centrality 100, AS174 Cogent at 96,
**AS9002 RETN (Russia-CIS backbone) carries 53 peer→target shortest paths
— removing it forces all of them to re-route.**

### BGP Attack Mitigation Playbook

11 documented measures with stakeholder, complexity, deployment timeframe,
and RFC/MANRS citations. Per city, the recommended order is **derived from
the specific threats observed** — e.g. Mariupol's blackout signal triggers
LEO-satellite (Starlink) and transit-diversity recommendations first;
Taipei's PRC adjacency triggers AS_PATH filtering and ECH/DoH first.

### Multi-scenario, single render path

Every conflict tab uses **the same** UI: city picker, satellite map with
auto-recentering, timeline scrubber with peer sparkline, brief panel with
threat/chokepoints/mitigations. Map labels (Russian / PRC / Iranian / Junta /
Cross-border) and date ranges adapt per scenario. No scenario is a
second-class citizen.

---

## Why this fits the Wargaming track

The SCSP brief asks teams to *"transform wargaming from a static, episodic
event into a rapid, on-demand capability that matches the speed of modern
conflict."*

Cyber Terrain Mapper does this by:

1. **Multi-domain synchronization** — bridges physical military maneuvers
   (ACLED data) with digital infrastructure consequences (BGP data).
2. **National impact** — same methodology applied to **5 active conflicts**
   plus a Taiwan-Strait contingency, with explicit US-relevance framing.
3. **Operational productisation** — every assessment exports as Markdown
   (analyst-readable) + JSON (downstream wargame tooling), with documented
   schema.
4. **Defense, not just observation** — every threat surface comes with
   specific, RFC-cited mitigations a real operator can deploy in days/weeks.

---

## Project layout

```
scsp-hacks-2026/
├── data_collection/                  Python data layer
│   ├── scenarios.py                  Per-conflict configuration
│   ├── mitigations.py                BGP-defense playbook (11 measures)
│   ├── fetch_acled_events.py         ACLED OAuth client + UCDP CSV loader
│   ├── collect_bgp_data.py           RIPE NCC MRT downloader + parser (Ukraine)
│   ├── lookup_asn_geolocation.py     ASN → country/coords via RIPE Stat
│   ├── compute_chokepoints.py        Brandes' betweenness centrality
│   ├── correlate_events_bgp.py       Joint kinetic + BGP timeline
│   ├── build_global_scenarios.py     Per-scenario assessment runner
│   ├── build_frontend_bundle.py      Final cyber_terrain.json assembly
│   ├── generate_briefs.py            Optional LLM-generated narratives
│   ├── acled_data/                   Cached ACLED events + UCDP filtered CSVs
│   ├── mrt_data/                     Raw RIPE NCC RIS MRT files (gitignored)
│   ├── pcap_output/                  Wireshark-compatible BGP captures
│   ├── ripe_stat_cache/              RIPE Stat API response cache (gitignored)
│   └── scenarios_data/               Per-scenario JSON outputs
│
├── frontend/                         React + Vite + TypeScript
│   ├── src/
│   │   ├── App.tsx                   Top-level orchestrator
│   │   ├── components/
│   │   │   ├── ScenarioPicker.tsx    Tabs across active conflicts
│   │   │   ├── GlobalOverview.tsx    World map landing view
│   │   │   ├── CityPicker.tsx        Per-scenario city list with threat badges
│   │   │   ├── MapView.tsx           Satellite map + AS path overlay
│   │   │   ├── TimelineScrubber.tsx  Peer-count sparkline + event pips
│   │   │   ├── BriefPanel.tsx        Threat score + components + brief
│   │   │   ├── MitigationPanel.tsx   Per-city mitigation recommendations
│   │   │   ├── ChokepointPanel.tsx   AS centrality leaderboard
│   │   │   ├── HeadlineKPIs.tsx      Aggregated stats bar
│   │   │   └── ExportButton.tsx      Markdown + JSON downloads
│   │   ├── lib/dates.ts              Scenario-aware date helpers
│   │   └── types.ts                  Full TypeScript surface for the bundle
│   └── public/cyber_terrain.json     Built bundle (regenerated by data layer)
│
└── README.md                         (you are here)
```

---

## How to run it

### 1. Install dependencies

**Python (data layer)** — Python 3.10+ recommended.

```bash
pip install requests mrtparse scapy anthropic
```

**Node.js (frontend)** — Node 20.19+ or 22.13+.

```bash
cd frontend
npm install
```

### 2. (Optional) Configure ACLED API for live event data

ACLED account with API access required. Without it, the system falls back
to UCDP GED v25.1 data (also real, just slower-updating).

```bash
export ACLED_EMAIL="your-email@org"
export ACLED_PASSWORD="your-password"
```

### 3. Build the data bundle

```bash
cd data_collection

# 1) Pull ACLED events (~137K events for Ukraine)
python3 fetch_acled_events.py

# 2) Pull MRT BGP data for Ukraine periods (rrc15/rrc16/rrc18)
python3 collect_bgp_data.py

# 3) Geolocate every ASN we observed
python3 lookup_asn_geolocation.py

# 4) Compute Russia-Ukraine BGP-graph chokepoints
python3 compute_chokepoints.py

# 5) Correlate kinetic events with BGP signal
python3 correlate_events_bgp.py

# 6) Build all scenarios (queries RIPE Stat per scenario AS)
python3 build_global_scenarios.py

# 7) Assemble final bundle for the frontend
python3 build_frontend_bundle.py
```

Each step is idempotent and caches its outputs. Re-runs are fast.

### 4. (Optional) Generate LLM-written briefs

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
python3 generate_briefs.py
```

Without this, briefs are template-generated. With it, Claude Opus 4.7
produces analyst-voice narratives per (city × period).

### 5. Run the frontend

```bash
cd ../frontend
npm run dev
```

Open `http://localhost:5173/`.

For production:

```bash
npm run build
# dist/ contains the static site, ready to deploy on any HTTP host
```

---

## Demo flow (5-minute presentation)

1. **Open**. Landing view is the **🌐 Global Overview** — world map, 27
   cities plotted, right panel shows totals (X critical, Y severe, peak
   threat = ZZ). One screen tells judges the scope.
2. **Click 🇷🇺🇺🇦 Russia ↔ Ukraine tab.** Map flies to Eastern Europe.
   Pick **Mariupol** in the city picker — threat score **62 (severe)**
   surfaces immediately.
3. **Drag the timeline scrubber** from Feb 2022 to Apr 2022. Watch:
   - The peer-visibility sparkline behind the slider drop off a cliff
   - The city marker flip to red `· DARK`
   - A pulsing red ring appear when the scrubber crosses ACLED kinetic
     events
4. **Click the Kharkiv tab on the timeline** — observe the orange
   **adversary-routed path** chevron at Apr 15 2022 (real MRT data showing
   AS9002 RETN in the transit chain).
5. **Scroll the right panel** to the **Network Resilience** section —
   AS3356 Lumen and AS174 Cogent at 100/96 centrality, with the
   adversarial chokepoint AS9002 flagged.
6. **Scroll further** to **BGP Attack Mitigations** — show the recommended
   measures (RPKI ROA, AS_PATH filtering, transit diversity, mTLS) tied to
   the specific threat profile observed for Mariupol.
7. **Click 🇨🇳🇹🇼 China ↔ Taiwan tab** — same UI shape, different threat
   actor. Map flies to East Asia. Taipei AS3462 sits at score 65 with
   3 direct PRC-state-operator adjacencies. Methodology generalizes.
8. **Hit the ⬇ Brief (.md) export button** — analyst-ready Markdown
   downloads. Demonstrates productisation.

---

## Acknowledgements & data sources

- **RIPE NCC** — RIS MRT archives, RIPE Stat API
- **ACLED** (Armed Conflict Location & Event Data Project) — Ukraine event
  data via authenticated API
- **UCDP GED v25.1** (Uppsala Conflict Data Program) — global conflict
  event dataset
- **MaxMind GeoLite2** — ASN database (optional)
- **OpenStreetMap / ESRI World Imagery** — base tiles

This project uses publicly-available, unclassified data sources. No
classified or restricted information was incorporated. Built for the
SCSP Hackathon 2026 Wargaming Track.

---

## Team

**Cortex** — submission for the Wargaming track, SCSP Hackathon 2026.
