# Cyber Terrain Mapper

> A real-time intelligence platform that maps how BGP routing reshapes itself
> around active conflicts, identifies AS-level chokepoints, and produces
> actionable mitigation guidance — including specific defenses against GenAI
> traffic fingerprinting on adversarial transit.

![Track: Wargaming](https://img.shields.io/badge/SCSP--track-Wargaming-yellow)
![Data: live](https://img.shields.io/badge/data-RIPE%20NCC%20%2B%20ACLED%20live-green)
![Conflicts: 5](https://img.shields.io/badge/active%20conflicts-5-red)

---

## Submission metadata

| Field | Value |
|---|---|
| **Team name** | Cortex |
| **Track** | Wargaming |
| **Team members** | Mithran Mohanraj · Mohamed Shaik · Vinay Jagan · Vemula Shresta |
| **Project name** | Cyber Terrain Mapper |
| **Repository** | https://github.com/mithranm/scsp-hacks-2026 |
| **Live demo** | **https://3dd1-2600-1700-a0-32f0-611f-2df6-5f3e-f7ba.ngrok-free.app/** |

---

## 🚀 Try it live

**Open the live application:**
**https://3dd1-2600-1700-a0-32f0-611f-2df6-5f3e-f7ba.ngrok-free.app/**

No install required — the URL above serves the running Cyber Terrain
Mapper directly. Click any conflict tab (Russia↔Ukraine, China↔Taiwan,
Myanmar, Sudan, Iran↔Yemen) to load its city threat scores, satellite
map, AS path overlays, and BGP-defense recommendations.

> If the link is unreachable, the ngrok tunnel may have rotated. Run
> the project locally instead — see the *How to run it* section below.

---

## What we built

**Cyber Terrain Mapper** is a multi-conflict intelligence platform that
fuses real-time BGP routing data, geocoded armed-conflict events, and
AS-level adjacency analysis into a single wargame-ready surface. It is
built around five active conflicts:

| Conflict | Threat actor | Target operators monitored |
|---|---|---|
| 🇷🇺🇺🇦 Russia ↔ Ukraine | Russian Federation (SORM-3 / FZ-374) | Datagroup, Ukrtelecom, Triolan, Maxnet, Cosmonova, KhersonNet |
| 🇨🇳🇹🇼 China ↔ Taiwan | PRC state operators (China Telecom, Unicom, Mobile) | Chunghwa, Taiwan Mobile, Sparq, Taiwan Fixed Network, ASNet |
| 🇲🇲 Myanmar civil war | Tatmadaw junta + Mytel | MPT Myanmar, Mytel, Telecom Intl Myanmar, Yatanarpon |
| 🇸🇩 Sudan civil war | RSF / SAF / regional re-routing | Sudatel, MTN Sudan, Zain Sudan |
| 🇮🇷🇾🇪 Iran proxy network | Iran TIC, IRGC, Houthi-aligned routing | YemenNet, Iraq EarthLink, Iran TIC |

The methodology is generic — adding a new conflict is a config edit, not
a code change.

### Core capabilities

1. **Per-city Cyber-Terrain Threat Score (0–100).** Composite of four
   transparent components: blackout signal (peer-count drop), routing
   instability or kinetic-event density, adversarial-AS adjacency, and
   intercept exposure (SORM / DPI / MSS-mandated access).
2. **Real BGP UPDATE samples** parsed from RIPE NCC RIS MRT files
   (rrc15 Kiev, rrc16 Hamburg, rrc18 Moscow). 580+ records show real
   Russian-routed paths through AS9002 (RETN) toward Ukrainian targets.
3. **Network resilience analysis** using Brandes' betweenness centrality
   — identifies that AS3356 (Lumen) and AS174 (Cogent) are #1/#2
   chokepoints, while AS9002 (RETN) is the top adversarial chokepoint
   carrying 53 peer→target shortest paths.
4. **GenAI traffic-fingerprinting exposure assessment.** Trained ML
   classifiers (Random Forest, BiLSTM, Transformer, CNN-LSTM, Ensemble,
   TabPFN) achieve **~89% accuracy** distinguishing GenAI traffic
   (ChatGPT, Gemini, Grok, Perplexity) from regular traffic from packet
   metadata alone — meaning DPI on adversarial transit can selectively
   block or surveil AI use without breaking encryption. Each city's
   GenAI exposure score quantifies this risk.
5. **BGP-defense playbook** with 14 documented mitigations (RPKI, ROV,
   AS_PATH filtering, transit diversity, IXP peering, mTLS/DoH, LEO
   satellite, MANRS, ASPA/BGPsec, RIS Live monitoring, traffic padding,
   VPN tunneling, on-prem AI, RIR diplomatic petition). Each carries
   stakeholder, complexity, deployment timeframe, and RFC/MANRS
   citations. Recommendations per city are **derived from the specific
   threats observed**.
6. **Multi-conflict UI with single render path.** All five conflicts use
   the same satellite map / scrubber / brief panel. Map auto-recenters
   per scenario; legend labels adapt per threat actor.

---

## Datasets and APIs used

| Source | Used for | Auth |
|---|---|---|
| **RIPE NCC RIS** (data.ris.ripe.net) | Raw MRT BGP UPDATE files from `rrc15`, `rrc16`, `rrc18` collectors. 580+ BGP records, hour-resolution. | Public, no auth |
| **RIPE Stat API** (stat.ripe.net) | `asn-neighbours`, `routing-history`, `as-overview`, `rir-stats-country`. 240 ASes geolocated; peer-visibility timelines per prefix. | Public, no auth |
| **ACLED API** (acleddata.com) | Live geocoded armed-conflict events for Ukraine — **137,388 events** Oct 2021 → Dec 2024 across 10 cities (Kyiv, Kharkiv, Mariupol, Kherson, Donetsk, Luhansk, Zaporizhia, Odessa, Dnipro, Mykolaiv). | OAuth (myACLED account with API access) |
| **UCDP GED v25.1** (Uppsala University) | Global geocoded conflict events for non-Ukraine scenarios (Sudan, Myanmar, Yemen). 250 MB CSV, filtered per scenario. | Public download |
| **MaxMind GeoLite2** | ASN database (optional, used by GenAI fingerprinting feature extractor). | Free with registration |
| **ESRI World Imagery** + **OpenStreetMap** | Satellite basemap and labels for the React frontend. | Public tile servers |
| **Anthropic API** (Claude Opus 4.7) | Optional LLM-generated cyber-terrain narratives per (city × period). | API key |

All data sources used are public or licensed for the team's use. No
classified information was incorporated.

### GenAI fingerprinting dataset

PCAP captures of network traffic from four GenAI services (ChatGPT,
Gemini, Grok, Perplexity) plus regular non-GenAI baseline traffic.
Feature extraction via `scapy` produces a `features.csv` with
~120 statistical features per session (packet inter-arrival times,
burst sizes, payload entropy, wavelet decompositions, TCP-flag
distributions). Trained over 5-fold cross-validation; full per-fold
classification reports are persisted in
`genai-fingerprinting/results/`.

| Model | Accuracy (5-fold CV) | F1 |
|---|---|---|
| **CNN-LSTM** | **0.894 ± 0.028** | **0.893 ± 0.028** |
| **Ensemble (stacking)** | **0.894 ± 0.022** | **0.893 ± 0.023** |
| Random Forest | 0.866 ± 0.033 | 0.865 ± 0.034 |
| Gradient Boosting | 0.871 ± 0.014 | 0.871 ± 0.015 |
| Transformer | 0.810 ± 0.064 | 0.808 ± 0.067 |

The 89% accuracy result feeds back into the cyber-terrain threat model:
when a city's traffic transits an adversarial DPI-capable AS, the
exposure assessment cites this measured fingerprint accuracy as
evidence of selective-surveillance feasibility.

---

## Architecture

```
   ┌──────────────────────────────────────────────────────────────────┐
   │                     DATA LAYER (Python)                           │
   │                                                                   │
   │  RIPE NCC RIS  ──▶  MRT BGP UPDATE files (rrc15/rrc16/rrc18)      │
   │  RIPE Stat API ──▶  asn-neighbours, routing-history, as-overview  │
   │  ACLED API     ──▶  137K geocoded kinetic events (Ukraine)        │
   │  UCDP GED v25  ──▶  Global event coverage (other conflicts)       │
   │  PCAP captures ──▶  GenAI traffic feature extraction (scapy)      │
   │      │                                                            │
   │      ▼                                                            │
   │  ┌──────────────────────────────────────────────────────────┐    │
   │  │  Per-scenario assessment                                  │    │
   │  │  • Threat-score formula (4 components, 0-100)             │    │
   │  │  • Adversarial AS adjacency detection                     │    │
   │  │  • Brandes' betweenness chokepoint analysis               │    │
   │  │  • GenAI exposure (routing × DPI × fingerprint accuracy)  │    │
   │  │  • Mitigation playbook (14 measures, RFC-cited)           │    │
   │  └──────────────────────────────────────────────────────────┘    │
   │      │                                                            │
   │      ▼                                                            │
   │  cyber_terrain.json (~3.8 MB single-file bundle)                  │
   └──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │                   PRESENTATION LAYER (React + Leaflet)           │
   │                                                                   │
   │   ┌─ Header + 6 KPI tiles ─────────────────────────────────┐     │
   │   │  Cyber Terrain Mapper · 5 conflicts · 27 cities · …    │     │
   │   └─────────────────────────────────────────────────────────┘    │
   │   ┌─ Scenario picker (tabs sorted by max threat) ─────────┐     │
   │   │  🌐 Global · 🇷🇺🇺🇦 RU↔UA · 🇨🇳🇹🇼 CN↔TW · 🇲🇲 · 🇸🇩 · 🇮🇷🇾🇪 │     │
   │   └─────────────────────────────────────────────────────────┘    │
   │   ┌── City picker ──┐  ┌── Map ──┐  ┌── Brief panel ─────┐      │
   │   │ Mariupol  62 ●  │  │ Sat. +  │  │ Threat 62/100      │      │
   │   │ Kharkiv   44 ●  │  │ AS path │  │ Adv. adjacencies   │      │
   │   │ …               │  │ overlay │  │ Sample AS paths    │      │
   │   └─────────────────┘  └─────────┘  │ GenAI exposure     │      │
   │                       ┌─ Timeline ─┐│ Chokepoint table   │      │
   │                       │ Scrubber + ││ Mitigation playbook│      │
   │                       │ events     ││ Export Markdown/JSON│     │
   │                       └────────────┘└────────────────────┘      │
   └──────────────────────────────────────────────────────────────────┘
```

---

## Cyber-Terrain Threat Score

| Component | Weight | What it measures |
|---|---|---|
| Blackout signal | 40 pts | Peer-count drop magnitude + sustained low peer floor |
| Routing instability / kinetic intensity | 25 pts | BGP UPDATE volume (Ukraine) or local kinetic event density (other) |
| Adversarial routing | 25 pts | Direct adjacency to known state-controlled adversary ASes |
| Intercept exposure | 10 pts | SORM/DPI/MSS-mandated access among observed transit |

**Levels:** 0–29 nominal · 30–59 elevated · 60–79 severe · 80–100 critical.

A second derived score — **GenAI Exposure** — combines routing exposure
(% paths through adversary AS) with the adversary's measured DPI
capability score (0–100) and our fingerprint-classifier accuracy (0.89).
Cities scoring high on both Cyber-Terrain and GenAI exposure are flagged
as locations where selective AI-service surveillance is feasible
*without* requiring TLS interception.

---

## How to run it

### Prerequisites

- **Python 3.10+** (3.12 tested)
- **Node.js 20.19+** (or 22.13+ / 24.x)
- ~2 GB free disk for caches and MRT downloads

### 1. Install dependencies

```bash
# Python (data layer + GenAI fingerprinting)
pip install -r requirements.txt
pip install requests mrtparse scapy anthropic

# Node (frontend)
cd frontend
npm install
```

### 2. (Optional) Configure live API access

```bash
export ACLED_EMAIL="your-email@org"        # for live ACLED events
export ACLED_PASSWORD="your-password"
export ANTHROPIC_API_KEY="sk-ant-..."      # for LLM-written briefs
```

Without ACLED creds, the system falls back to the UCDP GED v25.1
dataset (also real, just slower-updating). Without Anthropic key,
briefs are template-generated.

### 3. Build the data bundle

```bash
cd data_collection

# 1) ACLED kinetic events (Oct 2021 → Dec 2024)
python3 fetch_acled_events.py

# 2) RIPE NCC RIS MRT downloads + BGP UPDATE parsing for Ukraine
python3 collect_bgp_data.py

# 3) ASN geolocation via RIPE Stat
python3 lookup_asn_geolocation.py

# 4) Brandes' betweenness centrality on the BGP graph
python3 compute_chokepoints.py

# 5) Joint kinetic + BGP correlation timeline
python3 correlate_events_bgp.py

# 6) Per-conflict scenario assessments (5 scenarios)
python3 build_global_scenarios.py

# 7) (Optional) LLM-generated narratives (requires ANTHROPIC_API_KEY)
python3 generate_briefs.py

# 8) Assemble the final cyber_terrain.json bundle
python3 build_frontend_bundle.py
```

Each step caches its outputs (in `acled_data/`, `mrt_data/`,
`ripe_stat_cache/`, `scenarios_data/`). Re-runs are fast.

### 4. (Optional) Train GenAI fingerprinting models

```bash
cd genai-fingerprinting

# Feature extraction from PCAPs → processed/features.csv (run once)
python3 preprocessing/feature_extraction.py

# Train a single model
python3 models/baseline/training.py       # RF + Gradient Boosting + XGBoost + LightGBM
python3 models/transformer/training.py    # Transformer
python3 models/bilstm/training.py         # BiLSTM
python3 models/cnn_lstm/training.py       # CNN-LSTM (best single model)
python3 models/ensemble/training.py       # Learned stacking ensemble
python3 models/tabpfn/training.py         # TabPFN

# Or run the full pipeline end-to-end
python3 run_pipeline.py
```

Results land in `genai-fingerprinting/results/` (per-fold reports +
CV summary). Best single model: **CNN-LSTM at 0.894 accuracy**;
stacking ensemble matches.

### 5. Run the frontend

```bash
cd frontend
npm run dev      # development with HMR at http://localhost:5173/
# or
npm run build    # production build → dist/
```

The frontend loads `public/cyber_terrain.json` (the bundle from
step 3.8) and renders the full UI client-side. No backend required at
runtime.

---

## Project layout

```
scsp-hacks-2026/
├── data_collection/                  Python data layer
│   ├── scenarios.py                  Per-conflict configuration
│   ├── mitigations.py                BGP-defense playbook (14 measures)
│   ├── fetch_acled_events.py         ACLED OAuth client + UCDP CSV loader
│   ├── collect_bgp_data.py           RIPE NCC MRT downloader + parser
│   ├── lookup_asn_geolocation.py     ASN → country/coords via RIPE Stat
│   ├── compute_chokepoints.py        Brandes' betweenness centrality
│   ├── correlate_events_bgp.py       Joint kinetic + BGP timeline
│   ├── build_global_scenarios.py     Per-scenario assessment runner
│   ├── build_frontend_bundle.py      Final cyber_terrain.json assembly
│   ├── generate_briefs.py            Optional LLM narratives
│   ├── acled_data/                   Cached ACLED + UCDP filtered CSVs
│   ├── mrt_data/                     Raw RIPE NCC RIS MRT files (gitignored)
│   ├── pcap_output/                  Wireshark-compatible BGP captures
│   ├── ripe_stat_cache/              RIPE Stat API responses (gitignored)
│   └── scenarios_data/               Per-scenario JSON outputs
│
├── genai-fingerprinting/             ML traffic-classification subsystem
│   ├── preprocessing/                scapy-based feature extraction
│   ├── models/                       baseline / bilstm / cnn_lstm /
│   │                                 transformer / ensemble / tabpfn
│   ├── results/                      Per-fold CV reports
│   ├── figures/                      Confusion matrices, F1 plots
│   ├── visualizations/               Training-curve generators
│   ├── processed/features.csv        Extracted feature matrix
│   └── run_pipeline.py               End-to-end training pipeline
│
├── frontend/                         React + Vite + TypeScript
│   ├── src/
│   │   ├── App.tsx                   Top-level orchestrator
│   │   ├── components/
│   │   │   ├── ScenarioPicker.tsx    Per-conflict tabs with flag pairs
│   │   │   ├── GlobalOverview.tsx    World-map landing view
│   │   │   ├── CityPicker.tsx        Per-scenario city list + threat badges
│   │   │   ├── MapView.tsx           Satellite map + AS path overlay
│   │   │   ├── TimelineScrubber.tsx  Peer sparkline + event pips
│   │   │   ├── BriefPanel.tsx        Threat score + components + brief
│   │   │   ├── GenAIExposurePanel.tsx Per-city GenAI risk readout
│   │   │   ├── MitigationPanel.tsx   14-measure playbook UI
│   │   │   ├── ChokepointPanel.tsx   AS centrality leaderboard
│   │   │   ├── HeadlineKPIs.tsx      Aggregated stats bar
│   │   │   └── ExportButton.tsx      Markdown + JSON downloads
│   │   ├── lib/dates.ts              Scenario-aware date helpers
│   │   └── types.ts                  TypeScript surface for the bundle
│   └── public/cyber_terrain.json     Built bundle (regenerated by data layer)
│
├── PROBLEM.md                        Original problem statement
├── ACLED.md                          ACLED API reference
├── RIPE.md                           RIPE Stat API reference
├── requirements.txt                  Python dependencies
└── README.md                         (you are here)
```

---

## How this fits the Wargaming track

The SCSP brief asks teams to *"transform wargaming from a static,
episodic event into a rapid, on-demand capability that matches the speed
of modern conflict."* Cyber Terrain Mapper does this by:

1. **Multi-domain synchronization** — bridges physical military
   maneuvers (ACLED kinetic data) with digital infrastructure
   consequences (BGP routing).
2. **National impact** — same methodology applied to **5 active
   conflicts** plus a Taiwan-Strait contingency, with explicit
   US-relevance framing for SIGINT and CISA stakeholders.
3. **Operational productisation** — every assessment exports as
   Markdown (analyst-readable) + JSON (downstream wargame tooling)
   with a documented schema.
4. **Defense, not just observation** — every threat surface comes with
   specific, RFC-cited mitigations a real operator can deploy in
   days/weeks. Includes novel GenAI-specific defenses tied to our own
   measured 89% fingerprint accuracy.

---

## Acknowledgements

- **RIPE NCC** — RIS MRT archives, RIPE Stat API
- **ACLED** (Armed Conflict Location & Event Data Project)
- **UCDP GED v25.1** (Uppsala Conflict Data Program)
- **MaxMind GeoLite2** — ASN database
- **OpenStreetMap / ESRI World Imagery** — base tiles
- **MANRS / Cloudflare BGP research** — routing-security best practices
- **PyTorch / scikit-learn / XGBoost / LightGBM / TabPFN** — ML stack
  for GenAI fingerprinting

This project uses publicly-available, unclassified data sources. No
classified or restricted information was incorporated. Built for the
SCSP Hackathon 2026 Wargaming Track.

---

## Team Cortex

- Mithran Mohanraj
- Mohamed Shaik
- Vinay Jagan
- Shresta Vemula
