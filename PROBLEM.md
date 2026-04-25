


Here is a complete, structured Markdown file. You can drop this directly into your GitHub `README.md`, use it as your hackathon submission document, or share it with your team to build from. 

***

# 🌍 Cyber Terrain Mapper: Real-Time BGP Hijacking & Kinetic Conflict Correlation

## 🚨 The Problem Statement
In modern warfare, physical occupation is immediately followed by digital annexation. When adversarial forces capture physical territory, they weaponize the internet’s routing architecture (BGP - Border Gateway Protocol) to forcibly reroute civilian and strategic communications through their own sovereign infrastructure. 

Once rerouted, all unencrypted traffic is subjected to state surveillance apparatuses (such as Russia's SORM), fundamentally altering the intelligence landscape. 

**The Wargaming Gap:** Traditional wargames and military simulations model physical terrain (rivers, mountains, chokepoints) but completely ignore **cyber terrain**. Currently, wargame analysts and policy researchers must manually parse complex networking blogs months after an event occurs. There is no rapid, on-demand capability to visualize how physical military maneuvers alter digital information flows in real-time.

## 💡 The Solution
**Cyber Terrain Mapper** is an intelligence agent that transforms raw, global internet routing data into actionable cyber-terrain wargaming layers. 

It tracks how packets traveling to/from conflict zones are rerouted through adversarial infrastructure, cross-references these BGP anomalies with live kinetic conflict data, and generates automated, plain-English intelligence briefs about surveillance risks and information isolation.

---

## 🏗 Technical Architecture & Implementation Details

### 1. The Data Stack
The application relies on four distinct public datasets, combined to merge the physical and digital domains:

*   **RIPE Stat API:** Provides historical BGP routing paths (AS Paths) and WHOIS enrichment.
*   **CAIDA pybgpstream:** Python framework for processing live BGP routing data streams globally.
*   **ACLED API (Armed Conflict Location & Event Data):** Provides timestamps and geospatial data of physical military engagements and territorial shifts.
*   **MaxMind GeoLite2:** Maps Autonomous Systems (ASNs) and IP prefixes to physical lat/long coordinates for map visualization.

### 2. Core Workflows & Endpoints

#### A. Historical / Wargame Simulation Mode
Users input a target region (e.g., Kherson) and a timeframe. The backend executes the following:

1.  **Network Pathing:** Queries RIPE Stat to retrieve the Autonomous System (AS) path for the region's IP prefixes.
    *   `GET https://stat.ripe.net/data/bgplay/data.json?resource={prefix}&starttime={start}&endtime={end}`
    *   *Implementation:* Parse the `path` array. Detect anomalies where the terminal ASNs suddenly change country origin.
2.  **Kinetic Correlation:** Queries the ACLED API for the corresponding physical location within a 72-hour window of the BGP anomaly.
    *   `GET https://api.acleddata.com/acled/read?country=Ukraine&location={city_name}&event_date={date_range}`
3.  **Enrichment:** Converts anomalous ASNs into corporate and national entities using RIPE WHOIS.
    *   `GET https://stat.ripe.net/data/whois/data.json?resource={ASN}`

#### B. Live Threat Monitoring Mode
A persistent Python backend worker utilizes `pybgpstream` to monitor global BGP announcements in real-time.
*   *Implementation:* The worker filters the stream for a predefined list of high-risk IP prefixes (e.g., Eastern Ukrainian networks).
*   If a BGP announcement is detected appending a known hostile ASN (e.g., `AS12389` Rostelecom) to a previously neutral route, the backend pushes a WebSocket alert to the frontend.

#### C. LLM Intelligence Generation
Raw JSON routing data and ACLED conflict logs are injected into a Large Language Model (OpenAI/Anthropic) with a specific system prompt to generate a **Cyber Terrain Brief**.

*Example System Prompt:*
```text
You are a Cyber Threat Intelligence analyst briefing a wargame commander. 
You will be provided with BGP routing shifts and physical military conflict data. 
Draft a 1-paragraph brief explaining how the physical conflict resulted in the 
digital rerouting. Identify the newly introduced Autonomous Systems, flag if 
they belong to adversarial states, and assess the surveillance/SORM risk for 
data traveling through this new chokepoint. Keep it tactical and plain-English.
```

---

## 🚀 Proof of Concept: The Fall of Kherson (Demo Walkthrough)

To prove the efficacy of this agent, the MVP is hardcoded to replay the textbook cyber-annexation of Kherson, Ukraine in May 2022.

**Step 1: The Baseline (April 25-29, 2022)**
*   **Visual:** The UI displays a map showing traffic to Kherson (`AS47598`) routing cleanly through standard Ukrainian telecom infrastructure (`AS21219` Datagroup).

**Step 2: Physical Blackout (April 30, 2022)**
*   **Trigger:** ACLED API injects an event: *"Russian forces occupy local ISP facilities in Kherson."*
*   **Visual:** RIPE Stat data shows massive BGP withdrawals. The AS Path breaks. The UI flashes a network blackout.

**Step 3: The Sovereign Reroute (May 1, 2022)**
*   **Trigger:** RIPE Stat data returns online, but the BGP path has fundamentally mutated. 
*   **Visual:** Traffic is now routing through `AS208216` (Miranda Media, Crimea) and terminating in `AS12389` (Rostelecom, Russia).

**Step 4: The Intelligence Output**
*   The LLM agent instantly generates the resulting Cyber Terrain Brief:
> 🚨 **CRITICAL CYBER TERRAIN SHIFT: KHERSON**
> *Following the kinetic occupation of local ISP facilities reported on April 30, traffic for Khersontelecom (AS47598) has been forcibly rerouted through Russian state provider Rostelecom (AS12389). All unencrypted communications originating from or destined for this region are now traversing Russian sovereign infrastructure and are legally subject to SORM-3 lawful intercept obligations.*

---

## 🏆 Why This Fits the Wargaming Track
*"Transform wargaming from a static, episodic event into a rapid, on-demand capability that matches the speed of modern conflict."*

1.  **Multi-Domain Synchronization:** We are bridging the gap between physical military maneuvers (ACLED data) and digital infrastructure consequences (BGP data).
2.  **Novelty:** While other submissions will build LLMs that play military strategy board games, we are mapping the actual, real-world invisible terrain of information warfare.
3.  **National Impact:** Understanding how adversaries fragment the internet to enforce digital sovereignty and surveillance is a top priority for US intelligence, CISA, and the State Department. 

---

## 🛠 Tech Stack Overview
*   **Frontend:** React, TailwindCSS, MapboxGL / Leaflet (Geospatial AS Path visualization)
*   **Backend:** FastAPI (Python), WebSockets for live alerts
*   **Data Pipelines:** PyBGPStream, Requests (RIPE/ACLED APIs)
*   **AI:** OpenAI API (GPT-4) for intelligence synthesis