"""
BGP Attack Mitigation Playbook
Maps observed threat conditions to specific resolution measures.
Citations to MANRS, RFC 8210 (RPKI), RFC 7454 (BGP filtering), and Cloudflare
research are included so downstream wargame analysts have authoritative refs.
"""

# Each measure has:
#   id           – stable identifier
#   title        – short human-readable name
#   tier         – "preventive" | "detective" | "responsive"
#   complexity   – "low" | "medium" | "high"  (operational difficulty)
#   timeframe    – rough deployment time
#   description  – one-paragraph what / why / how
#   stakeholder  – who owns the action (operator | RIR | government | end-user)
#   references   – authoritative citations
MITIGATIONS = {
    "rpki_roa": {
        "title":       "RPKI ROA — sign route origin authorizations",
        "tier":        "preventive",
        "complexity":  "low",
        "timeframe":   "days",
        "stakeholder": "AS operator + RIR",
        "description": (
            "Publish Route Origin Authorizations (ROAs) at your RIR (RIPE/ARIN/APNIC) "
            "cryptographically binding your prefixes to your AS. Combined with ROV "
            "(Route Origin Validation) on upstream, this is the single highest-leverage "
            "defense against prefix hijacking. As of 2024, ~50% of IPv4 prefixes globally "
            "are RPKI-signed; coverage in conflict zones is often <20%."
        ),
        "references": ["RFC 9582", "RFC 8210", "MANRS"],
    },
    "rov_upstream": {
        "title":       "ROV — enable Route Origin Validation on upstream",
        "tier":        "preventive",
        "complexity":  "medium",
        "timeframe":   "weeks",
        "stakeholder": "AS operator",
        "description": (
            "Configure your border routers to drop BGP announcements that fail RPKI "
            "validation. Most Tier-1 transit (Cogent, Lumen/AS3356, NTT, Telia/AS1299) "
            "now enforce ROV by default for paying customers. Insist on it in your "
            "transit contract. Without ROV upstream, your own ROAs offer limited protection."
        ),
        "references": ["RFC 8893", "Cloudflare 'is BGP safe yet'"],
    },
    "transit_diversity": {
        "title":       "Multiple non-adversarial upstream transit",
        "tier":        "preventive",
        "complexity":  "medium",
        "timeframe":   "weeks–months",
        "stakeholder": "AS operator",
        "description": (
            "Maintain at least 3 distinct upstream transit providers in different "
            "AS-political-spheres so no single adversarial chokepoint can isolate you. "
            "Specifically avoid single-homed dependency on adversary-controlled or "
            "adversary-aligned transit. For Ukrainian operators this means no exclusive "
            "Russian/Belarusian transit; for Taiwanese this means avoiding sole China "
            "Telecom/Unicom adjacency."
        ),
        "references": ["RFC 7454"],
    },
    "ixp_neutral_peering": {
        "title":       "Direct peering at neutral IXPs",
        "tier":        "preventive",
        "complexity":  "medium",
        "timeframe":   "weeks",
        "stakeholder": "AS operator",
        "description": (
            "Establish direct peering at major neutral Internet Exchange Points "
            "(DE-CIX Frankfurt, AMS-IX Amsterdam, LINX London, NIX.CZ Prague). Direct "
            "IXP peering bypasses adversarial transit entirely for traffic destined to "
            "fellow IXP members. Highest impact when many endpoints (e.g. major content "
            "providers, DNS resolvers) are also peered at the same IXP."
        ),
        "references": ["MANRS", "PeeringDB"],
    },
    "as_path_filtering": {
        "title":       "AS_PATH filtering of known-adversary ASes",
        "tier":        "preventive",
        "complexity":  "low",
        "timeframe":   "hours",
        "stakeholder": "AS operator",
        "description": (
            "Configure inbound BGP filters that reject any path containing a known "
            "adversarial AS as a transit hop. List of adversarial ASes is per-scenario; "
            "for Ukraine this includes AS12389 (Rostelecom), AS8359 (MTS), AS9002 (RETN). "
            "Caveat: this is a blunt instrument and will increase path length / latency."
        ),
        "references": ["RFC 7454", "Cloudflare BGP best practices"],
    },
    "mtls_dot_doh": {
        "title":       "Encrypt-everything (mTLS, DoT/DoH, ESNI)",
        "tier":        "responsive",
        "complexity":  "low",
        "timeframe":   "days",
        "stakeholder": "end-user + service operator",
        "description": (
            "When BGP-level mitigations cannot fully prevent traffic from traversing "
            "adversarial infrastructure, end-to-end encryption ensures that intercepted "
            "traffic remains confidential. Mandate TLS 1.3 with ECH, DNS-over-TLS or "
            "DNS-over-HTTPS, and HSTS for all critical services. SORM/lawful-intercept "
            "obligations apply but cannot retrieve plaintext."
        ),
        "references": ["RFC 7858 (DoT)", "RFC 8484 (DoH)", "RFC 8744 (ECH)"],
    },
    "starlink_alt_transport": {
        "title":       "Resilient alternative transport (LEO satellite)",
        "tier":        "responsive",
        "complexity":  "high",
        "timeframe":   "weeks",
        "stakeholder": "AS operator + government",
        "description": (
            "Maintain LEO-satellite (Starlink) or military SATCOM standby capacity "
            "for critical services. Starlink famously kept Ukrainian command and "
            "civilian infrastructure online during routing blackouts in 2022. Cost: "
            "non-trivial CAPEX, but the operational continuity in conflict justifies it."
        ),
        "references": ["Starlink-Ukraine 2022 operational reports"],
    },
    "ris_monitoring": {
        "title":       "Real-time BGP monitoring (RIS Live, BGPMon)",
        "tier":        "detective",
        "complexity":  "low",
        "timeframe":   "days",
        "stakeholder": "AS operator + SOC",
        "description": (
            "Subscribe to RIPE NCC RIS Live WebSocket or commercial alternative "
            "(BGPMon, Kentik) and alert on any UPDATE for your prefixes that introduces "
            "a new origin AS or an adversarial transit hop. Detect hijack within seconds, "
            "not days. Free tier sufficient for organizations with <100 prefixes."
        ),
        "references": ["RIPE NCC RIS Live", "BGPmon"],
    },
    "manrs_membership": {
        "title":       "Join MANRS and follow the four mandatory actions",
        "tier":        "preventive",
        "complexity":  "low",
        "timeframe":   "weeks",
        "stakeholder": "AS operator",
        "description": (
            "MANRS (Mutually Agreed Norms for Routing Security) requires (1) prefix "
            "filtering, (2) anti-spoofing, (3) coordination via PeeringDB, and (4) "
            "global validation (publish ROAs). Membership signals to peers and customers "
            "that the operator is reachable and serious about routing security."
        ),
        "references": ["manrs.org"],
    },
    "rpki_path_validation": {
        "title":       "ASPA / BGPsec path-validation (emerging)",
        "tier":        "preventive",
        "complexity":  "high",
        "timeframe":   "months–years",
        "stakeholder": "AS operator + RIR + IETF",
        "description": (
            "ASPA (Autonomous System Provider Authorization, RFC 9774) and BGPsec "
            "(RFC 8205) extend RPKI from origin-only validation to full AS_PATH "
            "validation. Still not widely deployed, but the only definitive defense "
            "against route leaks and AS-path manipulation. Track adoption among "
            "your transit providers."
        ),
        "references": ["RFC 9774 (ASPA)", "RFC 8205 (BGPsec)"],
    },
    "diplomatic_pressure": {
        "title":       "Diplomatic / regulatory pressure on RIR",
        "tier":        "responsive",
        "complexity":  "high",
        "timeframe":   "months",
        "stakeholder": "government + RIR community",
        "description": (
            "When an adversarial state forcibly reassigns prefix blocks to its own "
            "ASes (as happened with Crimea AS50010 in 2014), the legitimate operator "
            "and host nation can petition the RIR (RIPE NCC, APNIC) to reverse the "
            "transfer. Process is slow and politically charged but has succeeded in "
            "limited cases. Most effective combined with sanctions enforcement."
        ),
        "references": ["RIPE NCC sanctions guidance"],
    },
    # ── GenAI Traffic Protection ──────────────────────────────────────
    "genai_traffic_padding": {
        "title":       "Traffic padding / shaping to defeat GenAI fingerprinting",
        "tier":        "responsive",
        "complexity":  "medium",
        "timeframe":   "days–weeks",
        "stakeholder": "end-user + service operator",
        "description": (
            "GenAI applications (ChatGPT, Gemini, Grok, Perplexity) produce distinctive "
            "network signatures — regular inter-arrival times, consistent burst sizes, and "
            "characteristic request-response patterns — that DPI can classify with ~89% "
            "accuracy. Traffic padding injects dummy packets to disrupt burst analysis and "
            "IAT regularity, reducing classifier confidence below actionable thresholds."
        ),
        "references": ["NDSS 2023 traffic-analysis padding", "IEEE S&P encrypted-traffic classification"],
    },
    "genai_vpn_tunneling": {
        "title":       "VPN / encrypted tunnel for AI service traffic",
        "tier":        "responsive",
        "complexity":  "low",
        "timeframe":   "hours–days",
        "stakeholder": "end-user",
        "description": (
            "Route all GenAI API and application traffic through a VPN tunnel terminating "
            "outside adversary-controlled transit. This hides the destination IP (defeating "
            "IP-based blocking) and wraps the traffic in a uniform encrypted envelope, "
            "degrading flow-level fingerprinting features like unique destination IPs and "
            "connection counts. WireGuard or IPsec preferred for low-overhead tunneling."
        ),
        "references": ["WireGuard protocol", "RFC 7296 (IKEv2)"],
    },
    "genai_on_premise": {
        "title":       "On-premise / air-gapped AI deployment",
        "tier":        "preventive",
        "complexity":  "high",
        "timeframe":   "weeks–months",
        "stakeholder": "military + government IT",
        "description": (
            "Deploy open-weight LLMs (Llama, Mistral, Qwen) on local or classified-network "
            "hardware to eliminate cloud AI traffic entirely. Removes the fingerprinting "
            "attack surface: no GenAI packets traverse any external network. Critical for "
            "intelligence analysis and operational planning where AI-assisted workflows "
            "must not be observable by adversary signals intelligence."
        ),
        "references": ["DoD CDAO AI adoption guidance", "NIST AI 600-1"],
    },
}


# Map observed-threat-condition → recommended mitigation IDs (priority order)
TRIGGERS = {
    # Threat: prefix hijack / origin change → another AS announces your prefix
    "prefix_hijack": [
        "rpki_roa", "rov_upstream", "ris_monitoring", "as_path_filtering",
        "diplomatic_pressure",
    ],
    # Threat: Russian/adversarial AS appearing as transit hop (path injection)
    "adversarial_transit": [
        "as_path_filtering", "transit_diversity", "ixp_neutral_peering",
        "mtls_dot_doh", "rpki_path_validation",
    ],
    # Threat: Communications blackout / peer count collapse
    "blackout": [
        "starlink_alt_transport", "transit_diversity", "ixp_neutral_peering",
        "ris_monitoring",
    ],
    # Threat: SORM / lawful-intercept exposure on adversary path
    "sorm_exposure": [
        "mtls_dot_doh", "as_path_filtering", "transit_diversity",
        "ixp_neutral_peering",
    ],
    # Threat: GenAI traffic exposed to adversary fingerprinting / blocking
    "genai_exposure": [
        "genai_vpn_tunneling", "genai_traffic_padding", "mtls_dot_doh",
        "genai_on_premise",
    ],
    # Generic baseline — every operator should have these regardless of threat
    "baseline": [
        "rpki_roa", "rov_upstream", "manrs_membership", "ris_monitoring",
    ],
}


def recommend_for_city(city_record):
    """
    Given a city record (with threat score + components), return a prioritized
    list of mitigation IDs tied to the specific threats observed.
    """
    t = city_record.get("threat", {})
    components = t.get("components", {})
    evidence = t.get("evidence", {})

    selected = []
    rationales = {}

    # Trigger by component
    if components.get("blackout", 0) >= 15:
        selected.extend(TRIGGERS["blackout"])
        rationales["blackout"] = (
            f"peer count drop of {evidence.get('peer_count_drop', 0)} indicates "
            f"effective communications blackout"
        )

    if components.get("russian_route", 0) > 0:
        selected.extend(TRIGGERS["adversarial_transit"])
        rationales["adversarial_transit"] = (
            f"{evidence.get('russian_paths_count', 0)} Russian-routed path(s) "
            f"observed in BGP samples"
        )

    if components.get("sorm_exposure", 0) > 0:
        selected.extend(TRIGGERS["sorm_exposure"])
        rationales["sorm_exposure"] = (
            f"SORM-capable ASes ({', '.join('AS' + a for a in evidence.get('sorm_ases_observed', []))}) "
            f"on observed path → unencrypted traffic legally subject to interception"
        )

    if components.get("instability", 0) >= 15:
        selected.extend(TRIGGERS["prefix_hijack"])
        rationales["prefix_hijack"] = (
            f"BGP UPDATE volume of {evidence.get('max_bgp_updates_in_day', 0)} per "
            f"observation window suggests possible route instability or hijack"
        )

    # GenAI exposure: trigger when adversarial routing or intercept capability exists
    if components.get("russian_route", 0) > 0 or components.get("sorm_exposure", 0) > 0:
        selected.extend(TRIGGERS["genai_exposure"])
        rationales["genai_exposure"] = (
            "traffic traverses adversary infrastructure with DPI capability — "
            "GenAI application traffic (ChatGPT, Gemini, etc.) can be fingerprinted "
            "with ~89% accuracy, enabling selective blocking or surveillance"
        )

    # Always layer in baseline
    selected.extend(TRIGGERS["baseline"])
    rationales["baseline"] = "minimum BGP-security hygiene applicable to every operator"

    # Dedupe while preserving order
    seen = set()
    ordered = []
    for m in selected:
        if m not in seen:
            seen.add(m)
            ordered.append(m)

    return {
        "recommended": ordered,
        "rationales": rationales,
    }
