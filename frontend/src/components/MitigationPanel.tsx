import { useState } from "react";
import type { GlobalScenarioCity } from "../types";

// Full playbook mirrored from mitigations.py
const PLAYBOOK: Record<string, {
  title: string;
  tier: string;
  complexity: string;
  timeframe: string;
  stakeholder: string;
  description: string;
  references: string[];
}> = {
  rpki_roa: {
    title:       "RPKI ROA — sign route origin authorizations",
    tier:        "preventive",
    complexity:  "low",
    timeframe:   "days",
    stakeholder: "AS operator + RIR",
    description: "Publish Route Origin Authorizations (ROAs) at your RIR (RIPE/ARIN/APNIC) cryptographically binding your prefixes to your AS. Combined with ROV on upstream, this is the single highest-leverage defense against prefix hijacking. ~50% of IPv4 prefixes globally are RPKI-signed; coverage in conflict zones is often <20%.",
    references:  ["RFC 9582", "RFC 8210", "MANRS"],
  },
  rov_upstream: {
    title:       "ROV — enable Route Origin Validation on upstream",
    tier:        "preventive",
    complexity:  "medium",
    timeframe:   "weeks",
    stakeholder: "AS operator",
    description: "Configure border routers to drop BGP announcements that fail RPKI validation. Most Tier-1 transit (Cogent, Lumen/Level3, NTT, Telia) now enforce ROV by default. Insist on it in your transit contract. Without ROV upstream, your own ROAs offer limited protection.",
    references:  ["RFC 8893", "Cloudflare 'is BGP safe yet'"],
  },
  transit_diversity: {
    title:       "Multiple non-adversarial upstream transit providers",
    tier:        "preventive",
    complexity:  "medium",
    timeframe:   "weeks–months",
    stakeholder: "AS operator",
    description: "Maintain ≥3 distinct upstream transit providers in different AS-political-spheres so no single adversarial chokepoint can isolate you. For Ukrainian operators: no exclusive Russian/Belarusian transit. For Taiwanese: avoid sole China Telecom/Unicom adjacency. For Gaza/Sudan: avoid single-provider dependency.",
    references:  ["RFC 7454"],
  },
  ixp_neutral_peering: {
    title:       "Direct peering at neutral IXPs",
    tier:        "preventive",
    complexity:  "medium",
    timeframe:   "weeks",
    stakeholder: "AS operator",
    description: "Establish peering at major neutral Internet Exchange Points (DE-CIX Frankfurt, AMS-IX, LINX London, NIX.CZ). Direct IXP peering bypasses adversarial transit entirely. Highest impact when major content providers and DNS resolvers are also at the same IXP.",
    references:  ["MANRS", "PeeringDB"],
  },
  as_path_filtering: {
    title:       "AS_PATH filtering — reject known-adversary transit hops",
    tier:        "preventive",
    complexity:  "low",
    timeframe:   "hours",
    stakeholder: "AS operator",
    description: "Configure inbound BGP filters that reject any path containing a known adversarial AS as transit. For Ukraine: AS12389 (Rostelecom), AS8359 (MTS), AS9002 (RETN). For Taiwan: AS4134 (China Telecom), AS4837 (Unicom). Caveat: blunt instrument, increases path length.",
    references:  ["RFC 7454", "Cloudflare BGP best practices"],
  },
  mtls_dot_doh: {
    title:       "Encrypt-everything (mTLS, DoT/DoH, ESNI)",
    tier:        "responsive",
    complexity:  "low",
    timeframe:   "days",
    stakeholder: "end-user + service operator",
    description: "When BGP mitigations cannot prevent traffic from traversing adversarial infrastructure, end-to-end encryption ensures intercepted traffic stays confidential. Mandate TLS 1.3 with ECH, DNS-over-TLS, HSTS. SORM/lawful-intercept obligations apply but cannot retrieve plaintext.",
    references:  ["RFC 7858 (DoT)", "RFC 8484 (DoH)", "RFC 8744 (ECH)"],
  },
  starlink_alt_transport: {
    title:       "Resilient alternative transport (LEO satellite)",
    tier:        "responsive",
    complexity:  "high",
    timeframe:   "weeks",
    stakeholder: "AS operator + government",
    description: "Maintain LEO-satellite (Starlink) or military SATCOM standby for critical services. Starlink kept Ukrainian command and civilian infrastructure online during routing blackouts in 2022. Non-trivial CAPEX, but operational continuity in conflict justifies it.",
    references:  ["Starlink-Ukraine 2022 operational reports"],
  },
  ris_monitoring: {
    title:       "Real-time BGP monitoring (RIS Live, BGPMon)",
    tier:        "detective",
    complexity:  "low",
    timeframe:   "days",
    stakeholder: "AS operator + SOC",
    description: "Subscribe to RIPE NCC RIS Live WebSocket or BGPMon and alert on any UPDATE for your prefixes that introduces a new origin AS or adversarial transit hop. Detect hijack within seconds, not days. Free tier sufficient for organizations with <100 prefixes.",
    references:  ["RIPE NCC RIS Live", "BGPmon"],
  },
  manrs_membership: {
    title:       "Join MANRS — four mandatory actions",
    tier:        "preventive",
    complexity:  "low",
    timeframe:   "weeks",
    stakeholder: "AS operator",
    description: "MANRS (Mutually Agreed Norms for Routing Security) requires (1) prefix filtering, (2) anti-spoofing, (3) PeeringDB coordination, (4) global validation via ROAs. Membership signals routing-security seriousness to peers and customers.",
    references:  ["manrs.org"],
  },
  rpki_path_validation: {
    title:       "ASPA / BGPsec full path-validation (emerging)",
    tier:        "preventive",
    complexity:  "high",
    timeframe:   "months–years",
    stakeholder: "AS operator + RIR + IETF",
    description: "ASPA (RFC 9774) and BGPsec (RFC 8205) extend RPKI from origin-only to full AS_PATH validation — the only definitive defense against route leaks and AS-path manipulation. Still not widely deployed; track adoption among your transit providers.",
    references:  ["RFC 9774 (ASPA)", "RFC 8205 (BGPsec)"],
  },
  diplomatic_pressure: {
    title:       "Diplomatic / RIR petition for reversed prefix reassignment",
    tier:        "responsive",
    complexity:  "high",
    timeframe:   "months",
    stakeholder: "government + RIR community",
    description: "When an adversarial state forcibly reassigns prefix blocks (as happened with Crimea AS50010 in 2014), the legitimate operator and host nation can petition the RIR (RIPE NCC, APNIC) to reverse the transfer. Slow and political, but has succeeded in limited cases. Most effective combined with sanctions.",
    references:  ["RIPE NCC sanctions guidance"],
  },
  genai_traffic_padding: {
    title:       "Traffic padding / shaping to defeat GenAI fingerprinting",
    tier:        "responsive",
    complexity:  "medium",
    timeframe:   "days\u2013weeks",
    stakeholder: "end-user + service operator",
    description: "GenAI applications (ChatGPT, Gemini, Grok, Perplexity) produce distinctive network signatures \u2014 regular inter-arrival times, consistent burst sizes, and characteristic request-response patterns \u2014 that DPI can classify with ~89% accuracy. Traffic padding injects dummy packets to disrupt burst analysis and IAT regularity, reducing classifier confidence below actionable thresholds.",
    references:  ["NDSS 2023 traffic-analysis padding", "IEEE S&P encrypted-traffic classification"],
  },
  genai_vpn_tunneling: {
    title:       "VPN / encrypted tunnel for AI service traffic",
    tier:        "responsive",
    complexity:  "low",
    timeframe:   "hours\u2013days",
    stakeholder: "end-user",
    description: "Route all GenAI API and application traffic through a VPN tunnel terminating outside adversary-controlled transit. This hides the destination IP (defeating IP-based blocking) and wraps traffic in a uniform encrypted envelope, degrading flow-level fingerprinting features like unique destination IPs and connection counts. WireGuard or IPsec preferred.",
    references:  ["WireGuard protocol", "RFC 7296 (IKEv2)"],
  },
  genai_on_premise: {
    title:       "On-premise / air-gapped AI deployment",
    tier:        "preventive",
    complexity:  "high",
    timeframe:   "weeks\u2013months",
    stakeholder: "military + government IT",
    description: "Deploy open-weight LLMs (Llama, Mistral, Qwen) on local or classified-network hardware to eliminate cloud AI traffic entirely. Removes the fingerprinting attack surface: no GenAI packets traverse any external network. Critical for intelligence analysis and operational planning where AI-assisted workflows must not be observable by adversary SIGINT.",
    references:  ["DoD CDAO AI adoption guidance", "NIST AI 600-1"],
  },
};

const TIER_COLOR: Record<string, string> = {
  preventive: "#36c773",
  detective:  "#4aa3ff",
  responsive: "#ff9b1c",
};

interface Props {
  city: GlobalScenarioCity;
}

export function MitigationPanel({ city }: Props) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const recs = city.mitigations?.recommended ?? [];
  const rationales = city.mitigations?.rationales ?? {};

  if (recs.length === 0) return null;

  const triggerGroups = Object.entries(rationales);

  return (
    <section className="mitigation-panel">
      <h3>BGP Attack Mitigations</h3>

      {triggerGroups.length > 0 && (
        <div className="mitigation-triggers">
          {triggerGroups.map(([trigger, rationale]) => (
            <div key={trigger} className="mitigation-trigger-row">
              <span className="mit-trigger-tag">{trigger.replace(/_/g, " ")}</span>
              <span className="mit-trigger-reason">{rationale}</span>
            </div>
          ))}
        </div>
      )}

      <ol className="mitigation-list">
        {recs.map((id) => {
          const m = PLAYBOOK[id];
          if (!m) return null;
          const isOpen = expanded === id;
          return (
            <li key={id} className={`mitigation-item tier-${m.tier}`}>
              <button
                className="mitigation-header"
                onClick={() => setExpanded(isOpen ? null : id)}
              >
                <span
                  className="mit-tier-dot"
                  style={{ background: TIER_COLOR[m.tier] }}
                />
                <span className="mit-title">{m.title}</span>
                <span className="mit-meta">
                  <span className="mit-complexity">{m.complexity}</span>
                  <span className="mit-time">{m.timeframe}</span>
                  <span className="mit-chevron">{isOpen ? "▲" : "▼"}</span>
                </span>
              </button>
              {isOpen && (
                <div className="mitigation-body">
                  <p className="mit-description">{m.description}</p>
                  <div className="mit-footer">
                    <span className="mit-stakeholder">Owner: {m.stakeholder}</span>
                    <span className="mit-refs">
                      {m.references.join(" · ")}
                    </span>
                  </div>
                </div>
              )}
            </li>
          );
        })}
      </ol>

      <div className="mitigation-legend">
        <span style={{ color: TIER_COLOR.preventive }}>■</span> preventive
        <span style={{ color: TIER_COLOR.detective }}>■</span> detective
        <span style={{ color: TIER_COLOR.responsive }}>■</span> responsive
      </div>
    </section>
  );
}
