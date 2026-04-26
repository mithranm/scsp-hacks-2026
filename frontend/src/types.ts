export interface ACLEDEvent {
  event_date: string;
  year: string;
  event_type: string;
  sub_event: string;
  actor1: string;
  actor2: string;
  admin1: string;
  admin2: string;
  location: string;
  city: string;
  latitude: number | string;
  longitude: number | string;
  fatalities: number | string;
  notes: string;
  source: string;
}

export interface BGPPeriodData {
  description: string;
  date: string;
  update_count: number;
  classifications: Record<string, number>;
  sample_paths: string[];
}

export interface CitySummary {
  kinetic_event_count?: number;
  first_event?: string | null;
  last_event?: string | null;
  max_bgp_updates_in_day?: number;
  peer_count_min?: number | null;
  peer_count_max?: number | null;
  peer_count_drop?: number;
}

export interface PeerTimelinePoint {
  date: string;
  peers: number;
}

export interface ThreatScore {
  score: number;
  level: "nominal" | "elevated" | "severe" | "critical";
  components: {
    blackout: number;
    instability: number;
    russian_route: number;
    sorm_exposure: number;
  };
  evidence: {
    peer_count_drop: number;
    max_bgp_updates_in_day: number;
    russian_paths_count: number;
    sorm_ases_observed: string[];
    adversarial_neighbours?: AdversarialNeighbour[];
    neighbours_total?: number;
  };
}

export interface City {
  name: string;
  asn: number;
  lat: number;
  lon: number;
  events: ACLEDEvent[];
  periods: Record<string, BGPPeriodData>;
  peer_timeline: PeerTimelinePoint[];
  summary: CitySummary;
  threat: ThreatScore;
}

export interface ASN {
  asn: number;
  holder: string;
  type: string;
  country: string;
  country_name: string;
  lat: number;
  lon: number;
  classification: "SORM" | "UA-target" | "Russian" | "Ukrainian" | "Belarusian" | "Transit";
  sorm_role: string;
  ua_city: string;
}

export interface PeriodMeta {
  label: string;
  description: string;
  date: string;
}

export interface CorrelationRow {
  date: string;
  city: string;
  kinetic_event: string;
  actor1: string;
  fatalities: string;
  notes: string;
  bgp_updates_in_window: number | string;
  ripe_peers_mean: number | string;
  sample_as_paths: string;
}

export interface Chokepoint {
  asn: number;
  centrality: number;
  raw_score: number;
  neighbors: number;
  holder: string;
  country: string;
  country_name: string;
  classification: string;
  sorm_role: string;
  is_adversarial: boolean;
}

export interface ChokepointAnalysis {
  graph_stats: {
    ases: number;
    edges: number;
    paths_observed: number;
    source_peers: number;
    ua_targets: number;
  };
  top_chokepoints: Chokepoint[];
  adversarial_chokepoints: Chokepoint[];
}

export interface ScenarioCity {
  city: string;
  name?: string;
  asn: number;
  lat: number;
  lon: number;
  prc_count?: number;
  prc_neighbours?: { asn: number; role: string }[];
  exposure_score: number;
  exposure_level: "nominal" | "elevated" | "severe" | "critical";
  neighbours_total: number;
  sample_prefix?: string | null;
  mean_peer_count?: number | null;
}

export interface Scenario {
  scenario_name: string;
  scenario_question: string;
  method: string;
  adversarial_ases: Record<string, string>;
  cities: ScenarioCity[];
  totals: {
    total_prc_adjacencies: number;
    exposed_targets: number;
    max_exposure: number;
    mean_exposure: number;
  };
}

/**
 * GlobalScenario — unified schema from build_global_scenarios.py.
 * Each scenario can power a complete cyber-terrain assessment for a conflict.
 */
export interface AdversarialNeighbour {
  asn: number;
  operator: string;
  role: string;
  v4_peers: number;
}

export interface GlobalScenarioCity {
  city: string;
  asn: number;
  lat: number;
  lon: number;
  threat: ThreatScore;
  peer_timeline: PeerTimelinePoint[];
  events: ACLEDEvent[];
  kinetic_event_count: number;
  sample_prefix?: string | null;
  peer_min: number;
  peer_max: number;
  mitigations: {
    recommended: string[];
    rationales: Record<string, string>;
  };
  // Every scenario now has periods (synthesized for non-Ukraine, MRT-derived for Ukraine)
  periods?: Record<string, BGPPeriodData>;
  summary?: CitySummary;
  name?: string;     // alias for `city` so legacy components work
}

export interface GlobalScenario {
  id: string;
  name: string;
  region: string;
  active_since: string;
  primary_actor: string;
  secondary_actor: string;
  summary: string;
  data_source: "live" | "contingency";
  date_start: string;
  date_end: string;
  adversarial_ases: Record<string, { operator: string; role: string }>;
  cities: GlobalScenarioCity[];
  totals: {
    city_count: number;
    total_events: number;
    exposed_cities: number;
    critical_cities: number;
    max_threat: number;
    mean_threat: number;
    total_adversarial_adjacencies: number;
  };
  chokepoints?: ChokepointAnalysis;
  generated_at: string;
}

export interface Bundle {
  generated_at: string;
  cities: Record<string, City>;
  asns: Record<string, ASN>;
  periods: PeriodMeta[];
  sorm_ases: Record<string, string>;
  correlation: CorrelationRow[];
  chokepoints?: ChokepointAnalysis;
  scenarios?: { taiwan_china?: Scenario };
  global_scenarios?: Record<string, GlobalScenario>;
  default_scenario?: string;
  briefs?: Record<string, Record<string, string>>;
  briefs_generated_at?: string;
  briefs_mode?: "llm" | "template";
  stats: {
    city_count: number;
    asn_count: number;
    event_count: number;
    bgp_records: number;
    ripe_entries: number;
  };
}
