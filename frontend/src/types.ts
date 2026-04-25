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

export interface City {
  name: string;
  asn: number;
  lat: number;
  lon: number;
  events: ACLEDEvent[];
  periods: Record<string, BGPPeriodData>;
  peer_timeline: PeerTimelinePoint[];
  summary: CitySummary;
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

export interface Bundle {
  generated_at: string;
  cities: Record<string, City>;
  asns: Record<string, ASN>;
  periods: PeriodMeta[];
  sorm_ases: Record<string, string>;
  correlation: CorrelationRow[];
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
