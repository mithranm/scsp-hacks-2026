"""
Global conflict scenario definitions.

Each scenario specifies:
  - target ASes for major cities/regions in the conflict zone
  - adversarial state-operated transit ASes (the equivalent of SORM)
  - the threat actor narrative
  - which RIPE NCC collectors give relevant vantage

The same analysis pipeline (BGP path inspection, peer-count tracking,
kinetic-event correlation, threat-score composition) runs against every
scenario unchanged.
"""

# Each adversarial ASN → ("operator", "role/legal-basis")
SCENARIOS = {

    # ─────────────────────────────────────────────────────────────────────
    "russia_ukraine": {
        "name":         "Russia ↔ Ukraine",
        "region":       "Eastern Europe",
        "active_since": "2022-02-24",
        "primary_actor": "Russian Federation",
        "secondary_actor": "Ukraine",
        "summary": "Full-scale Russian invasion since Feb 2022. Documented BGP "
                   "rerouting of occupied Ukrainian territory through Russian "
                   "state-operated transit subject to SORM legal-intercept.",
        "ucdp_country": "Ukraine",
        "date_start":   "2021-10-01",
        "date_end":     "2022-06-30",
        "ris_collectors": ["rrc15", "rrc16", "rrc18"],
        "targets": [
            {"city": "Kherson",    "asn": 21219, "lat": 46.6354, "lon": 32.6169},
            {"city": "Mariupol",   "asn": 6849,  "lat": 47.0971, "lon": 37.5434},
            {"city": "Kharkiv",    "asn": 13188, "lat": 49.9935, "lon": 36.2304},
            {"city": "Zaporizhia", "asn": 34700, "lat": 47.8388, "lon": 35.1396},
            {"city": "Donetsk",    "asn": 48593, "lat": 48.0159, "lon": 37.8028},
            {"city": "Luhansk",    "asn": 34867, "lat": 48.5740, "lon": 39.3078},
        ],
        "adversarial_ases": {
            8359:  ("MTS Russia",        "SORM-3 lawful intercept (FZ-374)"),
            12389: ("Rostelecom",        "State carrier, SORM-3 obligation"),
            31257: ("Vimpelcom/Beeline", "SORM-3 obligation"),
            8641:  ("Naukanet",          "FSB-linked academic backbone"),
            25159: ("Rostelecom backbone","SORM-3"),
            20485: ("TTNET Russia",      "SORM-3 obligation"),
            9049:  ("JSC Ertetel",       "Operating in occupied territory"),
            50010: ("Miranda-Media",     "Crimea reassignment 2014, FSB-linked"),
            34879: ("NetArt Group",      "Crimea reassignment 2014"),
            9002:  ("RETN",              "Russia-CIS backbone (op. HQ St. Petersburg)"),
        },
        "data_source": "live",
    },

    # ─────────────────────────────────────────────────────────────────────
    "sudan_civil_war": {
        "name":         "Sudan civil war (SAF ↔ RSF)",
        "region":       "East Africa",
        "active_since": "2023-04-15",
        "primary_actor": "Sudanese Armed Forces (SAF) / Rapid Support Forces (RSF)",
        "secondary_actor": "Civilian population",
        "summary": "Multiple nationwide internet shutdowns since April 2023. "
                   "Sudatel (AS33788), MTN Sudan (AS36972), and Zain Sudan (AS37197) "
                   "routing repeatedly withdrawn or rerouted through neighbouring "
                   "states under fighting.",
        "ucdp_country":   "Sudan",
        "date_start":     "2022-10-01",
        "date_end":       "2024-12-31",
        "ris_collectors": ["rrc05", "rrc06"],
        "targets": [
            {"city": "Khartoum",   "asn": 33788, "lat": 15.5007, "lon": 32.5599},
            {"city": "Omdurman",   "asn": 15706, "lat": 15.6445, "lon": 32.4777},
            {"city": "Port Sudan", "asn": 36972, "lat": 19.6158, "lon": 37.2164},
            {"city": "El Fasher",  "asn": 37197, "lat": 13.6293, "lon": 25.3499},
            {"city": "Nyala",      "asn": 36972, "lat": 12.0489, "lon": 24.8807},
        ],
        "adversarial_ases": {
            36992: ("Etisalat Misr",      "Egyptian transit (regional re-route)"),
            5384:  ("Emirates Telecomm",  "UAE transit"),
            8452:  ("TE Data Egypt",      "Egyptian state-aligned transit"),
            33802: ("Wagner-linked transit", "RSF-aligned routing (paramilitary)"),
        },
        "data_source": "live",
    },

    # ─────────────────────────────────────────────────────────────────────
    "myanmar_civil_war": {
        "name":         "Myanmar civil war",
        "region":       "Southeast Asia",
        "active_since": "2021-02-01",
        "primary_actor": "Tatmadaw (military junta) / People's Defence Force / EAOs",
        "secondary_actor": "Civilian population",
        "summary": "Following the 2021 coup, the junta has repeatedly imposed "
                   "nationwide internet shutdowns and forces all traffic through "
                   "state-controlled MPT (AS9988) for surveillance. Mytel "
                   "(AS135522) is partly owned by the junta-aligned military.",
        "ucdp_country":   "Myanmar (Burma)",
        "date_start":     "2023-01-01",
        "date_end":       "2024-12-31",
        "ris_collectors": ["rrc04", "rrc11"],
        "targets": [
            {"city": "Yangon",     "asn": 9988,   "lat": 16.8409, "lon": 96.1735},
            {"city": "Mandalay",   "asn": 135522, "lat": 21.9588, "lon": 96.0891},
            {"city": "Naypyidaw",  "asn": 132225, "lat": 19.7450, "lon": 96.1297},
            {"city": "Mawlamyine", "asn": 135507, "lat": 16.4913, "lon": 97.6285},
        ],
        "adversarial_ases": {
            9988:   ("MPT Myanmar",        "State telecom under military control"),
            136255: ("Myanmar Posts",      "Junta-controlled"),
            135522: ("Mytel",              "Military-aligned (Tatmadaw stake)"),
            132225: ("Telecom International Myanmar", "Naypyidaw national-government carrier"),
        },
        "data_source": "live",
    },

    # ─────────────────────────────────────────────────────────────────────
    "iran_yemen_houthi": {
        "name":         "Iran proxy network (Yemen, Iraq)",
        "region":       "Middle East",
        "active_since": "2014-09-01",
        "primary_actor": "Iran (IRGC) / Houthi forces / Iraqi PMF",
        "secondary_actor": "Saudi-led coalition / civilian infrastructure",
        "summary": "Yemen routes through Iran-aligned transit during periods of "
                   "Saudi blockade. Iran (TIC AS12880) operates the country's "
                   "single international gateway with full deep-packet inspection.",
        "ucdp_country":   "Yemen (North Yemen)",
        "date_start":     "2023-10-01",
        "date_end":       "2024-12-31",
        "ris_collectors": ["rrc05", "rrc13"],
        "targets": [
            {"city": "Sanaa",     "asn": 30873, "lat": 15.3694, "lon": 44.1910},
            {"city": "Aden",      "asn": 30873, "lat": 12.7855, "lon": 45.0187},
            {"city": "Hodeida",   "asn": 30873, "lat": 14.7978, "lon": 42.9545},
            {"city": "Taiz",      "asn": 30873, "lat": 13.5795, "lon": 44.0209},
            {"city": "Baghdad",   "asn": 21277, "lat": 33.3152, "lon": 44.3661},
            {"city": "Tehran",    "asn": 12880, "lat": 35.6892, "lon": 51.3890},
        ],
        "adversarial_ases": {
            12880: ("TIC Iran",                  "State gateway, full DPI mandated"),
            44244: ("Mobinnet Iran",             "Iranian state-aligned"),
            58224: ("Iran Telecom Co.",          "State carrier"),
            16735: ("MCI Iran",                  "Mobile Communication of Iran"),
            48159: ("ITC Iran (research net)",   "State research backbone"),
            31549: ("Iran Pars Online",          "State-aligned"),
            21277: ("Iraq EarthLink",            "Iraqi state-controlled gateway"),
        },
        "data_source": "live",
    },

    # ─────────────────────────────────────────────────────────────────────
    "china_taiwan": {
        "name":         "China ↔ Taiwan",
        "region":       "East Asia",
        "active_since": "1949-01-01",
        "primary_actor": "People's Republic of China (PLA, MSS)",
        "secondary_actor": "Republic of China (Taiwan)",
        "summary": "Taiwan Strait contingency. Major Taiwanese ASes maintain "
                   "direct adjacency to PRC state-operated transit (China Telecom, "
                   "Unicom, Mobile) — providing immediate intercept and route-hijack "
                   "capability if Beijing chose to weaponize it.",
        "ucdp_country":   None,  # No active conflict events; this is a contingency
        "date_start":     "2024-01-01",
        "date_end":       "2024-12-31",
        "ris_collectors": ["rrc06", "rrc23"],
        "targets": [
            {"city": "Taipei",      "asn": 3462,  "lat": 25.0330, "lon": 121.5654},
            {"city": "Kaohsiung",   "asn": 17421, "lat": 22.6273, "lon": 120.3014},
            {"city": "Taichung",    "asn": 4780,  "lat": 24.1477, "lon": 120.6736},
            {"city": "Hsinchu",     "asn": 9924,  "lat": 24.8138, "lon": 120.9675},
            {"city": "New Taipei",  "asn": 7539,  "lat": 25.0120, "lon": 121.4658},
        ],
        "adversarial_ases": {
            4134:  ("China Telecom",       "State-controlled, MSS data access"),
            4837:  ("China Unicom",        "State-controlled"),
            9808:  ("China Mobile",        "State-controlled"),
            4538:  ("CERNET",              "State-controlled academic"),
            7497:  ("CSTNET / CAS",        "State-controlled research"),
            9929:  ("China Netcom",        "Unicom subsidiary"),
            58453: ("China Mobile Intl",   "State-controlled"),
            23724: ("ChinaNet IDC",        "State-controlled"),
        },
        "data_source": "contingency",
    },
}
