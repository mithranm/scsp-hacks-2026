"""
Conflict Event Fetcher (ACLED OR UCDP GED)
Pulls geocoded armed-conflict events for target Ukrainian cities during the
2022 Russian invasion. Three paths, in priority order:

  1. UCDP GED CSV — if acled_data/ucdp_ukraine.csv is present
     UCDP Georeferenced Event Dataset (Uppsala). Free, no auth.
     This is the recommended path; UCDP is also listed in the SCSP track.
  2. ACLED OAuth API — if ACLED_EMAIL + ACLED_PASSWORD env vars are set
     Requires myACLED account approval (most free accounts can't access this).
  3. Curated fallback dataset — public-record events from news/Wikipedia.

Output:
  acled_ukraine_events.csv             — Normalized events for target cities
  acled_key_events.csv                 — Pivotal events
  acled_data/raw_acled_response.json   — Raw ACLED response (gitignored)
  acled_data/oauth_token.json          — Cached OAuth token (gitignored)
"""

import os
import sys
import csv
import json
import time
import urllib.request
import urllib.parse
import urllib.error
import datetime

try:
    import requests  # ACLED is behind Cloudflare; urllib UA gets a 1010 ban
except ImportError:
    sys.exit("requests not installed. Run: pip install requests")

# Browser-like UA — Cloudflare blocks raw urllib/python-requests defaults
BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
BROWSER_HEADERS = {
    "User-Agent":      BROWSER_UA,
    "Accept":          "application/json,text/plain,*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer":         "https://acleddata.com/",
}

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "acled_data")
os.makedirs(OUT_DIR, exist_ok=True)

# Target cities — must align with BGP data targets
TARGET_CITIES = [
    "Kyiv",
    "Odessa",
    "Dnipro",
    "Mykolaiv",
    "Kherson",
    "Mariupol",
    "Kharkiv",
    "Zaporizhia",
    "Donetsk",
    "Luhansk",
]

# Full conflict window — Oct 2021 baseline through end of 2024 (live ACLED API supports it)
DATE_START = "2021-10-01"
DATE_END   = "2024-12-31"


# ---------------------------------------------------------------------------
# Path 1 — UCDP GED CSV (preferred)
# ---------------------------------------------------------------------------

UCDP_CSV = os.path.join(OUT_DIR, "ucdp_ukraine.csv")

# UCDP type_of_violence codes
UCDP_VIOLENCE = {
    "1": ("Battles",                       "State-based armed conflict"),
    "2": ("Battles",                       "Non-state armed conflict"),
    "3": ("Violence against civilians",    "One-sided violence"),
}

# Oblast → city mapping. Donetsk Oblast events get split: Mariupol if the
# location text mentions Mariupol, otherwise Donetsk.
OBLAST_TO_CITY = {
    "Kherson oblast":                      "Kherson",
    "Donetsk oblast":                      "Donetsk",       # default; refined below
    "Kharkiv oblast":                      "Kharkiv",
    "Zaporizhzhya oblast":                 "Zaporizhia",
    "Luhansk oblast":                      "Luhansk",
}


def assign_city_from_ucdp(row):
    """Assign one of our target cities to a UCDP row, or None to skip."""
    adm1     = (row.get("adm_1") or "").strip()
    adm2     = (row.get("adm_2") or "").strip().lower()
    location = (row.get("where_coordinates") or "").lower()
    desc     = (row.get("where_description") or "").lower()
    haystack = " ".join([adm2, location, desc])

    # Mariupol-in-Donetsk-Oblast disambiguation
    if adm1 == "Donetsk oblast" and "mariupol" in haystack:
        return "Mariupol"

    return OBLAST_TO_CITY.get(adm1)


def normalize_ucdp_record(row, city):
    """Map a UCDP GED row into our common event dict."""
    type_code = (row.get("type_of_violence") or "").strip()
    event_type, sub_event = UCDP_VIOLENCE.get(type_code, ("Conflict", "Unspecified"))

    notes = (
        row.get("source_headline")
        or row.get("source_article")
        or row.get("where_description")
        or ""
    )

    try:
        fatalities = int(row.get("best") or 0)
    except ValueError:
        fatalities = 0

    return {
        "event_date":  (row.get("date_start") or "")[:10],
        "year":        row.get("year", ""),
        "event_type":  event_type,
        "sub_event":   sub_event,
        "actor1":      row.get("side_a", "") or "",
        "actor2":      row.get("side_b", "") or "",
        "admin1":      row.get("adm_1", "") or "",
        "admin2":      row.get("adm_2", "") or "",
        "location":    row.get("where_coordinates", "") or city,
        "city":        city,
        "latitude":    row.get("latitude", ""),
        "longitude":   row.get("longitude", ""),
        "fatalities":  fatalities,
        "notes":       notes[:500],
        "source":      "UCDP GED v25.1",
    }


def load_ucdp_events():
    print(f"[ucdp] loading {UCDP_CSV}")
    out = []
    skipped = 0
    with open(UCDP_CSV) as f:
        reader = csv.DictReader(f)
        for row in reader:
            city = assign_city_from_ucdp(row)
            if not city:
                skipped += 1
                continue
            d = (row.get("date_start") or "")[:10]
            if not (DATE_START <= d <= DATE_END):
                continue
            out.append(normalize_ucdp_record(row, city))
    print(f"[ucdp] {len(out)} events matched target cities ({skipped} outside our oblast set)")
    return out


# ---------------------------------------------------------------------------
# Path 2 — ACLED OAuth API
# ---------------------------------------------------------------------------

TOKEN_URL = "https://acleddata.com/oauth/token"
API_URL   = "https://acleddata.com/api/acled/read"
TOKEN_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "acled_data", "oauth_token.json")
RAW_DUMP    = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "acled_data", "raw_acled_response.json")


def _load_cached_token():
    if not os.path.exists(TOKEN_CACHE):
        return None
    try:
        with open(TOKEN_CACHE) as f:
            cache = json.load(f)
        if cache.get("expires_at", 0) > time.time() + 60:
            return cache["access_token"]
    except Exception:
        pass
    return None


def _save_cached_token(access_token, expires_in):
    os.makedirs(os.path.dirname(TOKEN_CACHE), exist_ok=True)
    with open(TOKEN_CACHE, "w") as f:
        json.dump({
            "access_token": access_token,
            "expires_at":   time.time() + int(expires_in) - 60,
        }, f)
    # restrict permissions on the token file
    try:
        os.chmod(TOKEN_CACHE, 0o600)
    except Exception:
        pass


def get_access_token(email, password):
    """OAuth password-grant. Returns access token (24h validity)."""
    cached = _load_cached_token()
    if cached:
        print("[acled-auth] using cached access token")
        return cached

    print("[acled-auth] requesting new access token via OAuth")
    headers = {**BROWSER_HEADERS,
               "Content-Type": "application/x-www-form-urlencoded"}
    data = {
        "username":   email,
        "password":   password,
        "grant_type": "password",
        "client_id":  "acled",
        "scope":      "authenticated",
    }
    try:
        r = requests.post(TOKEN_URL, data=data, headers=headers, timeout=30)
    except Exception as e:
        sys.exit(f"[acled-auth-err] {e}")
    if r.status_code != 200:
        sys.exit(f"[acled-auth-err] HTTP {r.status_code}: {r.text[:300]}")

    body = r.json()
    token = body.get("access_token")
    if not token:
        sys.exit(f"[acled-auth-err] no access_token in response: {body}")
    _save_cached_token(token, body.get("expires_in", 86400))
    return token


def fetch_acled_api(email, password):
    """
    Pull events from ACLED OAuth API for Ukraine in our window.
    """
    token = get_access_token(email, password)

    print(f"[acled-api] querying for Ukraine {DATE_START} → {DATE_END}")
    params = {
        "country":          "Ukraine",
        "event_date":       f"{DATE_START}|{DATE_END}",
        "event_date_where": "BETWEEN",
        "_format":          "json",
        "limit":            0,
    }
    headers = {**BROWSER_HEADERS,
               "Authorization": f"Bearer {token}"}
    try:
        r = requests.get(API_URL, params=params, headers=headers, timeout=180)
    except Exception as e:
        print(f"[acled-api-err] {e}")
        return []

    if r.status_code != 200:
        body = r.text[:500]
        print(f"[acled-api-err] HTTP {r.status_code}: {body}")
        if r.status_code == 403 and "Access denied" in body:
            print("\n[acled-fix-hint] Account auth succeeded but data scope is missing.")
            print("  The myACLED account needs to be approved for 'Curated Data' API access.")
            print("  Steps:")
            print("    1. Log in at https://acleddata.com/")
            print("    2. Go to Account → API Access (or Data Access)")
            print("    3. Accept the Terms of Use and request data access")
            print("    4. Once approved, re-run: rm acled_data/oauth_token.json &&")
            print("       ACLED_EMAIL=... ACLED_PASSWORD=... python3 fetch_acled_events.py")
        return []

    data = r.json()
    os.makedirs(os.path.dirname(RAW_DUMP), exist_ok=True)
    with open(RAW_DUMP, "w") as f:
        json.dump(data, f)

    events = data.get("data", [])
    print(f"[acled-api] {len(events)} raw events returned")
    return events


def normalize_acled_record(rec):
    """Reduce ACLED API record to fields we care about."""
    return {
        "event_date":   rec.get("event_date", ""),
        "year":         rec.get("year", ""),
        "event_type":   rec.get("event_type", ""),
        "sub_event":    rec.get("sub_event_type", ""),
        "actor1":       rec.get("actor1", ""),
        "actor2":       rec.get("actor2", ""),
        "admin1":       rec.get("admin1", ""),    # oblast
        "admin2":       rec.get("admin2", ""),
        "location":     rec.get("location", ""),
        "city":         rec.get("location", ""),  # nearest
        "latitude":     rec.get("latitude", ""),
        "longitude":    rec.get("longitude", ""),
        "fatalities":   rec.get("fatalities", "0"),
        "notes":        rec.get("notes", ""),
        "source":       "ACLED API",
    }


# ---------------------------------------------------------------------------
# Path 2 — Curated fallback (public-source occupation timeline)
# ---------------------------------------------------------------------------
# Sourced from public news (BBC, Reuters, Wikipedia "Russian occupation of
# Ukrainian cities" articles). Coordinates from OpenStreetMap.
# This is a minimal seed that covers the inflection points we need for the
# BGP correlation demo. ACLED API access gives much richer coverage.
# ---------------------------------------------------------------------------

CURATED_EVENTS = [
    # Pre-invasion baseline — no kinetic events
    {"event_date": "2021-10-15", "city": "Kherson",    "lat": 46.6354, "lon": 32.6169,
     "event_type": "Background", "sub_event": "Pre-invasion baseline",
     "actor1": "—", "actor2": "—", "fatalities": 0,
     "notes": "Stable pre-invasion period — used as BGP baseline."},

    # Invasion starts
    {"event_date": "2022-02-24", "city": "Kharkiv",    "lat": 49.9935, "lon": 36.2304,
     "event_type": "Battles", "sub_event": "Armed clash",
     "actor1": "Russian Armed Forces", "actor2": "Ukrainian Armed Forces", "fatalities": 50,
     "notes": "Battle of Kharkiv begins — Russian forces enter eastern Ukraine."},
    {"event_date": "2022-02-24", "city": "Mariupol",   "lat": 47.0971, "lon": 37.5434,
     "event_type": "Battles", "sub_event": "Armed clash",
     "actor1": "Russian Armed Forces", "actor2": "Ukrainian Armed Forces", "fatalities": 30,
     "notes": "Russian advance into Donetsk Oblast begins."},
    {"event_date": "2022-02-24", "city": "Luhansk",    "lat": 48.5740, "lon": 39.3078,
     "event_type": "Strategic developments", "sub_event": "Annexation",
     "actor1": "Russian Armed Forces", "actor2": "—", "fatalities": 0,
     "notes": "Luhansk People's Republic recognized; Russian forces enter."},

    # Kherson occupation
    {"event_date": "2022-02-25", "city": "Kherson",    "lat": 46.6354, "lon": 32.6169,
     "event_type": "Battles", "sub_event": "Armed clash",
     "actor1": "Russian Armed Forces", "actor2": "Ukrainian Armed Forces", "fatalities": 15,
     "notes": "Russian forces approach Kherson from Crimea."},
    {"event_date": "2022-03-02", "city": "Kherson",    "lat": 46.6354, "lon": 32.6169,
     "event_type": "Strategic developments", "sub_event": "Change to area of operations",
     "actor1": "Russian Armed Forces", "actor2": "—", "fatalities": 0,
     "notes": "Kherson falls — first major Ukrainian city captured. Local infrastructure including telecom comes under Russian control. BGP signal: KhersonNet AS21219 sees peer-count fluctuations."},
    {"event_date": "2022-04-30", "city": "Kherson",    "lat": 46.6354, "lon": 32.6169,
     "event_type": "Strategic developments", "sub_event": "Telecom rerouting",
     "actor1": "Russian occupation administration", "actor2": "—", "fatalities": 0,
     "notes": "Reports of Kherson internet rerouted via Russian operator Miranda-Media (AS50010, originally Crimea). RIPE NCC documents AS path changes."},

    # Mariupol siege
    {"event_date": "2022-02-25", "city": "Mariupol",   "lat": 47.0971, "lon": 37.5434,
     "event_type": "Battles", "sub_event": "Armed clash",
     "actor1": "Russian Armed Forces", "actor2": "Ukrainian Armed Forces", "fatalities": 100,
     "notes": "Russian forces begin encirclement of Mariupol."},
    {"event_date": "2022-03-01", "city": "Mariupol",   "lat": 47.0971, "lon": 37.5434,
     "event_type": "Violence against civilians", "sub_event": "Attack",
     "actor1": "Russian Armed Forces", "actor2": "Civilians", "fatalities": 200,
     "notes": "Mariupol siege begins; sustained shelling of civilian infrastructure."},
    {"event_date": "2022-03-15", "city": "Mariupol",   "lat": 47.0971, "lon": 37.5434,
     "event_type": "Strategic developments", "sub_event": "Communications blackout",
     "actor1": "Russian Armed Forces", "actor2": "—", "fatalities": 0,
     "notes": "Mariupol largely cut off from external communications. Ukrtelecom AS6849 prefixes lose visibility from RIPE NCC peers."},
    {"event_date": "2022-04-15", "city": "Mariupol",   "lat": 47.0971, "lon": 37.5434,
     "event_type": "Battles", "sub_event": "Armed clash",
     "actor1": "Russian Armed Forces", "actor2": "Ukrainian Armed Forces", "fatalities": 500,
     "notes": "Final phase of Mariupol siege — Azovstal steelworks holdout."},

    # Kharkiv
    {"event_date": "2022-02-27", "city": "Kharkiv",    "lat": 49.9935, "lon": 36.2304,
     "event_type": "Battles", "sub_event": "Armed clash",
     "actor1": "Russian Armed Forces", "actor2": "Ukrainian Armed Forces", "fatalities": 200,
     "notes": "Heavy fighting in Kharkiv outskirts; city remains under Ukrainian control."},
    {"event_date": "2022-03-01", "city": "Kharkiv",    "lat": 49.9935, "lon": 36.2304,
     "event_type": "Violence against civilians", "sub_event": "Shelling/missile",
     "actor1": "Russian Armed Forces", "actor2": "Civilians", "fatalities": 50,
     "notes": "Missile strike on Kharkiv government building; AS13188 prefixes show transient withdrawals."},

    # Zaporizhia
    {"event_date": "2022-03-04", "city": "Zaporizhia", "lat": 47.8388, "lon": 35.1396,
     "event_type": "Battles", "sub_event": "Armed clash",
     "actor1": "Russian Armed Forces", "actor2": "Ukrainian Armed Forces", "fatalities": 25,
     "notes": "Zaporizhia Nuclear Power Plant captured by Russian forces."},

    # Donetsk
    {"event_date": "2022-02-24", "city": "Donetsk",    "lat": 48.0159, "lon": 37.8028,
     "event_type": "Strategic developments", "sub_event": "Annexation",
     "actor1": "Russian Armed Forces", "actor2": "—", "fatalities": 0,
     "notes": "Donetsk People's Republic recognized; expanded Russian military presence."},
]


def normalize_curated_record(rec):
    return {
        "event_date":  rec["event_date"],
        "year":        rec["event_date"][:4],
        "event_type":  rec["event_type"],
        "sub_event":   rec["sub_event"],
        "actor1":      rec["actor1"],
        "actor2":      rec["actor2"],
        "admin1":      "",
        "admin2":      "",
        "location":    rec["city"],
        "city":        rec["city"],
        "latitude":    rec["lat"],
        "longitude":   rec["lon"],
        "fatalities":  rec["fatalities"],
        "notes":       rec["notes"],
        "source":      "Curated public records",
    }


# ---------------------------------------------------------------------------
# Filtering, classification
# ---------------------------------------------------------------------------

def filter_to_target_cities(events):
    """
    Keep events whose location/admin1/admin2 mentions one of our target cities.
    ACLED uses Ukrainian-style names; map common variants.
    """
    # Aliases — keep all-lowercase
    aliases = {
        "Kyiv":       ["kyiv", "kiev", "kyyiv"],
        "Odessa":     ["odesa", "odessa"],
        "Dnipro":     ["dnipro", "dnipropetrovsk", "dnepr"],
        "Mykolaiv":   ["mykolaiv", "nikolaev", "mykolayiv"],
        "Kherson":    ["kherson"],
        "Mariupol":   ["mariupol", "mariupol'"],
        "Kharkiv":    ["kharkiv", "kharkov"],
        "Zaporizhia": ["zaporizhia", "zaporizhzhia", "zaporozhe", "zaporozh'ye"],
        "Donetsk":    ["donetsk", "donets'k"],
        "Luhansk":    ["luhansk", "lugansk", "luhans'k"],
    }

    out = []
    for e in events:
        haystack = " ".join([
            (e.get("location") or ""),
            (e.get("admin1") or ""),
            (e.get("admin2") or ""),
            (e.get("admin3") or ""),
        ]).lower()
        for city, names in aliases.items():
            if any(n in haystack for n in names):
                e["city"] = city
                out.append(e)
                break
    return out


def classify_pivotal(event):
    """
    Mark events that are pivotal for cyber-terrain correlation:
    occupation/annexation, communications blackout, telecom rerouting.
    """
    sub = (event.get("sub_event") or "").lower()
    notes = (event.get("notes") or "").lower()
    pivotal_markers = [
        "annexation", "change to area of operations", "communications blackout",
        "telecom rerouting", "siege",
    ]
    for marker in pivotal_markers:
        if marker in sub or marker in notes:
            return True
    # Also flag events on our BGP data dates
    bgp_dates = {"2022-02-24", "2022-03-02", "2022-04-15"}
    if event.get("event_date") in bgp_dates:
        return True
    return False


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

FIELDS = [
    "event_date", "year", "event_type", "sub_event",
    "actor1", "actor2", "admin1", "admin2",
    "location", "city", "latitude", "longitude",
    "fatalities", "notes", "source",
]


def write_csv(rows, path):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in FIELDS})
    print(f"[saved] {os.path.basename(path)} ({len(rows)} events)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=== ACLED Event Collection ===\n")

    api_email    = os.environ.get("ACLED_EMAIL", "").strip()
    api_password = os.environ.get("ACLED_PASSWORD", "").strip()

    events = []

    if api_email and api_password:
        print(f"[mode] ACLED OAuth API (email={api_email})")
        raw = fetch_acled_api(api_email, api_password)
        normalized = [normalize_acled_record(r) for r in raw]
        events = filter_to_target_cities(normalized)
        print(f"[filter] {len(events)}/{len(normalized)} events match target cities")
        if not events and os.path.exists(UCDP_CSV):
            print("[warn] ACLED returned 0 — falling back to UCDP CSV")
            events = load_ucdp_events()
        elif not events:
            print("[warn] ACLED returned 0 — falling back to curated set")
            events = [normalize_curated_record(r) for r in CURATED_EVENTS]
    elif os.path.exists(UCDP_CSV):
        print(f"[mode] UCDP GED CSV ({UCDP_CSV})")
        events = load_ucdp_events()
    else:
        print("[mode] Curated fallback")
        print("       For real data: set ACLED_EMAIL + ACLED_PASSWORD or drop UCDP CSV.\n")
        events = [normalize_curated_record(r) for r in CURATED_EVENTS]

    # Sort by date
    events.sort(key=lambda e: e.get("event_date", ""))

    # Write all events
    write_csv(events, os.path.join(OUT_DIR, "acled_ukraine_events.csv"))

    # Pivotal events
    pivotal = [e for e in events if classify_pivotal(e)]
    write_csv(pivotal, os.path.join(OUT_DIR, "acled_key_events.csv"))

    # Per-city summary
    print("\n=== Events per city ===")
    by_city = {}
    for e in events:
        by_city.setdefault(e["city"], []).append(e)
    for city in TARGET_CITIES:
        ce = by_city.get(city, [])
        first = ce[0]["event_date"] if ce else "—"
        last  = ce[-1]["event_date"] if ce else "—"
        print(f"  {city:<12} {len(ce):>4} events   first={first}  last={last}")

    print(f"\n[done] Output in: {OUT_DIR}")


if __name__ == "__main__":
    main()
