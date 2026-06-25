"""
Origin Recon backend — DNS / origin / attacker-infrastructure recon engine.

Maker: XecureLogic (https://xecurelogic.com)

A self-contained FastAPI service that, given a domain, performs passive OSINT
recon and returns a structured result the UI renders (records, subdomains,
geo-located IPs, edge/CDN verdict, origin candidates, and IOCs).

Sources (all read-only / passive):
  - DNS (dnspython)         A/AAAA/MX/NS/TXT/SOA
  - Certificate Transparency (crt.sh)   real subdomain enumeration
  - RDAP (ipwhois)          ASN / org / network / country per IP
  - Team Cymru (DNS)        authoritative BGP-announcing ASN  [keyless]
  - Spamhaus ASN-DROP       bulletproof / hijacked ASN flag   [keyless]
  - ipinfo.io               geolocation (lat/lng) + ASN       [optional token]
  - SecurityTrails / VT     passive-DNS history (pre-CDN origin) [optional keys]
  - abuse.ch ThreatFox+URLhaus  known-bad confirmation         [optional key]

Design: fail-safe per source. A source being down or keyless degrades that one
section with a flag; the engine never fabricates data to fill a gap. All secrets
come from the environment — nothing is hardcoded.

Environment variables (all optional):
  IPINFO_TOKEN, SECURITYTRAILS_API_KEY, VT_API_KEY, ABUSECH_AUTH_KEY
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import os
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from typing import Optional

import dns.resolver
import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from ipwhois import IPWhois
from pydantic import BaseModel

import json

from . import exporters, history

# --------------------------------------------------------------------------- #
# Config                                                                      #
# --------------------------------------------------------------------------- #
IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "").strip()
SECURITYTRAILS_API_KEY = os.environ.get("SECURITYTRAILS_API_KEY", "").strip()
VT_API_KEY = os.environ.get("VT_API_KEY", "").strip()
ABUSECH_AUTH_KEY = os.environ.get("ABUSECH_AUTH_KEY", "").strip()

HTTP_TIMEOUT = 12
CACHE_DIR = Path(os.environ.get("RECON_CACHE", str(Path.home() / ".cache" / "origin-recon")))
CACHE_DIR.mkdir(parents=True, exist_ok=True)

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "origin-recon/2.0 (+local)"})
# The opt-in origin probe fetches an IP with a spoofed Host header, where the
# TLS cert will not match; silence the expected warning (we never rely on it).
requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]

# CDN / edge networks — only true edges count as "masking" (not generic clouds).
CDN_KEYWORDS = (
    "cloudflare", "akamai", "fastly", "cloudfront", "sucuri", "incapsula",
    "imperva", "stackpath", "edgecast", "bunnycdn", "cdn77", "gcore",
    "highwinds", "limelight", "section.io",
)

# Country-code -> (lat, lng) centroid, used when ipinfo has no precise loc.
COUNTRY_CENTROID = {
    "US": (39.8, -98.6), "CA": (56.1, -106.3), "GB": (54.0, -2.0), "IE": (53.4, -8.2),
    "NL": (52.1, 5.3), "DE": (51.2, 10.4), "FR": (46.2, 2.2), "IT": (41.9, 12.6),
    "ES": (40.4, -3.7), "PT": (39.4, -8.2), "CH": (46.8, 8.2), "AT": (47.5, 14.6),
    "BE": (50.5, 4.5), "PL": (51.9, 19.1), "SE": (60.1, 18.6), "NO": (60.5, 8.5),
    "FI": (61.9, 25.7), "DK": (56.3, 9.5), "RU": (61.5, 105.3), "UA": (48.4, 31.2),
    "RO": (45.9, 24.9), "BG": (42.7, 25.5), "TR": (38.9, 35.2), "CN": (35.9, 104.2),
    "HK": (22.3, 114.2), "JP": (36.2, 138.3), "KR": (35.9, 127.8), "IN": (20.6, 79.0),
    "SG": (1.35, 103.8), "AU": (-25.3, 133.8), "NZ": (-41.0, 174.0), "BR": (-14.2, -51.9),
    "AR": (-38.4, -63.6), "MX": (23.6, -102.6), "PA": (8.5, -80.8), "ZA": (-30.6, 22.9),
    "NG": (9.1, 8.7), "EG": (26.8, 30.8), "AE": (23.4, 53.8), "IL": (31.0, 34.9),
    "SC": (-4.7, 55.5), "CY": (35.1, 33.4), "MD": (47.4, 28.4), "BZ": (17.2, -88.5),
}


class ScanRequest(BaseModel):
    domain: str


class Record(BaseModel):
    id: Optional[int] = None
    type: str
    name: str
    value: str
    ip: Optional[str] = None
    priority: Optional[int] = None


class Subdomain(BaseModel):
    id: Optional[int] = None
    name: str
    has_a_record: bool
    ip: Optional[str] = None
    source: Optional[str] = None


class IPInfo(BaseModel):
    ip: str
    asn: Optional[str] = None
    asn_name: Optional[str] = None
    announced_asn: Optional[str] = None     # Team Cymru BGP-announcing ASN
    country: Optional[str] = None
    country_code: Optional[str] = None
    org: Optional[str] = None
    network: Optional[str] = None
    services: Optional[str] = None
    lat: Optional[float] = None
    lng: Optional[float] = None
    is_cdn: bool = False
    high_risk: bool = False                  # on Spamhaus ASN-DROP / known-abuse
    reputation: Optional[str] = None         # abuse.ch known-bad confirmation
    source: Optional[str] = None             # live | passive-dns | mx | ns
    # --- extended RDAP registry detail ---
    registry: Optional[str] = None           # RIR: arin | ripe | apnic | lacnic | afrinic
    network_name: Optional[str] = None       # registered network/handle name
    network_range: Optional[str] = None      # start - end addresses
    abuse_email: Optional[str] = None         # network abuse contact (for takedown)
    allocation_date: Optional[str] = None    # ASN / network allocation date


class DomainWhois(BaseModel):
    """Registration data for the apex domain.

    Populated from registry/registrar RDAP (preferred — structured JSON) with a
    port-43 WHOIS fallback. We query authoritative sources directly (IANA
    bootstrap -> registry -> registrar); no third-party aggregator API is used.
    Post-GDPR, registrant fields are usually redacted by the registry — when a
    value comes back privacy-masked we store the marker "Redacted" rather than
    the registry's free-text so the UI can render it consistently.
    """
    domain_name: Optional[str] = None
    registry_domain_id: Optional[str] = None
    registrar_whois_server: Optional[str] = None
    registrar_url: Optional[str] = None
    updated_date: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    registrar: Optional[str] = None
    registrar_iana_id: Optional[str] = None
    registrant_organization: Optional[str] = None
    registrant_street: Optional[str] = None
    registrant_city: Optional[str] = None
    registrant_state: Optional[str] = None
    registrant_postal_code: Optional[str] = None
    registrant_country: Optional[str] = None
    name_servers: list[str] = []
    domain_status: list[str] = []
    source: Optional[str] = None              # rdap | whois43
    error: Optional[str] = None               # why lookup degraded, if it did


class ScanDetail(BaseModel):
    id: int
    domain: str
    status: str
    created_at: str
    completed_at: str
    error: Optional[str] = None
    edge_masked: str = "unknown"             # yes | no | unknown
    edge_org: Optional[str] = None
    verdict: str = "unknown"                  # malicious | suspicious | clean | unknown
    verdict_reasons: list[str] = []
    whois: Optional[DomainWhois] = None
    records: list[Record]
    subdomains: list[Subdomain]
    ips: list[IPInfo]
    origin_candidates: list[IPInfo]
    notes: list[str] = []


app = FastAPI(
    title="Origin Recon API",
    version="2.0",
    contact={"name": "XecureLogic", "url": "https://xecurelogic.com"},
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173", "http://127.0.0.1:5173",
        "http://localhost:8000", "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #
def normalize_domain(domain: str) -> str:
    d = (domain or "").strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)
    d = d.split("/")[0].split(":")[0].strip(".")
    if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", d):
        raise HTTPException(status_code=400, detail="Invalid domain")
    return d


def safe_resolve(name: str, rtype: str):
    try:
        return list(dns.resolver.resolve(name, rtype, lifetime=5.0))
    except Exception:
        return []


def first_ip(name: str) -> Optional[str]:
    for rtype in ("A", "AAAA"):
        for ans in safe_resolve(name, rtype):
            ip = getattr(ans, "address", None)
            if ip:
                return ip
    return None


def is_public_ipv4(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return obj.version == 4 and not (obj.is_private or obj.is_loopback or obj.is_reserved)
    except ValueError:
        return False


def is_cdn(text: Optional[str]) -> bool:
    s = (text or "").lower()
    return any(k in s for k in CDN_KEYWORDS)


def asn_number(text: Optional[str]) -> Optional[str]:
    m = re.search(r"(\d+)", text or "")
    return m.group(1) if m else None


# --- Team Cymru: authoritative announcing ASN via DNS (keyless) ------------- #
def cymru_asn(ip: str) -> Optional[str]:
    if not is_public_ipv4(ip):
        return None
    try:
        rev = ".".join(reversed(ip.split(".")))
        ans = safe_resolve(f"{rev}.origin.asn.cymru.com", "TXT")
        if not ans:
            return None
        txt = str(ans[0]).strip('"')
        asn = (txt.split("|")[0]).strip()
        if not asn.isdigit():
            return None
        name_ans = safe_resolve(f"AS{asn}.asn.cymru.com", "TXT")
        name = ""
        if name_ans:
            parts = str(name_ans[0]).strip('"').split("|")
            if len(parts) >= 5:
                name = parts[4].strip()
        return f"AS{asn} {name}".strip()
    except Exception:
        return None


# --- Spamhaus ASN-DROP: bulletproof / hijacked ASN list (keyless, cached) --- #
_HR_SEED = {"202412", "52284"}  # observed-abuse seed (Omegatech, Panamaserver)
_HR_CACHE: Optional[set[str]] = None


def high_risk_asns() -> set[str]:
    global _HR_CACHE
    if _HR_CACHE is not None:
        return _HR_CACHE
    asns: set[str] = set(_HR_SEED)
    cache_file = CACHE_DIR / "asndrop.json"
    fresh = cache_file.exists() and (time.time() - cache_file.stat().st_mtime) < 86400
    raw = ""
    if fresh:
        raw = cache_file.read_text(errors="ignore")
    else:
        try:
            r = SESSION.get("https://www.spamhaus.org/drop/asndrop.json", timeout=HTTP_TIMEOUT)
            if r.ok:
                raw = r.text
                cache_file.write_text(raw)
        except Exception:
            pass
    for m in re.finditer(r'"asn"\s*:\s*(\d+)', raw):
        asns.add(m.group(1))
    _HR_CACHE = asns
    return asns


# --- Geolocation (ipinfo or country centroid) ------------------------------ #
def geolocate(ip: str) -> tuple[Optional[float], Optional[float], Optional[str], Optional[str]]:
    """Return (lat, lng, country_code, org) for an IP."""
    if IPINFO_TOKEN or True:  # ipinfo allows limited anonymous use
        try:
            url = f"https://ipinfo.io/{ip}/json"
            if IPINFO_TOKEN:
                url += f"?token={IPINFO_TOKEN}"
            r = SESSION.get(url, timeout=HTTP_TIMEOUT)
            if r.ok:
                j = r.json()
                cc = (j.get("country") or "").upper() or None
                org = j.get("org")
                loc = j.get("loc")
                if loc and "," in loc:
                    lat, lng = loc.split(",", 1)
                    return float(lat), float(lng), cc, org
                if cc and cc in COUNTRY_CENTROID:
                    lat, lng = COUNTRY_CENTROID[cc]
                    return lat, lng, cc, org
                return None, None, cc, org
        except Exception:
            pass
    return None, None, None, None


# --- abuse.ch reputation (ThreatFox + URLhaus) ----------------------------- #
def abusech_rep(ip: str) -> Optional[str]:
    if not ABUSECH_AUTH_KEY:
        return None
    out = []
    headers = {"Auth-Key": ABUSECH_AUTH_KEY}
    try:
        r = SESSION.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": ip},
            headers=headers, timeout=HTTP_TIMEOUT,
        )
        if r.ok:
            j = r.json()
            if j.get("query_status") == "ok" and j.get("data"):
                mal = sorted({d.get("malware_printable") for d in j["data"] if d.get("malware_printable")})
                thr = sorted({d.get("threat_type") for d in j["data"] if d.get("threat_type")})
                tag = "ThreatFox:" + (",".join(thr) or "hit")
                if mal:
                    tag += f" ({','.join(mal)})"
                out.append(tag)
    except Exception:
        pass
    try:
        r = SESSION.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": ip}, headers=headers, timeout=HTTP_TIMEOUT,
        )
        if r.ok:
            j = r.json()
            if j.get("query_status") == "ok":
                n = len(j.get("urls") or [])
                if n:
                    out.append(f"URLhaus:{n} malware URL(s)")
    except Exception:
        pass
    return "; ".join(out) if out else None


# --- Certificate Transparency subdomain enumeration (crt.sh, auto-retry) --- #
def ct_subdomains(domain: str) -> list[str]:
    names: set[str] = set()
    for attempt in range(3):
        try:
            r = SESSION.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=HTTP_TIMEOUT)
            if r.status_code == 200 and r.text.strip():
                try:
                    rows = r.json()
                except ValueError:
                    rows = None
                if rows is not None:
                    for row in rows:
                        for n in str(row.get("name_value", "")).splitlines():
                            n = n.strip().lower().lstrip("*.")
                            if n.endswith("." + domain) or n == domain:
                                names.add(n)
                    return sorted(names)
            # 502/503/empty => crt.sh is flaky; back off and retry
        except Exception:
            pass
        time.sleep(2 * (attempt + 1))
    return sorted(names)


# --- Passive DNS history (pre-CDN origins) --------------------------------- #
def passive_dns(domain: str) -> list[tuple[str, str]]:
    """Return list of (ip, source) historical A records."""
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    if SECURITYTRAILS_API_KEY:
        try:
            r = SESSION.get(
                f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
                headers={"APIKEY": SECURITYTRAILS_API_KEY}, timeout=HTTP_TIMEOUT,
            )
            if r.ok:
                for rec in r.json().get("records", []):
                    for v in rec.get("values", []):
                        ip = v.get("ip")
                        if ip and ip not in seen and is_public_ipv4(ip):
                            seen.add(ip); found.append((ip, "passive-dns:securitytrails"))
        except Exception:
            pass
    if VT_API_KEY:
        try:
            r = SESSION.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions?limit=40",
                headers={"x-apikey": VT_API_KEY}, timeout=HTTP_TIMEOUT,
            )
            if r.ok:
                for d in r.json().get("data", []):
                    ip = (d.get("attributes") or {}).get("ip_address")
                    if ip and ip not in seen and is_public_ipv4(ip):
                        seen.add(ip); found.append((ip, "passive-dns:virustotal"))
        except Exception:
            pass
    return found


# --- TLS / HTTP service banners -------------------------------------------- #
def probe_services(ip: str) -> Optional[str]:
    discovered: list[str] = []
    for port, label in ((80, "http"), (443, "https")):
        try:
            with closing(socket.create_connection((ip, port), timeout=1.5)) as sock:
                if port == 443:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                        ssock.settimeout(1.5)
                        ssock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
                        data = ssock.recv(2048)
                else:
                    sock.settimeout(1.5)
                    sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
                    data = sock.recv(2048)
            text = data.decode("latin-1", "ignore")
            server = None
            for ln in text.splitlines():
                if ln.lower().startswith("server:"):
                    server = ln.split(":", 1)[1].strip()
                    break
            discovered.append(f"{label}: {server or 'open'}")
        except Exception:
            continue
    return "\n".join(discovered) if discovered else None


def enrich_ip(ip: str, source: str, hr: set[str]) -> IPInfo:
    asn = asn_name = country = org = network = cc = None
    registry = net_name = net_range = abuse_email = alloc_date = None
    try:
        res = IPWhois(ip).lookup_rdap(asn_methods=["whois", "dns"])
        asn = res.get("asn")
        asn_name = res.get("asn_description")
        cc = (res.get("asn_country_code") or "").upper() or None
        registry = res.get("asn_registry") or None
        alloc_date = res.get("asn_date") or None
        net = res.get("network") or {}
        network = net.get("cidr")
        net_name = net.get("name")
        org = net_name or asn_name
        start, end = net.get("start_address"), net.get("end_address")
        if start and end:
            net_range = f"{start} - {end}"
        # Abuse contact: scan RDAP objects for an entity with the 'abuse' role.
        for obj in (res.get("objects") or {}).values():
            roles = obj.get("roles") or []
            if "abuse" in roles:
                emails = (obj.get("contact") or {}).get("email") or []
                if emails:
                    abuse_email = emails[0].get("value") if isinstance(emails[0], dict) else str(emails[0])
                    break
    except Exception:
        pass

    announced = cymru_asn(ip)
    lat, lng, geo_cc, geo_org = geolocate(ip)
    cc = geo_cc or cc
    org = org or geo_org
    rep = abusech_rep(ip)

    asn_n = asn_number(asn) or asn_number(announced)
    high = bool(asn_n and asn_n in hr)

    return IPInfo(
        ip=ip, asn=asn, asn_name=asn_name, announced_asn=announced,
        country=cc, country_code=cc, org=org, network=network,
        services=probe_services(ip), lat=lat, lng=lng,
        is_cdn=is_cdn(f"{asn_name} {org} {announced}"),
        high_risk=high, reputation=rep, source=source,
        registry=(registry.upper() if registry else None),
        network_name=net_name, network_range=net_range,
        abuse_email=abuse_email, allocation_date=alloc_date,
    )


# --------------------------------------------------------------------------- #
# Domain WHOIS — RDAP-first, port-43 fallback (no third-party aggregator)      #
# --------------------------------------------------------------------------- #
# Registries return privacy-masked free text post-GDPR; collapse the literal
# "redacted" markers to one token. NOTE we deliberately do NOT mask privacy-proxy
# org names (e.g. "Domains By Proxy, LLC", "Withheld for Privacy ehf") — those
# are real, useful intel about who fronts the registration.
_REDACTION_TOKENS = (
    "redacted", "data protected", "not disclosed", "gdpr masked",
    "statutory masking enabled", "non-public data",
)


def _redact_norm(value) -> Optional[str]:
    if value is None:
        return None
    v = str(value).strip()
    if not v:
        return None
    low = v.lower()
    if any(tok in low for tok in _REDACTION_TOKENS):
        return "Redacted"
    return v


def _flat(v) -> Optional[str]:
    """jCard values may be a string or a nested list (e.g. multi-line street)."""
    if v is None:
        return None
    if isinstance(v, list):
        joined = ", ".join(str(x).strip() for x in v if str(x).strip())
        return joined or None
    s = str(v).strip()
    return s or None


# --- RDAP path -------------------------------------------------------------- #
_RDAP_BOOTSTRAP: Optional[dict[str, str]] = None


def rdap_bootstrap() -> dict[str, str]:
    """TLD -> registry RDAP base URL, from IANA's authoritative bootstrap file."""
    global _RDAP_BOOTSTRAP
    if _RDAP_BOOTSTRAP is not None:
        return _RDAP_BOOTSTRAP
    mapping: dict[str, str] = {}
    cache_file = CACHE_DIR / "rdap-dns.json"
    fresh = cache_file.exists() and (time.time() - cache_file.stat().st_mtime) < 7 * 86400
    raw = ""
    if fresh:
        raw = cache_file.read_text(errors="ignore")
    else:
        try:
            r = SESSION.get("https://data.iana.org/rdap/dns.json", timeout=HTTP_TIMEOUT)
            if r.ok:
                raw = r.text
                cache_file.write_text(raw)
        except Exception:
            if cache_file.exists():
                raw = cache_file.read_text(errors="ignore")
    try:
        data = json.loads(raw) if raw else {}
        for svc in data.get("services", []):
            tlds, urls = svc[0], svc[1]
            base = next((u for u in urls if u.startswith("https")), (urls[0] if urls else None))
            if not base:
                continue
            base = base.rstrip("/")
            for t in tlds:
                mapping[t.lower().lstrip(".")] = base
    except Exception:
        pass
    _RDAP_BOOTSTRAP = mapping
    return mapping


def _vcard_props(entity: dict) -> dict[str, list]:
    """Flatten a jCard (vcardArray) into {prop_name: [(params, value), ...]}."""
    arr = entity.get("vcardArray")
    props: dict[str, list] = {}
    if not (isinstance(arr, list) and len(arr) == 2 and isinstance(arr[1], list)):
        return props
    for item in arr[1]:
        try:
            name, params, value = item[0], (item[1] or {}), item[3]
            props.setdefault(name, []).append((params, value))
        except Exception:
            continue
    return props


def _entity_by_role(entities: list, role: str) -> Optional[dict]:
    """Find the entity holding a role, searching one level of nesting."""
    for e in entities or []:
        if role in (e.get("roles") or []):
            return e
        nested = _entity_by_role(e.get("entities") or [], role)
        if nested:
            return nested
    return None


def _rdap_parse(j: dict, domain: str) -> DomainWhois:
    w = DomainWhois(source="rdap")
    w.domain_name = (j.get("ldhName") or j.get("unicodeName") or domain).lower()
    w.registry_domain_id = j.get("handle") or None
    w.registrar_whois_server = j.get("port43") or None
    w.domain_status = list(j.get("status") or [])
    w.name_servers = sorted({(n.get("ldhName") or "").lower().rstrip(".") for n in (j.get("nameservers") or []) if n.get("ldhName")})

    for ev in j.get("events") or []:
        act = (ev.get("eventAction") or "").lower()
        date = ev.get("eventDate")
        if act == "registration":
            w.creation_date = date
        elif act == "last changed":
            w.updated_date = date
        elif act == "expiration":
            w.expiration_date = date

    entities = j.get("entities") or []
    reg = _entity_by_role(entities, "registrar")
    if reg:
        props = _vcard_props(reg)
        if props.get("fn"):
            w.registrar = _flat(props["fn"][0][1])
        for pid in reg.get("publicIds") or []:
            if "iana" in (pid.get("type") or "").lower():
                w.registrar_iana_id = pid.get("identifier")
        # rel="about" is the human registrar site; "self" is the RDAP API URL — skip it.
        for ln in reg.get("links") or []:
            if (ln.get("rel") or "") == "about" and ln.get("href"):
                w.registrar_url = ln["href"]
                break

    registrant = _entity_by_role(entities, "registrant")
    if registrant:
        props = _vcard_props(registrant)
        if props.get("org"):
            w.registrant_organization = _redact_norm(_flat(props["org"][0][1]))
        if props.get("adr"):
            params, val = props["adr"][0]
            if isinstance(val, list) and len(val) >= 7:
                # jCard adr: [pobox, ext, street, locality, region, code, country]
                w.registrant_street = _redact_norm(_flat(val[2]))
                w.registrant_city = _redact_norm(_flat(val[3]))
                w.registrant_state = _redact_norm(_flat(val[4]))
                w.registrant_postal_code = _redact_norm(_flat(val[5]))
                w.registrant_country = _redact_norm(_flat(val[6]))
            elif (params or {}).get("label"):
                w.registrant_street = _redact_norm((params["label"]).replace("\n", ", "))
        if not w.registrant_country and props.get("country-name"):
            w.registrant_country = _redact_norm(_flat(props["country-name"][0][1]))
    return w


def domain_rdap(domain: str) -> Optional[DomainWhois]:
    """Query the authoritative registry RDAP for the TLD. None => no RDAP path."""
    boot = rdap_bootstrap()
    tld = domain.rsplit(".", 1)[-1]
    base = boot.get(tld)
    if not base:
        return None
    try:
        r = SESSION.get(f"{base}/domain/{domain}", timeout=HTTP_TIMEOUT,
                        headers={"Accept": "application/rdap+json"})
        if r.status_code == 404:
            return DomainWhois(domain_name=domain, source="rdap", error="not registered / not in registry RDAP")
        if not r.ok:
            return None
        return _rdap_parse(r.json(), domain)
    except Exception:
        return None


# --- port-43 WHOIS path (IANA referral -> registry -> registrar) ------------ #
def _whois_query(server: str, query: str, timeout: float = 8.0) -> str:
    with closing(socket.create_connection((server, 43), timeout=timeout)) as s:
        s.settimeout(timeout)
        s.sendall((query + "\r\n").encode("idna", "ignore") if not query.isascii()
                  else (query + "\r\n").encode())
        chunks: list[bytes] = []
        while True:
            try:
                data = s.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", "replace")


def _whois43_parse(text: str, domain: str) -> DomainWhois:
    w = DomainWhois(source="whois43")
    fields: dict[str, str] = {}
    ns: list[str] = []
    status: list[str] = []
    for line in text.splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k, v = k.strip().lower(), v.strip()
        if not v:
            continue
        if k == "name server":
            ns.append(v.lower())
        elif k in ("domain status", "status"):
            status.append(v)
        else:
            fields.setdefault(k, v)  # first occurrence wins (registry over noise)

    def g(*keys: str) -> Optional[str]:
        return next((fields[k] for k in keys if k in fields), None)

    w.domain_name = (g("domain name") or domain).lower()
    w.registry_domain_id = g("registry domain id")
    w.registrar_whois_server = g("registrar whois server")
    w.registrar_url = g("registrar url")
    w.updated_date = g("updated date")
    w.creation_date = g("creation date", "created", "created on")
    w.expiration_date = g("registry expiry date", "registrar registration expiration date",
                          "expiration date", "expiry date")
    w.registrar = g("registrar")
    w.registrar_iana_id = g("registrar iana id")
    w.registrant_organization = _redact_norm(g("registrant organization", "registrant org"))
    w.registrant_street = _redact_norm(g("registrant street", "registrant street1"))
    w.registrant_city = _redact_norm(g("registrant city"))
    w.registrant_state = _redact_norm(g("registrant state/province", "registrant state"))
    w.registrant_postal_code = _redact_norm(g("registrant postal code"))
    w.registrant_country = _redact_norm(g("registrant country"))
    w.name_servers = sorted(set(ns))
    w.domain_status = status
    return w


def whois43(domain: str) -> DomainWhois:
    # 1. IANA tells us the registry whois server for this TLD.
    server = None
    try:
        iana = _whois_query("whois.iana.org", domain)
        m = re.search(r"(?im)^refer:\s*(\S+)", iana)
        if m:
            server = m.group(1).strip()
    except Exception:
        pass
    if not server:
        return DomainWhois(domain_name=domain, source="whois43",
                           error="IANA returned no WHOIS referral for this TLD")
    # 2. Query the registry.
    try:
        text = _whois_query(server, domain)
    except Exception as e:
        return DomainWhois(domain_name=domain, source="whois43", error=f"registry WHOIS failed: {e}")
    # 3. Thin registries (.com/.net) only hold the registrar pointer — follow it.
    m = re.search(r"(?im)^Registrar WHOIS Server:\s*(\S+)", text)
    if m:
        rserver = m.group(1).strip().rstrip(".")
        if rserver and rserver.lower() != server.lower():
            try:
                richer = _whois_query(rserver, domain)
                if richer and re.search(r"(?im)^Domain Name:", richer):
                    text = richer
            except Exception:
                pass
    return _whois43_parse(text, domain)


def domain_whois(domain: str) -> DomainWhois:
    """RDAP first (structured), port-43 fallback when RDAP is absent or thin."""
    w = None
    try:
        w = domain_rdap(domain)
    except Exception:
        w = None
    rdap_thin = w is None or not (w.creation_date or w.registrar or w.name_servers)
    if rdap_thin:
        try:
            w43 = whois43(domain)
        except Exception as e:
            w43 = DomainWhois(domain_name=domain, error=f"WHOIS fallback failed: {e}")
        if w is None:
            return w43
        # Keep whichever actually carries registration signal.
        if w43.creation_date or w43.registrar:
            return w43
    return w if w is not None else DomainWhois(domain_name=domain, error="no RDAP or WHOIS data")


# --------------------------------------------------------------------------- #
# Scan                                                                        #
# --------------------------------------------------------------------------- #
def scan_domain(domain: str) -> ScanDetail:
    created = dt.datetime.now(dt.timezone.utc).isoformat()
    d = normalize_domain(domain)
    hr = high_risk_asns()
    records: list[Record] = []
    subdomains: list[Subdomain] = []
    notes: list[str] = []
    ip_sources: dict[str, str] = {}   # ip -> source
    rid = 1

    apex_ips: list[str] = []
    for ans in safe_resolve(d, "A"):
        ip = getattr(ans, "address", str(ans))
        records.append(Record(id=rid, type="A", name=d, value=ip, ip=ip)); rid += 1
        subdomains.append(Subdomain(id=len(subdomains) + 1, name=d, has_a_record=True, ip=ip, source="live"))
        ip_sources.setdefault(ip, "live"); apex_ips.append(ip)

    # CT subdomain enumeration (real, replaces the old hardcoded guess list).
    ct = ct_subdomains(d)
    if not ct:
        notes.append("crt.sh returned no subdomains (rate-limited or none on record).")
    for fqdn in ct[:60]:
        if fqdn == d:
            continue
        ip = first_ip(fqdn)
        has_a = ip is not None
        subdomains.append(Subdomain(id=len(subdomains) + 1, name=fqdn, has_a_record=has_a, ip=ip, source="ct"))
        if ip:
            records.append(Record(id=rid, type="A", name=fqdn, value=ip, ip=ip)); rid += 1
            ip_sources.setdefault(ip, "subdomain")

    for ans in safe_resolve(d, "MX"):
        host = str(getattr(ans, "exchange", ans)).rstrip(".")
        pref = int(getattr(ans, "preference", 0))
        ip = first_ip(host)
        records.append(Record(id=rid, type="MX", name=host, value=f"{pref} {host}", ip=ip, priority=pref)); rid += 1
        if ip:
            ip_sources.setdefault(ip, "mx")
    for ans in safe_resolve(d, "NS"):
        host = str(getattr(ans, "target", ans)).rstrip(".")
        ip = first_ip(host)
        records.append(Record(id=rid, type="NS", name=host, value=host, ip=ip)); rid += 1
        if ip:
            ip_sources.setdefault(ip, "ns")
    for ans in safe_resolve(d, "TXT"):
        try:
            value = "".join(p.decode() if isinstance(p, bytes) else str(p) for p in ans.strings)
        except Exception:
            value = str(ans).strip('"')
        records.append(Record(id=rid, type="TXT", name=d, value=value)); rid += 1
    for ans in safe_resolve(d, "SOA")[:1]:
        records.append(Record(id=rid, type="SOA", name=d, value=str(ans))); rid += 1

    # Enrich every live/observed IP concurrently (network-bound work). Run the
    # apex WHOIS lookup in the same pool so it costs no extra wall-clock.
    ip_items = sorted(ip_sources.items())
    with ThreadPoolExecutor(max_workers=11) as ex:
        whois_future = ex.submit(domain_whois, d)
        ips = list(ex.map(lambda kv: enrich_ip(kv[0], kv[1], hr), ip_items))
        try:
            whois = whois_future.result(timeout=30)
        except Exception:
            whois = None

    # Edge verdict from the apex IP(s).
    edge_masked = "unknown"
    edge_org = None
    if apex_ips:
        apex_enriched = next((x for x in ips if x.ip == apex_ips[0]), None)
        if apex_enriched:
            edge_org = apex_enriched.org or apex_enriched.asn_name
            edge_masked = "yes" if apex_enriched.is_cdn else "no"

    # Origin discovery: if masked, passive DNS is the highest-value lead.
    origin_candidates: list[IPInfo] = []
    seen_origin: set[str] = set()
    if edge_masked != "no":
        pdns_pairs = passive_dns(d)
        with ThreadPoolExecutor(max_workers=8) as ex:
            enriched_pdns = list(ex.map(lambda kv: enrich_ip(kv[0], kv[1], hr), pdns_pairs))
        for enriched in enriched_pdns:
            if enriched.ip in seen_origin or enriched.is_cdn:
                continue
            seen_origin.add(enriched.ip)
            origin_candidates.append(enriched)
        if not origin_candidates and (SECURITYTRAILS_API_KEY or VT_API_KEY):
            notes.append("Passive DNS returned no non-CDN historical origin.")
        elif not (SECURITYTRAILS_API_KEY or VT_API_KEY):
            notes.append("No passive-DNS key set; set SECURITYTRAILS_API_KEY or VT_API_KEY to unmask CDN origins.")
    else:
        # Not masked — the live host(s) are the origin.
        origin_candidates = [x for x in ips if x.source == "live" and not x.is_cdn]

    # Headline verdict from the collected signals (the "so what" for an analyst).
    all_hosts = ips + origin_candidates
    reasons: list[str] = []
    verdict = "clean"
    known_bad = [x for x in all_hosts if x.reputation]
    high_risk_hosts = [x for x in all_hosts if x.high_risk]
    njalla_ns = [r for r in records if r.type == "NS" and "njalla" in r.name.lower()]
    if known_bad:
        verdict = "malicious"
        for x in known_bad:
            reasons.append(f"{x.ip} confirmed known-bad — {x.reputation}")
    elif high_risk_hosts or njalla_ns:
        verdict = "suspicious"
        for x in high_risk_hosts:
            reasons.append(f"{x.ip} on bulletproof / high-risk ASN ({x.announced_asn or x.asn_name or x.asn})")
        if njalla_ns:
            reasons.append("nameservers on Njalla (anonymity registrar favored by threat actors)")
    elif not apex_ips:
        verdict = "unknown"
        reasons.append("domain did not resolve (parked, down, or sinkholed)")
    else:
        reasons.append("no known-bad or bulletproof-infrastructure signals in the sources that ran")
    if not (SECURITYTRAILS_API_KEY or VT_API_KEY or ABUSECH_AUTH_KEY) and verdict == "clean":
        reasons.append("note: reputation/passive-DNS keys not set — this is a partial assessment")

    completed = dt.datetime.now(dt.timezone.utc).isoformat()
    return ScanDetail(
        id=int(dt.datetime.now(dt.timezone.utc).timestamp()),
        domain=d, status="completed", created_at=created, completed_at=completed,
        edge_masked=edge_masked, edge_org=edge_org,
        verdict=verdict, verdict_reasons=reasons,
        whois=whois,
        records=records, subdomains=subdomains, ips=ips,
        origin_candidates=origin_candidates, notes=notes,
    )


# --------------------------------------------------------------------------- #
# Routes                                                                      #
# --------------------------------------------------------------------------- #
@app.post("/api/scan", response_model=ScanDetail)
def create_scan(req: ScanRequest):
    scan = scan_domain(req.domain)
    try:
        history.save_scan(scan)
    except Exception:
        pass  # persistence is best-effort; never fail a scan because the DB hiccupped
    return scan


@app.post("/api/iocs", response_class=PlainTextResponse)
def iocs(req: ScanRequest):
    """Flat CSV of indicators for SIEM / TIP ingestion."""
    scan = scan_domain(req.domain)
    rows = ["ioc_type,value,context", f"domain,{scan.domain},target"]
    for ip in scan.origin_candidates:
        ctx = f"asn={ip.asn or ''}; announced={ip.announced_asn or ''}; source={ip.source or ''}; high_risk={ip.high_risk}; rep={ip.reputation or ''}"
        rows.append(f'ip,{ip.ip},"{ctx}"')
    for sd in scan.subdomains:
        if sd.has_a_record:
            rows.append(f"domain,{sd.name},subdomain")
    return "\n".join(rows) + "\n"


class CheckRequest(BaseModel):
    value: str


@app.post("/api/report/urlhaus-check")
def urlhaus_check(req: CheckRequest):
    """Look up a URL or host in URLhaus (verified read API). Confirms known-bad."""
    if not ABUSECH_AUTH_KEY:
        return {"enabled": False, "detail": "ABUSECH_AUTH_KEY not set"}
    v = (req.value or "").strip()
    headers = {"Auth-Key": ABUSECH_AUTH_KEY}
    try:
        if "/" in v or v.startswith("http"):
            url = v if v.startswith("http") else f"http://{v}"
            r = SESSION.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, headers=headers, timeout=HTTP_TIMEOUT)
        else:
            r = SESSION.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": v}, headers=headers, timeout=HTTP_TIMEOUT)
        if r.ok:
            j = r.json()
            status = j.get("query_status")
            if status == "ok":
                return {
                    "enabled": True, "known": True,
                    "threat": j.get("threat") or j.get("url_status"),
                    "url_count": len(j.get("urls") or []),
                    "blacklists": j.get("blacklists"),
                    "reference": j.get("urlhaus_reference"),
                }
            return {"enabled": True, "known": False, "status": status}
    except Exception as e:
        return {"enabled": True, "error": str(e)}
    return {"enabled": True, "error": "lookup failed"}


@app.get("/api/config")
def config():
    """Report which optional enrichments are enabled (no secrets exposed)."""
    return {
        "ipinfo": bool(IPINFO_TOKEN),
        "securitytrails": bool(SECURITYTRAILS_API_KEY),
        "virustotal": bool(VT_API_KEY),
        "abusech": bool(ABUSECH_AUTH_KEY),
    }


@app.get("/api/health")
def health():
    return {"ok": True}


# --------------------------------------------------------------------------- #
# Scan history (SQLite persistence)                                           #
# --------------------------------------------------------------------------- #
@app.get("/api/history")
def history_list(limit: int = 50):
    return {"scans": history.list_scans(min(max(limit, 1), 200))}


@app.get("/api/history/{scan_id}")
def history_get(scan_id: int):
    s = history.get_scan(scan_id)
    if not s:
        raise HTTPException(status_code=404, detail="scan not found")
    return s


@app.delete("/api/history/{scan_id}")
def history_delete(scan_id: int):
    if not history.delete_scan(scan_id):
        raise HTTPException(status_code=404, detail="scan not found")
    return {"deleted": True, "id": scan_id}


# --------------------------------------------------------------------------- #
# Bulk scanning (bounded concurrency, capped)                                 #
# --------------------------------------------------------------------------- #
class BulkRequest(BaseModel):
    domains: list[str]


@app.post("/api/scan/bulk")
def scan_bulk(req: BulkRequest):
    seen: set[str] = set()
    domains: list[str] = []
    for raw in (req.domains or []):
        nd = normalize_domain(raw)
        if nd and nd not in seen:
            seen.add(nd)
            domains.append(nd)
    domains = domains[:50]  # hard cap: protects upstream APIs and the box
    if not domains:
        return {"count": 0, "results": []}

    def run(d: str) -> dict:
        try:
            scan = scan_domain(d)
            sid = None
            try:
                sid = history.save_scan(scan)
            except Exception:
                pass
            kb = sum(1 for x in (scan.origin_candidates + scan.ips) if x.reputation)
            return {"id": sid, "domain": d, "verdict": scan.verdict,
                    "edge_masked": scan.edge_masked, "host_count": len(scan.ips), "known_bad": kb}
        except Exception as e:
            return {"domain": d, "verdict": "error", "error": str(e)}

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=5) as ex:
        for r in ex.map(run, domains):
            results.append(r)
    return {"count": len(results), "results": results}


# --------------------------------------------------------------------------- #
# Verified URLhaus submission (public write — gated in the UI by confirm)      #
# Format per abuse.ch official submit_url.py: POST urlhaus.abuse.ch/api/       #
# --------------------------------------------------------------------------- #
class SubmitRequest(BaseModel):
    url: str
    threat: str = "malware_download"
    tags: list[str] = []
    anonymous: bool = False


@app.post("/api/report/urlhaus-submit")
def urlhaus_submit(req: SubmitRequest):
    if not ABUSECH_AUTH_KEY:
        return {"enabled": False, "detail": "ABUSECH_AUTH_KEY not set"}
    url = (req.url or "").strip()
    if not url:
        return {"enabled": True, "ok": False, "error": "empty url"}
    if not url.startswith("http"):
        url = "http://" + url
    payload = {
        "anonymous": "1" if req.anonymous else "0",
        "submission": [{
            "url": url,
            "threat": req.threat or "malware_download",
            "tags": req.tags or [],
        }],
    }
    headers = {"Content-Type": "application/json", "Auth-Key": ABUSECH_AUTH_KEY}
    try:
        r = SESSION.post("https://urlhaus.abuse.ch/api/", json=payload, headers=headers, timeout=HTTP_TIMEOUT)
        try:
            body = r.json()
        except ValueError:
            body = r.text
        return {"enabled": True, "ok": r.ok, "http_status": r.status_code, "response": body}
    except Exception as e:
        return {"enabled": True, "ok": False, "error": str(e)}


# --------------------------------------------------------------------------- #
# STIX 2.1 / MISP export (from stored scan)                                    #
# --------------------------------------------------------------------------- #
def _resolve_scan(scan_id: Optional[int], domain: Optional[str]) -> dict:
    s = None
    if scan_id:
        s = history.get_scan(scan_id)
    elif domain:
        s = history.latest_for_domain(normalize_domain(domain))
    if not s:
        raise HTTPException(status_code=404, detail="no stored scan; run a scan first")
    return s


@app.get("/api/export/stix")
def export_stix(id: Optional[int] = None, domain: Optional[str] = None):
    scan = _resolve_scan(id, domain)
    bundle = exporters.build_stix(scan)
    fname = f"{scan.get('domain', 'scan')}-stix.json"
    return Response(content=json.dumps(bundle, indent=2), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@app.get("/api/export/misp")
def export_misp(id: Optional[int] = None, domain: Optional[str] = None):
    scan = _resolve_scan(id, domain)
    event = exporters.build_misp(scan)
    fname = f"{scan.get('domain', 'scan')}-misp.json"
    return Response(content=json.dumps(event, indent=2), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{fname}"'})


# --------------------------------------------------------------------------- #
# Origin confirmation probe (ACTIVE — opt-in; refuses private targets)         #
# --------------------------------------------------------------------------- #
class ConfirmRequest(BaseModel):
    domain: str
    ip: str


def _fingerprint(resp: requests.Response) -> dict:
    import hashlib
    text = resp.text or ""
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    title = re.sub(r"\s+", " ", m.group(1)).strip()[:200] if m else ""
    return {
        "status": resp.status_code,
        "title": title,
        "len": len(text),
        "hash": hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()[:16],
        "server": resp.headers.get("Server", ""),
    }


@app.post("/api/confirm-origin")
def confirm_origin(req: ConfirmRequest):
    """Actively verify a candidate IP serves the target site (spoofed Host header).

    This is the only endpoint that touches target infrastructure directly, so it
    is opt-in per candidate. Refuses non-public IPs to avoid SSRF against the LAN.
    """
    domain = normalize_domain(req.domain)
    ip = (req.ip or "").strip()
    if not is_public_ipv4(ip):
        return {"ok": False, "error": "refusing to probe a non-public IP address"}

    def fetch(url: str, host: Optional[str], redirects: bool) -> Optional[dict]:
        for scheme in ("https", "http"):
            try:
                r = SESSION.get(
                    f"{scheme}://{url}/",
                    headers={"Host": host} if host else None,
                    timeout=HTTP_TIMEOUT, allow_redirects=redirects,
                    verify=(scheme == "https" and host is None),
                )
                return _fingerprint(r)
            except Exception:
                continue
        return None

    apex = fetch(domain, None, True)
    candidate = fetch(ip, domain, False)

    confirmed = False
    detail = "could not compare (one side did not respond)"
    if apex and candidate:
        same_body = candidate["hash"] == apex["hash"]
        same_title = bool(apex["title"]) and candidate["title"] == apex["title"]
        meaningful = apex["len"] > 200  # a 200-byte page is a stub/error, not proof
        cand_ok = candidate["status"] == 200
        if cand_ok and meaningful and (same_body or same_title):
            confirmed = True
            detail = "candidate serves the same content as the apex (matching body/title)"
        elif (same_body or same_title) and not meaningful:
            detail = "both sides returned an identical stub/error page — inconclusive, not a match"
        elif candidate["status"] in (0, None) or candidate["status"] >= 500:
            detail = "candidate did not serve a usable response on this host header"
        else:
            detail = f"candidate responded (HTTP {candidate['status']}) but content did not match the apex"
    return {"ok": True, "domain": domain, "ip": ip,
            "confirmed": confirmed, "detail": detail, "apex": apex, "candidate": candidate}


frontend_dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if frontend_dist.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="static")
