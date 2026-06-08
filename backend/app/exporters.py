"""Export builders: STIX 2.1 bundle and MISP event JSON.

Both are built by hand (no external deps) from a stored scan payload. They emit
indicators for the target domain and every resolved/candidate IP, marking
abuse.ch-confirmed hosts as malicious and the rest as anomalous (lower trust).
"""
from __future__ import annotations

import datetime as dt
import uuid


def _stix_ts() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _hosts(scan: dict) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for x in (scan.get("origin_candidates") or []) + (scan.get("ips") or []):
        ip = x.get("ip")
        if ip and ip not in seen:
            seen.add(ip)
            out.append(x)
    return out


def build_stix(scan: dict) -> dict:
    now = _stix_ts()
    objects: list[dict] = []

    def indicator(pattern: str, name: str, itype: str) -> dict:
        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": now,
            "modified": now,
            "name": name,
            "indicator_types": [itype],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": now,
        }

    domain = scan.get("domain")
    verdict = scan.get("verdict")
    if domain:
        dtype = "malicious-activity" if verdict == "malicious" else "anomalous-activity"
        objects.append(indicator(f"[domain-name:value = '{domain}']", f"domain {domain}", dtype))
    for x in _hosts(scan):
        ip = x["ip"]
        itype = "malicious-activity" if x.get("reputation") else "anomalous-activity"
        label = x.get("org") or x.get("asn_name") or "unknown ASN"
        objects.append(indicator(f"[ipv4-addr:value = '{ip}']", f"host {ip} ({label})", itype))

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


def build_misp(scan: dict) -> dict:
    now = dt.datetime.now(dt.timezone.utc)
    domain = scan.get("domain")
    verdict = scan.get("verdict")
    attrs: list[dict] = []
    if domain:
        attrs.append({
            "type": "domain", "category": "Network activity",
            "value": domain, "to_ids": verdict == "malicious",
            "comment": f"Origin Recon verdict: {verdict}",
        })
    for x in _hosts(scan):
        attrs.append({
            "type": "ip-dst", "category": "Network activity",
            "value": x["ip"], "to_ids": bool(x.get("reputation")),
            "comment": x.get("reputation") or x.get("announced_asn") or x.get("org") or "",
        })

    threat_level = "2" if verdict == "malicious" else ("3" if verdict == "suspicious" else "4")
    return {
        "Event": {
            "info": f"Origin Recon — {domain}",
            "date": now.strftime("%Y-%m-%d"),
            "threat_level_id": threat_level,   # 1 high, 2 medium, 3 low, 4 undefined
            "analysis": "1",                   # ongoing
            "distribution": "0",               # your org only
            "Attribute": attrs,
        }
    }
