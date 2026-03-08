"""
backend/intel.py
Firestore-backed shared intelligence layer for XSEVERITY.
Handles country intel cache, CVE cache, and range cache.
"""

import os
from datetime import datetime, timedelta
from typing import Optional

# ── Firestore client (lazy init) ───────────────────────────────────────────
_db = None

def get_db():
    global _db
    if _db is None:
        from google.cloud import firestore
        # Set GOOGLE_APPLICATION_CREDENTIALS env var to your service account JSON
        # Or use Application Default Credentials if running on GCP
        _db = firestore.Client()
    return _db


# ══════════════════════════════════════════════════════════════════════════
# Freshness helpers
# ══════════════════════════════════════════════════════════════════════════

def _age_days(ts) -> int:
    """Return age in days from a Firestore timestamp or datetime."""
    if ts is None:
        return 9999
    if hasattr(ts, 'timestamp'):
        dt = datetime.fromtimestamp(ts.timestamp())
    else:
        dt = ts
    return (datetime.utcnow() - dt).days


def _freshness_label(age_days: int) -> str:
    if age_days < 1:
        return "fresh"
    if age_days < 7:
        return "recent"
    if age_days < 30:
        return "aging"
    return "stale"


# ══════════════════════════════════════════════════════════════════════════
# Range cache  (30-day TTL, shared across all users)
# ══════════════════════════════════════════════════════════════════════════

def _range_key(country: str, rirs: list[str]) -> str:
    return f"{country.upper()}_{'_'.join(sorted(r.upper() for r in rirs))}"


async def get_cached_ranges(country: str, rirs: list[str]) -> Optional[dict]:
    """
    Returns cached range data if fresh (< 30 days), else None.
    Caller should fall back to live RIR fetch.
    """
    try:
        db = get_db()
        key = _range_key(country, rirs)
        doc = db.collection("range_cache").document(key).get()
        if not doc.exists:
            return None
        data = doc.to_dict()
        age = _age_days(data.get("cached_at"))
        return {
            **data,
            "from_cache": True,
            "age_days": age,
            "freshness": _freshness_label(age),
            "stale": age >= 30,
        }
    except Exception as e:
        print(f"[intel] range cache read error: {e}")
        return None


async def save_cached_ranges(country: str, rirs: list[str], result: dict):
    """Save fresh range fetch result to Firestore."""
    try:
        db = get_db()
        key = _range_key(country, rirs)
        now = datetime.utcnow()
        db.collection("range_cache").document(key).set({
            "country": result["country"],
            "country_name": result.get("country_name", ""),
            "rirs": result.get("rirs", rirs),
            "counts": result.get("counts", {}),
            "total": result.get("total", len(result.get("ranges", []))),
            "ranges": result.get("ranges", []),
            "last_updated": result.get("last_updated"),
            "masscan_hint": result.get("masscan_hint"),
            "cached_at": now,
            "expires_at": now + timedelta(days=30),
        })
        print(f"[intel] range cache saved: {key}")
    except Exception as e:
        print(f"[intel] range cache write error: {e}")


# ══════════════════════════════════════════════════════════════════════════
# CVE cache  (7-day TTL, keyed by software string)
# ══════════════════════════════════════════════════════════════════════════

def _cve_key(software: str, version: Optional[str]) -> str:
    base = software.lower().replace(" ", "_").replace("/", "_")
    if version:
        base += f"__{version.lower().replace(' ', '_')}"
    return base[:200]  # Firestore doc ID limit


async def get_cached_cves(software: str, version: Optional[str]) -> Optional[list]:
    """Returns cached CVE list if < 7 days old, else None."""
    try:
        db = get_db()
        key = _cve_key(software, version)
        doc = db.collection("cve_cache").document(key).get()
        if not doc.exists:
            return None
        data = doc.to_dict()
        age = _age_days(data.get("cached_at"))
        if age >= 7:
            return None
        return data.get("cves", [])
    except Exception as e:
        print(f"[intel] CVE cache read error: {e}")
        return None


async def save_cached_cves(software: str, version: Optional[str], cves: list):
    """Save CVE lookup result to Firestore."""
    try:
        db = get_db()
        key = _cve_key(software, version)
        now = datetime.utcnow()
        db.collection("cve_cache").document(key).set({
            "software": software,
            "version": version,
            "cves": cves,
            "cached_at": now,
            "expires_at": now + timedelta(days=7),
        })
    except Exception as e:
        print(f"[intel] CVE cache write error: {e}")


# ══════════════════════════════════════════════════════════════════════════
# Country intel  (crowdsourced scan results per country)
# ══════════════════════════════════════════════════════════════════════════

async def get_country_intel(country: str) -> Optional[dict]:
    """Returns current community scan state for a country."""
    try:
        db = get_db()
        doc = db.collection("country_intel").document(country.upper()).get()
        if not doc.exists:
            return None
        data = doc.to_dict()
        age = _age_days(data.get("last_scanned"))
        return {
            **data,
            "found": True,
            "age_days": age,
            "freshness": _freshness_label(age),
            "stale": age >= 30,
        }
    except Exception as e:
        print(f"[intel] country intel read error: {e}")
        return None


async def contribute_country_intel(country: str, payload: dict):
    """
    Called when a scan completes. Merges new scan data into country intel.
    Appends hits (capped at 500), updates stats, increments scan count.
    """
    try:
        from google.cloud import firestore as _fs
        db = get_db()
        ref = db.collection("country_intel").document(country.upper())
        doc = ref.get()

        now = datetime.utcnow()
        new_hits = payload.get("hits", [])

        # Cap hits at 500 — keep most recent
        existing_hits = []
        if doc.exists:
            existing_hits = doc.to_dict().get("hits", [])
        merged_hits = (existing_hits + new_hits)[-500:]

        # Build top software list from all hits
        software_count: dict = {}
        for hit in merged_hits:
            sw = hit.get("software")
            if sw:
                software_count[sw] = software_count.get(sw, 0) + 1
        top_software = sorted(software_count, key=software_count.get, reverse=True)[:10]

        # Build CVE summary
        cve_map: dict = {}
        for hit in merged_hits:
            for cve in hit.get("cves", []):
                cid = cve.get("id")
                if cid and cid not in cve_map:
                    cve_map[cid] = cve
        cve_summary = sorted(
            cve_map.values(),
            key=lambda c: float(c.get("score", 0) or 0),
            reverse=True
        )[:20]

        update = {
            "country": country.upper(),
            "country_name": payload.get("country_name", ""),
            "last_scanned": now,
            "scan_count": _fs.Increment(1),
            "stats": {
                "probed": payload.get("probed", 0),
                "open": payload.get("open", 0),
                "vulns": payload.get("vulns", 0),
            },
            "hits": merged_hits,
            "top_software": top_software,
            "cve_summary": cve_summary,
        }

        ref.set(update, merge=True)
        print(f"[intel] country intel updated: {country.upper()}")
    except Exception as e:
        print(f"[intel] country intel write error: {e}")