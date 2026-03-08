"""Core helpers wrapping the legacy CLI functions for API usage."""

import asyncio
from datetime import datetime
from typing import Dict, List, Optional

import aiohttp

from main import (
    RIRS,
    COUNTRY_HINTS,
    CVE_PROBE_PORTS,
    ensure_cache_dir,
    download_rir,
    parse_ranges,
    query_nvd,
)

# Comprehensive port set used when suggesting a masscan command
MASSCAN_PORTS: List[int] = [
    80, 443, 8080, 8443, 8000, 8001, 8008, 8088, 8888, 9090, 9443,
    21, 990, 22, 23, 2222,
    25, 465, 587, 110, 995, 143, 993,
    53, 139, 445, 137, 138, 3389,
    1433, 1434, 3306, 5432, 5984, 6379, 9200, 9300, 27017, 27018, 28017,
    500, 1194, 1701, 1723, 4500,
    161, 162, 199, 10161,
    2082, 2083, 2086, 2087, 2095, 2096,
    10000, 20000,
    4848, 7001, 7002, 9060, 9080,
    8161, 61616, 61613,
    4444, 4445, 8009,
    9000, 9001, 9002,
    8200, 8201, 8500,
    2375, 2376, 2377,
    6443, 10250, 10255,
    50070, 50075,
    5672, 15672, 25672,
    9092, 2181,
    3000, 9100, 5601, 4567,
    111, 2049,
    512, 513, 514,
    5900, 5901, 5902,
    6000, 6001, 11211,
    389, 636, 3268, 3269,
    88, 464, 102, 502,
]


def list_countries() -> List[Dict[str, str]]:
    return [
        {"code": code, "name": name}
        for code, name in sorted(COUNTRY_HINTS.items())
    ]


def list_rirs() -> List[Dict[str, str]]:
    return [{"name": name, "url": url} for name, url in RIRS.items()]


def build_masscan_hint(ranges_file: str, rate: int = 10000) -> str:
    ports_arg = ",".join(str(p) for p in MASSCAN_PORTS)
    return f"masscan -iL {ranges_file} -p {ports_arg} --rate {rate} -oJ scan_output.json"


def masscan_probe_ports() -> List[int]:
    return sorted(CVE_PROBE_PORTS)


def _validate_country(country_code: str) -> str:
    if not country_code or len(country_code) != 2:
        raise ValueError("country must be a 2-letter ISO code")
    return country_code.upper()


def _select_rirs(rirs: Optional[List[str]]) -> Dict[str, str]:
    if rirs is None:
        return dict(RIRS)
    selection = {k: v for k, v in RIRS.items() if k in rirs}
    if not selection:
        raise ValueError("no valid RIRs selected")
    return selection


async def fetch_ip_ranges(
    country_code: str,
    rirs: Optional[List[str]] = None,
    force: bool = False,
) -> Dict:
    country_code = _validate_country(country_code)
    selected_rirs = _select_rirs(rirs)

    ensure_cache_dir()

    connector = aiohttp.TCPConnector(limit=10)
    headers = {"User-Agent": "ip-range-api/1.0 (XSEVERITY)"}

    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        tasks = [download_rir(session, name, url, force=force) for name, url in selected_rirs.items()]
        results = await asyncio.gather(*tasks)

    valid_results = [(name, path) for name, path in results if path is not None]
    if not valid_results:
        return {
            "country": country_code,
            "country_name": COUNTRY_HINTS.get(country_code, "Unknown"),
            "rirs": list(selected_rirs.keys()),
            "counts": {},
            "ranges": [],
            "last_updated": None,
        }

    loop = asyncio.get_event_loop()
    parse_tasks = [
        loop.run_in_executor(None, parse_ranges, cache_path, country_code)
        for _, cache_path in valid_results
    ]
    parsed = await asyncio.gather(*parse_tasks)

    ranges_by_rir: Dict[str, List[str]] = {}
    all_ranges: set = set()
    for (rir_name, _), ranges in zip(valid_results, parsed):
        ranges_by_rir[rir_name] = ranges
        all_ranges.update(ranges)

    return {
        "country": country_code,
        "country_name": COUNTRY_HINTS.get(country_code, "Unknown"),
        "rirs": list(selected_rirs.keys()),
        "counts": {k: len(v) for k, v in ranges_by_rir.items()},
        "ranges": sorted(all_ranges),
        "last_updated": datetime.utcnow().isoformat() + "Z",
    }


async def search_cves(software: str, version: Optional[str] = None) -> List[Dict]:
    return await query_nvd(software, version or "")


def health_summary() -> Dict[str, str]:
    return {
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "available_rirs": len(RIRS),
    }
