#!/usr/bin/env python3
"""
IP Range Lookup by Country Code — Async + CVE Scan
Author: CILYNX / xseverity@0f1c3r
Fetches IPv4 ranges from all 5 RIRs concurrently (RIPE, ARIN, APNIC, LACNIC, AFRINIC)
Optional: masscan streaming producer → async CVE worker pool (10 concurrent workers)
"""

import math
import asyncio
import aiohttp
import aiofiles
import sys
import os
import re
import json
import ipaddress
import urllib.request
import urllib.parse
import argparse
from datetime import datetime

# ── RIR Sources ─────────────────────────────────────────────────────────────
RIRS = {
    "RIPE":    "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest",
    "ARIN":    "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
    "APNIC":   "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest",
    "LACNIC":  "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-latest",
    "AFRINIC": "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-latest",
}

CACHE_DIR = os.path.join(os.path.expanduser("~"), ".ip_range_cache")

COUNTRY_HINTS = {
    # Balkans / Eastern Europe (priority)
    "BA": "Bosnia and Herzegovina",
    "RS": "Serbia",
    "HR": "Croatia",
    "SI": "Slovenia",
    "ME": "Montenegro",
    "MK": "North Macedonia",
    "AL": "Albania",
    # Major powers
    "US": "United States",
    "DE": "Germany",
    "FR": "France",
    "GB": "United Kingdom",
    "RU": "Russia",
    "CN": "China",
    "IL": "Israel",
    "TR": "Turkey",
    "RO": "Romania",
    "HU": "Hungary",
    "PL": "Poland",
    # Europe
    "AD": "Andorra",
    "AT": "Austria",
    "BE": "Belgium",
    "BG": "Bulgaria",
    "BY": "Belarus",
    "CH": "Switzerland",
    "CY": "Cyprus",
    "CZ": "Czech Republic",
    "DK": "Denmark",
    "EE": "Estonia",
    "ES": "Spain",
    "FI": "Finland",
    "GR": "Greece",
    "IE": "Ireland",
    "IS": "Iceland",
    "IT": "Italy",
    "LI": "Liechtenstein",
    "LT": "Lithuania",
    "LU": "Luxembourg",
    "LV": "Latvia",
    "MC": "Monaco",
    "MD": "Moldova",
    "MT": "Malta",
    "NL": "Netherlands",
    "NO": "Norway",
    "PT": "Portugal",
    "SE": "Sweden",
    "SK": "Slovakia",
    "SM": "San Marino",
    "UA": "Ukraine",
    "VA": "Vatican City",
    "XK": "Kosovo",
    # Asia
    "AE": "United Arab Emirates",
    "AF": "Afghanistan",
    "AM": "Armenia",
    "AZ": "Azerbaijan",
    "BD": "Bangladesh",
    "BH": "Bahrain",
    "BN": "Brunei",
    "BT": "Bhutan",
    "GE": "Georgia",
    "HK": "Hong Kong",
    "ID": "Indonesia",
    "IN": "India",
    "IQ": "Iraq",
    "IR": "Iran",
    "JO": "Jordan",
    "JP": "Japan",
    "KG": "Kyrgyzstan",
    "KH": "Cambodia",
    "KP": "North Korea",
    "KR": "South Korea",
    "KW": "Kuwait",
    "KZ": "Kazakhstan",
    "LA": "Laos",
    "LB": "Lebanon",
    "LK": "Sri Lanka",
    "MM": "Myanmar",
    "MN": "Mongolia",
    "MO": "Macau",
    "MV": "Maldives",
    "MY": "Malaysia",
    "NP": "Nepal",
    "OM": "Oman",
    "PH": "Philippines",
    "PK": "Pakistan",
    "PS": "Palestine",
    "QA": "Qatar",
    "SA": "Saudi Arabia",
    "SG": "Singapore",
    "SY": "Syria",
    "TH": "Thailand",
    "TJ": "Tajikistan",
    "TL": "Timor-Leste",
    "TM": "Turkmenistan",
    "TW": "Taiwan",
    "UZ": "Uzbekistan",
    "VN": "Vietnam",
    "YE": "Yemen",
    # Americas
    "AG": "Antigua and Barbuda",
    "AI": "Anguilla",
    "AR": "Argentina",
    "AW": "Aruba",
    "BB": "Barbados",
    "BL": "Saint Barthelemy",
    "BM": "Bermuda",
    "BO": "Bolivia",
    "BR": "Brazil",
    "BS": "Bahamas",
    "BZ": "Belize",
    "CA": "Canada",
    "CL": "Chile",
    "CO": "Colombia",
    "CR": "Costa Rica",
    "CU": "Cuba",
    "DM": "Dominica",
    "DO": "Dominican Republic",
    "EC": "Ecuador",
    "GD": "Grenada",
    "GP": "Guadeloupe",
    "GT": "Guatemala",
    "GY": "Guyana",
    "HN": "Honduras",
    "HT": "Haiti",
    "JM": "Jamaica",
    "KN": "Saint Kitts and Nevis",
    "KY": "Cayman Islands",
    "LC": "Saint Lucia",
    "MQ": "Martinique",
    "MX": "Mexico",
    "NI": "Nicaragua",
    "PA": "Panama",
    "PE": "Peru",
    "PR": "Puerto Rico",
    "PY": "Paraguay",
    "SR": "Suriname",
    "SV": "El Salvador",
    "TC": "Turks and Caicos Islands",
    "TT": "Trinidad and Tobago",
    "UY": "Uruguay",
    "VC": "Saint Vincent and the Grenadines",
    "VE": "Venezuela",
    "VG": "British Virgin Islands",
    "VI": "U.S. Virgin Islands",
    # Africa
    "AO": "Angola",
    "BF": "Burkina Faso",
    "BI": "Burundi",
    "BJ": "Benin",
    "BW": "Botswana",
    "CD": "DR Congo",
    "CF": "Central African Republic",
    "CG": "Republic of the Congo",
    "CI": "Ivory Coast",
    "CM": "Cameroon",
    "CV": "Cape Verde",
    "DJ": "Djibouti",
    "DZ": "Algeria",
    "EG": "Egypt",
    "ER": "Eritrea",
    "ET": "Ethiopia",
    "GA": "Gabon",
    "GH": "Ghana",
    "GM": "Gambia",
    "GN": "Guinea",
    "GQ": "Equatorial Guinea",
    "GW": "Guinea-Bissau",
    "KE": "Kenya",
    "KM": "Comoros",
    "LR": "Liberia",
    "LS": "Lesotho",
    "LY": "Libya",
    "MA": "Morocco",
    "MG": "Madagascar",
    "ML": "Mali",
    "MR": "Mauritania",
    "MU": "Mauritius",
    "MW": "Malawi",
    "MZ": "Mozambique",
    "NA": "Namibia",
    "NE": "Niger",
    "NG": "Nigeria",
    "RE": "Reunion",
    "RW": "Rwanda",
    "SC": "Seychelles",
    "SD": "Sudan",
    "SL": "Sierra Leone",
    "SN": "Senegal",
    "SO": "Somalia",
    "SS": "South Sudan",
    "ST": "Sao Tome and Principe",
    "SZ": "Eswatini",
    "TD": "Chad",
    "TG": "Togo",
    "TN": "Tunisia",
    "TZ": "Tanzania",
    "UG": "Uganda",
    "ZA": "South Africa",
    "ZM": "Zambia",
    "ZW": "Zimbabwe",
    # Oceania
    "AU": "Australia",
    "FJ": "Fiji",
    "FM": "Micronesia",
    "GU": "Guam",
    "KI": "Kiribati",
    "MH": "Marshall Islands",
    "MP": "Northern Mariana Islands",
    "NC": "New Caledonia",
    "NR": "Nauru",
    "NZ": "New Zealand",
    "PF": "French Polynesia",
    "PG": "Papua New Guinea",
    "PW": "Palau",
    "SB": "Solomon Islands",
    "TO": "Tonga",
    "TV": "Tuvalu",
    "VU": "Vanuatu",
    "WS": "Samoa",
}

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

# ════════════════════════════════════════════════════════════════════════════
# RIR Download & Parse
# ════════════════════════════════════════════════════════════════════════════

def ensure_cache_dir():
    os.makedirs(CACHE_DIR, exist_ok=True)

def get_cache_path(rir_name: str) -> str:
    return os.path.join(CACHE_DIR, f"{rir_name.lower()}_delegated.txt")

def is_cache_fresh(cache_path: str, max_age_hours: int = 24) -> bool:
    if not os.path.exists(cache_path):
        return False
    age = datetime.now().timestamp() - os.path.getmtime(cache_path)
    return age < (max_age_hours * 3600)

async def download_rir(session, rir_name: str, url: str, force: bool = False):
    cache_path = get_cache_path(rir_name)
    if not force and is_cache_fresh(cache_path):
        print(f"  [{rir_name}] Using cached data")
        return rir_name, cache_path
    print(f"  [{rir_name}] Downloading ...")
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=60)) as resp:
            resp.raise_for_status()
            data = await resp.read()
        async with aiofiles.open(cache_path, "wb") as f:
            await f.write(data)
        print(f"  [{rir_name}] Done ({len(data) // 1024} KB)")
        return rir_name, cache_path
    except Exception as e:
        print(f"  [{rir_name}] Failed: {e}")
        return rir_name, None

def parse_ranges(cache_path: str, country_code: str) -> list:
    ranges = []
    country_code = country_code.upper()
    try:
        with open(cache_path, "r", errors="ignore") as f:
            for line in f:
                if line.startswith("#") or line.startswith("2"):
                    continue
                parts = line.strip().split("|")
                if len(parts) < 7:
                    continue
                if (parts[1].upper() == country_code and parts[2] == "ipv4"
                        and parts[6] in ("allocated", "assigned")):
                    try:
                        ip     = parts[3]
                        count  = int(parts[4])
                        prefix = 32 - int(math.log2(count))
                        ranges.append(f"{ip}/{prefix}")
                    except (ValueError, ZeroDivisionError):
                        continue
    except Exception as e:
        print(f"  Parse error: {e}")
    return ranges

# ════════════════════════════════════════════════════════════════════════════
# Banner Grabbing
# ════════════════════════════════════════════════════════════════════════════

# Ports masscan scans AND CVE workers probe — must be a set for O(1) lookup
CVE_PROBE_PORTS = {21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017}

VERSION_PATTERNS = [
    (r"[Ss]erver:\s*([^\r\n]+)",       "HTTP Server"),
    (r"SSH-[\d.]+-([^\r\n ]+)",        "SSH"),
    (r"^220[- ]([^\r\n]+)",            "FTP"),
    (r"(Apache[/\s][\d.]+)",           "Apache"),
    (r"(nginx[/\s][\d.]+)",            "nginx"),
    (r"(OpenSSH[_\s][\d.p]+)",         "OpenSSH"),
    (r"(vsftpd[\s/][\d.]+)",           "vsftpd"),
    (r"(Microsoft-IIS[/\s][\d.]+)",    "IIS"),
    (r"(PHP[/\s][\d.]+)",              "PHP"),
    (r"(WordPress[\s/][\d.]+)",        "WordPress"),
    (r"(Jetty[/\s(][\d.]+)",           "Jetty"),
    (r"(Tomcat[/\s][\d.]+)",           "Tomcat"),
    (r"(lighttpd[/\s][\d.]+)",         "lighttpd"),
    (r"(ProFTPD[\s/][\d.]+)",          "ProFTPD"),
    (r"(OpenSSL[/\s][\d.a-z]+)",       "OpenSSL"),
    (r"(redis[\s_][\d.]+)",            "Redis"),
    (r"(MongoDB[\s/][\d.]+)",          "MongoDB"),
    (r"(Elasticsearch[/\s][\d.]+)",    "Elasticsearch"),
]

async def grab_banner(ip: str, port: int, timeout: float = 3.0):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        if port in (80, 8080, 8000, 8001, 8008, 8088, 8888):
            writer.write(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        else:
            writer.write(b"\r\n")
        await writer.drain()
        try:
            data   = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            banner = data.decode(errors="ignore").strip()
        except Exception:
            banner = ""
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return banner if banner else None
    except Exception:
        return None

def extract_version_info(banner: str) -> list:
    findings = []
    for pattern, label in VERSION_PATTERNS:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            findings.append({"label": label, "value": match.group(1).strip()})
    return findings

# ════════════════════════════════════════════════════════════════════════════
# NVD CVE Lookup
# ════════════════════════════════════════════════════════════════════════════

async def query_nvd(software: str, version_str: str) -> list:
    keyword = f"{software} {version_str}"
    encoded = urllib.parse.quote(keyword)
    url     = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={encoded}&resultsPerPage=5"
    try:
        loop = asyncio.get_event_loop()
        def fetch():
            req = urllib.request.Request(url, headers={"User-Agent": "cilynx-scanner/1.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.read()
        data = json.loads(await loop.run_in_executor(None, fetch))
        cves = []
        for vuln in data.get("vulnerabilities", []):
            cve      = vuln["cve"]
            cve_id   = cve["id"]
            desc     = cve["descriptions"][0]["value"][:120] if cve.get("descriptions") else "N/A"
            metrics  = cve.get("metrics", {})
            score = (
                metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore")
                or metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {}).get("baseScore")
                or metrics.get("cvssMetricV2",  [{}])[0].get("cvssData", {}).get("baseScore")
                or "N/A"
            )
            severity = (
                metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity")
                or metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {}).get("baseSeverity")
                or "N/A"
            )
            cves.append({"id": cve_id, "score": score, "severity": severity, "desc": desc})
        return cves
    except Exception:
        return []

# ════════════════════════════════════════════════════════════════════════════
# CVE Worker — consumes (ip, port) from queue, banner grabs + NVD lookup
# ════════════════════════════════════════════════════════════════════════════

CVE_POOL_SIZE = 10    # concurrent CVE workers
CVE_QUEUE_MAX = 50    # queue buffer — masscan blocks when full (backpressure)

async def cve_worker(
    worker_id:     int,
    queue:         asyncio.Queue,
    findings:      list,
    seen_software: set,
    lock:          asyncio.Lock,
    stats:         dict,
):
    while True:
        item = await queue.get()
        if item is None:          # poison pill → this worker shuts down
            queue.task_done()
            break

        ip, port = item

        async with lock:
            stats["probed"] += 1

        banner = await grab_banner(ip, port)
        if not banner:
            queue.task_done()
            continue

        async with lock:
            stats["responsive"] += 1

        version_info = extract_version_info(banner)
        if not version_info:
            print(f"  {DIM}[W{worker_id:02d}]{RESET} {CYAN}{ip}:{port}{RESET} → open (no version)")
            queue.task_done()
            continue

        for info in version_info:
            key = info["value"].lower()
            async with lock:
                if key in seen_software:
                    continue
                seen_software.add(key)

            print(f"  {DIM}[W{worker_id:02d}]{RESET} {CYAN}{ip}:{port}{RESET} → "
                  f"{BOLD}{info['label']}: {info['value']}{RESET}")

            cves = await query_nvd(info["label"], info["value"])

            if cves:
                for cve in cves:
                    try:
                        color = RED if float(cve["score"]) >= 7.0 else YELLOW
                    except (ValueError, TypeError):
                        color = YELLOW
                    print(f"    {color}▶ {cve['id']} | CVSS {cve['score']} "
                          f"({cve['severity']}){RESET}")
                    print(f"      {cve['desc'][:100]}")
                async with lock:
                    findings.append({
                        "ip": ip, "port": port,
                        "software": info["value"], "cves": cves,
                    })
                    stats["vuln_hosts"] += 1
            else:
                print(f"    {GREEN}✓ No CVEs found in NVD{RESET}")
            print()

            await asyncio.sleep(0.7)   # NVD rate-limit courtesy

        queue.task_done()

# ════════════════════════════════════════════════════════════════════════════
# masscan Runner — launches sudo masscan, writes hits to JSON file
# ════════════════════════════════════════════════════════════════════════════

async def run_masscan(ranges_file: str, json_out: str, rate: int = 1000) -> asyncio.subprocess.Process:
    """
    Launches: sudo masscan -iL <ranges> -p <cve_ports> --rate <rate> --open-only -oJ <json_out>
    Returns the process handle so the caller can await proc.wait() after workers finish.
    masscan writes JSON entries to json_out as it finds them — the file watcher reads those.
    """
    ports_arg = ",".join(map(str, sorted(CVE_PROBE_PORTS)))
    cmd = [
        "sudo", "masscan",
        "-iL", ranges_file,
        "-p", ports_arg,
        "--rate", str(rate),
        "--open-only",
        "-oJ", json_out,
    ]
    print(f"  {CYAN}[masscan]{RESET} {' '.join(cmd)}\n")
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        return proc
    except FileNotFoundError:
        print(f"  {RED}[!] masscan not found — install: sudo apt install masscan{RESET}")
        return None


# ════════════════════════════════════════════════════════════════════════════
# JSON File Watcher — tails masscan's -oJ output, pushes new hits to queue
# ════════════════════════════════════════════════════════════════════════════

async def json_file_watcher(
    json_out:     str,
    queue:        asyncio.Queue,
    masscan_proc: asyncio.subprocess.Process,
    poll_interval: float = 0.5,
):
    """
    masscan -oJ writes one JSON object per line (plus header/footer).
    Each hit line looks like:
        {   "ip": "1.2.3.4",   "timestamp": "...", "ports": [ {"port": 22, "proto": "tcp", ...} ] },
    We tail the file, parse each new line as it appears, filter by CVE_PROBE_PORTS,
    and push (ip, port) into the queue.
    Stops when masscan process exits AND we've read all lines in the file.
    """
    seen_lines = 0
    # Wait for the file to be created by masscan
    while not os.path.exists(json_out):
        await asyncio.sleep(poll_interval)

    while True:
        with open(json_out, "r", errors="ignore") as f:
            lines = f.readlines()

        new_lines = lines[seen_lines:]
        for line in new_lines:
            line = line.strip().rstrip(",")  # masscan adds trailing comma between entries
            if not line or line.startswith("[") or line.startswith("]"):
                continue
            try:
                entry = json.loads(line)
                ip    = entry.get("ip", "")
                for p in entry.get("ports", []):
                    port = int(p.get("port", 0))
                    if port in CVE_PROBE_PORTS:
                        await queue.put((ip, port))
                        print(f"  {DIM}[watcher]{RESET} queued {ip}:{port}  "
                              f"{DIM}(q={queue.qsize()}){RESET}")
            except (json.JSONDecodeError, KeyError, ValueError):
                continue
        seen_lines = len(lines)

        # If masscan has exited and we've processed everything, we're done
        if masscan_proc.returncode is not None and seen_lines >= len(lines):
            break

        await asyncio.sleep(poll_interval)

    # Poison pills — signal all workers to shut down
    for _ in range(CVE_POOL_SIZE):
        await queue.put(None)


# ════════════════════════════════════════════════════════════════════════════
# CVE Scan Orchestrator
# ════════════════════════════════════════════════════════════════════════════

async def run_cve_scan(ranges_file: str, output_file: str = None, masscan_rate: int = 1000):
    json_out = (output_file or ranges_file).replace(".txt", "_masscan.json")

    print(f"\n{BOLD}{'='*55}{RESET}")
    print(f"  {CYAN}CVE Scan  —  sudo masscan → file watcher → {CVE_POOL_SIZE} workers{RESET}")
    print(f"  Ranges file  : {ranges_file}")
    print(f"  masscan JSON : {json_out}")
    print(f"  CVE ports    : {sorted(CVE_PROBE_PORTS)}")
    print(f"  Worker pool  : {CVE_POOL_SIZE}  (concurrent banner+NVD tasks)")
    print(f"  Queue buffer : {CVE_QUEUE_MAX}  (backpressure when full)")
    print(f"  masscan rate : {masscan_rate} pps")
    print(f"{BOLD}{'='*55}{RESET}\n")

    if not os.path.exists(ranges_file):
        print(f"  {RED}[!] File not found: {ranges_file}{RESET}")
        return

    # ── Shared state ─────────────────────────────────────────────────────────
    queue         = asyncio.Queue(maxsize=CVE_QUEUE_MAX)
    findings      = []
    seen_software = set()
    lock          = asyncio.Lock()
    stats         = {"probed": 0, "responsive": 0, "vuln_hosts": 0}

    # ── Launch sudo masscan subprocess ───────────────────────────────────────
    masscan_proc = await run_masscan(ranges_file, json_out, rate=masscan_rate)
    if masscan_proc is None:
        return

    # ── Spawn CVE workers ────────────────────────────────────────────────────
    workers = [
        asyncio.create_task(
            cve_worker(i + 1, queue, findings, seen_software, lock, stats)
        )
        for i in range(CVE_POOL_SIZE)
    ]

    # ── Start file watcher (producer) — runs alongside masscan ───────────────
    watcher = asyncio.create_task(
        json_file_watcher(json_out, queue, masscan_proc)
    )

    # ── Wait for masscan to finish, then watcher drains, then workers stop ───
    await masscan_proc.wait()           # masscan done
    await watcher                       # watcher reads remaining lines + sends poison pills
    await asyncio.gather(*workers)      # workers drain queue and exit

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n{BOLD}{'─'*55}{RESET}")
    print(f"  CVE scan complete.")
    print(f"  IPs probed         : {stats['probed']}")
    print(f"  Responsive services: {GREEN}{stats['responsive']}{RESET}")
    print(f"  Hosts with CVEs    : {RED}{stats['vuln_hosts']}{RESET}")
    print(f"  masscan JSON saved : {json_out}")
    print(f"{BOLD}{'─'*55}{RESET}\n")

    if output_file and findings:
        cve_out = output_file.replace(".txt", "_cve_results.json")
        with open(cve_out, "w") as f:
            json.dump(findings, f, indent=2)
        print(f"  {GREEN}CVE results saved: {cve_out}{RESET}")

# ════════════════════════════════════════════════════════════════════════════
# Main Lookup
# ════════════════════════════════════════════════════════════════════════════

async def lookup(
    country_code: str,
    rirs:         list = None,
    force:        bool = False,
    output_file:  str  = None,
    masscan_hint: bool = False,
    cve_scan:     bool = False,
    masscan_rate: int  = 1000,
):
    country_code  = country_code.upper()
    selected_rirs = {k: v for k, v in RIRS.items() if rirs is None or k in rirs}

    hint = COUNTRY_HINTS.get(country_code, "Unknown")
    print(f"\n{BOLD}{'='*55}{RESET}")
    print(f"  Country  : {country_code} ({hint})")
    print(f"  RIRs     : {', '.join(selected_rirs.keys())}")
    print(f"{BOLD}{'='*55}{RESET}\n")

    ensure_cache_dir()

    connector = aiohttp.TCPConnector(limit=10)
    headers   = {"User-Agent": "ip-range-lookup/2.0 (CILYNX)"}

    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        tasks   = [download_rir(session, n, u, force=force) for n, u in selected_rirs.items()]
        results = await asyncio.gather(*tasks)

    loop          = asyncio.get_event_loop()
    valid_results = [(name, path) for name, path in results if path is not None]

    parse_tasks = [
        loop.run_in_executor(None, parse_ranges, cache_path, country_code)
        for _, cache_path in valid_results
    ]
    parsed = await asyncio.gather(*parse_tasks)

    all_ranges = []
    for (rir_name, _), ranges in zip(valid_results, parsed):
        print(f"  [{rir_name}] Found {len(ranges)} ranges")
        all_ranges.extend(ranges)

    all_ranges = sorted(set(all_ranges))

    print(f"\n{BOLD}{'─'*55}{RESET}")
    print(f"  Total unique ranges: {len(all_ranges)}")
    print(f"{BOLD}{'─'*55}{RESET}\n")

    if not all_ranges:
        print("  No ranges found. Check country code or use --force to refresh cache.")
        return

    out = "\n".join(all_ranges)

    if output_file:
        async with aiofiles.open(output_file, "w") as f:
            await f.write(out + "\n")
        print(f"  {GREEN}Saved to: {output_file}{RESET}")

        if masscan_hint:
            ports = (
                "80,443,8080,8443,8000,8001,8008,8088,8888,9090,9443,"
                "21,990,22,23,2222,"
                "25,465,587,110,995,143,993,"
                "53,139,445,137,138,3389,"
                "1433,1434,3306,5432,5984,6379,9200,9300,27017,27018,28017,"
                "500,1194,1701,1723,4500,"
                "161,162,199,10161,"
                "2082,2083,2086,2087,2095,2096,"
                "10000,20000,"
                "4848,7001,7002,9060,9080,"
                "8161,61616,61613,"
                "4444,4445,8009,"
                "9000,9001,9002,"
                "8200,8201,8500,"
                "2375,2376,2377,"
                "6443,10250,10255,"
                "50070,50075,"
                "5672,15672,25672,"
                "9092,2181,"
                "3000,9100,5601,4567,"
                "111,2049,"
                "512,513,514,"
                "5900,5901,5902,"
                "6000,6001,11211,"
                "389,636,3268,3269,"
                "88,464,102,502"
            )
            print(f"\n  {CYAN}masscan command:{RESET}")
            print(f"  masscan -iL {output_file} -p {ports} --rate 10000 -oJ scan_output.json\n")

        if cve_scan:
            await run_cve_scan(output_file, output_file, masscan_rate=masscan_rate)
    else:
        print(out)
        if cve_scan:
            print(f"\n  {YELLOW}[!] CVE scan requires saving to a file first. Use -o <file>{RESET}")

# ════════════════════════════════════════════════════════════════════════════
# Interactive Mode
# ════════════════════════════════════════════════════════════════════════════

def interactive_mode() -> dict:
    print(f"\n{BOLD}╔══════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║      IP Range Lookup — CILYNX (async)        ║{RESET}")
    print(f"{BOLD}║   All RIRs | masscan producer | CVE workers  ║{RESET}")
    print(f"{BOLD}╚══════════════════════════════════════════════╝{RESET}\n")

    print("Known country codes:")
    for code, name in sorted(COUNTRY_HINTS.items()):
        print(f"  {CYAN}{code}{RESET}  ->  {name}")

    print()
    country_code = input("Enter country code (e.g. BA, IL, RS): ").strip().upper()
    if not country_code:
        print("No country code entered. Exiting.")
        sys.exit(1)

    output_file  = None
    masscan_flag = False
    cve_flag     = False
    masscan_rate = 1000

    save = input("Save to file? (y/N): ").strip().lower()
    if save == "y":
        default_name = f"{country_code.lower()}_ranges.txt"
        output_file  = input(f"Output filename [{default_name}]: ").strip() or default_name

        cve_flag = input("Run CVE scan on discovered ranges? (y/N): ").strip().lower() == "y"
        if cve_flag:
            rate_input   = input("masscan rate (pps) [1000]: ").strip()
            masscan_rate = int(rate_input) if rate_input.isdigit() else 1000
            masscan_flag = False   # CVE scan runs sudo masscan itself — hint not needed
        else:
            masscan_flag = input("Add masscan command hint? (y/N): ").strip().lower() == "y"

    force = input("Force refresh cache? (y/N): ").strip().lower() == "y"

    return dict(
        country_code=country_code,
        force=force,
        output_file=output_file,
        masscan_hint=masscan_flag,
        cve_scan=cve_flag,
        masscan_rate=masscan_rate,
    )

# ════════════════════════════════════════════════════════════════════════════
# Entry Point
# ════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="IP Range Lookup by Country Code — CILYNX (async + masscan + CVE)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 ip_range_lookup.py                               # interactive mode
  python3 ip_range_lookup.py -c BA                         # print BA ranges
  python3 ip_range_lookup.py -c IL -o il.txt               # save to file
  python3 ip_range_lookup.py -c RS -o rs.txt --masscan     # with masscan hint
  python3 ip_range_lookup.py -c BA -o ba.txt --cve         # masscan stream -> CVE workers
  python3 ip_range_lookup.py -c IR -o ir.txt --cve --rate 2000
  python3 ip_range_lookup.py -c DE --rir RIPE --force
        """,
    )
    parser.add_argument("-c", "--country",  help="ISO 3166-1 alpha-2 country code")
    parser.add_argument("-o", "--output",   help="Output file to save ranges")
    parser.add_argument("--rir", nargs="+", choices=list(RIRS.keys()), help="Limit to specific RIRs")
    parser.add_argument("--masscan",        action="store_true", help="Print masscan command hint")
    parser.add_argument("--cve",            action="store_true", help="masscan stream -> CVE worker pool")
    parser.add_argument("--rate",           type=int, default=1000, help="masscan rate pps (default: 1000)")
    parser.add_argument("--force",          action="store_true", help="Force re-download (ignore cache)")
    parser.add_argument("--list-rirs",      action="store_true", help="List available RIRs and exit")

    args = parser.parse_args()

    if args.list_rirs:
        print("\nAvailable RIRs:")
        for name, url in RIRS.items():
            print(f"  {name:10} {url}")
        sys.exit(0)

    if not args.country:
        kwargs = interactive_mode()
    else:
        kwargs = dict(
            country_code=args.country,
            rirs=args.rir,
            force=args.force,
            output_file=args.output,
            masscan_hint=args.masscan,
            cve_scan=args.cve,
            masscan_rate=args.rate,
        )

    asyncio.run(lookup(**kwargs))


if __name__ == "__main__":
    main()