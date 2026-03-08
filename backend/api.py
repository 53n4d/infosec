import asyncio
import ipaddress
import json
import os
import re
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import core
from backend.schemas import (
    Country,
    RangeResponse,
    CVEResponse,
    CVEItem,
    HealthResponse,
    ScanRequest,
    ScanResponse,
    ScanHit,
    JobStatus,
)

app = FastAPI(
    title="XSEVERITY IP Range + CVE API",
    version="0.2.0",
    description="Async IP range lookup across all RIRs with real masscan + CVE scanning.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_jobs: dict[str, dict] = {}


@app.get("/health", response_model=HealthResponse)
async def health():
    return core.health_summary()


@app.get("/countries", response_model=List[Country])
async def countries():
    return core.list_countries()


@app.get("/rirs")
async def rirs():
    return core.list_rirs()


@app.get("/ports/probe")
async def ports():
    return {"cve_probe_ports": core.masscan_probe_ports(), "masscan_ports": core.MASSCAN_PORTS}


@app.get("/")
async def root():
    return {
        "message": "XSEVERITY IP range lookup API v0.2",
        "endpoints": ["/health", "/countries", "/rirs", "/ranges?country=BA",
                      "/cves?software=nginx&version=1.24", "/scan", "/scan/{job_id}"],
    }


@app.get("/ranges", response_model=RangeResponse)
async def ranges(
    country: str = Query(..., description="ISO 3166-1 alpha-2 country code"),
    rir: Optional[List[str]] = Query(None),
    force: bool = False,
    masscan_hint: bool = False,
):
    try:
        data = await core.fetch_ip_ranges(country, rirs=rir, force=force)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    hint = None
    if masscan_hint:
        hint = core.build_masscan_hint(f"{data['country'].lower()}_ranges.txt")

    return RangeResponse(
        country=data["country"],
        country_name=data["country_name"],
        rirs=data["rirs"],
        counts=data["counts"],
        total=len(data["ranges"]),
        ranges=data["ranges"],
        last_updated=data["last_updated"],
        masscan_hint=hint,
    )


@app.get("/cves", response_model=CVEResponse)
async def cves(software: str = Query(...), version: Optional[str] = None):
    if not software:
        raise HTTPException(status_code=400, detail="software is required")
    results_raw = await core.search_cves(software, version)
    items = [
        CVEItem(
            id=e.get("id", ""),
            score=str(e.get("score", "N/A")),
            severity=str(e.get("severity", "N/A")),
            desc=e.get("desc", "N/A"),
        )
        for e in results_raw
    ]
    return CVEResponse(software=software, version=version, results=items)


@app.post("/scan", response_model=dict)
async def start_scan(request: ScanRequest):
    job_id = str(uuid.uuid4())
    _jobs[job_id] = {
        "status": "running",
        "probed": 0,
        "responsive": 0,
        "vuln_hosts": 0,
        "hits": [],
        "error": None,
    }
    asyncio.create_task(_run_scan_job(job_id, request))
    return {"job_id": job_id, "status": "running"}


@app.get("/scan/{job_id}", response_model=JobStatus)
async def get_scan(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return JobStatus(job_id=job_id, **job)


@app.get("/scan/{job_id}/stream")
async def stream_scan(job_id: str):
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    async def event_generator():
        last_hit_count = 0
        while True:
            job = _jobs.get(job_id)
            if not job:
                break

            hits = job["hits"]
            new_hits = hits[last_hit_count:]
            for hit in new_hits:
                data = json.dumps({"type": "hit", "hit": hit.dict() if hasattr(hit, "dict") else hit})
                yield f"data: {data}\n\n"
            last_hit_count = len(hits)

            stats = {
                "type": "stats",
                "probed": job["probed"],
                "responsive": job["responsive"],
                "vuln_hosts": job["vuln_hosts"],
                "status": job["status"],
            }
            yield f"data: {json.dumps(stats)}\n\n"

            if job["status"] in ("done", "error"):
                yield f"data: {json.dumps({'type': 'done', 'status': job['status']})}\n\n"
                break

            await asyncio.sleep(0.5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


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


async def _grab_banner(ip: str, port: int, timeout: float = 3.0) -> Optional[str]:
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
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
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


def _extract_version_info(banner: str) -> list:
    findings = []
    for pattern, label in VERSION_PATTERNS:
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            findings.append({"label": label, "value": m.group(1).strip()})
    return findings


async def _run_scan_job(job_id: str, request: ScanRequest):
    job = _jobs[job_id]
    ports_to_scan = list(request.ports) if (not request.all_ports and request.ports) else sorted(CVE_PROBE_PORTS)
    if request.scan_mode == 'deep':
        await _run_with_nmap(job_id, job, request, ports_to_scan)
    else:
        await _run_with_masscan(job_id, job, request, ports_to_scan)
    job["status"] = "done"


async def _run_with_masscan(job_id: str, job: dict, request: ScanRequest, ports: list):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as rf:
        rf.write("\n".join(request.ranges) + "\n")
        ranges_file = rf.name

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as jf:
        json_out = jf.name
    # Delete pre-created file — masscan runs as root and must create it itself
    os.unlink(json_out)

    ports_arg = ",".join(map(str, sorted(ports)))
    # Calculate dynamic wait time based on scan size
    total_ips = 0
    for r in request.ranges:
        try:
            total_ips += ipaddress.ip_network(r, strict=False).num_addresses
        except Exception:
            total_ips += 1
    total_packets = total_ips * max(len(ports), 1)
    dynamic_wait  = max(10, int(total_packets / request.masscan_rate) + 5)

    cmd = [
        "sudo", "masscan",
        "-iL", ranges_file,
        "-p", "0-65535" if request.all_ports else ports_arg,
        "--rate", str(request.masscan_rate),
        "--open-only",
        "--wait", str(dynamic_wait),
        "-oJ", json_out,
    ]

    print(f"[masscan] {total_ips} IPs × {max(len(ports),1)} ports = {total_packets} pkts @ {request.masscan_rate}pps → wait={dynamic_wait}s", flush=True)

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )

    queue = asyncio.Queue(maxsize=100)
    seen_software: set = set()

    watcher_task = asyncio.create_task(
        _watch_masscan_json(json_out, queue, proc, set(ports))
    )
    worker_tasks = [
        asyncio.create_task(_probe_worker(job_id, job, queue, seen_software, request.run_cve))
        for _ in range(10)
    ]

    await proc.wait()
    await watcher_task
    await asyncio.gather(*worker_tasks)

    # After masscan + probe workers finish, emit silent hits for IPs that
    # had no open ports — so frontend can show them when "Only findings" is off
    try:
        import ipaddress as _ip2
        found_ips = {h.ip for h in job["hits"]}
        for cidr in request.ranges:
            try:
                net = _ip2.ip_network(cidr, strict=False)
                # Skip huge ranges — only enumerate /20 and smaller (4096 IPs max)
                if net.num_addresses > 4096:
                    continue
                for addr in net.hosts():
                    ip_str = str(addr)
                    if ip_str not in found_ips:
                        silent_hit = ScanHit(
                            range=cidr,
                            ip=ip_str,
                            port=0,
                            status="silent",
                            banner=None,
                            software=None,
                            version_info=[],
                            cves=[],
                        )
                        job["hits"].append(silent_hit)
                        job["probed"] += 1
            except Exception:
                pass
    except Exception as e:
        print(f"[silent] error: {e}", flush=True)

    for f in (ranges_file, json_out):
        try:
            os.unlink(f)
        except OSError:
            pass


async def _watch_masscan_json(json_out: str, queue: asyncio.Queue,
                               proc, probe_ports: set, poll: float = 0.5):
    seen = 0
    while not os.path.exists(json_out):
        await asyncio.sleep(poll)

    while True:
        with open(json_out, "r", errors="ignore") as f:
            lines = f.readlines()
        for line in lines[seen:]:
            line = line.strip().rstrip(",")
            if not line or line.startswith("[") or line.startswith("]"):
                continue
            try:
                entry = json.loads(line)
                ip = entry.get("ip", "")
                for p in entry.get("ports", []):
                    port = int(p.get("port", 0))
                    if port in probe_ports:
                        await queue.put((ip, port))
            except (json.JSONDecodeError, KeyError, ValueError):
                pass
        seen = len(lines)

        if proc.returncode is not None and seen >= len(lines):
            break
        await asyncio.sleep(poll)

    for _ in range(10):
        await queue.put(None)


async def _probe_worker(job_id: str, job: dict, queue: asyncio.Queue,
                         seen_software: set, run_cve: bool):
    while True:
        item = await queue.get()
        if item is None:
            queue.task_done()
            break
        ip, port = item
        job["probed"] += 1
        job["responsive"] += 1

        banner = await _grab_banner(ip, port)
        version_info = _extract_version_info(banner) if banner else []
        cves = []

        if run_cve and version_info:
            for info in version_info:
                key = info["value"].lower()
                if key not in seen_software:
                    seen_software.add(key)
                    found = await core.search_cves(info["label"], info["value"])
                    cves.extend(found)
                    if found:
                        job["vuln_hosts"] += 1
                    await asyncio.sleep(0.7)

        # Always add hit — even without banner (masscan confirmed port open)
        hit = ScanHit(
            range="",
            ip=ip,
            port=port,
            status="open",
            banner=banner[:256] if banner else None,
            software=version_info[0]["value"] if version_info else None,
            version_info=version_info,
            cves=cves,
        )
        job["hits"].append(hit)
        queue.task_done()


import urllib.request as _urllib_req
import urllib.parse as _urllib_parse

@app.get("/ip/{ip}")
async def ip_intel(ip: str):
    fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,reverse"
    url = f"http://ip-api.com/json/{_urllib_parse.quote(ip)}?fields={fields}"
    loop = asyncio.get_event_loop()
    def _fetch():
        req = _urllib_req.Request(url, headers={"User-Agent": "xseverity-recon/1.0"})
        with _urllib_req.urlopen(req, timeout=8) as r:
            return json.loads(r.read())
    try:
        data = await loop.run_in_executor(None, _fetch)
        return data
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"IP lookup failed: {exc}")

async def _run_with_nmap(job_id: str, job: dict, request: ScanRequest, ports: list):
    """Deep scan using nmap — service detection, OS fingerprint, vuln scripts."""
    # Flatten all IPs from ranges (nmap handles CIDRs natively but we enumerate
    # for progress tracking — skip ranges larger than /20)
    targets = []
    for cidr in request.ranges:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.num_addresses <= 4096:
                targets.extend(str(h) for h in net.hosts())
            else:
                targets.append(cidr)  # pass CIDR directly to nmap
        except Exception:
            targets.append(cidr)

    if not targets:
        job["status"] = "done"
        return

    ports_arg = ",".join(map(str, sorted(ports))) if ports else "21,22,23,25,80,443,445,3306,3389,5432,6379,8080,8443,9200,27017"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        tf.write("\n".join(targets) + "\n")
        targets_file = tf.name

    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as xf:
        xml_out = xf.name
    os.unlink(xml_out)  # let nmap create it as root

    cmd = [
        "sudo", "nmap",
        "-iL", targets_file,
        "-p", ports_arg,
        "-sV",                      # service/version detection
        "-O",                       # OS detection
        "--script", "vuln,banner",  # vuln NSE scripts + banner
        "-T4",                      # aggressive timing
        "--open",                   # only show open ports
        "--host-timeout", "90s",    # skip unresponsive hosts after 90s
        "--min-parallelism", str(min(500, max(1, request.nmap_parallelism))),  # user-defined
        "--max-retries", "2",       # retry unresponsive ports twice
        "-oX", xml_out,             # XML output — parsed incrementally
    ]

    print(f"[nmap] {len(targets)} targets, ports={ports_arg}", flush=True)

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )

    # Poll XML output while nmap runs
    seen_ips = set()
    while proc.returncode is None:
        await asyncio.sleep(2)
        if os.path.exists(xml_out):
            _parse_nmap_xml(xml_out, job, seen_ips)

    await proc.wait()

    # Final parse after nmap exits
    if os.path.exists(xml_out):
        _parse_nmap_xml(xml_out, job, seen_ips)

    # Silent hosts — IPs nmap found no open ports on
    found_ips = {h.ip for h in job["hits"]}
    for cidr in request.ranges:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.num_addresses > 4096:
                continue
            for addr in net.hosts():
                ip_str = str(addr)
                if ip_str not in found_ips:
                    job["hits"].append(ScanHit(
                        range=cidr, ip=ip_str, port=0,
                        status="silent", banner=None, software=None,
                        version_info=[], cves=[],
                    ))
                    job["probed"] += 1
        except Exception:
            pass

    for f in (targets_file, xml_out):
        try:
            os.unlink(f)
        except OSError:
            pass


def _parse_nmap_xml(xml_path: str, job: dict, seen_ips: set):
    """Parse nmap XML output and append new hits to job."""
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError:
        return  # nmap still writing — incomplete XML

    for host in root.findall("host"):
        # Only up hosts
        state = host.find("status")
        if state is None or state.get("state") != "up":
            continue

        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")
        if not ip:
            continue

        # OS detection
        os_name = None
        os_el = host.find(".//osmatch")
        if os_el is not None:
            os_name = os_el.get("name")

        ports_el = host.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            port_state = port_el.find("state")
            if port_state is None or port_state.get("state") != "open":
                continue

            port_num = int(port_el.get("portid", 0))
            key = f"{ip}:{port_num}"
            if key in seen_ips:
                continue
            seen_ips.add(key)

            # Service info
            svc_el   = port_el.find("service")
            software = None
            banner   = None
            version_info = []

            if svc_el is not None:
                name    = svc_el.get("name", "")
                product = svc_el.get("product", "")
                version = svc_el.get("version", "")
                extra   = svc_el.get("extrainfo", "")
                ostype  = svc_el.get("ostype", "")
                tunnel  = svc_el.get("tunnel", "")

                parts = [p for p in [product, version, extra] if p]
                software = " ".join(parts) if parts else name or None
                banner = f"{name} {' '.join(parts)}".strip() or None

                if product:   version_info.append({"label": "Product", "value": product})
                if version:   version_info.append({"label": "Version", "value": version})
                if ostype:    version_info.append({"label": "OS Type", "value": ostype})
                if tunnel:    version_info.append({"label": "Tunnel",  "value": tunnel})
                if os_name:   version_info.append({"label": "OS",      "value": os_name})

            # NSE script output (vuln scripts) — deduplicated by CVE ID
            cve_map = {}  # id -> best entry
            for script in port_el.findall("script"):
                script_id  = script.get("id", "")
                script_out = script.get("output", "")

                # Try to extract per-CVE blocks with score
                # vulners output: "CVE-2024-6387  10.0  https://..."
                for line in script_out.splitlines():
                    line = line.strip()
                    cve_match = re.search(r"(CVE-\d{4}-\d+)", line)
                    if not cve_match:
                        continue
                    cve_id = cve_match.group(1)
                    if cve_id in cve_map:
                        continue  # already have this CVE — skip duplicate

                    # Try to extract CVSS score from the line
                    score_match = re.search(r"(\d+\.\d+)", line)
                    score = score_match.group(1) if score_match else "N/A"

                    # Severity from score
                    try:
                        s = float(score)
                        severity = "CRITICAL" if s >= 9.0 else "HIGH" if s >= 7.0 else "MEDIUM" if s >= 4.0 else "LOW"
                    except ValueError:
                        severity = "UNKNOWN"

                    cve_map[cve_id] = {
                        "id":       cve_id,
                        "score":    score,
                        "severity": severity,
                        "desc":     f"{script_id}: {line[:300]}",
                    }

            cves = list(cve_map.values())
            if cves:
                job["vuln_hosts"] += 1

            hit = ScanHit(
                range="", ip=ip, port=port_num, status="open",
                banner=banner, software=software,
                version_info=version_info, cves=cves,
            )
            job["hits"].append(hit)
            job["probed"] += 1
            job["responsive"] += 1