import asyncio
import ipaddress
import json
import os
import re
import sys
import tempfile
import uuid
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

# Allow importing main.py from parent dir
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

# ── In-memory job store ────────────────────────────────────────────────────
_jobs: dict[str, dict] = {}


# ══════════════════════════════════════════════════════════════════════════
# Health / meta
# ══════════════════════════════════════════════════════════════════════════

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


# ══════════════════════════════════════════════════════════════════════════
# Range lookup
# ══════════════════════════════════════════════════════════════════════════

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


# ══════════════════════════════════════════════════════════════════════════
# CVE lookup
# ══════════════════════════════════════════════════════════════════════════

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


# ══════════════════════════════════════════════════════════════════════════
# Scan — POST kicks off job, GET /scan/{id} polls, GET /scan/{id}/stream SSE
# ══════════════════════════════════════════════════════════════════════════

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
    """Server-Sent Events stream — emits newline-delimited JSON events."""
    if job_id not in _jobs:
        raise HTTPException(status_code=404, detail="Job not found")

    async def event_generator():
        last_hit_count = 0
        while True:
            job = _jobs.get(job_id)
            if not job:
                break

            # Emit any new hits since last poll
            hits = job["hits"]
            new_hits = hits[last_hit_count:]
            for hit in new_hits:
                data = json.dumps({"type": "hit", "hit": hit.dict() if hasattr(hit, "dict") else hit})
                yield f"data: {data}\n\n"
            last_hit_count = len(hits)

            # Emit stats heartbeat
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


# ══════════════════════════════════════════════════════════════════════════
# Real scan worker
# ══════════════════════════════════════════════════════════════════════════

# Ports to scan when "all_ports" is false and user gave no specific ports
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

    # Build list of (ip, port) to probe
    # We resolve sample IPs from each CIDR (cap at 256 IPs per range to be sane)
    targets: list[tuple[str, int]] = []
    ports_to_scan = list(request.ports) if (not request.all_ports and request.ports) else sorted(CVE_PROBE_PORTS)

    for cidr in request.ranges:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            limit = min(256, net.num_addresses)
            for i in range(limit):
                ip = str(net.network_address + i)
                for port in ports_to_scan:
                    targets.append((ip, port))
        except ValueError:
            continue

    # Use a masscan subprocess if available; otherwise fall back to async banner grabbing
    masscan_available = await _check_masscan()

    if masscan_available and request.ranges:
        await _run_with_masscan(job_id, job, request, ports_to_scan)
    else:
        await _run_async_probe(job_id, job, targets, request.run_cve)

    job["status"] = "done"


async def _check_masscan() -> bool:
    try:
        proc = await asyncio.create_subprocess_exec(
            "masscan", "--version",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        return proc.returncode == 0
    except FileNotFoundError:
        return False


async def _run_with_masscan(job_id: str, job: dict, request: ScanRequest, ports: list):
    """Write ranges to tmp file, run masscan, parse JSON output, banner grab + CVE."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as rf:
        rf.write("\n".join(request.ranges) + "\n")
        ranges_file = rf.name

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as jf:
        json_out = jf.name

    ports_arg = ",".join(map(str, sorted(ports)))
    cmd = [
        "sudo", "masscan",
        "-iL", ranges_file,
        "-p", ports_arg,
        "--rate", str(request.masscan_rate),
        "--open-only",
        "-oJ", json_out,
    ]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )

    # Concurrently watch masscan JSON output and grab banners
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

    # Cleanup
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

    for _ in range(10):  # poison pills
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

        banner = await _grab_banner(ip, port)
        if not banner:
            queue.task_done()
            continue

        job["responsive"] += 1
        version_info = _extract_version_info(banner)
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
                    await asyncio.sleep(0.7)  # NVD rate-limit

        hit = ScanHit(
            range="",  # filled below
            ip=ip,
            port=port,
            status="open",
            banner=banner[:256],
            software=version_info[0]["value"] if version_info else None,
            version_info=version_info,
            cves=cves,
        )
        job["hits"].append(hit)
        queue.task_done()


async def _run_async_probe(job_id: str, job: dict,
                            targets: list[tuple[str, int]], run_cve: bool):
    """Fallback: pure async banner grab without masscan."""
    sem = asyncio.Semaphore(50)
    seen_software: set = set()

    async def probe(ip: str, port: int):
        async with sem:
            job["probed"] += 1
            banner = await _grab_banner(ip, port)
            if not banner:
                return
            job["responsive"] += 1
            version_info = _extract_version_info(banner)
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

            hit = ScanHit(
                range="",
                ip=ip,
                port=port,
                status="open",
                banner=banner[:256],
                software=version_info[0]["value"] if version_info else None,
                version_info=version_info,
                cves=cves,
            )
            job["hits"].append(hit)

    await asyncio.gather(*[probe(ip, port) for ip, port in targets])


# ══════════════════════════════════════════════════════════════════════════
# IP Intelligence — geo/ASN proxy (avoids browser CORS issues with ip-api.com)
# ══════════════════════════════════════════════════════════════════════════

import urllib.request as _urllib_req
import urllib.parse as _urllib_parse

@app.get("/ip/{ip}")
async def ip_intel(ip: str):
    """
    Server-side proxy to ip-api.com so the browser never hits it directly.
    ip-api.com works fine from a server (no CORS restriction there).
    """
    fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,reverse"
    url = f"https://ip-api.com/json/{_urllib_parse.quote(ip)}?fields={fields}"
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