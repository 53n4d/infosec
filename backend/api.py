import asyncio
import ipaddress
import json
import os
import re
import sys
import tempfile
import uuid
import urllib.request as _urllib_req
import urllib.parse as _urllib_parse
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
    ScanHit,
    JobStatus,
)

app = FastAPI(
    title="XSEVERITY IP Range + CVE API",
    version="0.3.0",
    description="Async IP range lookup across all RIRs with masscan + CVE scanning.",
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
        "message": "XSEVERITY IP range lookup API v0.3",
        "endpoints": ["/health", "/countries", "/rirs",
                      "/ranges?country=BA",
                      "/cves?software=nginx&version=1.24",
                      "/scan", "/scan/{job_id}", "/scan/{job_id}/stream"],
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
        from_cache=False,
        age_days=0,
        freshness="fresh",
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
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    async def event_generator():
        sent_hits = 0
        while True:
            hits = job["hits"]
            while sent_hits < len(hits):
                hit = hits[sent_hits]
                hit_dict = hit.dict() if hasattr(hit, "dict") else hit
                yield f"data: {json.dumps({'type': 'hit', 'hit': hit_dict})}\n\n"
                sent_hits += 1

            yield f"data: {json.dumps({'type': 'stats', 'probed': job['probed'], 'responsive': job['responsive'], 'vuln_hosts': job['vuln_hosts'], 'status': job['status']})}\n\n"

            if job["status"] != "running":
                yield f"data: {json.dumps({'type': 'done'})}\n\n"
                break

            await asyncio.sleep(0.5)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


# ══════════════════════════════════════════════════════════════════════════
# Internal scan runner
# ══════════════════════════════════════════════════════════════════════════

async def _run_scan_job(job_id: str, request: ScanRequest):
    job = _jobs[job_id]
    try:
        ranges_list   = request.ranges
        ports_list    = request.ports or core.masscan_probe_ports()
        run_cve       = getattr(request, "run_cve", True)
        masscan_rate  = getattr(request, "masscan_rate", 1000)

        if not ranges_list:
            job["status"] = "error"
            job["error"]  = "No ranges provided"
            return

        # Try masscan first, fall back to async probe
        masscan_ok = False
        try:
            import shutil
            if shutil.which("masscan"):
                await _run_masscan_job(job_id, job, ranges_list, ports_list, run_cve, masscan_rate)
                masscan_ok = True
        except Exception as e:
            print(f"[scan] masscan failed: {e}, falling back to async probe")

        if not masscan_ok:
            targets = []
            for cidr in ranges_list:
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    for ip in list(net.hosts())[:256]:
                        for port in ports_list:
                            targets.append((str(ip), port))
                except Exception:
                    continue
            await _run_async_probe(job_id, job, targets, run_cve)

        job["status"] = "done"

    except Exception as e:
        job["status"] = "error"
        job["error"]  = str(e)


async def _run_masscan_job(job_id, job, ranges, ports, run_cve, rate):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(ranges))
        ranges_file = f.name

    json_out  = ranges_file.replace(".txt", "_out.json")
    ports_arg = ",".join(str(p) for p in ports)

    cmd = ["masscan", "-iL", ranges_file, "-p", ports_arg,
           "--rate", str(rate), "-oJ", json_out, "--wait", "2"]

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )

    queue        = asyncio.Queue(maxsize=500)
    seen_software: set = set()

    watcher = asyncio.create_task(
        _watch_masscan_output(json_out, queue, proc, ports)
    )
    workers = [
        asyncio.create_task(_banner_worker(job, queue, seen_software, run_cve))
        for _ in range(20)
    ]

    await proc.wait()
    await watcher
    await queue.join()

    for w in workers:
        w.cancel()

    try:
        os.unlink(ranges_file)
        os.unlink(json_out)
    except Exception:
        pass


async def _watch_masscan_output(json_out, queue, masscan_proc, probe_ports):
    probe_set = set(probe_ports)
    seen_lines = 0

    while True:
        await asyncio.sleep(0.3)
        if not os.path.exists(json_out):
            if masscan_proc.returncode is not None:
                break
            continue

        with open(json_out, "r", errors="ignore") as f:
            lines = f.readlines()

        for line in lines[seen_lines:]:
            line = line.strip().rstrip(",")
            if not line or line.startswith("[") or line.startswith("]"):
                continue
            try:
                entry = json.loads(line)
                ip = entry.get("ip", "")
                for p in entry.get("ports", []):
                    port = int(p.get("port", 0))
                    if not probe_ports or port in probe_set:
                        await queue.put((ip, port))
            except Exception:
                continue

        seen_lines = len(lines)
        if masscan_proc.returncode is not None:
            break

    # Signal all workers to stop
    for _ in range(20):
        await queue.put(None)


async def _banner_worker(job, queue, seen_software, run_cve):
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
        queue.task_done()


async def _run_async_probe(job_id: str, job: dict,
                            targets: list[tuple[str, int]], run_cve: bool):
    sem           = asyncio.Semaphore(50)
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
# Banner grab + version extraction
# ══════════════════════════════════════════════════════════════════════════

async def _grab_banner(ip: str, port: int, timeout: float = 3.0) -> Optional[str]:
    try:
        if port in (80, 8080, 8000, 8008, 8088):
            return await _http_banner(ip, port, timeout)
        if port in (443, 8443):
            return await _https_banner(ip, port, timeout)
        return await _tcp_banner(ip, port, timeout)
    except Exception:
        return None


async def _tcp_banner(ip, port, timeout):
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(ip, port), timeout=timeout
    )
    try:
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            if data:
                return data.decode("utf-8", errors="replace").strip()
        except asyncio.TimeoutError:
            pass
        probes = {
            22: b"SSH-2.0-XSEVERITY\r\n",
            21: b"USER anonymous\r\n",
            25: b"EHLO xseverity.local\r\n",
            110: b"QUIT\r\n",
            143: b"A001 CAPABILITY\r\n",
        }
        probe = probes.get(port, b"\r\n")
        writer.write(probe)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        return data.decode("utf-8", errors="replace").strip() if data else None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _http_banner(ip, port, timeout):
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(ip, port), timeout=timeout
    )
    try:
        req = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: XSEVERITY/1.0\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        return data.decode("utf-8", errors="replace").strip() if data else None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _https_banner(ip, port, timeout):
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(ip, port, ssl=ctx), timeout=timeout
    )
    try:
        req = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: XSEVERITY/1.0\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        return data.decode("utf-8", errors="replace").strip() if data else None
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _extract_version_info(banner: str) -> list[dict]:
    patterns = [
        (r"SSH-[\d.]+-(\S+)",             "SSH"),
        (r"Server:\s*(.+?)[\r\n]",        "HTTP Server"),
        (r"(OpenSSH[_/][\d.p]+\S*)",      "OpenSSH"),
        (r"(nginx/[\d.]+\S*)",            "nginx"),
        (r"(Apache/[\d.]+\S*)",           "Apache"),
        (r"(lighttpd/[\d.]+\S*)",         "lighttpd"),
        (r"(Caddy\S*)",                   "Caddy"),
        (r"(Microsoft-IIS/[\d.]+)",       "IIS"),
        (r"(MySQL\s+[\d.]+\S*)",          "MySQL"),
        (r"(PostgreSQL\s+[\d.]+\S*)",     "PostgreSQL"),
        (r"(MongoDB\s+[\d.]+\S*)",        "MongoDB"),
        (r"(Redis\s+[\d.]+\S*)",          "Redis"),
        (r"\d20\d.*?(vsftpd[\d. ]+)",     "vsftpd"),
        (r"(ProFTPD[\d. ]+\S*)",          "ProFTPD"),
        (r"(Exim\s+[\d.]+\S*)",           "Exim"),
        (r"(Postfix\S*)",                 "Postfix"),
        (r"(Dovecot\S*)",                 "Dovecot"),
    ]
    found = []
    seen  = set()
    for pattern, label in patterns:
        m = re.search(pattern, banner, re.IGNORECASE)
        if m:
            val = m.group(1).strip()
            if val not in seen:
                seen.add(val)
                found.append({"label": label, "value": val})
    return found


# ══════════════════════════════════════════════════════════════════════════
# IP Intelligence — geo/ASN proxy
# ══════════════════════════════════════════════════════════════════════════

@app.get("/ip/{ip}")
async def ip_intel(ip: str):
    fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,reverse"
    url    = f"http://ip-api.com/json/{_urllib_parse.quote(ip)}?fields={fields}"
    loop   = asyncio.get_event_loop()

    def _fetch():
        req = _urllib_req.Request(url, headers={"User-Agent": "xseverity-recon/1.0"})
        with _urllib_req.urlopen(req, timeout=8) as r:
            return json.loads(r.read())

    try:
        data = await loop.run_in_executor(None, _fetch)
        return data
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"IP lookup failed: {exc}")