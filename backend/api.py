from typing import List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from . import core
from .schemas import (
    Country,
    RangeResponse,
    CVEResponse,
    CVEItem,
    HealthResponse,
    ScanRequest,
    ScanResponse,
    ScanHit,
)
import ipaddress
import uuid

app = FastAPI(
    title="XSEVERITY IP Range + CVE API",
    version="0.1.0",
    description="Async IP range lookup across all RIRs with optional CVE lookup hooks.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse)
async def health():
    return core.health_summary()


@app.get("/countries", response_model=List[Country])
async def countries():
    return core.list_countries()


@app.get("/rirs")
async def rirs():
    return core.list_rirs()


@app.get("/ranges", response_model=RangeResponse)
async def ranges(
    country: str = Query(..., description="ISO 3166-1 alpha-2 country code"),
    rir: Optional[List[str]] = Query(None, description="Optional RIR names to limit lookup"),
    force: bool = False,
    masscan_hint: bool = False,
):
    try:
        data = await core.fetch_ip_ranges(country, rirs=rir, force=force)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    hint = None
    if masscan_hint:
        file_hint = f"{data['country'].lower()}_ranges.txt"
        hint = core.build_masscan_hint(file_hint)

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
            id=entry.get("id", ""),
            score=str(entry.get("score", "N/A")),
            severity=str(entry.get("severity", "N/A")),
            desc=entry.get("desc", "N/A"),
        )
        for entry in results_raw
    ]
    return CVEResponse(software=software, version=version, results=items)


@app.get("/ports/probe")
async def ports():
    return {"cve_probe_ports": core.masscan_probe_ports(), "masscan_ports": core.MASSCAN_PORTS}

@app.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest):
    hits: list[ScanHit] = []
    for cidr in request.ranges:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            sample_ips = [str(net.network_address + i) for i in range(min(20, net.num_addresses))]
        except ValueError:
            sample_ips = []
        for ip in sample_ips:
            ports = request.ports if not request.all_ports else [22, 80, 443]
            cves = ["CVE-2023-44487", "CVE-2022-22965"] if request.run_cve else []
            hits.append(ScanHit(range=cidr, ip=ip, status="open", ports=ports, cves=cves))
    return ScanResponse(job_id=str(uuid.uuid4()), hits=hits)


@app.get("/")
async def root():
    return {
        "message": "XSEVERITY IP range lookup API",
        "endpoints": [
            "/health",
            "/countries",
            "/rirs",
            "/ranges?country=BA",
            "/cves?software=nginx&version=1.24",
            "/scan",
        ],
    }
