from pydantic import BaseModel
from typing import List, Optional, Dict, Any


class Country(BaseModel):
    code: str
    name: str


class RangeResponse(BaseModel):
    country: str
    country_name: str
    rirs: List[str]
    counts: Dict[str, int]
    total: int
    ranges: List[str]
    last_updated: Optional[str] = None
    masscan_hint: Optional[str] = None
    # Cache metadata
    from_cache: bool = False
    age_days: int = 0
    freshness: str = "fresh"


class CVEItem(BaseModel):
    id: str
    score: str
    severity: str
    desc: str


class CVEResponse(BaseModel):
    software: str
    version: Optional[str] = None
    results: List[CVEItem]


class HealthResponse(BaseModel):
    status: str
    timestamp: str
    available_rirs: int
    intel_enabled: bool = False


class ScanRequest(BaseModel):
    ranges: List[str]
    ports: Optional[List[int]] = None
    all_ports: bool = False
    run_cve: bool = True
    masscan_rate: int = 1000
    country: Optional[str] = None      # optional — used for intel contribution
    scan_mode: str = 'wide'            # 'wide' (masscan) | 'deep' (nmap)
    nmap_parallelism: int = 100        # --min-parallelism for deep scan (1–500)


class ScanResponse(BaseModel):
    job_id: str
    status: str


class ScanHit(BaseModel):
    range: str = ""
    ip: str
    port: int = 0          # 0 = silent host (no open ports found by masscan)
    status: str = "open"   # "open" | "silent"
    banner: Optional[str] = None
    software: Optional[str] = None
    version_info: Optional[List[Dict[str, Any]]] = None
    cves: Optional[List[Dict[str, Any]]] = None


class JobStatus(BaseModel):
    job_id: str
    status: str
    probed: int
    responsive: int
    vuln_hosts: int
    hits: List[ScanHit]
    error: Optional[str] = None


class HttpInspectRequest(BaseModel):
    ip: str
    port: int = 80
    scheme: str = "http"  # http | https
    path: str = "/"


class HttpInspectResponse(BaseModel):
    title: Optional[str] = None
    status: Optional[int] = None
    screenshot: Optional[str] = None  # base64 PNG if captured (not implemented yet)
    error: Optional[str] = None


class HttpScreenshotRequest(BaseModel):
    ip: str
    port: int = 80
    scheme: str = "http"  # http | https
    path: str = "/"
    full_page: bool = False


class HttpScreenshotResponse(BaseModel):
    title: Optional[str] = None
    status: Optional[int] = None
    screenshot: Optional[str] = None  # base64 PNG
    error: Optional[str] = None
