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


class ScanResponse(BaseModel):
    job_id: str
    status: str


class ScanHit(BaseModel):
    range: str
    ip: str
    port: int
    status: str
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