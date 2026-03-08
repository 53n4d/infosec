from typing import Dict, List, Optional, Any

from pydantic import BaseModel, Field


class Country(BaseModel):
    code: str = Field(..., description="ISO 3166-1 alpha-2 code")
    name: str


class RangeResponse(BaseModel):
    country: str
    country_name: str
    rirs: List[str]
    counts: Dict[str, int]
    total: int
    ranges: List[str]
    last_updated: Optional[str]
    masscan_hint: Optional[str] = None


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


class ScanRequest(BaseModel):
    ranges: List[str]
    ports: List[int]
    all_ports: bool = False
    run_cve: bool = False
    masscan_rate: int = 1000


class ScanHit(BaseModel):
    range: str
    ip: str
    port: int
    status: str
    banner: Optional[str] = None
    software: Optional[str] = None
    version_info: List[Dict[str, str]] = []
    cves: List[Dict[str, Any]] = []


class ScanResponse(BaseModel):
    job_id: str
    hits: List[ScanHit]


class JobStatus(BaseModel):
    job_id: str
    status: str  # "running" | "done" | "error"
    probed: int
    responsive: int
    vuln_hosts: int
    hits: List[ScanHit]
    error: Optional[str] = None