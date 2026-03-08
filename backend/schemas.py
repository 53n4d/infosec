from typing import Dict, List, Optional

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


class ScanHit(BaseModel):
    range: str
    ip: str
    status: str
    ports: List[int]
    cves: List[str] = []


class ScanResponse(BaseModel):
    job_id: str
    hits: List[ScanHit]
