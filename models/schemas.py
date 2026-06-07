from pydantic import BaseModel
from typing import Literal
from datetime import datetime

class IOCRequest(BaseModel):
    value: str
    ioc_type: Literal["ip", "domain", "url", "hash"]

class EnrichmentResult(BaseModel):
    ioc_value: str
    ioc_type: str
    score: int
    verdict: Literal["CLEAN", "SUSPICIOUS", "MALICIOUS"]
    sources: dict
    timestamp: datetime