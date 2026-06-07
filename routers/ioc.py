from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_db
from models.schemas import IOCRequest, EnrichmentResult
from models.db_models import IOCEnrichment
from services.virustotal import check_ip
from datetime import datetime
from services.abuseipdb import check_ip as abuseipdb_check_ip

router = APIRouter()

@router.post("/enrich", response_model=EnrichmentResult)
async def enrich_ioc(request: IOCRequest, db: AsyncSession = Depends(get_db)):
    
    vt_result = await check_ip(request.value)
    abuse_result = await abuseipdb_check_ip(request.value)

    score = 0
    if vt_result["malicious"] > 0:
        score += 40
    if vt_result["suspicious"] > 0:
        score += 20
    if abuse_result["abuse_confidence_score"] > 50:
        score += 30
    if abuse_result["is_tor"]:
        score += 10

    if score >= 40:
        verdict = "MALICIOUS"
    elif score >= 20:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    enrichment = IOCEnrichment(
        ioc_value=request.value,
        ioc_type=request.ioc_type,
        score=score,
        verdict=verdict,
        sources={
            "virustotal": vt_result,
            "abuseipdb": abuse_result
        },
        timestamp=datetime.utcnow()
    )

    db.add(enrichment)
    await db.commit()
    await db.refresh(enrichment)

    return EnrichmentResult(
        ioc_value=enrichment.ioc_value,
        ioc_type=enrichment.ioc_type,
        score=enrichment.score,
        verdict=enrichment.verdict,
        sources=enrichment.sources,
        timestamp=enrichment.timestamp
    )