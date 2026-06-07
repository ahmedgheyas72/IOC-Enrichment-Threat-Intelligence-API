import httpx
import os
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
BASE_URL = "https://api.abuseipdb.com/api/v2"

async def check_ip(ip: str) -> dict:
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{BASE_URL}/check",
            headers=headers,
            params={"ipAddress": ip}
        )
        data = response.json()

    result = data["data"]

    return {
        "abuse_confidence_score": result["abuseConfidenceScore"],
        "total_reports": result["totalReports"],
        "is_tor": result["isTor"],
        "country_code": result["countryCode"]
    }