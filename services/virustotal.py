import httpx
import os 
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"

async def check_ip(ip: str) -> dict:
    headers = {"x-apikey": VT_API_KEY}
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{BASE_URL}/ip_addresses/{ip}", headers=headers)
        data = response.json()
    
    stats = data["data"]["attributes"]["last_analysis_stats"]
    
    return {
        "malicious": stats["malicious"],
        "suspicious": stats["suspicious"],
        "harmless": stats["harmless"],
        "undetected": stats["undetected"]
    }