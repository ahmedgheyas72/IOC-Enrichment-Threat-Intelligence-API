from fastapi import FastAPI
from database import engine, Base
from routers import ioc

app = FastAPI(title="IOC Enrichment API")

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

app.include_router(ioc.router, prefix="/ioc", tags=["IOC"])

@app.get("/health")
async def health():
    return {"status": "healthy"}        