from sqlalchemy import Column, String, Integer, DateTime, JSON
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid
from database import Base

class IOCEnrichment(Base):
    __tablename__ = "ioc_enrichments"

    id = Column(UUID(as_uuid=True),primary_key=True,default=uuid.uuid4)
    ioc_value = Column(String,nullable = False)
    ioc_type = Column(String,nullable = False)
    score = Column(Integer,nullable = False)
    verdict = Column(String,nullable = False)
    sources = Column(JSON,nullable = False)
    timestamp = Column(DateTime,default = datetime.utcnow)