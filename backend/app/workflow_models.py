from datetime import datetime, timezone

from sqlalchemy import JSON, Column, DateTime, Integer, String, Text

from .database import Base


def utcnow() -> datetime:
    """Naive UTC timestamp. The frontend treats zone-less timestamps as UTC."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    category = Column(String(32), nullable=False, index=True)
    severity = Column(String(16), nullable=False, index=True)
    status = Column(String(16), nullable=False, default="new", index=True)
    title = Column(String(200), nullable=False)
    normalized_url = Column(String(2048), nullable=False, index=True)
    hostname = Column(String(255))
    scan_id = Column(Integer)
    risk_score = Column(Integer)
    source = Column(String(64))
    evidence = Column(JSON, default=list)
    recommendation = Column(Text)
    dedupe_key = Column(String(2100), nullable=False, index=True)
    occurrences = Column(Integer, default=1)
    timeline = Column(JSON, default=list)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, nullable=False)
    acknowledged_at = Column(DateTime)
    closed_at = Column(DateTime)


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, index=True)
    normalized_url = Column(String(2048), nullable=False, unique=True, index=True)
    hostname = Column(String(255))
    status = Column(String(16), nullable=False, default="new", index=True)
    timeline = Column(JSON, default=list)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, nullable=False)
    closed_at = Column(DateTime)