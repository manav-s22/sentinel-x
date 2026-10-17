
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


class ScanRecord(Base):
    __tablename__ = "scan_history"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True
    )
    submitted_url: Mapped[str] = mapped_column(String(2048))
    normalized_url: Mapped[str] = mapped_column(String(2048))
    hostname: Mapped[str] = mapped_column(String(253), index=True)
    risk_score: Mapped[int] = mapped_column(Integer)
    risk_level: Mapped[str] = mapped_column(String(20), index=True)
    signal_count: Mapped[int] = mapped_column(Integer)
    signals: Mapped[list] = mapped_column(JSON)
    recommendation: Mapped[str] = mapped_column(String(500))
    analysis_method: Mapped[str] = mapped_column(
        String(30), default="heuristic"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
