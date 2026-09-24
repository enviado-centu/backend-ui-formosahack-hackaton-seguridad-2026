"""Scan database model."""

from sqlalchemy import Column, Integer, String, DateTime, Float, JSON, ForeignKey
from sqlalchemy.orm import relationship

from ..core.database import Base, utcnow


class Scan(Base):
    """Scan model for storing analysis results."""
    
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_uuid = Column(String, unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    url = Column(String, nullable=False)
    domain = Column(String, nullable=False)
    
    status = Column(String, default="pending")
    
    risk_score = Column(Float)
    risk_level = Column(String)
    classification_type = Column(String)
    classification_probability = Column(Float)
    
    kev_result = Column(JSON)
    rules_result = Column(JSON)
    ml_result = Column(JSON)
    
    page_data = Column(JSON)
    
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    completed_at = Column(DateTime(timezone=True))
    
    user = relationship("User", back_populates="scans")
