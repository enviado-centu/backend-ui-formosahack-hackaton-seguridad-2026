"""Scan database model."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Float, JSON, ForeignKey, Text
from sqlalchemy.orm import relationship

from ..core.database import Base


class Scan(Base):
    """Scan model for storing analysis results."""
    
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_uuid = Column(String, unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
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
    
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    
    user = relationship("User", back_populates="scans")
