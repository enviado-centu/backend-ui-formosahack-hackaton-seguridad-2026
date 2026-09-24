"""Scan schemas."""

from typing import Optional, Dict, Any, List
from pydantic import BaseModel, ConfigDict, Field, field_validator
from datetime import datetime


class PageDataRequest(BaseModel):
    """Page data for scan request."""
    
    url: str = Field(..., description="Full URL of the page")
    domain: str = Field(..., description="Domain name")
    title: Optional[str] = Field(None, description="Page title", max_length=500)
    visible_text: Optional[str] = Field(None, description="Visible text content", max_length=10000)
    dom: Optional[str] = Field(None, description="DOM/HTML content", max_length=100000)
    links: Optional[List[str]] = Field(None, description="List of links", max_length=1000)
    forms: Optional[List[Dict[str, Any]]] = Field(None, description="Form elements")
    scripts: Optional[List[str]] = Field(None, description="Script elements")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")
    
    @field_validator("url")
    @classmethod
    def validate_url(cls, v):
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        if len(v) > 2000:
            raise ValueError("URL too long")
        return v
    
    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v):
        if len(v) > 253:
            raise ValueError("Domain too long")
        return v


class ScanRequest(BaseModel):
    """Scan request."""
    page_data: PageDataRequest


class KevSignals(BaseModel):
    """Kev analysis signals."""
    available: bool
    is_phishing: Optional[float] = None
    is_malicious: Optional[float] = None
    threat_type: Optional[str] = None
    threat_confidence: Optional[float] = None
    threat_probabilities: Optional[Dict[str, float]] = None
    risk_score: Optional[float] = None
    latency_ms: Optional[float] = None
    error: Optional[str] = None


class RulesSignals(BaseModel):
    """Rules engine signals."""
    available: bool
    triggered_rules: List[str] = []
    rule_count: int = 0
    risk_score: float = 0.0
    details: Dict[str, Any] = {}


class MLSignals(BaseModel):
    """ML engine signals."""
    available: bool
    score: Optional[float] = None
    prediction: Optional[int] = None
    confidence: Optional[float] = None
    model_name: Optional[str] = None
    error: Optional[str] = None


class RiskAssessment(BaseModel):
    """Risk assessment result."""
    score: float = Field(..., ge=0, le=1)
    level: str
    classification_type: Optional[str] = None
    classification_probability: Optional[float] = None


class ScanSignals(BaseModel):
    """All signals from analysis engines."""
    kev: KevSignals
    rules: RulesSignals
    ml: MLSignals


class ScanResponse(BaseModel):
    """Scan response."""
    scan_id: str
    status: str
    target: Dict[str, str]
    risk: RiskAssessment
    classification: Dict[str, Any]
    signals: ScanSignals
    created_at: str
    completed_at: Optional[str] = None
    
    model_config = ConfigDict(from_attributes=True)


class ScanListItem(BaseModel):
    """Scan list item."""
    scan_id: str
    url: str
    domain: str
    status: str
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    classification_type: Optional[str] = None
    created_at: str
    
    model_config = ConfigDict(from_attributes=True)
