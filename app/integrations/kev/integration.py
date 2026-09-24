"""Integration with Kev AI model."""

import sys
import logging
from pathlib import Path
from typing import Optional

from ...schemas.scan import KevSignals
from ...core.config import settings

logger = logging.getLogger(__name__)

KEV_INTEGRATION_PATH = Path(__file__).parent.parent.parent.parent.parent / "kev_integration"

if str(KEV_INTEGRATION_PATH) not in sys.path:
    sys.path.insert(0, str(KEV_INTEGRATION_PATH))

try:
    from kev_integration import KevService, PageAnalysisRequest, KevConfig, KevError
    KEV_AVAILABLE = True
    logger.info("Kev integration loaded successfully")
except ImportError as e:
    logger.error(f"Failed to import kev_integration: {e}")
    KEV_AVAILABLE = False


class KevIntegration:
    """Integration with Kev AI model for phishing detection."""
    
    def __init__(self):
        self.service = None
        
        if KEV_AVAILABLE:
            try:
                config = KevConfig(
                    base_url=settings.KEV_BASE_URL,
                    model=settings.KEV_MODEL,
                    timeout=settings.KEV_TIMEOUT,
                )
                self.service = KevService(config)
                logger.info(f"Kev service initialized: {settings.KEV_BASE_URL}")
            except Exception as e:
                logger.error(f"Failed to initialize Kev service: {e}")
    
    def analyze(self, page_data: dict) -> KevSignals:
        """Analyze page using Kev."""
        if not self.service:
            logger.warning("Kev service not available")
            return KevSignals(available=False, error="Kev service not initialized")
        
        try:
            request = PageAnalysisRequest(
                url=page_data["url"],
                domain=page_data["domain"],
                title=page_data.get("title"),
                visible_text=page_data.get("visible_text"),
                page_content=page_data.get("dom"),
                links=page_data.get("links"),
                metadata=page_data.get("metadata"),
            )
            
            result = self.service.analyze(request)
            
            return KevSignals(
                available=True,
                is_phishing=result.is_phishing.probability,
                is_malicious=result.is_malicious.probability,
                threat_type=result.threat_type.value,
                threat_confidence=result.threat_type.confidence,
                threat_probabilities=result.threat_type.probabilities,
                risk_score=result.risk.score,
                latency_ms=result.latency_ms,
            )
        except Exception as e:
            logger.error(f"Kev analysis failed: {e}", exc_info=True)
            return KevSignals(available=False, error=str(e))
    
    def health_check(self) -> bool:
        """Check if Kev is available."""
        if not self.service:
            return False
        
        try:
            import httpx
            response = httpx.get(
                f"{settings.KEV_BASE_URL}/v1/models",
                timeout=5.0,
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Kev health check failed: {e}")
            return False
