"""Scan service - orchestrates the complete analysis workflow."""

import uuid
import logging
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.scan import Scan
from ..models.user import User
from ..schemas.scan import (
    ScanRequest,
    ScanResponse,
    ScanListItem,
    ScanSignals,
    RiskAssessment,
)
from ..integrations.modulo_py.integration import ModuloPyIntegration
from ..integrations.kev.integration import KevIntegration
from .risk_service import RiskService

logger = logging.getLogger(__name__)


class ScanService:
    """Service for managing scans and orchestrating analysis."""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.modulo_py = ModuloPyIntegration()
        self.kev = KevIntegration()
        self.risk_service = RiskService()
    
    async def create_scan(self, user: User, request: ScanRequest) -> ScanResponse:
        """Create and execute a new scan."""
        logger.info(f"Creating scan for user {user.id}: {request.page_data.url}")
        
        scan_uuid = str(uuid.uuid4())
        
        scan = Scan(
            scan_uuid=scan_uuid,
            user_id=user.id,
            url=request.page_data.url,
            domain=request.page_data.domain,
            status="processing",
            page_data=request.page_data.model_dump(),
        )
        
        self.db.add(scan)
        await self.db.commit()
        await self.db.refresh(scan)
        
        try:
            url = request.page_data.url
            
            kev_signals = self.kev.analyze(request.page_data.model_dump())
            rules_signals = self.modulo_py.analyze_rules(url)
            ml_signals = self.modulo_py.analyze_ml(url)
            
            risk_assessment = self.risk_service.assess_risk(
                kev=kev_signals,
                rules=rules_signals,
                ml=ml_signals,
            )
            
            scan.status = "completed"
            scan.risk_score = risk_assessment.score
            scan.risk_level = risk_assessment.level
            scan.classification_type = risk_assessment.classification_type
            scan.classification_probability = risk_assessment.classification_probability
            scan.kev_result = kev_signals.model_dump()
            scan.rules_result = rules_signals.model_dump()
            scan.ml_result = ml_signals.model_dump()
            scan.completed_at = datetime.now(timezone.utc)
            
            await self.db.commit()
            await self.db.refresh(scan)
            
            logger.info(
                f"Scan completed: {scan_uuid}, "
                f"risk={risk_assessment.score:.2f}, level={risk_assessment.level}"
            )
            
            return self._build_scan_response(scan, kev_signals, rules_signals, ml_signals, risk_assessment)
            
        except Exception as e:
            logger.error(f"Scan failed: {e}", exc_info=True)
            scan.status = "failed"
            await self.db.commit()
            raise
    
    async def get_scan(self, user: User, scan_uuid: str) -> Optional[ScanResponse]:
        """Get a specific scan by UUID."""
        result = await self.db.execute(
            select(Scan).where(Scan.scan_uuid == scan_uuid, Scan.user_id == user.id)
        )
        scan = result.scalar_one_or_none()
        
        if not scan:
            return None
        
        kev_signals = self._reconstruct_kev_signals(scan.kev_result)
        rules_signals = self._reconstruct_rules_signals(scan.rules_result)
        ml_signals = self._reconstruct_ml_signals(scan.ml_result)
        risk_assessment = self._reconstruct_risk_assessment(scan)
        
        return self._build_scan_response(scan, kev_signals, rules_signals, ml_signals, risk_assessment)
    
    async def list_scans(self, user: User, limit: int = 50, offset: int = 0) -> List[ScanListItem]:
        """List scans for a user."""
        result = await self.db.execute(
            select(Scan)
            .where(Scan.user_id == user.id)
            .order_by(Scan.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        scans = result.scalars().all()
        
        return [
            ScanListItem(
                scan_id=scan.scan_uuid,
                url=scan.url,
                domain=scan.domain,
                status=scan.status,
                risk_score=scan.risk_score,
                risk_level=scan.risk_level,
                classification_type=scan.classification_type,
                created_at=scan.created_at.isoformat(),
            )
            for scan in scans
        ]
    
    def _build_scan_response(
        self,
        scan: Scan,
        kev_signals,
        rules_signals,
        ml_signals,
        risk_assessment: RiskAssessment,
    ) -> ScanResponse:
        """Build scan response from scan and signals."""
        return ScanResponse(
            scan_id=scan.scan_uuid,
            status=scan.status,
            target={
                "url": scan.url,
                "domain": scan.domain,
            },
            risk=risk_assessment,
            classification={
                "type": risk_assessment.classification_type,
                "probability": risk_assessment.classification_probability,
            },
            signals=ScanSignals(
                kev=kev_signals,
                rules=rules_signals,
                ml=ml_signals,
            ),
            created_at=scan.created_at.isoformat(),
            completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
        )
    
    def _reconstruct_kev_signals(self, kev_result: dict):
        """Reconstruct Kev signals from stored result."""
        from ..schemas.scan import KevSignals
        if not kev_result:
            return KevSignals(available=False)
        return KevSignals(**kev_result)
    
    def _reconstruct_rules_signals(self, rules_result: dict):
        """Reconstruct rules signals from stored result."""
        from ..schemas.scan import RulesSignals
        if not rules_result:
            return RulesSignals(available=False)
        return RulesSignals(**rules_result)
    
    def _reconstruct_ml_signals(self, ml_result: dict):
        """Reconstruct ML signals from stored result."""
        from ..schemas.scan import MLSignals
        if not ml_result:
            return MLSignals(available=False)
        return MLSignals(**ml_result)
    
    def _reconstruct_risk_assessment(self, scan: Scan) -> RiskAssessment:
        """Reconstruct risk assessment from stored scan."""
        return RiskAssessment(
            score=scan.risk_score or 0.0,
            level=scan.risk_level or "unknown",
            classification_type=scan.classification_type,
            classification_probability=scan.classification_probability,
        )
