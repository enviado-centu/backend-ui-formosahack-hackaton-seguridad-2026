"""Scan service - orchestrates the complete analysis workflow."""

import uuid
import logging
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from ..core.database import utcnow
from ..models.scan import Scan
from ..models.user import User
from ..schemas.scan import (
    KevSignals,
    MLSignals,
    RiskAssessment,
    RulesSignals,
    ScanListItem,
    ScanRequest,
    ScanResponse,
    ScanSignals,
    ScanSummary,
)
from ..integrations.kev.integration import KevIntegration
from .risk_service import RiskService

logger = logging.getLogger(__name__)


class ScanService:
    """Service for managing scans and orchestrating analysis."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.kev = KevIntegration()
        self.risk_service = RiskService()

    async def create_scan(self, user: User, request: ScanRequest) -> ScanResponse:
        """Create and execute a new scan."""
        logger.info(f"Creating scan for user {user.id}: {request.page_data.url}")

        page_data = request.page_data.model_dump()
        scan = Scan(
            scan_uuid=str(uuid.uuid4()),
            user_id=user.id,
            url=request.page_data.url,
            domain=request.page_data.domain,
            status="processing",
            page_data=page_data,
        )

        self.db.add(scan)
        await self.db.commit()
        await self.db.refresh(scan)

        try:
            # Reglas, modelo y Kev son bloqueantes: se corren fuera del event loop
            resultado = await run_in_threadpool(
                self.risk_service.evaluar, request.page_data.url, lambda: self.kev.analyze(page_data)
            )

            scan.status = "completed"
            scan.risk_score = resultado.risk.score
            scan.risk_level = resultado.risk.level
            scan.classification_type = resultado.risk.classification_type
            scan.classification_probability = resultado.risk.classification_probability
            scan.kev_result = resultado.kev.model_dump()
            scan.rules_result = resultado.rules.model_dump()
            scan.ml_result = resultado.ml.model_dump()
            scan.summary = resultado.summary.model_dump()
            scan.completed_at = utcnow()

            await self.db.commit()
            await self.db.refresh(scan)

            logger.info(f"Scan completed: {scan.scan_uuid}, score={resultado.summary.score_100}, level={resultado.risk.level}")

            return self._build_scan_response(
                scan, resultado.kev, resultado.rules, resultado.ml, resultado.risk, resultado.summary
            )

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

        return self._build_scan_response(
            scan,
            KevSignals(**scan.kev_result) if scan.kev_result else KevSignals(available=False),
            RulesSignals(**scan.rules_result) if scan.rules_result else RulesSignals(available=False),
            MLSignals(**scan.ml_result) if scan.ml_result else MLSignals(available=False),
            RiskAssessment(
                score=scan.risk_score or 0.0,
                level=scan.risk_level or "unknown",
                classification_type=scan.classification_type,
                classification_probability=scan.classification_probability,
            ),
            ScanSummary(**scan.summary) if scan.summary else None,
        )

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
        kev_signals: KevSignals,
        rules_signals: RulesSignals,
        ml_signals: MLSignals,
        risk_assessment: RiskAssessment,
        summary: Optional[ScanSummary],
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
            summary=summary,
            created_at=scan.created_at.isoformat(),
            completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
        )
