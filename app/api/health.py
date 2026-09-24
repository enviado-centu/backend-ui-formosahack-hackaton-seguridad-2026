"""Health check endpoints."""

import logging
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.database import get_db, engine
from ..integrations.kev.integration import KevIntegration
from ..integrations.modulo_py.integration import ModuloPyIntegration

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
async def health_check(db: AsyncSession = Depends(get_db)):
    """General health check."""
    db_status = "ok"
    try:
        await db.execute("SELECT 1")
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        db_status = "error"
    
    kev_integration = KevIntegration()
    kev_status = "ok" if kev_integration.health_check() else "error"
    
    modulo_py = ModuloPyIntegration()
    modulo_py_status = "ok" if modulo_py.rules_engine else "error"
    
    overall_status = "ok" if all(s == "ok" for s in [db_status, kev_status, modulo_py_status]) else "degraded"
    
    return {
        "status": overall_status,
        "services": {
            "database": db_status,
            "kev": kev_status,
            "modulo_py": modulo_py_status,
        },
    }


@router.get("/kev")
async def kev_health():
    """Kev service health check."""
    kev_integration = KevIntegration()
    is_healthy = kev_integration.health_check()
    
    return {
        "status": "ok" if is_healthy else "error",
        "available": is_healthy,
    }


@router.get("/ml")
async def ml_health():
    """ML service health check."""
    modulo_py = ModuloPyIntegration()
    is_healthy = modulo_py.rules_engine is not None and modulo_py.ml_engine is not None
    
    return {
        "status": "ok" if is_healthy else "error",
        "available": is_healthy,
        "rules_engine": modulo_py.rules_engine is not None,
        "ml_engine": modulo_py.ml_engine is not None,
    }
