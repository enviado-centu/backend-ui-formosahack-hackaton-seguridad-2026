"""Health check endpoints."""

import logging
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.database import get_db
from ..integrations.kev.integration import KevIntegration
from ..integrations.modulo_py.integration import ModuloPyIntegration

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/health", tags=["health"])


def _ml_status() -> dict:
    """Estado del motor de reglas y del modelo de ML. Nunca lanza excepción."""
    modulo_py = ModuloPyIntegration()
    rules_ok = modulo_py.motor_available
    model_ok = modulo_py.predict_available
    return {
        "status": "ok" if rules_ok and model_ok else "degraded",
        "rules_engine": rules_ok,
        "ml_model_loaded": model_ok,
        "ml_error": None if model_ok else modulo_py.predict_error,
    }


@router.get("")
async def health_check(db: AsyncSession = Depends(get_db)):
    """General health check."""
    db_status = "ok"
    try:
        await db.execute(text("SELECT 1"))
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        db_status = "error"

    kev_status = "ok" if KevIntegration().health_check() else "error"

    ml = _ml_status()
    rules_status = "ok" if ml["rules_engine"] else "error"
    ml_status = "ok" if ml["ml_model_loaded"] else "error"

    services = {
        "database": db_status,
        "rules": rules_status,
        "ml_model": ml_status,
        "kev": kev_status,
    }
    return {
        "status": "ok" if all(s == "ok" for s in services.values()) else "degraded",
        "services": services,
    }


@router.get("/kev")
async def kev_health():
    """Kev service health check."""
    is_healthy = KevIntegration().health_check()

    return {
        "status": "ok" if is_healthy else "error",
        "available": is_healthy,
    }


@router.get("/ml")
async def ml_health():
    """Estado del motor de reglas y del modelo de ML (siempre 200)."""
    return _ml_status()
