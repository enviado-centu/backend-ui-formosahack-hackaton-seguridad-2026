"""Integration with Kev AI model."""

import importlib.util
import logging
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Optional

import httpx

from ...schemas.scan import KevSignals
from ...core.config import settings

logger = logging.getLogger(__name__)

# Carpeta que contiene los repos hermanos (MODULO-PY, kev-integration, ...)
RAIZ_REPOS = Path(__file__).resolve().parents[4]
NOMBRES_CARPETA_KEV = ("kev-integration", "kev_integration")
PAQUETE_KEV = "kev_integration"

# Si Kev no conecta, no se lo reintenta durante este tiempo: los escaneos no esperan
# el timeout de conexión en cada request mientras el servidor esté apagado.
PAUSA_KEV_CAIDO_S = 30
_kev_caido_hasta = 0.0


def _carpetas_candidatas() -> list[Path]:
    if settings.KEV_INTEGRATION_PATH:
        return [Path(settings.KEV_INTEGRATION_PATH)]
    return [RAIZ_REPOS / nombre for nombre in NOMBRES_CARPETA_KEV]


def _cargar_paquete_kev() -> ModuleType:
    """Carga el repo de Kev como paquete `kev_integration`, se llame como se llame su carpeta.

    Al clonarlo, la carpeta queda como `kev-integration` (con guion), que no se puede importar
    con un import normal: se registra con importlib a partir de su __init__.py.
    """
    if PAQUETE_KEV in sys.modules:
        return sys.modules[PAQUETE_KEV]
    candidatas = _carpetas_candidatas()
    for carpeta in candidatas:
        init = carpeta / "__init__.py"
        if not init.exists():
            continue
        spec = importlib.util.spec_from_file_location(
            PAQUETE_KEV, init, submodule_search_locations=[str(carpeta)]
        )
        modulo = importlib.util.module_from_spec(spec)
        sys.modules[PAQUETE_KEV] = modulo
        try:
            spec.loader.exec_module(modulo)
        except Exception:
            del sys.modules[PAQUETE_KEV]
            raise
        return modulo
    raise ImportError(
        "No se encontró el repo de Kev en: " + ", ".join(str(c) for c in candidatas)
        + ". Clonalo al lado del backend o definí KEV_INTEGRATION_PATH en .env."
    )


try:
    _kev = _cargar_paquete_kev()
    KevService = _kev.KevService
    PageAnalysisRequest = _kev.PageAnalysisRequest
    KevConfig = _kev.KevConfig
    ERRORES_CONEXION_KEV = (_kev.KevConnectionError, _kev.KevTimeoutError)
    KEV_AVAILABLE = True
    KEV_IMPORT_ERROR: Optional[str] = None
    logger.info("Kev integration loaded successfully")
except Exception as e:
    logger.error(f"Failed to import kev_integration: {e}")
    KEV_AVAILABLE = False
    KEV_IMPORT_ERROR = str(e)


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
            except Exception as e:
                logger.error(f"Failed to initialize Kev service: {e}")

    def analyze(self, page_data: dict) -> KevSignals:
        """Analyze page using Kev. Nunca lanza excepción: si Kev falla, available=False."""
        global _kev_caido_hasta

        if not self.service:
            return KevSignals(available=False, error=KEV_IMPORT_ERROR or "Kev service not initialized")

        if time.monotonic() < _kev_caido_hasta:
            return KevSignals(
                available=False,
                error=f"Kev no respondió hace menos de {PAUSA_KEV_CAIDO_S} s; se reintenta después",
            )

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
            if isinstance(e, ERRORES_CONEXION_KEV):
                _kev_caido_hasta = time.monotonic() + PAUSA_KEV_CAIDO_S
            logger.warning(f"Kev analysis failed: {e}")
            return KevSignals(available=False, error=str(e))

    def health_check(self) -> bool:
        """Check if Kev is available."""
        if not self.service:
            return False

        try:
            response = httpx.get(
                f"{settings.KEV_BASE_URL}/v1/models",
                timeout=min(settings.KEV_TIMEOUT, 3),
            )
            return response.status_code == 200
        except Exception as e:
            logger.info(f"Kev health check failed: {e}")
            return False
