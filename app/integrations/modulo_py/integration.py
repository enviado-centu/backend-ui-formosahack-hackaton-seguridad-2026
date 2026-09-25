"""Integration with MODULO-PY engine.

Solo adapta las funciones del motor (motor/listas.py, motor/reglas.py) y del modelo
(predict.py) a los schemas del backend. No reimplementa listas, reglas ni dominios.
"""

import sys
import logging
from pathlib import Path
from typing import Optional

from ...schemas.scan import RulesSignals, MLSignals

logger = logging.getLogger(__name__)

MODULO_PY_PATH = Path(__file__).resolve().parents[4] / "MODULO-PY"

if str(MODULO_PY_PATH) not in sys.path:
    sys.path.insert(0, str(MODULO_PY_PATH))

try:
    from motor.reglas import evaluar_reglas
    from motor.listas import cargar_lista_blanca, es_oficial, esta_en_lista_negra
    from features import dominio_registrable
    MOTOR_AVAILABLE = True
    logger.info("MODULO-PY motor loaded successfully")
except ImportError as e:
    logger.error(f"Failed to import MODULO-PY motor: {e}")
    MOTOR_AVAILABLE = False

PREDICT_ERROR: Optional[str] = None
try:
    from predict import predecir
    PREDICT_AVAILABLE = True
    logger.info("MODULO-PY predict loaded successfully")
except (ImportError, FileNotFoundError) as e:
    logger.warning(f"MODULO-PY predict not available: {e}")
    PREDICT_AVAILABLE = False
    PREDICT_ERROR = str(e)

MODEL_NAME = "modelo_phishing (versión 4c)"


class ModuloPyIntegration:
    """Integration with MODULO-PY rules and ML engines."""

    def __init__(self):
        self.motor_available = MOTOR_AVAILABLE
        self.predict_available = PREDICT_AVAILABLE
        self.predict_error = PREDICT_ERROR

    def lista_negra(self, url: str) -> Optional[dict]:
        """Coincidencia en lista negra ({"tipo", "coincidencia"}) o None."""
        if not self.motor_available:
            return None
        return esta_en_lista_negra(url)

    def marca_oficial(self, url: str) -> Optional[str]:
        """Id de la marca si la URL es de un dominio oficial; None si no."""
        if not self.motor_available:
            return None
        return es_oficial(url)

    def nombre_marca(self, marca_id: str) -> str:
        """Nombre legible de una marca de la lista blanca (ej. "Banco Nación")."""
        return cargar_lista_blanca()[marca_id]["nombre"]

    def lista_blanca(self) -> dict:
        """Marcas oficiales {id: datos} tal como las carga el motor."""
        if not self.motor_available:
            raise RuntimeError("El motor de MODULO-PY no está disponible")
        return cargar_lista_blanca()

    def dominio(self, url: str) -> str:
        """Dominio registrable de la URL (ej. bna.com.ar); "" si no se puede obtener."""
        if not self.motor_available:
            return ""
        try:
            return dominio_registrable(url)
        except ValueError:
            return ""

    def analyze_rules(self, url: str) -> RulesSignals:
        """Analyze URL using the motor rules engine."""
        if not self.motor_available:
            logger.warning("Motor not available")
            return RulesSignals(available=False)

        try:
            senales = evaluar_reglas(url)
            total_puntos = sum(s.puntos for s in senales)
            return RulesSignals(
                available=True,
                triggered_rules=[s.id for s in senales],
                rule_count=len(senales),
                risk_score=min(1.0, total_puntos / 100.0),
                details={
                    "senales": [
                        {"id": s.id, "puntos": s.puntos, "frase": s.frase, "detalle": s.detalle}
                        for s in senales
                    ],
                    "total_puntos": total_puntos,
                },
            )
        except Exception as e:
            logger.error(f"Rules analysis failed: {e}", exc_info=True)
            return RulesSignals(available=False, details={"error": str(e)})

    def analyze_ml(self, url: str) -> MLSignals:
        """Analyze URL using the ML model (predict.py)."""
        if not self.predict_available:
            return MLSignals(available=False, error=self.predict_error or "predict.py not available")

        try:
            result = predecir(url)
            return MLSignals(
                available=True,
                score=result["probabilidad"],
                is_suspicious=result["es_sospechoso"],
                threshold=result["umbral"],
                top_features=result["features_principales"],
                model_name=MODEL_NAME,
            )
        except Exception as e:
            logger.error(f"Predict analysis failed: {e}", exc_info=True)
            return MLSignals(available=False, error=str(e))
