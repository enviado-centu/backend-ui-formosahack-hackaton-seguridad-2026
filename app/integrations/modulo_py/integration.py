"""Integration with MODULO-PY engine."""

import sys
import logging
from pathlib import Path
from typing import Optional

from ...schemas.scan import RulesSignals, MLSignals

logger = logging.getLogger(__name__)

MODULO_PY_PATH = Path(__file__).parent.parent.parent.parent.parent / "MODULO-PY"

if str(MODULO_PY_PATH) not in sys.path:
    sys.path.insert(0, str(MODULO_PY_PATH))

try:
    from motor.reglas import evaluar_reglas
    from motor.listas import esta_en_lista_negra, es_oficial
    MOTOR_AVAILABLE = True
    logger.info("MODULO-PY motor loaded successfully")
except ImportError as e:
    logger.error(f"Failed to import MODULO-PY motor: {e}")
    MOTOR_AVAILABLE = False

try:
    from features import extract_features_dominio
    FEATURES_AVAILABLE = True
    logger.info("MODULO-PY features loaded successfully")
except (ImportError, FileNotFoundError) as e:
    logger.warning(f"MODULO-PY features not available: {e}")
    FEATURES_AVAILABLE = False

try:
    from predict import predecir
    PREDICT_AVAILABLE = True
    logger.info("MODULO-PY predict loaded successfully")
except (ImportError, FileNotFoundError) as e:
    logger.warning(f"MODULO-PY predict not available: {e}")
    PREDICT_AVAILABLE = False


class ModuloPyIntegration:
    """Integration with MODULO-PY rules and ML engines."""
    
    def __init__(self):
        self.motor_available = MOTOR_AVAILABLE
        self.features_available = FEATURES_AVAILABLE
        self.predict_available = PREDICT_AVAILABLE
        
        if MOTOR_AVAILABLE:
            logger.info("MODULO-PY motor initialized")
    
    def analyze_rules(self, url: str) -> RulesSignals:
        """Analyze URL using the motor rules engine."""
        if not self.motor_available:
            logger.warning("Motor not available")
            return RulesSignals(available=False)
        
        try:
            senales = evaluar_reglas(url)
            
            triggered_rules = [s.id for s in senales]
            total_puntos = sum(s.puntos for s in senales)
            risk_score = min(1.0, total_puntos / 100.0)
            
            details = {
                "senales": [
                    {
                        "id": s.id,
                        "puntos": s.puntos,
                        "frase": s.frase,
                        "detalle": s.detalle
                    }
                    for s in senales
                ],
                "total_puntos": total_puntos,
            }
            
            lista_negra = esta_en_lista_negra(url)
            if lista_negra:
                details["lista_negra"] = lista_negra
            
            oficial = es_oficial(url)
            if oficial:
                details["es_oficial"] = oficial
            
            return RulesSignals(
                available=True,
                triggered_rules=triggered_rules,
                rule_count=len(triggered_rules),
                risk_score=risk_score,
                details=details,
            )
        except Exception as e:
            logger.error(f"Rules analysis failed: {e}", exc_info=True)
            return RulesSignals(available=False, details={"error": str(e)})
    
    def analyze_ml(self, url: str) -> MLSignals:
        """Analyze URL using ML engine (predict.py if available, fallback otherwise)."""
        if self.predict_available:
            try:
                result = predecir(url)
                
                return MLSignals(
                    available=True,
                    score=result["probabilidad"],
                    prediction=0 if result["es_sospechoso"] else 1,
                    confidence=result["probabilidad"] if result["es_sospechoso"] else 1 - result["probabilidad"],
                    model_name="modelo_phishing_joblib",
                    details={
                        "umbral": result["umbral"],
                        "features_principales": result["features_principales"],
                    },
                )
            except Exception as e:
                logger.error(f"Predict analysis failed: {e}", exc_info=True)
                return MLSignals(available=False, error=str(e))
        else:
            logger.warning("ML engine not available")
            return MLSignals(available=False, error="predict.py not available")
    
    def extract_url_features(self, url: str) -> dict:
        """Extract features from URL using features.py module."""
        if not self.features_available:
            logger.warning("features module not available")
            return {}
        
        try:
            return extract_features_dominio(url)
        except Exception as e:
            logger.error(f"Feature extraction failed: {e}", exc_info=True)
            return {}
