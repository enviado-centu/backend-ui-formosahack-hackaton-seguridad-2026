"""Criterio único de riesgo del backend.

El motor (MODULO-PY/motor) aporta listas y reglas; el modelo aporta una probabilidad; Kev,
si está disponible, una opinión sobre el contenido. El puntaje (0-100), el nivel y la
clasificación se deciden solo acá, en RiskService.evaluar().
"""

import logging
from dataclasses import dataclass
from typing import Callable, Optional

from ..integrations.modulo_py.integration import ModuloPyIntegration
from ..schemas.scan import (
    KevSignals,
    MLSignals,
    RiskAssessment,
    RulesSignals,
    ScanSummary,
)

logger = logging.getLogger(__name__)

UMBRAL_MEDIO = 40
UMBRAL_ALTO = 70
PUNTOS_MODELO = 25
PUNTAJE_MAXIMO = 100

# Reglas del motor que indican imitación de una marca (su detalle trae marca_id)
REGLAS_MARCA = frozenset({"marca_host", "marca_otro_tld", "marca_path"})

# Frases para el usuario: hablan de señales, nunca afirman que el sitio "es" una estafa
FRASE_LISTA_NEGRA = "Este sitio figura en listas de sitios reportados por engaños"
FRASE_OFICIAL = "Es el sitio oficial de {nombre}"
FRASE_MODELO = "El análisis automático del dominio lo encuentra muy parecido a sitios fraudulentos conocidos"
FRASE_KEV = "El análisis del contenido de la página encontró señales de engaño"

TIPS = {
    "high": (
        "No ingreses datos, claves ni códigos en este sitio. Si necesitás operar, "
        "entrá desde la app oficial o escribiendo vos la dirección."
    ),
    "medium": (
        "Tené cuidado: revisá bien la dirección antes de seguir y no ingreses "
        "datos personales si no estás seguro de dónde estás."
    ),
    "low": (
        "No encontramos señales de riesgo. Igual, nunca compartas claves ni códigos "
        "que te pidan por mensaje."
    ),
}

CLASIFICACION_POR_NIVEL = {"low": "benign", "medium": "suspicious", "high": "phishing"}
GRAVEDAD = {"benign": 0, "suspicious": 1, "phishing": 2, "malware": 2, "scam": 2}
ORDEN_NIVEL = {"low": 0, "medium": 1, "high": 2}


def nivel_de(score_100: int) -> str:
    """bajo < 40, medio 40-69, alto >= 70."""
    if score_100 >= UMBRAL_ALTO:
        return "high"
    if score_100 >= UMBRAL_MEDIO:
        return "medium"
    return "low"


@dataclass
class ResultadoRiesgo:
    risk: RiskAssessment
    summary: ScanSummary
    rules: RulesSignals
    ml: MLSignals
    kev: KevSignals


class RiskService:
    """Combina lista negra, lista blanca, reglas, modelo y Kev en un único diagnóstico."""

    def __init__(self, modulo_py: Optional[ModuloPyIntegration] = None):
        self.modulo_py = modulo_py or ModuloPyIntegration()

    def evaluar(self, url: str, consultar_kev: Callable[[], KevSignals]) -> ResultadoRiesgo:
        """Diagnóstico de una URL. Orden (corta en el primer caso que aplica):

        a) lista negra -> 100, alto (no se consulta el modelo ni Kev);
        b) sitio oficial -> 0, bajo (no corren reglas, modelo ni Kev);
        c) resto -> puntos de las reglas + 25 si el modelo supera su umbral (tope 100).
           Kev solo puede subir el puntaje o la clasificación, nunca bajarlos.

        `consultar_kev` se llama solo en el caso c.
        """
        coincidencia = self.modulo_py.lista_negra(url)
        if coincidencia:
            return self._resultado(
                score=PUNTAJE_MAXIMO,
                source="lista_negra",
                reasons=[FRASE_LISTA_NEGRA],
                rules=RulesSignals(available=False, details={"omitido": "lista negra", "lista_negra": coincidencia}),
                ml=MLSignals(available=False, error="No se consultó: el sitio está en lista negra"),
                kev=KevSignals(available=False, error="No se consultó: el sitio está en lista negra"),
            )

        marca_id = self.modulo_py.marca_oficial(url)
        if marca_id:
            nombre = self.modulo_py.nombre_marca(marca_id)
            return self._resultado(
                score=0,
                source="sitio_oficial",
                reasons=[FRASE_OFICIAL.format(nombre=nombre)],
                official_brand=nombre,
                rules=RulesSignals(available=False, details={"omitido": "sitio oficial", "es_oficial": marca_id}),
                ml=MLSignals(available=False, error="No se consultó: es un sitio oficial"),
                kev=KevSignals(available=False, error="No se consultó: es un sitio oficial"),
            )

        rules = self.modulo_py.analyze_rules(url)
        senales = rules.details.get("senales", []) if rules.available else []
        score = sum(s["puntos"] for s in senales)
        reasons = [s["frase"] for s in senales]
        brand = next(
            (self.modulo_py.nombre_marca(s["detalle"]["marca_id"]) for s in senales if s["id"] in REGLAS_MARCA),
            None,
        )

        ml = self.modulo_py.analyze_ml(url)
        if ml.available and ml.is_suspicious:
            score += PUNTOS_MODELO
            reasons.append(FRASE_MODELO)
        score = min(score, PUNTAJE_MAXIMO)

        kev = consultar_kev()
        return self._resultado(
            score=score, source="analisis", reasons=reasons, brand=brand, rules=rules, ml=ml, kev=kev
        )

    def _resultado(
        self,
        *,
        score: int,
        source: str,
        reasons: list[str],
        rules: RulesSignals,
        ml: MLSignals,
        kev: KevSignals,
        brand: Optional[str] = None,
        official_brand: Optional[str] = None,
    ) -> ResultadoRiesgo:
        level = nivel_de(score)
        classification = CLASIFICACION_POR_NIVEL[level]
        probability = None

        # Kev solo puede subir: puntaje (y con él el nivel) y clasificación
        if kev.available and kev.is_phishing is not None:
            kev_subio_nivel = False
            score_kev = round(kev.is_phishing * 100)
            if score_kev > score:
                score = score_kev
                nuevo_nivel = nivel_de(score)
                if ORDEN_NIVEL[nuevo_nivel] > ORDEN_NIVEL[level]:
                    reasons = [*reasons, FRASE_KEV]
                    kev_subio_nivel = True
                level = nuevo_nivel
                classification = CLASIFICACION_POR_NIVEL[level]
            if kev.threat_type:
                clase_kev = kev.threat_type if kev.threat_type in GRAVEDAD else "suspicious"
                # Si Kev subió el nivel, su tipo (ej. scam) precisa al del nivel aunque pesen igual
                mas_grave = GRAVEDAD[clase_kev] > GRAVEDAD[classification]
                precisa = kev_subio_nivel and GRAVEDAD[clase_kev] == GRAVEDAD[classification]
                if mas_grave or precisa:
                    classification, probability = clase_kev, kev.threat_confidence

        logger.info(f"Riesgo: score={score} level={level} classification={classification} source={source}")
        return ResultadoRiesgo(
            risk=RiskAssessment(
                score=score / PUNTAJE_MAXIMO,
                level=level,
                classification_type=classification,
                classification_probability=probability,
            ),
            summary=ScanSummary(
                score_100=score,
                level=level,
                source=source,
                reasons=reasons,
                tip=TIPS[level],
                brand=brand,
                official_brand=official_brand,
            ),
            rules=rules,
            ml=ml,
            kev=kev,
        )
