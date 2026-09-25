"""Escaneo público para la extensión: mismo criterio que el escaneo con login, sin base de datos.

No se guarda nada ni se loguea la URL: la extensión consulta cada sitio que visita el usuario.
"""

import hashlib
import json

from ..integrations.modulo_py.integration import ModuloPyIntegration
from ..schemas.public import AnalizarPublicoResponse, ListaBlancaPublica, MarcaPublica
from ..schemas.scan import KevSignals
from .risk_service import RiskService

MOTIVO_SIN_KEV = "No se consulta en el escaneo público"
LARGO_VERSION = 12


def _sin_kev() -> KevSignals:
    # Kev analiza el contenido de la página y acá solo llega la URL; además agregaría su demora
    return KevSignals(available=False, error=MOTIVO_SIN_KEV)


def analizar_publico(url: str) -> AnalizarPublicoResponse:
    """Diagnóstico de una URL con RiskService.evaluar (bloqueante: correr fuera del event loop)."""
    modulo_py = ModuloPyIntegration()
    resultado = RiskService(modulo_py).evaluar(url, _sin_kev)
    return AnalizarPublicoResponse(url=url, dominio=modulo_py.dominio(url), summary=resultado.summary)


def lista_blanca_publica() -> ListaBlancaPublica:
    """Marcas oficiales del motor (id, nombre, dominios) y un hash corto de ese contenido.

    Lanza RuntimeError si el motor no está disponible.
    """
    marcas = [
        {"id": marca_id, "nombre": datos["nombre"], "dominios": list(datos["dominios"])}
        for marca_id, datos in ModuloPyIntegration().lista_blanca().items()
    ]
    contenido = json.dumps(marcas, sort_keys=True, ensure_ascii=False).encode("utf-8")
    version = hashlib.sha256(contenido).hexdigest()[:LARGO_VERSION]
    return ListaBlancaPublica(version=version, marcas=[MarcaPublica(**m) for m in marcas])
