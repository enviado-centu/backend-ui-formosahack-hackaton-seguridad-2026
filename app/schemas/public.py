"""Schemas de los endpoints públicos (sin login) que usa la extensión."""

from urllib.parse import urlsplit

from pydantic import BaseModel, Field, field_validator
from pydantic_core import PydanticCustomError

from .scan import ScanSummary

LARGO_MAXIMO_URL = 2048
ESQUEMAS_PERMITIDOS = ("http", "https")


class AnalizarPublicoRequest(BaseModel):
    """URL a analizar. Viaja en el body (POST) para que no quede en los logs de acceso."""

    url: str = Field(..., description="Dirección completa (http o https)")

    @field_validator("url")
    @classmethod
    def validar_url(cls, v: str) -> str:
        # PydanticCustomError: el mensaje del 422 sale en español, sin el prefijo "Value error,"
        v = v.strip()
        if len(v) > LARGO_MAXIMO_URL:
            raise PydanticCustomError(
                "url_larga", f"La dirección es demasiado larga (máximo {LARGO_MAXIMO_URL} caracteres)."
            )
        try:
            partes = urlsplit(v)
            host = partes.hostname
        except ValueError:
            partes, host = None, None
        if partes is None or partes.scheme.lower() not in ESQUEMAS_PERMITIDOS:
            raise PydanticCustomError(
                "url_esquema", "Solo se pueden analizar direcciones que empiecen con http:// o https://."
            )
        if not host:
            raise PydanticCustomError("url_sin_host", "La dirección no tiene un nombre de sitio.")
        return v


class AnalizarPublicoResponse(BaseModel):
    """Mismo bloque summary que el escaneo con login, más la URL y su dominio registrable."""

    url: str
    dominio: str
    summary: ScanSummary


class MarcaPublica(BaseModel):
    """Marca de la lista blanca con sus dominios registrables oficiales."""

    id: str
    nombre: str
    dominios: list[str]


class ListaBlancaPublica(BaseModel):
    """Lista blanca para que la extensión resuelva localmente los sitios oficiales."""

    version: str = Field(..., description="Hash corto del contenido: cambia solo si cambian las marcas")
    marcas: list[MarcaPublica]
