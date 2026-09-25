"""Endpoints públicos (sin login) para la extensión de navegador."""

import logging

from fastapi import APIRouter, Depends, HTTPException, Response, status
from starlette.concurrency import run_in_threadpool

from ..core.rate_limit import limitar_publico
from ..schemas.public import AnalizarPublicoRequest, AnalizarPublicoResponse, ListaBlancaPublica
from ..services.public_service import analizar_publico, lista_blanca_publica

logger = logging.getLogger(__name__)

# El límite corre antes de validar el body: los pedidos inválidos también cuentan
router = APIRouter(prefix="/public", tags=["public"], dependencies=[Depends(limitar_publico)])

CACHE_LISTA_BLANCA = "max-age=3600"


@router.post("/analizar", response_model=AnalizarPublicoResponse)
async def analizar(body: AnalizarPublicoRequest):
    """Analiza una URL sin guardar nada. POST para que la URL no quede en los logs de acceso."""
    # Reglas y modelo son bloqueantes: se corren fuera del event loop
    return await run_in_threadpool(analizar_publico, body.url)


@router.get("/lista-blanca", response_model=ListaBlancaPublica)
def lista_blanca(response: Response):
    """Dominios oficiales, para que la extensión no mande esas URLs al backend."""
    try:
        resultado = lista_blanca_publica()
    except RuntimeError as e:
        logger.error(f"Lista blanca no disponible: {e}")
        # El 503 no lleva Cache-Control: la extensión tiene que reintentar
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="La lista de sitios oficiales no está disponible en este momento. Probá de nuevo más tarde.",
        )
    response.headers["Cache-Control"] = CACHE_LISTA_BLANCA
    return resultado
