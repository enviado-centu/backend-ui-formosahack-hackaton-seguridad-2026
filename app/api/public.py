"""Endpoints públicos (sin login) para la extensión de navegador."""

from fastapi import APIRouter
from starlette.concurrency import run_in_threadpool

from ..schemas.public import AnalizarPublicoRequest, AnalizarPublicoResponse
from ..services.public_service import analizar_publico

router = APIRouter(prefix="/public", tags=["public"])


@router.post("/analizar", response_model=AnalizarPublicoResponse)
async def analizar(body: AnalizarPublicoRequest):
    """Analiza una URL sin guardar nada. POST para que la URL no quede en los logs de acceso."""
    # Reglas y modelo son bloqueantes: se corren fuera del event loop
    return await run_in_threadpool(analizar_publico, body.url)
