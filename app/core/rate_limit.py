"""Límite de pedidos por IP para /public/*, con ventana deslizante.

El estado vive en memoria de este proceso: no se comparte entre workers ni sobrevive a un
reinicio. Alcanza para la demo; con varios workers habría que moverlo a algo compartido.
"""

import math
import time
from collections import deque
from typing import Callable, Optional

from fastapi import HTTPException, Request, status

from .config import settings

VENTANA_S = 60.0
IP_DESCONOCIDA = "desconocido"
MAX_IPS_SIN_LIMPIAR = 10_000
MENSAJE_LIMITE = "Hiciste demasiadas consultas seguidas. Esperá unos segundos y probá de nuevo."


class LimitePorIP:
    """Cuenta los pedidos de cada IP en los últimos VENTANA_S segundos."""

    def __init__(self, ventana_s: float = VENTANA_S, reloj: Callable[[], float] = time.monotonic):
        self.ventana_s = ventana_s
        self.reloj = reloj
        self._pedidos: dict[str, deque[float]] = {}

    def registrar(self, ip: str, por_minuto: int) -> Optional[int]:
        """None si el pedido entra; si no, los segundos a esperar (Retry-After, >= 1)."""
        ahora = self.reloj()
        if len(self._pedidos) > MAX_IPS_SIN_LIMPIAR:
            self._olvidar_inactivas(ahora)
        pedidos = self._pedidos.setdefault(ip, deque())
        while pedidos and pedidos[0] <= ahora - self.ventana_s:
            pedidos.popleft()

        if len(pedidos) >= por_minuto:
            # Se libera un lugar cuando el pedido más viejo sale de la ventana
            return max(1, math.ceil(pedidos[0] + self.ventana_s - ahora))

        pedidos.append(ahora)
        return None

    def _olvidar_inactivas(self, ahora: float) -> None:
        """Borra las IPs sin pedidos dentro de la ventana, para que la memoria no crezca sin fin."""
        for ip in [ip for ip, p in self._pedidos.items() if not p or p[-1] <= ahora - self.ventana_s]:
            del self._pedidos[ip]

    def reiniciar(self) -> None:
        self._pedidos.clear()


limitador = LimitePorIP()


async def limitar_publico(request: Request) -> None:
    """Dependencia de /public/*. Usa la IP de la conexión: X-Forwarded-For no se lee
    porque cualquier cliente lo puede inventar para esquivar el límite."""
    ip = request.client.host if request.client else IP_DESCONOCIDA
    espera = limitador.registrar(ip, settings.PUBLIC_RATE_LIMIT_PER_MIN)
    if espera is not None:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=MENSAJE_LIMITE,
            headers={"Retry-After": str(espera)},
        )
