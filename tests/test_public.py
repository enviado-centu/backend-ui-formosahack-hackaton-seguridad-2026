"""Tests de los endpoints públicos (/public/*) y del límite de pedidos por IP."""

import logging

import pytest
from sqlalchemy import text

from app.core import rate_limit
from app.core.config import settings
from app.core.rate_limit import LimitePorIP, limitador
from app.integrations.kev.integration import KevIntegration
from app.schemas.scan import KevSignals

URL_LISTA_NEGRA = "https://bna-homebanking-verificar.xyz/login"
URL_OFICIAL = "https://www.bna.com.ar"
URL_FALSA = "https://mercadolibre.tienda-falsa.top/oferta-exclusiva"

MSG_ESQUEMA = "Solo se pueden analizar direcciones que empiecen con http:// o https://."
MSG_LARGA = "La dirección es demasiado larga (máximo 2048 caracteres)."


class RelojFalso:
    def __init__(self):
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture(autouse=True)
def limite_limpio():
    """Cada test arranca sin pedidos registrados."""
    limitador.reiniciar()
    yield
    limitador.reiniciar()


async def _cantidad_scans(engine) -> int:
    async with engine.connect() as conn:
        return (await conn.execute(text("SELECT COUNT(*) FROM scans"))).scalar_one()


# ---------------------------------------------------------------- /public/analizar

async def test_analizar_lista_negra_sin_token(client):
    r = await client.post("/public/analizar", json={"url": URL_LISTA_NEGRA})
    assert r.status_code == 200, r.text
    datos = r.json()
    assert datos["url"] == URL_LISTA_NEGRA
    assert datos["dominio"] == "bna-homebanking-verificar.xyz"
    assert datos["summary"]["score_100"] == 100
    assert datos["summary"]["level"] == "high"


async def test_analizar_sitio_oficial_sin_token(client):
    r = await client.post("/public/analizar", json={"url": URL_OFICIAL})
    assert r.status_code == 200, r.text
    datos = r.json()
    assert datos["dominio"] == "bna.com.ar"
    assert datos["summary"]["score_100"] == 0
    assert datos["summary"]["level"] == "low"
    assert datos["summary"]["official_brand"] == "Banco Nación"


async def test_analizar_recorta_espacios(client):
    r = await client.post("/public/analizar", json={"url": f"  {URL_OFICIAL}  "})
    assert r.status_code == 200, r.text
    assert r.json()["url"] == URL_OFICIAL


async def test_summary_igual_al_del_escaneo_con_login(client, auth, monkeypatch):
    # Kev apagado: el público nunca lo consulta y el test no depende de que esté corriendo
    monkeypatch.setattr(
        KevIntegration, "analyze", lambda self, page_data: KevSignals(available=False, error="apagado en test")
    )
    r = await client.post("/scans", headers=auth, json={"page_data": {"url": URL_FALSA}})
    assert r.status_code == 201, r.text
    con_login = r.json()["summary"]

    r = await client.post("/public/analizar", json={"url": URL_FALSA})
    assert r.status_code == 200, r.text
    assert r.json()["summary"] == con_login


async def test_analizar_no_escribe_en_scans(client, auth, engine):
    r = await client.post("/scans", headers=auth, json={"page_data": {"url": URL_FALSA}})
    assert r.status_code == 201, r.text
    antes = await _cantidad_scans(engine)
    assert antes == 1

    for url in (URL_LISTA_NEGRA, URL_OFICIAL, URL_FALSA):
        assert (await client.post("/public/analizar", json={"url": url})).status_code == 200

    assert await _cantidad_scans(engine) == antes


async def test_analizar_no_loguea_la_url(client, caplog):
    caplog.set_level(logging.INFO)
    for url in (URL_LISTA_NEGRA, URL_OFICIAL, URL_FALSA):
        assert (await client.post("/public/analizar", json={"url": url})).status_code == 200

    # Se capturan logs (ej. "Riesgo: score=..."): el test no pasa por no ver nada
    assert any(r.name == "app.services.risk_service" for r in caplog.records)
    for registro in caplog.records:
        if registro.levelno >= logging.INFO:
            mensaje = registro.getMessage()
            for url in (URL_LISTA_NEGRA, URL_OFICIAL, URL_FALSA):
                assert url not in mensaje, f"{registro.name} logueó la URL: {mensaje}"


@pytest.mark.parametrize(
    "url, mensaje",
    [
        ("chrome://extensions", MSG_ESQUEMA),
        ("javascript:alert(1)", MSG_ESQUEMA),
        ("", MSG_ESQUEMA),
        ("https://a.com/" + "x" * 3000, MSG_LARGA),
    ],
    ids=["chrome", "javascript", "vacia", "3000-caracteres"],
)
async def test_analizar_url_invalida(client, url, mensaje):
    r = await client.post("/public/analizar", json={"url": url})
    assert r.status_code == 422
    assert r.json()["detail"][0]["msg"] == mensaje


async def test_analizar_url_sin_host(client):
    r = await client.post("/public/analizar", json={"url": "http://"})
    assert r.status_code == 422
    assert r.json()["detail"][0]["msg"] == "La dirección no tiene un nombre de sitio."


# ---------------------------------------------------------------- /public/lista-blanca

async def test_lista_blanca_publica(client):
    r = await client.get("/public/lista-blanca")
    assert r.status_code == 200, r.text
    assert r.headers["cache-control"] == "max-age=3600"
    datos = r.json()

    marcas = {m["id"]: m for m in datos["marcas"]}
    assert marcas["bna"]["nombre"] == "Banco Nación"
    assert "bna.com.ar" in marcas["bna"]["dominios"]
    assert set(marcas["bna"]) == {"id", "nombre", "dominios"}

    otra = await client.get("/public/lista-blanca")
    assert datos["version"] and otra.json()["version"] == datos["version"]


# ---------------------------------------------------------------- límite de pedidos

async def test_limite_de_pedidos(client, monkeypatch):
    monkeypatch.setattr(settings, "PUBLIC_RATE_LIMIT_PER_MIN", 3)
    for _ in range(3):
        assert (await client.post("/public/analizar", json={"url": URL_OFICIAL})).status_code == 200

    r = await client.post("/public/analizar", json={"url": URL_OFICIAL})
    assert r.status_code == 429
    assert int(r.headers["retry-after"]) >= 1
    assert r.json()["detail"] == rate_limit.MENSAJE_LIMITE

    # El límite es para todo /public/*
    assert (await client.get("/public/lista-blanca")).status_code == 429


def test_limite_ventana_deslizante():
    reloj = RelojFalso()
    limite = LimitePorIP(reloj=reloj)
    assert limite.registrar("1.1.1.1", 2) is None
    reloj.t += 30
    assert limite.registrar("1.1.1.1", 2) is None
    assert limite.registrar("1.1.1.1", 2) == 30  # el primero sale de la ventana en 30 s
    assert limite.registrar("2.2.2.2", 2) is None  # cada IP tiene su cuenta

    reloj.t += 30  # el primer pedido ya salió de la ventana
    assert limite.registrar("1.1.1.1", 2) is None
    assert limite.registrar("1.1.1.1", 2) == 30


def test_limite_olvida_ips_inactivas(monkeypatch):
    monkeypatch.setattr(rate_limit, "MAX_IPS_SIN_LIMPIAR", 2)
    reloj = RelojFalso()
    limite = LimitePorIP(reloj=reloj)
    limite.registrar("1.1.1.1", 10)
    limite.registrar("2.2.2.2", 10)
    reloj.t += 45
    limite.registrar("3.3.3.3", 10)  # 3 IPs: todavía no supera el máximo al entrar

    reloj.t += 20  # 1.1.1.1 y 2.2.2.2 quedan fuera de la ventana; 3.3.3.3 no
    limite.registrar("4.4.4.4", 10)
    assert set(limite._pedidos) == {"3.3.3.3", "4.4.4.4"}
