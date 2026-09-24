"""Tests del criterio único de riesgo (app/services/risk_service.py)."""

import time

import pytest

from app.schemas.scan import KevSignals, MLSignals
from app.services.risk_service import (
    FRASE_KEV,
    FRASE_LISTA_NEGRA,
    FRASE_MODELO,
    RiskService,
    nivel_de,
)


def kev_no_se_consulta():
    raise AssertionError("Kev no debería consultarse en este caso")


def kev_caido():
    return KevSignals(available=False, error="Unable to connect to Kev")


def kev_con(is_phishing: float, threat_type: str, confianza: float = 0.9):
    return lambda: KevSignals(
        available=True, is_phishing=is_phishing, threat_type=threat_type, threat_confidence=confianza
    )


@pytest.fixture
def servicio():
    return RiskService()


@pytest.mark.parametrize("score, nivel", [(0, "low"), (39, "low"), (40, "medium"), (69, "medium"), (70, "high"), (100, "high")])
def test_umbrales_de_nivel(score, nivel):
    assert nivel_de(score) == nivel


def test_sitio_oficial_con_login_en_la_ruta(servicio):
    r = servicio.evaluar("https://www.bna.com.ar/personas/login", kev_no_se_consulta)

    assert r.summary.score_100 == 0
    assert r.summary.level == "low"
    assert r.summary.source == "sitio_oficial"
    assert r.summary.reasons == ["Es el sitio oficial de Banco Nación"]
    assert r.summary.official_brand == "Banco Nación"
    assert not any("login" in frase for frase in r.summary.reasons)
    # No corren reglas ni modelo
    assert r.rules.available is False
    assert r.ml.available is False
    assert r.risk.classification_type == "benign"


def test_lista_negra_da_100_sin_consultar_el_modelo(servicio, monkeypatch):
    monkeypatch.setattr(servicio.modulo_py, "lista_negra", lambda url: {"tipo": "dominio", "coincidencia": "trampa.com"})
    monkeypatch.setattr(servicio.modulo_py, "analyze_ml", lambda url: pytest.fail("no debería consultar el modelo"))

    r = servicio.evaluar("https://trampa.com/login", kev_no_se_consulta)

    assert r.summary.score_100 == 100
    assert r.summary.level == "high"
    assert r.summary.source == "lista_negra"
    assert r.summary.reasons == [FRASE_LISTA_NEGRA]
    assert r.risk.score == 1.0


def test_lista_negra_real_del_motor(servicio):
    # dominio:bna-homebanking-verificar.xyz está en motor/datos/lista_negra_propia.txt
    r = servicio.evaluar("http://bna-homebanking-verificar.xyz/login", kev_no_se_consulta)
    assert (r.summary.score_100, r.summary.source) == (100, "lista_negra")


def test_imitacion_de_marca_mas_tld_sospechoso_es_alto(servicio):
    r = servicio.evaluar("https://mercadolibre.tienda-falsa.top/oferta-exclusiva", kev_caido)

    assert r.summary.level == "high"
    assert r.summary.score_100 >= 72  # marca en el host (60) + TLD .top (12)
    assert r.summary.brand == "Mercado Libre"
    assert any("Mercado Libre" in frase for frase in r.summary.reasons)
    assert any(".top" in frase for frase in r.summary.reasons)
    assert r.risk.classification_type == "phishing"


def test_modelo_suma_25_con_su_frase(servicio, monkeypatch):
    monkeypatch.setattr(
        servicio.modulo_py, "analyze_ml", lambda url: MLSignals(available=True, score=0.95, is_suspicious=True, threshold=0.9)
    )
    r = servicio.evaluar("https://sitio-sin-reglas.com", kev_caido)
    assert r.summary.score_100 == 25
    assert r.summary.reasons == [FRASE_MODELO]
    assert r.summary.level == "low"


def test_modelo_no_cargado_no_suma(servicio, monkeypatch):
    monkeypatch.setattr(servicio.modulo_py, "analyze_ml", lambda url: MLSignals(available=False, error="sin modelo"))
    r = servicio.evaluar("https://mercadolibre.tienda-falsa.top/oferta-exclusiva", kev_caido)
    assert r.summary.score_100 == 72
    assert FRASE_MODELO not in r.summary.reasons


def test_kev_caido_no_rompe_el_diagnostico(servicio):
    r = servicio.evaluar("https://mercadolibre.tienda-falsa.top/oferta-exclusiva", kev_caido)
    assert r.kev.available is False
    assert r.summary.level == "high"


def test_kev_con_puntaje_bajo_no_baja_un_resultado_alto(servicio):
    r = servicio.evaluar("https://mercadolibre.tienda-falsa.top/oferta-exclusiva", kev_con(0.01, "benign", 0.99))
    assert r.summary.level == "high"
    assert r.risk.classification_type == "phishing"
    assert FRASE_KEV not in r.summary.reasons


def test_kev_puede_subir_el_nivel(servicio):
    r = servicio.evaluar("https://sitio-sin-reglas.com", kev_con(0.85, "scam", 0.8))
    assert r.summary.score_100 == 85
    assert r.summary.level == "high"
    assert FRASE_KEV in r.summary.reasons
    assert r.risk.classification_type == "scam"
    assert r.risk.classification_probability == 0.8


def test_kev_puede_subir_solo_la_clasificacion(servicio):
    r = servicio.evaluar("https://sitio-sin-reglas.com", kev_con(0.10, "malware", 0.7))
    assert r.summary.level == "low"
    assert r.risk.classification_type == "malware"


async def test_escaneo_con_kev_caido_responde_rapido(client, auth, monkeypatch):
    # Puerto sin servidor: la conexión se rechaza y el escaneo sigue sin Kev
    from app.core.config import settings
    from app.integrations.kev import integration as kev_integration

    monkeypatch.setattr(settings, "KEV_BASE_URL", "http://127.0.0.1:9")
    monkeypatch.setattr(kev_integration, "_kev_caido_hasta", 0.0)
    inicio = time.perf_counter()
    r = await client.post("/scans", headers=auth, json={"page_data": {"url": "https://google.com"}})
    duracion = time.perf_counter() - inicio

    assert r.status_code == 201, r.text
    datos = r.json()
    assert datos["signals"]["kev"]["available"] is False
    assert datos["summary"]["level"] == "low"
    assert datos["target"]["domain"] == "google.com"  # se deriva de la URL
    assert duracion < 3


async def test_kev_caido_no_se_reintenta_en_cada_escaneo(client, auth, monkeypatch):
    from app.core.config import settings
    from app.integrations.kev import integration as kev_integration

    monkeypatch.setattr(settings, "KEV_BASE_URL", "http://127.0.0.1:9")
    monkeypatch.setattr(kev_integration, "_kev_caido_hasta", 0.0)
    await client.post("/scans", headers=auth, json={"page_data": {"url": "https://google.com"}})

    inicio = time.perf_counter()
    r = await client.post("/scans", headers=auth, json={"page_data": {"url": "https://github.com"}})
    assert time.perf_counter() - inicio < 1
    assert "se reintenta" in r.json()["signals"]["kev"]["error"]
