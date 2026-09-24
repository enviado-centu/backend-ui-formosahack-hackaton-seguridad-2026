"""Tests de la API: autenticación, escaneos y health."""

URL_FALSA = "https://mercadolibre.tienda-falsa.top/oferta-exclusiva"


async def test_registro(client):
    r = await client.post("/auth/register", json={"email": "ana@example.com", "password": "password123"})
    assert r.status_code == 201
    datos = r.json()
    assert datos["email"] == "ana@example.com"
    assert datos["is_active"] is True
    assert "password" not in datos and "hashed_password" not in datos


async def test_registro_email_duplicado(client):
    cuerpo = {"email": "ana@example.com", "password": "password123"}
    assert (await client.post("/auth/register", json=cuerpo)).status_code == 201
    r = await client.post("/auth/register", json=cuerpo)
    assert r.status_code == 400
    assert "already exists" in r.json()["detail"]


async def test_registro_clave_corta(client):
    r = await client.post("/auth/register", json={"email": "ana@example.com", "password": "corta"})
    assert r.status_code == 422


async def test_login_clave_incorrecta(client):
    await client.post("/auth/register", json={"email": "ana@example.com", "password": "password123"})
    r = await client.post("/auth/login", json={"email": "ana@example.com", "password": "otra-clave-123"})
    assert r.status_code == 401


async def test_me_con_y_sin_token(client, auth):
    assert (await client.get("/auth/me")).status_code in (401, 403)
    r = await client.get("/auth/me", headers=auth)
    assert r.status_code == 200
    assert r.json()["email"] == "ana@example.com"


async def test_escanear_y_listar(client, auth):
    r = await client.post("/scans", headers=auth, json={"page_data": {"url": URL_FALSA, "domain": "x"}})
    assert r.status_code == 201, r.text
    escaneo = r.json()
    assert escaneo["status"] == "completed"
    assert escaneo["signals"]["rules"]["available"] is True

    r = await client.get("/scans", headers=auth)
    assert r.status_code == 200
    lista = r.json()
    assert [s["scan_id"] for s in lista] == [escaneo["scan_id"]]

    r = await client.get(f"/scans/{escaneo['scan_id']}", headers=auth)
    assert r.status_code == 200
    assert r.json()["risk"] == escaneo["risk"]


async def test_escanear_sin_token(client):
    r = await client.post("/scans", json={"page_data": {"url": URL_FALSA, "domain": "x"}})
    assert r.status_code in (401, 403)


async def test_escaneo_de_otro_usuario_da_404(client, auth, nuevo_token):
    r = await client.post("/scans", headers=auth, json={"page_data": {"url": URL_FALSA, "domain": "x"}})
    scan_id = r.json()["scan_id"]

    otro = {"Authorization": f"Bearer {await nuevo_token('beto@example.com')}"}
    assert (await client.get(f"/scans/{scan_id}", headers=otro)).status_code == 404
    assert (await client.get("/scans", headers=otro)).json() == []


async def test_health(client):
    r = await client.get("/health")
    assert r.status_code == 200
    assert r.json()["services"]["database"] == "ok"
    assert r.json()["services"]["rules"] == "ok"


async def test_health_ml_nunca_da_500(client):
    r = await client.get("/health/ml")
    assert r.status_code == 200
    datos = r.json()
    assert set(datos) == {"status", "rules_engine", "ml_model_loaded", "ml_error"}
    assert datos["rules_engine"] is True
    # Si el modelo no cargó, tiene que decir por qué
    assert datos["ml_model_loaded"] or datos["ml_error"]
