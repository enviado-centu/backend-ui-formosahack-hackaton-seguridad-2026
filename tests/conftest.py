"""Fixtures de los tests del backend.

Base de datos: si TEST_DATABASE_URL (en .env o en el entorno) responde, se usa esa base
PostgreSQL con las migraciones de Alembic aplicadas. Si no, SQLite en memoria con
create_all. El encabezado de pytest dice cuál se usó.
"""

import asyncio
import os
import subprocess
import sys
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

BACKEND = Path(__file__).resolve().parents[1]
SQLITE_MEMORIA = "sqlite+aiosqlite:///:memory:"

# La app exige DATABASE_URL: sin .env (por ejemplo en CI) los tests igual tienen que correr
if not os.environ.get("DATABASE_URL") and not (BACKEND / ".env").exists():
    os.environ["DATABASE_URL"] = SQLITE_MEMORIA

from app.core.config import settings  # noqa: E402
from app.core.database import Base, get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import scan, user  # noqa: E402,F401

_BASE_TEST = {"url": SQLITE_MEMORIA, "motivo": "TEST_DATABASE_URL no está definida"}


async def _postgres_responde(url: str) -> bool:
    engine = create_async_engine(url)
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    finally:
        await engine.dispose()


def pytest_configure(config):
    url = settings.TEST_DATABASE_URL
    if not url:
        return
    try:
        asyncio.run(_postgres_responde(url))
    except Exception as e:
        _BASE_TEST["motivo"] = f"TEST_DATABASE_URL no responde ({type(e).__name__}: {e})"
        return
    # La base de test se arma con las mismas migraciones que producción
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=BACKEND,
        env={**os.environ, "DATABASE_URL": url},
        check=True,
        capture_output=True,
    )
    _BASE_TEST.update(url=url, motivo=None)


def pytest_report_header(config):
    if _BASE_TEST["motivo"] is None:
        base = _BASE_TEST["url"].rsplit("@", 1)[-1]
        return f"base de test: PostgreSQL ({base}), migrada con alembic upgrade head"
    return f"base de test: SQLite en memoria ({_BASE_TEST['motivo']})"


@pytest.fixture(scope="session")
async def engine():
    if _BASE_TEST["motivo"] is None:
        eng = create_async_engine(_BASE_TEST["url"])
    else:
        eng = create_async_engine(
            SQLITE_MEMORIA, poolclass=StaticPool, connect_args={"check_same_thread": False}
        )
        async with eng.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest.fixture(autouse=True)
async def base_limpia(engine):
    """Cada test arranca con las tablas vacías."""
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM scans"))
        await conn.execute(text("DELETE FROM users"))


@pytest.fixture
async def client(engine):
    sesiones = async_sessionmaker(engine, expire_on_commit=False)

    async def get_db_test():
        async with sesiones() as session:
            yield session

    app.dependency_overrides[get_db] = get_db_test
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
    app.dependency_overrides.clear()


async def _token(client, email: str, password: str = "password123") -> str:
    r = await client.post("/auth/register", json={"email": email, "password": password})
    assert r.status_code == 201, r.text
    r = await client.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture
async def auth(client):
    """Headers de un usuario registrado y logueado."""
    token = await _token(client, "ana@example.com")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def nuevo_token(client):
    """Registra y loguea otro usuario; devuelve su token."""
    return lambda email: _token(client, email)
