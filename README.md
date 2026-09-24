# Backend - Phishing Detection API

Backend FastAPI para detección de phishing y amenazas.

## Arquitectura

```
Browser Extension / Mobile App / Dashboard
        │
        ▼
┌─────────────────────────┐
│       FastAPI Backend   │
└───────────┬─────────────┘
            │
            ▼
       Scan Service
            │
       ┌────┴────┐
       ▼         ▼
  MODULO-PY     Kev
  (Rules+ML)   (AI Model)
       │         │
       └────┬────┘
            ▼
      Risk Assessment
            │
            ▼
        Database
```

## Características

- ✅ Registro y autenticación de usuarios (JWT)
- ✅ Análisis de páginas web
- ✅ Integración con MODULO-PY (reglas + ML)
- ✅ Integración con Kev (modelo AI)
- ✅ Risk assessment combinado
- ✅ Historial de análisis
- ✅ Health checks
- ✅ Documentación OpenAPI automática

## Requisitos

- Python 3.13
- PostgreSQL 16 o superior: con Docker Desktop (recomendado) o instalado localmente
- Los repos hermanos clonados al lado de este, en la misma carpeta:
  `MODULO-PY/` (motor de reglas y modelo) y `kev-integration/` (cliente de Kev)

Todos los comandos son para **PowerShell en Windows** y se corren **desde la carpeta del backend**
(el `.env` se lee desde la carpeta actual).

## Instalación

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt   # requirements.txt + pytest (usá requirements.txt en producción)

copy .env.example .env
```

Editá `.env`:

- `POSTGRES_PASSWORD`: una clave cualquiera; poné **la misma** en `DATABASE_URL` y `TEST_DATABASE_URL`.
- `SECRET_KEY`: generala con `python -c "import secrets; print(secrets.token_urlsafe(64))"`.
  Si la dejás vacía en `ENVIRONMENT=development`, el backend genera una temporal y avisa
  (los tokens dejan de valer al reiniciar). En `ENVIRONMENT=production` es obligatoria.

## Base de datos (PostgreSQL)

### Opción A: con Docker

```powershell
docker compose up -d                  # postgres:16 con volumen persistente "pgdata"
docker compose ps                     # esperar a que diga "healthy"
alembic upgrade head                  # crea las tablas
```

La primera vez que arranca el volumen se crea también la base de tests `detector_test`.

Si ya tenés un PostgreSQL instalado escuchando en el 5432, poné `POSTGRES_PORT=5433` en `.env`
y cambiá `:5432` por `:5433` en `DATABASE_URL` y `TEST_DATABASE_URL`.

### Opción B: sin Docker (PostgreSQL instalado localmente)

1. Instalá PostgreSQL desde https://www.postgresql.org/download/windows/ (anotá la clave del usuario `postgres`).
2. Creá el rol `detector` y las bases `detector` y `detector_test` (te pide la clave de `postgres`):

   ```powershell
   $clave = (Select-String -Path .env -Pattern '^POSTGRES_PASSWORD=(.*)').Matches.Groups[1].Value
   & "C:\Program Files\PostgreSQL\18\bin\psql.exe" -U postgres -v clave=$clave -f scripts\crear_db_local.sql
   ```

   (Cambiá `18` por tu versión.) El script se puede correr más de una vez.
3. `alembic upgrade head`

### Migraciones

- Las tablas las crea **solo Alembic**; la aplicación no hace `create_all`.
- Nueva migración después de cambiar un modelo: `alembic revision --autogenerate -m "descripcion"`,
  revisarla a mano y `alembic upgrade head`.
- `alembic check` confirma que los modelos y la base coinciden.

Antes el backend usaba SQLite (`backend.db`). No había datos que conservar, así que no hay nada que migrar.

## Ejecución

```powershell
uvicorn app.main:app --reload --port 8000
```

Documentación: http://localhost:8000/docs

## Tests

```powershell
pytest
```

Si `TEST_DATABASE_URL` responde, los tests corren contra esa base PostgreSQL (se le aplican las
migraciones con Alembic). Si no, usan SQLite en memoria. La primera línea de la salida de pytest
dice cuál se usó.

## API Endpoints

### Autenticación

```bash
# Registro
POST /auth/register
{
  "email": "user@example.com",
  "password": "securepassword123"
}

# Login
POST /auth/login
{
  "email": "user@example.com",
  "password": "securepassword123"
}

# Obtener usuario actual
GET /auth/me
Authorization: Bearer <token>
```

### Scans

```bash
# Crear scan
POST /scans
Authorization: Bearer <token>
{
  "page_data": {
    "url": "https://example.com",
    "domain": "example.com",
    "title": "Example Page",
    "visible_text": "Page content...",
    "forms": [...],
    "links": [...]
  }
}

# Listar scans
GET /scans
Authorization: Bearer <token>

# Obtener scan específico
GET /scans/{scan_id}
Authorization: Bearer <token>
```

### Health Checks

```bash
# Health general
GET /health

# Health de Kev
GET /health/kev

# Health de ML
GET /health/ml
```

## Documentación API

Una vez iniciado el servidor, accede a:

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Estructura

```
backend/
├── app/
│   ├── main.py              # Entry point
│   ├── api/                 # Endpoints
│   │   ├── auth.py         # Autenticación
│   │   ├── scans.py        # Scans
│   │   └── health.py       # Health checks
│   ├── core/               # Configuración
│   │   ├── config.py       # Settings
│   │   ├── security.py     # JWT, passwords
│   │   ├── database.py     # DB setup
│   │   └── dependencies.py # Dependencias
│   ├── models/             # Modelos DB
│   │   ├── user.py
│   │   └── scan.py
│   ├── schemas/            # Schemas Pydantic
│   │   ├── auth.py
│   │   └── scan.py
│   ├── services/           # Lógica de negocio
│   │   ├── auth_service.py
│   │   ├── scan_service.py
│   │   └── risk_service.py
│   └── integrations/       # Integraciones externas
│       ├── kev/
│       └── modulo_py/
├── alembic/              # Migraciones
├── scripts/              # SQL para PostgreSQL local e init del contenedor
├── tests/
├── docker-compose.yml
├── requirements.txt
├── requirements-dev.txt
├── .env.example
└── README.md
```

## Flujo de Scan

1. Usuario envía POST /scans con datos de página
2. Backend valida y crea registro de scan
3. Ejecuta reglas de MODULO-PY
4. Ejecuta ML de MODULO-PY
5. Consulta Kev
6. Combina señales en Risk Assessment
7. Guarda resultado
8. Responde al cliente

## Configuración

Todas las variables están documentadas en `.env.example`.

## Dependencias

- FastAPI - Web framework
- SQLAlchemy (async) + asyncpg - ORM y driver de PostgreSQL
- Alembic - Migraciones
- Pydantic - Validación
- python-jose - JWT
- passlib - Password hashing
- httpx - HTTP client

## Licencia

Apache-2.0
