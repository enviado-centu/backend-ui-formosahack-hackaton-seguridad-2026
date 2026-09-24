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

## Instalación

```bash
cd backend

# Crear entorno virtual
python -m venv venv
source venv/bin/activate  # Linux/Mac
# o
venv\Scripts\activate  # Windows

# Instalar dependencias
pip install -r requirements.txt

# Configurar variables de entorno
cp .env.example .env
# Editar .env con tus valores
```

## Ejecución

```bash
# Iniciar servidor
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# O con más workers
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

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
├── tests/
├── requirements.txt
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

Variables de entorno en `.env`:

```bash
DATABASE_URL=sqlite+aiosqlite:///./backend.db
SECRET_KEY=your-secret-key
KEV_BASE_URL=http://localhost:8009
KEV_TIMEOUT=30
```

## Dependencias

- FastAPI - Web framework
- SQLAlchemy - ORM
- Pydantic - Validación
- python-jose - JWT
- passlib - Password hashing
- httpx - HTTP client

## Tests

```bash
pytest tests/ -v
```

## Licencia

Apache-2.0
