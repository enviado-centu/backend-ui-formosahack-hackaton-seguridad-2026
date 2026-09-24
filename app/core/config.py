"""Backend configuration."""

import logging
import secrets
from typing import Literal, Optional

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env."""

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        # .env también tiene las variables POSTGRES_* que usa docker-compose
        extra="ignore",
    )

    APP_NAME: str = "Phishing Detection API"
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: Literal["development", "production"] = "development"
    DEBUG: bool = False

    # Obligatoria. Ej.: postgresql+asyncpg://detector:<clave>@localhost:5432/detector
    DATABASE_URL: str
    # Base separada para pytest; si no está o no responde, los tests usan SQLite en memoria
    TEST_DATABASE_URL: Optional[str] = None

    SECRET_KEY: Optional[str] = None
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24

    KEV_BASE_URL: str = "http://127.0.0.1:8009"
    KEV_MODEL: str = "kev-latest"
    # Corto a propósito: si Kev no responde, el escaneo sigue sin esperar
    KEV_TIMEOUT: int = 3
    # Carpeta del repo kev-integration; por defecto se busca al lado del backend
    KEV_INTEGRATION_PATH: Optional[str] = None

    CORS_ORIGINS: list[str] = ["http://localhost:5173"]

    MAX_PAYLOAD_SIZE: int = 10 * 1024 * 1024

    @model_validator(mode="after")
    def check_secret_key(self) -> "Settings":
        if self.SECRET_KEY:
            return self
        if self.ENVIRONMENT == "production":
            raise ValueError("SECRET_KEY no está definida. Configurala en .env antes de arrancar en producción.")
        self.SECRET_KEY = secrets.token_urlsafe(64)
        logger.warning(
            "SECRET_KEY no está definida en .env: se generó una temporal. "
            "Los tokens emitidos dejan de valer al reiniciar el backend."
        )
        return self


settings = Settings()
