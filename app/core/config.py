"""Backend configuration."""

import os
from typing import Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    APP_NAME: str = "Phishing Detection API"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    
    DATABASE_URL: str = "sqlite+aiosqlite:///./backend.db"
    
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24
    
    KEV_BASE_URL: str = "http://localhost:8009"
    KEV_MODEL: str = "kev-latest"
    KEV_TIMEOUT: int = 30
    
    CORS_ORIGINS: list[str] = ["*"]
    
    MAX_PAYLOAD_SIZE: int = 10 * 1024 * 1024
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
