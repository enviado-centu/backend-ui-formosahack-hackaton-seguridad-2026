"""Authentication service."""

import logging
from datetime import timedelta
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.security import verify_password, get_password_hash, create_access_token
from ..core.config import settings
from ..models.user import User
from ..schemas.auth import UserRegister, UserLogin, TokenResponse, UserResponse

logger = logging.getLogger(__name__)


class AuthService:
    """Service for authentication operations."""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def register(self, data: UserRegister) -> User:
        """Register a new user."""
        logger.info(f"Registering user: {data.email}")
        
        result = await self.db.execute(select(User).where(User.email == data.email))
        existing_user = result.scalar_one_or_none()
        
        if existing_user:
            logger.warning(f"User already exists: {data.email}")
            raise ValueError("User with this email already exists")
        
        user = User(
            email=data.email,
            hashed_password=get_password_hash(data.password),
        )
        
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)
        
        logger.info(f"User registered successfully: {data.email}")
        return user
    
    async def login(self, data: UserLogin) -> TokenResponse:
        """Authenticate user and return JWT token."""
        logger.info(f"Login attempt: {data.email}")
        
        result = await self.db.execute(select(User).where(User.email == data.email))
        user = result.scalar_one_or_none()
        
        if not user or not verify_password(data.password, user.hashed_password):
            logger.warning(f"Invalid credentials for: {data.email}")
            raise ValueError("Invalid email or password")
        
        if not user.is_active:
            logger.warning(f"Inactive user attempted login: {data.email}")
            raise ValueError("User account is inactive")
        
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"user_id": user.id, "email": user.email},
            expires_delta=access_token_expires,
        )
        
        logger.info(f"User logged in successfully: {data.email}")
        return TokenResponse(access_token=access_token)
    
    async def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID."""
        result = await self.db.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()
    
    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        result = await self.db.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()
