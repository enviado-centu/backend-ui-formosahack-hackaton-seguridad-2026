"""Scan endpoints."""

import logging
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.database import get_db
from ..core.dependencies import get_current_user
from ..models.user import User
from ..schemas.scan import ScanRequest, ScanResponse, ScanListItem
from ..services.scan_service import ScanService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    request: ScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create and execute a new scan."""
    try:
        service = ScanService(db)
        result = await service.create_scan(current_user, request)
        return result
    except Exception as e:
        logger.error(f"Scan creation failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {str(e)}",
        )


@router.get("", response_model=List[ScanListItem])
async def list_scans(
    limit: int = 50,
    offset: int = 0,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List scans for the current user."""
    service = ScanService(db)
    scans = await service.list_scans(current_user, limit=limit, offset=offset)
    return scans


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific scan by ID."""
    service = ScanService(db)
    scan = await service.get_scan(current_user, scan_id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    
    return scan
