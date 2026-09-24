"""Columna summary en scans (diagnóstico armado por risk_service).

Revision ID: 0002_resumen_escaneo
Revises: 0001_inicial
Create Date: 2026-09-24
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002_resumen_escaneo"
down_revision: Union[str, Sequence[str], None] = "0001_inicial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("summary", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "summary")
