"""add param_location to findings

Revision ID: 7f2a9c1d4b30
Revises: 62833b6a7c78
Create Date: 2026-05-28 18:00:00.000000
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '7f2a9c1d4b30'
down_revision: str | None = '62833b6a7c78'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('findings', sa.Column('param_location', sa.String(length=16), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('findings') as batch_op:
        batch_op.drop_column('param_location')
