"""content hashes on objects and relationships

Objects and relationships keep the SHA-256 of their canonical content, written with the row, so
snapshots copy hashes instead of recomputing them. Existing rows start without one (NULL); the
first snapshot computes and stores the missing hashes.

Revision ID: 0003_content_hashes
Revises: 0002_drop_unused_tables
Create Date: 2026-10-07 16:00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_content_hashes"
down_revision: str | None = "0002_drop_unused_tables"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("objects", sa.Column("content_hash", sa.String(length=64), nullable=True))
    op.add_column("relationships", sa.Column("content_hash", sa.String(length=64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("relationships") as batch:
        batch.drop_column("content_hash")
    with op.batch_alter_table("objects") as batch:
        batch.drop_column("content_hash")
