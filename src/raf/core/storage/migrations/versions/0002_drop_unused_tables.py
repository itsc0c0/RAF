"""drop unused product state tables

Ghost, Range and Lab keep their state in the ``kv`` table; the dedicated tables created by the
initial schema were never used.

Revision ID: 0002_drop_unused_tables
Revises: 0001_initial
Create Date: 2026-10-07 13:30:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

import raf.core.storage.types

revision: str = "0002_drop_unused_tables"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSON = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    for table in ("ghost_ops", "ghost_models", "ranges", "labs"):
        op.drop_table(table)


def downgrade() -> None:
    utc = raf.core.storage.types.UTCDateTime
    op.create_table(
        "labs",
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("template", sa.String(length=64), nullable=False),
        sa.Column("backend", sa.String(length=32), nullable=False),
        sa.Column("config", _JSON, nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("container_id", sa.String(length=128), nullable=True),
        sa.Column("created_at", utc(), nullable=False),
        sa.Column("updated_at", utc(), nullable=False),
        sa.PrimaryKeyConstraint("name", name=op.f("pk_labs")),
    )
    op.create_table(
        "ranges",
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("preset", sa.String(length=64), nullable=True),
        sa.Column("seed", sa.Integer(), nullable=False),
        sa.Column("config", _JSON, nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("sim_clock", utc(), nullable=True),
        sa.Column("worker_pid", sa.Integer(), nullable=True),
        sa.Column("stats", _JSON, nullable=False),
        sa.Column("created_at", utc(), nullable=False),
        sa.Column("updated_at", utc(), nullable=False),
        sa.PrimaryKeyConstraint("name", name=op.f("pk_ranges")),
    )
    op.create_table(
        "ghost_models",
        sa.Column("id", sa.String(length=160), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("base_snapshot_id", sa.String(length=160), nullable=False),
        sa.Column("parent", sa.String(length=160), nullable=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("created_at", utc(), nullable=False),
        sa.Column("updated_at", utc(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ghost_models")),
        sa.UniqueConstraint("name", name=op.f("uq_ghost_models_name")),
    )
    op.create_table(
        "ghost_ops",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("model_id", sa.String(length=160), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("op", sa.String(length=64), nullable=False),
        sa.Column("params", _JSON, nullable=False),
        sa.Column("summary", _JSON, nullable=False),
        sa.Column("created_at", utc(), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ghost_ops")),
        sa.UniqueConstraint("model_id", "seq", name=op.f("uq_ghost_ops_model_id_seq")),
    )
