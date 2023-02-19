"""add user infos for invoices

Revision ID: f15cd9186e12
Create Date: 2023-02-19 23:52:11.843624
"""

from alembic import op

import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "f15cd9186e12"
down_revision = "8e1474316c94"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("auth_user", sa.Column("business", sa.Boolean(), nullable=True))
    op.add_column("auth_user", sa.Column("first_name", sa.String(length=128), nullable=True))
    op.add_column("auth_user", sa.Column("last_name", sa.String(length=128), nullable=True))
    op.add_column("auth_user", sa.Column("street", sa.String(length=256), nullable=True))
    op.add_column("auth_user", sa.Column("zip_code", sa.String(length=16), nullable=True))
    op.add_column("auth_user", sa.Column("city", sa.String(length=64), nullable=True))
    op.add_column("auth_user", sa.Column("country", sa.String(length=64), nullable=True))
    op.add_column("auth_user", sa.Column("vat_id", sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column("auth_user", "vat_id")
    op.drop_column("auth_user", "country")
    op.drop_column("auth_user", "city")
    op.drop_column("auth_user", "zip_code")
    op.drop_column("auth_user", "street")
    op.drop_column("auth_user", "last_name")
    op.drop_column("auth_user", "first_name")
    op.drop_column("auth_user", "business")
