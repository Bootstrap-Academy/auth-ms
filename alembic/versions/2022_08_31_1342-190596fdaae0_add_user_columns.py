"""add user columns

Revision ID: 190596fdaae0
Create Date: 2022-08-31 13:42:55.308325
"""

from alembic import op

import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "190596fdaae0"
down_revision = "57f71c43ee3a"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("user", sa.Column("display_name", sa.String(length=64), nullable=True))
    op.add_column("user", sa.Column("email", sa.String(length=254), nullable=True))
    op.add_column("user", sa.Column("email_verification_code", sa.String(length=32), nullable=True))
    op.create_unique_constraint(None, "user", ["email"])


def downgrade() -> None:
    op.drop_column("user", "email_verification_code")
    op.drop_column("user", "email")
    op.drop_column("user", "display_name")
