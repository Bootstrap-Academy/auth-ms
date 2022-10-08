"""add description and tags to users

Revision ID: 8dde6425760f
Create Date: 2022-10-08 17:06:14.127132
"""

from alembic import op

import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "8dde6425760f"
down_revision = "217346487384"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("auth_user", sa.Column("description", sa.String(length=1024), nullable=True))
    op.add_column("auth_user", sa.Column("_tags", sa.String(length=550), nullable=True))


def downgrade() -> None:
    op.drop_column("auth_user", "_tags")
    op.drop_column("auth_user", "description")
