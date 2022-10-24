"""add newsletter to users

Revision ID: 8ab8a73f19be
Create Date: 2022-10-24 12:51:10.100533
"""

from alembic import op

import sqlalchemy as sa

from api import models


# revision identifiers, used by Alembic.
revision = "8ab8a73f19be"
down_revision = "8dde6425760f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("auth_user", sa.Column("newsletter", sa.Boolean(), nullable=True))

    op.execute(sa.update(models.User).values(newsletter=False))


def downgrade() -> None:
    op.drop_column("auth_user", "newsletter")
