"""add last_name_change column to users

Revision ID: 8e1474316c94
Create Date: 2022-11-04 18:28:59.129856
"""

from alembic import op

import sqlalchemy as sa

from api import models
from api.database.database import UTCDateTime
from api.utils.utc import utcfromtimestamp


# revision identifiers, used by Alembic.
revision = "8e1474316c94"
down_revision = "8ab8a73f19be"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("auth_user", sa.Column("last_name_change", UTCDateTime(), nullable=True))

    op.execute(sa.update(models.User).values(last_name_change=utcfromtimestamp(0)))


def downgrade() -> None:
    op.drop_column("auth_user", "last_name_change")
