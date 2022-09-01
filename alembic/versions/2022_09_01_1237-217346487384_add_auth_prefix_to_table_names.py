"""add auth prefix to table names

Revision ID: 217346487384
Create Date: 2022-09-01 12:37:43.395244
"""

from alembic import op

import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "217346487384"
down_revision = "190596fdaae0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in ["user", "session", "oauth_user_connection"]:
        op.rename_table(table, f"auth_{table}")


def downgrade() -> None:
    for table in ["user", "session", "oauth_user_connection"]:
        op.rename_table(f"auth_{table}", table)
