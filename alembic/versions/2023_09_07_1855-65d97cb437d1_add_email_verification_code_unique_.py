"""add email_verification_code unique constraint

Revision ID: 65d97cb437d1
Create Date: 2023-09-07 18:55:08.100444
"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "65d97cb437d1"
down_revision = "f15cd9186e12"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_unique_constraint("auth_user_email_verification_code_unique", "auth_user", ["email_verification_code"])


def downgrade() -> None:
    op.drop_constraint("auth_user_email_verification_code_unique", "auth_user", type_="unique")
