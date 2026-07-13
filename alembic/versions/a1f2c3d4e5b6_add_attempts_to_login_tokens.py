"""Add attempts counter to login tokens

Revision ID: a1f2c3d4e5b6
Revises: c98779ab2cbd
Create Date: 2026-07-13 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1f2c3d4e5b6'
down_revision: Union[str, Sequence[str], None] = 'c98779ab2cbd'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        'login_tokens',
        sa.Column('attempts', sa.Integer(), server_default=sa.text('0'), nullable=False),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('login_tokens', 'attempts')
