"""add hulk/loic/hoic model toggles to user_settings

Add three per-user AI-model enable toggles (hulk_model_enabled,
loic_model_enabled, hoic_model_enabled) alongside the existing
bf_model_enabled / dos_model_enabled columns. Non-nullable booleans with a
server default of true so existing rows are backfilled as enabled.

Revision ID: d4e6f8a1b2c3
Revises: a3e5c7b9d1f2
Create Date: 2026-07-10 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'd4e6f8a1b2c3'
down_revision = 'a3e5c7b9d1f2'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('user_settings', schema=None) as batch_op:
        batch_op.add_column(sa.Column(
            'hulk_model_enabled', sa.Boolean(),
            nullable=False, server_default=sa.true()))
        batch_op.add_column(sa.Column(
            'loic_model_enabled', sa.Boolean(),
            nullable=False, server_default=sa.true()))
        batch_op.add_column(sa.Column(
            'hoic_model_enabled', sa.Boolean(),
            nullable=False, server_default=sa.true()))


def downgrade():
    with op.batch_alter_table('user_settings', schema=None) as batch_op:
        batch_op.drop_column('hoic_model_enabled')
        batch_op.drop_column('loic_model_enabled')
        batch_op.drop_column('hulk_model_enabled')
