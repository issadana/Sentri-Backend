"""add flow features to firewall_logs

Add the destination IP and network-flow feature columns (dst_ip, duration,
fwd_pkts, bwd_pkts, fwd_rate) to firewall_logs. All are nullable so existing
rows are unaffected.

Revision ID: a3e5c7b9d1f2
Revises: c1d2e3f4a5b6
Create Date: 2026-07-06 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'a3e5c7b9d1f2'
down_revision = 'c1d2e3f4a5b6'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('firewall_logs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('dst_ip', sa.String(length=45), nullable=True))
        batch_op.add_column(sa.Column('duration', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('fwd_pkts', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('bwd_pkts', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('fwd_rate', sa.Float(), nullable=True))


def downgrade():
    with op.batch_alter_table('firewall_logs', schema=None) as batch_op:
        batch_op.drop_column('fwd_rate')
        batch_op.drop_column('bwd_pkts')
        batch_op.drop_column('fwd_pkts')
        batch_op.drop_column('duration')
        batch_op.drop_column('dst_ip')
