"""drop unknown_events table

Removes the unknown_events table. It was write-only (populated by the
firewall-log ingestion path) with no reader; the review/training feature
that would have consumed it was never built.

Revision ID: d2e3f4a5b6c7
Revises: c1d2e3f4a5b6
Create Date: 2026-07-05

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd2e3f4a5b6c7'
down_revision = 'c1d2e3f4a5b6'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_table('unknown_events')


def downgrade():
    op.create_table(
        'unknown_events',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('src_ip', sa.String(length=45), nullable=True),
        sa.Column('src_port', sa.Integer(), nullable=True),
        sa.Column('dst_port', sa.Integer(), nullable=True),
        sa.Column('protocol', sa.Integer(), nullable=True),
        sa.Column('size_bytes', sa.Integer(), nullable=True),
        sa.Column('flow_iat_mean', sa.Float(), nullable=True),
        sa.Column('tot_fwd_pkts', sa.Integer(), nullable=True),
        sa.Column('pkt_size_avg', sa.Float(), nullable=True),
        sa.Column('flow_duration', sa.Float(), nullable=True),
        sa.Column('bf_score', sa.Float(), nullable=True),
        sa.Column('dos_score', sa.Float(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('label', sa.String(length=20), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
