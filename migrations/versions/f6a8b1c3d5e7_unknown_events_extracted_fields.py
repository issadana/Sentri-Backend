"""bring unknown_events to parity with firewall_logs extracted fields

Replace the legacy, never-populated flow columns (flow_iat_mean, tot_fwd_pkts,
pkt_size_avg, flow_duration) with the network-flow features that firewall_logs
actually carries (duration, fwd_pkts, bwd_pkts, fwd_rate), add dst_ip, and swap
the derived bf_score/dos_score pair for the model-output triple
(selected_model, selected_score, all_model_scores) plus threat_type. All are
nullable. Legacy column data is discarded on upgrade.

Revision ID: f6a8b1c3d5e7
Revises: e5f7a9b2c4d6
Create Date: 2026-07-10 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'f6a8b1c3d5e7'
down_revision = 'e5f7a9b2c4d6'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('unknown_events', schema=None) as batch_op:
        batch_op.add_column(sa.Column('dst_ip', sa.String(length=45), nullable=True))
        batch_op.add_column(sa.Column('duration', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('fwd_pkts', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('bwd_pkts', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('fwd_rate', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('selected_model', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('selected_score', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('all_model_scores', postgresql.JSONB(astext_type=sa.Text()), nullable=True))
        batch_op.add_column(sa.Column('threat_type', sa.String(length=50), nullable=True))
        batch_op.drop_column('flow_iat_mean')
        batch_op.drop_column('tot_fwd_pkts')
        batch_op.drop_column('pkt_size_avg')
        batch_op.drop_column('flow_duration')
        batch_op.drop_column('bf_score')
        batch_op.drop_column('dos_score')


def downgrade():
    with op.batch_alter_table('unknown_events', schema=None) as batch_op:
        batch_op.add_column(sa.Column('dos_score', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('bf_score', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('flow_duration', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('pkt_size_avg', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('tot_fwd_pkts', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('flow_iat_mean', sa.Float(), nullable=True))
        batch_op.drop_column('threat_type')
        batch_op.drop_column('all_model_scores')
        batch_op.drop_column('selected_score')
        batch_op.drop_column('selected_model')
        batch_op.drop_column('fwd_rate')
        batch_op.drop_column('bwd_pkts')
        batch_op.drop_column('fwd_pkts')
        batch_op.drop_column('duration')
        batch_op.drop_column('dst_ip')
