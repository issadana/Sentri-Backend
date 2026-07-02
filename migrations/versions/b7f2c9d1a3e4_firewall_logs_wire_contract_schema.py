"""firewall_logs wire-contract schema

Rebuild the firewall_logs table so its columns map 1:1 to the firewall-log
WebSocket wire contract emitted by the Flutter client (action / selected_model /
selected_score / size_bytes / created_at / all_model_scores JSONB), replacing the
earlier ML-feature layout (action_taken / prob_* / packet_size / timestamp).

Revision ID: b7f2c9d1a3e4
Revises: fe31bd54168d
Create Date: 2026-07-02 21:40:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'b7f2c9d1a3e4'
down_revision = 'fe31bd54168d'
branch_labels = None
depends_on = None


def upgrade():
    # 1. Add the contract columns (nullable/defaulted so we can backfill first).
    op.add_column('firewall_logs', sa.Column('size_bytes', sa.Integer(), nullable=True))
    op.add_column('firewall_logs', sa.Column('selected_model', sa.String(length=100), nullable=True))
    op.add_column('firewall_logs', sa.Column('selected_score', sa.Float(), nullable=True))
    op.add_column('firewall_logs', sa.Column('threat_type', sa.String(length=50), nullable=True))
    op.add_column('firewall_logs', sa.Column('action', sa.String(length=10), nullable=True))
    op.add_column('firewall_logs', sa.Column('created_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        'firewall_logs',
        sa.Column('received_at', sa.DateTime(timezone=True),
                  server_default=sa.text('now()'), nullable=False),
    )

    # 2. Backfill the contract columns from the legacy ML-feature columns so any
    #    existing rows survive the switch.
    op.execute("""
        UPDATE firewall_logs SET
            action = COALESCE(action_taken, 'allowed'),
            size_bytes = CAST(packet_size AS INTEGER),
            selected_score = max_attack_prob,
            threat_type = top_threat_type,
            created_at = COALESCE(timestamp, now())
    """)

    op.alter_column('firewall_logs', 'action', existing_type=sa.String(length=10), nullable=False)
    op.alter_column('firewall_logs', 'created_at',
                    existing_type=sa.DateTime(timezone=True), nullable=False)

    # 3. Retype the surviving columns to the contract types.
    op.alter_column('firewall_logs', 'protocol',
                    existing_type=sa.Integer(), type_=sa.SmallInteger(),
                    existing_nullable=True)
    op.alter_column('firewall_logs', 'id',
                    existing_type=sa.Integer(), type_=sa.BigInteger(),
                    existing_nullable=False, autoincrement=True)
    op.alter_column('firewall_logs', 'is_system',
                    existing_type=sa.Boolean(), nullable=False,
                    server_default=sa.text('false'))

    # all_model_scores was TEXT holding arbitrary (often non-JSON) strings; drop
    # and re-add as JSONB rather than risk a failing cast on legacy dev data.
    op.drop_column('firewall_logs', 'all_model_scores')
    op.add_column('firewall_logs', sa.Column('all_model_scores', postgresql.JSONB(), nullable=True))

    # 4. Drop the legacy ML-feature columns that are no longer part of the contract.
    for col in ['timestamp', 'dst_ip', 'packet_size', 'duration', 'iat_mean',
                'iat_std', 'fwd_pkts', 'bwd_pkts', 'fwd_max', 'fwd_rate',
                'fwd_mean', 'idle_mean', 'pkt_size_avg', 'prob_brute',
                'prob_dos', 'prob_adv_dos', 'prob_loic', 'prob_hoic',
                'top_threat_type', 'max_attack_prob', 'action_taken']:
        op.drop_column('firewall_logs', col)

    # 5. Query indexes used by the REST read path.
    op.create_index('ix_fwlogs_user_created', 'firewall_logs',
                    ['user_id', sa.text('created_at DESC')])
    op.create_index('ix_fwlogs_user_action', 'firewall_logs',
                    ['user_id', 'action'])


def downgrade():
    op.drop_index('ix_fwlogs_user_action', table_name='firewall_logs')
    op.drop_index('ix_fwlogs_user_created', table_name='firewall_logs')

    # Re-add the legacy ML-feature columns.
    op.add_column('firewall_logs', sa.Column('timestamp', sa.DateTime(), nullable=True))
    op.add_column('firewall_logs', sa.Column('dst_ip', sa.String(length=45), nullable=True))
    op.add_column('firewall_logs', sa.Column('packet_size', sa.Float(), nullable=True))
    op.add_column('firewall_logs', sa.Column('duration', sa.Float(), nullable=True))
    op.add_column('firewall_logs', sa.Column('iat_mean', sa.Float(), nullable=True))
    op.add_column('firewall_logs', sa.Column('iat_std', sa.Float(), nullable=True))
    op.add_column('firewall_logs', sa.Column('fwd_pkts', sa.Float(), nullable=True))
    op.add_column('firewall_logs', sa.Column('bwd_pkts', sa.Float(), nullable=True))
    op.add_column('firewall_logs', sa.Column('fwd_max', sa.Float(), nullable=True))
    op.add_column('firewall_logs', sa.Column('fwd_rate', sa.Float(), nullable=True))
    op.add_column('firewall_logs', sa.Column('fwd_mean', sa.Float(), nullable=True))
    op.add_column('firewall_logs', sa.Column('idle_mean', sa.Float(), nullable=True))
    op.add_column('firewall_logs', sa.Column('pkt_size_avg', sa.Float(), nullable=True))
    op.add_column('firewall_logs', sa.Column('prob_brute', sa.Float(), nullable=True))
    op.add_column('firewall_logs', sa.Column('prob_dos', sa.Float(), nullable=True))
    op.add_column('firewall_logs', sa.Column('prob_adv_dos', sa.Float(), nullable=True))
    op.add_column('firewall_logs', sa.Column('prob_loic', sa.Float(), nullable=True))
    op.add_column('firewall_logs', sa.Column('prob_hoic', sa.Float(), nullable=True))
    op.add_column('firewall_logs', sa.Column('top_threat_type', sa.String(length=20), nullable=True))
    op.add_column('firewall_logs', sa.Column('max_attack_prob', sa.Float(), nullable=True))
    op.add_column('firewall_logs', sa.Column('action_taken', sa.String(length=15), nullable=True))

    op.execute("""
        UPDATE firewall_logs SET
            action_taken = action,
            packet_size = size_bytes,
            max_attack_prob = selected_score,
            top_threat_type = threat_type,
            timestamp = created_at
    """)
    op.alter_column('firewall_logs', 'action_taken',
                    existing_type=sa.String(length=15), nullable=False)

    op.drop_column('firewall_logs', 'all_model_scores')
    op.add_column('firewall_logs', sa.Column('all_model_scores', sa.Text(), nullable=True))

    op.alter_column('firewall_logs', 'id',
                    existing_type=sa.BigInteger(), type_=sa.Integer(),
                    existing_nullable=False, autoincrement=True)
    op.alter_column('firewall_logs', 'protocol',
                    existing_type=sa.SmallInteger(), type_=sa.Integer(),
                    existing_nullable=True)

    op.drop_column('firewall_logs', 'received_at')
    op.drop_column('firewall_logs', 'created_at')
    op.drop_column('firewall_logs', 'action')
    op.drop_column('firewall_logs', 'threat_type')
    op.drop_column('firewall_logs', 'selected_score')
    op.drop_column('firewall_logs', 'selected_model')
    op.drop_column('firewall_logs', 'size_bytes')
