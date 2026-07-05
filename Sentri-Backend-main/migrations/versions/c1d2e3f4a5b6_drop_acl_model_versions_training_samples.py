"""drop acl_entries, model_versions and training_samples tables

Removes the ACL allow-list, the ML model-version registry and the
training-samples tables. The unknown_events table is kept (it is still
populated by the firewall-log ingestion path).

Revision ID: c1d2e3f4a5b6
Revises: b7f2c9d1a3e4
Create Date: 2026-07-05

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c1d2e3f4a5b6'
down_revision = 'b7f2c9d1a3e4'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_table('training_samples')
    op.drop_table('model_versions')
    op.drop_table('acl_entries')


def downgrade():
    op.create_table(
        'acl_entries',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('ip', sa.String(length=45), nullable=False),
        sa.Column('notes', sa.String(length=255), nullable=True),
        sa.Column('added_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'ip', name='unique_acl_user_ip'),
    )
    op.create_table(
        'model_versions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('filename', sa.String(length=255), nullable=False),
        sa.Column('accuracy', sa.Float(), nullable=True),
        sa.Column('samples', sa.Integer(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('deployed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'training_samples',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('event_id', sa.Integer(), nullable=True),
        sa.Column('label', sa.String(length=20), nullable=False),
        sa.Column('protocol', sa.Integer(), nullable=True),
        sa.Column('flow_iat_mean', sa.Float(), nullable=True),
        sa.Column('tot_fwd_pkts', sa.Integer(), nullable=True),
        sa.Column('pkt_size_avg', sa.Float(), nullable=True),
        sa.Column('flow_duration', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['event_id'], ['unknown_events.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('event_id'),
    )
