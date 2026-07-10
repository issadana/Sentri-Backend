"""replace blacklist bf_score/dos_score with model score fields

Bring blacklist_entries to parity with firewall_logs: drop the two legacy
per-model score columns (bf_score, dos_score) and add the firewall-log score
contract — selected_model, selected_score and the all_model_scores JSON object
(keyed by the 5 model ids). All three are nullable (manual blocks have no
scores).

Revision ID: e5f7a9b2c4d6
Revises: d4e6f8a1b2c3
Create Date: 2026-07-10 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'e5f7a9b2c4d6'
down_revision = 'd4e6f8a1b2c3'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('blacklist_entries', schema=None) as batch_op:
        batch_op.add_column(sa.Column('selected_model', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('selected_score', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('all_model_scores', postgresql.JSONB(astext_type=sa.Text()), nullable=True))
        batch_op.drop_column('bf_score')
        batch_op.drop_column('dos_score')


def downgrade():
    with op.batch_alter_table('blacklist_entries', schema=None) as batch_op:
        batch_op.add_column(sa.Column('dos_score', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('bf_score', sa.Float(), nullable=True))
        batch_op.drop_column('all_model_scores')
        batch_op.drop_column('selected_score')
        batch_op.drop_column('selected_model')
