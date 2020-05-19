"""empty message

Revision ID: 5eca9a7a2eac
Revises: 1a8545114b99
Create Date: 2020-05-19 10:58:19.955365

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5eca9a7a2eac'
down_revision = '1a8545114b99'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('orders', sa.Column('discription', sa.String(length=256), nullable=True))
    op.drop_column('orders', 'delivery_id')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('orders', sa.Column('delivery_id', sa.BIGINT(), autoincrement=False, nullable=True))
    op.drop_column('orders', 'discription')
    # ### end Alembic commands ###