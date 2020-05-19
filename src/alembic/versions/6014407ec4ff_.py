"""empty message

Revision ID: 6014407ec4ff
Revises: 5eca9a7a2eac
Create Date: 2020-05-19 20:11:10.265750

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6014407ec4ff'
down_revision = '5eca9a7a2eac'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('orders', sa.Column('description', sa.ARRAY(sa.String()), nullable=True))
    op.drop_column('orders', 'discription')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('orders', sa.Column('discription', sa.VARCHAR(length=256), autoincrement=False, nullable=True))
    op.drop_column('orders', 'description')
    # ### end Alembic commands ###
