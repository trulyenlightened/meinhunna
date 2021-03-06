"""empty message

Revision ID: 407d61c9be39
Revises: f4d4dba3f475
Create Date: 2020-05-14 13:22:15.934186

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '407d61c9be39'
down_revision = 'f4d4dba3f475'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('admin',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=256), nullable=True),
    sa.Column('password_hash', sa.String(length=256), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('admin')
    # ### end Alembic commands ###
