"""
Database configuration and initialization
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

from src.models import Base


db_user = "Merchant" #"postgres" Development server
db_password = "merchant0909" #"shaurya12"
db_name = "MerchantDB" #"MerchantDB"
db_host = "database-2.crfy9ltvtgyi.us-east-2.rds.amazonaws.com" #"0.0.0.0"
db_port = 5432 #5432

uri_string = f'postgres://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}'
print(uri_string)
engine = create_engine(uri_string)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
Base.query = db_session.query_property()


def init_db():

    import src.models
    Base.metadata.create_all(bind=engine)
