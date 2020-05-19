"""
Database schema definition
"""

from enum import Enum

import sqlalchemy
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class Delivery_Status(Enum):
    Pending = 'Pending'
    Cancelled = 'Cancelled'
    Shipped = 'Shipped'
    Delivered = 'Delivered'

class User(Base):
    """ Database table for users """
    __tablename__ = 'users'
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    name = sqlalchemy.Column(sqlalchemy.String(256), nullable=True)
    email = sqlalchemy.Column(sqlalchemy.String(256), nullable=True)
    phone_number = sqlalchemy.Column(sqlalchemy.String(256), nullable=True)
    address = sqlalchemy.Column(sqlalchemy.String(256), nullable=True)
    password_hash = sqlalchemy.Column(sqlalchemy.String(256), nullable=True)
    created_at = sqlalchemy.Column(sqlalchemy.DateTime(), nullable=True)

class Delivery_Boy(Base):
    """ Database table for Delivery_Boy """
    __tablename__ = 'delivery_boys'
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    name = sqlalchemy.Column(sqlalchemy.String(256), nullable=True)
    phone_number = sqlalchemy.Column(sqlalchemy.String(256), nullable=True)
    email = sqlalchemy.Column(sqlalchemy.String(256), nullable=True)
    created_at = sqlalchemy.Column(sqlalchemy.DateTime(), nullable=True)

class Merchant(Base):
    """ Database table for Merchant """
    __tablename__ = 'merchants'
    id = sqlalchemy.Column(sqlalchemy.BigInteger, primary_key=True)
    name = sqlalchemy.Column(sqlalchemy.String(256), nullable=True)
    phone_number = sqlalchemy.Column(sqlalchemy.String(256), nullable=True)
    email = sqlalchemy.Column(sqlalchemy.String(256), nullable=True)
    latitude = sqlalchemy.Column(sqlalchemy.String(256), nullable=True)
    longitude = sqlalchemy.Column(sqlalchemy.String(256), nullable=True)
    created_at = sqlalchemy.Column(sqlalchemy.DateTime(), nullable=True)
    boys_id = sqlalchemy.Column(sqlalchemy.types.ARRAY(sqlalchemy.Integer))

class Order(Base):
    """ Database table for Order"""
    __tablename__ = 'orders'
    id = sqlalchemy.Column(sqlalchemy.BigInteger, primary_key=True)
    user_id = sqlalchemy.Column(sqlalchemy.ForeignKey(User.id))
    merchant_id = sqlalchemy.Column(sqlalchemy.ForeignKey(Merchant.id))
    boys_id = sqlalchemy.Column(sqlalchemy.ForeignKey(Delivery_Boy.id))
    items = sqlalchemy.Column(sqlalchemy.types.ARRAY(sqlalchemy.String))
    quantity = sqlalchemy.Column(sqlalchemy.types.ARRAY(sqlalchemy.String))
    order_address = sqlalchemy.Column(sqlalchemy.String(256), nullable=True)
    status = sqlalchemy.Column(sqlalchemy.types.Enum(Delivery_Status))
    discription = sqlalchemy.Column(sqlalchemy.String(256), nullable=True)
    created_at = sqlalchemy.Column(sqlalchemy.DateTime(), nullable=True)

class Item(Base):
    """ Database table for Item"""
    __tablename__ = 'items'
    id = sqlalchemy.Column(sqlalchemy.BigInteger, primary_key=True)
    item_name = sqlalchemy.Column(sqlalchemy.String(256), nullable=True)
    item_unit = sqlalchemy.Column(sqlalchemy.String(256), nullable=True)
    sub_category_id = sqlalchemy.Column(sqlalchemy.Integer, nullable=True)

class Admin(Base):
    """ Database table for Admin """
    __tablename__ = 'admin'
    id = sqlalchemy.Column(sqlalchemy.Integer, primary_key=True)
    name = sqlalchemy.Column(sqlalchemy.String(256), nullable=True)
    password_hash = sqlalchemy.Column(sqlalchemy.String(256), nullable=True)
    created_at = sqlalchemy.Column(sqlalchemy.DateTime(), nullable=True)
