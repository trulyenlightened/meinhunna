"""
Controller for merchants API endpoints
"""
from datetime import datetime
import datetime
from argon2 import PasswordHasher
from flask import request
import flask_jwt_extended
import flask_restful
import marshmallow
import json
import random

import src.models as models
from src.database import db_session

ph = PasswordHasher(hash_len=64, salt_len=32)

class MerchantGetListSchema(marshmallow.Schema):
    phone_number = marshmallow.fields.Str()
    name = marshmallow.fields.Str()
    email = marshmallow.fields.Str()
    lat_long = marshmallow.fields.Str()
    address = marshmallow.fields.Str()
    boys_id = marshmallow.fields.Str()
    created_at = marshmallow.fields.DateTime()

merchant_get_list_schema = MerchantGetListSchema()


class Merchant(flask_restful.Resource):
    @staticmethod
    def post():
        try:
            me_response = json.loads(request.data.decode('utf-8'))
            create_merchant = models.Merchant(phone_number=me_response['phone_number'],
                                        name=me_response['name'],
                                        email=me_response['email'],
                                        address=me_response['address'],
                                        lat_long=me_response['lat_long'],
                                        boys_id=[me_response['boys_id']],
                                        password_hash=ph.hash("password"),
                                        created_at=datetime.datetime.now())

            db_session.add(create_merchant)
            db_session.flush()
        except Exception as e:
            print(e)
            return {"message": "something went wrong in creating merchant"}

        access_token = flask_jwt_extended.create_access_token(identity=create_merchant.id)
        try:
            db_session.commit()
            return {
                'access_token': access_token,
                'user': {
                    'id' : create_merchant.id,
                    'message': 'merchant successfully stored in database',
                    'Status': True
                },
            }
        except SQLAlchemyError as ex:
            print(ex)
            db_session.rollback()
            flask_restful.abort(400, message="Database error")

    @staticmethod
    @flask_jwt_extended.jwt_required
    def get():
        id = flask_jwt_extended.get_jwt_identity()
        try:
            merchant = db_session.query(models.Merchant).filter(models.Merchant.id == id).all()
            merchant_get_list_schema = MerchantGetListSchema()
            return merchant_get_list_schema.dump(merchant, many=True)
        except Exception as ex:
            print(ex)
            flask_restful.abort(400, message="error")

    @staticmethod
    @flask_jwt_extended.jwt_required
    def put():
        json_data = json.loads(request.data.decode('utf-8'))  # type: dict
        if not json_data:
            flask_restful.abort(400, message='There was no json data provided.')
        # make sure user exists
        merchant = db_session.query(models.Merchant).filter(models.Merchant.id == flask_jwt_extended.get_jwt_identity()).one()

        if 'name' in json_data.keys():
            merchant.name = json_data['name']

        if 'address' in json_data.keys():
            merchant.address = json_data['address']

        if 'password' in json_data.keys():
            password_hash = ph.hash(json_data['password'])
            merchant.password_hash = password_hash

        try:
            db_session.commit()
            return {
                'merchant': {
                    'id': merchant.id,
                    'name': merchant.name,
                    "created_at": merchant.created_at.isoformat()
                }
            }
        except Exception as ex:
            print(ex)
            db_session.rollback()
            flask_restful.abort(400, message="Database error")

    def delete(self, user_id):
        """ DELETE request """
        pass

class OTPSignUpMerchant(flask_restful.Resource):
    @staticmethod
    def post():
        try:
            me_response = json.loads(request.data.decode('utf-8'))
            phone_number = me_response['phone_number']
            r1 = random.randint(1234, 9876)
            return {
                "phone_number": phone_number,
                "OTP": r1,
                "message": "success"
            }
        except Exception as e:
            print(e)
            return {
                "message": "failed to send OTP"
            }

class Items(flask_restful.Resource):
    @staticmethod
    @flask_jwt_extended.jwt_required
    def post():
        try:
            merchant_id = flask_jwt_extended.get_jwt_identity()
            me_response = json.loads(request.data.decode('utf-8'))
            create_item = models.Item(item_name = me_response['item_name'],
                                        unit = me_response['unit'],
                                        merchant_id = merchant_id)
            db_session.add(create_item)
            db_session.flush()
        except Exception as e:
            print(e)
            return {"message": "exception on add item"}

        try:
            db_session.commit()
            return {
                "item_id": create_item.id,
                "merchant_id": create_item.merchant_id,
                "items": {
                    "item_name": create_item.item_name,
                    "unit": create_item.unit,
                    "message": "success"
                }
            }
        except Exception as e:
            print(e)
            return {"message": "failed to store item"}

    @staticmethod
    @flask_jwt_extended.jwt_required
    def get():
        try:
            id = flask_jwt_extended.get_jwt_identity()
            merchant_items = db_session.query(models.Item).filter(models.Item.merchant_id == id).all()

            item_list = []
            if len(merchant_items) != 0:
                for item in merchant_items:
                    item_list.append({
                        "merchant_id": item.merchant_id,
                        "item":{
                            "item_name": item.item_name,
                            "unit": item.unit
                        }
                    })
                return item_list
            else:
                return {"message": "No such item found"}

        except Exception as e:
            print(e)
            return {"message": "exception at get item"}

    @staticmethod
    @flask_jwt_extended.jwt_required
    def put():
        pass

    @staticmethod
    def delete(self, item_id):
        pass

class DeliveryBoy(flask_restful.Resource):
    @staticmethod
    def post():
        try:
            me_response = json.loads(request.data.decode('utf-8'))
            create_boy = models.Delivery_Boy(name = me_response['name'],
                                        phone_number = me_response['phone_number'],
                                        email = me_response['email'],
                                        created_at=datetime.datetime.now())

            db_session.add(create_boy)
            db_session.flush()

        except Exception as e:
            print(e)
            return {"message": "excepton at add boy"}

        try:
            db_session.commit()
            return {
                "boys_id": create_boy.id,
                "name": create_boy.name,
                "phone_number": create_boy.phone_number,
                "email": create_boy.email,
                "message": "success"
            }
        except Exception as e:
            print(e)
            return {"message": "failed to create boy"}

    @staticmethod
    def get():
        try:
            boys = db_session.query(models.Delivery_Boy).all()
            boys_list = []
            if len(boys) != 0:
                for boy in boys:
                    boys_list.append({
                        "boy_id": boy.id,
                        "boy":{
                            "name": boy.name,
                            "phone_number": boy.phone_number,
                            "email": boy.email
                        }
                    })
                return boys_list
            else:
                return {"message": "No such item found"}
        except Exception as e:
            print(e)
            return {"message": "failed to get boy"}

    @staticmethod
    def put(self, boy_id):
        pass

    @staticmethod
    def delete(self, boy_id):
        pass
