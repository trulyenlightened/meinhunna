"""
Controller for user API endpoints
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
import requests
from nose.tools import assert_true
import src.models as models
from src.database import db_session

ph = PasswordHasher(hash_len=64, salt_len=32)

class UserGetListSchema(marshmallow.Schema):

    phone_number = marshmallow.fields.Str()
    name = marshmallow.fields.Str()
    address = marshmallow.fields.Str()
    created_at = marshmallow.fields.DateTime()

user_get_list_schema = UserGetListSchema()


class User(flask_restful.Resource):
    @staticmethod
    def post():
        try:
            me_response = json.loads(request.data.decode('utf-8'))
            create_user = models.User(phone_number=me_response['phone_number'],
                                        name=me_response['name'],
                                        email=me_response['email'],
                                        address=me_response['address'],
                                        password_hash=ph.hash("password"),
                                        created_at=datetime.datetime.now())

            db_session.add(create_user)
            db_session.flush()
        except Exception as e:
            print(e)
            return {"message": "something went wrong in creating user"}

        access_token = flask_jwt_extended.create_access_token(identity=create_user.id)
        try:
            db_session.commit()
            return {
                'access_token': access_token,
                'user': {
                    'id' : create_user.id,
                    'message': 'user successfully stored in database',
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
            user = db_session.query(models.User).filter(models.User.id == id).all()
            user_get_list_schema = UserGetListSchema()
            return user_get_list_schema.dump(user, many=True)
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
        user = db_session.query(models.User).filter(models.User.id == flask_jwt_extended.get_jwt_identity()).one()

        if 'name' in json_data.keys():
            user.name = json_data['name']

        if 'address' in json_data.keys():
            user.address = json_data['address']

        if 'password' in json_data.keys():
            password_hash = ph.hash(json_data['password'])
            user.password_hash = password_hash

        try:
            db_session.commit()
            return {
                'user': {
                    'id': user.id,
                    'name': user.name,
                    "created_at": user.created_at.isoformat()
                }
            }
        except Exception as ex:
            print(ex)
            db_session.rollback()
            flask_restful.abort(400, message="Database error")

    def delete(self, user_id):
        """ DELETE request """
        pass

class OTPSignUp(flask_restful.Resource):
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

class GetMerchants(flask_restful.Resource):
    @staticmethod
    @flask_jwt_extended.jwt_required
    def get():
        id = flask_jwt_extended.get_jwt_identity()
        try:
            merchants = db_session.query(models.Merchant).all()
            merchants_list = []
            if len(merchants) != 0:
                for merchant in merchants:
                    boy = db_session.query(models.Delivery_Boy).filter(models.Delivery_Boy.id == merchant.boys_id[0]).first()
                    # if boy is not None:
                        # pass
                    merchants_list.append({
                        "merchant_id": merchant.id,
                        "merchant":{
                            "name": merchant.name,
                            "phone_number": merchant.phone_number,
                            "email": merchant.email,
                            "boys": {
                                "id": boy.id,
                                "name": boy.name,
                                "email": boy.email,
                                "phone_number": boy.phone_number
                            }
                        }
                    })
                return merchants_list
            else:
                return {"message": "No such merchants found"}

        except Exception as ex:
            print(ex)
            flask_restful.abort(400, message="Get Merchants error")

class Order(flask_restful.Resource):
    @staticmethod
    @flask_jwt_extended.jwt_required
    def post():
        try:
            me_response = json.loads(request.data.decode('utf-8'))

            merchant = db_session.query(models.Merchant).filter(models.Merchant.id == me_response['merchant_id']).first()
            user = db_session.query(models.User).filter(models.User.id == flask_jwt_extended.get_jwt_identity()).first()
            boy = db_session.query(models.Delivery_Boy).filter(models.Delivery_Boy.id == merchant.boys_id[0]).first()

            create_order = models.Order(user_id=flask_jwt_extended.get_jwt_identity(),
                                        merchant_id=me_response['merchant_id'],
                                        boys_id=merchant.boys_id[0],
                                        items=me_response['items'],
                                        quantity=me_response['quantity'],
                                        delivery_id=random.randint(123456, 987654),
                                        order_address=me_response['order_address'],
                                        status=models.Delivery_Status.Pending,
                                        created_at=datetime.datetime.now())

            db_session.add(create_order)
            db_session.flush()
        except Exception as e:
            print(e)
            return {"message": "something went wrong in creating user"}

        try:
            db_session.commit()

        except SQLAlchemyError as ex:
            print(ex)
            db_session.rollback()
            flask_restful.abort(400, message="Database error")

        try:
            user_message = "http://anysms.in/api.php?username=sanghvinfo&password=474173&sender=MHNCOS&sendto="+ user.phone_number + "&language=hindi&message=" + "मैं हूँ ना की टीम की तरफ से आपके आर्डर के लिए हार्दिक धन्यवाद् आपका आर्डर अगले 90 मिनट में आप तक पहुँच जायेगा&type=3"
            merchant_message = "http://anysms.in/api.php?username=sanghvinfo&password=474173&sender=MHNCOS&sendto="+ merchant.phone_number + "&language=hindi&message=" + "मैं हूँ ना की टीम की तरफ से आपके आर्डर के लिए हार्दिक धन्यवाद् आपका आर्डर अगले 90 मिनट में आप तक पहुँच जायेगा&type=3"
            boy_message = "http://anysms.in/api.php?username=sanghvinfo&password=474173&sender=MHNCOS&sendto="+ boy.phone_number + "&language=hindi&message=" + "मैं हूँ ना की टीम की तरफ से आपके आर्डर के लिए हार्दिक धन्यवाद् आपका आर्डर अगले 90 मिनट में आप तक पहुँच जायेगा&type=3"

            response1 = requests.get(user_message)
            response2 = requests.get(merchant_message)
            response3 = requests.get(boy_message)
            return {
                'id' : create_order.id,
                'Order Status': 'Pending'
            }
        except Exception as e:
            print(e)
            return {"message": "SMS sending failed"}

class NearBy(flask_restful.Resource):
    @staticmethod
    @flask_jwt_extended.jwt_required
    def post():
        try:
            result = []
            me_response = json.loads(request.data.decode('utf-8'))
            diff = []
            mer_list = []
            merchants = db_session.query(models.Merchant).all()

            each_item = []
            items = db_session.query(models.Item).all()
            for item in items:
                each_item.append({
                    'item_id': item.id,
                    'item_name': item.item_name,
                    'item_unit': item.item_unit
                })

            for merchant in merchants:
                print(float(merchant.latitude))
                print(float(me_response['latitude']))
                diff.append(abs(float(merchant.latitude)-float(me_response['latitude'])))
                mer_list.append({
                    "diff": abs(float(merchant.latitude)-float(me_response['latitude'])),
                    "merchant_array":
                        {'merchant_id':merchant.id,
                        'name':merchant.name,
                        "phone_number":merchant.phone_number,
                        "latitude":merchant.latitude,
                        "longitude":merchant.longitude
                        }
                })


            diff.sort()

            for i in range(len(diff)):
                for mer in mer_list:
                    if diff[i] == mer['diff']:
                        result.append({
                            "merchant": mer['merchant_array'],
                            "items": each_item
                        })

        except Exception as e:
            print(e)
            return {"message": "failed to get merchant"}

        return result
