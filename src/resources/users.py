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
# from nose.tools import assert_true
import src.models as models
from math import radians, cos, sin, asin, sqrt
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
            OTP_message = "http://anysms.in/api.php?username=sanghvinfo&password=474173&sender=MHNCOS&sendto="+ phone_number + "&language=hindi&message=आपका OTP यह है " + str(r1) + "&type=3"
            response = requests.get(OTP_message)
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

            user_detail = "नाम : "+user.name+"\n"+"पता : "+user.address+"\n"+"फ़ोन नंबर : "+user.phone_number +"\n"
            b = "नाम : "+boy.name+"\n"+"फ़ोन नंबर : "+boy.phone_number+"\n"
            m = "नाम : "+merchant.name+"\n"+"फ़ोन नंबर : "+merchant.phone_number+"\n"
            msg = []
            for i in range(len(me_response['items'])):
                msg.append("("+str(i+1)+") "+str(me_response['items'][i])+" "+str(me_response['quantity'][i])+"\n")

            stng = ""
            for ele in msg:
                stng += ele


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
            merchant_message = "http://anysms.in/api.php?username=sanghvinfo&password=474173&sender=MHNCOS&sendto="+ merchant.phone_number + "&language=hindi&message="+"ग्राहक का नाम और पता"+"\n"+user_detail+"\n"+"ग्राहक ने आर्डर किया है"+"\n"+ stng +"\n"+"डिलिवरी बॉय"+"\n"+b+"&type=3"
            boy_message = "http://anysms.in/api.php?username=sanghvinfo&password=474173&sender=MHNCOS&sendto="+ boy.phone_number + "&language=hindi&message=""ग्राहक का नाम और पता"+"\n"+user_detail+"\n"+"ग्राहक ने आर्डर किया है"+"\n"+ stng +"\n"+"merchant"+"\n"+m+"&type=3"

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

class Helper():
    @staticmethod
    def get_items(a):
        try:
            items = db_session.query(models.Item).filter(models.Item.sub_category_id == None).all()
            item_list = []

            for i, item in enumerate(items):
                sub_items = db_session.query(models.Item).filter(models.Item.sub_category_id==item.id).all()
                item_list.insert(i,{
                    "item_id": item.id,
                    "item_name": item.item_name,
                    "item_unit": item.item_unit,
                    "sub_items": []
                })
                if sub_items != 0:
                    for sub_item in sub_items:
                        item_list[i]["sub_items"].append({
                            "item_id": sub_item.id,
                            "item_name": sub_item.item_name,
                            "item_unit": sub_item.item_unit
                        })
            return item_list
        except Exception as e:
            print(e)
            return {"message": "exception at get item"}

    @staticmethod
    def distance(lat1, lat2, lon1, lon2):
        # The math module contains a function named
        # radians which converts from degrees to radians.
        # Haversine formula
        dlon = radians(lon2) - radians(lon1)
        dlat = radians(lat2) - radians(lat1)
        a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlon / 2)**2
        c = 2 * asin(sqrt(a))
        # Radius of earth in kilometers. Use 3956 for miles
        r = 6371
        # calculate the result
        return(c * r)

helper_obj = Helper()

class NearBy(flask_restful.Resource):
    @staticmethod
    @flask_jwt_extended.jwt_required
    def post():
        try:
            me_response = json.loads(request.data.decode('utf-8'))
            merchants = db_session.query(models.Merchant).all()
            each_item = helper_obj.get_items(a="b")
            result = []

            if me_response['latitude'] == None and me_response['longitude'] == None:
                for merchant in merchants:
                    result.append({
                        "merchant": {
                            "merchant_id": merchant.id,
                            "name": merchant.name,
                            "phone_number": merchant.phone_number,
                            "latitude": merchant.latitude,
                            "longitude": merchant.longitude
                            },
                        "items": each_item,
                        "diff": None
                    })
            else:
                for merchant in merchants:
                    lat1 = float(me_response['latitude'])
                    lat2 = float(merchant.latitude)
                    lon1 = float(me_response['longitude'])
                    lon2 = float(merchant.longitude)
                    difference = helper_obj.distance(lat1, lat2, lon1, lon2)

                    result.append({
                        "diff": difference,
                        "merchant_array": {
                            "merchant_id": merchant.id,
                            "name": merchant.name,
                            "phone_number": merchant.phone_number,
                            "latitude": merchant.latitude,
                            "longitude": merchant.longitude
                            },
                        "items": each_item
                    })

                result.sort(key=lambda item: item.get("diff"))

        except Exception as e:
            print(e)
            return {"message": "failed to get merchant"}

        return result
