""" Handles all api routing """

from flask import Blueprint, render_template
from flask_restful import Api

from src.resources.users import User,OTPSignUp,GetMerchants,Order,NearBy,ForgotPassword
from src.resources.merchants import Merchant,OTPSignUpMerchant,Items,DeliveryBoy

from src.resources.authentication import (JWTDistributor,
                                          JWTDistributorMerchant,
                                          ValidationEmailSender,
                                          TokenValidator,
                                          FacebookLogin,
                                          GoogleLogin)

# view_blueprint = Blueprint('view_blueprint', __name__)
api_blueprint = Blueprint('api_blueprint', __name__)

api = Api(api_blueprint)


api.add_resource(JWTDistributor, '/api/v1/auth')
api.add_resource(JWTDistributorMerchant, '/api/v1/auth/merchant')

api.add_resource(FacebookLogin, '/api/v1/auth/facebook')
api.add_resource(GoogleLogin, '/api/v1/auth/google')
api.add_resource(ValidationEmailSender, '/api/v1/validate')
api.add_resource(TokenValidator, '/api/v1/validate/<token>')

api.add_resource(User, '/api/v1/users')
api.add_resource(OTPSignUp, '/api/v1/otp')
api.add_resource(GetMerchants, '/api/v1/users/getmerchant')
api.add_resource(Order, '/api/v1/users/order')
api.add_resource(NearBy, '/api/v1/users/nearby')
api.add_resource(ForgotPassword, '/api/v1/users/forgotpassword')

api.add_resource(Merchant, '/api/v1/merchants')
api.add_resource(OTPSignUpMerchant, '/api/v1/otpmerchant')
api.add_resource(Items, '/api/v1/merchants/items')
api.add_resource(DeliveryBoy, '/api/v1/merchants/boy')
