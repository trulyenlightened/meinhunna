from flask import Blueprint, render_template, redirect, url_for, request,flash
from src.database import db_session
import src.models as models
from datetime import datetime
import datetime
from argon2 import PasswordHasher
import jsonify
from functools import wraps

import jwt
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token, set_access_cookies, jwt_refresh_token_required,
    get_jwt_identity, create_refresh_token, set_refresh_cookies, unset_jwt_cookies, verify_jwt_in_request
)


ph = PasswordHasher(hash_len=64, salt_len=32)

view_blueprint = Blueprint('view_blueprint', __name__)

def jwt_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
        except:
            return redirect(url_for('view_blueprint.admin'))
        return fn(*args, **kwargs)
    return wrapper

@view_blueprint.route('/dashboard/')
def index():
    return render_template('index.html')

@view_blueprint.route('/add_item/')
def add_item():
    sub_items = db_session.query(models.Item).filter(models.Item.sub_category_id == None).all()
    return render_template('add_item.html', sub_items=sub_items)

@view_blueprint.route('/add_item_hide/', methods=['POST'])
def add_item_hide():
    try:
        item_name = request.form['item_name']
        item_unit = request.form['item_unit']
        sub_category_id = request.form['sub_category']
        if sub_category_id == "None":
            sub_category_id = None
        create_item= models.Item(item_name=item_name,
                                    item_unit=item_unit,
                                    sub_category_id=sub_category_id)
        db_session.add(create_item)
        db_session.flush()

    except Exception as e:
        print(e)
        return {"message": "something went wrong in creating user"}

    try:
        db_session.commit()
        flash('Item successfully added')
        return redirect(url_for('view_blueprint.add_item'))
    except Exception as e:
        print(e)
        return {"message": "something went wrong in creating user"}

@view_blueprint.route('/update_user_uri/<user_id>', methods=['GET', 'POST'])
def update_user_uri(user_id):
    users = db_session.query(models.User).filter(models.User.id == user_id).all()
    return render_template('update_user.html', title="Update User", users=users)

@view_blueprint.route('/update_merchant_uri/<merchant_id>', methods=['GET', 'POST'])
def update_merchant_uri(merchant_id):
    merchants = db_session.query(models.Merchant).filter(models.Merchant.id == merchant_id).all()
    boys = db_session.query(models.Delivery_Boy).all()
    return render_template('update_merchant.html', title="Update Merchant", merchants=merchants, boys=boys)

@view_blueprint.route('/update_boy_uri/<boy_id>', methods=['GET', 'POST'])
def update_boy_uri(boy_id):
    boys = db_session.query(models.Delivery_Boy).filter(models.Delivery_Boy.id == boy_id).all()
    return render_template('update_delivery_boy.html', title="Update boys", boys=boys)

@view_blueprint.route('/admin/')
def admin():
    return render_template('admin_login.html', title="Admin Login")

@view_blueprint.route('/admin_logout/', methods=['POST'])
def logout():
    res = redirect(url_for('view_blueprint.index'))
    unset_jwt_cookies(res)
    return res


@view_blueprint.route('/admin_login/', methods=['POST'])
def admin_login():
    name = request.form['name']
    password = request.form['password']

    admin = db_session.query(models.Admin).filter(models.Admin.name == name).one_or_none()
    if admin is None:
        return {"message": "Admin Not Available"}

    try:
        ph.verify(admin.password_hash, password)

        access_token = create_access_token(identity=name)

        resp = redirect(url_for('view_blueprint.users'))
        # set_access_cookies(resp, access_token)
    except Exception as e:
        print(e)
        return {"message": "Admin Verification Failed"}

    return resp

@view_blueprint.route('/users/')
def users():
    users = db_session.query(models.User).all()
    total_user = len(users)
    return render_template('users.html', users=users, total_user=total_user, title="Users")

@view_blueprint.route('/add_user/', methods=['POST'])
def add_user():
    try:
        name = request.form['name']
        email = request.form['email']
        address = request.form['address']
        phone_number = request.form['phone_number']
        password = request.form['password']

        create_user = models.User(phone_number=phone_number,
                                    name=name,
                                    email=email,
                                    address=address,
                                    password_hash=ph.hash(password),
                                    created_at=datetime.datetime.now())
        db_session.add(create_user)
        db_session.flush()

    except Exception as e:
        print(e)
        return {"message": "something went wrong in creating user"}

    try:
        db_session.commit()

    except Exception as e:
        print(e)
        return {"message": "something went wrong in creating user"}

    return redirect(url_for('view_blueprint.users'))

@view_blueprint.route('/update_user/', methods=['POST'])
def update_user():
    try:
        name = request.form['name']
        new_name = request.form['new_name']
        email = request.form['email']
        new_email = request.form['new_email']
        address = request.form['address']
        new_address = request.form['new_address']
        phone_number = request.form['phone_number']
        new_phone_number = request.form['new_phone_number']
        user = db_session.query(models.User).filter(models.User.name == name).one()

        user.name = new_name
        user.email = new_email
        user.address = new_address
        user.phone_number = new_phone_number


    except Exception as e:
        print(e)
        return {"message": "user Update Adding failed"}
    try:
        db_session.commit()

    except Exception as e:
        print(e)
        return {"message": "user Update commit failed"}

    return redirect(url_for('view_blueprint.users'))




@view_blueprint.route('/delete_user/<user_id>', methods=['GET', 'POST'])
def delete_user(user_id):
    user = db_session.query(models.User).filter(models.User.id == user_id).delete()
    db_session.commit()
    return redirect(url_for('view_blueprint.users'))

@view_blueprint.route('/merchants/')
def merchants():
    merchants = db_session.query(models.Merchant).all()
    boys = db_session.query(models.Delivery_Boy).all()
    total_merchant = len(merchants)
    return render_template('merchants.html', merchants=merchants, total_merchant=total_merchant, boys=boys, title="Merchants")

@view_blueprint.route('/add_merchant/', methods=['POST'])
def add_merchant():
    try:
        name = request.form['name']
        email = request.form['email']
        latitude = request.form['latitude']
        longitude = request.form['longitude']
        boys_id = request.form['delivery-boys']
        phone_number = request.form['phone_number']

        create_merchant = models.Merchant(phone_number=phone_number,
                                    name=name,
                                    email=email,
                                    latitude=latitude,
                                    longitude=longitude,
                                    boys_id=[int(boys_id)],
                                    created_at=datetime.datetime.now())
        db_session.add(create_merchant)
        db_session.flush()

    except Exception as e:
        print(e)
        return {"message": "something went wrong in creating or adding merchants"}

    try:
        db_session.commit()

    except Exception as e:
        print(e)
        return {"message": "something went wrong in commit() merchants"}

    return redirect(url_for('view_blueprint.merchants'))


@view_blueprint.route('/update_merchant/', methods=['POST'])
def update_merchant():
    try:
        name = request.form['name']
        new_name = request.form['new_name']
        email = request.form['email']
        new_email = request.form['new_email']
        latitude = request.form['latitude']
        new_latitude = request.form['new_latitude']
        longitude = request.form['longitude']
        new_longitude = request.form['new_longitude']
        boys_id = request.form['delivery-boys']
        phone_number = request.form['phone_number']
        new_phone_number = request.form['new_phone_number']

        merchant = db_session.query(models.Merchant).filter(models.Merchant.name == name).one()

        merchant.name = new_name
        merchant.email = new_email
        merchant.latitude = new_latitude
        merchant.longitude = new_longitude
        merchant.phone_number = new_phone_number

        if int(boys_id) in merchant.boys_id:
            pass
        else:
            del merchant.boys_id[0]
            merchant.boys_id.append(int(boys_id))

    except Exception as e:
        print(e)
        return {"message": "merchant Update Adding failed"}
    try:
        db_session.commit()

    except Exception as e:
        print(e)
        return {"message": "merchant Update commit failed"}

    return redirect(url_for('view_blueprint.merchants'))

@view_blueprint.route('/delete_merchant/<merchant_id>', methods=['GET', 'POST'])
def delete_merchant(merchant_id):
    merchant = db_session.query(models.Merchant).filter(models.Merchant.id == merchant_id).delete()
    db_session.commit()
    return redirect(url_for('view_blueprint.merchants'))

@view_blueprint.route('/orders/')
def orders(delete=None):
    orders = db_session.query(models.User, models.Order, models.Merchant, models.Delivery_Boy).filter(models.User.id == models.Order.user_id).filter(models.Merchant.id == models.Order.merchant_id).filter(models.Delivery_Boy.id == models.Order.boys_id).all()
    total_order = len(orders)
    if request.args.get('delete') == "success":
        flash('Delete Entry Success')
    elif request.args.get('delete') == "fail":
        flash('Delete Entry Failed')
    return render_template('orders.html', orders=orders, total_order=total_order, title="Orders")

@view_blueprint.route('/delete_order/<order_id>', methods=['GET', 'POST'])
def delete_order(order_id):
    try:
        order = db_session.query(models.Order).filter(models.Order.id == order_id).delete()
        db_session.commit()
    except Exception as e:
        print(e)
        return redirect(url_for('view_blueprint.orders', delete="fail"))
    return redirect(url_for('view_blueprint.orders', delete="success"))

@view_blueprint.route('/delivery_boy/')
def delivery_boy():
    boys = db_session.query(models.Delivery_Boy).all()
    total_boy = len(boys)
    return render_template('delivery_boy.html', boys=boys, total_boy=total_boy, title="Delivery_Boy")

@view_blueprint.route('/add_boy/', methods=['POST'])
def add_boy():
    try:
        name = request.form['name']
        email = request.form['email']
        phone_number = request.form['phone_number']

        create_boy = models.Delivery_Boy(phone_number=phone_number,
                                    name=name,
                                    email=email,
                                    created_at=datetime.datetime.now())
        db_session.add(create_boy)
        db_session.flush()

    except Exception as e:
        print(e)
        return {"message": "something went wrong in creating boy"}

    try:
        db_session.commit()

    except Exception as e:
        print(e)
        return {"message": "something went wrong in creating boy"}

    return redirect(url_for('view_blueprint.delivery_boy'))

@view_blueprint.route('/update_boy/', methods=['POST'])
def update_boy():
    try:
        name = request.form['name']
        new_name = request.form['new_name']
        email = request.form['email']
        new_email = request.form['new_email']
        phone_number = request.form['phone_number']
        new_phone_number = request.form['new_phone_number']

        boy = db_session.query(models.Delivery_Boy).filter(models.Delivery_Boy.name == name).one()

        boy.name = new_name
        boy.email = new_email
        boy.phone_number = new_phone_number

    except Exception as e:
        print(e)
        return {"message": "delivery_boy Update Adding failed"}
    try:
        db_session.commit()

    except Exception as e:
        print(e)
        return {"message": "delivery_boy Update commit failed"}

    return redirect(url_for('view_blueprint.delivery_boy'))


@view_blueprint.route('/delete_boy/<boy_id>', methods=['GET', 'POST'])
def delete_boy(boy_id):
    boy = db_session.query(models.Delivery_Boy).filter(models.Delivery_Boy.id == boy_id).delete()
    db_session.commit()
    return redirect(url_for('view_blueprint.delivery_boy'))
