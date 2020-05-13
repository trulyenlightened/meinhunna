from flask import Blueprint, render_template, redirect, url_for, request
from src.database import db_session
import src.models as models
from datetime import datetime
import datetime
from argon2 import PasswordHasher

ph = PasswordHasher(hash_len=64, salt_len=32)

view_blueprint = Blueprint('view_blueprint', __name__)

@view_blueprint.route('/dashboard/')
def index():
    return render_template('index.html')

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

@view_blueprint.route('/update_user/', methods=['PUT'])
def update_user():
    pass

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
        print("--------------")
        print(boys_id)
        print("--------------")
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


@view_blueprint.route('/update_merchant/', methods=['PUT'])
def update_merchant():
    pass

@view_blueprint.route('/delete_merchant/', methods=['DELETE'])
def delete_merchant():
    pass

@view_blueprint.route('/orders/')
def orders():
    orders = db_session.query(models.Order).all()
    total_order = len(orders)
    return render_template('orders.html', orders=orders, total_order=total_order, title="Orders")

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

@view_blueprint.route('/delete_boy/<boy_id>', methods=['GET', 'POST'])
def delete_boy(boy_id):
    boy = db_session.query(models.Delivery_Boy).filter(models.Delivery_Boy.id == boy_id).delete()
    db_session.commit()
    return redirect(url_for('view_blueprint.delivery_boy'))
