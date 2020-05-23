from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from src.database import db_session
import src.models as models
from datetime import datetime
import datetime
from argon2 import PasswordHasher
import jsonify
from functools import wraps
from pytz import timezone
from sqlalchemy import desc

ph = PasswordHasher(hash_len=64, salt_len=32)

view_blueprint = Blueprint('view_blueprint', __name__)

"""
Template for Dashboard
"""
@view_blueprint.route('/dashboard/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('view_blueprint.admin'))
    return render_template('index.html')

"""
Template for Admin
"""
@view_blueprint.route('/admin/')
def admin():
    return render_template('admin_login.html', title="Admin Login")

@view_blueprint.route('/admin_logout/')
def admin_logout():
    session['logged_in'] = False
    return redirect(url_for('view_blueprint.admin'))

@view_blueprint.route('/admin_login/', methods=['POST'])
def admin_login():
    name = request.form['name']
    password = request.form['password']

    admin = db_session.query(models.Admin).filter(models.Admin.name == name).one_or_none()
    if admin is None:
        flash('Wrong Admin Name !!!')
        return redirect(url_for('view_blueprint.admin'))

    try:
        ph.verify(admin.password_hash, password)
        session['logged_in'] = True

    except Exception as e:
        print(e)
        flash('Wrong Password !!!')
        return redirect(url_for('view_blueprint.admin'))

    return redirect(url_for('view_blueprint.index'))

"""
Template for Items
"""
@view_blueprint.route('/items/')
def items():
    if not session.get('logged_in'):
        return redirect(url_for('view_blueprint.admin'))
    items = db_session.query(models.Item).order_by(desc(models.Item.id)).all()
    total_item = len(items)
    return render_template('items.html', items=items, total_item=total_item, title="Items")

@view_blueprint.route('/add_item/')
def add_item():
    if not session.get('logged_in'):
        return redirect(url_for('view_blueprint.admin'))
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
        create_item = models.Item(item_name=item_name,
                                    item_unit=item_unit,
                                    sub_category_id=sub_category_id)
        db_session.add(create_item)
        db_session.flush()

    except Exception as e:
        print(e)
        return {"message": "Add item failed"}
    try:
        db_session.commit()
        flash('Item successfully added')
        return redirect(url_for('view_blueprint.items'))

    except Exception as e:
        print(e)
        db_session.rollback()
        flash('Item failed to add')
        return redirect(url_for('view_blueprint.items'))

@view_blueprint.route('/update_item_uri/<item_id>', methods=['GET', 'POST'])
def update_item_uri(item_id):
    if not session.get('logged_in'):
        return redirect(url_for('view_blueprint.admin'))
    items = db_session.query(models.Item).filter(models.Item.id == item_id).all()
    sub_items = db_session.query(models.Item).filter(models.Item.sub_category_id == None).all()

    if items[0].sub_category_id is None:
        sub_name = None
    else:
        for sub_item in sub_items:
            if sub_item.id == int(items[0].sub_category_id):
                sub_name = sub_item.item_name
                break

    return render_template('update_item.html', title="Update Item", items=items, sub_items=sub_items, sub_name=sub_name)

@view_blueprint.route('/update_item/', methods=['POST'])
def update_item():
    try:
        id = request.form['id']
        name = request.form['new_name']
        item_unit = request.form['item_unit']
        sub_category_id = request.form['sub_category_id']
        item = db_session.query(models.Item).filter(models.Item.id == int(id)).one_or_none()

        if sub_category_id == "None":
            sub_category_id = None
        item.item_name = name
        item.item_unit = item_unit
        item.sub_category_id = sub_category_id

    except Exception as e:
        print(e)
        return {"message": "user Update Adding failed"}
    try:
        db_session.commit()
        flash('Update Item success')

    except Exception as e:
        print(e)
        db_session.rollback()
        flash('Update Item failed')
        return redirect(url_for('view_blueprint.items'))

    return redirect(url_for('view_blueprint.items'))

@view_blueprint.route('/delete_item/<item_id>', methods=['GET', 'POST'])
def delete_item(item_id):
    if not session.get('logged_in'):
        return redirect(url_for('view_blueprint.admin'))
    try:
        item = db_session.query(models.Item).filter(models.Item.id == item_id).delete()
        db_session.commit()
        flash('Item delete success')

    except Exception as e:
        print(e)
        db_session.rollback()
        flash('Item Delete Failed')
        return redirect(url_for('view_blueprint.items'))

    return redirect(url_for('view_blueprint.items'))

"""
Template for Users
"""
@view_blueprint.route('/users/')
def users():
    if not session.get('logged_in'):
        return redirect(url_for('view_blueprint.admin'))
    users = db_session.query(models.User).order_by(desc(models.User.created_at)).all()
    # for user in users:
    #     user.created_at = user.created_at.strftime("%d-%m-%Y %I:%M %p")
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

        now_asia = datetime.datetime.now(timezone('Asia/Kolkata'))
        print(now_asia.strftime("%d-%m-%Y %I:%M %p"))

        create_user = models.User(phone_number=phone_number,
                                    name=name,
                                    email=email,
                                    address=address,
                                    password_hash=ph.hash(password),
                                    created_at=now_asia)
        db_session.add(create_user)
        db_session.flush()

    except Exception as e:
        print(e)
        return {"message": "something went wrong in creating user"}
    try:
        db_session.commit()
        flash('New User successfully added')

    except Exception as e:
        print(e)
        db_session.rollback()
        flash('New User failed to add')
        return redirect(url_for('view_blueprint.users'))

    return redirect(url_for('view_blueprint.users'))

@view_blueprint.route('/update_user_uri/<user_id>', methods=['GET', 'POST'])
def update_user_uri(user_id):
    if not session.get('logged_in'):
        return redirect(url_for('view_blueprint.admin'))
    users = db_session.query(models.User).filter(models.User.id == user_id).all()
    return render_template('update_user.html', title="Update User", users=users)

@view_blueprint.route('/update_user/', methods=['POST'])
def update_user():
    try:
        user = db_session.query(models.User).filter(models.User.id == request.form['id']).one_or_none()

        user.name = request.form['new_name']
        user.email = request.form['new_email']
        user.address = request.form['new_address']
        user.phone_number = request.form['new_phone_number']

    except Exception as e:
        print(e)
        return {"message": "user Update Adding failed"}
    try:
        db_session.commit()
        flash('Update User success')

    except Exception as e:
        print(e)
        db_session.rollback()
        flash('Update User failed')
        return redirect(url_for('view_blueprint.users'))

    return redirect(url_for('view_blueprint.users'))

@view_blueprint.route('/delete_user/<user_id>', methods=['GET', 'POST'])
def delete_user(user_id):
    if not session.get('logged_in'):
        return redirect(url_for('view_blueprint.admin'))
    try:
        user = db_session.query(models.User).filter(models.User.id == user_id).delete()
        db_session.commit()
        flash('User delete success')

    except Exception as e:
        print(e)
        db_session.rollback()
        flash('User Delete Failed')
        return redirect(url_for('view_blueprint.users'))

    return redirect(url_for('view_blueprint.users'))

"""
Template for Merchants
"""
@view_blueprint.route('/merchants/')
def merchants():
    if not session.get('logged_in'):
        return redirect(url_for('view_blueprint.admin'))
    merchants = db_session.query(models.Merchant).order_by(desc(models.Merchant.created_at)).all()
    # for merchant in merchants:
    #     merchant.created_at = merchant.created_at.strftime("%d-%m-%Y %I:%M %p")
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

        now_asia = datetime.datetime.now(timezone('Asia/Kolkata'))

        create_merchant = models.Merchant(phone_number=phone_number,
                                    name=name,
                                    email=email,
                                    latitude=latitude,
                                    longitude=longitude,
                                    boys_id=[int(boys_id)],
                                    created_at=now_asia)
        db_session.add(create_merchant)
        db_session.flush()

    except Exception as e:
        print(e)
        return {"message": "something went wrong in creating or adding merchants"}
    try:
        db_session.commit()
        flash('New Merchant successfully added')

    except Exception as e:
        print(e)
        db_session.rollback()
        flash('New Merchant failed to add')
        return redirect(url_for('view_blueprint.merchants'))

    return redirect(url_for('view_blueprint.merchants'))

@view_blueprint.route('/update_merchant_uri/<merchant_id>', methods=['GET', 'POST'])
def update_merchant_uri(merchant_id):
    if not session.get('logged_in'):
        return redirect(url_for('view_blueprint.admin'))
    merchants = db_session.query(models.Merchant).filter(models.Merchant.id == merchant_id).all()
    boys = db_session.query(models.Delivery_Boy).all()
    return render_template('update_merchant.html', title="Update Merchant", merchants=merchants, boys=boys)

@view_blueprint.route('/update_merchant/', methods=['POST'])
def update_merchant():
    try:
        boys_id = request.form['delivery-boys']
        merchant = db_session.query(models.Merchant).filter(models.Merchant.id == request.form['id']).one_or_none()

        merchant.name = request.form['new_name']
        merchant.email = request.form['new_email']
        merchant.latitude = request.form['new_latitude']
        merchant.longitude = request.form['new_longitude']
        merchant.phone_number = request.form['new_phone_number']

        if int(boys_id) in merchant.boys_id:
            pass
        else:
            merchant.boys_id[0] = None
            db_session.commit()
            db_session.refresh(merchant)
            merchant.boys_id = [int(boys_id)]

    except Exception as e:
        print(e)
        return {"message": "merchant Update Adding failed"}
    try:
        db_session.commit()
        flash('Update Merchant success')

    except Exception as e:
        print(e)
        db_session.rollback()
        flash('Update Merchant failed')
        return redirect(url_for('view_blueprint.merchants'))

    return redirect(url_for('view_blueprint.merchants'))

@view_blueprint.route('/delete_merchant/<merchant_id>', methods=['GET', 'POST'])
def delete_merchant(merchant_id):
    if not session.get('logged_in'):
        return redirect(url_for('view_blueprint.admin'))
    try:
        merchant = db_session.query(models.Merchant).filter(models.Merchant.id == merchant_id).delete()
        db_session.commit()
        flash('Merchant delete success')

    except Exception as e:
        print(e)
        db_session.rollback()
        flash('Merchant Delete Failed')
        return redirect(url_for('view_blueprint.merchants'))

    return redirect(url_for('view_blueprint.merchants'))

"""
Template for Delivery_Boy
"""
@view_blueprint.route('/delivery_boy/')
def delivery_boy():
    if not session.get('logged_in'):
        return redirect(url_for('view_blueprint.admin'))
    boys = db_session.query(models.Delivery_Boy).order_by(desc(models.Delivery_Boy.created_at)).all()
    total_boy = len(boys)
    return render_template('delivery_boy.html', boys=boys, total_boy=total_boy, title="Delivery Boys")

@view_blueprint.route('/add_boy/', methods=['POST'])
def add_boy():
    try:
        name = request.form['name']
        email = request.form['email']
        phone_number = request.form['phone_number']

        now_asia = datetime.datetime.now(timezone('Asia/Kolkata'))

        create_boy = models.Delivery_Boy(phone_number=phone_number,
                                    name=name,
                                    email=email,
                                    created_at=now_asia)
        db_session.add(create_boy)
        db_session.flush()

    except Exception as e:
        print(e)
        return {"message": "something went wrong in creating boy"}
    try:
        db_session.commit()
        flash('New delivery boy successfully added')

    except Exception as e:
        print(e)
        db_session.rollback()
        flash('New delivery boy failed to add')
        return redirect(url_for('view_blueprint.delivery_boy'))

    return redirect(url_for('view_blueprint.delivery_boy'))

@view_blueprint.route('/update_boy_uri/<boy_id>', methods=['GET', 'POST'])
def update_boy_uri(boy_id):
    if not session.get('logged_in'):
        return redirect(url_for('view_blueprint.admin'))
    boys = db_session.query(models.Delivery_Boy).filter(models.Delivery_Boy.id == boy_id).all()
    return render_template('update_delivery_boy.html', title="Update boys", boys=boys)

@view_blueprint.route('/update_boy/', methods=['POST'])
def update_boy():
    try:
        boy = db_session.query(models.Delivery_Boy).filter(models.Delivery_Boy.id == request.form['id']).one_or_none()

        boy.name = request.form['new_name']
        boy.email = request.form['new_email']
        boy.phone_number = request.form['new_phone_number']

    except Exception as e:
        print(e)
        return {"message": "delivery_boy Update Adding failed"}
    try:
        db_session.commit()
        flash('Update delivery boy Success')

    except Exception as e:
        print(e)
        db_session.rollback()
        flash('Update delivery boy failed')
        return redirect(url_for('view_blueprint.delivery_boy'))

    return redirect(url_for('view_blueprint.delivery_boy'))

@view_blueprint.route('/delete_boy/<boy_id>', methods=['GET', 'POST'])
def delete_boy(boy_id):
    if not session.get('logged_in'):
        return redirect(url_for('view_blueprint.admin'))
    try:
        boy = db_session.query(models.Delivery_Boy).filter(models.Delivery_Boy.id == boy_id).delete()
        db_session.commit()
        flash('DeliveryBoy Delete Success')

    except Exception as e:
        print(e)
        db_session.rollback()
        flash('DeliveryBoy Delete Failed')
        return redirect(url_for('view_blueprint.delivery_boy'))

    return redirect(url_for('view_blueprint.delivery_boy'))

"""
Template for Orders
"""
@view_blueprint.route('/orders/')
def orders():
    if not session.get('logged_in'):
        return redirect(url_for('view_blueprint.admin'))
    orders = db_session.query(models.User, models.Order, models.Merchant, models.Delivery_Boy).filter(models.User.id == models.Order.user_id).filter(models.Merchant.id == models.Order.merchant_id).filter(models.Delivery_Boy.id == models.Order.boys_id).order_by(desc(models.Order.created_at)).all()
    total_order = len(orders)
    return render_template('orders.html', orders=orders, total_order=total_order, title="Orders")

@view_blueprint.route('/delete_order/<order_id>', methods=['GET', 'POST'])
def delete_order(order_id):
    try:
        order = db_session.query(models.Order).filter(models.Order.id == order_id).one_or_none()
        order.status = models.Delivery_Status.Cancelled
        db_session.commit()
        flash('Order Cancelled Success')

    except Exception as e:
        print(e)
        db_session.rollback()
        flash('Order Cancelled Failed')
        return redirect(url_for('view_blueprint.orders'))

    return redirect(url_for('view_blueprint.orders'))

@view_blueprint.route('/complete_order/<order_id>', methods=['GET', 'POST'])
def complete_order(order_id):
    try:
        order = db_session.query(models.Order).filter(models.Order.id == order_id).one_or_none()
        order.status = models.Delivery_Status.Delivered
        db_session.commit()
        flash('Order complete Success')

    except Exception as e:
        print(e)
        db_session.rollback()
        flash('Order complete Failed')
        return redirect(url_for('view_blueprint.orders'))

    return redirect(url_for('view_blueprint.orders'))


@view_blueprint.route('/update_orders/', methods=['POST'])
def update_orders():
    try:
        id = request.form['id']

        order = db_session.query(models.Order).filter(models.Order.id == int(id)).one_or_none()

        order.description = None
        db_session.commit()
        db_session.refresh(order)
        order.description = ["des"]
    except Exception as e:

        print(e)
        db_session.rollback()
        return {"message": "merchant Update Adding failed"}
    try:
        db_session.commit()
        flash('Update Merchant success')

    except Exception as e:
        print(e)
        db_session.rollback()
        flash('Update Merchant failed')
        return redirect(url_for('view_blueprint.orders'))

    return redirect(url_for('view_blueprint.orders'))

@view_blueprint.route('/update_orders_uri/')
def update_orders_uri():
    return render_template('update_order.html')


@view_blueprint.route('/download_csv/')
def download_csv():
    pass
    return redirect(url_for('view_blueprint.users'))
