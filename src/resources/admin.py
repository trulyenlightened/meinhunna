from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from src.resources.users import User

admin = Admin(app)
admin.add_view(ModelView(User, db.session))
