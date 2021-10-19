from flask import Flask ,render_template
from flask_sqlalchemy import SQLAlchemy 
from flask_admin import Admin 
from flask_admin.contrib.sqla import ModelView
import uuid
from sqlalchemy_utils import EmailType, UUIDType
import flask_admin as admin
from flask_admin.contrib.sqla.filters import BaseSQLAFilter, FilterEqual

app = Flask(__name__)

@app.route('/')
def index():
    return render_template("hello.html")

admin = Admin(app, name='Dev', template_mode='bootstrap3')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///admin.db'
app.config['SECRET_KEY'] = 'mysecret'

db = SQLAlchemy(app)

class FilterLastNameBrown(BaseSQLAFilter):
    def apply(self, query, value, alias=None):
        if value == '1':
            return query.filter(self.column == "Brown")
        else:
            return query.filter(self.column != "Brown")

    def operation(self):
        return 'is Brown'

class User(db.Model):
    id = db.Column(UUIDType(binary=False), default=uuid.uuid4, primary_key=True)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    rating = db.Column(db.Integer)
    email = db.Column(EmailType, unique=True, nullable=False)


class UserAdmin(ModelView):

    can_view_details = True  # show a modal dialog with records details
    action_disallowed_list = ['delete', ]

    form_widget_args = {
        'id': {
            'readonly': True
        }
    }
    column_list = [
        'first_name',
        'last_name',
        'email',
        'rating',
    ]
    column_searchable_list = [
        'first_name',
        'last_name',
        'email',
        'rating',
    ]
    column_editable_list = ['rating']
    column_details_list = ['id',] + column_list
    form_columns = [
        'id',
        'last_name',
        'first_name',
        'email',
        'rating',
    ]
    form_create_rules = [
        'last_name',
        'first_name',
        'rating',
        'email',
    ]

    column_auto_select_related = True
    column_default_sort = [('last_name', False), ('first_name', False)]  # sort on multiple columns

    # custom filter: each filter in the list is a filter operation (equals, not equals, etc)
    # filters with the same name will appear as operations under the same filter
    column_filters = [
        'first_name',
        FilterEqual(column=User.last_name, name='Last Name'),
        FilterLastNameBrown(column=User.last_name, name='Last Name',
                            options=(('1', 'Yes'), ('0', 'No'))),
        'email',
        'rating',
    ]
    
admin.add_view(UserAdmin(User, db.session))
class Mytools(ModelView):
    can_delete = False
    page_size = 50
    column_searchable_list = ['name']

if __name__ == '__main__':
    app.run(debug=True)