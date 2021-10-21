from flask import Flask ,render_template,redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy 
from flask_admin import Admin 
from flask_admin.contrib.sqla import ModelView
import uuid
from sqlalchemy_utils import EmailType, UUIDType
import flask_admin as admin
from flask_admin.contrib.sqla.filters import BaseSQLAFilter, FilterEqual
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField
from wtforms.validators import InputRequired,Length,ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///admin.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = 'mysecret'
admin = Admin(app, name='Dev', template_mode='bootstrap3')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return UserLogin.query.get(int(user_id))

@app.route('/')
def index():
    return render_template("home.html")

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route('/success', methods = ['POST'])  
def success():  
    if request.method == 'POST':  
        f = request.files['file']  
        newFile = FileContents(username=username,name=f.filename, data=f.read())
        db.session.add(newFile)
        db.session.commit()

        return 'Saved ' + f.filename + ' to the database'

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('login')

@app.route('/login', methods=['GET','POST'])
def login():
    form=LoginForm()
    global username
    username=form.username.data
    if form.validate_on_submit:
        user=UserLogin.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password,form.password.data):
                login_user(user)
                return redirect(url_for("dashboard"))
    return render_template("login.html", form=form)
@app.route('/register', methods=['GET','POST'])
def register():
    form=RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = UserLogin(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template("register.html",form=form)

class UserLogin(db.Model,UserMixin):
    id= db.Column(db.Integer,primary_key=True)
    username= db.Column(db.String(20),nullable=False, unique=True)
    password= db.Column(db.String(80),nullable=False)

class FileContents(db.Model):
    id= db.Column(db.Integer, primary_key=True)
    data = db.Column(db.LargeBinary, nullable=False)
    username= db.Column(db.String(20),db.ForeignKey(UserLogin.username))
    name=db.Column(db.String(300))
    

class User(db.Model):
    id = db.Column(UUIDType(binary=False), default=uuid.uuid4, primary_key=True)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    rating = db.Column(db.Integer)
    email = db.Column(EmailType, unique=True, nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(min=4,max=20)],
    render_kw={"placeholder": "Username"})

    password = StringField(validators=[InputRequired(),Length(min=4,max=20)],
    render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    def validate_username(self,username):
        existing_user_username = UserLogin.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different one")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(min=4,max=20)],
    render_kw={"placeholder": "Username"})

    password = StringField(validators=[InputRequired(),Length(min=4,max=20)],
    render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")

class FilterLastNameBrown(BaseSQLAFilter):
    def apply(self, query, value, alias=None):
        if value == '1':
            return query.filter(self.column == "Brown")
        else:
            return query.filter(self.column != "Brown")

    def operation(self):
        return 'is Brown'


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

class FileContentsAdmin(ModelView):
    can_view_details = True  # show a modal dialog with records details
    action_disallowed_list = ['delete', ]

    column_list = [
        'username',
        'name',
        'data',
    ]
    form_columns = [
        'username',
        'name',
    ]

    form_create_rules = [
        'username',
        'name',
        
    ]
    
admin.add_view(UserAdmin(User, db.session))
admin.add_view(ModelView(UserLogin, db.session))

admin.add_view(FileContentsAdmin(FileContents, db.session))
class Mytools(ModelView):
    can_delete = False
    page_size = 50
    column_searchable_list = ['name']

if __name__ == '__main__':
    app.run(debug=True)