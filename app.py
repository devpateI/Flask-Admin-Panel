from flask import Flask ,render_template,redirect, url_for, request,flash
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
import os
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_mail import Mail, Message

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///admin.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = 'mysecret'
app.config['MAX_FILE_LENGTH'] = 1024 * 1024 #This line is for adding constraint to upload maximumm 1MB file
app.config['UPLOAD_EXTENSIONS'] = ['.jpg', '.png', '.gif', '.txt'] #This line only uploads jpg, png, gif file

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'officialnaturelover@gmail.com'
app.config['MAIL_PASSWORD'] = 'lanroezzjnwzbeoo'

mail = Mail(app)

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

@app.route('/dashboard') #for dashboard
@login_required
def dashboard():
    f=db.session.query(FileContents.username,FileContents.name).all()
    return render_template("dashboard.html",f=f)

@app.route('/success', methods = ['POST'])  #for file uploading
def success():  
    if request.method == 'POST':  
        f = request.files['file']  
        print(f.read())
        filesize = int(request.cookies['filesize'])
        if int(filesize) >= app.config["MAX_FILE_LENGTH"]:
            flash("File is too large",'error') 
            return redirect(url_for('dashboard'))
        if f != '':
            file_ext = os.path.splitext(f.filename)[1]
        if file_ext not in app.config['UPLOAD_EXTENSIONS']:
            flash('Please upload only jpg, png or gif file','error')
            return redirect(url_for('dashboard'))
            # abort(400)
        else:
            newFile = FileContents(username=username,name=f.filename, data=f.read())
            db.session.add(newFile)
            db.session.commit()

            flash('Saved ' + f.filename + ' to the database','success')
            return redirect(url_for('dashboard'))

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
                flash('Login Successful','success')
                return redirect(url_for("dashboard"))
            else:
                flash('Username Password Incorrect','error')
                return render_template("login.html", form=form)
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

@app.route('/reset_password', methods=['GET','POST'])
def reset_password():
    form=ResetPasswordForm()
    if form.validate_on_submit():
        user=UserLogin.query.filter_by(username=form.username.data).first()
        if user:
            send_mail(user)
            flash('Reset request sent. Check your Email','success')
            return redirect(url_for('login'))
    else:
        flash('Enter a valid Username','error')
    return render_template("reset_request.html",form=form)

def send_mail(user):
    token=user.get_token()
    msg=Message('PasswordReset Request',recipients=[user.username],sender='noreply@dev.com')
    msg.body = f''' To reset Password follow link below.

    {url_for('reset_token',token=token,_external=True)}

    '''
    # print(msg.body)
    mail.send(msg)

@app.route('/reset_password/<token>',methods=['GET','POST'])
def reset_token(token):
    form = ChangePasswordForm()
    user=UserLogin.verify_token(token)
    if user is None:
        flash('That is invalid token','warning')
        return redirect(url_for('reset_password'))
 
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        user.password = hashed_password
        db.session.commit()
        flash('Password changed','success')
        return redirect(url_for('login'))


    return render_template("change_password.html",form=form)
       
@app.route('/download/<filename>')
def download_file(filename):
    s=db.session.query(FileContents.data).filter(FileContents.name == filename).first()
    with open(filename,'w') as f:
        f.write(str(s[0]))
        f.close()
    print(s)
    return redirect(url_for('dashboard'))

class UserLogin(db.Model,UserMixin):
    id= db.Column(db.Integer,primary_key=True)
    username= db.Column(db.String(20),nullable=False, unique=True)
    password= db.Column(db.String(80),nullable=False)

    def get_token(self,expires_sec=300):
        serial=Serializer(app.config['SECRET_KEY'],300)
        return serial.dumps({'user_id':self.id}).decode('utf8')

    @staticmethod
    def verify_token(token):
        serial=Serializer(app.config['SECRET_KEY'])
        try:
            user_id=serial.loads(token)['user_id']
        except:
            return None
        return UserLogin.query.get(user_id)
    

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

    password = PasswordField(validators=[InputRequired(),Length(min=4,max=20)],
    render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    def validate_username(self,username):
        existing_user_username = UserLogin.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already exists. Please choose a different one")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(min=4,max=20)],
    render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(),Length(min=4,max=20)],
    render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")

class ChangePasswordForm(FlaskForm):
    password = PasswordField(validators=[InputRequired(),Length(min=4,max=20)],
    render_kw={"placeholder": "Password"})

    submit = SubmitField("Change Password")

class ResetPasswordForm(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(min=4,max=20)],
    render_kw={"placeholder": "Username"})

    submit = SubmitField("Send Email")

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
        # 'data',
    ]
    form_columns = [
        'username',
        'name',
        'data',
    ]

    form_create_rules = [
        'username',
        'name',
        'data',
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
