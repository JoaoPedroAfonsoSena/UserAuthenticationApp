from flask import Flask,render_template,url_for,redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,login_user,LoginManager,login_required,logout_user,current_user
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,SubmitField,EmailField
from wtforms.validators import InputRequired,Length,ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'admin'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:admin@localhost/cargoapp'
db = SQLAlchemy(app)
bcrypt= Bcrypt(app)


login_manager=LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"

def get_id(self):
    return str(self.user_id)

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

class Users(db.Model,UserMixin):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    def get_id(self):
        return str(self.user_id)

class RegisterForm(FlaskForm):
    username= StringField(validators=[InputRequired(),Length(
        min=4,max=20)], render_kw={"placeholder":"Username"})
    email= EmailField(validators=[InputRequired(),Length(
        min=4,max=50)], render_kw={"placeholder":"Email"})
    password= PasswordField(validators=[InputRequired(),Length(
        min=4,max=20)], render_kw={"placeholder":"Password"})
    submit= SubmitField("Register")

    def validate_username(self,username):
        existing_user_username = Users.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username already Exists. Choose a diferent one.")

class LoginForm(FlaskForm):
    email= EmailField(validators=[InputRequired(),Length(
        min=4,max=50)], render_kw={"placeholder":"Email"})
    password= PasswordField(validators=[InputRequired(),Length(
        min=4,max=20)], render_kw={"placeholder":"Password"})
    submit= SubmitField("Login")


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/trabalhos')
def trabalhos():
    return render_template('tabela.html')

@app.route('/dashboard',methods=['GET','POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout',methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/login',methods=['GET','POST'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))

    return render_template('login.html',form=form)

@app.route('/register',methods=['GET','POST'])
def register():
    form=RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = Users(username=form.username.data,password=hashed_password,email=form.email.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html',form=form)

if __name__ == '__main__':
    app.run(debug=True )