from flask import Flask, render_template, redirect, url_for, request, flash, session, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user #does not care how data stored, uses dictionary,
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import Form, StringField, PasswordField, SubmitField, validators, TextField
from wtforms.validators import EqualTo, InputRequired, Length, ValidationError,  DataRequired, Email
from flask_bcrypt import Bcrypt
from email.utils import make_msgidfrom 
from flask_mail import Mail, Message
from io import BytesIO
import onetimepass, pyqrcode, os, base64

app=Flask(__name__)

app.config['SECRET_KEY']='thisisfirstflaskapp'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db=SQLAlchemy(app)
bcrypt=Bcrypt(app)
login_manager=LoginManager(app)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "username@gmail.com"
app.config['MAIL_PASSWORD'] = "password"

mail = Mail(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@login_manager.unauthorized_handler
def unauthorized():
    return redirect(url_for('register'))

class User(db.Model, UserMixin):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(20), unique=True, nullable=False)
    email=db.Column(db.String(120), unique=True, nullable=False)
    image_file=db.Column(db.String(20), nullable=False, default='default.jpg')
    password= db.Column(db.String(60), nullable=False)
    otp_secret = db.Column(db.String(16))

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.otp_secret is None:
            # generate a random secret
            self.otp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
    
    def __repr__(self):
        return f'{self.username}:{self.email}:{self.date_created.strftime("%d%m%Y, %H:%M:%S")}'
    
class RegistrationForm(FlaskForm):
    username=StringField(label= 'username', validators=[DataRequired(),Length(min=3, max=20)])
    email=StringField(validators=[DataRequired(),Email()])
    password=PasswordField(label= 'Password', validators=[DataRequired(),Length(min=3, max=20)])
    confirm_password= PasswordField(label='Confirm Password', validators=[DataRequired(), EqualTo])
    submit=SubmitField(label= 'Sign Up', validators=[DataRequired()])

    def validate_username(self, username):
        existing_user_username= User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                "That username already exists. Please choose a different one.")

class LoginForm(FlaskForm):
    email=StringField(label='Email', validators=[DataRequired(),Length(min=4, max=20)])
    password=PasswordField(validators=[DataRequired(),Length(min=4, max=20)])
    submit=SubmitField(label='Login', validators=[DataRequired()])

class ResetRequestForm(FlaskForm):
    email=StringField(label='Email', validators=[DataRequired()])
    submit= SubmitField(label='Reset Password', validators=[DataRequired()])

class ResetPasswordForm(FlaskForm):
    password=PasswordField(validators=[DataRequired(),Length(min=4, max=20)])
    confirm_password= PasswordField(label='Confirm Password', validators=[DataRequired(), EqualTo])
    submit=SubmitField(label='Change Password', validators=[DataRequired()])

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form=RegistrationForm()
    if form.validate_on_submit():
        encrypted_password=bcrypt.generate_password_hash(form.password.data)
        user= User(username=form.username.data, email=form.email.data, password=encrypted_password)
        db.session.add(user)
        db.session.commit()
        flash(f'Account created successfully for {{form.username.data}}')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        user= User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password,form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html',title='Login', form=form)

@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

def send_mail(user):
    token=user.get_token()
    msg=Message('Password Reset Request', recipients=[user.email], sender='noreply@codejana.com')
    msg.body=f''' To reset your password. Please follow the link below

    {url_for('reset_token', token=token,_external=True)}
    If you didn't send a password reset request. Please ignore this message.

    
    '''
    mail.send(msg)

@app.route('/reset_password', methods=['POST', 'GET'])
def reset_request():
    form=ResetRequestForm()
    if form.validate_on_submit():
        user=User.query.filter_by(email=form.email.data).first()
        if user:
            send_mail(user)
            flash('Reset request sent. Check your mail', 'success')
            return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Request', legend='Reset Password')

@app.route('/reset_password/<token>', methods=['POST', 'GET'])
def reset_token(token):
    user=User.verify_token(token)
    if user is None:
        flash('That is invalid token or expired. Please try again.', 'warning')
        return redirect(url_for('reset_request'))
    form=ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password=bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password=hashed_password
        db.session.commit()
        flash('Password changed. Please login.', 'success')
        return(redirect(url_for('login')))
    return render_template('change_password.html', title="Change Password", legend="Change Password", form=form)

@app.route('/twofactor')
def two_factor_setup():
    if 'username' not in session:
        return redirect(url_for('dashboard'))
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        return redirect(url_for('dashboard'))
    # since this page contains the sensitive qrcode, make sure the browser
    # does not cache it
    return render_template('two-factor-setup.html'), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}

@app.route('/qrcode')
def qrcode():
    if 'username' not in session:
        abort(404)
    user = User.query.filter_by(username=session['username']).first()
    if user is None:
        abort(404)

    # for added security, remove username from session
    del session['username']

    # render qrcode for FreeTOTP
    url = pyqrcode.create(user.get_totp_uri())
    stream = BytesIO()
    url.svg(stream, scale=3)
    return stream.getvalue(), 200, {
        'Content-Type': 'image/svg+xml',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'}


if __name__=='__main__':
    app.run(debug=True)