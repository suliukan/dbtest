#Login system for Degree Booster
from __future__ import print_function
from flask import render_template, flash, redirect, url_for, request, Flask 
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.urls import url_parse
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import Form,IntegerField, TextField, PasswordField, validators, SubmitField, SelectField, BooleanField
from wtforms.validators import ValidationError, DataRequired, EqualTo
from flask_bootstrap import Bootstrap
from flask_moment import Moment 
from flask_wtf import FlaskForm
import sys

#login form ( subclassesd from FlaskForm)
class LoginForm(FlaskForm):
    #add an if statement that checks if the username is legible
    #userName must be banner id number or email address that connects to the banner id of student and faculty
    username =TextField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators = [ DataRequired() ] ) 
    remember_me = BooleanField('keep me logged in') #represents a checkbox
    submit = SubmitField('Sign In')

#registration class
class RegistrationForm(FlaskForm):
    username = TextField('Username', [validators.Length(min=4, max=20)])
    password = PasswordField('New Password', [
        validators.Required(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')
    email = TextField('Email Address', [validators.Length(min=6, max=50)])
    firstName = TextField('First Name', [validators.Length(min=4, max=50)])
    lastName = TextField('Last Name', [validators.Length(min=4, max=50)])    
    faculty = BooleanField('Are you faculty?', [validators.Required()])
    
    
#user class part of registration
class User(UserMixin):
    def __init__(self, username, password, role):
        self.id = username
        #hash the password andn output it to stderr
        self.pass_hash = generate_password_hash(password)
        print(self.pass_hash, file=sys.stderr)
        self.role = role

#creating the Flask app object and login manager
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretsecretkey'
bootstrap = Bootstrap(app)
moment = Moment(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

#Our mock database of user objects, stored as a dictinary, where the key is the user id,
#and the values is the user object.

#change this to a database instead
#dabase code to get user . whether it is faculty or user
user_db = {'u': User('u', 'u', 'student'), 'a': User('a', 'a', 'faculty') }


#Returns True if logged in user has "faculty" role, False otherwise.
def is_faculty():
    if current_user:
        if current_user.role == 'faculty':
            return True
        else:
            return False
    else:
        print('User not authenticated.', file=sys.stderr)

def is_student():
    if current_user:
        if current_user.role=='student':
            return True
        else:
            return False
    else:
        print("User not authenticated.", file=sys.stderr)

#Login manager uses this functin to manage user sessions.
# Function does a lookup by id and returns the User object if it exists, None otherwise
@login_manager.user_loader
def load_user(id):
    return user_db.get(id) # this line will be changed to the query for the database instead of the dictionary used here for testing purposes only


#this mimics a situation where a non-admin user attempts to access an admin-only area.
# @login_required ensures that only authenticaed users may access this route.
@app.route('/faculty_only')
@login_required
def faculty_only(): 
    #determine if current user is faculty
    if is_faculty():
        return render_template('faculty.html', message="I am faculty.") 

#3 functions for student options...(function logic not implemented yet)
@app.route('/course_status')
@login_required
def course_status():
    if is_student():
        return render_template('course_status.html')
@app.route('/waiting_list')
@login_required
def waiting_list():
    if is_student():
        return render_template('waiting_list.html')
@app.route('/add_remove_course')
@login_required
def add_remove_course():
    if is_student():
        return render_template('add_remove_course.html')
#function for registration (registration form not done yet)
@app.route('/registration')
def register():
    return render_template('registration.html')


@app.route('/')
@app.route('/success')
@login_required
def success():
    return render_template('success.html',name=current_user.id)

@app.route('/login', methods =['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect( url_for('success') )
    # check login input credentials 
    form = LoginForm()
    if form.validate_on_submit():
        user = user_db[form.username.data] #database query will go here to get user
        #validate user
        valid_password = check_password_hash(user.pass_hash, form.password.data)
        if user is None or not valid_password :
            print('Invalid username or password', file=sys.stderr) #console output
            flash('Invalid ursername or password') #displays this message
            redirect(url_for('success'))
        else:
            login_user(user, form.remember_me.data)
            return redirect(url_for('success'))
    return render_template('login.html', title='Sign In', form=form )

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        
    return render_template('registration.html', title='Registration', form=form )

#logging out is managed by login manager
#log out option appears on the navbar only after a user logs on successfully 
@app.route('/logout')
def logout():
    logout_user()
    flash("You have been logged out.") #displays message
    return redirect(url_for('success'))


#creates user to test login/ logout function for both student or faculty
u = User(username='1234', password='cat', role='student')
user_db.update( {u.id : u} )
