import os
import json
import requests
import re
import datetime
import random

from flask import Flask, url_for, redirect, render_template, session, request, flash
from flask_sqlalchemy import SQLAlchemy
from wtforms import StringField, SubmitField, RadioField, IntegerField, PasswordField, BooleanField, SelectMultipleField, ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from flask_login import LoginManager, login_required, login_user, logout_user, current_user, UserMixin
from requests_oauthlib import OAuth2Session
from requests.exceptions import HTTPError
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager, Shell
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash

######################################
#######  APP CONFIGURATION   #########
######################################

# Configure base directory of app
basedir = os.path.abspath(os.path.dirname(__file__))

# To use http, not just https
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
basedir = os.path.abspath(os.path.dirname(__file__))

"""Google Project Credentials"""
class Auth:
    CLIENT_ID = ('881114570305-0oorg4gvkoqm0shdv9o0vb0t8m07epfa.apps.googleusercontent.com')
    CLIENT_SECRET = 'arD-p0d-PJDA-I-0o8-lfEJT'
    REDIRECT_URI = 'http://localhost:5000/oauthCallback'
    # URIs determined by Google, below
    AUTH_URI = 'https://accounts.google.com/o/oauth2/auth'
    TOKEN_URI = 'https://accounts.google.com/o/oauth2/token'
    USER_INFO = 'https://www.googleapis.com/userinfo/v2/me'
    SCOPE = ['profile', 'email']

class Config:
    """Base config"""
    APP_NAME = "Test Google Login"
    SECRET_KEY = os.environ.get("SECRET_KEY") or "something secret"

class DevConfig(Config):
    """Dev config"""
    DEBUG = True
    USE_RELOADER = True
    SQLALCHEMY_DATABASE_URI = "postgresql://postgres:T0ky0Bound@localhost/SI364finalgazdgabr"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True

class ProdConfig(Config):
    """Production config"""
    DEBUG = False
    USE_RELOADER = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or "postgresql://postgres:T0ky0Bound@localhost/SI364finalgazdgabr"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True

# To set up different configurations for development of an application
config = {
    "dev": DevConfig,
    "prod": ProdConfig,
    "default": DevConfig
}

"""APP creation and configuration"""
app = Flask(__name__)
app.config.from_object(config['dev'])
db = SQLAlchemy(app)
manager = Manager(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"

""" Set up Shell context so it's easy to use the shell to debug (taken from Sample-Login-App) """
def make_shell_context():
    return dict(app=app, db=db, User=User)

manager.add_command("shell", Shell(make_context=make_shell_context))

######################################
#############  MODELS  ###############
######################################

##### Association Table #####
user_questions = db.Table('user_questions',db.Column('question_id',db.Integer, db.ForeignKey('questions.id')),db.Column('user_id',db.Integer, db.ForeignKey('users.id')))

""" For Google-specific auth """
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=True)
    avatar = db.Column(db.String(200))
    tokens = db.Column(db.Text)
    api_token = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    trivia = db.relationship('Trivia',secondary=user_questions,backref=db.backref('questions',lazy='dynamic'),lazy='dynamic')

class Trivia(db.Model):
    __tablename__ = "questions"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(1000))
    category = db.Column(db.String(100))
    difficulty = db.Column(db.String(50))
    type = db.Column(db.String(50))
    correct = db.Column(db.String(280))
    answ = db.relationship('WrongAnswer',backref='Trivia')

class WrongAnswer(db.Model):
    __tablename__ = "wrong_answers"
    id = db.Column(db.Integer, primary_key=True)
    wrong = db.Column(db.String(500))
    question_id = db.Column(db.Integer, db.ForeignKey("questions.id"))

class NewQuestion(db.Model):
    __tablename__ = "new"
    id = db.Column(db.Integer, primary_key=True)
    new_text = db.Column(db.String(1000))
    new_answer = db.Column(db.String(280))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    new_trivia = db.relationship('User',backref='NewQuestion')

""" IMPORTANT FUNCTION / MANAGEMENT """
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

""" OAuth Session creation """
def get_google_auth(state=None, token=None):
    if token:
        return OAuth2Session(Auth.CLIENT_ID, token=token)
    if state:
        return OAuth2Session(
            Auth.CLIENT_ID,
            state=state,
            redirect_uri=Auth.REDIRECT_URI)
    oauth = OAuth2Session(
        Auth.CLIENT_ID,
        redirect_uri=Auth.REDIRECT_URI,
        scope=Auth.SCOPE)
    return oauth

SuperCorrect = "MEow"

######################################
#############  FORMS  ################
######################################

class TriviaParams(FlaskForm):
    category = RadioField('Choose a category: ', choices=[('any','Any'),('9','General Knowledge'),('10','Entertainment: Books'),('29','Entertainment: Comics'),('11','Entertainment: Film'),('12','Entertainment: Music'),('13','Entertainment: Musicals & Theater'),('14','Entertainment: Television'),('15','Entertainment: Video Games'), ('16','Entertainment: Board Games'), ('31','Entertainment: Japanese Anime & Manga'), ('32','Entertainment: Cartoon & Animations'),('17','Science & Nature'), ('18','Science: Computers'),('19','Science: Mathematics'),('30','Science: Gadgets'),('20','Mythology'),('21','Sports'),('22','Geography'),('23','History'),('24','Politics'),('25','Art'),('26','Celebrities'),('27','Animals'),('28','Vehicles')], validators=[Required()])
    difficulty = RadioField('Choose a difficulty: ', choices=[('easy','Easy'),('medium','Medium'),('hard','Hard')], validators=[Required()])
    submit = SubmitField()

class PlayTrivia(FlaskForm):
    option =  RadioField('', choices=[], validators=[Required()])
    Corr = "meow"
    submit = SubmitField()

class CreateYourOwn(FlaskForm):
    question = StringField("Enter a new trivia question: ", validators=[Required()])
    answer = StringField("Enter its answer: ", validators=[Required()])
    submit = SubmitField()

    def validate_question(self, field):
        q = re.findall("^.*?$", field.data)
        if len(q) == 0:
            raise ValidationError("Don't forget the question mark!")

    def validate_answer(self, field):
        q = re.findall("?", field.data)
        if len(q) != 0:
            raise ValidationError("Be more confident in your answer!")

class UpdateButtonForm(FlaskForm):
    submit = SubmitField('Update')

class UpdateTriviaForm(FlaskForm):
    new_question = StringField("Updated question: ", validators=[Required()])
    new_answer = StringField("Updated answer: ", validators=[Required()])
    submit = SubmitField('Update')

class DeleteButtonForm(FlaskForm):
    submit = SubmitField('Delete')

######################################
########  HELPER FUNCTIONS  ##########
######################################

def get_or_create_session_token():
    token_url = "https://opentdb.com/api_token.php?command=request"
    token_dict = json.loads(requests.get(token_url).text)
    token = token_dict["token"]
    return token

def hit_trivia_api(category, difficulty, type):
    session = get_or_create_session_token()
    base_url = 'https://opentdb.com/api.php?'

    if category == 'any':
        params_dict = {"amount":'1', "difficulty":difficulty, "type":"multiple", "token":session}
        raw_result = json.loads(requests.get(base_url, params=params_dict).text)

    else:
        params_dict = {"amount":'1', "category":category, "difficulty":difficulty, "type":"multiple", "token":session}
        raw_result = json.loads(requests.get(base_url, params=params_dict).text)
    return raw_result

def create_trivia(db_session, category, difficulty, type):
    api_result = hit_trivia_api(category, difficulty, type)
    Quest = api_result['results'][0]['question']
    correctA = api_result['results'][0]['correct_answer']
    incorrectAs = api_result['results'][0]['incorrect_answers']

    new_trivia = Trivia(text=Quest, category=category, difficulty=difficulty, type=type, correct=correctA)
    db_session.add(new_trivia)
    db_session.commit()
    for ia in incorrectAs:
        wrong_ans = WrongAnswer(wrong=ia, question_id=new_trivia.id)
        db_session.add(wrong_ans)
        db_session.commit()

    return new_trivia

def get_or_create_new_question(db_session, q_text, a_text):
    newQ = NewQuestion.query.filter_by(new_text=q_text).first()
    if newQ:
        return newQ
    else:
        newQ = NewQuestion(new_text=q_text, new_answer=a_text, user_id=current_user.id)
        db_session.add(newQ)
        db_session.commit()
        return newQ

######################################
###########  ERROR HANDLING ##########
######################################

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

######################################
##########  ROUTES/VIEWS  ############
######################################

"""Should render a home template that contains the global navigation and main input form where users can set parameters for their trivia questions."""
@app.route('/', methods=["GET","POST"])
@login_required
def home():
    form = TriviaParams()
    return render_template('base.html', form=form)

"""This route should send user's input to the API and return/display trivia questions for the user to answer."""
@app.route('/trivia', methods=["GET","POST"])
@login_required
def play_trivia():
    choices = {}
    global SuperCorrect
    answerform = PlayTrivia()
    if request.method == "GET":
        Categ = request.args.get('category')
        Difi = request.args.get('difficulty')
        gen_qs = create_trivia(db.session, Categ, Difi, "multiple")
        wrong_1s = WrongAnswer.query.filter_by(question_id=gen_qs.id).all()
        dudes = [(gump.wrong , gump.wrong) for gump in wrong_1s] + [( gen_qs.correct, gen_qs.correct)]
        random.shuffle(dudes)
        SuperCorrect = gen_qs.correct
        answerform.option.choices = dudes
        return render_template('play.html', form=answerform, q=gen_qs.text, choices=choices, cont=0)

    if request.method == 'POST':
        user_answer = answerform.option.data
        correct_ans = SuperCorrect
        return render_template('play.html', form=answerform, ca=correct_ans, ya=user_answer, cont=1)

"""Renders a form and template that allows a user to input their own question and an answer for it, then save it."""
@app.route('/makeyourown', methods=["GET","POST"])
@login_required
def create_question():
    create_form = CreateYourOwn()
    if create_form.validate_on_submit():
        get_or_create_new_question(db.session, create_form.question.data, create_form.answer.data)
        flash("Successfully saved new question!")
        return redirect(url_for('create_question'))
    return render_template('create.html', form=create_form)

"""Retrieves all of a user's self-created trivia questions with answers and displays them."""
@app.route('/yourtrivia', methods=["GET","POST"])
@login_required
def see_my_questions():
    u_qs = NewQuestion.query.filter_by(user_id=current_user.id).all()
    uform = UpdateButtonForm()
    dform = DeleteButtonForm()
    return render_template('all_user_questions.html', delform=dform,upform=uform,qs=u_qs)

@app.route('/update/<q_id>',methods=["GET","POST"])
@login_required
def update(q_id):
    form = UpdateTriviaForm()
    if form.validate_on_submit():
        dq = NewQuestion.query.filter_by(id=q_id).first()
        dq.new_text = form.new_question.data
        dq.new_answer = form.new_answer.data
        db.session.commit()
        flash("Updated question!")
        return redirect(url_for('see_my_questions'))
    return render_template('update_trivia.html', form=form)

@app.route('/delete/<q>',methods=["GET","POST"])
@login_required
def delete(q):
    dq = NewQuestion.query.filter_by(id=q).first()
    db.session.delete(dq)
    db.session.commit()
    flash("Successfully deleted question!")
    return redirect(url_for('see_my_questions'))

#######################################
##### Login/Logout/Callback views #####
#######################################

@app.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    google = get_google_auth()
    auth_url, state = google.authorization_url(
        Auth.AUTH_URI, access_type='offline')
    session['oauth_state'] = state
    return render_template('login.html', auth_url=auth_url)

""" Taken from  the Sample-Login-OAuth-Example and adapted """
@app.route('/oauthCallback')
def callback():
    if current_user is not None and current_user.is_authenticated:
        return redirect(url_for('home'))
    if 'error' in request.args: # Good Q: 'what are request.args here, why do they matter?'
        if request.args.get('error') == 'access_denied':
            return 'You denied access.'
        return 'Error encountered.'
    # print(request.args, "ARGS")
    if 'code' not in request.args and 'state' not in request.args:
        return redirect(url_for('login'))
    else:
        google = get_google_auth(state=session['oauth_state'])
        try:
            token = google.fetch_token(
                Auth.TOKEN_URI,
                client_secret=Auth.CLIENT_SECRET,
                authorization_response=request.url)
        except HTTPError:
            return 'HTTPError occurred.'
        google = get_google_auth(token=token)
        resp = google.get(Auth.USER_INFO)
        if resp.status_code == 200:
            # print("SUCCESS 200") # For debugging/understanding
            user_data = resp.json()
            email = user_data['email']
            user = User.query.filter_by(email=email).first()
            if user is None:
                # print("No user...")
                user = User()
                user.email = email
            user.name = user_data['name']
            # print(token)
            user.tokens = json.dumps(token)
            user.avatar = user_data['picture']
            #user.api_token = get_or_create_session_token()
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for('home'))
        return 'Could not fetch your information.'

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == "__main__":
    db.create_all()
    manager.run()
