from datetime import datetime
from app import db, login
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    user_id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    uname = db.Column(db.String(25), nullable=False, unique=True)

    pword = db.Column(db.String(80), nullable=False)

    twofa = db.Column(db.String(25))

    isAdmin = db.Column(db.Boolean, nullable=False)

    def __init__(self, uname, pword, twofa):
        self.uname = uname
        self.pword = pword
        self.twofa = twofa

    def getPassword(self):
        return self.pword

    def get2FA(self):
        return self.twofa

    def getUname(self):
        return self.uname

    def get_id(self):
        return self.getUname()

    def __repr__(self):
        return '<User {}>'.format(self.username)

class LoginRecord(db.Model):
    __tablename__ = 'login_records'
    record_number =  db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    log_on = db.Column(db.DateTime, nullable=False)
    log_off = db.Column(db.DateTime, nullable=True)
    user = db.relationship(User)

class QueryRecord(db.Model):
    __tablename__ = 'query_records'
    record_number =  db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    query_text = db.Column(db.Text, nullable=True)
    query_result  = db.Column(db.Text, nullable=True)
    time = db.Column(db.DateTime, nullable=False)
    user = db.relationship(User)


@login_manager.user_loader
def load_user(id):
    existing_user = User.query.filter_by(uname=id).first()
    return existing_user

with app.app_context():
    db.init_app(app)
    db.create_all()
    if not load_user('admin'):
         adminUser = User('admin', sha256_crypt.hash('Administrator@1'), '12345678901')
         adminUser.isAdmin = True
         db.session.add(adminUser)
         db.session.commit()

class UserForm(FlaskForm):
    uname = StringField('User Name:', validators=[DataRequired()])
    pword = StringField('Password: ', validators=[DataRequired()])
    twofa = StringField('2FA Token:', validators=[], id='2fa')


def addUser(uname, pword, twofa):
    user = User(uname, sha256_crypt.hash(pword), twofa)
    user.isAdmin = False
    db.session.add(user)
    db.session.commit()

def passwordMatch(user, pword):
    if sha256_crypt.verify(pword, user.getPassword()):
        return True
    else:
        return False


def twofaMatch(user, twofa):
    if user.get2FA() == twofa:
        return True
    else:
        return False

def addLogonRecord(uname):
    record = LoginRecord()
    record.user_id = uname
    record.log_on = datetime.datetime.utcnow()
    db.session.add(record)
    db.session.commit()

def updateLogonRecordAtLogoff(uname):
   earliestLogin = LoginRecord.query.filter_by(user_id=uname, log_off=None).order_by(LoginRecord.log_on).first()
   earliestLogin.log_off = datetime.datetime.utcnow()
   db.session.add(earliestLogin)
   db.session.commit()

def addQueryRecord(querytext, queryresult):
    query = QueryRecord()
    query.user_id = current_user.getUname()
    query.query_text = querytext
    query.query_result = queryresult
    query.time = datetime.datetime.utcnow()
    db.session.add(query)
    db.session.commit()

def secureResponse(render):
    response = make_response(render)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src '127.0.0.1:5000'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return response

@app.errorhandler(404)
def not_found(e):
    return secureResponse(render_template("PageNotFound.html"))




