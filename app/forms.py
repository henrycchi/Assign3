from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from app.models import User

class SpellForm(FlaskForm):
    inputtext = StringField('CheckText', id='inputtext', validators=[DataRequired()])
    submit = SubmitField('Submit')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()], id='uname')
    password = PasswordField('Password', validators=[DataRequired()], id='pword')
    twofa = StringField('2FA - ENTER YOUR CELL NUMBER', validators=[DataRequired()], id='2fa')
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()], id='uname')
    twofa = StringField('2FA - ENTER YOUR CELL NUMBER', validators=[DataRequired()], id='2fa')
    password = PasswordField('Password', validators=[DataRequired()], id='pword')
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')

    def validate_twofa(self, twofa):
        user = User.query.filter_by(twofa=twofa.data).first()
        if user is not None:
            raise ValidationError('Please use a different Cell Number.')


