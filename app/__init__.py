from flask import Flask, request, redirect, render_template, make_response, Response
from config import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
app.secret_key = secrets.token_urlsafe(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///theDB.db'
csrf = CSRFProtect(app)
db = SQLAlchemy()

from app import routes, models

