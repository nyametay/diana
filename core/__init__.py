from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta
from dotenv import load_dotenv
from flask import Flask
import os


# Load .env variables
load_dotenv()

app = Flask(__name__)
app.permanent_session_lifetime = timedelta(days=10)

# ---------- Config ----------
SECRET_KEY = os.getenv('SECRET_KEY')
DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "super-secret-change-me")
ACCESS_EXPIRES_MINUTES = int(os.getenv("ACCESS_EXPIRES_MINUTES", 15))
REFRESH_EXPIRES_DAYS = int(os.getenv("REFRESH_EXPIRES_DAYS", 30))


# Secret Key
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=ACCESS_EXPIRES_MINUTES)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=REFRESH_EXPIRES_DAYS)


# Initialize DB
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Import routes
from core import routes
