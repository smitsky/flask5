# Full app.py (WTForms + CSRF integrated, minimal and ready)
from flask import Flask, render_template, redirect, url_for, request, flash
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse, urljoin

from flask_wtf import CSRFProtect
from forms import LoginForm, RegisterForm

from dotenv import load_dotenv
load_dotenv()  # ← This loads .env into os.environ

app = Flask(__name__)
import os
app.secret_key = os.getenv('FLASK_SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.permanent_session_lifetime = timedelta(days=5)

db = SQLAlchemy(app)

# Login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# CSRF protection
csrf = CSRFProtect(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        flash("Already logged in.")
        return redirect(url_for('home'))

    form = RegisterForm()
    # Always pass form=form when rendering template so the template has the variable
    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip() if form.email.data else None
        password = form.password.data

        if User.query.filter_by(username=username).first():
            flash("Username already taken.")
            return render_template('register.html', form=form)

        u = User(username=username, email=email)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        flash("Account created — please log in.")
        return redirect(url_for('login'))

    # GET or validation failed
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash("Already logged in.")
        return redirect(url_for('home'))

    form = LoginForm()
    next_page = request.args.get('next')

    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data
        remember = form.remember.data
        posted_next = request.form.get('next')
        if posted_next:
            next_page = posted_next

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user, remember=remember)
            flash("Logged in.")
            if next_page and is_safe_url(next_page):
                return redirect(next_page)
            return redirect(url_for('home'))

        flash("Invalid username or password.")
        return render_template('login.html', form=form, next=next_page)

    return render_template('login.html', form=form, next=next_page)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out.")
    return redirect(url_for('home'))

@app.route('/protected')
@login_required
def protected():
    return render_template('protected.html')

@app.cli.command('init-db')
def init_db():
    db.create_all()
    print("Database initialized.")

if __name__ == '__main__':
    app.run(debug=True)