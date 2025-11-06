# Full app.py (WTForms + CSRF integrated, minimal and ready) — upgraded to lazily bump PBKDF2 iterations
from flask import Flask, render_template, redirect, url_for, request, flash
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse, urljoin
import os

from flask_wtf import CSRFProtect
from forms import LoginForm, RegisterForm

from dotenv import load_dotenv
# In production (Render), this is ignored or benign.
# We keep it for local development environments.
load_dotenv() 

app = Flask(__name__)
# NOTE: Moving db and migrate initialization below config setup is often safer.
# We will execute the config setup first.

# --- Environment Variable Setup for Render and Local ---

# 1. Get the Secret Key (Required for both local and Render)
app.secret_key = os.getenv('FLASK_SECRET_KEY')

# 2. Dynamic Database URI Configuration
DATABASE_URL = os.environ.get('DATABASE_URL')

if DATABASE_URL:
    # --- Production Configuration (Render/PostgreSQL) ---
    # Render's URL starts with 'postgres://'. SQLAlchemy recommends 'postgresql://' for the driver.
    # We use .replace to ensure compatibility with modern psycopg2/SQLAlchemy.
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL.replace("postgres://", "postgresql://", 1)
else:
    # --- Local Configuration (SQLite) ---
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'

# --- Common Configurations ---
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.permanent_session_lifetime = timedelta(days=5)

# PBKDF2 target iterations (configurable via env)
app.config['PBKDF2_ITERATIONS'] = int(os.getenv('PBKDF2_ITERATIONS', '200000'))
# Hash algorithm used by werkzeug generate_password_hash (we use pbkdf2:sha256)
app.config['PBKDF2_ALGORITHM'] = 'pbkdf2:sha256'

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
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password, iterations=None):
        """
        Create and store a password hash using the configured PBKDF2 algorithm + iterations.
        By default, uses app.config['PBKDF2_ITERATIONS'].
        """
        if iterations is None:
            iterations = app.config.get('PBKDF2_ITERATIONS', 200000)
        method = f"{app.config.get('PBKDF2_ALGORITHM', 'pbkdf2:sha256')}:{iterations}"
        # werkzeug's generate_password_hash stores method and salt in the returned string
        self.password_hash = generate_password_hash(password, method=method)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def needs_rehash(self, target_iterations=None):
        """
        Parse stored hash method to determine iteration count and return True if
        stored iterations < target_iterations.
        """
        if target_iterations is None:
            target_iterations = app.config.get('PBKDF2_ITERATIONS', 200000)
        # Stored werkzeug hash looks like: "pbkdf2:sha256:260000$<salt>$<hash>"
        try:
            method_part = self.password_hash.split('$', 1)[0]  # "pbkdf2:sha256:260000"
            parts = method_part.split(':')  # ["pbkdf2", "sha256", "260000"]
            if len(parts) >= 3:
                stored_iters = int(parts[2])
            else:
                # No explicit iterations encoded — treat as very old/small value
                stored_iters = 0
        except Exception:
            stored_iters = 0
        return stored_iters < int(target_iterations)

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
        # set_password uses the configured PBKDF2 iterations
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

            # Lazy upgrade: if stored hash uses fewer iterations than our target,
            # re-hash now (we have plaintext password).
            try:
                if user.needs_rehash():
                    user.set_password(password)  # uses app.config['PBKDF2_ITERATIONS']
                    db.session.add(user)
                    db.session.commit()
                    # Optionally log/metric that a rehash occurred
                    app.logger.info(f"Upgraded password hash iterations for user_id={user.id}")
            except Exception as e:
                app.logger.exception("Failed to upgrade password hash (non-fatal)")

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
    print("Database initialized.")

# In app.py, add this to ensure table creation can be run via CLI
@app.cli.command('create-db')
def create_db_tables():
    """Creates database tables defined in models."""
    with app.app_context():
        db.create_all()
    print("Database tables created successfully.")

if __name__ == '__main__':
    app.run(debug=True)
