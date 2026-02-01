import os
from functools import wraps
from flask import (
    Flask, render_template, request,
    redirect, url_for, session,
    flash, abort, g
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# -------------------------------------------------
# APP CONFIG
# -------------------------------------------------

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-this-secret")
app.config["ADMIN_SECRET_KEY"] = os.getenv("ADMIN_SECRET_KEY", "4675")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "appointment_system.db")

app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# -------------------------------------------------
# MODELS
# -------------------------------------------------

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default="user")

    appointments = db.relationship("Appointment", backref="user", lazy=True)


class Appointment(db.Model):
    __tablename__ = "appointments"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    date = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(20), nullable=False)
    reason = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default="Pending")


# -------------------------------------------------
# MIDDLEWARE
# -------------------------------------------------

@app.before_request
def load_logged_in_user():
    user_id = session.get("user_id")
    g.user = db.session.get(User, user_id) if user_id else None


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not g.user:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not g.user or g.user.role != "admin":
            abort(403)
        return f(*args, **kwargs)
    return wrapper


# -------------------------------------------------
# HEALTH CHECK (IMPORTANT)
# -------------------------------------------------

@app.route("/health")
def health():
    return "OK", 200


# -------------------------------------------------
# ROUTES
# -------------------------------------------------

@app.route("/")
def index():
    return render_template("home.html")


# ---------------- AUTH ----------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("user_dashboard"))

    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]

        if User.query.filter_by(email=email).first():
            flash("Email already exists", "error")
            return redirect(url_for("register"))

        user = User(
            name=name,
            email=email,
            password=generate_password_hash(password),
            role="user"
        )

        db.session.add(user)
        db.session.commit()

        flash("Registration successful", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("index"))

    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            return redirect(
                url_for("admin_dashboard")
                if user.role == "admin"
                else url_for("user_dashboard")
            )

        flash("Invalid credentials", "error")

    return render_template("login.html")


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        admin = User.query.filter_by(email=email, role="admin").first()

        if admin and check_password_hash(admin.password, password):
            session["user_id"] = admin.id
            return redirect(url_for("admin_dashboard"))

        flash("Invalid admin credentials", "error")

    return render_template("admin_login.html")


@app.route("/admin/register", methods=["GET", "POST"])
def admin_register():
    if request.method == "POST":
        if request.form["secret_key"] != app.config["ADMIN_SECRET_KEY"]:
            flash("Invalid admin secret key", "error")
            return redirect(url_for("admin_register"))

        admin = User(
            name=request.form["name"],
            email=request.form["email"],
            password=generate_password_hash(request.form["password"]),
            role="admin"
        )

        db.session.add(admin)
        db.session.commit()

        flash("Admin registered successfully", "success")
        return redirect(url_for("admin_login"))

    return render_template("admin_register.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------- USER ----------------

@app.route("/dashboard")
@login_required
def user_dashboard():
    if g.user.role == "admin":
        return redirect(url_for("admin_dashboard"))
    return render_template("dashboard.html")


@app.route("/book", methods=["GET", "POST"])
@login_required
def book():
    if request.method == "POST":
        appointment = Appointment(
            user_id=g.user.id,
            date=request.form["date"],
            time=request.form["time"],
            reason=request.form["reason"]
        )
        db.session.add(appointment)
        db.session.commit()
        return redirect(url_for("my_appointments"))

    return render_template("book.html")


@app.route("/my_appointments")
@login_required
def my_appointments():
    appts = Appointment.query.filter_by(user_id=g.user.id).all()
    return render_template("my_appointments.html", appointments=appts)


# ---------------- ADMIN ----------------

@app.route("/admin")
@admin_required
def admin_dashboard():
    pending = Appointment.query.filter_by(status="Pending").all()
    all_appts = Appointment.query.all()
    return render_template(
        "admin.html",
        pending_appointments=pending,
        all_appointments=all_appts
    )


@app.route("/admin/approve/<int:id>")
@admin_required
def approve(id):
    appt = db.session.get(Appointment, id)
    appt.status = "Approved"
    db.session.commit()
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/reject/<int:id>")
@admin_required
def reject(id):
    appt = db.session.get(Appointment, id)
    appt.status = "Rejected"
    db.session.commit()
    return redirect(url_for("admin_dashboard"))


# -------------------------------------------------
# ERRORS
# -------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template("404.html"), 403


@app.errorhandler(500)
def server_error(e):
    return render_template("500.html"), 500
