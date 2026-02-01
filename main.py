import os
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask App
app = Flask(__name__)
app.config['SECRET_KEY'] = '4675'
app.config['ADMIN_SECRET_KEY'] = '4675' # Ideally use env variable
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///appointment_system.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Extensions
db = SQLAlchemy(main)

# ------------------------------
# DATABASE MODELS
# ------------------------------

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')  # 'user' or 'admin'
    appointments = db.relationship('Appointment', backref='user', lazy=True)

class Appointment(db.Model):
    __tablename__ = 'appointments'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    date = db.Column(db.String(20), nullable=False)  # Storing as string YYYY-MM-DD for simplicity
    time = db.Column(db.String(20), nullable=False)
    reason = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default='Pending')  # Pending, Approved, Rejected

# ------------------------------
# HELPER FUNCTIONS & DECORATORS
# ------------------------------

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        g.user = db.session.get(User, user_id)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None or g.user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# ------------------------------
# ROUTES
# ------------------------------

@app.route('/')
def index():
    return render_template('home.html')

# --- AUTHENTICATION ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if g.user:
        return redirect(url_for('user_dashboard'))
    
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        
        user_exists = User.query.filter_by(email=email).first()
        if user_exists:
            flash('Email already registered!', 'error')
            return redirect(url_for('register'))
            
        hashed_password = generate_password_hash(password)
        new_user = User(name=name, email=email, password=hashed_password, role='user')
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration.', 'error')
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid email or password.', 'error')
            
    return render_template('login.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if g.user:
        if g.user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        user = User.query.filter_by(email=email).first()
        
        # Check if user exists, password is correct AND is admin
        if user and user.role == 'admin' and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('admin_dashboard'))
        elif user and user.role != 'admin':
             flash('Access Denied. You are not an admin.', 'error')
        else:
            flash('Invalid admin credentials.', 'error')
            
    return render_template('admin_login.html')

@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if g.user:
        if g.user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        secret_key = request.form['secret_key']

        # Validation
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('admin_register'))
            
        if secret_key != app.config['ADMIN_SECRET_KEY']:
            flash('Invalid Admin Secret Key. Access Denied.', 'error')
            return redirect(url_for('admin_register'))

        user_exists = User.query.filter_by(email=email).first()
        if user_exists:
            flash('Email already registered!', 'error')
            return redirect(url_for('admin_register'))

        hashed_password = generate_password_hash(password)
        new_admin = User(name=name, email=email, password=hashed_password, role='admin')

        try:
            db.session.add(new_admin)
            db.session.commit()
            flash('Admin registration successful! Please login.', 'success')
            return redirect(url_for('admin_login'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'error')

    return render_template('admin_register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# --- USER FEATURES ---

@app.route('/dashboard')
@login_required
def user_dashboard():
    if g.user.role == 'admin':
        return redirect(url_for('admin_dashboard'))
    return render_template('dashboard.html', user=g.user)

@app.route('/book', methods=['GET', 'POST'])
@login_required
def book_appointment():
    if request.method == 'POST':
        date = request.form['date']
        time = request.form['time']
        reason = request.form['reason']
        
        # Basic Validation
        if not date or not time or not reason:
            flash('All fields are required.', 'error')
            return redirect(url_for('book_appointment'))
            
        new_appointment = Appointment(
            user_id=g.user.id,
            date=date,
            time=time,
            reason=reason,
            status='Pending'
        )
        
        try:
            db.session.add(new_appointment)
            db.session.commit()
            flash('Appointment booked successfully! Status: Pending.', 'success')
            return redirect(url_for('my_appointments'))
        except Exception as e:
            db.session.rollback()
            flash('Error booking appointment.', 'error')
            
    return render_template('book.html')

@app.route('/my_appointments')
@login_required
def my_appointments():
    appointments = Appointment.query.filter_by(user_id=g.user.id).order_by(Appointment.date.desc()).all()
    return render_template('my_appointments.html', appointments=appointments)

@app.route('/cancel_appointment/<int:id>')
@login_required
def cancel_appointment(id):
    appointment = db.session.get(Appointment, id)
    if appointment and appointment.user_id == g.user.id:
        if appointment.status == 'Pending':
            db.session.delete(appointment)
            db.session.commit()
            flash('Appointment cancelled.', 'success')
        else:
            flash('Cannot cancel processed appointments.', 'warning')
    else:
        flash('Appointment not found or access denied.', 'error')
    return redirect(url_for('my_appointments'))

# --- ADMIN FEATURES ---

@app.route('/admin')
@admin_required
def admin_dashboard():
    pending_appointments = Appointment.query.filter_by(status='Pending').order_by(Appointment.date.asc()).all()
    all_appointments = Appointment.query.order_by(Appointment.date.desc()).all()
    return render_template('admin.html', pending_appointments=pending_appointments, all_appointments=all_appointments, user=g.user)

@app.route('/admin/approve/<int:id>')
@admin_required
def approve_appointment(id):
    appointment = db.session.get(Appointment, id)
    if appointment:
        appointment.status = 'Approved'
        db.session.commit()
        flash(f'Appointment ID {id} Approved.', 'success')
    else:
        flash('Appointment not found.', 'error')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject/<int:id>')
@admin_required
def reject_appointment(id):
    appointment = db.session.get(Appointment, id)
    if appointment:
        appointment.status = 'Rejected'
        db.session.commit()
        flash(f'Appointment ID {id} Rejected.', 'success')
    else:
        flash('Appointment not found.', 'error')
    return redirect(url_for('admin_dashboard'))

# --- ERROR HANDLERS ---

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden_error(e):
    return render_template('404.html'), 403 # Be discreet, or use custom 403 page

# Setup Database
with app.app_context():
    db.create_all()
    # Check if a default admin exists, if not create one for testing
    admin_exists = User.query.filter_by(role='admin').first()
    if not admin_exists:
        hashed_pw = generate_password_hash('admin123')
        default_admin = User(name='System Admin', email='admin@example.com', password=hashed_pw, role='admin')
        db.session.add(default_admin)
        db.session.commit()
        print("Default admin created: admin@example.com / admin123")

if __name__ == '__main__':
    app.run(debug=True)
