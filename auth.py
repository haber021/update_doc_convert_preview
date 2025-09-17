from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from app import app
from extensions import db
from models import User, Role
from utils import log_user_action

auth = Blueprint('auth', __name__)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = bool(request.form.get('remember'))

        if not username or not password:
            flash('Please fill in all fields.', 'error')
            return render_template('login.html')

        # Find user
        user = User.query.filter_by(username=username).first()

        if user and user.is_active and check_password_hash(user.password_hash, password):
            # Update last login
            user.last_login = datetime.utcnow()
            db.session.commit()

            # Log the login
            log_user_action(user.id, 'login', None, f"User logged in with role: {user.role.name}")

            login_user(user, remember=remember)

            # Redirect to next page or dashboard
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)

            flash(f'Welcome back, {user.get_full_name()}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')

        # Log failed login attempt
        if user:
            log_user_action(user.id, 'failed_login', None, f"Failed login attempt")
    
    # GET request or failed POST - show login form
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    # Log the logout
    log_user_action(current_user.id, 'logout', None, "User logged out")
    
    logout_user()
    # flash(message, category)
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Only allow registration if current user is admin or if no users exist
    if User.query.count() > 0 and (not current_user.is_authenticated or not current_user.can_access_admin()):
        flash('Registration is restricted. Please contact an administrator.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        student_id = request.form.get('student_id')
        role_id = request.form.get('role_id')
        
        # Validation
        if not all([username, email, password, confirm_password, first_name, last_name, role_id]):
            flash('Please fill in all required fields.', 'error')
            return render_template('register.html', roles=Role.query.all())
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('register.html', roles=Role.query.all())
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('register.html', roles=Role.query.all())
        
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('register.html', roles=Role.query.all())
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'error')
            return render_template('register.html', roles=Role.query.all())
        
        if student_id and User.query.filter_by(student_id=student_id).first():
            flash('Student ID already exists.', 'error')
            return render_template('register.html', roles=Role.query.all())
        
        # Create new user
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            first_name=first_name,
            last_name=last_name,
            student_id=student_id if student_id else None,
            role_id=role_id
        )
        
        db.session.add(user)
        db.session.commit()
        
        # Log the registration
        log_user_action(user.id, 'register', None, f"New user registered with role: {user.role.name}")
        
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    # GET request - show registration form
    roles = Role.query.all()
    return render_template('register.html', roles=roles)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([current_password, new_password, confirm_password]):
            flash('Please fill in all fields.', 'error')
            return render_template('settings.html')
        
        if not check_password_hash(current_user.password_hash, current_password):
            flash('Current password is incorrect.', 'error')
            return render_template('settings.html')
        
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return render_template('settings.html')
        
        if len(new_password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('settings.html')
        
        # Update password
        current_user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        # Log the password change
        log_user_action(current_user.id, 'password_change', None, "User changed password")
        
        flash('Password changed successfully!', 'success')
        return redirect(url_for('settings'))
    
    return render_template('settings.html')
