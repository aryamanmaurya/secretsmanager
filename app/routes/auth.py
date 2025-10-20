from flask import render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User, ActivityLog
from app.forms import LoginForm, RegistrationForm
from app.utils.security import log_activity, check_account_lock, record_failed_attempt
from datetime import datetime, timedelta
import os

from . import auth_bp

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        # Check if user exists and account is locked
        if user and user.is_locked():
            flash('Account is temporarily locked due to too many failed attempts. Please try again later.', 'danger')
            return render_template('auth/login.html', form=form)
        
        # Check credentials
        if user and user.check_password(form.password.data) and user.is_active:
            login_user(user, remember=form.remember_me.data)
            user.login_attempts = 0
            user.locked_until = None
            db.session.commit()
            
            log_activity(current_user.id, 'login', request.remote_addr, f'User logged in successfully')
            flash('Login successful!', 'success')
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('main.dashboard'))
        else:
            if user:
                record_failed_attempt(user)
                attempts_left = 5 - user.login_attempts
                if attempts_left <= 0:
                    flash('Account locked due to too many failed attempts. Please try again in 15 minutes.', 'danger')
                else:
                    flash(f'Invalid username or password. {attempts_left} attempts remaining.', 'danger')
            else:
                flash('Invalid username or password.', 'danger')
    
    return render_template('auth/login.html', form=form)

@auth_bp.route('/logout')
@login_required
def logout():
    log_activity(current_user.id, 'logout', request.remote_addr, f'User logged out')
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    # Only allow registration if no users exist yet (first admin) or if user is admin
    user_count = User.query.count()
    if user_count > 0 and (not current_user.is_authenticated or not current_user.is_admin):
        flash('Registration is disabled. Please contact an administrator.', 'warning')
        return redirect(url_for('auth.login'))
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        # Check if username or email already exists
        existing_user = User.query.filter((User.username == form.username.data) | (User.email == form.email.data)).first()
        if existing_user:
            flash('Username or email already exists.', 'danger')
            return render_template('auth/register.html', form=form)
        
        user = User(
            username=form.username.data,
            email=form.email.data,
            is_admin=(user_count == 0)  # First user becomes admin
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        log_activity(user.id, 'registration', request.remote_addr, f'New user registered: {user.username}')
        
        if user_count == 0:
            flash('First admin user created successfully! Please log in.', 'success')
        else:
            flash('User registered successfully!', 'success')
        
        return redirect(url_for('auth.login'))
    
    return render_template('auth/register.html', form=form)
