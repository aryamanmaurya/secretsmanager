from flask import render_template, request, jsonify, flash, redirect, url_for, session
from flask_login import login_required, current_user, login_user
from app import db
from app.models import User, ActivityLog, Project, ProjectShare
from app.forms import UserManagementForm, RegistrationForm
from app.utils.security import log_activity, get_client_ip
from datetime import datetime, timedelta

from . import admin_bp

@admin_bp.route('/')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('main.dashboard'))

    # Get statistics
    total_users = User.query.count()
    total_projects = Project.query.count()
    
    # Fix total_secrets calculation
    from app.models import Secret
    total_secrets = Secret.query.count()
    
    recent_activity = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(10).all()

    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         total_projects=total_projects,
                         total_secrets=total_secrets,
                         recent_activity=recent_activity)

@admin_bp.route('/users')
@login_required
def manage_users():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('main.dashboard'))

    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users)

@admin_bp.route('/users/create', methods=['GET', 'POST'])
@login_required
def create_user():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('main.dashboard'))

    form = RegistrationForm()

    if form.validate_on_submit():
        # Check if username or email already exists
        existing_user = User.query.filter((User.username == form.username.data) | (User.email == form.email.data)).first()
        if existing_user:
            flash('Username or email already exists.', 'danger')
            return render_template('admin/create_user.html', form=form)

        user = User(
            username=form.username.data,
            email=form.email.data,
            is_admin=False  # Default to non-admin, can be changed later
        )
        user.set_password(form.password.data)

        db.session.add(user)
        db.session.commit()

        log_activity(current_user.id, 'create_user', get_client_ip(),
                    f'Admin created user: {user.username}')

        flash('User created successfully!', 'success')
        return redirect(url_for('admin.manage_users'))

    return render_template('admin/create_user.html', form=form)


@admin_bp.route('/users/<int:user_id>/toggle_admin', methods=['POST'])
@login_required
def toggle_admin(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    user = User.query.get_or_404(user_id)

    # Prevent self-demotion if you're the only admin
    admin_count = User.query.filter_by(is_admin=True).count()
    if user.id == current_user.id and admin_count == 1:
        return jsonify({'success': False, 'error': 'Cannot remove admin privileges from the only admin user'}), 400

    user.is_admin = not user.is_admin
    db.session.commit()

    action = 'granted_admin' if user.is_admin else 'revoked_admin'
    log_activity(current_user.id, action, get_client_ip(),
                f'Admin {action} for user: {user.username}')

    return jsonify({'success': True, 'is_admin': user.is_admin})

@admin_bp.route('/users/<int:user_id>/toggle_active', methods=['POST'])
@login_required
def toggle_active(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    user = User.query.get_or_404(user_id)

    # Prevent self-deactivation
    if user.id == current_user.id:
        return jsonify({'success': False, 'error': 'Cannot deactivate your own account'}), 400

    user.is_active = not user.is_active
    db.session.commit()

    action = 'activated' if user.is_active else 'deactivated'
    log_activity(current_user.id, f'{action}_user', get_client_ip(),
                f'Admin {action} user: {user.username}')

    return jsonify({'success': True, 'is_active': user.is_active})

@admin_bp.route('/users/<int:user_id>/toggle_sharing', methods=['POST'])
@login_required
def toggle_sharing(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    user = User.query.get_or_404(user_id)
    user.sharing_enabled = not user.sharing_enabled
    db.session.commit()

    action = 'enabled_sharing' if user.sharing_enabled else 'disabled_sharing'
    log_activity(current_user.id, action, get_client_ip(),
                f'Admin {action} for user: {user.username}')

    return jsonify({'success': True, 'sharing_enabled': user.sharing_enabled})

@admin_bp.route('/users/<int:user_id>/reset_password', methods=['POST'])
@login_required
def reset_user_password(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    user = User.query.get_or_404(user_id)
    
    # Get password from JSON data
    if not request.is_json:
        return jsonify({'success': False, 'error': 'Content-Type must be application/json'}), 400
        
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No JSON data received'}), 400
        
    new_password = data.get('new_password')

    if not new_password or len(new_password) < 8:
        return jsonify({'success': False, 'error': 'Password must be at least 8 characters long'}), 400

    # Check password complexity
    import re
    has_upper = re.search(r'[A-Z]', new_password)
    has_lower = re.search(r'[a-z]', new_password)
    has_digit = re.search(r'\d', new_password)
    has_special = re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password)
    
    if not (has_upper and has_lower and has_digit and has_special):
        return jsonify({'success': False, 'error': 'Password must contain uppercase, lowercase, digit, and special character'}), 400

    user.set_password(new_password)
    user.login_attempts = 0
    user.locked_until = None
    db.session.commit()

    log_activity(current_user.id, 'reset_user_password', get_client_ip(),
                f'Admin reset password for user: {user.username}')

    return jsonify({'success': True, 'message': 'Password reset successfully!'})


@admin_bp.route('/users/<int:user_id>/impersonate')
@login_required
def impersonate(user_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('main.dashboard'))

    user = User.query.get_or_404(user_id)

    # Store original user ID in session for reverting
    original_user_id = current_user.id
    login_user(user)
    session['original_user_id'] = original_user_id

    log_activity(original_user_id, 'impersonate', get_client_ip(),
                f'Admin impersonated user: {user.username}')

    flash(f'Now impersonating user: {user.username}', 'info')
    return redirect(url_for('main.dashboard'))

@admin_bp.route('/revert_impersonate')
@login_required
def revert_impersonate():
    original_user_id = session.get('original_user_id')

    if not original_user_id:
        flash('No impersonation session found.', 'warning')
        return redirect(url_for('main.dashboard'))

    original_user = User.query.get(original_user_id)
    if original_user:
        login_user(original_user)
        session.pop('original_user_id', None)

        log_activity(original_user_id, 'revert_impersonate', get_client_ip(),
                    'Admin reverted from impersonation')

        flash('Reverted to admin account.', 'success')

    return redirect(url_for('admin.admin_dashboard'))

@admin_bp.route('/activity')
@login_required
def activity_logs():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('main.dashboard'))

    page = request.args.get('page', 1, type=int)
    per_page = 50

    activities = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template('admin/activity_logs.html', activities=activities)
