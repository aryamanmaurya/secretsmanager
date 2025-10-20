from flask import request
from app.models import ActivityLog, User, db
from datetime import datetime, timedelta

def log_activity(user_id, action, ip_address, details=None):
    """Log user activity"""
    activity = ActivityLog(
        user_id=user_id,
        action=action,
        ip_address=ip_address,
        details=details
    )
    db.session.add(activity)
    db.session.commit()

def record_failed_attempt(user):
    """Record failed login attempt and lock account if necessary"""
    user.login_attempts += 1
    
    if user.login_attempts >= 5:
        user.locked_until = datetime.utcnow() + timedelta(minutes=15)
    
    db.session.commit()

def check_account_lock(user):
    """Check if account is locked and reset if lock period has passed"""
    if user.locked_until and user.locked_until <= datetime.utcnow():
        user.login_attempts = 0
        user.locked_until = None
        db.session.commit()
        return False
    return user.locked_until and user.locked_until > datetime.utcnow()

def get_client_ip():
    """Get client IP address considering proxies"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr
