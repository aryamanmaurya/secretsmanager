import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'mysql://a:a@localhost/password_manager'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security settings
    SESSION_TIMEOUT = timedelta(minutes=15)
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = timedelta(minutes=15)
    
    # File upload settings
    MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB
    ALLOWED_EXTENSIONS = {'txt', 'pem', 'key', 'crt', 'cer', 'pfx', 'p12'}
