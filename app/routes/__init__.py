from flask import Blueprint

# Define blueprints here
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
main_bp = Blueprint('main', __name__)
projects_bp = Blueprint('projects', __name__, url_prefix='/projects')
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# Import routes after blueprint definitions to avoid circular imports
from . import auth, main, projects, admin
