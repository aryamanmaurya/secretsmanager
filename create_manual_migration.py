from app import create_app, db
from app.models import User, Project, Secret, ProjectShare, ActivityLog

app = create_app()

with app.app_context():
    # Generate migration manually
    from flask_migrate import Migrate
    migrate = Migrate(app, db)
    
    import os
    from alembic.config import Config
    from alembic import command
    
    # Initialize migrations
    if not os.path.exists('migrations'):
        command.init(Config("alembic.ini"), 'migrations')
    
    # Create migration
    alembic_cfg = Config("migrations/alembic.ini")
    command.revision(alembic_cfg, autogenerate=True, message="Initial tables")
    
    print("Manual migration created!")
