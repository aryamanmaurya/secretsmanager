from app import create_app
from app.models import db, User

def create_admin_user():
    app = create_app()
    
    with app.app_context():
        try:
            # Create all tables
            db.create_all()
            print("✓ Database tables created successfully!")
            
            # Check if admin already exists
            admin = User.query.filter_by(username='admin').first()
            if admin:
                print("✓ Admin user already exists!")
                return True
                
            # Create admin user
            admin_user = User(
                username='admin',
                email='admin@email.com',
                is_admin=True,
                is_active=True,
                sharing_enabled=True
            )
            admin_user.set_password('admin123')
            
            db.session.add(admin_user)
            db.session.commit()
            
            print("✓ Admin user created successfully!")
            print("  Username: admin")
            print("  Email: admin@email.com") 
            print("  Password: admin123")
            return True
            
        except Exception as e:
            print(f"✗ Error: {e}")
            return False

if __name__ == '__main__':
    success = create_admin_user()
    if success:
        print("\n🎉 Setup completed! You can now run: python3 run.py")
    else:
        print("\n❌ Setup failed. Please check the error above.")
