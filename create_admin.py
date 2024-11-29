from app import db, User  # Import the app and models
from werkzeug.security import generate_password_hash

def create_admin():
    username = "admin"  # Change as needed
    email = "admin@gmail.com"  # Change as needed
    password = "admin123"  # Change as needed
    role = "admin"
    
    # Check if admin already exists
    existing_admin = User.query.filter_by(email=email).first()
    if existing_admin:
        print("Admin already exists!")
        return

    # Create new admin
    new_admin = User(
        username=username,
        email=email,
        role=role,
        address=None,
        phone=None,
        pincode=None,
        service_expertise=None,
        experience=None,
        about=None,
        profile_pic=None,
    )
    new_admin.set_password(password)  # Hash the password

    db.session.add(new_admin)
    db.session.commit()
    print("Admin created successfully!")

if __name__ == "__main__":
    from app import app  # Import the app instance

    with app.app_context():
        create_admin()
