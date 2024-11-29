from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from validate_email_address import validate_email
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configuration
app.secret_key = "secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///homeglam.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = "static/uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# Initialize database
db = SQLAlchemy(app)

# Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), nullable=False)
    email = db.Column(db.String(40), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # Role: 'customer', 'professional', 'admin'
    address = db.Column(db.String(255), nullable=True)
    phone = db.Column(db.String(15), nullable=True)
    pincode = db.Column(db.String(10), nullable=True)
    service_expertise = db.Column(db.String(100), nullable=True)
    experience = db.Column(db.String(100), nullable=True)
    about = db.Column(db.Text, nullable=True)
    profile_pic = db.Column(db.String(255), nullable=True)  # Store profile picture path

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# Routes
@app.route('/')
@app.route('/login')
def login():
    message = session.pop("message", None)
    status = session.pop("status", None)
    return render_template('login.html', message=message, status=status)

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/register/customer', methods=["GET", "POST"])
def register_customer():
    if request.method == "POST":
        username = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        address = request.form.get("address")
        phone = request.form.get("phone")
        pincode = request.form.get("pincode")
        profile_pic = request.files.get("profile_pic")

        filename = None
        if profile_pic and profile_pic.filename:
            filename = secure_filename(profile_pic.filename)
            profile_pic.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        # Email validation
        if not validate_email(email):
            session["message"] = "Invalid email format!"
            session["status"] = "danger"
            return redirect(url_for("register_customer"))

        # Check if user already exists
        if User.query.filter_by(email=email).first():
            session["message"] = "User with this email already exists!"
            session["status"] = "danger"
            return redirect(url_for("register_customer"))

        # Register the user
        new_user = User(
            username=username,
            email=email,
            role="customer",
            address=address,
            phone=phone,
            pincode=pincode,
            profile_pic=filename,
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        session["message"] = "Registration successful!"
        session["status"] = "success"
        return redirect(url_for("login"))

    message = session.pop("message", None)
    status = session.pop("status", None)
    return render_template("register_customer.html", message=message, status=status)


@app.route('/register/professional', methods=["GET", "POST"])
def register_professional():
    if request.method == "POST":
        username = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        address = request.form.get("address")
        phone = request.form.get("phone")
        pincode = request.form.get("pincode")
        service_expertise = request.form.get("service_expertise")
        experience = request.form.get("experience")
        about = request.form.get("about")
        profile_pic = request.files.get("profile_pic")

        filename = None
        if profile_pic and profile_pic.filename:
            filename = secure_filename(profile_pic.filename)
            profile_pic.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        # Email validation
        if not validate_email(email):
            session["message"] = "Invalid email format!"
            session["status"] = "danger"
            return redirect(url_for("register_professional"))

        # Check if user already exists
        if User.query.filter_by(email=email).first():
            session["message"] = "User with this email already exists!"
            session["status"] = "danger"
            return redirect(url_for("register_professional"))

        # Register the user
        new_user = User(
            username=username,
            email=email,
            role="professional",
            address=address,
            phone=phone,
            pincode=pincode,
            service_expertise=service_expertise,
            experience=experience,
            about=about,
            profile_pic=filename,
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        session["message"] = "Registration successful!"
        session["status"] = "success"
        return redirect(url_for("login"))

    message = session.pop("message", None)
    status = session.pop("status", None)
    return render_template("register_professional.html", message=message, status=status)


@app.route('/login_validation', methods=['POST'])
def login_validation():
    email = request.form.get('email')
    password = request.form.get('password')

    # Validate email
    if not validate_email(email):
        session["message"] = "Invalid email format!"
        session["status"] = "danger"
        return redirect(url_for("login"))

    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        session["email"] = email  # Store email in session
        session["role"] = user.role  # Store user role in session
        session["username"] = user.username  # Store username in session (for welcome message)
        session["message"] = "Login successful!"
        session["status"] = "success"

        # Redirect based on user role
        if user.role == "customer":
            return redirect(url_for("customer_dashboard"))
        elif user.role == "professional":
            return redirect(url_for("professional_dashboard"))
        elif user.role == "admin":
            return redirect(url_for("admin_dashboard"))
    else:
        session["message"] = "Wrong email or password!"
        session["status"] = "danger"
        return redirect(url_for("login"))



@app.route('/admin_dashboard')
def admin_dashboard():
    if 'email' in session:
        return render_template('admin_dashboard.html')
    return redirect(url_for('login'))


@app.route('/customer_dashboard')
def customer_dashboard():
    if 'email' in session:
        return render_template('customer_dashboard.html')
    return redirect(url_for('login'))


@app.route('/professional_dashboard')
def professional_dashboard():
    if 'email' in session:
        return render_template('professional_dashboard.html')
    return redirect(url_for('login'))




@app.route('/customer_dashboard/profile', methods=["GET", "POST"])
def customer_profile():
    if 'email' not in session or session.get("role") != "customer":
        return redirect(url_for('login'))

    user = User.query.filter_by(email=session['email']).first()
    
    if request.method == "POST":
        # Handle profile update (excluding name, email, phone)
        user.address = request.form.get('address')
        user.phone = request.form.get('phone')
        user.pincode = request.form.get('pincode') 

        profile_pic = request.files.get('profile_pic')
        if profile_pic and profile_pic.filename:
            filename = secure_filename(profile_pic.filename)
            profile_pic.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            user.profile_pic = filename

        db.session.commit()
        session["message"] = "Profile updated successfully!"
        session["status"] = "success"
        return redirect(url_for('customer_profile'))

    return render_template('profile.html', user=user)

@app.route('/professional_dashboard/profile', methods=["GET", "POST"])
def professional_profile():
    if 'email' not in session or session.get("role") != "professional":
        return redirect(url_for('login'))  # Redirect to login if the role is not professional

    user = User.query.filter_by(email=session['email']).first()

    if request.method == "POST":
        user.address = request.form.get('address')
        user.phone = request.form.get('phone')
        user.pincode = request.form.get('pincode')  # Update pincode
        user.service_expertise = request.form.get('service_expertise')  # Update service expertise
        user.experience = request.form.get('experience')  # Update experience level
        user.about = request.form.get('about')  # Update about section


        profile_pic = request.files.get('profile_pic')
        if profile_pic and profile_pic.filename:
            filename = secure_filename(profile_pic.filename)
            profile_pic.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            user.profile_pic = filename

        db.session.commit()
        session["message"] = "Profile updated successfully!"
        session["status"] = "success"
        return redirect(url_for('professional_profile'))  # Redirect after successful update

    return render_template('profile.html', user=user)


@app.route('/admin_dashboard/profile', methods=["GET", "POST"])
def admin_profile():
    if 'email' not in session or session.get("role") != "admin":
        return redirect(url_for('login'))  # Redirect to login if the role is not admin

    user = User.query.filter_by(email=session['email']).first()

    if request.method == "POST":
        # Update fields for admin
        user.address = request.form.get('address')
        user.phone = request.form.get('phone')
        user.pincode = request.form.get('pincode')  # Update pincode
        user.about = request.form.get('about')  # Update about section

        # Profile picture upload
        profile_pic = request.files.get('profile_pic')
        if profile_pic and profile_pic.filename:
            filename = secure_filename(profile_pic.filename)
            profile_pic.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            user.profile_pic = filename

        db.session.commit()
        session["message"] = "Profile updated successfully!"
        session["status"] = "success"
        return redirect(url_for('admin_profile'))  # Redirect after successful update

    return render_template('profile.html', user=user)



# Run the app
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
