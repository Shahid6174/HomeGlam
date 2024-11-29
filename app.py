from flask import Flask, render_template, request, redirect, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from validate_email_address import validate_email
from werkzeug.utils import secure_filename
import os
from datetime import timedelta

# Initialize the Flask app
app = Flask(__name__)

# App configuration
app.secret_key = "secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///homeglam.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = "static/uploads"
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB size limit
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# Initialize the database
db = SQLAlchemy(app)

# Allowed file extensions for profile picture uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    """Check if the uploaded file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), nullable=False)
    email = db.Column(db.String(40), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # Role: 'customer', 'professional', or 'admin'
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
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        return redirect(url_for('login_validation'))
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/home')
def home():
    username = request.args.get('username')
    if 'email' in session:
        return render_template('home.html', username=username)
    else:
        return redirect(url_for('login'))

@app.route('/customer_dashboard')
def customer_dashboard():
    if 'email' in session:
        return "Welcome to the Customer Dashboard!"
    return redirect(url_for('login'))

@app.route('/professional_dashboard')
def professional_dashboard():
    if 'email' in session:
        return "Welcome to the Professional Dashboard!"
    return redirect(url_for('login'))

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'email' in session and session.get('role') == 'admin':
        return render_template('admin_dashboard.html')
    return redirect(url_for('login'))

@app.route('/login_validation', methods=['POST'])
def login_validation():
    email = request.form.get('email')
    password = request.form.get('password')

    if not validate_email(email):
        return render_template('error.html', error_message="Invalid Email Format!", redirect_url=url_for('login'))

    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        session['email'] = email
        session['role'] = user.role
        session.permanent = True  # Activate session timeout

        # Redirect based on user role
        if user.role == 'customer':
            return redirect(url_for('customer_dashboard'))
        elif user.role == 'professional':
            return redirect(url_for('professional_dashboard'))
        elif user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('home', username=user.username))
    else:
        return render_template('error.html', error_message="Wrong Password/Email!", redirect_url=url_for('login'))

@app.route("/register/customer", methods=["GET", "POST"])
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
        if profile_pic and allowed_file(profile_pic.filename):
            filename = secure_filename(profile_pic.filename)
            profile_pic.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        if not validate_email(email):
            flash("Invalid email format!", "danger")
            return redirect(url_for("register_customer"))

        if User.query.filter_by(email=email).first():
            flash("User with this email already exists!", "danger")
            return redirect(url_for("register_customer"))

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

        flash("Registration successful!", "success")
        return redirect(url_for("login"))
    return render_template("register_customer.html")

@app.route("/register/professional", methods=["GET", "POST"])
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
        if profile_pic and allowed_file(profile_pic.filename):
            filename = secure_filename(profile_pic.filename)
            profile_pic.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        if not validate_email(email):
            flash("Invalid email format!", "danger")
            return redirect(url_for("register_professional"))

        if User.query.filter_by(email=email).first():
            flash("User with this email already exists!", "danger")
            return redirect(url_for("register_professional"))

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

        flash("Registration successful!", "success")
        return redirect(url_for("login"))
    return render_template("register_professional.html")

@app.route('/login_error')
def login_error():
    error_message = request.args.get('error_message', "An error occurred.")
    return render_template('login_error.html', error_message=error_message)

@app.route('/register_error')
def register_error():
    error_message = request.args.get('error_message', "An error occurred.")
    return render_template('register_error.html', error_message=error_message)

# Run the app
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
