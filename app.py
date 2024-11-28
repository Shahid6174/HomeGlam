from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from validate_email_address import validate_email

app = Flask(__name__)

app.secret_key = "secret_key"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///homeglam.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), nullable=False)
    email = db.Column(db.String(40), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # New column for user role

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@app.route('/')
@app.route('/login')
def login():
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
        session['role'] = user.role  # Store user role in session
        username = user.username
        
        # Redirect based on user role
        if user.role == 'customer':
            return redirect(url_for('customer_dashboard'))
        elif user.role == 'professional':
            return redirect(url_for('professional_dashboard'))
        elif user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('home', username=username))
    else:
        return render_template('error.html', error_message="Wrong Password/Email!", redirect_url=url_for('login'))

@app.route('/reg_validation', methods=['POST'])
def reg_validation():
    username = request.form.get('name')
    email = request.form.get('email')
    password = request.form.get('password')
    role = request.form.get('role')  # Get the selected role
    
    # Validate email format
    if not validate_email(email):
        return render_template('error.html', error_message="Invalid Email Format!", redirect_url=url_for('register'))

    # Check if a user exists with the same email and role
    existing_user = User.query.filter_by(email=email, role=role).first()
    
    if existing_user:
        return render_template('error.html', error_message="User Already Exists with the same role!", redirect_url=url_for('register'))
    
    # Create new user if no existing user found
    new_user = User(username=username, email=email, role=role)  # Set the role
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    session['email'] = email
    session['role'] = role  # Store role in session
    return redirect(url_for('home', username=username))

@app.route('/login_error')
def login_error():
    error_message = request.args.get('error_message', "An error occurred.")
    return render_template('login_error.html', error_message=error_message)

@app.route('/register_error')
def register_error():
    error_message = request.args.get('error_message', "An error occurred.")
    return render_template('register_error.html', error_message=error_message)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
