from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configure the SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Route for the home page
@app.route('/')
def home():
    return render_template('home.html')

# Route for registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Use 'pbkdf2:sha256' for secure password hashing
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_user = User(username=username, email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! You can now login.', 'success')
            return redirect(url_for('login'))
        except:
            flash('User already exists or invalid data.', 'danger')

    return render_template('register.html')


# Route for login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')

    return render_template('login.html')

# Route for the dashboard (protected route)
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('You need to login first.', 'danger')
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', username=session['username'])

# Route for logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    
    with app.app_context():  # Set up application context
        db.create_all()  # Create database tables
    app.run(debug=True)

