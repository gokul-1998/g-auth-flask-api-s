from flask import Flask, flash, redirect, render_template, request, url_for, session, jsonify
from flask_oauthlib.client import OAuth
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, login_required, roles_required
from sec import consumer_key, consumer_secret
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SECURITY_PASSWORD_SALT'] = 'your_salt'  # Change this to a random value

# Setup Flask-Security
app.config['SECURITY_GOOGLE_OAUTH'] = {
    'consumer_key': consumer_key,
    'consumer_secret': consumer_secret,
}
app.config['SECURITY_LOGIN_URL'] = '/login'
app.config['SECURITY_LOGOUT_URL'] = '/logout'
app.config['SECURITY_REGISTER_URL'] = '/register'
app.config['SECURITY_POST_LOGIN_VIEW'] = '/'
app.config['SECURITY_POST_LOGOUT_VIEW'] = '/'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

db = SQLAlchemy(app)

# Define User and Role models for Flask-Security
roles_users = db.Table('roles_users',
                       db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
                       db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    active = db.Column(db.Boolean())
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore, register_blueprint=False)

# Your existing routes

@app.route('/')
def index():
    return 'Welcome to Flask Google Authentication Example!'

@app.route('/login')
def login():
    return redirect(url_for('security.login'))

@app.route('/logout')
@login_required
def logout():
    return redirect(url_for('security.logout'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if email=="21f1007026@ds.study.iitm.ac.in"

        user = user_datastore.create_user(email=email, password=password)
        db.session.commit()

        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('security.login'))

    return render_template('register.html')  # You should create a register.html template for the registration form


# New routes with role-based authentication



@app.route('/api/authorized/admin')
@login_required
@roles_required('admin')
def admin_api():
    return jsonify({'message': 'Admin API', 'user_email': security.current_user.email, 'role': 'admin'})

@app.route('/api/authorized/user')
@login_required
@roles_required('user')
def user_api():
    return jsonify({'message': 'User API', 'user_email': security.current_user.email, 'role': 'user'})

@app.route('/api/unauthorized')
def unauthorized_api():
    return jsonify({'message': 'Unauthorized API'})

if __name__ == '__main__':
    with app.app_context():

        db.create_all()
        app.run(debug=True)
