from flask import Flask, render_template, request, redirect, session, url_for, jsonify, make_response
from models import User
from werkzeug.security import generate_password_hash, check_password_hash
from config.db import db
from config.config import Config
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)



app.config.from_object(Config)



db.init_app(app)

with app.app_context():
        db.create_all()  # Create database tables




#Initialize OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=Config.GOOGLE_CLIENT_ID,
    client_secret=Config.GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
    },
    
)
   
github = oauth.register(
    name='github',
    client_id=Config.GITHUB_CLIENT_ID,
    client_secret=Config.GITHUB_CLIENT_SECRET,
    access_token_url='https://github.com/login/oauth/access_token',
    access_token_params=None,
    authorize_url='https://github.com/login/oauth/authorize',
    authorize_params=None,
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'user:email'},
)

# Routes

@app.route("/")
def home():
    if 'email' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


# Login
@app.route("/login", methods=["POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()
        #if user and check_password_hash(user.password_hash, password):
        if user and user.password_hash == password:
            session['email'] = email
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for(home))
    return render_template('index.html')

# Register
@app.route("/register", methods=["POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        if User.query.filter_by(email= email).first():
            return render_template('index.html', error="Username already exists")
        else:
            
            new_user = User(email=email)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            session['email'] = email
            return redirect(url_for('dashboard'))
    return render_template('index.html') 

# Dashboard
@app.route("/dashboard")
def dashboard():
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()
        return render_template('dashboard.html', user=user)
    return redirect(url_for('home'))

# Logout 
@app.route("/logout")
def logout():
    session.pop('email', None)
    return redirect(url_for('home'))


# Google OAuth
@app.route("/login/google")
def login_google():
    try:
        redirect_uri = url_for('authorize_google', _external=True)
        return google.authorize_redirect(redirect_uri)
    except Exception as e:
        print(f"Error during Google login: {e}")
        app.logger.error(f"Error during Google login: {e}")
        return "Error during Google login", 500
@app.route("/authorize/google")
def authorize_google():
    token = google.authorize_access_token()
    userinfo_endpoint = google.server_metadata['userinfo_endpoint']
    resp = google.get(userinfo_endpoint)
    user_info = resp.json()
    email = user_info['email']
    name = user_info['name']
    provider = 'google'
    avatar_url = user_info['picture']
    
    # Check if the user already exists
    user = User.query.filter_by(email=email).first()

    if not user:
        # Create a new user
        user = User(email=email, name=name, avatar_url=avatar_url, provider=provider)
        db.session.add(user)
        db.session.commit()
    
    session['email'] = email
    session['oauth_token'] = token
    return redirect(url_for('dashboard'))


@app.route('/login/github')
def login_github():
    redirect_uri = url_for('authorize_github', _external=True)
    return github.authorize_redirect(redirect_uri)


@app.route('/authorize/github')
def authorize_github():
    token = github.authorize_access_token()
    if not token:
        return "GitHub authorization failed", 400
    
    resp = github.get('user')  # Get user profile
    profile = resp.json()
    
    email_resp = github.get('user/emails')
    emails = email_resp.json()
    primary_email = next((email['email'] for email in emails if email.get('primary')), None)
    
    email = primary_email or profile['email']
    name = profile.get('name') or profile.get('login')
    avatar_url = profile.get('avatar_url')
    provider = 'github'

    # Check or create user
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email, name=name, avatar_url=avatar_url, provider=provider)
        db.session.add(user)
        db.session.commit()

    session['email'] = email
    session['oauth_token'] = token
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)