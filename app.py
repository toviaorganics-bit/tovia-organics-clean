from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response
from flask_pymongo import PyMongo
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity,
    verify_jwt_in_request, decode_token
)
from flask_bcrypt import Bcrypt
from flask_cors import CORS, cross_origin
from datetime import datetime, timedelta
from bson.objectid import ObjectId
from functools import wraps
import os
from dotenv import load_dotenv
import stripe
import json
import threading
import uuid
import re
import smtplib
import ssl
from email.message import EmailMessage
import time
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading
import time

try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    GOOGLE_LIBS_AVAILABLE = True
except Exception:
    GOOGLE_LIBS_AVAILABLE = False

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
# Allow CORS from the frontend dev server and enable credentials for cookies
CORS(app, supports_credentials=True, resources={r"/api/*": {"origins": ["http://127.0.0.1:5500", "http://localhost:5500", "http://localhost:5000"]}})

# Import routes
from routes import verify_bp, init_verify_routes

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['MONGO_URI'] = os.environ.get('MONGODB_URI')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', os.urandom(24))
app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies']
app.config['JWT_ACCESS_COOKIE_NAME'] = 'tovia_session'
app.config['JWT_COOKIE_CSRF_PROTECT'] = False
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)
app.config['JWT_TOKEN_LOCATION'] = ['headers', 'cookies']
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')

# Email configuration (SMTP)
SMTP_HOST = os.environ.get('SMTP_HOST')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USER = os.environ.get('SMTP_USER')
SMTP_PASS = os.environ.get('SMTP_PASS')
FROM_EMAIL = os.environ.get('FROM_EMAIL', SMTP_USER)
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', FROM_EMAIL)
GMAIL_SERVICE_ACCOUNT_JSON = os.environ.get('GMAIL_SERVICE_ACCOUNT_JSON')
GMAIL_DELEGATED_USER = os.environ.get('GMAIL_DELEGATED_USER')
GMAIL_OAUTH_CLIENT_ID = os.environ.get('GMAIL_OAUTH_CLIENT_ID')
GMAIL_OAUTH_CLIENT_SECRET = os.environ.get('GMAIL_OAUTH_CLIENT_SECRET')
GMAIL_OAUTH_REFRESH_TOKEN = os.environ.get('GMAIL_OAUTH_REFRESH_TOKEN')
GMAIL_OAUTH_TOKEN_FILE = os.environ.get('GMAIL_OAUTH_TOKEN_FILE', 'gmail_oauth_token.json')
ADMIN_API_SECRET = os.environ.get('ADMIN_API_SECRET')

def send_verification_email(user_email, name, verification_token, base_url=None):
    """Send account verification email using the configured email system."""
    try:
        # Use provided base_url or construct a default one
        base_url = base_url or "http://localhost:5000/"
        verification_url = base_url + "api/verify/" + verification_token
        
        print("=== Sending Verification Email ===")
        print("Email:", user_email)
        print("Token:", verification_token)
        print("URL:", verification_url)
        
        # Read email template
        with open('templates/emails/verify_account.html', 'r', encoding='utf-8') as f:
            template = f.read()
        
        # Replace template variables
        email_content = template.replace('{{ name }}', name)\
                               .replace('{{ verification_url }}', verification_url)\
                               .replace('{{ year }}', str(datetime.utcnow().year))
        
        # Send email
        result = send_email(
            subject="Verify Your Tovia Organics Account",
            recipient=user_email,
            body="Please verify your Tovia Organics account.",
            html=email_content
        )
        
        print("Verification email result:", result)
        return result
        
    except Exception as e:
        print(f"Error sending verification email: {str(e)}")
        import traceback
        print("Full traceback:")
        print(traceback.format_exc())
        return False

def send_email(subject, recipient, body, html=None):
    print(f"\n=== Starting Email Send Process ===")
    print(f"Subject: {subject}")
    print(f"Recipient: {recipient}")
    print(f"Has HTML content: {bool(html)}")
    
    try:
        # Try to send via Gmail OAuth first
        if GMAIL_OAUTH_REFRESH_TOKEN and GMAIL_OAUTH_CLIENT_ID and GMAIL_OAUTH_CLIENT_SECRET:
            print("Attempting to send via Gmail OAuth...")
            return send_via_gmail_oauth(subject, recipient, body, html, GMAIL_OAUTH_REFRESH_TOKEN)
        # Fallback to regular SMTP if OAuth fails
        elif SMTP_HOST and SMTP_PORT and SMTP_USER:
            print("Falling back to regular SMTP...")
            return send_via_gmail(subject, recipient, body, html)
        else:
            print("ERROR: No email configuration available")
            return False
    except Exception as e:
        print(f"Email send error: {str(e)}")
        import traceback
        print("Full traceback:")
        print(traceback.format_exc())
        return False
    """Send an email via configured SMTP server. recipient can be a string or list."""
    # Prefer Gmail OAuth2 refresh-token if provided (single-account flow)
    oauth_refresh = GMAIL_OAUTH_REFRESH_TOKEN
    # If not provided via env, try token file
    if not oauth_refresh and os.path.exists(GMAIL_OAUTH_TOKEN_FILE):
        try:
            with open(GMAIL_OAUTH_TOKEN_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                oauth_refresh = data.get('refresh_token')
        except Exception:
            oauth_refresh = None

    if oauth_refresh and GMAIL_OAUTH_CLIENT_ID and GMAIL_OAUTH_CLIENT_SECRET:
        try:
            return send_via_gmail_oauth(subject, recipient, body, html, oauth_refresh)
        except Exception as e:
            print(f"[email] Gmail OAuth send failed: {e}")

    # Prefer Gmail API via service account if available
    if GMAIL_SERVICE_ACCOUNT_JSON and GMAIL_DELEGATED_USER and GOOGLE_LIBS_AVAILABLE:
        try:
            return send_via_gmail(subject, recipient, body, html)
        except Exception as e:
            print(f"[email] Gmail API send failed: {e}")

    # Fallback to SMTP if configured
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        # SMTP not configured; in DEBUG, print to console
        print(f"[email] SMTP not configured. Would send to {recipient}: {subject}\n{body}")
        return False

    try:
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = FROM_EMAIL
        msg['To'] = recipient if isinstance(recipient, str) else ','.join(recipient)
        msg.set_content(body)
        if html:
            # attach HTML alternative
            msg.add_alternative(html, subtype='html')

        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls(context=context)
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"[email] failed to send email: {e}")
        return False


def send_via_gmail(subject, recipient, body, html=None):
    """Send email using Gmail API via service account with domain-wide delegation.
    GMAIL_SERVICE_ACCOUNT_JSON should contain the service account JSON or a filesystem path.
    GMAIL_DELEGATED_USER should be the email address to send as (the user to impersonate).
    """
    if not GOOGLE_LIBS_AVAILABLE:
        raise RuntimeError('Google API libraries not installed')

    # Load service account info
    info = None
    try:
        # If env var points to a file path
        if os.path.exists(GMAIL_SERVICE_ACCOUNT_JSON):
            with open(GMAIL_SERVICE_ACCOUNT_JSON, 'r', encoding='utf-8') as f:
                info = json.load(f)
        else:
            # Try parsing JSON from env var (could be base64 encoded)
            try:
                info = json.loads(GMAIL_SERVICE_ACCOUNT_JSON)
            except Exception:
                # Try base64 decode
                try:
                    decoded = base64.b64decode(GMAIL_SERVICE_ACCOUNT_JSON).decode('utf-8')
                    info = json.loads(decoded)
                except Exception as e:
                    raise ValueError('GMAIL_SERVICE_ACCOUNT_JSON is not valid JSON or file path') from e
    except Exception as e:
        raise

    scopes = ['https://www.googleapis.com/auth/gmail.send']
    credentials = service_account.Credentials.from_service_account_info(info, scopes=scopes)
    delegated_creds = credentials.with_subject(GMAIL_DELEGATED_USER)

    service = build('gmail', 'v1', credentials=delegated_creds, cache_discovery=False)

    message = MIMEMultipart('alternative')
    message['Subject'] = subject
    message['To'] = recipient if isinstance(recipient, str) else ','.join(recipient)
    message['From'] = FROM_EMAIL or GMAIL_DELEGATED_USER
    part1 = MIMEText(body, 'plain')
    message.attach(part1)
    if html:
        part2 = MIMEText(html, 'html')
        message.attach(part2)

    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    send_req = {'raw': raw}
    result = service.users().messages().send(userId='me', body=send_req).execute()
    return True


def refresh_access_token(refresh_token):
    """Exchange a refresh token for an access token using Google's OAuth2 token endpoint."""
    import requests
    token_url = 'https://oauth2.googleapis.com/token'
    resp = requests.post(token_url, data={
        'client_id': GMAIL_OAUTH_CLIENT_ID,
        'client_secret': GMAIL_OAUTH_CLIENT_SECRET,
        'refresh_token': refresh_token,
        'grant_type': 'refresh_token'
    })
    if resp.status_code != 200:
        raise RuntimeError(f'Failed to refresh token: {resp.text}')
    return resp.json().get('access_token')


def send_via_gmail_oauth(subject, recipient, body, html, refresh_token):
    """Send via Gmail API using OAuth2 refresh token for a single account."""
    if not GOOGLE_LIBS_AVAILABLE:
        raise RuntimeError('Google API libraries not installed')

    access_token = refresh_access_token(refresh_token)
    from googleapiclient.discovery import build
    from google.oauth2.credentials import Credentials

    creds = Credentials(token=access_token)
    service = build('gmail', 'v1', credentials=creds, cache_discovery=False)

    message = MIMEMultipart('alternative')
    message['Subject'] = subject
    message['To'] = recipient if isinstance(recipient, str) else ','.join(recipient)
    message['From'] = FROM_EMAIL
    part1 = MIMEText(body, 'plain')
    message.attach(part1)
    if html:
        part2 = MIMEText(html, 'html')
        message.attach(part2)

    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    send_req = {'raw': raw}
    result = service.users().messages().send(userId='me', body=send_req).execute()
    return True


# OAuth2 helper endpoints for one-time authorization flow
@app.route('/oauth2/start')
def oauth2_start():
    # build consent URL to obtain code
    redirect_uri = request.host_url.rstrip('/') + url_for('oauth2_callback')
    client_id = GMAIL_OAUTH_CLIENT_ID
    scope = 'https://www.googleapis.com/auth/gmail.send'
    url = (
        'https://accounts.google.com/o/oauth2/v2/auth'
        f'?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code&scope={scope}'
        '&access_type=offline&prompt=consent'
    )
    return redirect(url)


@app.route('/oauth2/callback')
def oauth2_callback():
    code = request.args.get('code')
    if not code:
        return 'Authorization failed: no code provided', 400
    # Exchange code for tokens
    import requests
    redirect_uri = request.host_url.rstrip('/') + url_for('oauth2_callback')
    token_resp = requests.post('https://oauth2.googleapis.com/token', data={
        'client_id': GMAIL_OAUTH_CLIENT_ID,
        'client_secret': GMAIL_OAUTH_CLIENT_SECRET,
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': redirect_uri
    })
    if token_resp.status_code != 200:
        return f'Failed to exchange code: {token_resp.text}', 400
    tokens = token_resp.json()
    # Save refresh_token to file (for convenience)
    refresh_token = tokens.get('refresh_token')
    if not refresh_token:
        return 'No refresh token returned. Make sure you used access_type=offline and prompt=consent.', 400
    try:
        with open(GMAIL_OAUTH_TOKEN_FILE, 'w', encoding='utf-8') as f:
            json.dump({'refresh_token': refresh_token}, f)
    except Exception as e:
        return f'Failed to save token: {e}', 500
    return 'Authorization successful. Refresh token saved to server.'

# Initialize extensions
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

# Initialize MongoDB
try:
    mongo = PyMongo(app)
    # Test the connection
    mongo.db.command('ping')
    print("Connected to MongoDB successfully!")
    
    # Initialize and register blueprints
    init_verify_routes(mongo)  # Initialize verify routes with mongo instance
    app.register_blueprint(verify_bp)  # Register the verify blueprint
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
    raise

# User Helper Functions
def create_user(name, email, password):
    """Create a new user in the database"""
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user = {
        'name': name,
        'email': email.lower(),  # Store email in lowercase for case-insensitive comparison
        'password': hashed_password,
        'created_at': datetime.utcnow(),
        'is_active': True
    }
    return mongo.db.users.insert_one(user)

def get_user_by_email(email):
    """Get user by email (case-insensitive)"""
    return mongo.db.users.find_one({'email': email.lower()})


def get_current_user_id():
    """Normalize JWT identity to a string user id.
    Identity may be a string id, an ObjectId, or a user dict (older tokens).
    Returns a string id or None.
    """
    identity = get_jwt_identity()
    if not identity:
        return None
    # If identity is a dict (older token shape), extract id
    if isinstance(identity, dict):
        uid = identity.get('_id') or identity.get('id') or identity.get('user') or identity
        # if nested user object
        if isinstance(uid, dict):
            uid = uid.get('_id') or uid.get('id')
    else:
        uid = identity

    # If uid is an ObjectId-like dict, attempt to extract
    try:
        if isinstance(uid, ObjectId):
            return str(uid)
        # If it's already a string, return it
        if isinstance(uid, str):
            return uid
        # Fallback: stringify
        return str(uid)
    except Exception:
        return None

def validate_email(email):
    """Basic email validation"""
    import re
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return bool(re.match(pattern, email))

def validate_password(password):
    """
    Validate password strength
    - At least 8 characters long
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one number
    """
    if len(password) < 8:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    return True

def admin_required(f):
    @wraps(f)
    @jwt_required()
    def decorated_function(*args, **kwargs):
        current_user_id = get_current_user_id()
        user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
        
        if not user or user.get('email') != 'admin@toviaorganics.com':
            return jsonify({
                'success': False,
                'message': 'Admin access required'
            }), 403
        return f(*args, **kwargs)
    return decorated_function

# Authentication Routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json() or {}

    # Extract user data
    name = data.get('name', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')

    # Basic validation
    if not all([name, email, password]):
        return jsonify({'success': False, 'message': 'All fields are required'}), 400

    if not validate_email(email):
        return jsonify({'success': False, 'message': 'Invalid email format'}), 400

    if not validate_password(password):
        return jsonify({'success': False, 'message': 'Password must be at least 8 characters long and contain uppercase, lowercase, and numbers'}), 400

    # Check existing user
    if get_user_by_email(email):
        return jsonify({'success': False, 'message': 'Email already registered'}), 400

    try:
        result = create_user(name, email, password)
        inserted_id = getattr(result, 'inserted_id', None) or str(result)

        access_token = create_access_token(identity=str(inserted_id))

        resp = jsonify({
            'success': True,
            'message': 'Registration successful',
            'user': {
                'id': str(inserted_id),
                'name': name,
                'email': email
            }
    , 'token': access_token
    })

        resp.set_cookie(
            'access_token_cookie',
            access_token,
            httponly=True,
            secure=not app.config.get('DEBUG', False),
            samesite='Strict',
            max_age=60*60*24*7
        )

        # Notify user and admin via email
        try:
            user_email = email
            subject = 'Welcome to Tovia Organics - Account Created'
            body = f"Hi {name},\n\nThank you for creating an account at Tovia Organics. If you did not sign up, please contact support.\n\n— Tovia Organics"
            try:
                html = render_template('emails/welcome.html', name=name, year=datetime.utcnow().year, site_url=request.host_url)
            except Exception:
                html = None
            send_email(subject, user_email, body, html)
            # notify admin
            admin_subject = f'New user registered: {email}'
            admin_body = f'New user registered:\n\nName: {name}\nEmail: {email}\nTime: {datetime.utcnow().isoformat()}'
            send_email(admin_subject, ADMIN_EMAIL, admin_body)
        except Exception:
            pass

        return resp, 201
    except Exception as e:
        return jsonify({'success': False, 'message': f'Registration failed: {str(e)}'}), 500


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    password = data.get('password', '')

    if not all([email, password]):
        return jsonify({'success': False, 'message': 'Email and password are required'}), 400

    user = get_user_by_email(email)
    if not user:
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
    try:
        if not verify_password(user, password):
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

        access_token = create_access_token(identity=str(user['_id']))

        resp = jsonify({
            'success': True, 
            'message': 'Signed in successfully', 
            'user': {
                'id': str(user['_id']), 
                'name': user.get('name'), 
                'email': user.get('email'),
                'verified': user.get('verified', False)  # MAKE SURE THIS LINE IS PRESENT
            }, 
            'token': access_token
        })
        
        resp.set_cookie(
            'access_token_cookie',
            access_token,
            httponly=True,
            secure=not app.config.get('DEBUG', False),
            samesite='Strict',
            max_age=60*60*24*7
        )

        # Notify admin
        try:
            send_email(f'User signed in: {user.get("email")}', ADMIN_EMAIL, f'User {user.get("name")} ({user.get("email")}) signed in at {datetime.utcnow().isoformat()}')
        except Exception:
            pass

        # Notify user about the sign-in (security notification)
        try:
            user_subject = 'New sign-in to your Tovia Organics account'
            user_body = (
                f"Hi {user.get('name')},\n\n"
                f"We noticed a sign-in to your Tovia Organics account on {datetime.utcnow().isoformat()} UTC.\n"
                "If this was you, no further action is required. If you did not sign in, please reset your password immediately.\n\n"
                "— Tovia Organics"
            )
            try:
                html = render_template(
                    'emails/signin_notification.html',
                    name=user.get('name'),
                    time=datetime.utcnow().isoformat(),
                    year=datetime.utcnow().year,
                    title='New sign-in detected',
                    message='We noticed a sign-in to your Tovia Organics account from a device or browser. If this was you, no action is required. If you did not sign in, please reset your password immediately.'
                )
            except Exception:
                html = None
            send_email(user_subject, user.get('email'), user_body, html)
        except Exception:
            pass

        return resp, 200
    except Exception as e:
        return jsonify({'success': False, 'message': f'Login failed: {str(e)}'}), 500

# Profile Management Routes
@app.route('/api/profile', methods=['GET'])
@jwt_required()
def get_profile():
    current_user_id = get_jwt_identity()
    user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
    
    if not user:
        return jsonify({
            'success': False,
            'message': 'User not found'
        }), 404
    
    return jsonify({
        'success': True,
        'user': {
            'id': str(user['_id']),
            'name': user['name'],
            'email': user['email']
        }
    })

@app.route('/api/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    # Get current user
    user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
    if not user:
        return jsonify({
            'success': False,
            'message': 'User not found'
        }), 404
    
    # Prepare update data
    update_data = {}
    
    # Update name if provided
    if 'name' in data:
        name = data['name'].strip()
        if name:
            update_data['name'] = name
        else:
            return jsonify({
                'success': False,
                'message': 'Name cannot be empty'
            }), 400
            
    # Update email if provided
    if 'email' in data:
        email = data['email'].strip().lower()
        if not validate_email(email):
            return jsonify({
                'success': False,
                'message': 'Invalid email format'
            }), 400

        # Check if email is already taken by another user
        existing_user = mongo.db.users.find_one({
            '_id': {'$ne': ObjectId(current_user_id)},
            'email': email
        })
        if existing_user:
            return jsonify({
                'success': False,
                'message': 'Email already taken'
            }), 400

        update_data['email'] = email
    
    # Update password if provided
    if 'current_password' in data and 'new_password' in data:
        current_password = data['current_password']
        new_password = data['new_password']
        
        # Verify current password
        if not bcrypt.check_password_hash(user['password'], current_password):
            return jsonify({
                'success': False,
                'message': 'Current password is incorrect'
            }), 401
        
        # Validate new password
        if not validate_password(new_password):
            return jsonify({
                'success': False,
                'message': 'New password must be at least 8 characters long and contain uppercase, lowercase, and numbers'
            }), 400
            
        # Hash new password
        update_data['password'] = bcrypt.generate_password_hash(new_password).decode('utf-8')
    
    # If there are no updates, return current data
    if not update_data:
        return jsonify({
            'success': True,
            'message': 'No changes made',
            'user': {
                'id': str(user['_id']),
                'name': user['name'],
                'email': user['email']
            }
        })
    
    # Update user in database
    try:
        mongo.db.users.update_one(
            {'_id': ObjectId(current_user_id)},
            {'$set': update_data}
        )
        
        # Get updated user data
        updated_user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
        
        return jsonify({
            'success': True,
            'message': 'Profile updated successfully',
            'user': {
                'id': str(updated_user['_id']),
                'name': updated_user['name'],
                'email': updated_user['email']
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Failed to update profile: {str(e)}'
        }), 500

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    
    if not email:
        return jsonify({
            'success': False,
            'message': 'Email is required'
        }), 400
        
    # Find user by email
    user = get_user_by_email(email)
    if not user:
        return jsonify({
            'success': False,
            'message': 'If a user with this email exists, they will receive a password reset link'
        }), 200
    
    # Generate reset token
    reset_token = create_access_token(
        identity=str(user['_id']),
        expires_delta=timedelta(hours=1),
        additional_claims={'reset_password': True}
    )
    
    # Store reset token in database with expiration
    mongo.db.password_resets.insert_one({
        'user_id': user['_id'],
        'token': reset_token,
        'created_at': datetime.utcnow(),
        'expires_at': datetime.utcnow() + timedelta(hours=1),
        'used': False
    })
    
    # TODO: Send email with reset link
    # For now, we'll just return the token in the response
    # In production, you would send this via email
    return jsonify({
        'success': True,
        'message': 'Password reset instructions have been sent to your email',
        'debug_token': reset_token  # Remove this in production
    })

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')
    
    if not all([token, new_password]):
        return jsonify({
            'success': False,
            'message': 'Token and new password are required'
        }), 400
        
    # Validate new password
    if not validate_password(new_password):
        return jsonify({
            'success': False,
            'message': 'Password must be at least 8 characters long and contain uppercase, lowercase, and numbers'
        }), 400
    
    try:
        # Verify and decode token
        decoded_token = decode_token(token)
        if not decoded_token.get('reset_password', False):
            raise Exception('Invalid reset token')
            
        user_id = decoded_token['sub']  # 'sub' contains the user ID
        
        # Check if token has been used
        reset_record = mongo.db.password_resets.find_one({
            'token': token,
            'used': False,
            'expires_at': {'$gt': datetime.utcnow()}
        })
        
        if not reset_record:
            return jsonify({
                'success': False,
                'message': 'Invalid or expired reset token'
            }), 400
        
        # Update password
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        mongo.db.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'password': hashed_password}}
        )
        
        # Mark token as used
        mongo.db.password_resets.update_one(
            {'_id': reset_record['_id']},
            {'$set': {'used': True}}
        )
        
        return jsonify({
            'success': True,
            'message': 'Password has been reset successfully'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': 'Invalid or expired reset token'
        }), 400

@app.route('/api/account/change-password', methods=['POST'])
@cross_origin(origins=["http://127.0.0.1:5500", "http://localhost:5500"], supports_credentials=True)
@jwt_required()
def change_password():
    data = request.get_json() or {}
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    if not current_password or not new_password:
        return jsonify({'success': False, 'message': 'Current and new passwords are required'}), 400

    current_user_id = get_jwt_identity()
    user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    if not verify_password(user, current_password):
        return jsonify({'success': False, 'message': 'Current password is incorrect'}), 401

    if not validate_password(new_password):
        return jsonify({'success': False, 'message': 'New password does not meet requirements'}), 400

    try:
        mongo.db.users.update_one({'_id': ObjectId(current_user_id)}, {'$set': {'password': bcrypt.generate_password_hash(new_password).decode('utf-8')}})
        # notify user and admin
        try:
            # Use the signin notification template for password change notifications for consistency
            user_subject = 'Your Tovia Organics password was changed'
            user_body = 'Your account password was changed. If this was not you, contact support immediately.'
            try:
                html = render_template(
                    'emails/signin_notification.html',
                    name=user.get('name'),
                    time=datetime.utcnow().isoformat(),
                    year=datetime.utcnow().year,
                    title='Your password was changed',
                    message='Your account password was changed. If this was not you, contact support immediately.'
                )
            except Exception:
                html = None
            send_email(user_subject, user.get('email'), user_body, html)
            send_email(f'User changed password: {user.get("email")}', ADMIN_EMAIL, f'User {user.get("email")} changed their password at {datetime.utcnow().isoformat()}')
        except Exception:
            pass
        return jsonify({'success': True, 'message': 'Password updated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/account/delete', methods=['POST'])
@cross_origin(origins=["http://127.0.0.1:5500", "http://localhost:5500"], supports_credentials=True)
@jwt_required()
def delete_account():
    data = request.get_json() or {}
    confirm = data.get('confirm', False)
    if not confirm:
        return jsonify({'success': False, 'message': 'Confirmation required'}), 400

    current_user_id = get_jwt_identity()
    user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    try:
        # Delete user-related data: cart, password_resets, orders (soft decisions - here fully delete)
        mongo.db.cart_items.delete_many({'user_id': ObjectId(current_user_id)})
        mongo.db.password_resets.delete_many({'user_id': ObjectId(current_user_id)})
        mongo.db.orders.delete_many({'user_id': ObjectId(current_user_id)})
        mongo.db.users.delete_one({'_id': ObjectId(current_user_id)})

        # notify admin and user
        try:
            # Reuse signin notification template for account deletion notices to the user
            user_subject = 'Your Tovia Organics account was deleted'
            user_body = 'Your account has been deleted. If this was not you, contact support immediately.'
            try:
                html = render_template(
                    'emails/signin_notification.html',
                    name=user.get('name'),
                    time=datetime.utcnow().isoformat(),
                    year=datetime.utcnow().year,
                    title='Your account was deleted',
                    message='Your account has been deleted. If this was not you, contact support immediately.'
                )
            except Exception:
                html = None
            send_email(user_subject, user.get('email'), user_body, html)
            send_email(f'User deleted account: {user.get("email")}', ADMIN_EMAIL, f'User {user.get("email")} deleted their account at {datetime.utcnow().isoformat()}')
        except Exception:
            pass

        resp = make_response(jsonify({'success': True, 'message': 'Account deleted'}))
        resp.delete_cookie('access_token_cookie')
        return resp
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    

@app.route('/admin/test-email', methods=['POST'])
def admin_test_email():
    """Trigger a test email from server. Protect with ADMIN_API_SECRET in env for safety."""
    key = request.headers.get('X-Admin-Secret') or request.args.get('key')
    if ADMIN_API_SECRET and key != ADMIN_API_SECRET:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401

    data = request.get_json() or {}
    subject = data.get('subject', 'Test email from Tovia Organics')
    recipient = data.get('recipient') or FROM_EMAIL
    body = data.get('body', 'This is a test email sent from the Tovia Organics server.')

    try:
        ok = send_email(subject, recipient, body)
        return jsonify({'success': ok}), (200 if ok else 500)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    # Get current user
    user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
    if not user:
        return jsonify({
            'success': False,
            'message': 'User not found'
        }), 404
    
    # Prepare update data
    update_data = {}
    
    # Update name if provided
    if 'name' in data:
        name = data['name'].strip()
        if name:
            update_data['name'] = name
        else:
            return jsonify({
                'success': False,
                'message': 'Name cannot be empty'
            }), 400
    
    # Update email if provided
    if 'email' in data:
        email = data['email'].strip().lower()
        if not validate_email(email):
            return jsonify({
                'success': False,
                'message': 'Invalid email format'
            }), 400
            
        # Check if email is already taken by another user
        existing_user = mongo.db.users.find_one({
            '_id': {'$ne': ObjectId(current_user_id)},
            'email': email
        })
        if existing_user:
            return jsonify({
                'success': False,
                'message': 'Email already taken'
            }), 400
            
        update_data['email'] = email
    
    # Update password if provided
    if 'current_password' in data and 'new_password' in data:
        current_password = data['current_password']
        new_password = data['new_password']
        
        # Verify current password
        if not bcrypt.check_password_hash(user['password'], current_password):
            return jsonify({
                'success': False,
                'message': 'Current password is incorrect'
            }), 401
        
        # Validate new password
        if not validate_password(new_password):
            return jsonify({
                'success': False,
                'message': 'New password must be at least 8 characters long and contain uppercase, lowercase, and numbers'
            }), 400
            
        # Hash new password
        update_data['password'] = bcrypt.generate_password_hash(new_password).decode('utf-8')
    
    # If there are no updates, return current data
    if not update_data:
        return jsonify({
            'success': True,
            'message': 'No changes made',
            'user': {
                'id': str(user['_id']),
                'name': user['name'],
                'email': user['email']
            }
        })
    
    # Update user in database
    try:
        mongo.db.users.update_one(
            {'_id': ObjectId(current_user_id)},
            {'$set': update_data}
        )
        
        # Get updated user data
        updated_user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
        
        return jsonify({
            'success': True,
            'message': 'Profile updated successfully',
            'user': {
                'id': str(updated_user['_id']),
                'name': updated_user['name'],
                'email': updated_user['email']
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Failed to update profile: {str(e)}'
        }), 500
    
    # Extract user data
    name = data.get('name', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    
    # Validate input
    if not all([name, email, password]):
        return jsonify({
            'success': False,
            'message': 'All fields are required'
        }), 400
        
    # Validate email format
    if not validate_email(email):
        return jsonify({
            'success': False,
            'message': 'Invalid email format'
        }), 400
        
    # Validate password strength
    if not validate_password(password):
        return jsonify({
            'success': False,
            'message': 'Password must be at least 8 characters long and contain uppercase, lowercase, and numbers'
        }), 400
        
    # Check if user already exists
    if get_user_by_email(email):
        return jsonify({
            'success': False,
            'message': 'Email already registered'
        }), 400
        
    try:
        # Create new user
        result = create_user(name, email, password)
        
        # Create JWT token
        access_token = create_access_token(identity=str(result.inserted_id))
        
        # Prepare response
        resp = jsonify({
            'success': True,
            'message': 'Registration successful',
            'user': {
                'id': str(result.inserted_id),
                'name': name,
                'email': email
            }
        })
        
        # Set JWT token in HTTP-only cookie
        # In development (HTTP) we should not set secure=True, only enable it in production (HTTPS)
        resp.set_cookie(
            'access_token_cookie',
            access_token,
            httponly=True,
            secure=not app.config.get('DEBUG', False),
            samesite='Strict',  # Protect against CSRF
            max_age=60*60*24*7  # 7 days
        )
        
        return resp, 201
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Registration failed: {str(e)}'
        }), 500

# Initialize required collections
# Add this enhanced init_db function to your app.py file to replace the existing one

def init_db():
    """Initialize the database with all required collections and indexes"""
    try:
        # Create indexes for users collection
        mongo.db.users.create_index('email', unique=True)
        
        # Create indexes for products collection
        mongo.db.products.create_index('slug', unique=True)
        mongo.db.products.create_index([('category', 1), ('is_active', 1)])
        
        # Create indexes for orders collection
        mongo.db.orders.create_index([('user_id', 1), ('date_created', -1)])
        mongo.db.orders.create_index('order_number', unique=True)
        
        # Create indexes for cart items collection
        mongo.db.cart_items.create_index([('user_id', 1), ('product_id', 1)], unique=True)
        
        # Create indexes for reviews collection
        mongo.db.reviews.create_index([('product_id', 1), ('status', 1)])
        mongo.db.reviews.create_index([('user_id', 1), ('product_id', 1)], unique=True)
        mongo.db.reviews.create_index('created_at')
        
        # Create indexes for review requests collection
        mongo.db.review_requests.create_index('token', unique=True)
        mongo.db.review_requests.create_index([('user_id', 1), ('product_id', 1), ('order_id', 1)])
        mongo.db.review_requests.create_index('expires_at')
        mongo.db.review_requests.create_index([('email_sent', 1), ('used', 1)])
        
        # Create indexes for password resets collection
        mongo.db.password_resets.create_index('token', unique=True)
        mongo.db.password_resets.create_index('expires_at')
        
        print("Database collections and indexes initialized successfully!")
    except Exception as e:
        print(f"Error initializing database: {e}")
        raise

# Also add this function to create sample reviews (optional, for testing)
def create_sample_reviews():
    """Create sample reviews for testing (call this manually if needed)"""
    try:
        # Find some products and users
        rose_water = mongo.db.products.find_one({'slug': 'rose-water-lotion'})
        herbal_oil = mongo.db.products.find_one({'slug': 'herbal-oil-blend'})
        admin_user = mongo.db.users.find_one({'email': 'admin@toviaorganics.com'})
        
        if not all([rose_water, herbal_oil, admin_user]):
            print("Sample data not found. Run init_sample_data() first.")
            return
        
        sample_reviews = [
            {
                'user_id': admin_user['_id'],
                'product_id': rose_water['_id'],
                'rating': 5,
                'comment': 'Absolutely love this lotion! It absorbs quickly and leaves my skin feeling so soft and hydrated. The rose scent is divine.',
                'status': 'approved',
                'verified_purchase': True,
                'created_at': datetime.utcnow() - timedelta(days=10)
            },
            {
                'user_id': admin_user['_id'],
                'product_id': herbal_oil['_id'], 
                'rating': 4,
                'comment': 'Great oil blend! I use it on my face and it has really improved my skin texture. Only wish it came in a larger size.',
                'status': 'approved',
                'verified_purchase': True,
                'created_at': datetime.utcnow() - timedelta(days=5)
            }
        ]
        
        for review in sample_reviews:
            # Check if review already exists
            existing = mongo.db.reviews.find_one({
                'user_id': review['user_id'],
                'product_id': review['product_id']
            })
            if not existing:
                mongo.db.reviews.insert_one(review)
        
        print("Sample reviews created!")
        
    except Exception as e:
        print(f"Error creating sample reviews: {e}")

# Add this enhanced order status management function
def update_order_status_and_send_reviews(order_id, new_status):
    """Update order status and automatically send review requests when order is delivered"""
    try:
        result = mongo.db.orders.update_one(
            {'_id': ObjectId(order_id)},
            {'$set': {'status': new_status, 'status_updated_at': datetime.utcnow()}}
        )
        
        if result.modified_count == 0:
            return False, "Order not found"
        
        # If order status is set to 'delivered', send review requests
        if new_status.lower() in ['delivered', 'completed']:
            order = mongo.db.orders.find_one({'_id': ObjectId(order_id)})
            user = mongo.db.users.find_one({'_id': order['user_id']})
            
            if not user:
                return False, "User not found"
            
            # Get review requests for this order that haven't been sent
            review_requests = list(mongo.db.review_requests.find({
                'order_id': ObjectId(order_id),
                'email_sent': False
            }))
            
            sent_count = 0
            for review_request in review_requests:
                product = mongo.db.products.find_one({'_id': review_request['product_id']})
                if not product:
                    continue
                
                # Create review link
                review_link = f"{request.host_url.rstrip('/')}/api/reviews/request/{review_request['token']}"
                
                # Send review request email
                subject = f"How was your {product['name']}? Leave a review!"
                body = f"""Hi {user['name']},

Thank you for your recent purchase of {product['name']} from Tovia Organics!

We'd love to hear about your experience with this product. Your honest feedback helps other customers make informed decisions and helps us continue to improve our products.

Please click the link below to leave a review:
{review_link}

This review link will expire in 60 days from your purchase date, so don't wait too long!

As a small business, every review means the world to us. Thank you for taking the time to share your thoughts.

Best regards,
The Tovia Organics Team

P.S. If you have any issues with your order, please don't hesitate to contact us directly at ToviaOrganics@gmail.com"""
                
                if send_email(subject, user['email'], body):
                    # Mark as sent
                    mongo.db.review_requests.update_one(
                        {'_id': review_request['_id']},
                        {'$set': {'email_sent': True, 'email_sent_at': datetime.utcnow()}}
                    )
                    sent_count += 1
            
            return True, f"Order status updated and {sent_count} review requests sent"
        else:
            return True, "Order status updated"
            
    except Exception as e:
        return False, str(e)

# Add this admin route to manually trigger review emails
@app.route('/api/admin/orders/<order_id>/update-status', methods=['POST'])
@jwt_required()
@admin_required
def admin_update_order_status(order_id):
    """Update order status and optionally send review requests"""
    try:
        data = request.get_json()
        new_status = data.get('status')
        
        if not new_status:
            return jsonify({'success': False, 'message': 'Status is required'}), 400
        
        success, message = update_order_status_and_send_reviews(order_id, new_status)
        
        return jsonify({
            'success': success,
            'message': message
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# =============================================================================
# JWT Configuration
# =============================================================================

# JWT error handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        'success': False,
        'message': 'Token has expired'
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        'success': False,
        'message': 'Invalid token'
    }), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        'success': False,
        'message': 'Missing authorization token'
    }), 401

# =============================================================================
# Helper Functions
# =============================================================================
def create_user(name, email, password):
    """Create a new user"""
    if mongo.db.users.find_one({'email': email.lower()}):
        return None
    
    user = {
        'name': name,
        'email': email.lower(),
        'password': bcrypt.generate_password_hash(password).decode('utf-8'),
        'created_at': datetime.utcnow(),
        'is_active': True
    }
    
    result = mongo.db.users.insert_one(user)
    user['_id'] = str(result.inserted_id)
    return user

def get_user(user_id):
    """Get user by ID"""
    try:
        user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
        if user:
            user['_id'] = str(user['_id'])
        return user
    except:
        return None

def get_user_by_email(email):
    """Get user by email"""
    user = mongo.db.users.find_one({'email': email.lower()})
    if user:
        user['_id'] = str(user['_id'])
    return user

def verify_password(user, password):
    """Verify password hash"""
    if not user or 'password' not in user:
        return False
    return bcrypt.check_password_hash(user['password'], password)

# Helper Functions
def get_cart_items(user_id):
    """Get user's cart items"""
    return list(mongo.db.cart_items.find({'user_id': ObjectId(user_id)}))

def get_cart_total(user_id):
    """Calculate cart total for a user"""
    cart_items = get_cart_items(user_id)
    total = 0
    for item in cart_items:
        product = mongo.db.products.find_one({'_id': item['product_id']})
        if product:
            total += float(product['price']) * item['quantity']
    return total

def get_cart_count(user_id):
    """Get number of items in user's cart"""
    cart_items = get_cart_items(user_id)
    return sum(item['quantity'] for item in cart_items)

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def init_sample_data():
    """Initialize database with sample data"""
    
    # Create categories
    categories_data = [
        {'name': 'Skincare', 'slug': 'skincare', 'description': 'Nourishing skincare products', 'is_active': True},
        {'name': 'Cleansers', 'slug': 'cleansers', 'description': 'Gentle cleansing products', 'is_active': True},
        {'name': 'Treatments', 'slug': 'treatments', 'description': 'Specialized treatment products', 'is_active': True}
    ]
    
    for cat_data in categories_data:
        if not mongo.db.categories.find_one({'slug': cat_data['slug']}):
            mongo.db.categories.insert_one(cat_data)
    
    # Create sample products
    products_data = [
        {
            'name': 'Radiant Glow Serum', 'slug': 'radiant-glow-serum', 'category_slug': 'skincare',
            'price': 28.00, 'stock_quantity': 50, 'featured': True, 'is_active': True,
            'description': 'A lightweight, fast-absorbing serum that brightens and hydrates your skin with the power of Vitamin C and organic jojoba oil.',
            'ingredients': ['Vitamin C', 'Jojoba Oil', 'Hyaluronic Acid', 'Aloe Vera Extract'],
            'benefits': ['Brightens skin tone', 'Reduces dark spots', 'Hydrates deeply', 'Anti-aging properties'],
            'usage_instructions': 'Apply 2-3 drops to clean skin morning and evening. Follow with moisturizer.',
            'image_url': 'https://placehold.co/600x400/E0EBE4/333333?text=Radiant+Serum',
            'date_created': datetime.utcnow()
        },
        {
            'name': 'Nourishing Face Cream', 'slug': 'nourishing-face-cream', 'category_slug': 'skincare',
            'price': 35.00, 'stock_quantity': 30, 'featured': False, 'is_active': True,
            'description': 'Rich, luxurious moisturizer that deeply nourishes and repairs your skin with organic shea butter and rosehip oil.',
            'ingredients': ['Shea Butter', 'Rosehip Oil', 'Ceramides', 'Vitamin E'],
            'benefits': ['Deep moisturization', 'Repairs skin barrier', 'Anti-aging', 'Soothes irritation'],
            'usage_instructions': 'Apply to clean skin morning and evening. Massage gently until absorbed.',
            'image_url': 'https://placehold.co/600x400/E0EBE4/333333?text=Nourishing+Cream',
            'date_created': datetime.utcnow()
        },
        {
            'name': 'Soothing Cream Cleanser', 'slug': 'soothing-cream-cleanser', 'category_slug': 'cleansers',
            'price': 22.00, 'stock_quantity': 40, 'featured': True, 'is_active': True,
            'description': 'Gentle cream cleanser that removes impurities while maintaining skin\'s natural moisture with chamomile and green tea.',
            'ingredients': ['Chamomile Extract', 'Green Tea', 'Coconut Oil', 'Glycerin'],
            'benefits': ['Gentle cleansing', 'Calms irritation', 'Maintains moisture', 'Suitable for sensitive skin'],
            'usage_instructions': 'Massage onto damp skin, rinse with warm water. Use morning and evening.',
            'image_url': 'https://placehold.co/600x400/E0EBE4/333333?text=Soothing+Cleanser',
            'date_created': datetime.utcnow()
        },
        {
            'name': 'Hydrating Facial Mist', 'slug': 'hydrating-facial-mist', 'category_slug': 'treatments',
            'price': 18.00, 'stock_quantity': 60, 'featured': True, 'is_active': True,
            'description': 'Refreshing rosewater and aloe mist that hydrates and tones throughout the day.',
            'ingredients': ['Rose Water', 'Aloe Vera', 'Glycerin', 'Botanical Extracts'],
            'benefits': ['Instant hydration', 'Refreshes makeup', 'Balances pH', 'Calming effect'],
            'usage_instructions': 'Spray 6-8 inches from face. Use throughout the day as needed.',
            'image_url': 'https://placehold.co/600x400/E0EBE4/333333?text=Hydrating+Mist',
            'date_created': datetime.utcnow()
        }
    ]
    
    for prod_data in products_data:
        if not mongo.db.products.find_one({'slug': prod_data['slug']}):
            category = mongo.db.categories.find_one({'slug': prod_data['category_slug']})
            if category:
                prod_data['category_id'] = category['_id']
                del prod_data['category_slug']
                mongo.db.products.insert_one(prod_data)

# =============================================================================
# COOKIE MANAGEMENT
# =============================================================================

def set_user_preferences(response, preferences):
    """Set user preferences in cookies"""
    response.set_cookie('user_prefs', json.dumps(preferences), max_age=30*24*60*60)  # 30 days
    return response

def get_user_preferences():
    """Get user preferences from cookies"""
    prefs = request.cookies.get('user_prefs')
    if prefs:
        try:
            return json.loads(prefs)
        except:
            pass
    return {'currency': 'USD', 'theme': 'light', 'marketing_emails': True}

# =============================================================================
# ROUTES - MAIN PAGES
# =============================================================================

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/test-db')
def test_db():
    try:
        # Test MongoDB connection
        mongo.db.command('ping')
        # Try to create a test document
        result = mongo.db.test.insert_one({'test': True, 'timestamp': datetime.utcnow()})
        # Clean up by removing the test document
        mongo.db.test.delete_one({'_id': result.inserted_id})
        return jsonify({
            'status': 'success',
            'message': 'Database connection successful'
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Database connection failed: {str(e)}'
        }), 500

@app.route('/api/products')
def api_products():
    try:
        categories = list(mongo.db.categories.find({'is_active': True}))
        products = list(mongo.db.products.find({'is_active': True}))
        
        # Convert ObjectIds to strings
        for category in categories:
            category['_id'] = str(category['_id'])
        
        for product in products:
            product['_id'] = str(product['_id'])
            product['category_id'] = str(product['category_id'])
            product['price'] = float(product['price'])
            
            # Add category info
            category = mongo.db.categories.find_one({'_id': ObjectId(product['category_id'])})
            if category:
                product['category_slug'] = category['slug']
                product['category_name'] = category['name']
        
        return jsonify({
            'success': True,
            'categories': categories,
            'products': products
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/products/<slug>')
def api_product_detail(slug):
    try:
        product = mongo.db.products.find_one({'slug': slug, 'is_active': True})
        if not product:
            return jsonify({'success': False, 'message': 'Product not found'}), 404
        
        product['_id'] = str(product['_id'])
        product['category_id'] = str(product['category_id'])
        product['price'] = float(product['price'])
        
        return jsonify({
            'success': True,
            'product': product
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# =============================================================================
# ROUTES - AUTHENTICATION
# =============================================================================

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'message': 'Email and password are required'}), 400
        
        user = get_user_by_email(email)
        
        if user and verify_password(user, password):
            access_token = create_access_token(identity=str(user['_id']))
            return jsonify({
                'token': access_token,
                'user': {
                    'id': str(user['_id']),
                    'name': user['name'],
                    'email': user['email'],
                    'verified': user.get('verified', False)
                }
            }), 200
        
        return jsonify({'message': 'Invalid email or password'}), 401
    
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/auth/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        
        # Validation
        if not all([name, email, password]):
            return jsonify({'message': 'All fields are required'}), 400
        
        if len(password) < 8:
            return jsonify({'message': 'Password must be at least 8 characters long'}), 400
        
        # Create new user
        user = create_user(name, email, password)
        if not user:
            return jsonify({'message': 'Email already exists'}), 409
        
        # Generate access token
        access_token = create_access_token(identity=str(user['_id']))
        
        return jsonify({
            'token': access_token,
            'user': {
                'id': str(user['_id']),
                'name': user['name'],
                'email': user['email']
            }
        }), 201
        
    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/auth/logout', methods=['POST'])
@jwt_required()
def logout():
    # JWT is stateless, so we just return success
    # The client will remove the token
    return jsonify({'message': 'Successfully logged out'}), 200

@app.route('/api/auth/user', methods=['GET'])
@jwt_required()
def get_user_profile():
    try:
        current_user_id = get_current_user_id()
        user = get_user(current_user_id)

        if not user:
            return jsonify({'message': 'User not found'}), 404

        cart_items = get_cart_items(current_user_id)
        cart_count = sum(item['quantity'] for item in cart_items)

        return jsonify({
            'user': {
                'id': str(user['_id']),
                'name': user['name'],
                'email': user['email'],
                'cart_count': cart_count
            }
        }), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/api/signup', methods=['POST'])
def api_signup():
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        
        # Validation
        if not all([name, email, password]):
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        
        if len(password) < 8:
            return jsonify({'success': False, 'message': 'Password must be at least 8 characters'}), 400
        
        # Check if user exists
        if get_user_by_email(email):
            return jsonify({'success': False, 'message': 'Email already registered'}), 400
        
        print("\n=== Starting Account Creation Process ===")
        
        # Generate verification token
        verification_token = str(uuid.uuid4())
        print(f"1. Generated verification token: {verification_token}")

        # Create new user with verification data
        user_data = {
            'name': name,
            'email': email,
            'password': bcrypt.generate_password_hash(password).decode('utf-8'),
            'created_at': datetime.utcnow(),
            'verified': False,
            'verification_token': verification_token,
            'verification_expires': datetime.utcnow() + timedelta(hours=24),
            'orders': []
        }
        
        # Insert the user
        result = mongo.db.users.insert_one(user_data)
        if not result.inserted_id:
            return jsonify({'success': False, 'message': 'Error creating account'}), 500
        
        print(f"2. User created with ID: {result.inserted_id}")
        
        # Generate access token
        access_token = create_access_token(identity=str(result.inserted_id))
        print("3. Access token generated")

        # Send welcome email first
        try:
            print("4. Sending welcome email...")
            with open('templates/emails/welcome.html', 'r', encoding='utf-8') as f:
                welcome_template = f.read()
            welcome_content = welcome_template.replace('{{ name }}', name).replace('{{ year }}', str(datetime.utcnow().year))
            
            welcome_result = send_email(
                subject="Welcome to Tovia Organics - Account Created",
                recipient=email,
                body="Welcome to Tovia Organics!",
                html=welcome_content
            )
            print(f"Welcome email result: {welcome_result}")
            
        except Exception as e:
            print(f"Welcome email error: {str(e)}")

        # Send verification email
        try:
            print("5. Sending verification email...")
            send_verification_email(email, name, verification_token, base_url=request.host_url)
            print("6. Verification email sent successfully!")
        except Exception as e:
            print(f"Verification email error: {str(e)}")
            import traceback
            print("Traceback:", traceback.format_exc())
        
        # Return success response with user data
        user_data = {
            'id': str(result.inserted_id),
            'name': name,
            'email': email,
            'verified': False
        }
        
        # Notify admin
        try:
            admin_subject = f'New user registered: {email}'
            admin_body = f'New user registered:\n\nName: {name}\nEmail: {email}\nTime: {datetime.utcnow().isoformat()}'
            send_email(admin_subject, ADMIN_EMAIL, admin_body)
        except Exception as e:
            print(f"Admin notification error: {str(e)}")
        
        # Prepare response
        resp = make_response(jsonify({
            'success': True,
            'message': 'Account created successfully! Please check your email for verification.',
            'user': {
                'id': str(result.inserted_id),
                'name': user_data['name'],
                'email': user_data['email'],
                'verified': False
            },
            'token': access_token
        }))
        
        # Set JWT token in HTTP-only cookie
        resp.set_cookie(
            'access_token_cookie',
            access_token,
            httponly=True,
            secure=not app.config.get('DEBUG', False),  # Use secure=False in development
            samesite='Strict',
            max_age=30*24*60*60  # 30 days
        )
        
        print("7. Response prepared and sent")
        return resp, 201
        
    except Exception as e:
        print(f"Signup error: {str(e)}")
        import traceback
        print(traceback.format_exc())
        return jsonify({'success': False, 'message': 'Error creating account'}), 500

@app.route('/api/user')
@jwt_required()
def api_user():
    try:
        current_user_id = get_current_user_id()
        if not current_user_id:
            return jsonify({'success': False, 'message': 'Invalid user ID'}), 401
            
        user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        cart_count = get_cart_count(current_user_id)
        
        return jsonify({
            'success': True,
            'user': {
                'id': str(user['_id']),
                'name': user.get('name'),
                'email': user.get('email'),
                'verified': user.get('verified', False),  # Make sure to include verification status
                'cart_count': cart_count
            }
        })
    except Exception as e:
        print(f"Error in /api/user: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/check-verification', methods=['POST'])
@jwt_required()
def check_verification_status():
    """Manual endpoint to check verification status"""
    try:
        current_user_id = get_current_user_id()
        if not current_user_id:
            return jsonify({'success': False, 'message': 'Invalid user ID'}), 401
            
        user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        return jsonify({
            'success': True,
            'verified': user.get('verified', False),
            'message': 'Verified' if user.get('verified', False) else 'Not verified'
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    
# =============================================================================
# ROUTES - CART MANAGEMENT
# =============================================================================

@app.route('/api/cart', methods=['GET'])
@jwt_required()
def api_cart():
    try:
        current_user_id = get_current_user_id()
        cart_items = list(mongo.db.cart_items.find({'user_id': ObjectId(current_user_id)}))
        
        cart_data = []
        total = 0
        
        for item in cart_items:
            product = mongo.db.products.find_one({'_id': ObjectId(item['product_id'])})
            if product:
                item_total = float(product['price']) * item['quantity']
                item_data = {
                    'id': str(item['_id']),
                    'product_id': str(product['_id']),
                    'product_name': product['name'],
                    'product_slug': product['slug'],
                    'price': float(product['price']),
                    'quantity': item['quantity'],
                    'total': item_total,
                    'image_url': product['image_url']
                }
                cart_data.append(item_data)
                total += item_total
        
        return jsonify({
            'success': True,
            'items': cart_data,
            'total': total,
            'count': sum(item['quantity'] for item in cart_data)
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/cart/add', methods=['POST'])
@jwt_required()
def api_cart_add():
    try:
        current_user_id = get_current_user_id()
        data = request.get_json()
        product_id = data.get('product_id')
        quantity = data.get('quantity', 1)
        
        if not product_id:
            return jsonify({'success': False, 'message': 'Product ID required'}), 400
        
        product = mongo.db.products.find_one({'_id': ObjectId(product_id)})
        if not product or not product.get('is_active', True):
            return jsonify({'success': False, 'message': 'Product not found'}), 404
        
        if product['stock_quantity'] < quantity:
            return jsonify({'success': False, 'message': 'Not enough stock available'}), 400
        
        # Check if item already in cart
        cart_item = mongo.db.cart_items.find_one({
            'user_id': ObjectId(current_user_id),
            'product_id': ObjectId(product_id)
        })
        
        if cart_item:
            new_quantity = cart_item['quantity'] + quantity
            if new_quantity > 5:  # Max 5 per product
                return jsonify({'success': False, 'message': 'Maximum 5 items per product'}), 400
            
            mongo.db.cart_items.update_one(
                {'_id': cart_item['_id']},
                {'$set': {'quantity': new_quantity, 'date_updated': datetime.utcnow()}}
            )
        else:
            cart_item_data = {
                'user_id': ObjectId(current_user_id),
                'product_id': ObjectId(product_id),
                'quantity': quantity,
                'date_added': datetime.utcnow()
            }
            mongo.db.cart_items.insert_one(cart_item_data)
        
        return jsonify({
            'success': True, 
            'message': f'{product["name"]} added to cart',
            'cart_count': get_cart_count(current_user_id)
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/cart/update/<item_id>', methods=['PUT'])
@jwt_required()
def api_cart_update(item_id):
    try:
        current_user_id = get_current_user_id()
        data = request.get_json()
        quantity = data.get('quantity', 1)
        
        cart_item = mongo.db.cart_items.find_one({
            '_id': ObjectId(item_id),
            'user_id': ObjectId(current_user_id)
        })
        
        if not cart_item:
            return jsonify({'success': False, 'message': 'Cart item not found'}), 404
        
        if quantity <= 0:
            mongo.db.cart_items.delete_one({'_id': ObjectId(item_id)})
        elif quantity > 5:
            return jsonify({'success': False, 'message': 'Maximum 5 items per product'}), 400
        else:
            product = mongo.db.products.find_one({'_id': ObjectId(cart_item['product_id'])})
            if not product or product['stock_quantity'] < quantity:
                return jsonify({'success': False, 'message': 'Not enough stock available'}), 400
            
            mongo.db.cart_items.update_one(
                {'_id': ObjectId(item_id)},
                {'$set': {'quantity': quantity, 'date_updated': datetime.utcnow()}}
            )
        
        return jsonify({
            'success': True,
            'cart_count': get_cart_count(current_user_id)
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/cart/remove/<item_id>', methods=['DELETE'])
@jwt_required()
def api_cart_remove(item_id):
    try:
        current_user_id = get_current_user_id()
        result = mongo.db.cart_items.delete_one({
            '_id': ObjectId(item_id),
            'user_id': ObjectId(current_user_id)
        })
        
        if result.deleted_count == 0:
            return jsonify({'success': False, 'message': 'Cart item not found'}), 404
        
        return jsonify({
            'success': True,
            'message': 'Item removed from cart',
            'cart_count': get_cart_count(current_user_id)
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/cart/clear', methods=['DELETE'])
@jwt_required()
def api_cart_clear():
    try:
        current_user_id = get_jwt_identity()
        mongo.db.cart_items.delete_many({'user_id': ObjectId(current_user_id)})
        return jsonify({'success': True, 'message': 'Cart cleared'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# =============================================================================
# ROUTES - PAYMENT & CHECKOUT
# =============================================================================

@app.route('/api/checkout/create-payment-intent', methods=['POST'])
@jwt_required()
def create_payment_intent():
    try:
        current_user_id = get_jwt_identity()
        user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        cart_total = get_cart_total(current_user_id)
        if cart_total <= 0:
            return jsonify({'error': 'Cart is empty'}), 400
        
        # Create payment intent with Stripe
        intent = stripe.PaymentIntent.create(
            amount=int(cart_total * 100),  # Stripe uses cents
            currency='usd',
            automatic_payment_methods={'enabled': True},
            metadata={
                'user_id': str(user['_id']),
                'user_email': user['email']
            }
        )
        
        return jsonify({
            'client_secret': intent['client_secret'],
            'amount': cart_total
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/checkout/confirm', methods=['POST'])
@jwt_required()
def confirm_checkout():
    try:
        current_user_id = get_jwt_identity()
        user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        data = request.get_json()
        payment_intent_id = data.get('payment_intent_id')
        shipping_info = data.get('shipping_info', {})
        
        if not payment_intent_id:
            return jsonify({'error': 'Payment intent ID required'}), 400
        
        # Verify payment with Stripe
        intent = stripe.PaymentIntent.retrieve(payment_intent_id)
        
        if intent.status != 'succeeded':
            return jsonify({'error': 'Payment not completed'}), 400
        
        # Get cart items
        cart_items = list(mongo.db.cart_items.find({'user_id': ObjectId(current_user_id)}))
        if not cart_items:
            return jsonify({'error': 'Cart is empty'}), 400
        
        # Create order
        order_data = {
            'user_id': ObjectId(current_user_id),
            'order_number': f'TO-{datetime.now().strftime("%Y%m%d%H%M%S")}-{str(uuid.uuid4())[:8]}',
            'total_amount': get_cart_total(current_user_id),
            'stripe_payment_intent_id': payment_intent_id,
            'payment_status': 'completed',
            'status': 'processing',
            'shipping_info': shipping_info,
            'date_created': datetime.utcnow(),
            'items': []
        }
        
        # Process cart items and update stock
        for cart_item in cart_items:
            product = mongo.db.products.find_one({'_id': ObjectId(cart_item['product_id'])})
            if not product:
                return jsonify({'error': 'Product not found'}), 400
            
            if product['stock_quantity'] < cart_item['quantity']:
                return jsonify({'error': f'Not enough stock for {product["name"]}'}), 400
            
            # Update stock
            mongo.db.products.update_one(
                {'_id': ObjectId(cart_item['product_id'])},
                {'$inc': {'stock_quantity': -cart_item['quantity']}}
            )
            
            # Add to order items
            order_data['items'].append({
                'product_id': ObjectId(cart_item['product_id']),
                'product_name': product['name'],
                'quantity': cart_item['quantity'],
                'price_at_time': float(product['price'])
            })
        
        # Save order
        result = mongo.db.orders.insert_one(order_data)
        
        # Clear cart
        mongo.db.cart_items.delete_many({'user_id': ObjectId(current_user_id)})

        # Notify user about the order
        try:
            user_subject = f'Your order {order_data["order_number"]} confirmation'
            user_body = f"Thank you for your order. Order {order_data['order_number']} has been received and is being processed. Total: ${order_data['total_amount']:.2f}"
            try:
                html = render_template(
                    'emails/signin_notification.html',
                    name=user.get('name'),
                    time=datetime.utcnow().isoformat(),
                    year=datetime.utcnow().year,
                    title=f'Order {order_data["order_number"]} confirmation',
                    message=f"Thank you for your order. Order {order_data['order_number']} has been received and is being processed. Total: ${order_data['total_amount']:.2f}"
                )
            except Exception:
                html = None
            send_email(user_subject, user.get('email'), user_body, html)
        except Exception:
            pass

        return jsonify({
            'success': True,
            'order_id': str(result.inserted_id),
            'order_number': order_data['order_number'],
            'message': 'Order completed successfully!'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# ROUTES - ORDER MANAGEMENT
# =============================================================================

@app.route('/api/orders')
@jwt_required()
def api_orders():
    try:
        current_user_id = get_jwt_identity()
        orders = list(mongo.db.orders.find({'user_id': ObjectId(current_user_id)}).sort('date_created', -1))
        
        orders_data = []
        for order in orders:
            order_data = {
                'id': str(order['_id']),
                'order_number': order['order_number'],
                'status': order['status'],
                'total_amount': float(order['total_amount']),
                'date_created': order['date_created'].isoformat(),
                'items': order.get('items', [])
            }
            orders_data.append(order_data)
        
        return jsonify({
            'success': True,
            'orders': orders_data
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# =============================================================================
# ROUTES - USER PREFERENCES
# =============================================================================

@app.route('/api/preferences', methods=['GET'])
def api_get_preferences():
    return jsonify({
        'success': True,
        'preferences': get_user_preferences()
    })

@app.route('/api/preferences', methods=['POST'])
def api_set_preferences():
    try:
        data = request.get_json()
        preferences = get_user_preferences()
        preferences.update(data)
        
        resp = make_response(jsonify({
            'success': True,
            'message': 'Preferences updated'
        }))
        
        return set_user_preferences(resp, preferences)
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    
@app.route('/api/reviews/<product_id>', methods=['GET'])
def get_product_reviews(product_id):
    """Get all approved reviews for a product"""
    try:
        # Convert product_id to ObjectId if it's a valid ObjectId string
        try:
            product_object_id = ObjectId(product_id)
        except:
            # If it's a slug, find the product first
            product = mongo.db.products.find_one({'slug': product_id})
            if not product:
                return jsonify({'success': False, 'message': 'Product not found'}), 404
            product_object_id = product['_id']

        reviews = list(mongo.db.reviews.find({
            'product_id': product_object_id,
            'status': 'approved'
        }).sort('created_at', -1))

        reviews_data = []
        for review in reviews:
            # Get user info
            user = mongo.db.users.find_one({'_id': ObjectId(review['user_id'])})
            user_name = "Anonymous"
            if user and user.get('name'):
                # Format name as "FirstName***"
                name_parts = user['name'].split()
                if name_parts:
                    first_name = name_parts[0]
                    user_name = f"{first_name}***"

            reviews_data.append({
                'id': str(review['_id']),
                'user_name': user_name,
                'rating': review['rating'],
                'comment': review['comment'],
                'created_at': review['created_at'].isoformat(),
                'verified_purchase': review.get('verified_purchase', False)
            })

        return jsonify({
            'success': True,
            'reviews': reviews_data,
            'total_reviews': len(reviews_data),
            'average_rating': sum(r['rating'] for r in reviews_data) / len(reviews_data) if reviews_data else 0
        })

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/reviews/submit', methods=['POST'])
@jwt_required()
def submit_review():
    """Submit a review for a product (only if user has purchased it)"""
    try:
        current_user_id = get_current_user_id()
        data = request.get_json()
        
        product_id = data.get('product_id')
        rating = data.get('rating')
        comment = data.get('comment', '').strip()
        review_token = data.get('review_token')  # Token from email link
        
        # Validate input
        if not all([product_id, rating, review_token]):
            return jsonify({'success': False, 'message': 'Product ID, rating, and review token are required'}), 400
        
        if not isinstance(rating, int) or rating < 1 or rating > 5:
            return jsonify({'success': False, 'message': 'Rating must be between 1 and 5'}), 400
        
        # Verify review token
        review_request = mongo.db.review_requests.find_one({
            'token': review_token,
            'user_id': ObjectId(current_user_id),
            'product_id': ObjectId(product_id),
            'used': False,
            'expires_at': {'$gt': datetime.utcnow()}
        })
        
        if not review_request:
            return jsonify({'success': False, 'message': 'Invalid or expired review token'}), 400
        
        # Check if user already reviewed this product
        existing_review = mongo.db.reviews.find_one({
            'user_id': ObjectId(current_user_id),
            'product_id': ObjectId(product_id)
        })
        
        if existing_review:
            return jsonify({'success': False, 'message': 'You have already reviewed this product'}), 400
        
        # Get product info
        product = mongo.db.products.find_one({'_id': ObjectId(product_id)})
        if not product:
            return jsonify({'success': False, 'message': 'Product not found'}), 404
        
        # Create review
        review_data = {
            'user_id': ObjectId(current_user_id),
            'product_id': ObjectId(product_id),
            'order_id': review_request['order_id'],
            'rating': rating,
            'comment': comment,
            'status': 'pending',  # Reviews need approval
            'verified_purchase': True,
            'created_at': datetime.utcnow()
        }
        
        result = mongo.db.reviews.insert_one(review_data)
        
        # Mark review token as used
        mongo.db.review_requests.update_one(
            {'_id': review_request['_id']},
            {'$set': {'used': True}}
        )
        
        # Auto-approve review (you can change this to manual approval)
        mongo.db.reviews.update_one(
            {'_id': result.inserted_id},
            {'$set': {'status': 'approved'}}
        )
        
        # Notify admin of new review
        try:
            user = mongo.db.users.find_one({'_id': ObjectId(current_user_id)})
            subject = f'New review submitted for {product["name"]}'
            body = f'User {user.get("name")} ({user.get("email")}) submitted a {rating}-star review for {product["name"]}.\n\nComment: {comment}'
            send_email(subject, ADMIN_EMAIL, body)
        except Exception:
            pass
        
        return jsonify({
            'success': True,
            'message': 'Review submitted successfully!'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/reviews/request/<token>')
def review_request_page(token):
    """Display review form page from email link"""
    try:
        # Verify token
        review_request = mongo.db.review_requests.find_one({
            'token': token,
            'used': False,
            'expires_at': {'$gt': datetime.utcnow()}
        })
        
        if not review_request:
            return render_template('review_expired.html'), 400
        
        # Get product and user info
        product = mongo.db.products.find_one({'_id': review_request['product_id']})
        user = mongo.db.users.find_one({'_id': review_request['user_id']})
        
        if not product or not user:
            return render_template('review_expired.html'), 400
        
        return render_template('review_form.html', 
                             product=product, 
                             user=user, 
                             token=token)
        
    except Exception as e:
        return render_template('review_expired.html'), 500


# =============================================================================
# ENHANCED ORDER MANAGEMENT FOR REVIEW SYSTEM
# =============================================================================


@app.route('/api/admin/send-review-requests/<order_id>', methods=['POST'])
@jwt_required()
@admin_required
def send_review_requests(order_id):
    """Send review request emails for a completed order"""
    try:
        order = mongo.db.orders.find_one({'_id': ObjectId(order_id)})
        if not order:
            return jsonify({'success': False, 'message': 'Order not found'}), 404
        
        user = mongo.db.users.find_one({'_id': order['user_id']})
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        # Get review requests for this order
        review_requests = list(mongo.db.review_requests.find({
            'order_id': ObjectId(order_id),
            'email_sent': False
        }))
        
        sent_count = 0
        for review_request in review_requests:
            product = mongo.db.products.find_one({'_id': review_request['product_id']})
            if not product:
                continue
            
            # Create review link
            review_link = f"{request.host_url.rstrip('/')}/api/reviews/request/{review_request['token']}"
            
            # Send review request email
            subject = f"How was your {product['name']}? Leave a review!"
            body = f"""Hi {user['name']},

Thank you for your recent purchase of {product['name']} from Tovia Organics!

We'd love to hear about your experience. Your feedback helps other customers and helps us improve our products.

Please click the link below to leave a review:
{review_link}

This link will expire in 60 days from your purchase date.

Thank you for choosing Tovia Organics!

Best regards,
The Tovia Organics Team"""
            
            if send_email(subject, user['email'], body):
                # Mark as sent
                mongo.db.review_requests.update_one(
                    {'_id': review_request['_id']},
                    {'$set': {'email_sent': True, 'email_sent_at': datetime.utcnow()}}
                )
                sent_count += 1
        
        return jsonify({
            'success': True,
            'message': f'Review request emails sent for {sent_count} products'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# =============================================================================
# ADMIN REVIEW MANAGEMENT
# =============================================================================

@app.route('/api/admin/reviews', methods=['GET'])
@jwt_required()
@admin_required
def admin_get_reviews():
    """Get all reviews for admin management"""
    try:
        status = request.args.get('status', 'all')
        
        query = {}
        if status != 'all':
            query['status'] = status
        
        reviews = list(mongo.db.reviews.find(query).sort('created_at', -1))
        
        reviews_data = []
        for review in reviews:
            user = mongo.db.users.find_one({'_id': review['user_id']})
            product = mongo.db.products.find_one({'_id': review['product_id']})
            
            reviews_data.append({
                'id': str(review['_id']),
                'user_name': user.get('name', 'Unknown') if user else 'Unknown',
                'user_email': user.get('email', 'Unknown') if user else 'Unknown',
                'product_name': product.get('name', 'Unknown') if product else 'Unknown',
                'rating': review['rating'],
                'comment': review['comment'],
                'status': review['status'],
                'verified_purchase': review.get('verified_purchase', False),
                'created_at': review['created_at'].isoformat()
            })
        
        return jsonify({
            'success': True,
            'reviews': reviews_data
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/admin/reviews/<review_id>/approve', methods=['POST'])
@jwt_required()
@admin_required
def approve_review(review_id):
    """Approve a review"""
    try:
        result = mongo.db.reviews.update_one(
            {'_id': ObjectId(review_id)},
            {'$set': {'status': 'approved', 'approved_at': datetime.utcnow()}}
        )
        
        if result.modified_count == 0:
            return jsonify({'success': False, 'message': 'Review not found'}), 404
        
        return jsonify({'success': True, 'message': 'Review approved'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/admin/reviews/<review_id>/reject', methods=['POST'])
@jwt_required()
@admin_required
def reject_review(review_id):
    """Reject a review"""
    try:
        result = mongo.db.reviews.update_one(
            {'_id': ObjectId(review_id)},
            {'$set': {'status': 'rejected', 'rejected_at': datetime.utcnow()}}
        )
        
        if result.modified_count == 0:
            return jsonify({'success': False, 'message': 'Review not found'}), 404
        
        return jsonify({'success': True, 'message': 'Review rejected'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# =============================================================================
# ADMIN ROUTES
# =============================================================================

@app.route('/api/admin/dashboard')
@jwt_required()
@admin_required
def admin_dashboard():
    try:
        total_users = mongo.db.users.count_documents({})
        total_products = mongo.db.products.count_documents({})
        total_orders = mongo.db.orders.count_documents({})
        
        # Calculate total revenue
        pipeline = [
            {'$match': {'payment_status': 'completed'}},
            {'$group': {'_id': None, 'total': {'$sum': '$total_amount'}}}
        ]
        revenue_result = list(mongo.db.orders.aggregate(pipeline))
        total_revenue = float(revenue_result[0]['total']) if revenue_result else 0
        
        # Recent orders
        recent_orders = list(mongo.db.orders.find().sort('date_created', -1).limit(10))
        
        orders_data = []
        for order in recent_orders:
            user = mongo.db.users.find_one({'_id': order['user_id']})
            orders_data.append({
                'id': str(order['_id']),
                'order_number': order['order_number'],
                'customer_name': user['name'] if user else 'Unknown',
                'total': float(order['total_amount']),
                'status': order['status'],
                'date': order['date_created'].isoformat()
            })
        
        return jsonify({
            'success': True,
            'stats': {
                'total_users': total_users,
                'total_products': total_products,
                'total_orders': total_orders,
                'total_revenue': total_revenue
            },
            'recent_orders': orders_data
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# =============================================================================
# ERROR HANDLERS
# =============================================================================

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(403)
def forbidden_error(error):
    return jsonify({'error': 'Access forbidden'}), 403

# =============================================================================
# DATABASE INITIALIZATION
# =============================================================================

def initialize_app():
    """Initialize the application with database and sample data"""
    try:
        # Test MongoDB connection
        mongo.db.command('ping')
        print('MongoDB connected successfully!')
        
        # Create admin user and sample data in development only unless SKIP_SAMPLE is set
        skip_sample = os.environ.get('SKIP_SAMPLE', '').lower() in ('1', 'true', 'yes')
        if not skip_sample:
            admin_email = 'admin@toviaorganics.com'
            if not get_user_by_email(admin_email):
                admin_user = create_user('Admin', admin_email, 'admin123')  # Change password in production!
                print(f'Admin user created: {admin_email} / admin123')
            # Initialize sample data
            init_sample_data()
            print('Sample data initialized!')
        
    except Exception as e:
        print(f'Database initialization error: {e}')

# =============================================================================
# CLI COMMANDS
# =============================================================================

@app.cli.command()
def init_db():
    """Initialize the database."""
    init_sample_data()
    print('Database initialized!')

@app.cli.command()
def create_admin():
    """Create admin user."""
    email = input('Admin email: ')
    password = input('Admin password: ')
    name = input('Admin name: ')
    
    if get_user_by_email(email):
        print('User already exists!')
        return
    
    admin = create_user(name, email, password)
    if admin:
        print('Admin user created successfully!')
    else:
        print('Failed to create admin user')

# =============================================================================
# RUN APPLICATION
# =============================================================================

if __name__ == '__main__':
    # Development configuration
    app.config['DEBUG'] = os.environ.get('DEBUG', 'True').lower() == 'true'
    
    # Initialize app
    initialize_app()
    
    port = int(os.environ.get('PORT', 5000))
    # Disable the reloader to avoid Windows socket selector issues (WinError 10038)
    app.run(host='0.0.0.0', port=port, debug=app.config['DEBUG'], use_reloader=False)


# Fallback: ensure CORS headers are present for API responses (development convenience)
@app.after_request
def add_cors_headers(response):
    try:
        origin = request.headers.get('Origin')
        if origin and request.path.startswith('/api/'):
            response.headers.setdefault('Access-Control-Allow-Origin', origin)
            response.headers.setdefault('Access-Control-Allow-Credentials', 'true')
            response.headers.setdefault('Access-Control-Allow-Headers', 'Content-Type')
            response.headers.setdefault('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
    except Exception:
        pass
    return response