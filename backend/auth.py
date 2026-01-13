import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify

SECRET_KEY = "your-secret-key-change-this-in-production-2024"

USERS_DB = {
    "admin": {
        "username": "admin",
        "password": "admin123",
        "role": "admin"
    },
    "analyst": {
        "username": "analyst",
        "password": "analyst123",
        "role": "analyst"
    },
    "viewer": {
        "username": "viewer",
        "password": "viewer123",
        "role": "viewer"
    }
}


def authenticate_user(username, password):
    user = USERS_DB.get(username)
    if user and user['password'] == password:
        return {
            'username': user['username'],
            'role': user['role']
        }
    return None


def generate_token(username, role):
    try:
        payload = {
            'username': username,
            'role': role,
            'exp': datetime.utcnow() + timedelta(hours=24),
            'iat': datetime.utcnow()
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        return token
    except Exception as e:
        print(f"Error generating token: {e}")
        return None


def verify_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        print("Token has expired")
        return None
    except jwt.InvalidTokenError:
        print("Invalid token")
        return None


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({
                    'success': False,
                    'message': 'Invalid token format'
                }), 401
        
        if not token:
            return jsonify({
                'success': False,
                'message': 'Token is missing'
            }), 401
        
        payload = verify_token(token)
        if not payload:
            return jsonify({
                'success': False,
                'message': 'Token is invalid or expired'
            }), 401
        
        request.current_user = payload
        return f(*args, **kwargs)
    
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(request, 'current_user'):
            return jsonify({
                'success': False,
                'message': 'Authentication required'
            }), 401
        
        if request.current_user.get('role') != 'admin':
            return jsonify({
                'success': False,
                'message': 'Admin privileges required'
            }), 403
        
        return f(*args, **kwargs)
    
    return decorated


def get_all_users():
    users = []
    for username, user_data in USERS_DB.items():
        users.append({
            'username': user_data['username'],
            'role': user_data['role']
        })
    return users