"""
Flask API Server for Wireless Threat Detection Dashboard
Connects React frontend with Python backend

NEW: Added Authentication & Authorization System

Endpoints:
- POST /api/auth/login       - User login (returns JWT token)
- POST /api/auth/verify      - Verify JWT token
- POST /api/auth/logout      - User logout
- POST /api/upload-pcap      - Upload and analyze PCAP/PCAPNG file (AUTH REQUIRED)
- POST /api/upload-csv       - Upload and analyze CSV file (AUTH REQUIRED)
- GET  /api/status           - Check server status
- GET  /api/results          - Get latest analysis results (AUTH REQUIRED)
- GET  /api/threats          - Get supported threats list
- POST /api/train            - Train model with custom data (ADMIN ONLY)
- GET  /api/export/<filename>- Download results file (AUTH REQUIRED)
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import json
from datetime import datetime

# Import your wireless analyzer
from wireless_analyzer import WirelessVulnerabilityAnalyzer

# Import authentication functions
from auth import (
    authenticate_user,
    generate_token,
    verify_token,
    token_required,
    admin_required,
    get_all_users
)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configuration
UPLOAD_FOLDER = '../data/uploads'
RESULTS_FOLDER = '../results'
ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'csv'}
MAX_FILE_SIZE = 100 * 1024 * 1024

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Create folders if they don't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(RESULTS_FOLDER, exist_ok=True)

# Initialize analyzer
analyzer = WirelessVulnerabilityAnalyzer()

# Store latest results
latest_results = None


def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({
                'success': False,
                'message': 'Username and password required'
            }), 400
        
        username = data['username']
        password = data['password']
        
        user = authenticate_user(username, password)
        
        if user is None:
            return jsonify({
                'success': False,
                'message': 'Invalid username or password'
            }), 401
        
        token = generate_token(user['username'], user['role'])
        
        if token is None:
            return jsonify({
                'success': False,
                'message': 'Error generating token'
            }), 500
        
        print(f"[+] User logged in: {username} (Role: {user['role']})")
        
        return jsonify({
            'success': True,
            'token': token,
            'username': user['username'],
            'role': user['role'],
            'message': 'Login successful'
        }), 200
    
    except Exception as e:
        print(f"[-] Login error: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Login error',
            'details': str(e)
        }), 500


@app.route('/api/auth/verify', methods=['POST'])
def verify():
    """Verify JWT token"""
    try:
        data = request.get_json()
        
        if not data or 'token' not in data:
            return jsonify({
                'valid': False,
                'message': 'Token required'
            }), 400
        
        token = data['token']
        payload = verify_token(token)
        
        if payload is None:
            return jsonify({
                'valid': False,
                'message': 'Invalid or expired token'
            }), 401
        
        return jsonify({
            'valid': True,
            'username': payload['username'],
            'role': payload['role']
        }), 200
    
    except Exception as e:
        return jsonify({
            'valid': False,
            'message': 'Verification error'
        }), 500


@app.route('/api/auth/logout', methods=['POST'])
@token_required
def logout():
    """User logout endpoint"""
    username = request.current_user['username']
    print(f"[+] User logged out: {username}")
    
    return jsonify({
        'success': True,
        'message': 'Logged out successfully'
    }), 200


@app.route('/api/auth/users', methods=['GET'])
@token_required
@admin_required
def list_users():
    """Get list of all users (Admin only)"""
    users = get_all_users()
    return jsonify({
        'success': True,
        'users': users,
        'total': len(users)
    }), 200


@app.route('/')
def index():
    """API root endpoint"""
    return jsonify({
        'name': 'Wireless Threat Detection API',
        'version': '2.0.0',
        'status': 'running',
        'authentication': 'enabled',
        'threats': 13,
        'supported_formats': ['pcap', 'pcapng', 'csv'],
        'max_file_size': '100MB',
        'endpoints': {
            'login': '/api/auth/login',
            'verify': '/api/auth/verify',
            'upload_pcap': '/api/upload-pcap (AUTH)',
            'upload_csv': '/api/upload-csv (AUTH)',
            'status': '/api/status',
            'results': '/api/results (AUTH)',
            'threats': '/api/threats'
        }
    })


@app.route('/api/status', methods=['GET'])
def get_status():
    """Get server and analyzer status"""
    return jsonify({
        'status': 'online',
        'timestamp': datetime.now().isoformat(),
        'analyzer_ready': True,
        'model_trained': analyzer.classifier.is_trained,
        'threats_supported': len(analyzer.classifier.class_labels),
        'authentication': 'enabled'
    })


@app.route('/api/threats', methods=['GET'])
def get_threats():
    """Get list of supported threats"""
    return jsonify({
        'total_threats': len(analyzer.classifier.class_labels) - 1,
        'threats': analyzer.classifier.class_labels[1:],
        'descriptions': {
            threat: analyzer.classifier.threat_descriptions[threat]
            for threat in analyzer.classifier.class_labels
        }
    })


@app.route('/api/upload-pcap', methods=['POST'])
@token_required
def upload_pcap():
    """Upload and analyze PCAP/PCAPNG file (AUTH REQUIRED)"""
    global latest_results
    
    try:
        username = request.current_user['username']
        print(f"[+] PCAP upload by user: {username}")
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({
                'error': 'Invalid file format',
                'allowed': ['pcap', 'pcapng', 'csv']
            }), 400
        
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        unique_filename = f"{timestamp}_{username}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        print(f"[+] Saving file: {filepath}")
        file.save(filepath)
        
        file_size = os.path.getsize(filepath)
        print(f"[+] File size: {file_size / 1024 / 1024:.2f}MB")
        
        print(f"[+] Starting analysis...")
        results = analyzer.analyze_pcap(filepath)
        
        if results is None:
            return jsonify({'error': 'Analysis failed'}), 500
        
        results['analyzed_by'] = username
        results['analyzed_at'] = datetime.now().isoformat()
        
        latest_results = results
        
        results_filename = f"{timestamp}_{username}_results.json"
        results_path = os.path.join(RESULTS_FOLDER, results_filename)
        with open(results_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"[+] Analysis complete! Results saved to: {results_path}")
        
        return jsonify({
            'success': True,
            'message': 'Analysis completed successfully',
            'filename': filename,
            'file_size_mb': round(file_size / 1024 / 1024, 2),
            'results': results,
            'results_file': results_filename
        })
    
    except Exception as e:
        print(f"[-] Error during analysis: {str(e)}")
        return jsonify({
            'error': 'Analysis error',
            'details': str(e)
        }), 500


@app.route('/api/upload-csv', methods=['POST'])
@token_required
def upload_csv():
    """Upload and analyze CSV file (AUTH REQUIRED)"""
    global latest_results
    
    try:
        username = request.current_user['username']
        print(f"[+] CSV upload by user: {username}")
        
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not file.filename.endswith('.csv'):
            return jsonify({'error': 'File must be CSV format'}), 400
        
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        unique_filename = f"{timestamp}_{username}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        print(f"[+] Saving CSV: {filepath}")
        file.save(filepath)
        
        file_size = os.path.getsize(filepath)
        print(f"[+] File size: {file_size / 1024 / 1024:.2f}MB")
        
        print(f"[+] Starting CSV analysis...")
        results = analyzer.analyze_csv(filepath)
        
        if results is None:
            return jsonify({'error': 'Analysis failed'}), 500
        
        results['analyzed_by'] = username
        results['analyzed_at'] = datetime.now().isoformat()
        
        latest_results = results
        
        results_filename = f"{timestamp}_{username}_csv_results.json"
        results_path = os.path.join(RESULTS_FOLDER, results_filename)
        with open(results_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"[+] CSV analysis complete!")
        
        return jsonify({
            'success': True,
            'message': 'CSV analysis completed successfully',
            'filename': filename,
            'file_size_mb': round(file_size / 1024 / 1024, 2),
            'results': results,
            'results_file': results_filename
        })
    
    except Exception as e:
        print(f"[-] Error during CSV analysis: {str(e)}")
        return jsonify({
            'error': 'CSV analysis error',
            'details': str(e)
        }), 500


@app.route('/api/results', methods=['GET'])
@token_required
def get_results():
    """Get latest analysis results (AUTH REQUIRED)"""
    if latest_results is None:
        return jsonify({
            'message': 'No analysis results available',
            'available': False
        })
    
    return jsonify({
        'available': True,
        'results': latest_results
    })


@app.route('/api/export/<filename>', methods=['GET'])
@token_required
def export_results(filename):
    """Download results file (AUTH REQUIRED)"""
    try:
        return send_from_directory(RESULTS_FOLDER, filename, as_attachment=True)
    except:
        return jsonify({'error': 'File not found'}), 404


@app.route('/api/train', methods=['POST'])
@token_required
@admin_required
def train_model():
    """Train model with custom dataset (ADMIN ONLY)"""
    try:
        username = request.current_user['username']
        print(f"[+] Model training requested by admin: {username}")
        
        data = request.get_json()
        
        return jsonify({
            'success': True,
            'message': 'Model training not yet implemented',
            'note': 'Model is pre-trained and ready to use',
            'requested_by': username
        })
    
    except Exception as e:
        return jsonify({
            'error': 'Training error',
            'details': str(e)
        }), 500


@app.errorhandler(413)
def file_too_large(e):
    """Handle file size exceeded error"""
    return jsonify({
        'error': 'File too large',
        'max_size': '100MB'
    }), 413


@app.errorhandler(500)
def internal_error(e):
    """Handle internal server errors"""
    return jsonify({
        'error': 'Internal server error',
        'details': str(e)
    }), 500


@app.errorhandler(401)
def unauthorized(e):
    """Handle unauthorized access"""
    return jsonify({
        'error': 'Unauthorized',
        'message': 'Authentication required'
    }), 401


@app.errorhandler(403)
def forbidden(e):
    """Handle forbidden access"""
    return jsonify({
        'error': 'Forbidden',
        'message': 'Insufficient permissions'
    }), 403


if __name__ == '__main__':
    print("\n" + "="*70)
    print("WIRELESS THREAT DETECTION API SERVER v2.0")
    print("="*70)
    print(f"Authentication: ENABLED")
    print(f"Server starting on: http://localhost:5000")
    print(f"Supported threats: {len(analyzer.classifier.class_labels) - 1}")
    print(f"Max file size: 100MB")
    print(f"Supported formats: PCAP, PCAPNG, CSV")
    print("="*70)
    print("\nDemo Login Credentials:")
    print("  Username: admin    | Password: admin123    | Role: Admin")
    print("  Username: analyst  | Password: analyst123  | Role: Analyst")
    print("  Username: viewer   | Password: viewer123   | Role: Viewer")
    print("="*70)
    print("\nEndpoints:")
    print("  POST http://localhost:5000/api/auth/login")
    print("  POST http://localhost:5000/api/auth/verify")
    print("  GET  http://localhost:5000/api/status")
    print("  GET  http://localhost:5000/api/threats")
    print("  POST http://localhost:5000/api/upload-pcap (AUTH)")
    print("  POST http://localhost:5000/api/upload-csv (AUTH)")
    print("  GET  http://localhost:5000/api/results (AUTH)")
    print("  GET  http://localhost:5000/api/export/<file> (AUTH)")
    print("  POST http://localhost:5000/api/train (ADMIN)")
    print("="*70)
    print("\nPress Ctrl+C to stop server\n")
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        threaded=True
    )