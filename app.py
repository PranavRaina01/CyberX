from flask import Flask, request, jsonify, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from functools import wraps
from datetime import datetime, timedelta
from collections import defaultdict
import jwt
import logging
import os
import numpy as np
import sys
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential, ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient
from train_model import CyberSecurityModel

# Load environment variables
load_dotenv()

# Configure logging with structured logging
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('application.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

def get_key_vault_secret(secret_name):
    """Get secret from Azure Key Vault or environment variables"""
    # First try environment variables
    env_value = os.getenv(secret_name.replace('-', '_'))
    if env_value:
        return env_value
        
    # Fall back to Azure Key Vault if configured
    key_vault_url = os.getenv('KEY_VAULT_URL')
    if not key_vault_url:
        return None
        
    try:
        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=key_vault_url, credential=credential)
        return client.get_secret(secret_name).value
    except Exception as e:
        logger.warning(f"Could not retrieve secret from Key Vault: {str(e)}")
        return None

# Load configurations
app.config.update(
    TESTING=os.getenv('TESTING', 'False').lower() == 'true',
    SECRET_KEY=os.getenv('SECRET_KEY') or get_key_vault_secret('SECRET-KEY'),
    API_KEY=os.getenv('API_KEY') or get_key_vault_secret('API-KEY'),
    JWT_ALGORITHM=os.getenv('JWT_ALGORITHM', 'HS256'),
    JWT_EXPIRATION_DAYS=int(os.getenv('JWT_EXPIRATION_DAYS', '30'))
)

# Validate critical configurations
if not app.config['SECRET_KEY']:
    logger.error("Secret key not configured!")
    raise ValueError("Secret key must be configured in Key Vault or .env file")

if not app.config['API_KEY']:
    logger.error("API key not configured!")
    raise ValueError("API key must be configured in Key Vault or .env file")

# Setup rate limiter with configuration from environment
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[
        os.getenv('RATE_LIMIT_DEFAULT', "200 per day"),
        os.getenv('RATE_LIMIT_HOURLY', "50 per hour")
    ]
)

class ThreatDetectionSystem:
    def __init__(self):
        try:
            self.model = CyberSecurityModel.load_model('model.pkl')
            logger.info("Model loaded successfully")
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            self.model = None
        
        self.threat_cache = []
        self.alert_thresholds = {
            'high': 0.9,
            'medium': 0.7,
            'low': 0.5
        }

    def analyze_traffic(self, features):
        """
        Analyze network traffic and return threat assessment
        """
        try:
            # Handle both single array and 2D array inputs
            if len(features.shape) == 1:
                features_array = features.reshape(1, -1)
            else:
                features_array = features
                
            prediction, confidence = self.model.predict(features_array)
            
            threat_level = self._determine_threat_level(confidence[0])
            
            result = {
                'is_threat': bool(prediction[0]),
                'confidence': float(confidence[0]),
                'threat_level': threat_level,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            # Store in memory cache
            self.threat_cache.append(result)
            # Keep only last 1000 results
            if len(self.threat_cache) > 1000:
                self.threat_cache.pop(0)
            
            return result
        except Exception as e:
            logger.error(f"Error in traffic analysis: {str(e)}")
            raise

    def _determine_threat_level(self, confidence):
        """
        Determine threat level based on confidence score
        """
        if confidence >= self.alert_thresholds['high']:
            return 'high'
        elif confidence >= self.alert_thresholds['medium']:
            return 'medium'
        elif confidence >= self.alert_thresholds['low']:
            return 'low'
        return 'info'

    def get_cached_threats(self, hours=24):
        """
        Retrieve recent threats from memory cache
        """
        current_time = datetime.utcnow()
        return [
            threat for threat in self.threat_cache
            if current_time - datetime.fromisoformat(threat['timestamp']) <= timedelta(hours=hours)
        ]

# Initialize threat detection system
threat_system = ThreatDetectionSystem()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check for token in headers
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'error': 'Invalid Authorization header format'}), 401
        
        if not token:
            return jsonify({'error': 'Token is required'}), 401
        
        try:
            # Decode token with claims validation
            payload = jwt.decode(
                token,
                app.config['SECRET_KEY'],
                algorithms=[app.config['JWT_ALGORITHM']],
                options={
                    'verify_exp': True,
                    'require': ['exp', 'iat', 'sub', 'aud', 'iss']
                },
                audience='cybersecurity_api',
                issuer='cybersecurity_system'
            )
            
            request.token_payload = payload
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {str(e)}")
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    return decorated

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    try:
        auth = request.json
        if not auth or not auth.get('api_key'):
            return jsonify({'error': 'API key is required'}), 401
        
        if auth['api_key'] == app.config['API_KEY']:
            # Generate token with additional security claims
            token = jwt.encode(
                {
                    'sub': 'api_client',  # subject
                    'iat': datetime.utcnow(),  # issued at
                    'exp': datetime.utcnow() + timedelta(days=app.config['JWT_EXPIRATION_DAYS']),
                    'aud': 'cybersecurity_api',  # audience
                    'iss': 'cybersecurity_system'  # issuer
                },
                app.config['SECRET_KEY'],
                algorithm=app.config['JWT_ALGORITHM']
            )
            
            return jsonify({
                'token': token,
                'expires_in': app.config['JWT_EXPIRATION_DAYS'] * 24 * 3600  # seconds
            })
        
        return jsonify({'error': 'Invalid API key'}), 401
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Authentication failed'}), 500  # Generic error message for security

@app.route('/api/analyze', methods=['POST'])
@token_required
@limiter.limit("10 per minute")
def analyze_traffic():
    """
    Analyze network traffic for potential threats
    """
    try:
        if not threat_system.model:
            return jsonify({'error': 'Model not loaded'}), 500

        data = request.json
        if not data or 'traffic_data' not in data:
            return jsonify({'error': 'Invalid input format'}), 400

        features = data['traffic_data']
        result = threat_system.analyze_traffic(features)
        
        return jsonify(result)

    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/threats/recent', methods=['GET'])
@token_required
def get_recent_threats():
    """
    Get recent threat detections
    """
    try:
        hours = request.args.get('hours', default=24, type=int)
        threats = threat_system.get_cached_threats(hours)
        return jsonify({
            'threats': threats,
            'count': len(threats)
        })
    except Exception as e:
        logger.error(f"Error retrieving threats: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
@token_required
def get_statistics():
    """
    Get threat detection statistics
    """
    try:
        threats = threat_system.get_cached_threats()
        total_threats = len(threats)
        threat_levels = defaultdict(int)
        
        for threat in threats:
            threat_levels[threat['threat_level']] += 1
            
        return jsonify({
            'total_threats': total_threats,
            'threat_levels': dict(threat_levels),
            'timeframe_hours': 24
        })
    except Exception as e:
        logger.error(f"Error retrieving statistics: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Add route for web interface
@app.route('/')
def index():
    try:
        return render_template('index.html')
    except Exception as e:
        logger.error(f"Error rendering home page: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Get data from request
        data = request.get_json()
        if not data:
            data = request.form.to_dict()  # Handle form data if not JSON
        
        # Create feature dictionary with basic features
        features_dict = {
            'protocol_type': int(data['protocol_type']),
            'service': int(data['service']),
            'src_bytes': int(data['src_bytes']),
            'dst_bytes': int(data['dst_bytes']),
            'duration': int(data['duration'])
        }
        
        # Add engineered features
        features_dict['bytes_ratio'] = features_dict['src_bytes'] / (features_dict['dst_bytes'] + 1)
        features_dict['total_bytes'] = features_dict['src_bytes'] + features_dict['dst_bytes']
        features_dict['bytes_per_second'] = features_dict['total_bytes'] / (features_dict['duration'] + 1)
        
        # Convert to numpy array in correct order
        features = np.array([
            features_dict['protocol_type'],
            features_dict['service'],
            features_dict['src_bytes'],
            features_dict['dst_bytes'],
            features_dict['duration'],
            features_dict['bytes_ratio'],
            features_dict['total_bytes'],
            features_dict['bytes_per_second']
        ])
        
        # Make prediction using the threat detection system
        result = threat_system.analyze_traffic(features)
        
        return jsonify({
            'success': True,
            'prediction': int(result['is_threat']),
            'probability': float(result['confidence']),
            'threat_level': result['threat_level'].capitalize()
        })

    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/documentation')
def documentation():
    return jsonify({
        'protocol_types': {
            '0': 'TCP',
            '1': 'UDP',
            '2': 'ICMP'
        },
        'services': {
            '0': 'HTTP',
            '1': 'FTP',
            '2': 'SMTP',
            '3': 'SSH'
        },
        'metrics': {
            'src_bytes': 'Number of bytes sent from source to destination',
            'dst_bytes': 'Number of bytes sent from destination to source',
            'duration': 'Duration of the connection in seconds'
        },
        'output': {
            '0': 'Normal Traffic',
            '1': 'Potential Threat'
        }
    })

if __name__ == '__main__':
    logger.info("Starting Flask application...")
    debug_mode = os.getenv('FLASK_DEBUG', '0').lower() in ('1', 'true')
    app.run(debug=debug_mode, host='0.0.0.0', port=int(os.getenv('PORT', 5000)))