from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return 'Hello, World!'

if __name__ == '__main__':
    print("Starting test Flask server...")
    app.run(debug=True, port=5001)

import unittest
import json
import numpy as np
from app import app, threat_system
import jwt
from datetime import datetime, timedelta

class TestThreatDetectionSystem(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SECRET_KEY'] = 'test-secret-key'
        app.config['API_KEY'] = 'test-api-key'
        self.client = app.test_client()
        self.valid_token = jwt.encode(
            {'api_key': 'test-api-key', 'exp': datetime.utcnow() + timedelta(days=1)},
            app.config['SECRET_KEY']
        )

    def get_auth_headers(self):
        return {'Authorization': f'Bearer {self.valid_token}'}

    def test_login_success(self):
        response = self.client.post('/api/login',
            json={'api_key': 'test-api-key'})
        self.assertEqual(response.status_code, 200)
        self.assertIn('token', response.json)

    def test_login_failure(self):
        response = self.client.post('/api/login',
            json={'api_key': 'wrong-key'})
        self.assertEqual(response.status_code, 401)

    def test_analyze_traffic_valid(self):
        test_data = {
            'traffic_data': np.array([1, 0, 1000, 500, 30, 2, 1500, 50])
        }
        response = self.client.post('/api/analyze',
            json=test_data,
            headers=self.get_auth_headers())
        self.assertEqual(response.status_code, 200)
        result = response.json
        self.assertIn('is_threat', result)
        self.assertIn('confidence', result)
        self.assertIn('threat_level', result)

    def test_analyze_traffic_invalid_input(self):
        response = self.client.post('/api/analyze',
            json={},
            headers=self.get_auth_headers())
        self.assertEqual(response.status_code, 400)

    def test_analyze_traffic_unauthorized(self):
        test_data = {
            'traffic_data': np.array([1, 0, 1000, 500, 30, 2, 1500, 50])
        }
        response = self.client.post('/api/analyze', json=test_data)
        self.assertEqual(response.status_code, 401)

    def test_get_recent_threats(self):
        # First add some threats
        test_data = {
            'traffic_data': np.array([1, 0, 1000, 500, 30, 2, 1500, 50])
        }
        self.client.post('/api/analyze',
            json=test_data,
            headers=self.get_auth_headers())

        response = self.client.get('/api/threats/recent',
            headers=self.get_auth_headers())
        self.assertEqual(response.status_code, 200)
        result = response.json
        self.assertIn('threats', result)
        self.assertIn('count', result)
        self.assertGreater(result['count'], 0)

    def test_get_statistics(self):
        # First add some threats
        test_data = {
            'traffic_data': np.array([1, 0, 1000, 500, 30, 2, 1500, 50])
        }
        self.client.post('/api/analyze',
            json=test_data,
            headers=self.get_auth_headers())

        response = self.client.get('/api/stats',
            headers=self.get_auth_headers())
        self.assertEqual(response.status_code, 200)
        result = response.json
        self.assertIn('total_threats', result)
        self.assertIn('threat_levels', result)
        self.assertIn('timeframe_hours', result)

    def test_predict_endpoint(self):
        test_data = {
            'protocol_type': 1,
            'service': 0,
            'src_bytes': 1000,
            'dst_bytes': 500,
            'duration': 30
        }
        response = self.client.post('/predict', json=test_data)
        self.assertEqual(response.status_code, 200)
        result = response.json
        self.assertIn('success', result)
        self.assertIn('prediction', result)
        self.assertIn('probability', result)
        self.assertIn('threat_level', result)

    def test_documentation_endpoint(self):
        response = self.client.get('/documentation')
        self.assertEqual(response.status_code, 200)
        result = response.json
        self.assertIn('protocol_types', result)
        self.assertIn('services', result)
        self.assertIn('metrics', result)
        self.assertIn('output', result)

    def test_threat_level_determination(self):
        self.assertEqual(threat_system._determine_threat_level(0.95), 'high')
        self.assertEqual(threat_system._determine_threat_level(0.85), 'medium')
        self.assertEqual(threat_system._determine_threat_level(0.55), 'low')
        self.assertEqual(threat_system._determine_threat_level(0.3), 'info')

if __name__ == '__main__':
    unittest.main()