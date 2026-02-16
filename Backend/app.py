from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import numpy as np
import pandas as pd
import re
import pickle
import os
from sklearn.preprocessing import StandardScaler

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend requests

# Global variables for model and scaler
model = None
scaler = None

def extract_features(url):
    """Extract features from a URL"""
    feature_lst = []
    
    # 1. URL Length
    feature_lst.append(len(url))
    
    # 2. Count of '.'
    feature_lst.append(url.count('.'))
    
    # 3. Count of '/'
    feature_lst.append(url.count('/'))
    
    # 4. Count of '-'
    feature_lst.append(url.count('-'))
    
    # 5. Check whether 'https' is present
    feature_lst.append(1 if url.startswith('https') else 0)
    
    # 6. Check whether IP Address is present
    ip_pattern = re.compile(
        r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}'
    )
    feature_lst.append(1 if ip_pattern.search(url) else 0)
    
    # 7-11. Check suspicious keywords
    suspicious_words = ['login', 'verify', 'update', 'secure', 'account']
    for word in suspicious_words:
        feature_lst.append(1 if word in url.lower() else 0)
    
    return np.array(feature_lst).reshape(1, -1)

def load_model():
    """Load the trained model and scaler"""
    global model, scaler
    
    try:
        if os.path.exists('phishing_model.pkl'):
            with open('phishing_model.pkl', 'rb') as f:
                model = pickle.load(f)
            print("Model loaded successfully!")
        else:
            print("Model file not found. Please train the model first.")
            return False
            
        if os.path.exists('scaler.pkl'):
            with open('scaler.pkl', 'rb') as f:
                scaler = pickle.load(f)
            print("Scaler loaded successfully!")
        else:
            print("Scaler file not found. Please train the model first.")
            return False
            
        return True
    except Exception as e:
        print(f"Error loading model: {e}")
        return False

@app.route('/api/check-phishing', methods=['POST'])
def check_phishing():
    """
    API endpoint to check if a URL is phishing
    Expected JSON: {"url": "https://example.com"}
    """
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({
                'success': False,
                'error': 'URL is required',
                'message': 'Please enter a valid URL'
            }), 400
        
        # Validate URL format
        if not (url.startswith('http://') or url.startswith('https://')):
            url = 'https://' + url
        
        # Extract features
        features = extract_features(url)
        feature_values = features[0].tolist()  # Get actual values
        
        # Scale features
        if scaler is None:
            return jsonify({
                'success': False,
                'error': 'Model not initialized',
                'message': 'Server error: Model not loaded'
            }), 500
        
        scaled_features = scaler.transform(features)
        
        # Make prediction
        prediction = model.predict(scaled_features)[0]
        prediction_proba = model.predict_proba(scaled_features)[0]
        
        # Prepare response
        is_phishing = bool(prediction == 1)
        confidence = float(max(prediction_proba)) * 100
        
        # Detailed feature analysis
        feature_analysis = {
            'url_length': {
                'value': int(feature_values[0]),
                'status': 'High Risk' if feature_values[0] > 100 else 'Medium Risk' if feature_values[0] > 75 else 'Normal',
                'description': 'Length of the URL'
            },
            'num_dots': {
                'value': int(feature_values[1]),
                'status': 'Suspicious' if feature_values[1] > 5 else 'Normal',
                'description': 'Number of dots (.) in URL'
            },
            'num_hyphens': {
                'value': int(feature_values[2]),
                'status': 'Suspicious' if feature_values[2] > 4 else 'Normal',
                'description': 'Number of hyphens (-) in URL'
            },
            'num_slashes': {
                'value': int(feature_values[3]),
                'status': 'Suspicious' if feature_values[3] > 5 else 'Normal',
                'description': 'Number of slashes (/) in URL'
            },
            'has_https': {
                'value': 'Yes' if feature_values[4] == 1 else 'No',
                'status': 'Secure' if feature_values[4] == 1 else 'Not Secure',
                'description': 'HTTPS protocol presence'
            },
            'has_ip': {
                'value': 'Yes' if feature_values[5] == 1 else 'No',
                'status': 'Suspicious' if feature_values[5] == 1 else 'Normal',
                'description': 'IP address in URL'
            },
            'suspicious_keywords': {
                'keywords': [
                    {'name': 'login', 'found': bool(feature_values[6])},
                    {'name': 'verify', 'found': bool(feature_values[7])},
                    {'name': 'update', 'found': bool(feature_values[8])},
                    {'name': 'secure', 'found': bool(feature_values[9])},
                    {'name': 'account', 'found': bool(feature_values[10])}
                ],
                'count': int(sum(feature_values[6:11])),
                'status': 'High Risk' if sum(feature_values[6:11]) >= 3 else 'Warning' if sum(feature_values[6:11]) >= 1 else 'Normal'
            }
        }
        
        return jsonify({
            'success': True,
            'url': url,
            'is_phishing': is_phishing,
            'confidence': round(confidence, 2),
            'phishing_probability': round(float(prediction_proba[1]) * 100, 2),
            'legitimate_probability': round(float(prediction_proba[0]) * 100, 2),
            'message': 'Phishing detected! Be cautious.' if is_phishing else 'Website appears to be safe.',
            'features': feature_analysis
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'An error occurred while checking the URL'
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    model_status = "loaded" if model is not None else "not loaded"
    scaler_status = "loaded" if scaler is not None else "not loaded"
    
    return jsonify({
        'status': 'running',
        'model_status': model_status,
        'scaler_status': scaler_status
    }), 200

@app.route('/', methods=['GET'])
def home():
    """Serve the home page"""
    return render_template('index.html')

@app.route('/phishing', methods=['GET'])
def phishing():
    """Serve the phishing detection page"""
    return render_template('PHISHING.HTML')

@app.route('/knowmore', methods=['GET'])
def knowmore():
    """Serve the about page"""
    try:
        return render_template('knowmore.html')
    except:
        return "<h1>About Page - Under Construction</h1>"

@app.route('/contact', methods=['GET'])
def contact():
    """Serve the contact page"""
    try:
        return render_template('contact.html')
    except:
        return "<h1>Contact Page - Under Construction</h1>"

if __name__ == '__main__':
    # Load model on startup
    if load_model():
        print("Starting Flask server...")
        print("Frontend available at: http://0.0.0.0:5000/")
        print("API available at: http://0.0.0.0:5000/api/")
        app.run(debug=True, host='0.0.0.0', port=5000)
    else:
        print("Failed to load model. Please train it first using train_model.py")
