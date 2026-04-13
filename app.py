from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import numpy as np
import pandas as pd
import re
import pickle
import os
import requests
import json
from difflib import SequenceMatcher
from sklearn.preprocessing import StandardScaler
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend requests

# Global variables for model and scaler
model = None
scaler = None

def extract_features(url):
    """Extract 31 advanced features from a URL"""
    feature_lst = []

    # ============ EXISTING 11 FEATURES ============

    # 1. URL Length
    feature_lst.append(len(url))

    # 2. Count of '.'
    feature_lst.append(url.count('.'))

    # 3. Count of '/'
    feature_lst.append(url.count('/'))

    # 4. Count of '-'
    feature_lst.append(url.count('-'))

    # 5. HTTPS protocol
    feature_lst.append(1 if url.startswith('https') else 0)

    # 6. IP Address present
    ip_pattern = re.compile(r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}')
    feature_lst.append(1 if ip_pattern.search(url) else 0)

    # 7-11. Suspicious keywords
    suspicious_words = ['login', 'verify', 'update', 'secure', 'account']
    for word in suspicious_words:
        feature_lst.append(1 if word in url.lower() else 0)

    # ============ NEW 20 FEATURES ============

    try:
        # Add http:// if missing for proper parsing
        parsed_url = url if url.startswith(('http://', 'https://')) else 'http://' + url
        parsed = urlparse(parsed_url)
        domain = parsed.netloc
        path = parsed.path

        # 12. Subdomain Count
        subdomain_count = domain.count('.') - 1 if '.' in domain else 0
        feature_lst.append(min(subdomain_count, 5))

        # 13. Domain Length
        feature_lst.append(len(domain))

        # 14. TLD Length
        tld = domain.split('.')[-1] if '.' in domain else domain
        feature_lst.append(len(tld))

        # 15. @ Symbol present
        feature_lst.append(1 if '@' in url else 0)

        # 16. Double slash position check
        double_slash_pos = url.find('//')
        after_protocol = url.find('//', 6) if double_slash_pos != -1 else -1
        feature_lst.append(1 if after_protocol != -1 else 0)

        # 17. Consecutive digits
        consecutive_digits = 1 if re.search(r'\d{4,}', url) else 0
        feature_lst.append(consecutive_digits)

        # 18. Special characters count
        special_chars = len(re.findall(r'[&%$=]', url))
        feature_lst.append(min(special_chars, 5))

        # 19. Port number present
        feature_lst.append(1 if ':' in domain else 0)

        # 20. Redirect indicators
        redirect_keywords = ['redirect', '/go/', '/go?', 'goto', 'redirecturl']
        feature_lst.append(1 if any(kw in url.lower() for kw in redirect_keywords) else 0)

        # 21. Query parameters count
        query_param_count = url.count('?')
        feature_lst.append(min(query_param_count, 3))

        # 22. Form action indicators
        form_suspicious = 1 if any(kw in url.lower() for kw in ['action=', 'formsubmit']) else 0
        feature_lst.append(form_suspicious)

        # 23. External links indicators
        external_links = url.count('http') - 1
        feature_lst.append(min(external_links, 3))

        # 24. Embedded object count
        embedded = len(re.findall(r'(src|href)=', url.lower()))
        feature_lst.append(min(embedded, 3))

        # 25. JavaScript indicators
        js_indicators = 1 if any(kw in url.lower() for kw in ['.js', 'javascript:', 'onclick']) else 0
        feature_lst.append(js_indicators)

        # 26. Suspicious TLDs
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'top', 'download']
        feature_lst.append(1 if tld in suspicious_tlds else 0)

        # 27. Punycode present
        feature_lst.append(1 if 'xn--' in url else 0)

        # 28. Extra slashes
        feature_lst.append(1 if url.count('/') > 7 else 0)

        # 29. Very long domain
        feature_lst.append(1 if len(domain) > 50 else 0)

        # 30. Percent encoding
        feature_lst.append(1 if '%' in url else 0)

        # 31. URL contains both http and https
        feature_lst.append(1 if url.count('http') > 1 else 0)

    except Exception:
        # If parsing fails, add zeros for new features
        for _ in range(20):
            feature_lst.append(0)

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

def detect_phishing_rules(url):
    """Rule-based phishing detection for domain squatting and known patterns"""
    phishing_score = 0.0
    flags = []

    def get_root_domain(hostname):
        parts = [p for p in hostname.split('.') if p]
        if len(parts) >= 2:
            return parts[-2]
        return parts[0] if parts else ''

    def normalize_leetspeak(text):
        substitutions = str.maketrans({
            '0': 'o',
            '1': 'l',
            '3': 'e',
            '4': 'a',
            '5': 's',
            '7': 't',
            '8': 'b',
            '9': 'g',
            '@': 'a',
            '$': 's'
        })
        return text.translate(substitutions)

    parsed = urlparse(url)
    domain = (parsed.hostname or parsed.netloc or '').lower()
    path = parsed.path.lower()
    root_domain = get_root_domain(domain)
    normalized_root = normalize_leetspeak(root_domain.replace('-', ''))
    domain_squatting_detected = False
    domain_squatting_flags = []
    known_brands = ['paypal', 'apple', 'amazon', 'google', 'microsoft', 'facebook', 'twitter', 'netflix', 'steam', 'superbet']

    # 1. Domain squatting detection layer
    # 1A. Numeric prefix/suffix with brand tokens (e.g., 1829superbet, paypal2026)
    if root_domain:
        if root_domain[0].isdigit() or root_domain[-1].isdigit():
            for brand in known_brands:
                if brand in normalized_root:
                    phishing_score += 0.9
                    message = f"Domain squatting: numeric affix around brand token ({root_domain})"
                    flags.append(message)
                    domain_squatting_flags.append(message)
                    domain_squatting_detected = True
                    break

    # 1B. Leetspeak brand mimicry (e.g., paypa1, g00gle)
    if root_domain:
        for brand in known_brands:
            if brand in normalized_root and brand not in root_domain:
                phishing_score += 0.75
                message = f"Domain squatting: leetspeak brand mimicry ({root_domain} -> {brand})"
                flags.append(message)
                domain_squatting_flags.append(message)
                domain_squatting_detected = True
                break

    # 1C. Typo-squatting based on string similarity
    if root_domain and not domain_squatting_detected:
        for brand in known_brands:
            similarity = SequenceMatcher(None, normalized_root, brand).ratio()
            if 0.78 <= similarity < 1.0 and len(normalized_root) >= 5:
                phishing_score += 0.7
                message = f"Domain squatting: typo-mimic detected ({root_domain} ~ {brand})"
                flags.append(message)
                domain_squatting_flags.append(message)
                domain_squatting_detected = True
                break

    # 2. High-Risk TLDs
    high_risk_tlds = ['tk', 'ml', 'ga', 'cf', 'top', 'download', 'baby', 'space', 'click',
                      'date', 'faith', 'gdn', 'loan', 'party', 'racing', 'review', 'trade',
                      'webcam', 'win', 'work', 'xyz', 'zip', 'pw', 'online', 'site', 'website', 'icu', 'tech', 'info', 'bid']
    tld = domain.split('.')[-1]
    if tld in high_risk_tlds:
        phishing_score += 0.6
        flags.append(f"High-risk TLD detected: .{tld}")

    # 3. Brand Mimicry (contains a brand in longer lookalike hostname)
    for brand in known_brands:
        if brand in domain and domain != brand:  # Contains brand but isn't exact
            # Check for subtle variations
            if len(domain) - len(brand) < 5:  # Similar length
                phishing_score += 0.7
                flags.append(f"Possible brand mimicry: {brand}")
                break

    # 4. Suspicious URL Parameters
    if '&id=' in url or (url.count('=') > 3 and url.count('&') > 2):
        phishing_score += 0.5
        flags.append("Suspicious URL parameters detected")

    # 5. Very Long URL (common in phishing)
    if len(url) > 120:
        phishing_score += 0.4
        flags.append("Unusually long URL")

    # 6. Suspicious Keywords in URL
    suspicious_keywords = ['verify', 'confirm', 'update', 'login', 'secure', 'account',
                          'bank', 'paypal', 'amazon', 'payment', 'credential']
    for keyword in suspicious_keywords:
        if keyword in domain or keyword in path:
            phishing_score += 0.3
            flags.append(f"Suspicious keyword: {keyword}")
            break

    # 7. No HTTPS
    if not url.startswith('https'):
        phishing_score += 0.3
        flags.append("No HTTPS protocol")

    # Cap score at 1.0
    phishing_score = min(phishing_score, 1.0)

    return {
        'rule_score': phishing_score,
        'flags': flags,
        'is_phishing_rule': phishing_score > 0.5,
        'domain_squatting_detected': domain_squatting_detected,
        'domain_squatting_flags': domain_squatting_flags
    }

def get_llm_analysis(url, phishing_data):
    """Get AI analysis using Ollama for the phishing detection result"""
    try:
        # Extract model features from new format
        model_features = phishing_data.get('model_analysis', {}).get('features', {})
        rule_flags = phishing_data.get('rule_analysis', {}).get('flags', [])

        # Prepare the prompt for Ollama with structured output format
        prompt = f"""You are a cybersecurity expert analyzing a phishing detection result. Provide structured analysis.

URL Analyzed: {url}
Detection Result: {'PHISHING ALERT - DANGEROUS' if phishing_data['is_phishing'] else 'SAFE - LEGITIMATE'}
Confidence: {phishing_data['confidence']}%

Key Findings:
- URL Length: {model_features.get('url_length', {}).get('value', 'N/A')} ({model_features.get('url_length', {}).get('status', 'N/A')})
- HTTPS Protocol: {model_features.get('has_https', {}).get('value', 'N/A')} ({model_features.get('has_https', {}).get('status', 'N/A')})
- IP Address Present: {model_features.get('has_ip', {}).get('value', 'N/A')} ({model_features.get('has_ip', {}).get('status', 'N/A')})
- Suspicious Keywords: {model_features.get('suspicious_keywords', {}).get('count', 0)}
- Rule-Based Flags: {len(rule_flags)} detected

CRITICAL: Format your response EXACTLY as follows with these section headers and values:

VERDICT: [PHISHING or SAFE]
CONFIDENCE: [number from 0 to 100]

ASSESSMENT:
[Write 2-3 sentences summarizing whether this is safe or dangerous]

KEY FINDINGS:
[List 2-3 main security concerns or positive confirmations]

RECOMMENDATIONS:
[Provide 2-3 specific actions the user should take]

Be concise and actionable."""

        # Get Ollama host from environment or use default
        ollama_host = os.getenv('OLLAMA_HOST', 'http://127.0.0.1:11434')

        # Call Ollama API
        response = requests.post(
            f'{ollama_host}/api/generate',
            json={
                'model': 'gemma4:31b-cloud',
                'prompt': prompt,
                'stream': False,
                'temperature': 0.3
            },
            timeout=120
        )

        if response.status_code == 200:
            result = response.json()
            analysis_text = result.get('response', '').strip()

            verdict_match = re.search(r'VERDICT:\s*(PHISHING|SAFE)', analysis_text, re.IGNORECASE)
            confidence_match = re.search(r'CONFIDENCE:\s*([0-9]+(?:\.[0-9]+)?)', analysis_text, re.IGNORECASE)
            assessment_match = re.search(r'ASSESSMENT:\s*([\s\S]*?)(?=KEY FINDINGS:|$)', analysis_text, re.IGNORECASE)
            findings_match = re.search(r'KEY FINDINGS:\s*([\s\S]*?)(?=RECOMMENDATIONS:|$)', analysis_text, re.IGNORECASE)
            recommendations_match = re.search(r'RECOMMENDATIONS:\s*([\s\S]*?)$', analysis_text, re.IGNORECASE)

            verdict = verdict_match.group(1).upper() if verdict_match else ('PHISHING' if phishing_data.get('is_phishing') else 'SAFE')
            llm_confidence = float(confidence_match.group(1)) if confidence_match else 70.0
            llm_confidence = max(0.0, min(llm_confidence, 100.0))
            llm_risk_score = llm_confidence / 100 if verdict == 'PHISHING' else 1 - (llm_confidence / 100)

            return {
                'success': True,
                'analysis': analysis_text,
                'verdict': verdict,
                'confidence': round(llm_confidence, 2),
                'phishing_risk_score': round(llm_risk_score * 100, 2),
                'assessment': assessment_match.group(1).strip() if assessment_match else analysis_text,
                'key_findings': findings_match.group(1).strip() if findings_match else '',
                'recommendations': recommendations_match.group(1).strip() if recommendations_match else ''
            }
        else:
            return {
                'success': False,
                'error': f'Ollama API error: {response.status_code}'
            }

    except requests.exceptions.ConnectionError:
        return {
            'success': False,
            'error': 'Ollama is not running. Make sure to run: ollama serve'
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

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

        # Handle predict_proba for models that only saw one class
        try:
            prediction_proba = model.predict_proba(scaled_features)[0]
            # If model only knows one class, ensure we have 2 probabilities
            if len(prediction_proba) == 1:
                if prediction == 1:
                    prediction_proba = [0.0, 1.0]
                else:
                    prediction_proba = [1.0, 0.0]
        except:
            # Fallback if predict_proba fails
            prediction_proba = [1.0 - float(prediction), float(prediction)]

        # Prepare response
        is_phishing = bool(prediction == 1)
        # Get rule-based detection
        rule_result = detect_phishing_rules(url)
        rule_score = rule_result['rule_score']
        rule_flags = rule_result['flags']

        # ===== WEIGHTED ENSEMBLE SCORING =====
        # Base engine (50%): Model 40% + Rule-based 10%
        # LLM (50%): Gemma4 analysis
        model_prob = float(prediction_proba[1])  # Phishing probability from model
        base_engine_score = (model_prob * 0.4) + (rule_score * 0.1)

        # Detailed feature analysis (using first 11 features for display)
        # Note: Model uses 31 features but we show the key 11 for user understanding
        feature_analysis = {
            'url_length': {
                'value': f"{int(feature_values[0])} characters" if len(feature_values) > 0 else "N/A",
                'status': 'High Risk' if len(feature_values) > 0 and feature_values[0] > 100 else ('Medium Risk' if len(feature_values) > 0 and feature_values[0] > 75 else 'Normal'),
                'description': 'Length of the URL'
            },
            'num_dots': {
                'value': int(feature_values[1]) if len(feature_values) > 1 else 0,
                'status': 'Suspicious' if len(feature_values) > 1 and feature_values[1] > 5 else 'Normal',
                'description': 'Number of dots (.) in URL'
            },
            'num_slashes': {
                'value': int(feature_values[3]) if len(feature_values) > 3 else 0,
                'status': 'Suspicious' if len(feature_values) > 3 and feature_values[3] > 5 else 'Normal',
                'description': 'Number of slashes (/) in URL'
            },
            'num_hyphens': {
                'value': int(feature_values[2]) if len(feature_values) > 2 else 0,
                'status': 'Suspicious' if len(feature_values) > 2 and feature_values[2] > 4 else 'Normal',
                'description': 'Number of hyphens (-) in URL'
            },
            'has_https': {
                'value': 'Yes' if len(feature_values) > 4 and feature_values[4] == 1 else 'No',
                'status': 'Secure' if len(feature_values) > 4 and feature_values[4] == 1 else 'Not Secure',
                'description': 'HTTPS protocol presence'
            },
            'has_ip': {
                'value': 'Yes' if len(feature_values) > 5 and feature_values[5] == 1 else 'No',
                'status': 'Suspicious' if len(feature_values) > 5 and feature_values[5] == 1 else 'Normal',
                'description': 'IP address in URL'
            },
            'suspicious_keywords': {
                'keywords': [
                    {'name': 'login', 'found': bool(feature_values[6]) if len(feature_values) > 6 else False},
                    {'name': 'verify', 'found': bool(feature_values[7]) if len(feature_values) > 7 else False},
                    {'name': 'update', 'found': bool(feature_values[8]) if len(feature_values) > 8 else False},
                    {'name': 'secure', 'found': bool(feature_values[9]) if len(feature_values) > 9 else False},
                    {'name': 'account', 'found': bool(feature_values[10]) if len(feature_values) > 10 else False}
                ],
                'count': int(sum(feature_values[6:11])) if len(feature_values) > 10 else 0,
                'status': 'High Risk' if len(feature_values) > 10 and sum(feature_values[6:11]) >= 3 else ('Warning' if len(feature_values) > 10 and sum(feature_values[6:11]) >= 1 else 'Normal')
            }
        }

        preliminary_confidence = max(base_engine_score, 1 - base_engine_score) * 100
        preliminary_is_phishing = base_engine_score > 0.5
        preliminary_data = {
            'is_phishing': preliminary_is_phishing,
            'confidence': round(preliminary_confidence, 2),
            'model_analysis': {'features': feature_analysis},
            'rule_analysis': {'flags': rule_flags}
        }

        llm_result = get_llm_analysis(url, preliminary_data)
        llm_success = llm_result.get('success', False)

        if llm_success:
            llm_risk_prob = float(llm_result.get('phishing_risk_score', 50.0)) / 100
        else:
            # Neutral fallback if LLM is unavailable
            llm_risk_prob = 0.5

        # Weighted ensemble score
        ensemble_score = base_engine_score + (llm_risk_prob * 0.5)

        # Final decision
        is_phishing_final = ensemble_score > 0.5
        final_confidence = max(ensemble_score, 1 - ensemble_score) * 100

        # ===== END WEIGHTED ENSEMBLE =====
        

        model_verdict_confidence = (model_prob if is_phishing else float(prediction_proba[0])) * 100
        rule_verdict_confidence = (rule_score if rule_result['is_phishing_rule'] else (1 - rule_score)) * 100

        return jsonify({
            'success': True,
            'url': url,
            # Final Ensemble Result
            'is_phishing': is_phishing_final,
            'confidence': round(final_confidence, 2),
            'message': 'Phishing detected! Be cautious.' if is_phishing_final else 'Website appears to be safe.',
            'ensemble_analysis': {
                'verdict': 'PHISHING' if is_phishing_final else 'SAFE',
                'is_phishing': is_phishing_final,
                'confidence': round(final_confidence, 2),
                'phishing_risk_score': round(ensemble_score * 100, 2),
                'threshold': 50.0,
                'weights': {
                    'model_weight': 0.4,
                    'rule_weight': 0.1,
                    'llm_weight': 0.5
                },
                'contributions': {
                    'model_contribution': round(model_prob * 40, 2),
                    'rule_contribution': round(rule_score * 10, 2),
                    'llm_contribution': round(llm_risk_prob * 50, 2)
                }
            },

            # Model Analysis Details
            'model_analysis': {
                'is_phishing': is_phishing,
                'verdict': 'PHISHING' if is_phishing else 'SAFE',
                'confidence': round(model_verdict_confidence, 2),
                'phishing_probability': round(float(prediction_proba[1]) * 100, 2),
                'legitimate_probability': round(float(prediction_proba[0]) * 100, 2),
                'features': feature_analysis
            },

            # Rule-Based Analysis Details
            'rule_analysis': {
                'score': round(rule_score * 100, 2),
                'is_phishing': rule_result['is_phishing_rule'],
                'verdict': 'PHISHING' if rule_result['is_phishing_rule'] else 'SAFE',
                'confidence': round(rule_verdict_confidence, 2),
                'domain_squatting_detected': rule_result['domain_squatting_detected'],
                'domain_squatting_flags': rule_result['domain_squatting_flags'],
                'flags': rule_flags
            },
            'llm_analysis': {
                'success': llm_success,
                'model': 'gemma4:31b-cloud',
                'verdict': llm_result.get('verdict', 'UNKNOWN') if llm_success else 'UNAVAILABLE',
                'confidence': llm_result.get('confidence', 0.0) if llm_success else 0.0,
                'phishing_risk_score': llm_result.get('phishing_risk_score', 50.0) if llm_success else 50.0,
                'assessment': llm_result.get('assessment', ''),
                'key_findings': llm_result.get('key_findings', ''),
                'recommendations': llm_result.get('recommendations', ''),
                'analysis': llm_result.get('analysis', ''),
                'error': llm_result.get('error') if not llm_success else None
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'An error occurred while checking the URL'
        }), 500

@app.route('/api/llm-analysis', methods=['POST'])
def llm_analysis():
    """Get AI analysis for a phishing detection result"""
    try:
        data = request.json
        url = data.get('url', '')
        phishing_data = data.get('phishing_data', {})

        if not url or not phishing_data:
            return jsonify({
                'success': False,
                'error': 'Missing URL or phishing detection data'
            }), 400

        # Get LLM analysis from Ollama
        analysis_result = get_llm_analysis(url, phishing_data)

        return jsonify(analysis_result), 200 if analysis_result['success'] else 500

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'message': 'An error occurred while generating AI analysis'
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
