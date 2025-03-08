from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import tensorflow as tf
import spacy
import joblib
import numpy as np
from urllib.parse import urlparse
import tldextract
from bs4 import BeautifulSoup
import requests
from preprocessing.url_features import extract_url_features
from preprocessing.text_features import extract_text_features
from models.phishing_classifier import PhishingClassifier

app = Flask(__name__)
CORS(app)

# HTML template for the home page
HOME_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Phishing Detection API</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
            line-height: 1.6;
            background-color: #f0f2f5;
        }
        .header {
            text-align: center;
            padding: 20px;
            background: #2196F3;
            color: white;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        .endpoint {
            background: white;
            padding: 25px;
            margin: 20px 0;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        code {
            background: #e0e0e0;
            padding: 2px 5px;
            border-radius: 3px;
        }
        h2 {
            color: #2196F3;
            margin-top: 0;
        }
        .test-form {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"], textarea {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
            margin-bottom: 10px;
        }
        textarea {
            height: 100px;
            resize: vertical;
        }
        button {
            background: #2196F3;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }
        button:hover {
            background: #1976D2;
        }
        .result {
            margin-top: 15px;
            padding: 15px;
            border-radius: 4px;
            display: none;
        }
        .success {
            background: #e8f5e9;
            border: 1px solid #a5d6a7;
        }
        .error {
            background: #ffebee;
            border: 1px solid #ffcdd2;
        }
        .risk-high {
            color: #d32f2f;
            font-weight: bold;
        }
        .risk-medium {
            color: #f57c00;
            font-weight: bold;
        }
        .risk-low {
            color: #388e3c;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Phishing Detection API</h1>
        <p>Test our AI-powered phishing detection system</p>
    </div>
    
    <div class="endpoint">
        <h2>📡 Analyze URL</h2>
        <p><strong>Endpoint:</strong> <code>POST /api/analyze_url</code></p>
        <p><strong>Description:</strong> Analyzes a URL for potential phishing indicators.</p>
        
        <div class="test-form">
            <div class="form-group">
                <label for="url-input">Test a URL:</label>
                <input type="text" id="url-input" placeholder="Enter a URL (e.g., https://example.com)">
                <button onclick="testURL()">Analyze URL</button>
            </div>
            <div id="url-result" class="result"></div>
        </div>

        <details>
            <summary>API Details</summary>
            <p><strong>Request Format:</strong></p>
            <pre><code>{
    "url": "https://example.com"
}</code></pre>
            <p><strong>Response Format:</strong></p>
            <pre><code>{
    "is_phishing": true/false,
    "risk_score": 0.95,
    "url": "https://example.com"
}</code></pre>
        </details>
    </div>

    <div class="endpoint">
        <h2>📧 Analyze Email</h2>
        <p><strong>Endpoint:</strong> <code>POST /api/analyze_email</code></p>
        <p><strong>Description:</strong> Analyzes email content for potential phishing indicators.</p>
        
        <div class="test-form">
            <div class="form-group">
                <label for="email-input">Test an email:</label>
                <textarea id="email-input" placeholder="Paste email content here..."></textarea>
                <button onclick="testEmail()">Analyze Email</button>
            </div>
            <div id="email-result" class="result"></div>
        </div>

        <details>
            <summary>API Details</summary>
            <p><strong>Request Format:</strong></p>
            <pre><code>{
    "email_content": "Email text content..."
}</code></pre>
            <p><strong>Response Format:</strong></p>
            <pre><code>{
    "is_phishing": true/false,
    "risk_score": 0.85,
    "analyzed_content": "Preview of analyzed content..."
}</code></pre>
        </details>
    </div>

    <div class="endpoint">
        <h2>📝 Report Feedback</h2>
        <p><strong>Endpoint:</strong> <code>POST /api/report_feedback</code></p>
        <p><strong>Description:</strong> Submit feedback about analysis results.</p>
        
        <div class="test-form">
            <div class="form-group">
                <label for="feedback-url">URL:</label>
                <input type="text" id="feedback-url" placeholder="Enter URL">
                <label>
                    <input type="checkbox" id="feedback-is-phishing"> Is Phishing?
                </label>
                <select id="feedback-type">
                    <option value="url">URL</option>
                    <option value="email">Email</option>
                </select>
                <button onclick="submitFeedback()">Submit Feedback</button>
            </div>
            <div id="feedback-result" class="result"></div>
        </div>

        <details>
            <summary>API Details</summary>
            <p><strong>Request Format:</strong></p>
            <pre><code>{
    "url": "https://example.com",
    "is_phishing": true/false,
    "content_type": "url" or "email"
}</code></pre>
            <p><strong>Response Format:</strong></p>
            <pre><code>{
    "status": "success",
    "message": "Feedback recorded successfully"
}</code></pre>
        </details>
    </div>

    <script>
        function showResult(elementId, data, isError = false) {
            const element = document.getElementById(elementId);
            element.style.display = 'block';
            element.className = 'result ' + (isError ? 'error' : 'success');
            
            if (isError) {
                element.innerHTML = `<strong>Error:</strong> ${data.error || 'Unknown error occurred'}`;
                return;
            }
            
            if (data.risk_score !== undefined) {
                const riskClass = data.risk_score > 0.8 ? 'risk-high' : 
                                data.risk_score > 0.5 ? 'risk-medium' : 'risk-low';
                const riskLevel = data.risk_score > 0.8 ? 'High' : 
                                data.risk_score > 0.5 ? 'Medium' : 'Low';
                
                element.innerHTML = `
                    <strong>Result:</strong><br>
                    Risk Level: <span class="${riskClass}">${riskLevel}</span><br>
                    Risk Score: <span class="${riskClass}">${(data.risk_score * 100).toFixed(1)}%</span><br>
                    Is Phishing: ${data.is_phishing ? '⚠️ Yes' : '✅ No'}
                `;
            } else {
                element.innerHTML = `<strong>Success:</strong> ${data.message || JSON.stringify(data)}`;
            }
        }

        async function testURL() {
            const url = document.getElementById('url-input').value;
            try {
                const response = await fetch('/api/analyze_url', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url})
                });
                const data = await response.json();
                showResult('url-result', data, !response.ok);
            } catch (error) {
                showResult('url-result', {error: error.message}, true);
            }
        }

        async function testEmail() {
            const email_content = document.getElementById('email-input').value;
            try {
                const response = await fetch('/api/analyze_email', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({email_content})
                });
                const data = await response.json();
                showResult('email-result', data, !response.ok);
            } catch (error) {
                showResult('email-result', {error: error.message}, true);
            }
        }

        async function submitFeedback() {
            const url = document.getElementById('feedback-url').value;
            const is_phishing = document.getElementById('feedback-is-phishing').checked;
            const content_type = document.getElementById('feedback-type').value;
            try {
                const response = await fetch('/api/report_feedback', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url, is_phishing, content_type})
                });
                const data = await response.json();
                showResult('feedback-result', data, !response.ok);
            } catch (error) {
                showResult('feedback-result', {error: error.message}, true);
            }
        }
    </script>
</body>
</html>
"""

# Load pre-trained models and NLP pipeline
try:
    nlp = spacy.load("en_core_web_sm")
    url_model = tf.keras.models.load_model('models/url_model')
    email_model = tf.keras.models.load_model('models/email_model')
    url_vectorizer = joblib.load('models/url_vectorizer.pkl')
    text_vectorizer = joblib.load('models/text_vectorizer.pkl')
except Exception as e:
    print(f"Error loading models: {e}")

@app.route('/')
def home():
    """Render the API documentation page."""
    return render_template_string(HOME_TEMPLATE)

@app.route('/api/analyze_url', methods=['POST'])
def analyze_url():
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
            
        # Add https:// if no scheme is provided
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        # Extract URL features
        feature_dict = extract_url_features(url)
        
        # Convert dictionary to list in the correct order expected by the vectorizer
        feature_names = [
            'length', 'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
            'num_params', 'num_digits', 'num_fragments', 'domain_length',
            'subdomain_length', 'tld_length', 'has_port', 'is_ip', 'path_length',
            'query_length', 'has_https', 'has_suspicious_words', 'has_suspicious_tld',
            'has_at_symbol', 'has_double_slash', 'has_encoded_chars', 'avg_domain_token_length',
            'max_domain_token_length', 'num_special_chars', 'num_path_tokens',
            'num_subdomains'
        ]
        
        features = [feature_dict[name] for name in feature_names]
        
        # Transform features using pre-trained vectorizer
        features_vec = url_vectorizer.transform([features])
        
        # Get model prediction
        prediction = url_model.predict(features_vec)[0]
        risk_score = float(prediction[0])
        
        # Add feature analysis to the response
        analysis = {
            'suspicious_indicators': [],
            'security_indicators': [],
            'feature_details': {}  # Add detailed feature information
        }
        
        # Add feature details for debugging
        for name, value in zip(feature_names, features):
            analysis['feature_details'][name] = value
        
        # Add suspicious indicators with more nuanced thresholds
        if feature_dict['has_suspicious_words'] > 0:
            analysis['suspicious_indicators'].append(f"Contains {feature_dict['has_suspicious_words']} suspicious keywords")
        if feature_dict['has_suspicious_tld']:
            analysis['suspicious_indicators'].append('Uses suspicious top-level domain')
        if feature_dict['is_ip']:
            analysis['suspicious_indicators'].append('Uses IP address instead of domain name')
        if feature_dict['num_dots'] > 3:
            analysis['suspicious_indicators'].append(f"Contains {feature_dict['num_dots']} dots (unusual)")
        if feature_dict['has_encoded_chars']:
            analysis['suspicious_indicators'].append('Contains encoded characters')
        if feature_dict['num_special_chars'] > 5:
            analysis['suspicious_indicators'].append(f"High number of special characters: {feature_dict['num_special_chars']}")
            
        # Add security indicators with more context
        if feature_dict['has_https']:
            analysis['security_indicators'].append('Uses HTTPS')
        if feature_dict['has_suspicious_words'] == 0:
            analysis['security_indicators'].append('No suspicious keywords detected')
        if not feature_dict['has_suspicious_tld']:
            analysis['security_indicators'].append(f"Uses common top-level domain: {tldextract.extract(url).suffix}")
        if feature_dict['num_special_chars'] <= 5:
            analysis['security_indicators'].append('Normal number of special characters')
        if feature_dict['domain_length'] < 20:
            analysis['security_indicators'].append('Normal domain length')
        
        # Adjust risk thresholds
        high_risk_threshold = 0.8
        medium_risk_threshold = 0.5
        
        return jsonify({
            'is_phishing': risk_score > medium_risk_threshold,
            'risk_score': risk_score,
            'url': url,
            'analysis': analysis,
            'risk_level': 'High' if risk_score > high_risk_threshold else 
                         'Medium' if risk_score > medium_risk_threshold else 'Low'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze_email', methods=['POST'])
def analyze_email():
    try:
        data = request.get_json()
        email_content = data.get('email_content')
        
        if not email_content:
            return jsonify({'error': 'Email content is required'}), 400
            
        # Extract text features using spaCy
        features = extract_text_features(email_content, nlp)
        
        # Transform features using pre-trained vectorizer
        features_vec = text_vectorizer.transform([features])
        
        # Get model prediction
        prediction = email_model.predict(features_vec)[0]
        risk_score = float(prediction[0])
        
        return jsonify({
            'is_phishing': risk_score > 0.5,
            'risk_score': risk_score,
            'analyzed_content': email_content[:100] + '...'  # Preview of analyzed content
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/report_feedback', methods=['POST'])
def report_feedback():
    try:
        data = request.get_json()
        url = data.get('url')
        is_phishing = data.get('is_phishing')
        content_type = data.get('content_type')  # 'url' or 'email'
        
        # TODO: Implement feedback storage for model retraining
        # Store feedback in database for later model improvement
        
        return jsonify({
            'status': 'success',
            'message': 'Feedback recorded successfully'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True) 