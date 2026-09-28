
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import pandas as pd
import numpy as np
import urllib.parse
import re
import math
from collections import Counter
import shap

# Load the trained model
model = joblib.load('url_classifier_v3.joblib')

# Initialize the SHAP Explainer
explainer = shap.TreeExplainer(model)

# Expected columns in exact order
feature_columns = ['url_length', 'domain_length', 'path_length', 'num_digits', 
                   'num_special_chars', 'has_ip', 'num_suspicious_words',
                   'domain_entropy', 'tld_length', 'is_suspicious_tld',
                   'num_encoded_chars', 'directory_depth', 'subdomain_count']

app = FastAPI(title="URL Threat Classifier API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows any website/extension to query the API
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

def calculate_entropy(text):
    if not text: 
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())

def extract_features(url_str):
    if not url_str.startswith('http'):
        url_str = 'http://' + url_str
        
    features = {}
    features['url_length'] = len(url_str)
    features['num_digits'] = sum(c.isdigit() for c in url_str)
    features['num_special_chars'] = sum(1 for c in url_str if c in ['@', '?', '-', '=', '.', '_'])
    features['num_encoded_chars'] = url_str.count('%')
    
    suspicious_keywords = ['login', 'secure', 'account', 'update', 'admin', 'verify']
    features['num_suspicious_words'] = sum(1 for word in suspicious_keywords if word in url_str.lower())
    
    try:
        parsed = urllib.parse.urlparse(url_str)
        domain = parsed.netloc
        path = parsed.path
        
        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        features['directory_depth'] = path.count('/')
        features['subdomain_count'] = domain.count('.')
        features['domain_entropy'] = calculate_entropy(domain)
        
        tld = domain.split('.')[-1] if '.' in domain else ''
        features['tld_length'] = len(tld)
        features['is_suspicious_tld'] = 1 if tld.lower() in ['xyz', 'top', 'pw', 'tk', 'cn', 'ru', 'cc', 'biz', 'info', 'su'] else 0
        
        features['has_ip'] = 1 if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', domain) else 0
        
    except Exception:
        for col in ['domain_length', 'path_length', 'directory_depth', 'subdomain_count', 'domain_entropy', 'tld_length', 'is_suspicious_tld', 'has_ip']:
            features[col] = 0
            
    return features

@app.post("/scan")
def scan_url(request: URLRequest):
    features = extract_features(request.url)
    input_df = pd.DataFrame([features])[feature_columns]
    
    prediction = int(model.predict(input_df)[0])
    confidence = float(max(model.predict_proba(input_df)[0]) * 100)
    
    # Calculate SHAP values
    shap_vals = explainer.shap_values(input_df)
    
    # Robust extraction across different SHAP versions:
    # Format A: List of 2D arrays -> [array_class0(1, 13), array_class1(1, 13)]
    if isinstance(shap_vals, list):
        malicious_shap = shap_vals[1][0]
    # Format B: 3D NumPy array -> shape (1, 13, 2) where index 1 on axis 2 is class 1 (Malicious)
    elif isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 3:
        malicious_shap = shap_vals[0, :, 1]
    # Format C: 2D NumPy array -> shape (1, 13)
    elif isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 2:
        malicious_shap = shap_vals[0]
    else:
        malicious_shap = np.array(shap_vals).flatten()[:len(feature_columns)]
    
    explanation = {
        feature: round(float(val), 4) 
        for feature, val in zip(feature_columns, malicious_shap)
    }
    
    return {
        "target_url": request.url,
        "status": "Malicious" if prediction == 1 else "Safe",
        "confidence": round(confidence, 2),
        "explanation": explanation
    }