# 🛡️ Real-Time Malicious URL Classifier

An end-to-end machine learning pipeline and web service that detects malicious links and phishing attempts using purely lexical and structural feature extraction. 

Unlike traditional blocklists, this tool uses a tuned Random Forest classifier to identify zero-day threats based on URL evasion tactics (e.g., domain entropy, directory depth, subdomain abuse). It includes Explainable AI (XAI) via SHAP to provide transparent reasoning for every classification.

## Features
* Lexical Feature Extraction: Extracts 13 security-focused metrics without executing external network requests.
* Optimized Inference: Uses a tuned Random Forest model (~92% accuracy) trained on balanced datasets.
* Explainable AI (SHAP): Visually breaks down the mathematical impact of each feature on the model's final decision.
* FastAPI Backend: High-performance REST API for model inference.
* Streamlit Dashboard: Interactive web UI for real-time URL scanning.

## Local Setup
1. Clone the repository: `git clone https://github.com/yourusername/malicious-url-classifier.git`
2. Install dependencies: `pip install -r requirements.txt`
3. Start the FastAPI server: `uvicorn api:app --reload`
4. Start the Streamlit frontend (in a new terminal): `streamlit run app.py`