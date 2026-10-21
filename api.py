from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import pandas as pd
import numpy as np
import shap

from features import extract_features, FEATURE_COLUMNS

# Load the trained model
model = joblib.load('url_classifier_v3.joblib')

# Initialize the SHAP Explainer
explainer = shap.TreeExplainer(model)

app = FastAPI(title="URL Threat Classifier API")

# The extension calls the API from its background service worker, which host_permissions
# already exempt from CORS, and Streamlit calls it server-side - so browser origins are
# limited to extensions rather than letting any website query the local API
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"chrome-extension://.*",
    allow_methods=["POST"],
    allow_headers=["Content-Type"],
)

class URLRequest(BaseModel):
    url: str

@app.post("/scan")
def scan_url(request: URLRequest):
    features = extract_features(request.url)
    input_df = pd.DataFrame([features])[FEATURE_COLUMNS]

    # One forest pass gives both the label and its confidence
    probabilities = model.predict_proba(input_df)[0]
    prediction = int(model.classes_[np.argmax(probabilities)])
    confidence = float(np.max(probabilities) * 100)

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
        malicious_shap = np.array(shap_vals).flatten()[:len(FEATURE_COLUMNS)]

    explanation = {
        feature: round(float(val), 4)
        for feature, val in zip(FEATURE_COLUMNS, malicious_shap)
    }

    return {
        "target_url": request.url,
        "status": "Malicious" if prediction == 1 else "Safe",
        "confidence": round(confidence, 2),
        "explanation": explanation
    }
