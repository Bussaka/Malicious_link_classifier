from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import pandas as pd
import numpy as np
import shap

from features import extract_features, text_for_ngrams
from allowlist import is_allowlisted, is_never_block, ALLOWLIST

# Load the trained model bundle (see url_model_v4.ipynb). The bundle carries the feature
# order, vectorizer and blocking threshold it was trained with, so they can't drift from the model.
#   kind 'rf'       - Random Forest on the 21 v4 features, explained with SHAP
#   kind 'char_lr'  - logistic regression on character n-grams, explained by n-gram weights
#   kind 'ensemble' - average of the two
bundle = joblib.load('url_classifier_v4.joblib')
KIND = bundle['kind']
THRESHOLD = bundle['threshold']
FEATURE_COLUMNS = bundle['feature_columns']
rf_model = bundle['rf_model']
text_model = bundle['text_model']
vectorizer = bundle['vectorizer']

if rf_model is not None:
    # Scans are one URL at a time; spinning up a thread pool per call costs more than it saves
    rf_model.n_jobs = 1

if not ALLOWLIST:
    print("WARNING: allowlist.txt not found - every URL will go through the model")

# Initialize the SHAP Explainer
explainer = shap.TreeExplainer(rf_model) if rf_model is not None else None
ngram_names = np.array(vectorizer.get_feature_names_out()) if vectorizer is not None else None

# How many n-grams to report; the extension shows the top 7 contributors overall
TOP_NGRAMS = 8

app = FastAPI(title="URL Threat Classifier API")

# The extension calls the API from its background service worker, which host_permissions
# already exempt from CORS, and Streamlit calls it server-side - so browser origins are
# limited to extensions rather than letting any website query the local API
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"chrome-extension://.*",
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

class URLRequest(BaseModel):
    url: str


def score_rf(url):
    input_df = pd.DataFrame([extract_features(url)])[FEATURE_COLUMNS]
    probability = float(rf_model.predict_proba(input_df)[0][list(rf_model.classes_).index(1)])

    # Exact TreeSHAP takes ~5s on this 200-tree forest - longer than the extension waits for a
    # verdict - so the Saabas approximation (instant, still sums to the prediction) is used
    shap_vals = explainer.shap_values(input_df, approximate=True)

    # Robust extraction across different SHAP versions:
    # Format A: List of 2D arrays -> [array_class0(1, n), array_class1(1, n)]
    if isinstance(shap_vals, list):
        malicious_shap = shap_vals[1][0]
    # Format B: 3D NumPy array -> shape (1, n, 2) where index 1 on axis 2 is class 1 (Malicious)
    elif isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 3:
        malicious_shap = shap_vals[0, :, 1]
    # Format C: 2D NumPy array -> shape (1, n)
    elif isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 2:
        malicious_shap = shap_vals[0]
    else:
        malicious_shap = np.array(shap_vals).flatten()[:len(FEATURE_COLUMNS)]

    # Values are in probability units and sum to (probability - base rate)
    explanation = {feature: float(val) for feature, val in zip(FEATURE_COLUMNS, malicious_shap)}
    return probability, explanation


def score_text(url):
    x = vectorizer.transform([text_for_ngrams(url)])
    probability = float(text_model.predict_proba(x)[0][list(text_model.classes_).index(1)])

    # A linear model's exact per-feature contribution to the log-odds is weight * value.
    # Scaled by p(1-p) (the slope of the sigmoid) to approximate probability units, so they
    # sit on the same scale as the SHAP values above.
    row = x.tocoo()
    contributions = row.data * text_model.coef_[0][row.col] * probability * (1 - probability)
    top = np.argsort(-np.abs(contributions))[:TOP_NGRAMS]
    explanation = {f'ngram "{ngram_names[row.col[i]]}"': float(contributions[i]) for i in top}
    return probability, explanation


def score(url):
    if KIND == 'rf':
        return score_rf(url)
    if KIND == 'char_lr':
        return score_text(url)
    # Ensemble: each model contributes half the probability, and so half of each explanation
    p_rf, exp_rf = score_rf(url)
    p_text, exp_text = score_text(url)
    explanation = {k: v / 2 for k, v in {**exp_rf, **exp_text}.items()}
    return (p_rf + p_text) / 2, explanation


@app.get("/health")
def health():
    # Lets the dashboard show whether the backend is up and which model it serves
    return {
        "status": "ok",
        "model": bundle['version'],
        "kind": KIND,
        "threshold": round(THRESHOLD, 4),
        "allowlist_size": len(ALLOWLIST),
    }


@app.post("/scan")
def scan_url(request: URLRequest):
    # Popular domains and document platforms skip the model entirely (see allowlist.py)
    skip_reason = ("document_platform" if is_never_block(request.url)
                   else "allowlisted" if is_allowlisted(request.url) else None)
    if skip_reason:
        return {
            "target_url": request.url,
            "status": "Safe",
            "reason": skip_reason,
            "confidence": 100.0,
            "malicious_probability": 0.0,
            "threshold": round(THRESHOLD, 4),
            "explanation": {}
        }

    malicious_probability, explanation = score(request.url)

    # Block only above the tuned threshold rather than at 0.5 - it was chosen for a 2.5%
    # false-positive rate on real pages (see url_model_v4.ipynb, step 6)
    is_malicious = malicious_probability > THRESHOLD
    confidence = (malicious_probability if is_malicious else 1 - malicious_probability) * 100

    return {
        "target_url": request.url,
        "status": "Malicious" if is_malicious else "Safe",
        "reason": "model",
        "confidence": round(confidence, 2),
        "malicious_probability": round(malicious_probability, 4),
        "threshold": round(THRESHOLD, 4),
        "explanation": {k: round(v, 4) for k, v in explanation.items()}
    }
