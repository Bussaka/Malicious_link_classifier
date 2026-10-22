from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI
from pydantic import BaseModel
import copy
from typing import Optional

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

if not ALLOWLIST:
    print("WARNING: allowlist.txt not found - every URL will go through the model")

# Exact TreeSHAP over all 200 deep trees (median depth ~47) takes ~4s - too slow for a page the
# user is waiting on. A forest's SHAP values are the average of its trees' values, so exact SHAP
# on a fixed random sample of trees estimates them closely (correlation 0.97-0.99 with the full
# computation for 40 trees, ~0.7s). The faster Saabas approximation was dropped: it agreed only
# ~0.9 and could flip a feature's sign.
EXPLAIN_TREES = 40


def sample_trees(forest, k=EXPLAIN_TREES):
    # Fixed seed, so a URL always gets the same explanation
    rng = np.random.default_rng(0)
    sample = copy.copy(forest)
    picked = rng.choice(len(forest.estimators_), size=min(k, len(forest.estimators_)), replace=False)
    sample.estimators_ = [forest.estimators_[i] for i in sorted(picked)]
    sample.n_estimators = len(sample.estimators_)
    return sample


if rf_model is not None:
    # Scans are one URL at a time; spinning up a thread pool per call costs more than it saves
    rf_model.n_jobs = 1
    explained_forest = sample_trees(rf_model)
    explainer = shap.TreeExplainer(explained_forest)
else:
    explained_forest = explainer = None
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
    # Explanations cost ~0.7s. None (default): only for Malicious verdicts, which the block page
    # shows. True: always (the dashboard). False: never (link and download checks only need the score).
    explain: Optional[bool] = None


def rf_probability(input_df):
    return float(rf_model.predict_proba(input_df)[0][list(rf_model.classes_).index(1)])


def explain_rf(input_df):
    shap_vals = explainer.shap_values(input_df)

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
    return {feature: float(val) for feature, val in zip(FEATURE_COLUMNS, malicious_shap)}


def text_probability(x):
    return float(text_model.predict_proba(x)[0][list(text_model.classes_).index(1)])


def explain_text(x, probability):
    # A linear model's exact per-feature contribution to the log-odds is weight * value.
    # Scaled by p(1-p) (the slope of the sigmoid) to approximate probability units, so they
    # sit on the same scale as the SHAP values above.
    row = x.tocoo()
    contributions = row.data * text_model.coef_[0][row.col] * probability * (1 - probability)
    top = np.argsort(-np.abs(contributions))[:TOP_NGRAMS]
    return {f'ngram "{ngram_names[row.col[i]]}"': float(contributions[i]) for i in top}


def score(url):
    """Returns (probability, explain) where explain() computes the explanation on demand."""
    parts = []  # (probability, explain callable) per model in the bundle
    if KIND in ('rf', 'ensemble'):
        input_df = pd.DataFrame([extract_features(url)])[FEATURE_COLUMNS]
        parts.append((rf_probability(input_df), lambda: explain_rf(input_df)))
    if KIND in ('char_lr', 'ensemble'):
        x = vectorizer.transform([text_for_ngrams(url)])
        p_text = text_probability(x)
        parts.append((p_text, lambda: explain_text(x, p_text)))

    probability = sum(p for p, _ in parts) / len(parts)

    def explain():
        # Ensemble: each model contributes 1/n of the probability, and so 1/n of its explanation
        merged = {}
        for _, part_explain in parts:
            merged.update(part_explain())
        return {k: v / len(parts) for k, v in merged.items()}

    return probability, explain


@app.get("/health")
def health():
    # Lets the dashboard show whether the backend is up and which model it serves
    return {
        "status": "ok",
        "model": bundle['version'],
        "kind": KIND,
        # When the bundle was trained (absent on bundles from before retrain.py), to spot a stale model
        "trained_at": bundle.get('trained_at'),
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

    malicious_probability, explain = score(request.url)

    # Block only above the tuned threshold rather than at 0.5 - it was chosen for a 2.5%
    # false-positive rate on real pages (see url_model_v4.ipynb, step 6)
    is_malicious = malicious_probability > THRESHOLD
    confidence = (malicious_probability if is_malicious else 1 - malicious_probability) * 100
    wants_explanation = is_malicious if request.explain is None else request.explain
    explanation = explain() if wants_explanation else {}

    return {
        "target_url": request.url,
        "status": "Malicious" if is_malicious else "Safe",
        "reason": "model",
        "confidence": round(confidence, 2),
        "malicious_probability": round(malicious_probability, 4),
        "threshold": round(THRESHOLD, 4),
        "explanation": {k: round(v, 4) for k, v in explanation.items()}
    }
