# 🛡️ Real-Time Malicious URL Classifier & Browser Shield

An end-to-end machine learning pipeline and client-side browser extension that detects malicious links and phishing attempts using purely lexical and structural feature extraction. 

Unlike traditional blocklists that only stop known threats, this tool uses a tuned Random Forest classifier to identify zero-day threats based on URL evasion tactics (e.g., domain entropy, directory depth, subdomain abuse). It includes Explainable AI (XAI) via SHAP to provide transparent reasoning for every classification directly in the browser.

##  Features
* Lexical Feature Extraction: Extracts 13 security-focused metrics on the fly without executing external network requests.
* Explainable AI (SHAP): Visually breaks down the mathematical impact of each feature on the model's final decision.
* FastAPI Backend: High-performance REST API handling model inference.
* Browser Interceptor: A Manifest V3 Chrome Extension that keeps each unscanned page hidden until the model returns a verdict, then either reveals it or replaces it with a block screen. If the API is unreachable or takes longer than 5 seconds, the page is shown (fail-open).
* Intelligent Caching: Safelists benign domains for 7 days and blocks individual malicious pages for 24 hours in `chrome.storage.local`, so normal browsing has near-zero latency while stale verdicts are rescanned.
* Toolbar Popup: Shows the current site's verdict and lets you rescan it, revoke a "proceed anyway" exception, or clear all cached verdicts.
* Streamlit Dashboard: Interactive web UI for manual offline URL analysis.

## 📁 Project Structure
| File | Purpose |
|---|---|
| `url_eda.ipynb` | EDA, feature engineering (v1 → v3), Random Forest training and tuning |
| `features.py` | Feature extractor shared by the notebook and the API |
| `api.py` | FastAPI backend: `POST /scan` returns verdict, confidence and SHAP values |
| `app.py` | Streamlit dashboard for manual scans |
| `ThreatScanner_Extension/` | Chrome extension (content script, background worker, popup) |

## 💻 Local Environment Setup

### 0. Prerequisites
* Python 3.12
* The [Malicious URLs dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset) (`malicious_phish.csv`) in the project root — only needed to retrain
* The trained model `url_classifier_v3.joblib` in the project root. It is not committed (see `.gitignore`); generate it by running every cell of `url_eda.ipynb`.

```bash
python -m venv venv
venv\Scripts\activate          # Windows  (macOS/Linux: source venv/bin/activate)
pip install -r requirements.txt
```

> `scikit-learn` is pinned to the version the model was saved with. Loading the model with a different version can fail or silently change predictions; if you upgrade it, retrain the model.

### 1. Start the API Backend
```bash
uvicorn api:app --host 127.0.0.1 --port 8000
```
Wait for `Application startup complete` (loading the model takes a little while). Interactive docs are at http://127.0.0.1:8000/docs. Quick check:
```bash
curl -X POST http://127.0.0.1:8000/scan -H "Content-Type: application/json" -d "{\"url\": \"example.com/login/verify\"}"
```

### 2. Install the Chrome Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Toggle **Developer mode** ON (top right corner).
3. Click **Load unpacked** (top left corner).
4. Select the `ThreatScanner_Extension` folder located inside this repository.
5. (Optional) Pin **ThreatScanner Shield** from the puzzle-piece menu to keep the popup one click away.

### 3. Test the Shield
* The Pass-Through (Cache Test): Navigate to a benign site like `https://www.wikipedia.org`. The page will load instantly. Check your FastAPI terminal to confirm the API was only queried once, after which the domain is cached.
* The Interception: Paste this heavily encoded, evasion-style URL into your browser:
  `http://example.com/login/secure/account/update/verify/admin/nested/dir1/dir2/dir3/session/auth?token=928371982739182371&redirect=%20%20%20`
* The Result: The extension will hijack the screen, block the page, and render a SHAP breakdown chart showing exactly why the URL was classified as a threat.
* Proceed Anyway: Clicking **I understand the risks, proceed anyway** adds a permanent exception for that domain. Open the toolbar popup and choose **Remove exception & block again** to undo it.
* Fail-Open: Stop the API and visit an unscanned site — the page loads after the scan fails and the error is logged in the page's DevTools console.

### 4. (Optional) Run the Streamlit Dashboard
To manually scan URLs using the web UI instead of the browser extension, keep the API running and in a second terminal run:
```bash
streamlit run app.py
```
Then open http://localhost:8501.
