 🛡️ Real-Time Malicious URL Classifier & Browser Shield

An end-to-end machine learning pipeline and client-side browser extension that detects malicious links and phishing attempts using purely lexical and structural feature extraction. 

Unlike traditional blocklists that only stop known threats, this tool uses a tuned Random Forest classifier to identify zero-day threats based on URL evasion tactics (e.g., domain entropy, directory depth, subdomain abuse). It includes Explainable AI (XAI) via SHAP to provide transparent reasoning for every classification directly in the browser.

##  Features
* Lexical Feature Extraction: Extracts 13 security-focused metrics on the fly without executing external network requests.
* Explainable AI (SHAP): Visually breaks down the mathematical impact of each feature on the model's final decision.
* FastAPI Backend: High-performance REST API handling model inference.
* Browser Interceptor: A Manifest V3 Chrome Extension that halts navigation to malicious sites before the DOM renders.
* Intelligent Caching: Safelists benign domains in `chrome.storage.local` to ensure zero latency during normal web browsing.
* Streamlit Dashboard: Interactive web UI for manual offline URL analysis.

## 💻 Local Environment Setup

### 1. Start the API Backend

### 2. Install the Chrome Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Toggle **Developer mode** ON (top right corner).
3. Click **Load unpacked** (top left corner).
4. Select the `ThreatScanner_Extension` folder located inside this repository.

### 3. Test the Shield
* The Pass-Through (Cache Test): Navigate to a benign site like `https://www.wikipedia.org`. The page will load instantly. Check your FastAPI terminal to confirm the API was only queried once, after which the domain is cached.
* The Interception: Paste this heavily encoded, evasion-style URL into your browser:
  `http://example.com/login/secure/account/update/verify/admin/nested/dir1/dir2/dir3/session/auth?token=928371982739182371&redirect=%20%20%20`
* The Result:The extension will instantly hijack the screen, block the navigation, and render a SHAP breakdown chart showing exactly why the URL was classified as a threat.

### 4. (Optional) Run the Streamlit Dashboard
To manually scan URLs using the web UI instead of the browser extension, open a second terminal and run: