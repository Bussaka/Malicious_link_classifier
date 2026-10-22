# Real-Time Malicious URL Classifier & Browser Shield

[![Tests](https://github.com/Bussaka/Malicious_link_classifier/actions/workflows/tests.yml/badge.svg)](https://github.com/Bussaka/Malicious_link_classifier/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An end-to-end machine learning pipeline and client-side browser extension that detects malicious links and phishing attempts using purely lexical and structural analysis of the URL — no page content is fetched.

Unlike traditional blocklists that only stop known threats, this tool scores URLs it has never seen, using an ensemble of a Random Forest over engineered features (domain entropy, subdomain abuse, brand impersonation, …) and a character n-gram model. A popularity allowlist handles well-known sites, and every model verdict comes with an explanation (SHAP values and n-gram weights) shown directly in the browser.

##  Features
* URL Normalization: Every URL is reduced to the same shape (no scheme, no `www.`, no trailing slash) before scoring, so the model judges content rather than formatting.
* Two Complementary Models: A Random Forest on 21 security-focused features plus a TF-IDF character n-gram logistic regression, averaged.
* Popularity Allowlist: The Tranco top 10k domains skip the model, except platforms where anyone can publish (site builders, static hosting, shorteners, wildcard DNS).
* Document Platforms Never Blocked: Google Docs/Drive/Forms and SharePoint/OneDrive links are always allowed, because their ID-style URLs can't be judged lexically and false blocks there would break everyday work. Look-alike domains (e.g. `docs.google.com.account-verify.xyz`) are still scored.
* Tuned Blocking Threshold: Chosen for a 2.5% false-positive rate on real browsing, not the default 50%.
* Explainable AI: Exact SHAP values (computed on a fixed 40-tree sample of the forest, ~0.7 s) and per-n-gram contributions break down a verdict. They are computed only when shown: for blocked pages and in the dashboard.
* FastAPI Backend: REST API scoring a URL in ~30 ms.
* Browser Interceptor: A Manifest V3 Chrome Extension that keeps each unscanned page hidden until the model returns a verdict, then either reveals it or replaces it with a block screen (typically within half a second; the explanation chart fills in afterwards). If the API is unreachable or takes longer than 5 seconds, the page is shown (fail-open).
* Embedded Frames and Single-Page Apps: Iframes are scanned too and get a compact notice when flagged; in-app navigations (`history.pushState`) are rescanned.
* Link and Download Checks: Links are checked while the pointer rests on them, so clicking a flagged one opens a warning instead. Downloads are held until their address is checked and cancelled if flagged, with a notification.
* Intelligent Caching: Safelists benign domains for 7 days and blocks individual malicious pages for 24 hours in `chrome.storage.local`, so normal browsing has near-zero latency while stale verdicts are rescanned.
* Toolbar Popup: Shows the current site's verdict and lets you rescan it, revoke a "proceed anyway" exception, pause protection for an hour, or clear cached verdicts.
* Settings Page: API address with a connection test, pausing (15 minutes to indefinitely), the list of exceptions with per-domain removal, and cache clearing.
* Protection Status: The extension checks the API every minute and after every scan. The toolbar icon shows a red **!** badge when the API is unreachable and a grey **II** while you have paused protection, since pages then open without being scanned.
* Streamlit Dashboard: Interactive web UI for manual URL analysis.

## Model Performance (v4)

All numbers are on data the model never trained on, split by host so no website appears in both training and test. "Real browsing" blends 80% inner pages (upvoted Hacker News links) with 20% homepages (Tranco top-100k sites).

| | v3 (previous) | **v4 (current)** |
|---|---|---|
| Real browsing wrongly blocked | 39.3% | **2.4%** |
| PhishTank phishing caught | 58.4% | **80.4%** |
| OpenPhish phishing caught (never-seen feed) | 81.4% | **89.6%** |
| URLhaus malware caught | 94.4% | 94.7% |

v3 reported 91.94% accuracy, but that test split shared websites with its training data and its URLs were formatted in a way that leaked the label (92% of benign training URLs had no `http(s)://`; real browser URLs always do). `url_model_v4.ipynb` walks through each fix and measures it.

**Known limitations**
* The model only sees the URL. Phishing pages on platforms with ID-style URLs look identical to legitimate ones:
  * Google Docs/Drive/Forms and SharePoint/OneDrive are never blocked, so phishing hosted there gets through — about 8% of PhishTank submissions.
  * Other hosting platforms (e.g. Vercel apps) are still scored, so legitimate links there are sometimes blocked.
* The benign inner-page sample comes from Hacker News, which leans technical; false-positive rates on other kinds of browsing may differ.
* Safe verdicts are cached per domain, so in-app navigations on a domain that was already judged Safe are not rescanned until that verdict expires (7 days). The rescan matters when the first scan failed or the cache was cleared.
* A link clicked before its hover check finishes is not stopped on the spot; the page it opens is still blocked on arrival, and a download from it is still checked.

**Privacy:** every page address you open, link you hover and file you download is sent to the API at the configured address (your own machine by default). Nothing else about the page is read.
* Threat feeds change daily. Retrain periodically (see below) to keep up with new campaigns.

## Project Structure
| File | Purpose |
|---|---|
| `url_model_v4.ipynb` | Current model: data cleaning, external data, model comparison, allowlist, threshold, export |
| `url_eda.ipynb` | Original EDA and the v1 → v3 Random Forest (kept for history) |
| `features.py` | URL normalization and feature extraction, shared by the notebooks and the API |
| `allowlist.py` / `allowlist.txt` | Popularity allowlist, the platform exclusions applied to it, and the never-block document platforms |
| `fetch_data.py` | Downloads the external datasets used by `url_model_v4.ipynb` |
| `retrain.py` | Fetches fresh data, retrains, and promotes the model only if it passes quality gates |
| `api.py` | FastAPI backend: `POST /scan` returns verdict, score, threshold and explanation |
| `app.py` | Streamlit dashboard for manual scans |
| `ThreatScanner_Extension/` | Chrome extension (content script, background worker, popup, settings page, icons) |
| `tests/` | pytest suite (features, allowlist, API, retraining), Node tests for the extension's shared logic, and a browser end-to-end test |
| `.github/workflows/tests.yml` | CI: runs the Python and extension tests on every push and pull request |

## Local Environment Setup

### 0. Prerequisites
* Python 3.12
* The trained model `url_classifier_v4.joblib` in the project root. It is not committed (see `.gitignore`); generate it with the steps under **Retraining** below.

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
Wait for `Application startup complete` (loading the model takes ~25 seconds). Interactive docs are at http://127.0.0.1:8000/docs. Quick check:
```bash
curl -X POST http://127.0.0.1:8000/scan -H "Content-Type: application/json" -d "{\"url\": \"http://paypal.com.account-verify.xyz/login\"}"
```

### 2. Install the Chrome Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Toggle **Developer mode** ON (top right corner).
3. Click **Load unpacked** (top left corner).
4. Select the `ThreatScanner_Extension` folder located inside this repository.
5. (Optional) Pin **ThreatScanner Shield** from the puzzle-piece menu to keep the popup one click away.

Chrome lists what the extension can do: read every site's address (to scan it), read browsing history (`webNavigation`, to see in-app navigations), manage downloads (to hold and cancel flagged ones) and show notifications. To use an API on another port or machine, open the popup and choose **Settings**.

### 3. Test the Shield
* The Pass-Through: Navigate to `https://www.wikipedia.org`. It is on the allowlist, so it loads instantly; the toolbar popup shows it as safelisted.
* The Interception: The extension can only run on pages that actually load, so the demo serves a local page under a phishing-style hostname. [nip.io](https://nip.io) resolves any `*.127.0.0.1.nip.io` name to your own machine. In any empty folder run:
  ```bash
  python -m http.server 8080
  ```
  then open `http://paypal.com.account-verify.127.0.0.1.nip.io:8080/login`.
* The Result: The extension blocks the page and renders a breakdown chart showing which features and character sequences made the URL look malicious.
* Proceed Anyway: Click **Details**, then **Continue to … (unsafe)**. This adds a permanent exception for that domain. Undo it from the toolbar popup (**Remove exception and block again**) or the Settings page.
* Fail-Open: Stop the API and visit an unscanned site. The page loads after the scan fails, and the toolbar icon shows a red **!** badge.

### 4. (Optional) Run the Streamlit Dashboard
To manually scan URLs using the web UI instead of the browser extension, keep the API running and in a second terminal run:
```bash
streamlit run app.py
```
Then open http://localhost:8501.

## Running the Tests
```bash
pip install -r requirements-dev.txt
python -m pytest                              # Python: features, allowlist, API
node --test "tests/extension/*.test.mjs"      # Extension shared logic: cache, verdict lookup, pause (Node 18+)
```
The API tests build a tiny stand-in model, so they don't need `url_classifier_v4.joblib`; one extra smoke test runs against the real model when it is present.

The browser end-to-end test loads the extension into a headless browser and checks page, iframe, link, download, in-app navigation and settings behaviour against the running API:
```bash
uvicorn api:app --port 8000          # first terminal
python tests/e2e/run_e2e.py          # second terminal
```
It needs Microsoft Edge (or set `BROWSER` to a Chromium / Chrome for Testing binary; branded Chrome 137+ ignores `--load-extension`) and port 80 free, because the test site is served as `*.localtest.me`. Screenshots are saved to `tests/e2e/output/`.

## Retraining
Threat campaigns change constantly, so the model should be retrained regularly (monthly is a reasonable default).

**One-time setup:** download the [Malicious URLs dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset), place `malicious_phish.csv` in the project root, and `pip install -r requirements-dev.txt`.

**Retrain:**
```bash
python retrain.py              # fetch fresh feeds, train, check, promote
python retrain.py --dry-run    # train and check only; the live model is untouched
python retrain.py --skip-fetch # reuse the data already in data/external/
```
Each run downloads fresh threat data (`fetch_data.py`), trains `url_model_v4.ipynb` into `runs/<timestamp>/` (about 10-15 minutes), and checks the candidate's held-out results against minimum quality gates:

| Gate | Needs | Current model |
|---|---|---|
| Real browsing wrongly blocked | at most 3.5% | 2.4% |
| PhishTank phishing caught | at least 70% | 80.4% |
| OpenPhish phishing caught | at least 80% | 89.6% |
| URLhaus malware caught | at least 85% | 94.7% |

Only a candidate that passes every gate replaces `url_classifier_v4.joblib` and `allowlist.txt`; the previous versions are kept as `*.previous.*` for rollback. Restart the API afterwards to load the new model (the dashboard footer shows the training date). Every run is logged to `runs/retrain_log.jsonl`, and a failed run's executed notebook in its run folder shows what went wrong. Exit code 0 = promoted, 1 = rejected by the gates, 2 = could not train.

**Schedule it** (1st of each month at 03:00, output appended to `runs/retrain.out`):

*Windows (Task Scheduler)*, in a Command Prompt (`cmd.exe`, not PowerShell) opened in the project folder:
```bat
schtasks /Create /TN "ThreatScanner retrain" /SC MONTHLY /D 1 /ST 03:00 /TR "cmd /c cd /d \"%CD%\" && python retrain.py >> runs\retrain.out 2>&1"
```
*macOS / Linux (cron)*, via `crontab -e`:
```
0 3 1 * * cd /path/to/Malicious_link_classifier && python3 retrain.py >> runs/retrain.out 2>&1
```

Running `url_model_v4.ipynb` by hand still works and writes straight to the project root. Rerunning `url_eda.ipynb` reproduces the old v3 model (`url_classifier_v3.joblib`), which `url_model_v4.ipynb` uses as an optional baseline.

## License and Data Sources
The code is released under the [MIT License](LICENSE).

The model is trained and evaluated on public datasets, which are **not** included in this repository: `fetch_data.py` downloads them from their sources, and each remains subject to its provider's terms of use (some restrict commercial use, so check them before using a trained model commercially).

| Source | Used for |
|---|---|
| [Malicious URLs dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset) (Kaggle, sid321axn) | Base benign, phishing and malware URLs |
| [Tranco](https://tranco-list.eu/) top-sites list (Le Pochat et al., *Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation*, NDSS 2019) | Benign homepages and the allowlist (`allowlist.txt` is derived from it) |
| [PhishTank](https://phishtank.org/) | Verified phishing URLs |
| [URLhaus](https://urlhaus.abuse.ch/) by abuse.ch | Malware distribution URLs |
| [OpenPhish](https://openphish.com/) community feed | Held-out phishing test set |
| [Hacker News](https://news.ycombinator.com/) via the [Algolia HN Search API](https://hn.algolia.com/api) | Benign inner pages |
