import importlib
import os
import sys

import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from features import FEATURE_COLUMNS, extract_features, text_for_ngrams  # noqa: E402

REAL_MODEL_PATH = os.path.join(ROOT, 'url_classifier_v4.joblib')

BENIGN = [
    'wikipedia.org/wiki/Python', 'blog.example.dev/2026/03/notes-on-rust', 'news.example.com/world/europe',
    'shop.example.co.uk/products/teapot', 'example.org/about', 'docs.example.io/getting-started',
    'recipes.example.net/sourdough', 'example.edu/courses/cs101', 'github.com/user/project/issues',
    'forum.example.com/t/how-to-bake-bread/123',
]
MALICIOUS = [
    'paypal.com.account-verify.xyz/login', 'secure-login-apple.top/verify/account',
    '192.168.13.7:8080/bins/mirai.arm', 'update-account-microsoft.tk/signin.php?session=8f3a9c2e71',
    'amazon-security-alert.cf/update/billing', '45.12.9.88/x/install.exe',
    'netflix-billing-update.ga/account/verify', 'login.paypal-secure.ml/webapps/auth',
    'chase.com.verify-identity.gq/login.php', 'dhl-parcel-redelivery.xyz/track?id=99887766',
]


def make_fake_bundle(threshold=0.5):
    """A tiny model of the same shape as url_classifier_v4.joblib, so the API runs without the real file."""
    urls = BENIGN + MALICIOUS
    labels = np.array([0] * len(BENIGN) + [1] * len(MALICIOUS))

    rf = RandomForestClassifier(n_estimators=10, random_state=0)
    rf.fit(pd.DataFrame([extract_features(u) for u in urls])[FEATURE_COLUMNS], labels)

    vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(3, 5), sublinear_tf=True)
    text_model = LogisticRegression(C=4, max_iter=1000)
    text_model.fit(vectorizer.fit_transform([text_for_ngrams(u) for u in urls]), labels)

    return {'version': 'test', 'kind': 'ensemble', 'rf_model': rf, 'feature_columns': FEATURE_COLUMNS,
            'text_model': text_model, 'vectorizer': vectorizer, 'threshold': threshold}


@pytest.fixture(scope='session')
def api_module():
    """Imports api.py with joblib.load returning the fake bundle and a small known allowlist."""
    import allowlist
    import joblib

    bundle = make_fake_bundle()
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(joblib, 'load', lambda path: bundle)
        mp.setattr(allowlist, 'ALLOWLIST', frozenset({'wikipedia.org', 'github.com', 'bbc.co.uk'}))
        sys.modules.pop('api', None)
        api = importlib.import_module('api')
        yield api
    sys.modules.pop('api', None)


@pytest.fixture(scope='session')
def client(api_module):
    from fastapi.testclient import TestClient
    return TestClient(api_module.app)
