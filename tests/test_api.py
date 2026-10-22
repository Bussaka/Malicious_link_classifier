import os

import pytest

from conftest import REAL_MODEL_PATH


def test_health(client):
    body = client.get('/health').json()
    assert body['status'] == 'ok'
    assert body['kind'] == 'ensemble'
    assert body['threshold'] == 0.5
    assert body['allowlist_size'] == 3


def test_scan_response_shape(client):
    body = client.post('/scan', json={'url': 'http://paypal.com.account-verify.xyz/login'}).json()
    assert set(body) == {'target_url', 'status', 'reason', 'confidence', 'malicious_probability',
                         'threshold', 'explanation'}
    assert body['reason'] == 'model'
    assert body['status'] in ('Safe', 'Malicious')
    assert 0 <= body['malicious_probability'] <= 1
    assert 0 <= body['confidence'] <= 100


@pytest.mark.parametrize('url', ['http://paypal.com.account-verify.xyz/login', 'https://blog.example.dev/notes',
                                 'http://45.12.9.88/x/install.exe'])
def test_status_follows_threshold(client, url):
    body = client.post('/scan', json={'url': url}).json()
    assert (body['status'] == 'Malicious') == (body['malicious_probability'] > body['threshold'])
    expected = body['malicious_probability'] if body['status'] == 'Malicious' else 1 - body['malicious_probability']
    assert body['confidence'] == pytest.approx(expected * 100, abs=0.01)


def test_obvious_cases(client):
    # The fake model is trained on these patterns, so they must land on the right side
    assert client.post('/scan', json={'url': 'http://paypal.com.account-verify.xyz/login'}).json()['status'] == 'Malicious'
    assert client.post('/scan', json={'url': 'https://blog.example.dev/2026/03/notes-on-rust'}).json()['status'] == 'Safe'


def test_ensemble_explanation_has_features_and_ngrams(client):
    explanation = client.post('/scan', json={'url': 'http://paypal.com.account-verify.xyz/login'}).json()['explanation']
    assert any(k.startswith('ngram "') for k in explanation)
    assert 'subdomain_count' in explanation
    assert all(isinstance(v, float) for v in explanation.values())


def test_explanation_only_when_needed(client):
    # Safe verdicts skip the ~0.7s SHAP computation unless the caller asks for it
    url = 'https://blog.example.dev/2026/03/notes-on-rust'
    assert client.post('/scan', json={'url': url}).json()['explanation'] == {}
    assert client.post('/scan', json={'url': url, 'explain': True}).json()['explanation'] != {}
    # Malicious verdicts explain by default (the block page shows it); link checks opt out
    bad = 'http://paypal.com.account-verify.xyz/login'
    assert client.post('/scan', json={'url': bad}).json()['explanation'] != {}
    opted_out = client.post('/scan', json={'url': bad, 'explain': False}).json()
    assert opted_out['status'] == 'Malicious' and opted_out['explanation'] == {}


def test_explainer_uses_a_fixed_tree_sample(api_module):
    import copy
    # The fake forest has 10 trees, fewer than EXPLAIN_TREES, so all of them are explained
    assert len(api_module.explained_forest.estimators_) == 10

    big = copy.copy(api_module.rf_model)
    big.estimators_ = [copy.deepcopy(t) for t in api_module.rf_model.estimators_ * 10]
    first, second = api_module.sample_trees(big), api_module.sample_trees(big)
    assert len(first.estimators_) == api_module.EXPLAIN_TREES
    # Same trees every time, so a URL's explanation is stable across requests
    assert [id(t) for t in first.estimators_] == [id(t) for t in second.estimators_]
    # The original forest is untouched
    assert len(big.estimators_) == 100


def test_allowlisted_skips_model(client):
    body = client.post('/scan', json={'url': 'https://en.wikipedia.org/wiki/Phishing'}).json()
    assert body['status'] == 'Safe'
    assert body['reason'] == 'allowlisted'
    assert body['explanation'] == {}


def test_document_platform_is_never_blocked(client):
    body = client.post('/scan', json={'url': 'https://docs.google.com/forms/d/e/1FAIpQLSf3kD8x/viewform'}).json()
    assert body['status'] == 'Safe'
    assert body['reason'] == 'document_platform'


def test_document_platform_lookalike_is_scored(client):
    body = client.post('/scan', json={'url': 'http://docs.google.com.account-verify.xyz/forms/login'}).json()
    assert body['reason'] == 'model'


@pytest.mark.parametrize('url', ['', 'not a url', 'http://[bad/', 'x' * 10_000, 'javascript:alert(1)'])
def test_malformed_urls_do_not_crash(client, url):
    response = client.post('/scan', json={'url': url})
    assert response.status_code == 200
    assert response.json()['status'] in ('Safe', 'Malicious')


def test_missing_url_is_rejected(client):
    assert client.post('/scan', json={}).status_code == 422


def test_cors_allows_extensions_only(client):
    def preflight(origin):
        return client.options('/scan', headers={'Origin': origin, 'Access-Control-Request-Method': 'POST',
                                                'Access-Control-Request-Headers': 'content-type'})

    allowed = preflight('chrome-extension://abcdefghijklmnop')
    assert allowed.status_code == 200
    assert allowed.headers['access-control-allow-origin'] == 'chrome-extension://abcdefghijklmnop'

    rejected = preflight('https://evil.example')
    assert rejected.status_code == 400
    assert 'access-control-allow-origin' not in rejected.headers


@pytest.mark.skipif(not os.path.exists(REAL_MODEL_PATH), reason='url_classifier_v4.joblib not built')
def test_real_model_smoke():
    """Runs only where the trained model exists: the README's demo cases on the shipped bundle."""
    import joblib
    from features import FEATURE_COLUMNS, extract_features, text_for_ngrams
    import pandas as pd

    bundle = joblib.load(REAL_MODEL_PATH)
    assert bundle['feature_columns'] == FEATURE_COLUMNS
    assert 0 < bundle['threshold'] < 1

    def probability(url):
        p_rf = bundle['rf_model'].predict_proba(pd.DataFrame([extract_features(url)])[FEATURE_COLUMNS])[0][1]
        p_text = bundle['text_model'].predict_proba(bundle['vectorizer'].transform([text_for_ngrams(url)]))[0][1]
        return (p_rf + p_text) / 2

    assert probability('http://paypal.com.account-verify.127.0.0.1.nip.io:8080/login') > bundle['threshold']
    assert probability('http://192.168.13.7:8080/bins/mirai.arm') > bundle['threshold']
    assert probability('https://blog.janedoe.dev/2026/03/notes-on-rust-lifetimes') < bundle['threshold']
