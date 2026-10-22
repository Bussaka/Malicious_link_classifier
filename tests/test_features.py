import pytest

from features import (FEATURE_COLUMNS, FEATURE_COLUMNS_V3, extract_features, extract_features_v3,
                      normalize_url, text_for_ngrams)


@pytest.mark.parametrize('raw, expected', [
    # The formatting the v3 model learned as a label must all collapse to one shape
    ('https://www.wikipedia.org/', 'wikipedia.org'),
    ('http://wikipedia.org', 'wikipedia.org'),
    ('wikipedia.org/', 'wikipedia.org'),
    ('www.wikipedia.org', 'wikipedia.org'),
    # Host is lowercased, the path keeps its case; fragments never reach the server
    ('HTTP://WWW.Example.COM/Path/File.HTML#section', 'example.com/Path/File.HTML'),
    ('https://example.com/a/b/?x=1', 'example.com/a/b/?x=1'),
    ('example.com?q=1', 'example.com?q=1'),
    # Any scheme is stripped, and "http" at the start of a domain is not mistaken for one
    ('ftp://files.example.com/pub', 'files.example.com/pub'),
    ('httpbin.org/get', 'httpbin.org/get'),
    ('  https://example.com/x  ', 'example.com/x'),
    ('https://user@evil.com:8080/x', 'user@evil.com:8080/x'),
])
def test_normalize_url(raw, expected):
    assert normalize_url(raw) == expected


def test_normalize_url_is_idempotent():
    for url in ['https://www.Example.com/a/', 'evil.com:8080/x?y=1', 'paypal.com.verify.xyz/login']:
        assert normalize_url(normalize_url(url)) == normalize_url(url)


def test_browser_and_dataset_formats_get_identical_features():
    # The core fix of v4: the same page must not look different because of how it was written down
    assert extract_features('https://www.example.com/login/') == extract_features('example.com/login')


@pytest.mark.parametrize('url', ['a.com', 'http://[bad/', '', '192.168.0.1:99999/x', 'x' * 5000])
def test_extract_features_returns_every_column(url):
    features = extract_features(url)
    assert set(features) == set(FEATURE_COLUMNS)
    assert all(isinstance(v, (int, float)) for v in features.values())


@pytest.mark.parametrize('url, brand_in_host', [
    ('paypal.com.secure-login.xyz/verify', 1),   # brand in the subdomains
    ('paypal-secure.com', 1),                    # brand mixed into the registered name
    ('roblox-free-robux.top', 1),
    ('paypal.com', 0),                           # the brand's own domain
    ('www.paypal.com/signin', 0),
    ('mail.google.com', 0),
    ('google.co.uk/search', 0),                  # second-level suffix handled
    ('pineapple.com', 0),                        # substring, not a token
    ('applesauce-recipes.net', 0),
])
def test_brand_in_host(url, brand_in_host):
    assert extract_features(url)['brand_in_host'] == brand_in_host


def test_brand_in_path():
    assert extract_features('evil.com/paypal/login')['brand_in_path'] == 1
    assert extract_features('evil.com/?redirect=apple')['brand_in_path'] == 1
    assert extract_features('evil.com/pineapple-cake')['brand_in_path'] == 0


def test_keywords_match_whole_tokens_only():
    assert extract_features('site.com/update')['num_suspicious_words'] == 1
    assert extract_features('site.com/login/secure/verify')['num_suspicious_words'] == 3
    assert extract_features('site.com/updated-news')['num_suspicious_words'] == 0
    assert extract_features('site.com/insecure')['num_suspicious_words'] == 0


def test_host_features():
    f = extract_features('https://user@192.168.1.10:8080/a/b/c?x=1&y=2')
    assert f['has_ip'] == 1
    assert f['has_port'] == 1
    assert f['has_at_in_host'] == 1
    assert f['directory_depth'] == 3
    assert f['num_query_params'] == 2

    f = extract_features('my-very-long-host.example.com/')
    assert f['has_ip'] == 0 and f['has_port'] == 0 and f['has_at_in_host'] == 0
    assert f['num_host_hyphens'] == 3
    assert f['subdomain_count'] == 2


def test_suspicious_tld():
    assert extract_features('login.example.xyz')['is_suspicious_tld'] == 1
    assert extract_features('example.com')['is_suspicious_tld'] == 0


def test_text_for_ngrams_masks_digits():
    # Dates in benign paths must not become a "recent = benign" signal
    assert text_for_ngrams('https://www.blog.dev/2026/03/post-17') == 'blog.dev/0000/00/post-00'
    assert text_for_ngrams('192.168.1.1:8080/x') == '000.000.0.0:0000/x'


def test_v3_extractor_is_frozen():
    # url_classifier_v3.joblib was trained on these exact values; changing them silently breaks it
    # (pinned from the extractor after verifying it matched the notebook on all 651k dataset URLs)
    f = extract_features_v3('https://www.paypal.com.account-verify.xyz/login?x=1')
    assert set(f) == set(FEATURE_COLUMNS_V3)
    assert f.pop('domain_entropy') == pytest.approx(4.104407755459851)
    assert f == {'url_length': 51, 'num_digits': 1, 'num_special_chars': 7, 'num_encoded_chars': 0,
                 'num_suspicious_words': 3, 'domain_length': 33, 'path_length': 6, 'directory_depth': 1,
                 'subdomain_count': 4, 'tld_length': 3, 'is_suspicious_tld': 1, 'has_ip': 0}
    # v3 used substring matching and kept the scheme - unlike v4
    assert extract_features_v3('example.com')['url_length'] == len('http://example.com')
