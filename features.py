import urllib.parse
import re
import math
from collections import Counter

# Single source of truth for feature extraction, shared by the notebooks (training)
# and api.py (inference) so the two can't drift apart.
#   v3 - url_eda.ipynb / url_classifier_v3.joblib, kept unchanged so that model reproduces
#   v4 - url_model_v4.ipynb / url_classifier_v4.joblib, used by the API

# Expected columns in exact order - the v3 model was trained on this ordering
FEATURE_COLUMNS_V3 = ['url_length', 'domain_length', 'path_length', 'num_digits',
                      'num_special_chars', 'has_ip', 'num_suspicious_words',
                      'domain_entropy', 'tld_length', 'is_suspicious_tld',
                      'num_encoded_chars', 'directory_depth', 'subdomain_count']

FEATURE_COLUMNS = FEATURE_COLUMNS_V3 + ['query_length', 'num_query_params', 'host_digit_ratio',
                                        'num_host_hyphens', 'has_port', 'has_at_in_host',
                                        'brand_in_host', 'brand_in_path']

SUSPICIOUS_KEYWORDS = ['login', 'secure', 'account', 'update', 'admin', 'verify']

# TLDs historically favored by attackers due to low cost or weak registration rules
SUSPICIOUS_TLDS = ['xyz', 'top', 'pw', 'tk', 'cn', 'ru', 'cc', 'biz', 'info', 'su']

# Frequently impersonated brands - a brand name outside its own domain is a classic phishing tell
BRANDS = {'paypal', 'apple', 'icloud', 'microsoft', 'office365', 'outlook', 'google', 'gmail',
          'amazon', 'facebook', 'instagram', 'whatsapp', 'netflix', 'roblox', 'steam', 'dropbox',
          'linkedin', 'adobe', 'docusign', 'wellsfargo', 'chase', 'bankofamerica', 'coinbase',
          'binance', 'metamask', 'dhl', 'fedex', 'usps'}

SECOND_LEVEL_SUFFIXES = {'co', 'com', 'net', 'org', 'gov', 'ac', 'edu'}

IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
SCHEME_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.-]*://')
TOKEN_SPLIT = re.compile(r'[^a-z0-9]+')
DIGITS = re.compile(r'\d')


# Calculates the Shannon entropy (randomness) of a given text string
def calculate_entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    # Applies the Shannon entropy formula: H(X) = -sum(p(x) * log2(p(x)))
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def normalize_url(url):
    """Strips formatting that says nothing about intent but leaks labels in the training data.

    In malicious_phish.csv, 92% of benign URLs have no scheme and 3% start with www., while
    malicious ones mostly have both - so the raw model learned "looks like a browser URL"
    means malicious. Browsers always send full URLs, so every input is reduced to the same
    shape: no scheme, no fragment, lowercase host without www., no trailing slash.
    """
    url_str = SCHEME_PATTERN.sub('', str(url).strip())
    url_str = url_str.split('#')[0]

    split_at = min((i for i in (url_str.find('/'), url_str.find('?')) if i != -1), default=len(url_str))
    host, rest = url_str[:split_at].lower(), url_str[split_at:]
    if host.startswith('www.'):
        host = host[4:]

    return host + rest.rstrip('/')


def text_for_ngrams(url):
    """Input text for the character n-gram model: the normalized URL with every digit as 0.

    Benign pages collected in 2026 are full of "/2026/" dates while older malicious data isn't,
    so raw digits let the model learn "recent = benign". Masking keeps the shape of numbers
    (IPs, ports, long IDs) without their values.
    """
    return DIGITS.sub('0', normalize_url(url))


def _registered_domain(hostname):
    # Approximation without a public-suffix list: the last two labels,
    # or three for second-level suffixes like co.uk / com.au
    parts = hostname.split('.')
    if len(parts) >= 3 and parts[-2] in SECOND_LEVEL_SUFFIXES:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])


def _has_brand(text):
    return not BRANDS.isdisjoint(TOKEN_SPLIT.split(text.lower()))


def extract_features(url):
    """v4 features, computed on the normalized URL."""
    url_str = normalize_url(url)

    features = {}

    features['url_length'] = len(url_str)
    features['num_digits'] = sum(c.isdigit() for c in url_str)
    features['num_special_chars'] = sum(1 for c in url_str if c in ['@', '?', '-', '=', '.', '_'])
    features['num_encoded_chars'] = url_str.count('%')

    # Whole tokens only, so "update" no longer fires on e.g. "/updated-news/"
    tokens = set(TOKEN_SPLIT.split(url_str.lower()))
    features['num_suspicious_words'] = sum(1 for word in SUSPICIOUS_KEYWORDS if word in tokens)

    try:
        # The scheme is only there so urlparse finds the netloc; nothing below depends on it
        parsed = urllib.parse.urlparse('http://' + url_str)
        domain = parsed.netloc
        path = parsed.path
        hostname = parsed.hostname or ''

        features['domain_length'] = len(domain)
        features['path_length'] = len(path)
        features['directory_depth'] = path.count('/')
        features['subdomain_count'] = hostname.count('.')
        features['domain_entropy'] = calculate_entropy(hostname)

        domain_parts = hostname.split('.')
        tld = domain_parts[-1] if len(domain_parts) > 1 else ''
        features['tld_length'] = len(tld)
        features['is_suspicious_tld'] = 1 if tld in SUSPICIOUS_TLDS else 0
        features['has_ip'] = 1 if IP_PATTERN.search(hostname) else 0

        features['query_length'] = len(parsed.query)
        features['num_query_params'] = len(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        features['host_digit_ratio'] = sum(c.isdigit() for c in hostname) / len(hostname) if hostname else 0.0
        features['num_host_hyphens'] = hostname.count('-')
        # parsed.port raises ValueError on out-of-range ports, which the except below handles
        features['has_port'] = 1 if parsed.port is not None else 0
        # user@host hides the real destination behind a fake-looking prefix
        features['has_at_in_host'] = 1 if '@' in domain else 0

        # A brand in the subdomains (paypal.com.evil.xyz) or mixed into the registered
        # name (paypal-secure.com) - but not the brand's own domain (paypal.com)
        registered = _registered_domain(hostname)
        subdomains = hostname[:-len(registered)]
        registered_name = registered.split('.')[0]
        features['brand_in_host'] = 1 if (_has_brand(subdomains) or
                                          (registered_name not in BRANDS and _has_brand(registered_name))) else 0
        features['brand_in_path'] = 1 if _has_brand(path + ' ' + parsed.query) else 0

    except ValueError:
        # urlparse raises ValueError on malformed input (e.g. an unbalanced '[' in the netloc)
        for col in FEATURE_COLUMNS:
            features.setdefault(col, 0)

    return features


def extract_features_v3(url):
    """v3 features on the raw URL - frozen to match url_classifier_v3.joblib."""
    # Ensures the input is treated as a string to prevent errors with missing or numerical data
    url_str = str(url)
    if not url_str.startswith('http'):
        url_str = 'http://' + url_str

    features = {}

    # Base structural features - these work even on corrupted URLs
    features['url_length'] = len(url_str)
    features['num_digits'] = sum(c.isdigit() for c in url_str)
    features['num_special_chars'] = sum(1 for c in url_str if c in ['@', '?', '-', '=', '.', '_'])

    # Evasion Metric 1: Counts the percentage signs used in URL encoding (e.g., %20, %3C)
    features['num_encoded_chars'] = url_str.count('%')

    features['num_suspicious_words'] = sum(1 for word in SUSPICIOUS_KEYWORDS if word in url_str.lower())

    try:
        parsed = urllib.parse.urlparse(url_str)
        domain = parsed.netloc
        path = parsed.path

        features['domain_length'] = len(domain)
        features['path_length'] = len(path)

        # Evasion Metric 2: A higher slash count often indicates a payload buried deep in nested folders
        features['directory_depth'] = path.count('/')

        # Evasion Metric 3: Attackers string multiple subdomains together to spoof legitimate services
        features['subdomain_count'] = domain.count('.')

        # Measures how random or algorithmic the domain name appears
        features['domain_entropy'] = calculate_entropy(domain)

        domain_parts = domain.split('.')
        tld = domain_parts[-1] if len(domain_parts) > 1 else ''
        features['tld_length'] = len(tld)
        features['is_suspicious_tld'] = 1 if tld.lower() in SUSPICIOUS_TLDS else 0

        features['has_ip'] = 1 if IP_PATTERN.search(domain) else 0

    except ValueError:
        # urlparse raises ValueError on malformed input (e.g. an unbalanced '[' in the netloc)
        for col in ['domain_length', 'path_length', 'directory_depth', 'subdomain_count',
                    'domain_entropy', 'tld_length', 'is_suspicious_tld', 'has_ip']:
            features[col] = 0

    return features
