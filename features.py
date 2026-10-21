import urllib.parse
import re
import math
from collections import Counter

# Single source of truth for feature extraction, shared by url_eda.ipynb (training)
# and api.py (inference) so the two can't drift apart.

# Expected columns in exact order - the model was trained on this ordering
FEATURE_COLUMNS = ['url_length', 'domain_length', 'path_length', 'num_digits',
                   'num_special_chars', 'has_ip', 'num_suspicious_words',
                   'domain_entropy', 'tld_length', 'is_suspicious_tld',
                   'num_encoded_chars', 'directory_depth', 'subdomain_count']

SUSPICIOUS_KEYWORDS = ['login', 'secure', 'account', 'update', 'admin', 'verify']

# TLDs historically favored by attackers due to low cost or weak registration rules
SUSPICIOUS_TLDS = ['xyz', 'top', 'pw', 'tk', 'cn', 'ru', 'cc', 'biz', 'info', 'su']

IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


# Calculates the Shannon entropy (randomness) of a given text string
def calculate_entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    # Applies the Shannon entropy formula: H(X) = -sum(p(x) * log2(p(x)))
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def extract_features(url):
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
