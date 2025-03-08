import re
from urllib.parse import urlparse
import tldextract
import numpy as np

def extract_url_features(url):
    """Extract features from URL for phishing detection."""
    features = {}
    
    # Parse URL
    parsed_url = urlparse(url)
    extracted = tldextract.extract(url)
    
    # Basic URL components
    features['length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_underscores'] = url.count('_')
    features['num_slashes'] = url.count('/')
    features['num_params'] = len(parsed_url.query.split('&')) if parsed_url.query else 0
    features['num_digits'] = sum(c.isdigit() for c in url)
    features['num_fragments'] = 1 if parsed_url.fragment else 0
    
    # Domain specific features
    features['domain_length'] = len(extracted.domain)
    features['subdomain_length'] = len(extracted.subdomain)
    features['tld_length'] = len(extracted.suffix)
    features['has_port'] = 1 if parsed_url.port else 0
    features['is_ip'] = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', extracted.domain) else 0
    features['path_length'] = len(parsed_url.path)
    features['query_length'] = len(parsed_url.query)
    
    # Security indicators
    features['has_https'] = 1 if parsed_url.scheme == 'https' else 0
    features['has_suspicious_words'] = check_suspicious_words(url.lower())
    features['has_suspicious_tld'] = check_suspicious_tld(extracted.suffix)
    features['has_at_symbol'] = 1 if '@' in url else 0
    features['has_double_slash'] = 1 if '//' in parsed_url.path else 0
    features['has_encoded_chars'] = 1 if '%' in url and any(c.isalnum() for c in url.split('%')[1:]) else 0
    
    # Additional statistical features
    domain_tokens = [token for token in extracted.domain.split('.') if token]
    features['avg_domain_token_length'] = np.mean([len(token) for token in domain_tokens]) if domain_tokens else 0
    features['max_domain_token_length'] = max([len(token) for token in domain_tokens] or [0])
    features['num_special_chars'] = len(re.findall(r'[^a-zA-Z0-9\s\-\.]', url))  # Exclude common chars
    features['num_path_tokens'] = len([x for x in parsed_url.path.split('/') if x])
    features['num_subdomains'] = len([x for x in extracted.subdomain.split('.') if x])
    
    return features

def check_suspicious_words(url):
    """Check for presence of suspicious words commonly used in phishing URLs."""
    suspicious_words = [
        'login', 'signin', 'verify', 'secure', 'account', 'update', 'banking',
        'confirm', 'password', 'pay', 'security', 'support', 'service',
        'wallet', 'authenticate', 'validation', 'recover', 'unlock', 'authorize'
    ]
    
    # Don't count common words in legitimate domains
    legitimate_domains = ['login.gov', 'secure.com', 'security.org', 'support.apple.com', 'account.google.com']
    if any(domain in url for domain in legitimate_domains):
        return 0
        
    return sum(1 for word in suspicious_words if word in url)

def check_suspicious_tld(tld):
    """Check if TLD is commonly associated with phishing."""
    suspicious_tlds = [
        'xyz', 'top', 'work', 'party', 'gq', 'ml', 'cf', 'tk', 'ga',
        'bid', 'download', 'loan', 'racing', 'online', 'win', 'stream'
    ]
    
    # Common legitimate TLDs should never be considered suspicious
    legitimate_tlds = ['com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'live']
    if tld.lower() in legitimate_tlds:
        return 0
        
    return 1 if tld.lower() in suspicious_tlds else 0 