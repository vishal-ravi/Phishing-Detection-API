import re
import numpy as np
from bs4 import BeautifulSoup

def extract_text_features(text, nlp):
    """Extract NLP features from email content for phishing detection."""
    features = {}
    
    # Clean text
    cleaned_text = clean_text(text)
    
    # Process with spaCy
    doc = nlp(cleaned_text)
    
    # Basic text features
    features['text_length'] = len(cleaned_text)
    features['word_count'] = len(doc)
    features['avg_word_length'] = np.mean([len(token.text) for token in doc]) if doc else 0
    features['sentence_count'] = len(list(doc.sents))
    
    # Linguistic features
    features['num_entities'] = len(doc.ents)
    features['num_urls'] = len(re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text))
    features['has_html'] = 1 if bool(BeautifulSoup(text, "html.parser").find()) else 0
    
    # Sentiment and urgency indicators
    features['has_urgency_words'] = check_urgency_words(cleaned_text)
    features['has_monetary_terms'] = check_monetary_terms(cleaned_text)
    features['has_suspicious_formatting'] = check_suspicious_formatting(text)
    
    # Security indicators
    features['has_security_words'] = check_security_words(cleaned_text)
    features['has_personal_info_requests'] = check_personal_info_requests(cleaned_text)
    
    return features

def clean_text(text):
    """Clean and normalize text content."""
    # Remove HTML tags
    text = BeautifulSoup(text, "html.parser").get_text()
    
    # Remove special characters and extra whitespace
    text = re.sub(r'[^\w\s]', ' ', text)
    text = ' '.join(text.split())
    
    return text.lower()

def check_urgency_words(text):
    """Check for presence of urgency-indicating words."""
    urgency_words = [
        'urgent', 'immediate', 'action required', 'account suspended',
        'limited time', 'expire', 'deadline', 'warning', 'important',
        'suspended', 'blocked', 'unauthorized', 'suspicious'
    ]
    return sum(1 for word in urgency_words if word in text)

def check_monetary_terms(text):
    """Check for presence of monetary terms."""
    monetary_terms = [
        'money', 'bank', 'account', 'credit', 'debit', 'card',
        'payment', 'transfer', 'transaction', 'balance', 'fund'
    ]
    return sum(1 for term in monetary_terms if term in text)

def check_suspicious_formatting(text):
    """Check for suspicious text formatting."""
    suspicious_patterns = [
        r'[A-Z]{5,}',  # Excessive caps
        r'\d{16}',     # Possible credit card numbers
        r'\$\d+',      # Dollar amounts
        r'[!]{2,}'     # Multiple exclamation marks
    ]
    return sum(1 for pattern in suspicious_patterns if re.search(pattern, text))

def check_security_words(text):
    """Check for security-related terms."""
    security_words = [
        'password', 'login', 'verify', 'authentication', 'secure',
        'security', 'update', 'confirm', 'validate', 'identity'
    ]
    return sum(1 for word in security_words if word in text)

def check_personal_info_requests(text):
    """Check for requests for personal information."""
    personal_info_terms = [
        'ssn', 'social security', 'birth date', 'credit card',
        'cvv', 'pin', 'mother maiden', 'passport'
    ]
    return sum(1 for term in personal_info_terms if term in text) 