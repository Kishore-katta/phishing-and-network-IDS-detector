import re
import math
import os
from collections import Counter
from urllib.parse import urlparse
import tldextract
import wordfreq
import difflib
import joblib
from utils import tokenizer_url
import sys

# Crucial: joblib/pickle often looks for the tokenizer function in the __main__ module 
# if it was trained there, or in its original path. By putting it in utils and 
# also patching it into __main__, we ensure maximum compatibility.
import __main__
__main__.tokenizer_url = tokenizer_url

# Load the trained model
MODEL_PATH = "models/phishing_nlp_model.pkl"
try:
    if os.path.exists(MODEL_PATH):
        # We need to make sure 'tokenizer_url' is in the namespace for joblib to load it if it was pickled
        model = joblib.load(MODEL_PATH)
        print(f"INFO: Phishing NLP model loaded from {MODEL_PATH}")
    else:
        model = None
        print(f"WARNING: Phishing NLP model not found at {MODEL_PATH}. Using rule-based logic only.")
except Exception as e:
    model = None
    print(f"ERROR: Could not load phishing model: {e}")

# Note: In the original code, these sets were populated from a CSV.
phishing_domains = set()
phishing_patterns = set()

def blacklist_check(url):
    parsed = urlparse(url.lower())
    domain = parsed.netloc.replace("www.", "")
    path = parsed.path

    if domain in phishing_domains:
        return True

    for token in phishing_patterns:
        if token in path:
            return True

    return False

def shannon_entropy(s):
    if not s:
        return 0
    probs = [n / len(s) for n in Counter(s).values()]
    return -sum(p * math.log2(p) for p in probs)

def vowel_ratio(domain):
    if not domain:
        return 0
    return sum(1 for c in domain if c in "aeiou") / max(len(domain), 1)

def max_consecutive_consonants(domain):
    count = max_count = 0
    for c in domain:
        if c.isalpha() and c not in "aeiou":
            count += 1
            max_count = max(max_count, count)
        else:
            count = 0
    return max_count

def digit_substitution(domain):
    return int(any(c.isdigit() for c in domain))

def get_domain_token(url):
    domain = urlparse(url).netloc.lower().replace("www.", "")
    return domain.split(".")[0]

def is_typosquatting_domain(url):
    token = get_domain_token(url)
    if len(token) < 5:
        return False

    try:
        # Use a subset of top words if wordfreq is available
        top_words = wordfreq.top_n_list("en", 1000)
        for word in top_words:
            similarity = difflib.SequenceMatcher(None, token, word).ratio()
            if 0.88 < similarity < 0.99:
                return True
    except Exception:
        pass
    return False

def universal_rule_check(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")
        path = parsed.path.lower()

        if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
            return True

        if is_typosquatting_domain(url):
            return True

        if shannon_entropy(domain) > 4.2:
            return True

        if vowel_ratio(domain) < 0.25:
            return True

        if max_consecutive_consonants(domain) >= 5:
            return True

        if digit_substitution(domain):
            return True

        if len(domain) > 30:
            return True

        if path.count("/") > 6:
            return True
    except Exception:
        pass
    return False

def predict_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    # 1. Check Blacklist (High Priority)
    if blacklist_check(url):
        return 0.99, "Phishing"

    # 2. Check ML Model (if available)
    ml_prob = 0.0
    ml_label = "Legitimate"
    
    if model:
        try:
            # Get probability scores
            # model is a Pipeline([('tfidf', ...), ('clf', ...)])
            probs = model.predict_proba([url])[0]
            classes = model.classes_
            
            # Map classes (usually 'bad' and 'good' from your dataset)
            prob_map = dict(zip(classes, probs))
            
            # 'bad' is Phishing in our training dataset
            ml_prob = prob_map.get('bad', 0.0)
            
            if ml_prob > 0.5:
                ml_label = "Phishing"
        except Exception as e:
            print(f"ML Prediction Error: {e}")

    # 3. Check Universal Rules
    rules_triggered = universal_rule_check(url)

    # 4. Combined Hybrid Logic
    # If ML is very sure (>80%) or Rules + ML agree (>50%)
    if ml_prob > 0.8:
        return ml_prob, "Phishing"
    elif rules_triggered and ml_prob > 0.3:
        return max(0.90, ml_prob), "Phishing"
    elif rules_triggered:
        return 0.85, "Phishing"
    
    # Final Fallback
    final_prob = max(0.10, ml_prob) 
    return final_prob, "Phishing" if final_prob > 0.5 else "Legitimate"

