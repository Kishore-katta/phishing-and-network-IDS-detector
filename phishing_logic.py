import re
import math
from collections import Counter
from urllib.parse import urlparse
import tldextract
import wordfreq
import difflib

# Note: In the original code, these sets were populated from a CSV.
# To keep the application functional without the CSV file (which seems missing or large),
# I'll include some base logic. If the user provides the CSV later, this can be expanded.
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

    if blacklist_check(url):
        return 0.99, "Phishing"

    if universal_rule_check(url):
        return 0.95, "Phishing"

    # Fallback to legitimate if no rules triggered and ML models are not active
    return 0.10, "Legitimate"
