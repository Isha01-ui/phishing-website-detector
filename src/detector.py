"""
Phishing Website Detector — heuristic + rule-based URL classifier
"""
import re
from urllib.parse import urlparse

class PhishDetector:
    SUSPICIOUS_KEYWORDS = [
        'login', 'verify', 'bank', 'update', 'secure', 'account',
        'confirm', 'password', 'signin', 'ebay', 'paypal', 'apple',
        'amazon', 'microsoft', 'support', 'suspended', 'unusual'
    ]
    TRUSTED_TLDS = {'.com', '.org', '.gov', '.edu', '.net'}

    def __init__(self):
        self.results = []

    def analyze(self, url: str) -> dict:
        flags = []
        parsed = urlparse(url if '://' in url else 'http://' + url)
        host = parsed.netloc.lower()
        path = parsed.path.lower()
        full = url.lower()

        # Flag 1: IP address instead of domain
        if re.match(r'^\d+\.\d+\.\d+\.\d+', host):
            flags.append('IP address used instead of domain')

        # Flag 2: Unusually long URL
        if len(url) > 75:
            flags.append(f'Suspicious URL length ({len(url)} chars)')

        # Flag 3: Too many subdomains
        if host.count('.') > 3:
            flags.append('Excessive subdomains')

        # Flag 4: Suspicious keywords in URL
        hits = [k for k in self.SUSPICIOUS_KEYWORDS if k in full]
        if hits:
            flags.append(f'Suspicious keywords: {", ".join(hits)}')

        # Flag 5: Hyphen abuse (common in lookalike domains)
        if host.count('-') > 2:
            flags.append('Multiple hyphens in domain')

        # Flag 6: @ symbol in URL (tricks browsers)
        if '@' in url:
            flags.append('@ symbol in URL (credential spoofing risk)')

        # Flag 7: Non-standard port
        if parsed.port and parsed.port not in (80, 443):
            flags.append(f'Non-standard port: {parsed.port}')

        score = len(flags)
        verdict = 'SAFE' if score == 0 else 'SUSPICIOUS' if score <= 2 else 'LIKELY PHISHING'

        return {'url': url, 'verdict': verdict, 'score': score, 'flags': flags}

    def check(self, url: str) -> bool:
        return self.analyze(url)['verdict'] != 'SAFE'
