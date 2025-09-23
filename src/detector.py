"""
Simple starter for Phishing Website Detector
This file contains a minimal Detector class that you can extend.
"""
import re
from urllib.parse import urlparse

class PhishDetector:
    def __init__(self):
        # placeholder for model, rules, etc.
        self.suspicious_keywords = ['login', 'verify', 'bank', 'update', 'secure', 'account']

    def is_suspicious_url(self, url: str) -> bool:
        # basic heuristics: IP address in host, long domain, suspicious keywords
        try:
            parsed = urlparse(url)
            host = parsed.netloc
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
                return True
            if len(host) > 30:
                return True
            lowered = url.lower()
            if any(k in lowered for k in self.suspicious_keywords):
                return True
            return False
        except Exception:
            return True  # if we can't parse, treat as suspicious
