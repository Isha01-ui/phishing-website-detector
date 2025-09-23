"""
Demo runner for Phishing Website Detector
Run: python3 src/main.py
"""
from detector import PhishDetector

def demo():
    d = PhishDetector()
    samples = [
        "http://192.168.0.5/login",
        "https://secure-bank.example.com/verify",
        "https://github.com/",
        "http://very-long-domain-name-with-lots-of-characters-example.com/account"
    ]
    for u in samples:
        print(u, "->", "PHISH" if d.is_suspicious_url(u) else "OK")

if __name__ == "__main__":
    demo()
