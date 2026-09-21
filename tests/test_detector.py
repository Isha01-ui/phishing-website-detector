"""
Unit tests for PhishDetector
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import unittest
from detector import PhishDetector

class TestPhishDetector(unittest.TestCase):

    def setUp(self):
        self.detector = PhishDetector()

    # --- Safe URLs ---

    def test_safe_google(self):
        result = self.detector.analyze("https://google.com")
        self.assertEqual(result['verdict'], 'SAFE')

    def test_safe_amazon(self):
        result = self.detector.analyze("https://amazon.com")
        self.assertEqual(result['verdict'], 'SAFE')

    # --- IP address ---

    def test_ip_address_flagged(self):
        result = self.detector.analyze("http://192.168.1.1/login")
        self.assertIn('IP address used instead of domain', result['flags'])

    # --- Suspicious keywords ---

    def test_keyword_login(self):
        result = self.detector.analyze("http://example.com/login/verify")
        hits = [f for f in result['flags'] if 'keywords' in f]
        self.assertTrue(len(hits) > 0)

    def test_keyword_paypal(self):
        result = self.detector.analyze("http://paypal-secure.com/update")
        hits = [f for f in result['flags'] if 'keywords' in f]
        self.assertTrue(len(hits) > 0)

    # --- @ symbol spoofing ---

    def test_at_symbol_flagged(self):
        result = self.detector.analyze("https://legit.com@evil.ru/signin")
        self.assertIn('@ symbol in URL (credential spoofing risk)', result['flags'])

    # --- Long URL ---

    def test_long_url_flagged(self):
        long_url = "http://" + "a" * 80 + ".com"
        result = self.detector.analyze(long_url)
        hits = [f for f in result['flags'] if 'length' in f]
        self.assertTrue(len(hits) > 0)

    # --- Excessive subdomains ---

    def test_excessive_subdomains(self):
        result = self.detector.analyze("http://a.b.c.d.evil.com/login")
        self.assertIn('Excessive subdomains', result['flags'])

    # --- Verdict scoring ---

    def test_likely_phishing_verdict(self):
        result = self.detector.analyze(
            "http://192.168.1.1/paypal-login-verify-account-confirm-update"
        )
        self.assertEqual(result['verdict'], 'LIKELY PHISHING')

    def test_check_returns_bool(self):
        self.assertIsInstance(self.detector.check("https://google.com"), bool)
        self.assertFalse(self.detector.check("https://google.com"))
        self.assertTrue(self.detector.check("http://192.168.1.1/login"))


if __name__ == '__main__':
    unittest.main()
