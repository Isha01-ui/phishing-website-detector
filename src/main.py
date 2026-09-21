from detector import PhishDetector

test_urls = [
    "https://google.com",
    "http://192.168.1.1/login/verify",
    "http://paypal-secure-account-verify.com/update",
    "https://login.microsoftonline.com@malicious.ru/signin",
    "https://amazon.com",
    "http://very-long-suspicious-url-login-verify-account-confirm.xyz/path/to/fake"
]

detector = PhishDetector()
for url in test_urls:
    result = detector.analyze(url)
    print(f"\n[{result['verdict']}] {url}")
    for flag in result['flags']:
        print(f"  ⚠ {flag}")
