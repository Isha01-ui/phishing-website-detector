Phishing Website Detector

Rule-based phishing URL detector using 7 heuristics: IP address detection, @ symbol spoofing, excessive subdomains, suspicious keywords, long URLs, hyphen abuse, and non-standard ports.

## Files
- `src/detector.py` — Phishing URL detector with 7 heuristic rules.
- `src/main.py` — Demo runner.
- `tests/` —  Unit test suite (10 test cases).
- `requirements.txt` — Python dependencies.

## Setup
1. Create and activate virtualenv:
   ```bash
   python3 -m venv phish_env
   source phish_env/bin/activate
   pip install -r requirements.txt

python3 src/main.py

