import os
import requests
import base64
import re
import logging
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
from Levenshtein import distance
from supabase import create_client, Client
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ===============================
# App Setup
# ===============================

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# ===============================
# مفاتيحك (لم يتم تعديلها)
# ===============================

SUPABASE_URL = "PUT_YOUR_SUPABASE_URL"
SUPABASE_KEY = "PUT_YOUR_SUPABASE_KEY"
VT_API_KEY = "PUT_YOUR_VIRUSTOTAL_KEY"
TELEGRAM_TOKEN = "PUT_YOUR_TELEGRAM_TOKEN"
CHAT_ID = "PUT_YOUR_CHAT_ID"

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ===============================
# Rate Limiting
# ===============================

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10 per minute"]
)

# ===============================
# Cache
# ===============================

CACHE = {}

# ===============================
# Lists
# ===============================

WHITELIST = [
    'google.com', 'facebook.com', 'microsoft.com',
    'apple.com', 'paypal.com', 'binance.com', 'github.com'
]

BLACKLIST = [
    'casajoys.com', 'foyya7me.com',
    'free-gifts.xyz', 'login-verify-secure.top', 'win-iphone.click'
]

# ===============================
# Helpers
# ===============================

def is_valid_url(url):
    try:
        parsed = urlparse(url if url.startswith("http") else "https://" + url)
        return parsed.scheme in ["http", "https"] and parsed.netloc
    except:
        return False


def get_vt_stats(url):
    try:
        u_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{u_id}",
            headers={"x-apikey": VT_API_KEY},
            timeout=7
        )

        if r.status_code == 200:
            return r.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})

        if r.status_code == 404:
            return None

    except requests.exceptions.Timeout:
        logging.warning("VirusTotal Timeout")
    except Exception as e:
        logging.error(f"VT Error: {e}")

    return None


def analyze_logic(url, domain, vt):
    risk = 0
    reasons = []

    # Whitelist
    if domain in WHITELIST:
        return 0, ["Trusted domain"]

    # Blacklist
    if domain in BLACKLIST:
        return 95, ["Blacklisted domain"]

    # Detect IP
    if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
        risk += 40
        reasons.append("Using IP instead of domain")

    # Long URL
    if len(url) > 75:
        risk += 10
        reasons.append("Very long URL")

    # Hyphen abuse
    if domain.count('-') > 2:
        risk += 15
        reasons.append("Suspicious domain structure")

    # Typosquatting
    for trust in WHITELIST:
        if distance(domain.split('.')[0], trust.split('.')[0]) == 1:
            risk += 60
            reasons.append("Possible typosquatting")

    # Suspicious keywords
    if re.search(r'(login|verify|update|secure|gift|bank|wallet|crypto)', url.lower()):
        risk += 15
        reasons.append("Suspicious keywords detected")

    # VirusTotal
    if vt:
        mal = vt.get('malicious', 0)
        suspicious = vt.get('suspicious', 0)

        if mal > 0:
            risk += mal * 20
            reasons.append(f"Detected malicious by {mal} engines")

        if suspicious > 0:
            risk += suspicious * 10
            reasons.append(f"Suspicious by {suspicious} engines")

    return min(risk, 100), reasons


# ===============================
# Routes
# ===============================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
@limiter.limit("5 per minute")
def analyze():

    data = request.get_json()
    raw_url = data.get('link', '').strip()

    if not raw_url:
        return jsonify({"error": "URL required"}), 400

    if not is_valid_url(raw_url):
        return jsonify({"error": "Invalid URL"}), 400

    url = raw_url if raw_url.startswith('http') else 'https://' + raw_url
    domain = urlparse(url).netloc.lower()

    # Cache check
    if url in CACHE:
        return jsonify(CACHE[url])

    vt_stats = get_vt_stats(url)
    risk_score, reasons = analyze_logic(url, domain, vt_stats)

    is_bad = risk_score >= 60

    # Update counters safely
    try:
        supabase.rpc('increment_scanned', {}).execute()
        if is_bad:
            supabase.rpc('increment_threats', {}).execute()
    except Exception as e:
        logging.warning(f"Supabase error: {e}")

    # Telegram alert
    try:
        status = "🚨" if is_bad else "✅"
        msg = f"{status} Scan Result\nURL: {url}\nRisk: {risk_score}%"
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": CHAT_ID, "text": msg},
            timeout=5
        )
    except:
        pass

    response_data = {
        "status": "danger" if is_bad else "safe",
        "risk_score": risk_score,
        "confidence": "high" if risk_score > 70 else "medium" if risk_score > 40 else "low",
        "reasons": reasons,
        "url": url
    }

    CACHE[url] = response_data

    return jsonify(response_data)


# ===============================
# Run
# ===============================

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
