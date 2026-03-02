import os, requests, base64, socket, time, logging
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
import firebase_admin
from firebase_admin import credentials, db

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# --- بيانات الوصول ---
VT_API_KEY = "07c7587e1d272b5f0187493944bb59ba9a29a56a16c2df681ab56b3f3c887564"
TELEGRAM_TOKEN = "8072400877:AAEhIU4s8csph7d6NBM5MlZDlfWIAV7ca2o"
CHAT_ID = "7421725464"

# إعداد Firebase
FIREBASE_CONFIG = {
    "type": "service_account",
    "project_id": "secucode-pro",
    "private_key_id": "131da2ca8578982b77e48fa71f8c4b65880b0784",
    "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCZwhV2C+HnRrp8\nTemJc7bdbGw2JUb47hZ1ShXk2ReFbQ256bhud1AIO+rxHJ0fzq8Ba+ZTaAsodLxU\nn74+dxpyrMUolvBONnWgFeQtgqFsHouAAy0j/iJs6yNny6o4f/TVp4UKixqY+jT0\nTSBo8ixU7Dxh6VWdom62BsKUAGN8ALFM5N6+4z3fbCj9fB4mmvibIQLLAVwxZ703\ndSP1ZFOJgd98LEHYOBYBKAOQ/fEyq20e8PEokuVnoLqvLxJDGCwGvv5aEadq2t3O\nhJ9oJAefIDD2YsAPgeMu8MAtlHlTuoqu82FGehQ2v6mtC4121W2NFLORPC1fttWE\nFr5U5La3AgMBAAECggEAAUqVcGNeFirBiZCBK7wwJ6P3mLGZpkmD9N5R6FByJyy+\nr91nA2d4fZpiP3ZA9jTda0K8Hr9B2uEm8CjcqcJGXmtDC/UTsQIhAm5H9DE2gAyr\nej0lkOh6l9ScwTHA0Z8MnTy0xOBpeRdjZ32pjiSSixW0QB8kj4u0NJ+yvW+3NDru\ntErFEF03IaMgfnK279reWuNKC72lZfVlkFk9qoi6b34j1mdhAXlkIqPm1plkd8py\nZDPxGf7/xdB32peadLpuWHvd/JyE9hLGa+CT9g12kKOcxh/KmJVD5MBkIriQAFoh\nT7pvJm9SDju4uDtc6O26IME3/YIwjB+YfgrXMySMiQKBgQDOSdjq2/TJTYXoen2X\ncvlssZGGVenb30rcQHIPtC9xHhczPJ6cAPhRltmeV37HO8g82unNnbsAePCsVZx+\nX6p2y9VDzTDimAJEXd/JVjwBnFs8/8GwUwLoFvsbnAvA8pSFHYmKURDJolPjJ0Gw\qr40NrApbRG47JYQHyhHTfOPwwKBgQC+z5Xa2yT1rSzOsNoOwfJmTo0oThNaTExE\n6/8/1F7NpeZLKbew5sai20CmmvWKljVKgiyUdJLZShlbnqv3QUvEL+PH9pWNftpd\phAlbEG9UPjF6nR8IrOwtAXK3tMyrGlYl7EI0dgwY8pzoYgUraRik2AqfaG2BRe/\n8oUXZMKh/QKBgGmwaiOCB/su7cF7KGd0r5fhrgZedA+Dao5HsmibT4cr/ITytOyG\njrL2j45Rk5Gt7lxHaGxBOLL4\n-----END PRIVATE KEY-----\n",
    "client_email": "firebase-adminsdk-fbsvc@secucode-pro.iam.gserviceaccount.com"
}

try:
    if not firebase_admin._apps:
        cred = credentials.Certificate(FIREBASE_CONFIG)
        firebase_admin.initialize_app(cred, {
            'databaseURL': 'https://flutter-ai-playground-2de28-default-rtdb.europe-west1.firebasedatabase.app'
        })
except Exception as e: logging.error(f"Firebase Error: {e}")

WHITELIST = ['google.com', 'microsoft.com', 'apple.com', 'facebook.com', 'github.com']

def get_vt_stats(url):
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": VT_API_KEY}, timeout=5)
        if response.status_code == 200:
            return response.json()['data']['attributes']['last_analysis_stats']
    except: return None

def get_forensics(domain):
    try:
        ip = socket.gethostbyname(domain)
        geo = requests.get(f"https://ipapi.co/{ip}/json/", timeout=3).json()
        return {"ip": ip, "country": geo.get("country_name", "Unknown")}
    except: return {"ip": "0.0.0.0", "country": "Cloud Node"}

@app.route('/')
def index(): return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        raw_url = data.get('link', '').strip()
        if not raw_url: return jsonify({"error": "No URL"}), 400
        
        url = raw_url if raw_url.startswith('http') else 'https://' + raw_url
        domain = urlparse(url).netloc.lower() or url
        
        server_info = get_forensics(domain)
        vt_stats = get_vt_stats(url)
        
        is_official = any(d in domain for d in WHITELIST)
        mal_count = vt_stats.get('malicious', 0) if vt_stats else 0
        risk_score = 0 if is_official else min(10 + (mal_count * 30), 100)
        is_blacklisted = risk_score >= 60

        # إرسال تلجرام
        try:
            status = "🛑" if is_blacklisted else "✅"
            msg = f"{status} *SecuCode Scan*\n*URL:* {url}\n*Risk:* {risk_score}%"
            requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": CHAT_ID, "text": msg, "parse_mode": "Markdown"})
        except: pass

        return jsonify({
            "is_official": is_official,
            "is_blacklisted": is_blacklisted,
            "risk_score": risk_score,
            "server": server_info,
            "url": url
        })
    except Exception as e: return jsonify({"error": str(e)}), 500

if __name__ == '__main__': app.run(debug=True)
