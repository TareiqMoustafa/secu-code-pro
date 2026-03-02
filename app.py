import os, requests, base64, socket, time, logging, re
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
from Levenshtein import distance # تأكد من تثبيت pip install python-Levenshtein
import firebase_admin
from firebase_admin import credentials, db

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# --- إعدادات الوصول ---
VT_API_KEY = "07c7587e1d272b5f0187493944bb59ba9a29a56a16c2df681ab56b3f3c887564"
TELEGRAM_TOKEN = "8072400877:AAEhIU4s8csph7d6NBM5MlZDlfWIAV7ca2o"
CHAT_ID = "7421725464"

# إعداد Firebase
try:
    if not firebase_admin._apps:
        cred = credentials.Certificate("serviceAccountKey.json") # يفضل وضع الملف في مسار المشروع
        firebase_admin.initialize_app(cred, {
            'databaseURL': 'https://flutter-ai-playground-2de28-default-rtdb.europe-west1.firebasedatabase.app'
        })
except Exception as e: logging.error(f"Firebase Error: {e}")

# --- القائمة البيضاء (المواقع الموثوقة) ---
WHITELIST = [
    'google.com', 'facebook.com', 'microsoft.com', 'apple.com', 'twitter.com', 
    'instagram.com', 'linkedin.com', 'github.com', 'amazon.com', 'netflix.com',
    'paypal.com', 'binance.com', 'youtube.com', 'wikipedia.org'
]

# --- القائمة السوداء (أمثلة لنطاقات مشبوهة شائعة) ---
# ملاحظة: في المشاريع الضخمة يتم سحب هذه القائمة من API خارجي مثل PhishTank
BLACKLIST = [
    'bit.ly', 'cutt.ly', 't.co', 'tinyurl.com', 'free-gifts.click', 
    'login-secure-update.com', 'verify-account-now.top', 'casajoys.com', 
    'foyya7me.com', 'win-iphone-free.xyz', 'update-password-bank.net'
]

def get_vt_stats(url):
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}", 
            headers={"x-apikey": VT_API_KEY}, 
            timeout=5
        )
        if response.status_code == 200:
            return response.json()['data']['attributes']['last_analysis_stats']
    except: return None

def get_forensics(domain):
    try:
        ip = socket.gethostbyname(domain)
        geo = requests.get(f"https://ipapi.co/{ip}/json/", timeout=3).json()
        return {"ip": ip, "country": geo.get("country_name", "Unknown"), "org": geo.get("org", "Unknown")}
    except: return {"ip": "0.0.0.0", "country": "Hidden/CDN", "org": "Protected"}

def calculate_risk(url, domain, vt_stats):
    risk = 0
    reasons = []

    # 1. فحص القائمة البيضاء
    if any(d == domain for d in WHITELIST):
        return 0, ["✅ نطاق رسمي موثوق"]

    # 2. فحص القائمة السوداء اليدوية
    if any(d in domain for d in BLACKLIST):
        risk += 80
        reasons.append("🚩 النطاق مدرج في قاعدة بيانات المواقع المشبوهة")

    # 3. فحص انتحال الهوية (Typosquatting)
    # لو الرابط شبه المواقع المشهورة (مثلاً g00gle)
    for trust_d in WHITELIST:
        main_part = trust_d.split('.')[0]
        domain_part = domain.split('.')[0]
        if distance(domain_part, main_part) == 1 and domain_part != main_part:
            risk += 70
            reasons.append(f"⚠️ انتحال صفة: الرابط يحاول تقليد {trust_d}")

    # 4. فحص الروابط المختصرة (غالباً ما تستخدم في التصيد)
    if any(short in domain for short in ['bit.ly', 't.co', 'cutt.ly']):
        risk += 30
        reasons.append("ℹ️ رابط مختصر: غالباً ما يستخدم لإخفاء الوجهة النهائية")

    # 5. نتائج VirusTotal
    if vt_stats:
        mal = vt_stats.get('malicious', 0)
        sus = vt_stats.get('suspicious', 0)
        if mal > 0:
            risk += (mal * 25)
            reasons.append(f"🚩 اكتشفه {mal} محرك فحص كـ 'رابط ضار'")
        if sus > 0:
            risk += 15
            reasons.append("⚠️ تم تصنيفه كـ 'مشبوه' بواسطة محركات الفحص")

    # 6. فحص الكلمات الدليلة للاحتيال في الرابط
    bad_keywords = ['login', 'verify', 'secure', 'account', 'update', 'banking', 'free', 'gift', 'prize']
    if any(word in url.lower() for word in bad_keywords) and not any(d in domain for d in WHITELIST):
        risk += 20
        reasons.append("🔍 الرابط يحتوي على كلمات تستخدم عادة في التصيد")

    return min(risk, 100), reasons

@app.route('/')
def index(): return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        raw_url = data.get('link', '').strip()
        if not raw_url: return jsonify({"error": "No URL"}), 400
        
        # ضبط صيغة الرابط
        url = raw_url if raw_url.startswith('http') else 'https://' + raw_url
        parsed = urlparse(url)
        domain = parsed.netloc.lower() or parsed.path.lower()
        
        # جلب البيانات
        server_info = get_forensics(domain)
        vt_stats = get_vt_stats(url)
        
        # حساب الخطورة بالمنطق الجديد
        risk_score, reasons = calculate_risk(url, domain, vt_stats)
        is_blacklisted = risk_score >= 60

        # إرسال تلجرام
        try:
            status_icon = "🛑" if is_blacklisted else "✅"
            msg = (f"{status_icon} *SecuCode Forensic Report*\n\n"
                   f"*URL:* `{url}`\n"
                   f"*Risk Score:* `{risk_score}%`\n"
                   f"*IP:* `{server_info['ip']}`\n"
                   f"*Country:* `{server_info['country']}`\n"
                   f"*Findings:* {', '.join(reasons)}")
            requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", 
                          json={"chat_id": CHAT_ID, "text": msg, "parse_mode": "Markdown"})
        except: pass

        return jsonify({
            "is_official": risk_score == 0,
            "is_blacklisted": is_blacklisted,
            "risk_score": risk_score,
            "server": server_info,
            "reasons": reasons,
            "url": url
        })
    except Exception as e: 
        logging.error(f"Analysis Error: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__': app.run(debug=True)
