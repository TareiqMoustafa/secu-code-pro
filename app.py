import os, requests, base64, socket, re, logging
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
from Levenshtein import distance
from supabase import create_client, Client

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# --- بيانات ربط Supabase (القاعدة الجديدة) ---
SUPABASE_URL = "https://ikkwtwbymnpzouggtwah.supabase.co"
SUPABASE_KEY = "sb_publishable_xft-w0W9IodndRwBEa8abA_wrjM5VYE"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- مفاتيح الوصول ---
VT_API_KEY = "07c7587e1d272b5f0187493944bb59ba9a29a56a16c2df681ab56b3f3c887564"
TELEGRAM_TOKEN = "8072400877:AAEhIU4s8csph7d6NBM5MlZDlfWIAV7ca2o"
CHAT_ID = "7421725464"

# --- القوائم الذكية ---
WHITELIST = ['google.com', 'facebook.com', 'microsoft.com', 'apple.com', 'paypal.com', 'binance.com', 'github.com']
# قائمة سوداء محدثة لأشهر مواقع الاحتيال الحالية
BLACKLIST = ['casajoys.com', 'foyya7me.com', 'free-gifts.xyz', 'login-verify-secure.top', 'win-iphone.click']

def get_vt_stats(url):
    try:
        u_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{u_id}", headers={"x-apikey": VT_API_KEY}, timeout=4).json()
        return r.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
    except: return None

def analyze_logic(url, domain, vt):
    risk = 0
    reasons = []
    
    # 1. فحص القائمة البيضاء
    if any(d in domain for d in WHITELIST): return 0, ["✅ موقع رسمي موثوق"]

    # 2. فحص القائمة السوداء
    if any(d in domain for d in BLACKLIST):
        risk += 90
        reasons.append("🚩 محظور: هذا الموقع مدرج في القائمة السوداء للاحتيال")

    # 3. كشف انتحال الهوية (Typosquatting)
    for trust in WHITELIST:
        clean_trust = trust.split('.')[0]
        clean_domain = domain.split('.')[0]
        if distance(clean_domain, clean_trust) == 1 and clean_domain != clean_trust:
            risk += 80
            reasons.append(f"⚠️ انتحال: يحاول تقليد موقع {trust} بشكل مخادع")

    # 4. نتائج VirusTotal
    if vt:
        mal = vt.get('malicious', 0)
        if mal > 0:
            risk += (mal * 20)
            reasons.append(f"🚨 VirusTotal: تم كشفه بواسطة {mal} برنامج حماية")

    # 5. كلمات مشبوهة في الرابط
    if re.search(r'(login|verify|update|secure|gift|prize|bank)', url.lower()):
        risk += 15
        reasons.append("🔍 اشتباه: الرابط يحتوي على كلمات تستخدم في التصيد")

    return min(risk, 100), reasons

@app.route('/')
def index(): return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        raw_url = data.get('link', '').strip()
        if not raw_url: return jsonify({"error": "No URL"}), 400
        
        url = raw_url if raw_url.startswith('http') else 'https://' + raw_url
        domain = urlparse(url).netloc.lower()
        
        vt_stats = get_vt_stats(url)
        risk_score, reasons = analyze_logic(url, domain, vt_stats)
        is_bad = risk_score >= 60

        # تحديث العدادات في Supabase (استخدام دالة RPC لزيادة الرقم)
        try:
            supabase.rpc('increment_scanned', {}).execute()
            if is_bad: supabase.rpc('increment_threats', {}).execute()
        except: pass

        # تنبيه تليجرام
        try:
            status = "🛑" if is_bad else "✅"
            msg = f"{status} *SecuCode Scan*\n*URL:* {url}\n*Risk:* {risk_score}%\n*Result:* {reasons[0] if reasons else 'Clean'}"
            requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": CHAT_ID, "text": msg, "parse_mode": "Markdown"})
        except: pass

        return jsonify({
            "risk_score": risk_score,
            "is_blacklisted": is_bad,
            "reasons": reasons,
            "url": url
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__': app.run(debug=True)
