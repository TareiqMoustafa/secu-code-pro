import os, requests, base64, re, logging
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
from Levenshtein import distance
from supabase import create_client, Client

app = Flask(__name__)

# إعداد السجلات لمراقبة الأخطاء
logging.basicConfig(level=logging.INFO)

# --- إعدادات Supabase ---
# ملاحظة: يفضل مستقبلاً وضع هذه المفاتيح في Environment Variables على Vercel
SUPABASE_URL = "https://ikkwtwbymnpzouggtwah.supabase.co"
SUPABASE_KEY = "sb_publishable_xft-w0W9IodndRwBEa8abA_wrjM5VYE"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- مفاتيح API الخارجي ---
VT_API_KEY = "07c7587e1d272b5f0187493944bb59ba9a29a56a16c2df681ab56b3f3c887564"
TELEGRAM_TOKEN = "8072400877:AAEhIU4s8csph7d6NBM5MlZDlfWIAV7ca2o"
CHAT_ID = "7421725464"

# القوائم البيضاء والسوداء
WHITELIST = ['google.com', 'facebook.com', 'microsoft.com', 'apple.com', 'paypal.com', 'binance.com', 'github.com']
BLACKLIST = ['casajoys.com', 'foyya7me.com', 'free-gifts.xyz', 'login-verify-secure.top', 'win-iphone.click']

def get_server_info(domain):
    """جلب معلومات الخادم الجغرافية والعنوان الرقمي"""
    try:
        # استخدام خدمة ipapi لجلب بيانات الدومين
        response = requests.get(f"https://ipapi.co/{domain}/json/", timeout=3)
        if response.status_code == 200:
            res_data = response.json()
            return {
                "ip": res_data.get("ip", "Unknown"),
                "country": res_data.get("country_name", "Unknown")
            }
    except Exception as e:
        logging.error(f"Server info error: {e}")
    return {"ip": "0.0.0.0", "country": "Unknown"}

def get_vt_stats(url):
    """تحليل الرابط عبر VirusTotal API"""
    try:
        # تحويل الرابط إلى Base64 المطلوب لـ VirusTotal
        u_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{u_id}", headers=headers, timeout=5)
        if r.status_code == 200:
            return r.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
    except Exception as e:
        logging.error(f"VirusTotal error: {e}")
    return None

def analyze_logic(url, domain, vt):
    """المنطق البرمجي لتحديد درجة الخطورة"""
    risk = 0
    reasons = []

    # 1. فحص القائمة البيضاء
    if any(d == domain for d in WHITELIST):
        return 0, ["✅ موقع رسمي موثوق"]

    # 2. فحص القائمة السوداء
    if any(d in domain for d in BLACKLIST):
        risk += 90
        reasons.append("🚩 محظور: هذا الموقع مدرج في القائمة السوداء")

    # 3. فحص انتحال الشخصية (Typosquatting)
    for trust in WHITELIST:
        clean_trust = trust.split('.')[0]
        clean_domain = domain.split('.')[0]
        if distance(clean_domain, clean_trust) == 1 and clean_domain != clean_trust:
            risk += 85
            reasons.append(f"⚠️ انتحال: يحاول تقليد موقع {trust}")

    # 4. تحليل نتائج VirusTotal
    if vt:
        malicious_count = vt.get('malicious', 0)
        suspicious_count = vt.get('suspicious', 0)
        if malicious_count > 0:
            risk += (malicious_count * 25)
            reasons.append(f"🚨 VirusTotal: تم كشفه بواسطة {malicious_count} برنامج حماية")
        elif suspicious_count > 0:
            risk += 30
            reasons.append("🔍 اشتباه: تم تصنيفه كموقع مشبوه")

    # 5. كلمات دالة على التصيد
    if re.search(r'(login|verify|update|secure|gift|prize|bank|account)', url.lower()):
        risk += 15
        if risk < 50: reasons.append("🔍 ملاحظة: الرابط يحتوي على كلمات تطلب بيانات حساسة")

    return min(risk, 100), reasons

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/stats', methods=['GET'])
def get_stats():
    """جلب الإحصائيات الحالية من Supabase للواجهة الأمامية"""
    try:
        res = supabase.table("stats").select("*").eq("id", 1).single().execute()
        return jsonify(res.data)
    except Exception as e:
        logging.error(f"Fetch stats error: {e}")
        return jsonify({"total_scanned": 0, "threats_detected": 0})

@app.route('/analyze', methods=['POST'])
def analyze():
    """المسار الرئيسي لاستقبال طلبات الفحص"""
    try:
        data = request.get_json()
        raw_url = data.get('link', '').strip()
        
        if not raw_url:
            return jsonify({"error": "No URL provided"}), 400
        
        # تصحيح صيغة الرابط
        url = raw_url if raw_url.startswith(('http://', 'https://')) else 'https://' + raw_url
        domain = urlparse(url).netloc.lower()
        
        # تنفيذ التحليلات
        vt_stats = get_vt_stats(url)
        server_info = get_server_info(domain)
        risk_score, reasons = analyze_logic(url, domain, vt_stats)
        is_threat = risk_score >= 60

        # تحديث قاعدة بيانات Supabase (زيادة العدادات)
        try:
            supabase.rpc('increment_scanned').execute()
            if is_threat:
                supabase.rpc('increment_threats').execute()
        except Exception as e:
            logging.error(f"Database update failed: {e}")

        # إرسال تنبيه إلى تليجرام
        try:
            status_icon = "🛑" if is_threat else "✅"
            msg = (f"{status_icon} *SecuCode Scan Result*\n\n"
                   f"*URL:* `{url}`\n"
                   f"*Risk Score:* {risk_score}%\n"
                   f"*Diagnosis:* {reasons[0] if reasons else 'Clean'}\n"
                   f"*Server IP:* {server_info['ip']}")
            requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", 
                          json={"chat_id": CHAT_ID, "text": msg, "parse_mode": "Markdown"})
        except:
            pass

        return jsonify({
            "risk_score": risk_score,
            "is_blacklisted": is_threat,
            "reasons": reasons,
            "url": url,
            "server": server_info
        })

    except Exception as e:
        logging.error(f"Global analyze error: {e}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    # التشغيل محلياً للتجربة
    app.run(host='0.0.0.0', port=5000, debug=True)
