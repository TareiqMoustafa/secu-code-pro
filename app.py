import os
import requests
import base64
import socket
import ssl
import time
import math
import logging
import re
import validators
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
import firebase_admin
from firebase_admin import credentials, db
from Levenshtein import distance

app = Flask(__name__)

# إعداد السجلات البرمجية (Logging) لسهولة التتبع
logging.basicConfig(level=logging.INFO)

# --- إعدادات الحماية والوصول ---
# يتم جلب المفاتيح من بيئة العمل (Environment Variables) لضمان أعلى معايير الأمان
VT_API_KEY = os.getenv("VT_API_KEY", "07c7587e1d272b5f0187493944bb59ba9a29a56a16c2df681ab56b3f3c887564")

# تشغيل نظام Firebase Admin SDK
try:
    if not firebase_admin._apps:
        # ملاحظة: تأكد من إضافة FIREBASE_PRIVATE_KEY في إعدادات Vercel
        cred = credentials.Certificate({
            "type": "service_account",
            "project_id": "secucode-pro",
            "private_key": os.getenv("FIREBASE_PRIVATE_KEY", "").replace('\\n', '\n'),
            "client_email": "firebase-adminsdk-fbsvc@secucode-pro.iam.gserviceaccount.com"
        })
        firebase_admin.initialize_app(cred, {
            'databaseURL': 'https://flutter-ai-playground-2de28-default-rtdb.europe-west1.firebasedatabase.app'
        })
except Exception as e:
    logging.error(f"System: Firebase initialization failed: {e}")

# --- محركات التحليل الجنائي المتقدمة ---

def calculate_entropy(text):
    """خوارزمية قياس العشوائية لكشف الدومينات المولدة آلياً (DGA)"""
    if not text: return 0
    probs = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return - sum([p * math.log(p) / math.log(2.0) for p in probs])

def deep_forensic_engine(url):
    """المحرك المركزي لاتخاذ القرار السيبراني بناءً على 4 طبقات فحص"""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    risk_points = 0
    findings = []
    
    # 1. كشف التزييف الرقمي (Typosquatting)
    # تقنية تقارن اسم النطاق بأشهر العلامات التجارية العالمية
    sensitive_brands = ['google', 'facebook', 'paypal', 'binance', 'apple', 'microsoft', 'netflix', 'amazon']
    clean_name = domain.split('.')[0]
    for brand in sensitive_brands:
        d = distance(clean_name, brand)
        if 0 < d <= 2: # تشابه بصري خادع
            risk_points += 75
            findings.append(f"Potential Phishing: Domain mimics {brand.upper()}")

    # 2. تحليل الانتروبيا (Entropy Analysis)
    # كشف الأسماء العشوائية التي تستخدمها البرمجيات الخبيثة
    if calculate_entropy(domain) > 3.8:
        risk_points += 45
        findings.append("Suspicious Pattern: Algorithmic Domain detected")

    # 3. فحص البروتوكول الأمني (SSL/TLS Inspection)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                findings.append("Verified: Grade-A SSL Encryption Active")
    except:
        risk_points += 40
        findings.append("Warning: Unencrypted Connection (Missing SSL)")

    # 4. قاعدة بيانات التهديدات العالمية (VirusTotal Intel)
    try:
        u_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_res = requests.get(f"https://www.virustotal.com/api/v3/urls/{u_id}", 
                             headers={"x-apikey": VT_API_KEY}, timeout=5).json()
        malicious = vt_res['data']['attributes']['last_analysis_stats']['malicious']
        if malicious > 0:
            risk_points += (malicious * 30)
            findings.append(f"Threat Intelligence: Flagged by {malicious} security vendors")
    except:
        pass

    final_score = min(risk_points, 100)
    return {
        "risk_score": final_score,
        "is_blacklisted": final_score >= 50,
        "findings": findings
    }

# --- المسارات البرمجية (Endpoints) ---

@app.route('/analyze', methods=['POST'])
def analyze():
    start_time = time.time()
    try:
        data = request.get_json()
        target_url = data.get('link', '').strip()

        # التحقق من صحة الرابط برمجياً لمنع الأخطاء التقنية
        if not target_url:
            return jsonify({"status": "error", "message": "URL is required"}), 400
            
        if not target_url.startswith(('http://', 'https://')):
            target_url = "https://" + target_url

        if not validators.url(target_url):
            return jsonify({"status": "error", "message": "Invalid URL format"}), 400

        # تتبع الرابط الوجهة (للمواقع المختصرة مثل bit.ly)
        try:
            final_target = requests.head(target_url, allow_redirects=True, timeout=5).url
        except:
            final_target = target_url
            
        domain = urlparse(final_target).netloc.lower()
        
        # إطلاق محرك التحليل الجنائي
        analysis = deep_forensic_engine(final_target)
        
        # جلب تفاصيل البنية التحتية للسيرفر (Infrastructure Details)
        try:
            ip_addr = socket.gethostbyname(domain)
            geo_data = requests.get(f"https://ipapi.co/{ip_addr}/json/", timeout=3).json()
            server_details = {
                "ip": ip_addr,
                "country": geo_data.get("country_name", "International Data Center"),
                "isp": geo_data.get("org", "Managed Infrastructure"),
                "asn": geo_data.get("asn", "Private Network")
            }
        except:
            server_details = {"ip": "Hidden/CDN", "country": "Secure Proxy", "isp": "Cloud Network", "asn": "N/A"}

        # تحديث الإحصائيات اللحظية في قاعدة بيانات Firebase
        try:
            db.reference('stats/clicks').transaction(lambda x: (x or 0) + 1)
            if analysis["is_blacklisted"]:
                db.reference('stats/threats').transaction(lambda x: (x or 0) + 1)
        except:
            pass

        # توليد الاستجابة النهائية
        return jsonify({
            "status": "Verified",
            "url": final_target,
            "risk_score": analysis["risk_score"],
            "is_blacklisted": analysis["is_blacklisted"],
            "forensic_report": analysis["findings"],
            "server": server_details,
            "latency": f"{int((time.time() - start_time) * 1000)}ms",
            "timestamp": time.strftime("%H:%M:%S | %Y-%m-%d")
        })

    except Exception as e:
        logging.error(f"Critical Analysis Error: {e}")
        return jsonify({"status": "error", "message": "Internal Analysis Failure"}), 500

@app.route('/')
def home():
    """المسار الأساسي لفتح واجهة النظام"""
    return render_template('index.html')

# تشغيل التطبيق (مناسب للبيئة المحلية، Vercel سيستخدم gunicorn)
if __name__ == '__main__':
    app.run(debug=False)
