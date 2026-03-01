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
from Levenshtein import distance
from supabase import create_client, Client

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# --- إعدادات الربط (Supabase & VirusTotal) ---
SUPABASE_URL = "https://ikkwtwbymnpzouggtwah.supabase.co"
SUPABASE_KEY = "sb_publishable_xft-w0W9IodndRwBEa8abA_wrjM5VYE"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# مفتاح VirusTotal (تأكد من صحته)
VT_API_KEY = os.getenv("VT_API_KEY", "07c7587e1d272b5f0187493944bb59ba9a29a56a16c2df681ab56b3f3c887564")

# --- القائمة السوداء الصارمة ---
BANNED_DOMAINS = ['casajoys.com', 'foyya7me']

def calculate_entropy(text):
    if not text: return 0
    probs = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return - sum([p * math.log(p) / math.log(2.0) for p in probs])

def deep_forensic_engine(url):
    """محرك هجين يجمع بين التحليل السلوكي واستخبارات VirusTotal"""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    # 1. فحص الحظر الصارم (أعلى أولوية)
    if any(banned in url.lower() for banned in BANNED_DOMAINS):
        return {
            "risk_score": 100,
            "is_blacklisted": True,
            "findings": ["⚠️ حظر يدوي: الدومين مدرج في القائمة السوداء الخاصة بالنظام"]
        }

    risk_points = 0
    findings = []
    
    # 2. تحليل VirusTotal (الاستخبارات العالمية)
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", 
                             headers={"x-apikey": VT_API_KEY}, timeout=5).json()
        malicious_count = vt_res['data']['attributes']['last_analysis_stats']['malicious']
        if malicious_count > 0:
            risk_points += (malicious_count * 20)
            findings.append(f"🚩 VirusTotal: تم تصنيفه كتهديد من قبل {malicious_count} محرك فحص عالمي")
    except:
        pass

    # 3. كشف التزييف (Typosquatting)
    sensitive_brands = ['google', 'facebook', 'paypal', 'binance', 'apple', 'microsoft']
    clean_name = domain.split('.')[0]
    for brand in sensitive_brands:
        if 0 < distance(clean_name, brand) <= 2:
            risk_points += 70
            findings.append(f"🔍 تنبيه انتحال: تشابه كبير مع نطاق {brand.upper()} الرسمي")

    # 4. فحص الـ SSL
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                findings.append("✅ أمن البيانات: شهادة SSL صالحة")
    except:
        risk_points += 30
        findings.append("🚫 تحذير: اتصال غير مشفر (SSL مفقود)")

    final_score = min(risk_points, 100)
    return {
        "risk_score": final_score,
        "is_blacklisted": final_score >= 50,
        "findings": findings
    }

@app.route('/analyze', methods=['POST'])
def analyze():
    start_time = time.time()
    try:
        data = request.get_json()
        target_url = data.get('link', '').strip()

        if not target_url:
            return jsonify({"status": "error", "message": "الرابط مطلوب"}), 400
            
        processed_url = target_url if target_url.startswith(('http://', 'https://')) else "https://" + target_url

        if not validators.url(processed_url):
            return jsonify({"status": "error", "message": "صيغة غير صالحة"}), 400

        # التحليل
        analysis = deep_forensic_engine(processed_url)
        
        # تحديث Supabase (RPC)
        try:
            supabase.rpc('increment_scanned', {}).execute()
            if analysis["is_blacklisted"]:
                supabase.rpc('increment_threats', {}).execute()
        except Exception as e:
            logging.error(f"Supabase Error: {e}")

        return jsonify({
            "status": "Verified",
            "url": processed_url,
            "risk_score": analysis["risk_score"],
            "is_blacklisted": analysis["is_blacklisted"],
            "forensic_report": analysis["findings"],
            "latency": f"{int((time.time() - start_time) * 1000)}ms"
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=False)
