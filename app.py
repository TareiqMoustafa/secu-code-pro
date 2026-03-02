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

# --- إعدادات Supabase الخاصة بك (تم دمجها بنجاح) ---
SUPABASE_URL = "https://ikkwtwbymnpzouggtwah.supabase.co"
SUPABASE_KEY = "sb_publishable_xft-w0W9IodndRwBEa8abA_wrjM5VYE"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- القائمة السوداء الصارمة (Strict Blacklist) ---
BANNED_DOMAINS = ['casajoys.com', 'foyya7me']

def calculate_entropy(text):
    """حساب عشوائية الدومين لكشف الروابط المولدة آلياً"""
    if not text: return 0
    probs = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return - sum([p * math.log(p) / math.log(2.0) for p in probs])

def deep_forensic_engine(url):
    """المحرك الجنائي لتحليل الرابط"""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    # 1. الحظر الفوري (Blacklist)
    if any(banned in url.lower() for banned in BANNED_DOMAINS):
        return {
            "risk_score": 100,
            "is_blacklisted": True,
            "findings": ["⚠️ حظر صارم: هذا الدومين مدرج في القائمة السوداء العالمية", "❌ تم منع الوصول: مصدر تهديد معروف"]
        }

    risk_points = 0
    findings = []
    
    # 2. كشف التزييف (Typosquatting)
    sensitive_brands = ['google', 'facebook', 'paypal', 'binance', 'apple', 'microsoft', 'netflix', 'amazon']
    clean_name = domain.split('.')[0]
    for brand in sensitive_brands:
        if 0 < distance(clean_name, brand) <= 2:
            risk_points += 85
            findings.append(f"🚩 تنبيه انتحال: الرابط يحاول تقليد موقع {brand.upper()} الرسمي")

    # 3. تحليل الانتروبيا (DGA Detection)
    if calculate_entropy(domain) > 3.8:
        risk_points += 40
        findings.append("🔍 نمط مشبوه: اسم الدومين يبدو وكأنه مولد آلياً بواسطة برمجيات خبيثة")

    # 4. فحص الـ SSL/TLS
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                findings.append("✅ اتصال آمن: شهادة الـ SSL صالحة ومفعلة")
    except:
        risk_points += 45
        findings.append("🚫 خطر أمني: الاتصال غير مشفر (لا يوجد SSL)")

    final_score = min(risk_points, 100)
    return {
        "risk_score": final_score,
        "is_blacklisted": final_score >= 60,
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
            return jsonify({"status": "error", "message": "صيغة الرابط غير صحيحة"}), 400

        try:
            final_target = requests.head(processed_url, allow_redirects=True, timeout=5).url
        except:
            final_target = processed_url
            
        analysis = deep_forensic_engine(final_target)
        
        # --- تحديث العدادات في Supabase ---
        try:
            supabase.rpc('increment_scanned', {}).execute()
            if analysis["is_blacklisted"]:
                supabase.rpc('increment_threats', {}).execute()
        except Exception as e:
            logging.error(f"Database Error: {e}")

        return jsonify({
            "status": "Verified",
            "url": final_target,
            "risk_score": analysis["risk_score"],
            "is_blacklisted": analysis["is_blacklisted"],
            "forensic_report": analysis["findings"],
            "latency": f"{int((time.time() - start_time) * 1000)}ms",
            "timestamp": time.strftime("%H:%M:%S")
        })

    except Exception as e:
        return jsonify({"status": "error", "message": "فشل في التحليل"}), 500

@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=False)
