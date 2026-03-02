import os
import requests
import base64
import socket
import ssl
import time
import math
import logging
import validators
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
from Levenshtein import distance
from supabase import create_client, Client

# إعداد تطبيق Flask
app = Flask(__name__)

# إعداد تسجيل الأخطاء (Logging) لمراقبة أداء السيرفر
logging.basicConfig(level=logging.INFO)

# --- إعدادات الربط مع قاعدة البيانات السحابية (Supabase) ---
# تم استخدام البيانات الخاصة بمشروعك للربط المباشر
SUPABASE_URL = "https://ikkwtwbymnpzouggtwah.supabase.co"
SUPABASE_KEY = "sb_publishable_xft-w0W9IodndRwBEa8abA_wrjM5VYE"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- إعدادات مفتاح VirusTotal API ---
# المفتاح الخاص بك لتفعيل الفحص العالمي للروابط
VT_API_KEY = os.getenv("VT_API_KEY", "07c7587e1d272b5f0187493944bb59ba9a29a56a16c2df681ab56b3f3c887564")

# --- القائمة السوداء اليدوية (Blacklist) ---
# المواقع التي يتم حظرها فوراً بناءً على طلبك
BANNED_DOMAINS = ['casajoys.com', 'foyya7me']

def deep_forensic_engine(url):
    """
    محرك التحليل الجنائي الهجين:
    يقوم بدمج الفحص المحلي (Heuristic) مع الاستخبارات العالمية (Threat Intelligence)
    """
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    # 1. فحص الحظر الإداري الفوري (أعلى أولوية)
    if any(banned in url.lower() for banned in BANNED_DOMAINS):
        return {
            "risk_score": 100, 
            "is_blacklisted": True, 
            "findings": ["⚠️ حظر إداري: هذا النطاق مدرج في القائمة السوداء للنظام."]
        }

    risk_points = 0
    findings = []
    
    # 2. فحص استخبارات VirusTotal العالمية
    try:
        # تحويل الرابط إلى ID متوافق مع API v3
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_res = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}", 
            headers={"x-apikey": VT_API_KEY}, 
            timeout=4
        ).json()
        
        # استخراج عدد المحركات التي صنفت الرابط كتهديد
        malicious_count = vt_res.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
        
        if malicious_count > 0:
            risk_points += (malicious_count * 25)
            findings.append(f"🚩 VirusTotal: تم اكتشاف الرابط بواسطة {malicious_count} محرك فحص عالمي.")
    except Exception as e:
        logging.error(f"VirusTotal Error: {e}")

    # 3. فحص انتحال الهوية (Typosquatting) باستخدام خوارزمية Levenshtein
    # كشف الروابط التي تحاول تقليد الماركات العالمية (مثل faceb0ok بدل facebook)
    sensitive_brands = ['google', 'facebook', 'paypal', 'binance', 'apple', 'amazon', 'microsoft']
    clean_domain = domain.split('.')[0]
    
    for brand in sensitive_brands:
        d = distance(clean_domain, brand)
        if 0 < d <= 2:
            risk_points += 75
            findings.append(f"🔍 انتحال هوية: تم اكتشاف تشابه كبير مع نطاق {brand.upper()} الرسمي.")

    # 4. فحص بروتوكولات الأمان والتشفير (SSL/TLS)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                findings.append("✅ أمن البيانات: شهادة SSL صالحة والاتصال مشفر.")
    except Exception:
        risk_points += 40
        findings.append("🚫 تحذير أمني: الموقع لا يدعم التشفير (SSL مفقود)، البيانات عرضة للتنصت.")

    # حساب النتيجة النهائية (بحد أقصى 100)
    final_score = min(risk_points, 100)
    
    return {
        "risk_score": final_score,
        "is_blacklisted": final_score >= 50,
        "findings": findings
    }

@app.route('/')
def home():
    """عرض الصفحة الرئيسية للموقع"""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """نقطة النهاية (Endpoint) لاستقبال الروابط وتحليلها"""
    try:
        data = request.get_json()
        target_url = data.get('link', '').strip()

        if not target_url:
            return jsonify({"status": "error", "message": "الرابط مطلوب للفحص"}), 400
            
        # التأكد من وجود البروتوكول في الرابط
        if not target_url.startswith(('http://', 'https://')):
            target_url = "https://" + target_url

        # التحقق من صحة صياغة الرابط
        if not validators.url(target_url):
            return jsonify({"status": "error", "message": "صيغة الرابط غير صحيحة"}), 400

        # بدء عملية التحليل الجنائي
        analysis = deep_forensic_engine(target_url)
        
        # تحديث عدادات Supabase السحابية (إحصائيات حية)
        try:
            # زيادة عداد الروابط المفحوصة
            supabase.rpc('increment_scanned', {}).execute()
            
            # إذا كان الرابط ضاراً، يتم زيادة عداد التهديدات
            if analysis["is_blacklisted"]:
                supabase.rpc('increment_threats', {}).execute()
        except Exception as e:
            logging.error(f"Supabase RPC Error: {e}")

        # إرسال النتيجة النهائية للواجهة الأمامية
        return jsonify({
            "status": "success",
            "url": target_url,
            "risk_score": analysis["risk_score"],
            "is_blacklisted": analysis["is_blacklisted"],
            "forensic_report": analysis["findings"]
        })

    except Exception as e:
        logging.error(f"Global Error: {e}")
        return jsonify({"status": "error", "message": "حدث خطأ غير متوقع في السيرفر"}), 500

if __name__ == '__main__':
    # تشغيل السيرفر في وضع التطوير (أو الإنتاج عند الرفع)
    app.run(debug=True)
