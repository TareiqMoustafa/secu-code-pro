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

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# --- إعدادات الربط (تأكد من كتابتها بدقة) ---
SUPABASE_URL = "https://ikkwtwbymnpzouggtwah.supabase.co"
SUPABASE_KEY = "sb_publishable_xft-w0W9IodndRwBEa8abA_wrjM5VYE"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# مفتاح VirusTotal 
VT_API_KEY = os.getenv("VT_API_KEY", "07c7587e1d272b5f0187493944bb59ba9a29a56a16c2df681ab56b3f3c887564")

# القائمة السوداء الصارمة
BANNED_DOMAINS = ['casajoys.com', 'foyya7me']

def deep_forensic_engine(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    # 1. فحص الحظر اليدوي الفوري
    if any(banned in url.lower() for banned in BANNED_DOMAINS):
        return {"risk_score": 100, "is_blacklisted": True, "findings": ["⚠️ حظر إداري: الدومين مدرج في القائمة السوداء"]}

    risk_points = 0
    findings = []
    
    # 2. فحص VirusTotal
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", 
                             headers={"x-apikey": VT_API_KEY}, timeout=4).json()
        mal_stats = vt_res.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        malicious = mal_stats.get('malicious', 0)
        if malicious > 0:
            risk_points += (malicious * 25)
            findings.append(f"🚩 VirusTotal: مكتشف بواسطة {malicious} محرك")
    except: pass

    # 3. فحص التزييف (Levenshtein)
    for brand in ['google', 'facebook', 'paypal', 'apple']:
        if 0 < distance(domain.split('.')[0], brand) <= 2:
            risk_points += 70
            findings.append(f"🔍 انتحال هوية: تشابه مع {brand.upper()}")

    # 4. فحص SSL
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname=domain):
                findings.append("✅ اتصال مشفر وآمن")
    except:
        risk_points += 40
        findings.append("🚫 اتصال غير آمن (بدون SSL)")

    score = min(risk_points, 100)
    return {"risk_score": score, "is_blacklisted": score >= 50, "findings": findings}

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        target_url = data.get('link', '').strip()
        if not target_url: return jsonify({"status": "error", "message": "الرابط فارغ"}), 400
        
        if not target_url.startswith(('http://', 'https://')): target_url = "https://" + target_url
        
        analysis = deep_forensic_engine(target_url)
        
        # تحديث Supabase (تأكد من وجود وظائف الـ RPC في Supabase SQL)
        try:
            supabase.rpc('increment_scanned', {}).execute()
            if analysis["is_blacklisted"]:
                supabase.rpc('increment_threats', {}).execute()
        except: pass

        return jsonify({
            "status": "success",
            "risk_score": analysis["risk_score"],
            "is_blacklisted": analysis["is_blacklisted"],
            "forensic_report": analysis["findings"]
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/')
def home(): return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
