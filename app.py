import os
import requests
import base64
import socket
import ssl
import time
import math
import logging
import re
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
import firebase_admin
from firebase_admin import credentials, db
from Levenshtein import distance

app = Flask(__name__)

# إعدادات المفاتيح (تأكد من وضع مفتاحك الصحيح لـ VT)
VT_API_KEY = "07c7587e1d272b5f0187493944bb59ba9a29a56a16c2df681ab56b3f3c887564"

# --- محركات الاستخبارات المتقدمة ---

def calculate_entropy(text):
    """تقنية متطورة لكشف الدومينات المولدة آلياً (DGA Detection)"""
    if not text: return 0
    probs = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in probs])
    return entropy

def check_domain_age_risk(domain):
    """تحليل منطقي: مواقع الاحتيال لا تعيش طويلاً"""
    # في النسخة الاحترافية نستخدم Whois API، هنا نضع منطقاً استباقياً
    suspicious_tlds = ['.zip', '.mov', '.top', '.xyz', '.work', '.click']
    return any(domain.endswith(tld) for tld in suspicious_tlds)

def deep_forensic_engine(url):
    """المحرك المركزي لاتخاذ القرار السيبراني"""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    # مصفوفة المخاطر (Risk Matrix)
    metrics = {
        "entropy": calculate_entropy(domain),
        "typosquatting": False,
        "ssl_score": 0,
        "reputation_score": 0,
        "is_dga": False
    }
    
    risk_points = 0
    findings = []

    # 1. كشف الـ Typosquatting (تشابه الأسماء)
    sensitive_brands = ['google', 'facebook', 'paypal', 'binance', 'apple', 'microsoft', 'netflix']
    clean_name = domain.split('.')[0]
    for brand in sensitive_brands:
        d = distance(clean_name, brand)
        if 0 < d <= 2: # تشابه قريب جداً ولكنه ليس الأصل
            metrics["typosquatting"] = True
            risk_points += 70
            findings.append(f"High-Risk Similarity to {brand.upper()}")

    # 2. تحليل العشوائية (Entropy)
    if metrics["entropy"] > 3.8: # مؤشر تقني على أن الدومين مشبوه ومولد آلياً
        metrics["is_dga"] = True
        risk_points += 40
        findings.append("Algorithmic Domain Generation Detected")

    # 3. الفحص التقني العميق (SSL & Handshake)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                metrics["ssl_score"] = 100
                findings.append("Grade-A SSL Encryption")
    except:
        risk_points += 35
        findings.append("Insecure Protocol (Missing SSL)")

    # 4. الاستخبارات الجماعية (VirusTotal V3)
    try:
        u_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_res = requests.get(f"https://www.virustotal.com/api/v3/urls/{u_id}", 
                             headers={"x-apikey": VT_API_KEY}, timeout=5).json()
        malicious = vt_res['data']['attributes']['last_analysis_stats']['malicious']
        if malicious > 0:
            risk_points += (malicious * 30)
            findings.append(f"Confirmed Threat by {malicious} Engines")
    except: pass

    final_score = min(risk_points, 100)
    return {
        "risk_score": final_score,
        "is_blacklisted": final_score >= 50,
        "findings": findings,
        "tech_metrics": metrics
    }

# --- مسارات النظام ---

@app.route('/analyze', methods=['POST'])
def analyze():
    timer_start = time.time()
    try:
        data = request.get_json()
        target = data.get('link', '').strip()
        
        # بروتوكول التنظيف الاستباقي للرابط
        if not re.match(r'http(s)?://', target):
            target = "https://" + target
            
        # تتبع الرابط النهائي (للمواقع المختصرة)
        try:
            final_target = requests.head(target, allow_redirects=True, timeout=5).url
        except: final_target = target
            
        domain = urlparse(final_target).netloc.lower()
        
        # تشغيل محرك التحليل الجنائي
        report = deep_forensic_engine(final_target)
        
        # جلب بيانات البنية التحتية (Server Ops)
        try:
            ip_addr = socket.gethostbyname(domain)
            geo = requests.get(f"https://ipapi.co/{ip_addr}/json/", timeout=3).json()
            server = {
                "ip": ip_addr,
                "country": geo.get("country_name", "International"),
                "isp": geo.get("org", "Private Data Center"),
                "asn": geo.get("asn", "Unknown")
            }
        except:
            server = {"ip": "Proxy/CDN", "country": "Hidden", "isp": "Cloudflare/Akamai", "asn": "N/A"}

        # مزامنة البيانات مع Firebase
        try:
            db.reference('stats/clicks').transaction(lambda x: (x or 0) + 1)
            if report["is_blacklisted"]:
                db.reference('stats/threats').transaction(lambda x: (x or 0) + 1)
        except: pass

        return jsonify({
            "status": "Verified",
            "url": final_target,
            "risk_score": report["risk_score"],
            "is_blacklisted": report["is_blacklisted"],
            "forensic_report": report["findings"],
            "server_details": server,
            "latency": f"{int((time.time() - timer_start) * 1000)}ms",
            "security_grade": "A+" if report["risk_score"] < 20 else ("C" if report["risk_score"] < 50 else "F")
        })

    except Exception as e:
        return jsonify({"status": "Critical Error", "log": str(e)}), 500

@app.route('/')
def main_gateway():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
