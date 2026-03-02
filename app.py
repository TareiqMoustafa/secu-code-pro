import os, requests, base64, socket, ssl
from flask import Flask, request, jsonify, render_template
from urllib.parse import urlparse
from Levenshtein import distance
from supabase import create_client, Client

app = Flask(__name__)

# --- الربط المباشر ببياناتك الجديدة ---
SUPABASE_URL = "https://ikkwtwbymnpzouggtwah.supabase.co"
SUPABASE_KEY = "sb_publishable_xft-w0W9IodndRwBEa8abA_wrjM5VYE"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# مفتاح VirusTotal للتحليل العالمي
VT_API_KEY = "07c7587e1d272b5f0187493944bb59ba9a29a56a16c2df681ab56b3f3c887564"

def forensic_logic(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    # القائمة السوداء الفورية
    if any(b in url.lower() for b in ['casajoys.com', 'foyya7me']):
        return {"score": 100, "bad": True, "report": ["⚠️ حظر إداري: الموقع مدرج في القائمة السوداء"]}

    risk = 0
    findings = []
    
    # فحص VirusTotal
    try:
        u_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{u_id}", headers={"x-apikey": VT_API_KEY}, timeout=3).json()
        mal = r.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
        if mal > 0:
            risk += (mal * 20)
            findings.append(f"🚩 VirusTotal: مكتشف بواسطة {mal} محرك فحص")
    except: pass

    # فحص انتحال الهوية
    if any(distance(domain.split('.')[0], brand) <= 2 for brand in ['google', 'facebook', 'paypal']):
        risk += 75
        findings.append("🔍 انتحال هوية: تشابه مع موقع رسمي")

    # فحص التشفير SSL
    try:
        with socket.create_connection((domain, 443), timeout=2):
            findings.append("✅ تشفير SSL: الاتصال مؤمن")
    except:
        risk += 40
        findings.append("🚫 خطر: الموقع لا يدعم التشفير (No SSL)")

    final_score = min(risk, 100)
    return {"score": final_score, "bad": final_score >= 50, "report": findings}

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        url = data.get('link', '').strip()
        if not url: return jsonify({"status": "error", "message": "الرابط فارغ"}), 400
        
        if not url.startswith('http'): url = "https://" + url
        
        res = forensic_logic(url)
        
        # تحديث الإحصائيات في Supabase
        try:
            supabase.rpc('increment_scanned', {}).execute()
            if res["bad"]: supabase.rpc('increment_threats', {}).execute()
        except: pass

        return jsonify({"status": "success", "bad": res["bad"], "score": res["score"], "report": res["report"]})
    except Exception as e:
        return jsonify({"status": "error", "message": "فشل الاتصال بالسيرفر"}), 500

if __name__ == '__main__':
    app.run(debug=True)
