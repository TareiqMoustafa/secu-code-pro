import os, requests, base64, re, logging, socket, ssl, json, hashlib, time, random, string, hmac
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify, render_template, send_file
from urllib.parse import urlparse
from dotenv import load_dotenv
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from supabase import create_client, Client
from subscriptions import DAILY_LIMIT, has_feature
from bs4 import BeautifulSoup
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()

app = Flask(__name__)

# ========== التحقق الصارم من المتغيرات البيئية الأساسية ==========
REQUIRED_ENV_VARS = [
    'SECRET_KEY',
    'JWT_SECRET_KEY',
    'SUPABASE_URL',
    'SUPABASE_KEY',
    'VT_API_KEY',
    'URLSCAN_API_KEY',
    'GOOGLE_SAFE_KEY'
]

missing_vars = [var for var in REQUIRED_ENV_VARS if not os.environ.get(var)]
if missing_vars:
    raise RuntimeError(f"❌ Missing required environment variables: {', '.join(missing_vars)}")

app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['JWT_SECRET_KEY'] = os.environ['JWT_SECRET_KEY']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)

# ========== إصلاح مشكلة IP خلف Vercel (ProxyFix) ==========
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

jwt = JWTManager(app)

# ========== رؤوس الأمان المتقدمة ==========
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' https://cdn.tailwindcss.com https://unpkg.com https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com;"
    return response

# ========== Supabase (بعد التأكد من وجود المتغيرات) ==========
SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_KEY = os.environ["SUPABASE_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ========== API Keys (المطلوبة والاختيارية) ==========
VT_API_KEY         = os.environ["VT_API_KEY"]
TELEGRAM_TOKEN     = os.environ.get("TELEGRAM_TOKEN", "")
CHAT_ID            = os.environ.get("CHAT_ID", "")
CLAUDE_API_KEY     = os.environ.get("CLAUDE_API_KEY", "")
URLSCAN_API_KEY    = os.environ["URLSCAN_API_KEY"]
GOOGLE_SAFE_KEY    = os.environ["GOOGLE_SAFE_KEY"]
ABUSEIPDB_KEY      = os.environ.get("ABUSEIPDB_KEY", "free")
ADMIN_SECRET_KEY   = os.environ.get("ADMIN_SECRET_KEY", "admin-secret-change-me")
PHISHTANK_API_KEY  = os.environ.get("PHISHTANK_API_KEY", "")
GREYNOISE_API_KEY  = os.environ.get("GREYNOISE_API_KEY", "")

# ═══════════════════════════════════════════════════════════════════════════
# Helper functions
# ═══════════════════════════════════════════════════════════════════════════

def get_current_user():
    try:
        user_id = get_jwt_identity()
        if user_id and supabase:
            res = supabase.table("users").select("*").eq("id", user_id).execute()
            if res.data:
                return res.data[0]
    except Exception as e:
        logger.warning(f"get_current_user error: {e}")
    return None

def ensure_user_exists(user_id, email):
    if not supabase:
        return
    try:
        res = supabase.table("users").select("*").eq("id", user_id).execute()
        if not res.data:
            supabase.table("users").insert({
                "id": user_id,
                "email": email,
                "plan": "free",
                "scans_used_today": 0,
                "quota_reset_date": datetime.now(timezone.utc).date().isoformat()
            }).execute()
            logger.info(f"Created new user record for {email}")
    except Exception as e:
        logger.warning(f"ensure_user_exists error: {e}")

def get_user_quota(user):
    if not user:
        return None, 0, 0, 0
    daily_limit = DAILY_LIMIT
    used_today = user.get("scans_used_today", 0)
    remaining = max(0, daily_limit - used_today)
    return "free", used_today, daily_limit, remaining

def reset_daily_quota_if_needed(user_id):
    if not supabase:
        return
    today = datetime.now(timezone.utc).date().isoformat()
    try:
        res = supabase.table("users").select("quota_reset_date").eq("id", user_id).execute()
        if res.data:
            last_reset = res.data[0].get("quota_reset_date")
            if last_reset != today:
                supabase.table("users").update({"scans_used_today": 0, "quota_reset_date": today}).eq("id", user_id).execute()
                logger.info(f"Daily quota reset for user {user_id}")
    except Exception as e:
        logger.warning(f"Quota reset failed: {e}")

def increment_user_quota(user_id):
    if not supabase or not user_id:
        return
    try:
        res = supabase.table("users").select("scans_used_today").eq("id", user_id).execute()
        used = res.data[0].get("scans_used_today", 0) if res.data else 0
        supabase.table("users").update({"scans_used_today": used + 1}).eq("id", user_id).execute()
    except Exception as e:
        logger.warning(f"Quota increment failed: {e}")

# ═══════════════════════════════════════════════════════════════════════════
# Stats helpers
# ═══════════════════════════════════════════════════════════════════════════

def ensure_stats_table():
    if not supabase:
        return
    try:
        supabase.table("stats").select("*").limit(1).execute()
    except:
        logger.warning("Stats table not found.")

def increment_stats_safely(is_threat):
    if not supabase:
        return
    try:
        supabase.rpc('increment_scanned').execute()
        if is_threat:
            supabase.rpc('increment_threats').execute()
        logger.info(f"Stats updated via RPC (threat={is_threat})")
        return
    except Exception as e:
        logger.error(f"RPC failed: {e}")
    try:
        res = supabase.table("stats").select("*").eq("id", 1).execute()
        if res.data:
            curr = res.data[0]
            new_scanned = curr.get("total_scanned", 0) + 1
            new_threats = curr.get("threats_detected", 0) + (1 if is_threat else 0)
            supabase.table("stats").update({"total_scanned": new_scanned, "threats_detected": new_threats}).eq("id", 1).execute()
        else:
            supabase.table("stats").insert({"id": 1, "total_scanned": 1, "threats_detected": 1 if is_threat else 0}).execute()
        logger.info(f"Stats updated via direct update")
    except Exception as e2:
        logger.error(f"Direct update failed: {e2}")

# ═══════════════════════════════════════════════════════════════════════════
# Internal Reputation Cache
# ═══════════════════════════════════════════════════════════════════════════

def get_cached_reputation(url):
    if not supabase:
        return None
    try:
        res = supabase.table("reputation_cache").select("*").eq("url", url).execute()
        if res.data:
            return res.data[0]
    except:
        return None

def update_cached_reputation(url, risk_score, is_threat, verdict, reasons, info_notes):
    if not supabase:
        return
    try:
        existing = get_cached_reputation(url)
        if existing:
            supabase.table("reputation_cache").update({
                "risk_score": risk_score,
                "is_threat": is_threat,
                "verdict": verdict,
                "reasons": reasons,
                "info_notes": info_notes,
                "last_scanned": datetime.now(timezone.utc).isoformat(),
                "scan_count": existing.get("scan_count", 0) + 1
            }).eq("url", url).execute()
        else:
            supabase.table("reputation_cache").insert({
                "url": url,
                "risk_score": risk_score,
                "is_threat": is_threat,
                "verdict": verdict,
                "reasons": reasons,
                "info_notes": info_notes,
                "last_scanned": datetime.now(timezone.utc).isoformat(),
                "scan_count": 1
            }).execute()
    except:
        pass

def get_user_stats(user_id):
    if not supabase:
        return {}
    try:
        week_ago = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
        res = supabase.table("scan_history").select("risk_score, is_threat, scanned_at").eq("user_id", user_id).gte("scanned_at", week_ago).execute()
        total_scans = len(res.data)
        threats = sum(1 for r in res.data if r['is_threat'])
        avg_risk = sum(r['risk_score'] for r in res.data) / total_scans if total_scans > 0 else 0
        return {'total_scans': total_scans, 'threats': threats, 'avg_risk': avg_risk, 'history': res.data}
    except:
        return {}

# ═══════════════════════════════════════════════════════════════════════════
# Link Preview & Screenshot
# ═══════════════════════════════════════════════════════════════════════════

def fetch_link_preview(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; SecuCodePro/2.0)'}
        resp = requests.get(url, timeout=5, headers=headers, allow_redirects=True)
        if resp.status_code != 200:
            return None
        soup = BeautifulSoup(resp.text, 'html.parser')
        title = soup.find('title')
        title = title.get_text().strip() if title else ''
        meta_desc = soup.find('meta', attrs={'name': 'description'}) or soup.find('meta', attrs={'property': 'og:description'})
        description = meta_desc.get('content', '').strip() if meta_desc else ''
        og_image = soup.find('meta', attrs={'property': 'og:image'})
        image_url = og_image.get('content', '') if og_image else ''
        if not image_url:
            img = soup.find('img')
            if img and img.get('src'):
                image_url = requests.compat.urljoin(url, img['src'])
        return {'title': title[:200], 'description': description[:300], 'image': image_url, 'url': resp.url}
    except:
        return None

def get_urlscan_screenshot(url):
    if not URLSCAN_API_KEY:
        return None
    try:
        headers = {"Content-Type": "application/json", "API-Key": URLSCAN_API_KEY}
        r = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json={"url": url, "visibility": "unlisted"}, timeout=10)
        if r.status_code not in (200, 201):
            return None
        scan_id = r.json().get("uuid")
        if not scan_id:
            return None
        for _ in range(12):
            time.sleep(5)
            res = requests.get(f"https://urlscan.io/api/v1/result/{scan_id}/", timeout=8)
            if res.status_code == 200:
                return f"https://urlscan.io/screenshots/{scan_id}.png"
        return None
    except:
        return None

# ═══════════════════════════════════════════════════════════════════════════
# NEW: PhishTank & GreyNoise Functions
# ═══════════════════════════════════════════════════════════════════════════

def check_phishtank(url):
    """
    التحقق مما إذا كان الرابط مدرجاً في PhishTank كرابط تصيد.
    يعيد dict: { 'in_database': bool, 'phish_id': str, 'verified': bool }
    """
    if not PHISHTANK_API_KEY:
        return None
    try:
        payload = {'url': url, 'format': 'json', 'app_key': PHISHTANK_API_KEY}
        r = requests.post('https://checkurl.phishtank.com/checkurl/', data=payload, timeout=10)
        if r.status_code == 200:
            data = r.json()
            results = data.get('results', {})
            in_db = results.get('in_database') == 'true'
            return {
                'in_database': in_db,
                'phish_id': results.get('phish_id'),
                'verified': results.get('verified') == 'true',
                'verified_at': results.get('verified_at')
            }
    except Exception as e:
        logger.warning(f"PhishTank check failed: {e}")
    return None

def check_greynoise(ip):
    """
    تصنيف عنوان IP باستخدام GreyNoise.
    يعيد dict يحتوي على classification و name و link وغيرها.
    """
    if not GREYNOISE_API_KEY or not ip or ip == "0.0.0.0":
        return None
    try:
        headers = {"key": GREYNOISE_API_KEY, "Accept": "application/json"}
        r = requests.get(f"https://api.greynoise.io/v3/community/{ip}", headers=headers, timeout=5)
        if r.status_code == 200:
            data = r.json()
            return {
                'ip': data.get('ip'),
                'classification': data.get('classification'),  # malicious, benign, unknown
                'name': data.get('name'),
                'noise': data.get('noise', False),
                'riot': data.get('riot', False),
                'link': data.get('link'),
                'last_seen': data.get('last_seen')
            }
    except Exception as e:
        logger.warning(f"GreyNoise check failed: {e}")
    return None

# ═══════════════════════════════════════════════════════════════════════════
# ANALYSIS FUNCTIONS (full versions)
# ═══════════════════════════════════════════════════════════════════════════

try:
    import dns.resolver, dns.reversename
    DNS_AVAILABLE = True
except:
    DNS_AVAILABLE = False

try:
    from Levenshtein import distance as lev_distance
except:
    def lev_distance(s1, s2):
        if len(s1) < len(s2): s1, s2 = s2, s1
        if not s2: return len(s1)
        prev = list(range(len(s2)+1))
        for i, c1 in enumerate(s1):
            curr = [i+1]
            for j, c2 in enumerate(s2):
                curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(c1!=c2)))
            prev = curr
        return prev[-1]

WHITELIST = [
    'google.com','facebook.com','microsoft.com','apple.com','paypal.com','binance.com','github.com','amazon.com','twitter.com','x.com',
    'linkedin.com','youtube.com','instagram.com','whatsapp.com','cloudflare.com','wikipedia.org','reddit.com','stackoverflow.com',
    'mozilla.org','adobe.com','netflix.com','spotify.com','openai.com','anthropic.com','telegram.org','discord.com','tiktok.com',
    'snapchat.com','zoom.us','dropbox.com','icloud.com','outlook.com','office.com','live.com','bing.com','yahoo.com','twitch.tv'
]
BLACKLIST = [
    'casajoys.com','foyya7me.com','free-gifts.xyz','login-verify-secure.top','win-iphone.click','secure-login-verify.com',
    'paypa1.com','amaz0n.com','g00gle.com','faceb00k.com','micros0ft.com','paypa1.net'
]
URL_SHORTENERS = [
    'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','buff.ly','short.link','rb.gy','is.gd','v.gd','cutt.ly','tiny.cc',
    'shorturl.at','bl.ink','rebrand.ly','youtu.be','fb.me'
]
HIGH_RISK_TLDS = [
    '.xyz','.top','.click','.loan','.win','.gq','.tk','.ml','.cf','.ga','.work','.party','.download','.racing','.review',
    '.science','.trade','.wang','.buzz','.icu','.cyou','.monster','.rest'
]
PHISHING_PATTERNS = [
    (r'(login|signin|sign-in)', 25, "Credential-harvesting keyword"),
    (r'(verify|validation|confirm)', 20, "Account-verification phishing pattern"),
    (r'(update|upgrade|renew)', 15, "Forced-update social engineering"),
    (r'(secure|security|protect)', 10, "False-security reassurance keyword"),
    (r'(gift|prize|winner|reward|free)', 35, "Reward-lure phishing vector"),
    (r'(bank|account|wallet|crypto)', 30, "Financial-credential targeting"),
    (r'(suspend|blocked|locked|alert)', 25, "Urgency-manipulation trigger"),
    (r'\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}', 20, "IP-address masquerading as domain"),
    (r'@', 40, "'@' in URL — credential bypass technique"),
    (r'(paypal|apple|microsoft|amazon|google).+\.(xyz|top|click|tk|ml)', 60, "Brand impersonation with suspicious TLD"),
    (r'(password|passwd|pwd|credentials)', 30, "Password-targeting keyword"),
    (r'\.php\?.*=http', 25, "Open redirect vulnerability"),
    (r'(%[0-9a-f]{2}){3,}', 20, "Heavy URL encoding — obfuscation attempt"),
]

def check_ssl(domain):
    result = {"has_ssl": False, "valid": False, "issuer": "", "expiry": "", "days_left": None, "grade": "F"}
    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(5)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()
        result["has_ssl"] = True
        result["valid"] = True
        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        result["issuer"] = issuer_dict.get("organizationName", "Unknown CA")
        expiry_str = cert.get("notAfter", "")
        if expiry_str:
            expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry_dt - datetime.now(timezone.utc)).days
            result["expiry"] = expiry_dt.strftime("%Y-%m-%d")
            result["days_left"] = days_left
            result["grade"] = "A+" if days_left > 90 else "A" if days_left > 60 else "B" if days_left > 14 else "C"
    except ssl.SSLCertVerificationError:
        result["has_ssl"] = True
        result["valid"] = False
        result["grade"] = "F"
    except:
        pass
    return result

def check_whois(domain):
    result = {"registered": None, "age_days": None, "registrar": "", "is_new": False, "expires": ""}
    try:
        resp = requests.get(f"https://api.whoisfreaks.com/v1.0/whois?apiKey=free&whois=live&domainName={domain}", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            created = data.get("domain_registered_on") or data.get("create_date", "")
            expires = data.get("domain_expires_on", "")
            if created:
                dt = datetime.strptime(created[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                age = (datetime.now(timezone.utc) - dt).days
                result.update({"registered": created[:10], "age_days": age, "is_new": age < 90, "registrar": data.get("registrar_name", ""), "expires": expires[:10] if expires else ""})
    except:
        pass
    return result

def check_ip_reputation(ip):
    result = {"score": 0, "is_vpn": False, "is_proxy": False, "is_tor": False, "abuse_reports": 0, "risk": "Unknown"}
    if not ip or ip == "0.0.0.0":
        return result
    try:
        headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        r = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90", headers=headers, timeout=4)
        if r.status_code == 200:
            d = r.json().get("data", {})
            score = d.get("abuseConfidenceScore", 0)
            result.update({"score": score, "abuse_reports": d.get("totalReports", 0), "is_tor": d.get("isTor", False), "risk": "HIGH" if score > 50 else "MEDIUM" if score > 20 else "LOW"})
    except:
        pass
    try:
        r2 = requests.get(f"https://ipapi.co/{ip}/json/", timeout=4)
        if r2.status_code == 200:
            d2 = r2.json()
            result["is_proxy"] = bool(d2.get("proxy", False))
            result["is_vpn"] = bool(d2.get("vpn", False))
    except:
        pass
    return result

def get_dns_intel(domain):
    result = {"ip": None, "ipv6": None, "mx": [], "ns": [], "txt": [], "reverse": None, "hosting": None, "country": None, "city": None, "org": None, "asn": None, "all_ips": [], "dns_sec": False}
    if DNS_AVAILABLE:
        try:
            answers = dns.resolver.resolve(domain, 'A')
            ips = [str(r) for r in answers]
            result["all_ips"] = ips
            result["ip"] = ips[0] if ips else None
        except:
            pass
        try:
            ans6 = dns.resolver.resolve(domain, 'AAAA')
            result["ipv6"] = str(ans6[0])
        except:
            pass
        try:
            mx_ans = dns.resolver.resolve(domain, 'MX')
            result["mx"] = sorted([str(r.exchange).rstrip('.') for r in mx_ans])
        except:
            pass
        try:
            ns_ans = dns.resolver.resolve(domain, 'NS')
            result["ns"] = [str(r).rstrip('.') for r in ns_ans]
        except:
            pass
        try:
            txt_ans = dns.resolver.resolve(domain, 'TXT')
            result["txt"] = [str(r) for r in txt_ans][:5]
        except:
            pass
        try:
            dns.resolver.resolve(domain, 'DNSKEY')
            result["dns_sec"] = True
        except:
            pass
    else:
        try:
            r = requests.get(f"https://dns.google/resolve?name={domain}&type=A", timeout=4)
            if r.status_code == 200:
                for ans in r.json().get("Answer", []):
                    val = ans.get("data", "")
                    if re.match(r'^\d+\.\d+\.\d+\.\d+$', val):
                        result["all_ips"].append(val)
                result["ip"] = result["all_ips"][0] if result["all_ips"] else None
        except:
            pass
    if result["ip"]:
        try:
            geo = requests.get(f"https://ipapi.co/{result['ip']}/json/", timeout=4).json()
            result.update({"country": geo.get("country_name", ""), "city": geo.get("city", ""), "org": geo.get("org", ""), "asn": geo.get("asn", ""), "hosting": geo.get("org", "")})
        except:
            pass
        if DNS_AVAILABLE:
            try:
                rev = dns.resolver.resolve(dns.reversename.from_address(result["ip"]), 'PTR')
                result["reverse"] = str(rev[0]).rstrip('.')
            except:
                pass
    return result

def trace_real_ip(domain):
    ips = set()
    if DNS_AVAILABLE:
        try:
            for r in dns.resolver.resolve(domain, 'A'):
                ips.add(str(r))
        except:
            pass
    try:
        r = requests.get(f"https://dns.google/resolve?name={domain}&type=A", timeout=4)
        if r.status_code == 200:
            for ans in r.json().get("Answer", []):
                val = ans.get("data", "")
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', val):
                    ips.add(val)
    except:
        pass
    try:
        r = requests.get(f"https://cloudflare-dns.com/dns-query?name={domain}&type=A", headers={"Accept": "application/dns-json"}, timeout=4)
        if r.status_code == 200:
            for ans in r.json().get("Answer", []):
                val = ans.get("data", "")
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', val):
                    ips.add(val)
    except:
        pass
    result = []
    for ip in list(ips)[:5]:
        info = {"ip": ip, "country": "", "city": "", "org": "", "asn": "", "is_hosting": False}
        try:
            geo = requests.get(f"https://ipapi.co/{ip}/json/", timeout=4).json()
            info.update({"country": geo.get("country_name", ""), "city": geo.get("city", ""), "org": geo.get("org", ""), "asn": geo.get("asn", "")})
            info["is_hosting"] = any(h in info["org"].lower() for h in ['amazon', 'google', 'microsoft', 'cloudflare', 'digitalocean', 'linode', 'vultr', 'ovh', 'hetzner', 'fastly', 'akamai', 'cdn'])
        except:
            pass
        result.append(info)
    return result

def check_google_safe(url):
    result = {"safe": True, "threats": [], "checked": False}
    if not GOOGLE_SAFE_KEY:
        return result
    try:
        payload = {"client": {"clientId": "secucode-pro", "clientVersion": "5.0"}, "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}}
        r = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_KEY}", json=payload, timeout=5)
        if r.status_code == 200:
            result["checked"] = True
            matches = r.json().get("matches", [])
            if matches:
                result["safe"] = False
                result["threats"] = [m.get("threatType", "") for m in matches]
    except:
        pass
    return result

def get_vt_report(url):
    if not VT_API_KEY:
        return None
    try:
        u_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        r = requests.get(f"https://www.virustotal.com/api/v3/urls/{u_id}", headers={"x-apikey": VT_API_KEY}, timeout=6)
        if r.status_code == 200:
            attrs = r.json().get('data', {}).get('attributes', {})
            return {"stats": attrs.get('last_analysis_stats', {}), "categories": attrs.get('categories', {}), "reputation": attrs.get('reputation', 0), "engines": {n: res.get('result') for n, res in attrs.get('last_analysis_results', {}).items() if res.get('category') in ('malicious', 'suspicious')}}
    except:
        return None

def get_dns_history(domain):
    result = {"records": [], "changes": 0, "first_seen": None, "suspicious": False}
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=5)
        if r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.strip().split("\n")[:8]:
                parts = line.split(",")
                if len(parts) >= 2:
                    result["records"].append({"ip": parts[1].strip(), "subdomain": parts[0].strip()})
            result["changes"] = len(result["records"])
            result["suspicious"] = len(result["records"]) > 5
    except:
        pass
    return result

def ai_analyze(url, domain, risk_score, reasons, dns_data, vt_data, ssl_data):
    if not CLAUDE_API_KEY:
        return None
    try:
        vt_summary = ""
        if vt_data:
            s = vt_data.get("stats", {})
            vt_summary = f"VirusTotal: {s.get('malicious',0)} malicious, {s.get('suspicious',0)} suspicious"
        ssl_summary = f"SSL: {'Valid' if ssl_data.get('valid') else 'Invalid'}, Grade: {ssl_data.get('grade','?')}"
        dns_summary = f"IP: {dns_data.get('ip','?')}, Country: {dns_data.get('country','?')}, Org: {dns_data.get('org','?')}"
        prompt = f"""Analyze URL: {url}, Domain: {domain}, Risk Score: {risk_score}/100, Issues: {'; '.join(reasons[:8]) if reasons else 'None'}. {dns_summary} {ssl_summary} {vt_summary}. Respond in JSON: {{"verdict": "CRITICAL|SUSPICIOUS|SAFE", "confidence": 0-100, "ai_risk_adjustment": -20 to +20, "attack_type": "Phishing|Malware|Scam|Typosquatting|Brand_Impersonation|Safe|Unknown", "summary_ar": "تحليل بالعربية", "summary_en": "Analysis in English", "recommendation_ar": "نصيحة بالعربية", "recommendation_en": "Advice in English", "indicators": []}}"""
        resp = requests.post("https://api.anthropic.com/v1/messages", headers={"x-api-key": CLAUDE_API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json"}, json={"model": "claude-haiku-4-5-20251001", "max_tokens": 800, "messages": [{"role": "user", "content": prompt}]}, timeout=12)
        if resp.status_code == 200:
            text = resp.json()["content"][0]["text"]
            text = re.sub(r'```json|```', '', text).strip()
            return json.loads(text)
    except:
        return None

def get_threat_feed():
    threats = []
    try:
        r = requests.post("https://urlhaus-api.abuse.ch/v1/urls/recent/", json={"limit": 12}, timeout=5)
        if r.status_code == 200:
            for item in r.json().get("urls", [])[:12]:
                threats.append({"url": item.get("url", "")[:80], "threat": item.get("threat", "malware"), "date": item.get("date_added", "")[:10], "country": item.get("country", "?")})
    except:
        pass
    return threats

def bulk_analyze(urls):
    results = []
    for raw_url in urls[:50]:
        raw_url = raw_url.strip()
        if not raw_url:
            continue
        try:
            url = raw_url if raw_url.startswith(('http://', 'https://')) else 'https://' + raw_url
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if not domain:
                continue
            clean = domain[4:] if domain.startswith('www.') else domain
            risk, reasons = 0, []
            if any(clean == d or clean.endswith('.' + d) for d in WHITELIST):
                results.append({"url": raw_url, "risk": 0, "verdict": "SAFE", "reason": "Whitelisted domain"})
                continue
            if any(bl in domain for bl in BLACKLIST):
                risk += 90
                reasons.append("Blacklisted")
            for trusted in WHITELIST:
                bt, bd = trusted.split('.')[0], clean.split('.')[0]
                if 0 < lev_distance(bd, bt) <= 2 and bd != bt:
                    risk += 80
                    reasons.append(f"Typosquatting: {trusted}")
                    break
            for pattern, weight, _ in PHISHING_PATTERNS:
                if re.search(pattern, url.lower()):
                    risk += weight
            if any(domain.endswith(t) for t in HIGH_RISK_TLDS):
                risk += 20
            if url.startswith('http://'):
                risk += 10
            risk = min(risk, 100)
            verdict = "THREAT" if risk >= 60 else "SUSPICIOUS" if risk >= 25 else "SAFE"
            results.append({"url": raw_url, "risk": risk, "verdict": verdict, "reason": reasons[0] if reasons else "Pattern analysis"})
        except Exception as e:
            results.append({"url": raw_url, "risk": 0, "verdict": "ERROR", "reason": str(e)})
    return results

def resolve_shortened_url(url):
    try:
        raw = urlparse(url).netloc.lower()
        domain = raw[4:] if raw.startswith('www.') else raw
        if any(s in domain for s in URL_SHORTENERS):
            resp = requests.head(url, allow_redirects=True, timeout=5, headers={"User-Agent": "SecuCodePro/5.0"})
            if resp.url != url:
                return resp.url, True
    except:
        pass
    return url, False

def analyze_logic(url, domain, vt, ssl_info, whois_info, ip_rep, google_safe=None, phishtank_result=None, greynoise_result=None):
    risk, reasons, info = 0, [], []
    clean = domain[4:] if domain.startswith('www.') else domain
    if any(clean == d or clean.endswith('.' + d) for d in WHITELIST):
        return 0, ["Globally-verified official domain — no threat vectors detected."], []
    if any(bl in domain for bl in BLACKLIST):
        risk += 90
        reasons.append("BLACKLIST HIT: Domain flagged in threat-intelligence registry.")
    # --- NEW: PhishTank integration ---
    if phishtank_result and phishtank_result.get('in_database'):
        if phishtank_result.get('verified'):
            risk += 80
            reasons.append(f"PHISHTANK: Verified phishing URL (ID: {phishtank_result.get('phish_id')})")
        else:
            risk += 50
            reasons.append(f"PHISHTANK: Reported as phishing (unverified) (ID: {phishtank_result.get('phish_id')})")
    for trusted in WHITELIST:
        bt, bd = trusted.split('.')[0], clean.split('.')[0]
        lev = lev_distance(bd, bt)
        if 0 < lev <= 2 and bd != bt:
            risk += 80
            reasons.append(f"TYPOSQUATTING: Impersonating '{trusted}' (edit-distance={lev}).")
            break
    if google_safe and not google_safe.get("safe", True):
        risk += 70
        for t in google_safe.get("threats", []):
            reasons.append(f"GOOGLE SAFE BROWSING: Flagged as {t}")
    if vt:
        s = vt.get("stats", {})
        mal, sus = s.get('malicious', 0), s.get('suspicious', 0)
        eng = vt.get("engines", {})
        if mal > 0:
            risk += min(mal * 20, 60)
            reasons.append(f"VIRUSTOTAL: Malicious — flagged by {mal} engines" + (f" [{', '.join(list(eng.keys())[:5])}]" if eng else "") + ".")
        elif sus > 0:
            risk += 30
            reasons.append(f"VIRUSTOTAL: Suspicious — {sus} engines flagged.")
        if vt.get("reputation", 0) < -10:
            risk += 15
            info.append(f"Community reputation: {vt['reputation']} (severely negative).")
        if vt.get("categories"):
            info.append(f"Categories: {', '.join(set(vt['categories'].values()))}.")
    else:
        info.append("VirusTotal scan unavailable — may be a new/uncrawled URL.")
    if not ssl_info.get("has_ssl"):
        risk += 20
        reasons.append("NO SSL: Site has no HTTPS — data transmitted in plaintext.")
    elif not ssl_info.get("valid"):
        risk += 30
        reasons.append("INVALID SSL: Certificate verification failed — possible MITM attack.")
    elif ssl_info.get("days_left") is not None and ssl_info["days_left"] < 14:
        risk += 15
        reasons.append(f"SSL EXPIRING: Certificate expires in {ssl_info['days_left']} days.")
    else:
        info.append(f"SSL Valid — Issuer: {ssl_info.get('issuer','?')}, Expires: {ssl_info.get('expiry','?')} ({ssl_info.get('days_left','?')} days), Grade: {ssl_info.get('grade','?')}.")
    if whois_info.get("is_new"):
        risk += 25
        reasons.append(f"NEW DOMAIN: Registered only {whois_info['age_days']} days ago.")
    elif whois_info.get("age_days"):
        info.append(f"Domain age: {whois_info['age_days']} days (registered {whois_info.get('registered','?')}).")
    # --- NEW: GreyNoise integration for IP reputation ---
    if greynoise_result:
        classification = greynoise_result.get('classification')
        if classification == 'malicious':
            risk += 40
            reasons.append(f"GREYNOISE: IP {greynoise_result.get('ip')} is classified as malicious.")
        elif classification == 'benign':
            risk = max(0, risk - 10)
            info.append(f"GREYNOISE: IP {greynoise_result.get('ip')} is known benign (noise).")
        if greynoise_result.get('noise'):
            info.append("GreyNoise indicates this IP is scanning the internet (background noise).")
    if ip_rep.get("risk") == "HIGH":
        risk += 35
        reasons.append(f"IP THREAT: Abuse score {ip_rep['score']}% — {ip_rep['abuse_reports']} reports.")
    elif ip_rep.get("risk") == "MEDIUM":
        risk += 15
        info.append(f"IP flagged with abuse score {ip_rep['score']}%.")
    if ip_rep.get("is_tor"):
        risk += 25
        reasons.append("TOR EXIT NODE: Request from anonymous Tor network.")
    if ip_rep.get("is_proxy") or ip_rep.get("is_vpn"):
        risk += 10
        info.append("Proxy/VPN detected on server IP.")
    url_lower = url.lower()
    for pattern, weight, label in PHISHING_PATTERNS:
        if re.search(pattern, url_lower):
            risk += weight
            if risk < 95:
                reasons.append(label)
    if len(domain.split('.')) > 4:
        risk += 20
        reasons.append("DEEP SUBDOMAIN: Excessive depth — common obfuscation technique.")
    if any(domain.endswith(t) for t in HIGH_RISK_TLDS):
        tld = domain.rsplit('.', 1)[-1]
        risk += 20
        reasons.append(f"HIGH-RISK TLD: '.{tld}' — commonly abused in phishing campaigns.")
    if url.startswith('http://'):
        risk += 10
        info.append("PROTOCOL: Unencrypted HTTP — no TLS/SSL in transit.")
    if len(url) > 200:
        risk += 10
        info.append(f"URL Length: {len(url)} chars — unusually long URLs often mask destinations.")
    final = min(risk, 100)
    if final < 15 and not reasons:
        info.append("No known threat patterns detected in this URL's structure.")
    return final, reasons, info

# ═══════════════════════════════════════════════════════════════════════════
# Enhanced PDF Report Generation
# ═══════════════════════════════════════════════════════════════════════════
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.legends import Legend
from io import BytesIO

def generate_pdf_report(scan_data):
    try:
        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4,
                                leftMargin=1.8*cm, rightMargin=1.8*cm,
                                topMargin=2.5*cm, bottomMargin=2.5*cm)
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(name='CustomTitle', parent=styles['Title'],
                                     fontSize=20, textColor=colors.HexColor("#0ea5e9"),
                                     alignment=TA_CENTER, spaceAfter=20)
        heading_style = ParagraphStyle(name='CustomHeading', parent=styles['Heading2'],
                                       fontSize=14, textColor=colors.HexColor("#1e293b"),
                                       spaceBefore=16, spaceAfter=8)
        normal_style = ParagraphStyle(name='CustomNormal', parent=styles['Normal'],
                                      fontSize=9, textColor=colors.black, alignment=TA_RIGHT)
        
        story = []
        
        def header_footer(canvas, doc):
            canvas.saveState()
            canvas.setFillColor(colors.HexColor("#0ea5e9"))
            canvas.setFont('Helvetica-Bold', 12)
            canvas.drawString(1.8*cm, A4[1]-1.5*cm, "SecuCode Pro | Threat Intelligence Report")
            canvas.setFont('Helvetica', 8)
            canvas.drawRightString(A4[0]-1.8*cm, A4[1]-1.5*cm, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
            canvas.line(1.8*cm, A4[1]-1.8*cm, A4[0]-1.8*cm, A4[1]-1.8*cm)
            canvas.setFont('Helvetica', 7)
            canvas.drawString(1.8*cm, 1.2*cm, "This report is confidential and for authorized use only.")
            canvas.drawRightString(A4[0]-1.8*cm, 1.2*cm, f"Page {doc.page}")
            canvas.restoreState()
        
        story.append(Paragraph("SecuCode Pro Threat Intelligence Report", title_style))
        story.append(Spacer(1, 0.2*cm))
        
        url = scan_data.get('url', 'N/A')
        risk = scan_data.get('risk_score', 0)
        is_threat = scan_data.get('is_threat', False)
        verdict_text = "⚠️ THREAT DETECTED" if is_threat else "✅ SAFE"
        
        summary_data = [
            [Paragraph("<b>URL:</b>", normal_style), Paragraph(url, normal_style)],
            [Paragraph("<b>Scan Date:</b>", normal_style), Paragraph(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), normal_style)],
            [Paragraph("<b>Risk Score:</b>", normal_style), Paragraph(f"{risk}%", normal_style)],
            [Paragraph("<b>Verdict:</b>", normal_style), Paragraph(verdict_text, normal_style)]
        ]
        summary_table = Table(summary_data, colWidths=[3*cm, 10*cm])
        summary_table.setStyle(TableStyle([
            ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f8fafc")),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.8*cm))
        
        screenshot_url = scan_data.get('screenshot')
        if screenshot_url:
            try:
                img_data = requests.get(screenshot_url, timeout=5).content
                img = Image(BytesIO(img_data), width=12*cm, height=8*cm)
                story.append(Paragraph("<b>Screenshot:</b>", heading_style))
                story.append(img)
                story.append(Spacer(1, 0.5*cm))
            except:
                pass
        
        preview = scan_data.get('link_preview')
        if preview:
            story.append(Paragraph("<b>Link Preview:</b>", heading_style))
            preview_data = [
                [Paragraph("<b>Title:</b>", normal_style), Paragraph(preview.get('title', 'N/A'), normal_style)],
                [Paragraph("<b>Description:</b>", normal_style), Paragraph(preview.get('description', 'N/A'), normal_style)],
            ]
            preview_table = Table(preview_data, colWidths=[3*cm, 10*cm])
            preview_table.setStyle(TableStyle([('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f8fafc")), ('GRID', (0,0), (-1,-1), 0.5, colors.grey)]))
            story.append(preview_table)
            story.append(Spacer(1, 0.5*cm))
        
        reasons = scan_data.get('reasons', [])
        if reasons:
            story.append(Paragraph("<b>Threat Vectors Identified:</b>", heading_style))
            for r in reasons[:10]:
                story.append(Paragraph(f"• {r}", normal_style))
            story.append(Spacer(1, 0.5*cm))
        
        info_notes = scan_data.get('info_notes', [])
        if info_notes:
            story.append(Paragraph("<b>Intelligence Notes:</b>", heading_style))
            for n in info_notes[:10]:
                story.append(Paragraph(f"• {n}", normal_style))
            story.append(Spacer(1, 0.5*cm))
        
        whois = scan_data.get('whois', {})
        if whois.get('age_days') is not None:
            story.append(Paragraph("<b>WHOIS Domain Analysis:</b>", heading_style))
            whois_data = [
                ["Registrar", whois.get('registrar', 'N/A')],
                ["Registered On", whois.get('registered', 'N/A')],
                ["Domain Age (Days)", str(whois.get('age_days', 'N/A'))],
                ["Is New Domain?", "Yes" if whois.get('is_new') else "No"],
            ]
            whois_table = Table(whois_data, colWidths=[4*cm, 8*cm])
            whois_table.setStyle(TableStyle([('BACKGROUND', (0,0), (0,-1), colors.HexColor("#e2e8f0")), ('GRID', (0,0), (-1,-1), 0.5, colors.grey)]))
            story.append(whois_table)
            story.append(Spacer(1, 0.5*cm))
        
        ssl = scan_data.get('ssl', {})
        if ssl:
            story.append(Paragraph("<b>SSL/TLS Certificate:</b>", heading_style))
            ssl_data = [
                ["SSL Present", "Yes" if ssl.get('has_ssl') else "No"],
                ["Valid", "Yes" if ssl.get('valid') else "No"],
                ["Issuer", ssl.get('issuer', 'N/A')],
                ["Expiry Date", ssl.get('expiry', 'N/A')],
                ["Days Left", str(ssl.get('days_left', 'N/A'))],
                ["Grade", ssl.get('grade', 'N/A')],
            ]
            ssl_table = Table(ssl_data, colWidths=[4*cm, 8*cm])
            ssl_table.setStyle(TableStyle([('BACKGROUND', (0,0), (0,-1), colors.HexColor("#e2e8f0")), ('GRID', (0,0), (-1,-1), 0.5, colors.grey)]))
            story.append(ssl_table)
            story.append(Spacer(1, 0.5*cm))
        
        dns = scan_data.get('dns', {})
        if dns.get('ip'):
            story.append(Paragraph("<b>DNS Intelligence:</b>", heading_style))
            dns_data = [
                ["Primary IP", dns.get('ip', 'N/A')],
                ["Country", dns.get('country', 'N/A')],
                ["City", dns.get('city', 'N/A')],
                ["Organization", dns.get('org', 'N/A')],
                ["ASN", dns.get('asn', 'N/A')],
                ["DNSSEC", "Enabled" if dns.get('dns_sec') else "Disabled"],
            ]
            dns_table = Table(dns_data, colWidths=[4*cm, 8*cm])
            dns_table.setStyle(TableStyle([('BACKGROUND', (0,0), (0,-1), colors.HexColor("#e2e8f0")), ('GRID', (0,0), (-1,-1), 0.5, colors.grey)]))
            story.append(dns_table)
            story.append(Spacer(1, 0.5*cm))
        
        vt = scan_data.get('vt')
        if vt:
            story.append(Paragraph("<b>VirusTotal Detection Distribution:</b>", heading_style))
            drawing = Drawing(400, 200)
            pie = Pie()
            pie.x = 150
            pie.y = 50
            pie.width = 100
            pie.height = 100
            pie.data = [vt.get('malicious',0), vt.get('suspicious',0), vt.get('clean',0)]
            pie.labels = ['Malicious', 'Suspicious', 'Clean']
            pie.slices[0].fillColor = colors.red
            pie.slices[1].fillColor = colors.orange
            pie.slices[2].fillColor = colors.green
            drawing.add(pie)
            legend = Legend()
            legend.alignment = 'right'
            legend.x = 280
            legend.y = 70
            legend.colorNamePairs = [(colors.red, 'Malicious'), (colors.orange, 'Suspicious'), (colors.green, 'Clean')]
            drawing.add(legend)
            story.append(drawing)
            story.append(Spacer(1, 0.5*cm))
        
        ai = scan_data.get('ai')
        if ai:
            story.append(Paragraph("<b>AI Threat Analysis:</b>", heading_style))
            ai_data = [
                ["Verdict", ai.get('verdict', 'N/A')],
                ["Confidence", f"{ai.get('confidence', 0)}%"],
                ["Attack Type", ai.get('attack_type', 'N/A')],
            ]
            ai_table = Table(ai_data, colWidths=[4*cm, 8*cm])
            ai_table.setStyle(TableStyle([('BACKGROUND', (0,0), (0,-1), colors.HexColor("#e2e8f0")), ('GRID', (0,0), (-1,-1), 0.5, colors.grey)]))
            story.append(ai_table)
            summary_ar = ai.get('summary_ar')
            if summary_ar:
                story.append(Paragraph(f"<i>{summary_ar}</i>", normal_style))
            recommendation_ar = ai.get('recommendation_ar')
            if recommendation_ar:
                story.append(Paragraph(f"<b>Recommendation:</b> {recommendation_ar}", normal_style))
        
        doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
        buf.seek(0)
        return buf
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        return None

# ═══════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    try:
        auth_res = supabase.auth.sign_up({"email": email, "password": password})
        user = auth_res.user
        if not user:
            return jsonify({"error": "Signup failed"}), 400
        supabase.table("users").insert({
            "id": user.id,
            "email": email,
            "plan": "free",
            "scans_used_today": 0,
            "quota_reset_date": datetime.now(timezone.utc).date().isoformat()
        }).execute()
        access_token = create_access_token(identity=user.id)
        return jsonify({"access_token": access_token, "user": {"id": user.id, "email": email}})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    try:
        auth_res = supabase.auth.sign_in_with_password({"email": email, "password": password})
        user = auth_res.user
        if not user:
            return jsonify({"error": "Invalid credentials"}), 401
        access_token = create_access_token(identity=user.id)
        return jsonify({"access_token": access_token, "user": {"id": user.id, "email": email}})
    except Exception as e:
        return jsonify({"error": str(e)}), 401

@app.route('/me', methods=['GET'])
@jwt_required()
def me():
    user_id = get_jwt_identity()
    email = None
    try:
        auth_user = supabase.auth.admin.get_user_by_id(user_id)
        if auth_user and auth_user.user:
            email = auth_user.user.email
    except:
        pass
    ensure_user_exists(user_id, email)
    user = get_current_user()
    if not user:
        return jsonify({"error": "User not found"}), 404
    plan, used, limit, remaining = get_user_quota(user)
    return jsonify({
        "id": user["id"],
        "email": user.get("email") or email,
        "plan": plan,
        "scans_used_today": used,
        "daily_limit": limit,
        "remaining_scans_today": remaining
    })

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login-page')
def login_page():
    return render_template('login.html')

@app.route('/signup-page')
def signup_page():
    return render_template('signup.html')

@app.route('/dashboard')
@jwt_required()
def dashboard():
    return render_template('index.html')

@app.route('/stats')
def get_stats():
    if not supabase:
        return jsonify({"total_scanned": 0, "threats_detected": 0})
    try:
        res = supabase.table("stats").select("*").eq("id", 1).single().execute()
        return jsonify(res.data)
    except:
        return jsonify({"total_scanned": 0, "threats_detected": 0})

@app.route('/user/stats', methods=['GET'])
@jwt_required()
def user_stats():
    user = get_current_user()
    if not user:
        return jsonify({"error": "User not found"}), 404
    stats = get_user_stats(user['id'])
    return jsonify(stats)

@app.route('/feed')
def threat_feed():
    return jsonify(get_threat_feed())

@app.route('/history', methods=['GET'])
@jwt_required()
def get_history():
    user = get_current_user()
    if not user:
        return jsonify([])
    try:
        res = supabase.table("scan_history").select("*").eq("user_id", user['id']).order("scanned_at", desc=True).limit(20).execute()
        return jsonify(res.data or [])
    except:
        return jsonify([])

@app.route('/bulk', methods=['POST'])
@jwt_required()
def bulk_scan():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401
    try:
        data = request.get_json()
        urls = data.get('urls', [])
        results = bulk_analyze(urls)
        return jsonify({"results": results, "total": len(results), "threats": sum(1 for r in results if r['verdict'] == 'THREAT'), "suspicious": sum(1 for r in results if r['verdict'] == 'SUSPICIOUS'), "safe": sum(1 for r in results if r['verdict'] == 'SAFE')})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/report', methods=['POST'])
@jwt_required()
def generate_report():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401
    try:
        scan_data = request.get_json()
        pdf_buf = generate_pdf_report(scan_data)
        if not pdf_buf:
            return jsonify({"error": "PDF generation failed"}), 500
        filename = f"SecuCode_Pro_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        return send_file(pdf_buf, mimetype='application/pdf', as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/analyze', methods=['POST'])
@jwt_required()
def analyze():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401

    reset_daily_quota_if_needed(user['id'])
    plan, used, limit, remaining = get_user_quota(user)
    if remaining <= 0:
        return jsonify({
            "error": "Daily scan limit reached. Please try again tomorrow.",
            "quota_exceeded": True,
            "plan": plan,
            "limit": limit,
            "used": used,
            "message_ar": f"لقد استنفدت حصتك اليومية ({limit} فحوصات). عاود المحاولة غداً.",
            "message_en": f"You've reached your daily limit ({limit} scans). Try again tomorrow."
        }), 429

    try:
        data = request.get_json()
        raw_url = data.get('link', '').strip()
        if not raw_url:
            return jsonify({"error": "No URL provided"}), 400

        url = raw_url if raw_url.startswith(('http://', 'https://')) else 'https://' + raw_url
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if not domain:
            return jsonify({"error": "Could not parse domain"}), 400

        resolved_url, was_shortened = resolve_shortened_url(url)
        if was_shortened:
            domain = urlparse(resolved_url).netloc.lower()
        clean_domain = domain[4:] if domain.startswith('www.') else domain

        cached = get_cached_reputation(resolved_url)
        if cached:
            last_scanned = cached.get('last_scanned')
            if last_scanned:
                try:
                    last_date = datetime.fromisoformat(last_scanned.replace('Z', '+00:00'))
                    if (datetime.now(timezone.utc) - last_date).days < 7:
                        return jsonify({
                            "risk_score": cached['risk_score'],
                            "is_threat": cached['is_threat'],
                            "reasons": cached['reasons'] or [],
                            "info_notes": cached['info_notes'] or [],
                            "url": resolved_url,
                            "original_url": url if was_shortened else None,
                            "was_shortened": was_shortened,
                            "cached": True,
                            "quota": {"plan": plan, "used": used, "limit": limit, "remaining": remaining}
                        })
                except:
                    pass

        ssl_info = check_ssl(clean_domain)
        whois_info = check_whois(clean_domain)
        dns_data = get_dns_intel(clean_domain)
        ip_trace = trace_real_ip(clean_domain)
        google_safe = check_google_safe(resolved_url)
        vt_report = get_vt_report(resolved_url)
        ip_rep = check_ip_reputation(dns_data.get("ip")) if dns_data.get("ip") else {"risk": "Unknown"}

        # --- NEW: Call PhishTank & GreyNoise ---
        phishtank_result = check_phishtank(resolved_url)
        greynoise_result = check_greynoise(dns_data.get("ip")) if dns_data.get("ip") else None

        risk_score, reasons, info_notes = analyze_logic(
            resolved_url, domain, vt_report, ssl_info, whois_info, ip_rep,
            google_safe, phishtank_result, greynoise_result
        )
        is_threat = risk_score >= 60

        ai_result = None
        try:
            ai_result = ai_analyze(resolved_url, clean_domain, risk_score, reasons, dns_data, vt_report, ssl_info)
            if ai_result and ai_result.get("ai_risk_adjustment"):
                risk_score = max(0, min(100, risk_score + ai_result["ai_risk_adjustment"]))
                is_threat = risk_score >= 60
        except:
            pass

        vt_detail = None
        if vt_report:
            s = vt_report.get("stats", {})
            vt_detail = {"malicious": s.get("malicious", 0), "suspicious": s.get("suspicious", 0), "clean": s.get("harmless", 0) + s.get("undetected", 0), "total": sum(s.values()), "reputation": vt_report.get("reputation", 0), "engines": vt_report.get("engines", {})}

        link_preview_data = fetch_link_preview(resolved_url)
        screenshot_url = get_urlscan_screenshot(resolved_url) if URLSCAN_API_KEY else None

        verdict = "THREAT" if is_threat else "SAFE" if risk_score < 25 else "SUSPICIOUS"
        update_cached_reputation(resolved_url, risk_score, is_threat, verdict, reasons, info_notes)

        if supabase:
            try:
                supabase.table("scan_history").insert({
                    "user_id": user['id'],
                    "url": resolved_url[:500],
                    "domain": clean_domain[:200],
                    "risk_score": risk_score,
                    "is_threat": is_threat,
                    "reason": reasons[0][:300] if reasons else "Clean",
                    "country": dns_data.get("country", ""),
                    "scanned_at": datetime.now(timezone.utc).isoformat()
                }).execute()
            except:
                pass

        increment_stats_safely(is_threat)
        increment_user_quota(user['id'])

        updated_user = get_current_user()
        _, used_new, limit_new, remaining_new = get_user_quota(updated_user)

        return jsonify({
            "risk_score": risk_score,
            "is_threat": is_threat,
            "reasons": reasons,
            "info_notes": info_notes,
            "url": resolved_url,
            "original_url": url if was_shortened else None,
            "was_shortened": was_shortened,
            "server": {"ip": dns_data.get("ip", ""), "country": dns_data.get("country", ""), "city": dns_data.get("city", ""), "org": dns_data.get("org", ""), "asn": dns_data.get("asn", "")},
            "dns": dns_data,
            "ip_trace": ip_trace,
            "google_safe": google_safe,
            "vt": vt_detail,
            "ssl": ssl_info,
            "whois": whois_info,
            "ip_rep": ip_rep,
            "ai": ai_result,
            "phishtank": phishtank_result,
            "greynoise": greynoise_result,
            "link_preview": link_preview_data,
            "screenshot": screenshot_url,
            "quota": {"plan": plan, "used": used_new, "limit": limit_new, "remaining": remaining_new}
        })

    except Exception as e:
        logger.error(f"Analysis critical error: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.route('/user/subscription-status', methods=['GET'])
@jwt_required()
def subscription_status():
    user = get_current_user()
    if not user:
        return jsonify({"error": "User not found"}), 404
    features = ["basic_scan", "pdf_report", "ai_analysis", "bulk_scan", "link_preview", "screenshot"]
    return jsonify({
        "plan": "free",
        "features": features,
        "has_pdf": True,
        "has_bulk": True,
        "has_ai": True,
        "has_preview": True,
        "has_screenshot": True
    })

@app.route('/preview', methods=['POST'])
@jwt_required()
def link_preview():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({"error": "URL required"}), 400
    preview = fetch_link_preview(url)
    if not preview:
        return jsonify({"error": "Could not fetch preview"}), 404
    return jsonify(preview)

with app.app_context():
    ensure_stats_table()

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)
