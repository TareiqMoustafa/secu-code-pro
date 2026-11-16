"""
SecuCode Pro - Multi-Source Threat Intelligence Engine
Professional URL Analysis Engine with Graceful Degradation
Developers: Tarek Mostafa, Mazen Amro
"""

import os
import re
import base64
import hashlib
import socket
import concurrent.futures
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ─────────────────────────────────────────────
# Configuration from Environment Variables
# ─────────────────────────────────────────────
VT_API_KEY = os.getenv("VT_API_KEY", "").strip()
GSB_API_KEY = os.getenv("GSB_API_KEY", "").strip()
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "").strip()
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY", "").strip()  # Optional now
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

# Timeouts
REQUEST_TIMEOUT = 8
VT_TIMEOUT = 12

# Trusted domains (partial match)
WHITELIST_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "youtube.com",
    "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.com",
    "microsoft.com", "office.com", "live.com", "microsoftonline.com",
    "apple.com", "icloud.com", "github.com", "githubusercontent.com",
    "twitter.com", "x.com", "twimg.com", "linkedin.com",
    "amazon.com", "amazonaws.com", "cloudflare.com", "akamai.net",
    "wikipedia.org", "wikimedia.org", "reddit.com", "stackoverflow.com",
    "npmjs.com", "pypi.org", "vercel.app", "netlify.app",
}


def _normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except Exception:
        return ""


def _is_whitelisted(domain: str) -> bool:
    if not domain:
        return False
    # Dynamic whitelist first
    try:
        from utils.storage import is_whitelisted as dyn_whitelist
        if dyn_whitelist(domain):
            return True
    except Exception:
        pass
    for trusted in WHITELIST_DOMAINS:
        if domain == trusted or domain.endswith("." + trusted):
            return True
    return False


def _check_blacklist(domain: str) -> Optional[str]:
    try:
        from utils.storage import is_blacklisted
        return is_blacklisted(domain)
    except Exception:
        return None


def _resolve_ip(domain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


# ─────────────────────────────────────────────
# Individual Source Checkers
# ─────────────────────────────────────────────

def check_virustotal(url: str) -> Dict[str, Any]:
    """VirusTotal v3 - URL report (fast path using ID)"""
    result = {
        "source": "VirusTotal",
        "status": "unavailable",
        "score": 0,
        "details": {},
        "error": None,
    }
    if not VT_API_KEY:
        result["error"] = "API key not configured"
        return result

    try:
        # Fast path: get existing report by URL ID
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=VT_TIMEOUT,
        )

        if resp.status_code == 404:
            # Submit for analysis
            resp = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=VT_TIMEOUT,
            )
            if resp.status_code in (200, 201):
                analysis_id = resp.json().get("data", {}).get("id")
                result["status"] = "submitted"
                result["details"] = {"analysis_id": analysis_id, "note": "Scan submitted, results pending"}
                result["score"] = 15  # mild pending score
                return result
            else:
                result["error"] = f"Submit failed: {resp.status_code}"
                return result

        if resp.status_code != 200:
            result["error"] = f"HTTP {resp.status_code}"
            return result

        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1

        # Score: weight malicious heavily
        score = min(100, int((malicious * 12 + suspicious * 5) / max(1, total / 10)))
        if malicious >= 5:
            score = max(score, 85)
        elif malicious >= 2:
            score = max(score, 60)
        elif malicious >= 1:
            score = max(score, 40)

        result["status"] = "ok"
        result["score"] = score
        result["details"] = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": data.get("reputation", 0),
            "categories": data.get("categories", {}),
            "last_analysis_date": data.get("last_analysis_date"),
        }
    except Exception as e:
        result["error"] = str(e)[:120]
    return result


def check_google_safe_browsing(url: str) -> Dict[str, Any]:
    """Google Safe Browsing Lookup API v4"""
    result = {
        "source": "Google Safe Browsing",
        "status": "unavailable",
        "score": 0,
        "details": {},
        "error": None,
    }
    if not GSB_API_KEY:
        result["error"] = "API key not configured"
        return result

    try:
        payload = {
            "client": {"clientId": "secucode-pro", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION", "THREAT_TYPE_UNSPECIFIED"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        resp = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}",
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            result["error"] = f"HTTP {resp.status_code}"
            return result

        data = resp.json()
        matches = data.get("matches", [])
        if matches:
            threat_types = list({m.get("threatType") for m in matches})
            result["status"] = "threat_found"
            result["score"] = 95
            result["details"] = {
                "matches": len(matches),
                "threat_types": threat_types,
                "platform": matches[0].get("platformType"),
            }
        else:
            result["status"] = "clean"
            result["score"] = 0
            result["details"] = {"matches": 0}
    except Exception as e:
        result["error"] = str(e)[:120]
    return result


def check_urlhaus(url: str) -> Dict[str, Any]:
    """URLhaus (abuse.ch) - Malware URL database"""
    result = {
        "source": "URLhaus",
        "status": "unavailable",
        "score": 0,
        "details": {},
        "error": None,
    }
    try:
        headers = {}
        if URLHAUS_AUTH_KEY:
            headers["Auth-Key"] = URLHAUS_AUTH_KEY

        # Primary: query by URL
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            # Fallback to host query
            domain = _extract_domain(url)
            resp = requests.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": domain},
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )

        data = resp.json() if resp.content else {}
        query_status = data.get("query_status", "")

        if query_status == "ok" or data.get("url_status") or data.get("urls"):
            threat = data.get("threat") or "malware"
            tags = data.get("tags") or []
            blacklists = data.get("blacklists") or {}
            result["status"] = "threat_found"
            result["score"] = 90
            result["details"] = {
                "threat": threat,
                "tags": tags[:8],
                "url_status": data.get("url_status"),
                "blacklists": blacklists,
                "date_added": data.get("date_added"),
            }
        elif query_status in ("no_results", "no_such_host"):
            result["status"] = "clean"
            result["score"] = 0
            result["details"] = {"query_status": query_status}
        else:
            result["status"] = "unknown"
            result["details"] = {"query_status": query_status}
    except Exception as e:
        result["error"] = str(e)[:120]
    return result


def check_abuseipdb(ip: str) -> Dict[str, Any]:
    """AbuseIPDB - IP reputation"""
    result = {
        "source": "AbuseIPDB",
        "status": "unavailable",
        "score": 0,
        "details": {},
        "error": None,
    }
    if not ABUSEIPDB_KEY or not ip:
        result["error"] = "API key or IP missing"
        return result

    try:
        headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params=params,
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 200:
            result["error"] = f"HTTP {resp.status_code}"
            return result

        data = resp.json().get("data", {})
        conf = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)

        score = min(100, conf)
        if conf >= 80:
            score = max(score, 85)
        elif conf >= 50:
            score = max(score, 55)
        elif conf >= 25:
            score = max(score, 30)

        result["status"] = "ok"
        result["score"] = score
        result["details"] = {
            "abuse_confidence": conf,
            "total_reports": total_reports,
            "is_whitelisted": data.get("isWhitelisted", False),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "last_reported": data.get("lastReportedAt"),
        }
    except Exception as e:
        result["error"] = str(e)[:120]
    return result


def check_behavioral(url: str) -> Dict[str, Any]:
    """Behavioral / content analysis of the page"""
    result = {
        "source": "Behavioral Analysis",
        "status": "unavailable",
        "score": 0,
        "details": {},
        "error": None,
    }
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; SecuCodePro/2.0; +https://secucode.pro)",
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,ar;q=0.9",
        }
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, verify=False, headers=headers, allow_redirects=True)
        final_url = resp.url
        html = resp.text[:150000]  # limit size

        findings = []
        score = 0

        # Privacy invasive APIs
        if re.search(r"getUserMedia|navigator\.mediaDevices|camera|microphone|webkitGetUserMedia", html, re.I):
            findings.append("Requests camera/microphone access")
            score += 45

        # Excessive scripts
        script_count = len(re.findall(r"<script", html, re.I))
        if script_count > 80:
            findings.append(f"Excessive scripts ({script_count})")
            score += 25
        elif script_count > 40:
            findings.append(f"High script count ({script_count})")
            score += 10

        # Suspicious patterns
        if re.search(r"eval\s*\(|document\.write\s*\(|fromCharCode|atob\s*\(", html, re.I):
            findings.append("Obfuscated / eval usage detected")
            score += 30

        # Phishing indicators
        phishing_keywords = [
            r"verify.?account", r"confirm.?identity", r"update.?payment",
            r"suspended.?account", r"unusual.?activity", r"login.?now",
            r"password.?expired", r"security.?alert", r"claim.?prize",
        ]
        for kw in phishing_keywords:
            if re.search(kw, html, re.I):
                findings.append("Possible phishing language")
                score += 20
                break

        # Form action to external / data: URLs
        if re.search(r'<form[^>]+action=["\']?(https?:)?//(?!.*' + re.escape(_extract_domain(url)) + r')', html, re.I):
            findings.append("Form posts to external domain")
            score += 25

        # Meta refresh / JS redirect
        if re.search(r'<meta[^>]+http-equiv=["\']?refresh', html, re.I) or "window.location" in html.lower():
            findings.append("Automatic redirects present")
            score += 10

        # Mixed content or insecure
        if final_url.startswith("http://") and not final_url.startswith("https://"):
            findings.append("Served over HTTP (insecure)")
            score += 15

        score = min(100, score)
        result["status"] = "ok"
        result["score"] = score
        result["details"] = {
            "findings": findings,
            "script_count": script_count,
            "final_url": final_url,
            "status_code": resp.status_code,
            "content_type": resp.headers.get("Content-Type", "")[:60],
        }
    except requests.exceptions.Timeout:
        result["error"] = "Timeout"
        result["score"] = 20
        result["status"] = "timeout"
    except Exception as e:
        result["error"] = str(e)[:100]
        result["score"] = 15
        result["status"] = "error"
    return result


def check_whois_age(domain: str) -> Dict[str, Any]:
    """Simple domain age heuristic via public RDAP / whois-like"""
    result = {
        "source": "Domain Age (RDAP)",
        "status": "unavailable",
        "score": 0,
        "details": {},
        "error": None,
    }
    if not domain:
        return result
    try:
        # Use a free RDAP endpoint
        resp = requests.get(
            f"https://rdap.org/domain/{domain}",
            timeout=REQUEST_TIMEOUT,
            headers={"Accept": "application/rdap+json"},
        )
        if resp.status_code != 200:
            # fallback
            resp = requests.get(
                f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={domain}&outputFormat=JSON",
                timeout=5,
            )
            # This may fail without key; we ignore

        if resp.status_code == 200 and "rdap.org" in str(resp.url):
            data = resp.json()
            events = data.get("events", [])
            created = None
            for ev in events:
                if ev.get("eventAction") in ("registration", "created"):
                    created = ev.get("eventDate")
                    break
            if created:
                try:
                    # rough age calculation
                    created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                    age_days = (datetime.now(created_dt.tzinfo) - created_dt).days
                    result["details"]["age_days"] = age_days
                    result["details"]["created"] = created[:10]
                    if age_days < 7:
                        result["score"] = 70
                        result["status"] = "very_new"
                    elif age_days < 30:
                        result["score"] = 45
                        result["status"] = "new"
                    elif age_days < 90:
                        result["score"] = 20
                        result["status"] = "recent"
                    else:
                        result["score"] = 0
                        result["status"] = "established"
                except Exception:
                    result["status"] = "parsed"
            else:
                result["status"] = "no_date"
        else:
            result["status"] = "unavailable"
            result["error"] = "RDAP unavailable"
    except Exception as e:
        result["error"] = str(e)[:80]
    return result



def check_ssl(url: str, domain: str) -> Dict[str, Any]:
    """SSL/TLS certificate analysis"""
    result = {
        "source": "SSL/TLS Analysis",
        "status": "unavailable",
        "score": 0,
        "details": {},
        "error": None,
    }
    try:
        import ssl
        import socket
        from datetime import datetime
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                not_after = cert.get("notAfter")
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                subject = dict(x[0] for x in cert.get("subject", ()))
                days_left = None
                if not_after:
                    try:
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        days_left = (exp - datetime.utcnow()).days
                    except Exception:
                        pass
                score = 0
                findings = []
                if days_left is not None:
                    if days_left < 0:
                        score = 70
                        findings.append("Certificate expired")
                    elif days_left < 14:
                        score = 35
                        findings.append(f"Expires in {days_left} days")
                result["status"] = "ok"
                result["score"] = score
                result["details"] = {
                    "issuer": issuer.get("organizationName") or issuer.get("commonName"),
                    "subject": subject.get("commonName"),
                    "expires": not_after,
                    "days_left": days_left,
                    "findings": findings,
                    "version": ssock.version(),
                }
    except ssl.SSLCertVerificationError as e:
        result["status"] = "invalid_cert"
        result["score"] = 55
        result["details"] = {"findings": ["Certificate verification failed"], "error": str(e)[:100]}
    except Exception as e:
        result["error"] = str(e)[:100]
        result["score"] = 10
    return result


# ─────────────────────────────────────────────
# Main Orchestrator
# ─────────────────────────────────────────────

def analyze_url(url: str) -> Dict[str, Any]:
    """
    Full multi-source analysis with parallel execution and risk aggregation.
    Returns a structured professional report.
    """
    url = _normalize_url(url)
    if not url or len(url) < 8:
        return {
            "success": False,
            "error": "Invalid or empty URL",
            "risk_score": 0,
            "risk_level": "unknown",
        }

    domain = _extract_domain(url)
    ip = _resolve_ip(domain)

    # Early blacklist (highest priority)
    bl_reason = _check_blacklist(domain)
    if bl_reason:
        return {
            "success": True,
            "url": url,
            "domain": domain,
            "ip": ip,
            "risk_score": 100,
            "points": 100,
            "risk_level": "critical",
            "risk_label": "Blacklisted",
            "violation_key": "BLACKLISTED",
            "summary": f"This domain is on the internal blacklist. Reason: {bl_reason}",
            "sources": [
                {"source": "Blacklist", "status": "threat_found", "score": 100, "details": {"reason": bl_reason}}
            ],
            "screenshot": f"https://s0.wp.com/mshots/v1/{url}?w=900&h=600",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "engine": "SecuCode-Pro-MultiSource-v2.4",
        }


    # Live threat feeds (OpenPhish / URLhaus / PhishingArmy)
    try:
        from utils.threat_feeds import check_domain as feed_check_domain, refresh_feeds
        # soft refresh in background style (fast if cached)
        refresh_feeds(force=False)
        feed_hit = feed_check_domain(domain)
        if feed_hit:
            threat = feed_hit.get("threat_type") or "malicious"
            src = feed_hit.get("source") or "ThreatFeed"
            return {
                "success": True,
                "url": url,
                "domain": domain,
                "ip": ip,
                "risk_score": 98,
                "points": 98,
                "risk_level": "critical",
                "risk_label": "Malicious Feed Match",
                "violation_key": "THREAT_FEED",
                "summary": f"Domain found in live threat intelligence feed ({src}). Type: {threat}.",
                "sources": [
                    {
                        "source": f"Live Feed · {src}",
                        "status": "threat_found",
                        "score": 98,
                        "details": feed_hit,
                    }
                ],
                "screenshot": f"https://s0.wp.com/mshots/v1/{url}?w=900&h=600",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "engine": "SecuCode-Pro-MultiSource-v2.4",
            }
    except Exception:
        pass

    # Early whitelist
    if _is_whitelisted(domain):
        return {
            "success": True,
            "url": url,
            "domain": domain,
            "ip": ip,
            "risk_score": 0,
            "points": 0,
            "risk_level": "safe",
            "risk_label": "Trusted",
            "violation_key": "TRUSTED",
            "summary": "Domain is on the trusted whitelist (major legitimate services).",
            "sources": [
                {"source": "Whitelist", "status": "trusted", "score": 0, "details": {"matched": True}}
            ],
            "screenshot": f"https://s0.wp.com/mshots/v1/{url}?w=900&h=600",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "engine": "SecuCode-Pro-MultiSource-v2.4",
        }

    # Parallel execution of all sources
    sources_results: List[Dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = {
            executor.submit(check_virustotal, url): "vt",
            executor.submit(check_google_safe_browsing, url): "gsb",
            executor.submit(check_urlhaus, url): "urlhaus",
            executor.submit(check_behavioral, url): "behavioral",
            executor.submit(check_whois_age, domain): "whois",
            executor.submit(check_ssl, url, domain): "ssl",
        }
        if ip:
            futures[executor.submit(check_abuseipdb, ip)] = "abuseipdb"

        for future in concurrent.futures.as_completed(futures, timeout=25):
            try:
                res = future.result()
                sources_results.append(res)
            except Exception as e:
                sources_results.append({
                    "source": futures.get(future, "unknown"),
                    "status": "error",
                    "score": 0,
                    "error": str(e)[:80],
                })

    # Aggregate score (weighted)
    weights = {
        "VirusTotal": 1.4,
        "Google Safe Browsing": 1.6,
        "URLhaus": 1.5,
        "AbuseIPDB": 1.1,
        "Behavioral Analysis": 0.9,
        "Domain Age (RDAP)": 0.7,
        "SSL/TLS Analysis": 0.8,
    }

    total_weight = 0.0
    weighted_score = 0.0
    available_sources = 0
    high_confidence_threat = False

    for s in sources_results:
        src = s.get("source", "")
        sc = s.get("score", 0) or 0
        w = weights.get(src, 1.0)
        if s.get("status") not in ("unavailable", "error") and not s.get("error"):
            available_sources += 1
            weighted_score += sc * w
            total_weight += w
            if sc >= 85 and src in ("Google Safe Browsing", "URLhaus", "VirusTotal"):
                high_confidence_threat = True

    if total_weight > 0:
        final_score = int(min(100, weighted_score / total_weight))
    else:
        final_score = 25  # unknown / all failed

    if high_confidence_threat:
        final_score = max(final_score, 88)

    # Risk level
    if final_score >= 75:
        risk_level = "critical"
        risk_label = "Critical / Malicious"
        violation_key = "MALICIOUS"
    elif final_score >= 45:
        risk_level = "suspicious"
        risk_label = "Suspicious"
        violation_key = "SUSPICIOUS"
    elif final_score >= 20:
        risk_level = "low"
        risk_label = "Low Risk"
        violation_key = "LOW"
    else:
        risk_level = "safe"
        risk_label = "Safe"
        violation_key = "CLEAN"

    # Build human summary
    threat_sources = [s["source"] for s in sources_results if (s.get("score") or 0) >= 50]
    if threat_sources:
        summary = f"Threat signals detected from: {', '.join(threat_sources)}. Review carefully."
    elif available_sources >= 3:
        summary = "No significant threats detected across multiple intelligence sources."
    else:
        summary = "Limited data available. Some sources were unavailable."

    # Telegram notification (non-blocking)
    if TELEGRAM_TOKEN and TELEGRAM_CHAT_ID and final_score >= 40:
        try:
            msg = (
                f"🛡️ <b>SecuCode Pro Scan</b>\n"
                f"🔗 <code>{domain}</code>\n"
                f"📊 Risk: <b>{final_score}%</b> ({risk_label})\n"
                f"🔑 Key: {violation_key}\n"
                f"📡 Sources: {available_sources}"
            )
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
                json={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "HTML"},
                timeout=2,
            )
        except Exception:
            pass

    return {
        "success": True,
        "url": url,
        "domain": domain,
        "ip": ip,
        "risk_score": final_score,
        "risk_level": risk_level,
        "risk_label": risk_label,
        "violation_key": violation_key,
        "summary": summary,
        "sources": sources_results,
        "available_sources": available_sources,
        "screenshot": f"https://s0.wp.com/mshots/v1/{url}?w=900&h=600",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "engine": "SecuCode-Pro-MultiSource-v2.4",
    }
