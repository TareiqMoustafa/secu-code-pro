"""
Live Threat Intelligence Feeds
Fetches and caches urgent malicious URL/domain lists from public sources.
Updated on demand with TTL cache to respect rate limits.
"""

import os
import time
import threading
from typing import Dict, Optional, Set, Tuple
from urllib.parse import urlparse

import requests

_lock = threading.Lock()
_CACHE_TTL = int(os.getenv("THREAT_FEED_TTL", "1800"))  # 30 minutes

# domain -> {source, threat_type, first_seen}
_malicious_domains: Dict[str, dict] = {}
_malicious_urls: Dict[str, dict] = {}
_last_refresh = 0.0
_refreshing = False


def _norm_domain(host: str) -> str:
    host = (host or "").lower().strip()
    if host.startswith("www."):
        host = host[4:]
    return host


def _extract_host(url: str) -> str:
    try:
        if "://" not in url:
            url = "http://" + url
        return _norm_domain(urlparse(url).netloc)
    except Exception:
        return ""


def _fetch_openphish() -> int:
    """OpenPhish community feed - phishing URLs, free, no key."""
    count = 0
    try:
        resp = requests.get("https://openphish.com/feed.txt", timeout=12)
        if resp.status_code != 200:
            return 0
        for line in resp.text.splitlines():
            url = line.strip()
            if not url or url.startswith("#"):
                continue
            host = _extract_host(url)
            if not host:
                continue
            _malicious_domains[host] = {
                "source": "OpenPhish",
                "threat_type": "phishing",
                "url": url[:200],
            }
            _malicious_urls[url.lower()[:300]] = {
                "source": "OpenPhish",
                "threat_type": "phishing",
            }
            count += 1
    except Exception as e:
        print(f"[feeds] OpenPhish error: {e}")
    return count


def _fetch_urlhaus_recent() -> int:
    """URLhaus recent malicious URLs."""
    count = 0
    try:
        headers = {}
        key = os.getenv("URLHAUS_AUTH_KEY", "").strip()
        if key:
            headers["Auth-Key"] = key
        resp = requests.get(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/",
            headers=headers,
            timeout=15,
        )
        if resp.status_code != 200:
            return 0
        data = resp.json()
        urls = data.get("urls") or []
        for item in urls:
            url = (item.get("url") or "").strip()
            host = _norm_domain(item.get("host") or _extract_host(url))
            threat = item.get("threat") or "malware"
            if host:
                _malicious_domains[host] = {
                    "source": "URLhaus",
                    "threat_type": threat,
                    "url": url[:200],
                    "tags": item.get("tags") or [],
                }
                count += 1
            if url:
                _malicious_urls[url.lower()[:300]] = {
                    "source": "URLhaus",
                    "threat_type": threat,
                }
    except Exception as e:
        print(f"[feeds] URLhaus recent error: {e}")
    return count


def _fetch_phishing_army() -> int:
    """Phishing Army blocklist - domains only."""
    count = 0
    try:
        resp = requests.get(
            "https://phishing.army/download/phishing_army_blocklist_extended.txt",
            timeout=15,
        )
        if resp.status_code != 200:
            return 0
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            host = _norm_domain(line)
            if host and "." in host:
                # don't overwrite higher-confidence sources
                if host not in _malicious_domains:
                    _malicious_domains[host] = {
                        "source": "PhishingArmy",
                        "threat_type": "phishing",
                    }
                    count += 1
    except Exception as e:
        print(f"[feeds] PhishingArmy error: {e}")
    return count


def refresh_feeds(force: bool = False) -> dict:
    """Refresh all threat feeds. Thread-safe with TTL."""
    global _last_refresh, _refreshing
    now = time.time()
    with _lock:
        if not force and (now - _last_refresh) < _CACHE_TTL and _malicious_domains:
            return {
                "cached": True,
                "domains": len(_malicious_domains),
                "urls": len(_malicious_urls),
                "age_sec": int(now - _last_refresh),
            }
        if _refreshing:
            return {"refreshing": True, "domains": len(_malicious_domains)}
        _refreshing = True

    try:
        c1 = _fetch_openphish()
        c2 = _fetch_urlhaus_recent()
        c3 = _fetch_phishing_army()
        with _lock:
            _last_refresh = time.time()
        return {
            "cached": False,
            "openphish": c1,
            "urlhaus": c2,
            "phishing_army": c3,
            "domains": len(_malicious_domains),
            "urls": len(_malicious_urls),
        }
    finally:
        with _lock:
            _refreshing = False


def check_domain(domain: str) -> Optional[dict]:
    """Return threat info if domain is in live feeds."""
    domain = _norm_domain(domain)
    if not domain:
        return None
    # ensure feeds loaded at least once
    if not _malicious_domains and (time.time() - _last_refresh) > 5:
        try:
            refresh_feeds()
        except Exception:
            pass
    with _lock:
        info = _malicious_domains.get(domain)
        if info:
            return dict(info)
        # parent domain check (sub.evil.com -> evil.com)
        parts = domain.split(".")
        if len(parts) > 2:
            parent = ".".join(parts[-2:])
            info = _malicious_domains.get(parent)
            if info:
                return {**info, "matched_parent": parent}
    return None


def check_url(url: str) -> Optional[dict]:
    url_l = (url or "").lower().strip()
    with _lock:
        if url_l in _malicious_urls:
            return dict(_malicious_urls[url_l])
    return check_domain(_extract_host(url))


def feed_stats() -> dict:
    return {
        "domains": len(_malicious_domains),
        "urls": len(_malicious_urls),
        "last_refresh": _last_refresh,
        "ttl_sec": _CACHE_TTL,
        "age_sec": int(time.time() - _last_refresh) if _last_refresh else None,
    }
