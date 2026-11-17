"""
SecuCode Pro Storage Layer
- Primary: Supabase PostgreSQL (when DATABASE_URL or SUPABASE_DB_PASSWORD is set)
- Fallback: in-memory + /tmp file
"""

import os
import json
import hashlib
import time
import threading
from datetime import datetime
from typing import List, Dict, Any, Optional
from collections import deque
from urllib.parse import quote_plus

_lock = threading.Lock()
_MAX_HISTORY = 500

def _clean_env(v: str) -> str:
    v = (v or "").strip()
    if len(v) >= 2 and ((v[0] == v[-1] == '"') or (v[0] == v[-1] == "'")):
        v = v[1:-1].strip()
    return v

_DATABASE_URL = _clean_env(os.getenv("DATABASE_URL", ""))
_DB_PASSWORD = _clean_env(os.getenv("SUPABASE_DB_PASSWORD", ""))

if not _DATABASE_URL and _DB_PASSWORD:
    user = os.getenv("SUPABASE_DB_USER", "postgres.afhvwbrwxbtfkooxrbct")
    host = os.getenv("SUPABASE_DB_HOST", "aws-1-eu-west-3.pooler.supabase.com")
    port = os.getenv("SUPABASE_DB_PORT", "6543")
    dbname = os.getenv("SUPABASE_DB_NAME", "postgres")
    _DATABASE_URL = f"postgresql://{user}:{quote_plus(_DB_PASSWORD)}@{host}:{port}/{dbname}"

_USE_PG = bool(_DATABASE_URL)
_schema_ready = False

_history: deque = deque(maxlen=_MAX_HISTORY)
_HISTORY_FILE = os.getenv("HISTORY_FILE", "/tmp/secucode_history.json")
_lists_file = os.getenv("LISTS_FILE", "/tmp/secucode_lists.json")
_whitelist: set = set()
_blacklist: dict = {}


def _get_conn():
    if not _USE_PG:
        return None
    try:
        import psycopg2
        conn = psycopg2.connect(_DATABASE_URL, connect_timeout=8, sslmode="require")
        conn.autocommit = True
        return conn
    except Exception as e:
        print(f"[storage] Postgres connection failed: {e}")
        return None


def _ensure_schema():
    global _schema_ready
    if _schema_ready or not _USE_PG:
        return
    conn = _get_conn()
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id              BIGSERIAL PRIMARY KEY,
                report_id       TEXT UNIQUE NOT NULL,
                url             TEXT,
                domain          TEXT,
                ip              TEXT,
                risk_score      INTEGER DEFAULT 0,
                risk_level      TEXT,
                risk_label      TEXT,
                violation_key   TEXT,
                summary         TEXT,
                available_sources INTEGER DEFAULT 0,
                sources_count   INTEGER DEFAULT 0,
                engine          TEXT,
                sources_json    JSONB,
                created_at      TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
            CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_scans_report ON scans(report_id);

            CREATE TABLE IF NOT EXISTS whitelist (
                id          BIGSERIAL PRIMARY KEY,
                domain      TEXT UNIQUE NOT NULL,
                added_by    TEXT DEFAULT 'admin',
                created_at  TIMESTAMPTZ DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS blacklist (
                id          BIGSERIAL PRIMARY KEY,
                domain      TEXT UNIQUE NOT NULL,
                reason      TEXT DEFAULT 'Manual',
                created_at  TIMESTAMPTZ DEFAULT NOW()
            );

            CREATE TABLE IF NOT EXISTS community_reports (
                id          BIGSERIAL PRIMARY KEY,
                url         TEXT NOT NULL,
                domain      TEXT,
                reason      TEXT,
                details     TEXT,
                reporter    TEXT DEFAULT 'anonymous',
                status      TEXT DEFAULT 'pending',
                created_at  TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_reports_status ON community_reports(status);
            CREATE INDEX IF NOT EXISTS idx_reports_created ON community_reports(created_at DESC);
        """)
        cur.close()
        conn.close()
        _schema_ready = True
        print("[storage] Supabase schema ready")
    except Exception as e:
        print(f"[storage] Schema error: {e}")
        try:
            conn.close()
        except Exception:
            pass


def _load_from_file():
    global _history
    try:
        if os.path.exists(_HISTORY_FILE):
            with open(_HISTORY_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    _history = deque(data[-_MAX_HISTORY:], maxlen=_MAX_HISTORY)
    except Exception:
        pass


def _save_to_file():
    try:
        with open(_HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(list(_history), f, ensure_ascii=False)
    except Exception:
        pass


def _load_lists():
    global _whitelist, _blacklist
    try:
        if os.path.exists(_lists_file):
            with open(_lists_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                _whitelist = set(data.get("whitelist", []))
                _blacklist = data.get("blacklist", {})
    except Exception:
        pass


def _save_lists():
    try:
        with open(_lists_file, "w", encoding="utf-8") as f:
            json.dump({"whitelist": list(_whitelist), "blacklist": _blacklist}, f, ensure_ascii=False)
    except Exception:
        pass


_load_from_file()
_load_lists()


def add_scan(result: Dict[str, Any]) -> str:
    ts = result.get("timestamp") or datetime.utcnow().isoformat() + "Z"
    domain = result.get("domain") or ""
    raw_id = f"{domain}-{ts}-{time.time_ns()}"
    report_id = "SCR-" + hashlib.sha256(raw_id.encode()).hexdigest()[:12].upper()

    score = result.get("points")
    if score is None:
        score = result.get("risk_score", 0)
    if isinstance(score, str):
        score = 0

    entry = {
        "id": report_id,
        "report_id": report_id,
        "url": result.get("url"),
        "domain": domain,
        "ip": result.get("ip"),
        "risk_score": int(score),
        "risk_level": result.get("risk_level"),
        "risk_label": result.get("risk_label"),
        "violation_key": result.get("violation_key"),
        "summary": result.get("summary"),
        "available_sources": result.get("available_sources") or 0,
        "sources_count": len(result.get("sources") or []),
        "timestamp": ts,
        "engine": result.get("engine", "SecuCode-Pro-v2.3"),
        "sources_json": result.get("sources"),
    }

    if _USE_PG:
        _ensure_schema()
        conn = _get_conn()
        if conn:
            try:
                from psycopg2.extras import Json
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO scans (
                        report_id, url, domain, ip, risk_score, risk_level, risk_label,
                        violation_key, summary, available_sources, sources_count, engine, sources_json
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (report_id) DO NOTHING
                """, (
                    report_id, entry["url"], entry["domain"], entry["ip"],
                    entry["risk_score"], entry["risk_level"], entry["risk_label"],
                    entry["violation_key"], entry["summary"],
                    entry["available_sources"], entry["sources_count"],
                    entry["engine"], Json(entry.get("sources_json")),
                ))
                cur.close()
                conn.close()
                return report_id
            except Exception as e:
                print(f"[storage] insert failed: {e}")
                try:
                    conn.close()
                except Exception:
                    pass

    with _lock:
        _history.appendleft({k: v for k, v in entry.items() if k != "sources_json"})
        _save_to_file()
    return report_id


def get_history(limit: int = 50, domain: Optional[str] = None) -> List[Dict]:
    if _USE_PG:
        _ensure_schema()
        conn = _get_conn()
        if conn:
            try:
                from psycopg2.extras import RealDictCursor
                cur = conn.cursor(cursor_factory=RealDictCursor)
                if domain:
                    domain = domain.lower().replace("www.", "")
                    cur.execute("""
                        SELECT report_id, url, domain, ip, risk_score, risk_level, risk_label,
                               violation_key, summary, available_sources, sources_count, engine,
                               created_at AS timestamp
                        FROM scans WHERE domain = %s
                        ORDER BY created_at DESC LIMIT %s
                    """, (domain, limit))
                else:
                    cur.execute("""
                        SELECT report_id, url, domain, ip, risk_score, risk_level, risk_label,
                               violation_key, summary, available_sources, sources_count, engine,
                               created_at AS timestamp
                        FROM scans ORDER BY created_at DESC LIMIT %s
                    """, (limit,))
                rows = cur.fetchall()
                cur.close()
                conn.close()
                return [dict(r) for r in rows]
            except Exception as e:
                print(f"[storage] history failed: {e}")
                try:
                    conn.close()
                except Exception:
                    pass

    with _lock:
        items = list(_history)
    if domain:
        domain = domain.lower().replace("www.", "")
        items = [i for i in items if (i.get("domain") or "").lower() == domain]
    return items[:limit]


def get_report(report_id: str) -> Optional[Dict]:
    if _USE_PG:
        _ensure_schema()
        conn = _get_conn()
        if conn:
            try:
                from psycopg2.extras import RealDictCursor
                cur = conn.cursor(cursor_factory=RealDictCursor)
                cur.execute("""
                    SELECT report_id, url, domain, ip, risk_score, risk_level, risk_label,
                           violation_key, summary, available_sources, sources_count, engine,
                           sources_json, created_at AS timestamp
                    FROM scans WHERE report_id = %s LIMIT 1
                """, (report_id,))
                row = cur.fetchone()
                cur.close()
                conn.close()
                return dict(row) if row else None
            except Exception as e:
                print(f"[storage] get_report failed: {e}")
                try:
                    conn.close()
                except Exception:
                    pass

    with _lock:
        for item in _history:
            if item.get("report_id") == report_id or item.get("id") == report_id:
                return item
    return None



def db_status() -> Dict[str, Any]:
    """Diagnostic for /api/health — never raises."""
    info = {
        "backend": "memory",
        "has_database_url": bool(_DATABASE_URL),
        "has_password_env": bool(_DB_PASSWORD),
        "connected": False,
        "error": None,
    }
    if not _DATABASE_URL:
        info["error"] = "DATABASE_URL is empty — set it in Vercel Environment Variables"
        return info
    try:
        import psycopg2
        conn = psycopg2.connect(_DATABASE_URL, connect_timeout=8, sslmode="require")
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        try:
            cur.execute("SELECT COUNT(*) FROM scans")
            info["scans_table"] = True
            info["total_scans"] = cur.fetchone()[0]
        except Exception:
            info["scans_table"] = False
            info["error"] = "connected but table scans missing — run schema.sql in Supabase"
        cur.close()
        conn.close()
        info["backend"] = "supabase"
        info["connected"] = True
        if info.get("scans_table") and not info.get("error"):
            info["error"] = None
        return info
    except Exception as e:
        info["error"] = str(e)[:200]
        return info


def get_stats() -> Dict[str, Any]:
    if _USE_PG:
        _ensure_schema()
        conn = _get_conn()
        if conn:
            try:
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM scans")
                total = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM scans WHERE risk_level IN ('critical','suspicious')")
                threats = cur.fetchone()[0]
                cur.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'critical'")
                critical = cur.fetchone()[0]
                cur.execute("""
                    SELECT COUNT(*) FROM scans
                    WHERE COALESCE(risk_level, '') IN ('safe', 'low')
                       OR (COALESCE(risk_level, '') NOT IN ('critical', 'suspicious', 'safe', 'low')
                           AND COALESCE(risk_score, 0) < 45)
                """)
                safe = cur.fetchone()[0]
                cur.execute("SELECT created_at FROM scans ORDER BY created_at DESC LIMIT 1")
                row = cur.fetchone()
                last = row[0].isoformat() if row and row[0] else None
                cur.close()
                conn.close()
                return {
                    "total_scans": total,
                    "threats_detected": threats,
                    "safe_count": safe,
                    "critical_count": critical,
                    "last_scan": last,
                    "backend": "supabase",
                }
            except Exception as e:
                print(f"[storage] stats failed: {e}")
                try:
                    conn.close()
                except Exception:
                    pass

    with _lock:
        items = list(_history)
    total = len(items)
    threats = sum(1 for i in items if i.get("risk_level") in ("critical", "suspicious"))
    critical = sum(1 for i in items if i.get("risk_level") == "critical")
    safe = sum(1 for i in items if i.get("risk_level") in ("safe", "low") or (not i.get("risk_level") and (i.get("risk_score") or 0) < 20))
    return {
        "total_scans": total,
        "threats_detected": threats,
        "safe_count": safe,
        "critical_count": critical,
        "last_scan": items[0]["timestamp"] if items else None,
        "backend": "memory",
    }


def is_blacklisted(domain: str) -> Optional[str]:
    domain = (domain or "").lower().replace("www.", "")
    if not domain:
        return None
    if _USE_PG:
        _ensure_schema()
        conn = _get_conn()
        if conn:
            try:
                cur = conn.cursor()
                cur.execute("SELECT reason FROM blacklist WHERE domain = %s LIMIT 1", (domain,))
                row = cur.fetchone()
                cur.close()
                conn.close()
                return row[0] if row else None
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
    return _blacklist.get(domain)


def is_whitelisted(domain: str) -> bool:
    domain = (domain or "").lower().replace("www.", "")
    if not domain:
        return False
    if _USE_PG:
        _ensure_schema()
        conn = _get_conn()
        if conn:
            try:
                cur = conn.cursor()
                cur.execute("SELECT 1 FROM whitelist WHERE domain = %s LIMIT 1", (domain,))
                row = cur.fetchone()
                cur.close()
                conn.close()
                return bool(row)
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
    return domain in _whitelist


def add_to_blacklist(domain: str, reason: str = "Manual") -> bool:
    domain = domain.lower().replace("www.", "").strip()
    if not domain:
        return False
    if _USE_PG:
        _ensure_schema()
        conn = _get_conn()
        if conn:
            try:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO blacklist (domain, reason) VALUES (%s, %s)
                    ON CONFLICT (domain) DO UPDATE SET reason = EXCLUDED.reason
                """, (domain, reason))
                cur.close()
                conn.close()
                return True
            except Exception as e:
                print(f"[storage] blacklist add failed: {e}")
                try:
                    conn.close()
                except Exception:
                    pass
    with _lock:
        _blacklist[domain] = reason
        _save_lists()
    return True


def remove_from_blacklist(domain: str) -> bool:
    domain = domain.lower().replace("www.", "").strip()
    if _USE_PG:
        _ensure_schema()
        conn = _get_conn()
        if conn:
            try:
                cur = conn.cursor()
                cur.execute("DELETE FROM blacklist WHERE domain = %s", (domain,))
                cur.close()
                conn.close()
                return True
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
    with _lock:
        if domain in _blacklist:
            del _blacklist[domain]
            _save_lists()
            return True
    return False


def add_to_whitelist(domain: str) -> bool:
    domain = domain.lower().replace("www.", "").strip()
    if not domain:
        return False
    if _USE_PG:
        _ensure_schema()
        conn = _get_conn()
        if conn:
            try:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO whitelist (domain) VALUES (%s)
                    ON CONFLICT (domain) DO NOTHING
                """, (domain,))
                cur.close()
                conn.close()
                return True
            except Exception as e:
                print(f"[storage] whitelist add failed: {e}")
                try:
                    conn.close()
                except Exception:
                    pass
    with _lock:
        _whitelist.add(domain)
        _save_lists()
    return True


def remove_from_whitelist(domain: str) -> bool:
    domain = domain.lower().replace("www.", "").strip()
    if _USE_PG:
        _ensure_schema()
        conn = _get_conn()
        if conn:
            try:
                cur = conn.cursor()
                cur.execute("DELETE FROM whitelist WHERE domain = %s", (domain,))
                cur.close()
                conn.close()
                return True
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
    with _lock:
        if domain in _whitelist:
            _whitelist.discard(domain)
            _save_lists()
            return True
    return False


def get_lists() -> Dict:
    if _USE_PG:
        _ensure_schema()
        conn = _get_conn()
        if conn:
            try:
                cur = conn.cursor()
                cur.execute("SELECT domain FROM whitelist ORDER BY domain")
                wl = [r[0] for r in cur.fetchall()]
                cur.execute("SELECT domain, reason FROM blacklist ORDER BY domain")
                bl = {r[0]: r[1] for r in cur.fetchall()}
                cur.close()
                conn.close()
                return {"whitelist": wl, "blacklist": bl}
            except Exception as e:
                print(f"[storage] get_lists failed: {e}")
                try:
                    conn.close()
                except Exception:
                    pass
    with _lock:
        return {"whitelist": sorted(list(_whitelist)), "blacklist": dict(_blacklist)}


# ─── Community Reports ────────────────────────────────

_reports_mem: list = []


def add_community_report(url: str, reason: str = "", details: str = "", reporter: str = "anonymous") -> dict:
    from urllib.parse import urlparse
    url = (url or "").strip()
    if not url:
        return {"success": False, "error": "url required"}
    if not url.startswith("http"):
        url = "https://" + url
    try:
        domain = urlparse(url).netloc.lower().replace("www.", "")
    except Exception:
        domain = ""
    reason = (reason or "suspicious")[:120]
    details = (details or "")[:500]
    reporter = (reporter or "anonymous")[:80]

    if _USE_PG:
        _ensure_schema()
        conn = _get_conn()
        if conn:
            try:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO community_reports (url, domain, reason, details, reporter, status)
                    VALUES (%s, %s, %s, %s, %s, 'pending') RETURNING id, created_at
                """, (url, domain, reason, details, reporter))
                row = cur.fetchone()
                cur.close()
                conn.close()
                return {"success": True, "id": row[0], "domain": domain, "status": "pending"}
            except Exception as e:
                print(f"[storage] report insert failed: {e}")
                try:
                    conn.close()
                except Exception:
                    pass

    entry = {
        "id": len(_reports_mem) + 1,
        "url": url,
        "domain": domain,
        "reason": reason,
        "details": details,
        "reporter": reporter,
        "status": "pending",
        "created_at": datetime.utcnow().isoformat() + "Z",
    }
    with _lock:
        _reports_mem.insert(0, entry)
        _reports_mem[:] = _reports_mem[:200]
    return {"success": True, **entry}


def get_community_reports(status: str = None, limit: int = 50) -> list:
    if _USE_PG:
        _ensure_schema()
        conn = _get_conn()
        if conn:
            try:
                from psycopg2.extras import RealDictCursor
                cur = conn.cursor(cursor_factory=RealDictCursor)
                if status:
                    cur.execute("""
                        SELECT id, url, domain, reason, details, reporter, status, created_at
                        FROM community_reports WHERE status = %s
                        ORDER BY created_at DESC LIMIT %s
                    """, (status, limit))
                else:
                    cur.execute("""
                        SELECT id, url, domain, reason, details, reporter, status, created_at
                        FROM community_reports ORDER BY created_at DESC LIMIT %s
                    """, (limit,))
                rows = [dict(r) for r in cur.fetchall()]
                cur.close()
                conn.close()
                return rows
            except Exception as e:
                print(f"[storage] get reports failed: {e}")
                try:
                    conn.close()
                except Exception:
                    pass
    with _lock:
        items = list(_reports_mem)
    if status:
        items = [i for i in items if i.get("status") == status]
    return items[:limit]


def moderate_report(report_id: int, status: str, add_blacklist: bool = False) -> bool:
    status = status if status in ("pending", "approved", "rejected") else "pending"
    domain = None
    if _USE_PG:
        _ensure_schema()
        conn = _get_conn()
        if conn:
            try:
                cur = conn.cursor()
                cur.execute("UPDATE community_reports SET status = %s WHERE id = %s RETURNING domain", (status, report_id))
                row = cur.fetchone()
                domain = row[0] if row else None
                cur.close()
                conn.close()
            except Exception as e:
                print(f"[storage] moderate failed: {e}")
                try:
                    conn.close()
                except Exception:
                    pass
                return False
    else:
        with _lock:
            for r in _reports_mem:
                if r.get("id") == report_id:
                    r["status"] = status
                    domain = r.get("domain")
                    break

    if add_blacklist and domain and status == "approved":
        add_to_blacklist(domain, reason="Community report #" + str(report_id))
    return True


def public_threat_stats() -> dict:
    """Aggregated public stats for the threat intelligence page."""
    base = get_stats()
    feed = {}
    try:
        from utils.threat_feeds import feed_stats, refresh_feeds
        refresh_feeds(force=False)
        feed = feed_stats()
    except Exception:
        pass

    recent_critical = []
    hist = get_history(limit=80)
    for h in hist:
        if h.get("risk_level") in ("critical", "suspicious"):
            recent_critical.append({
                "domain": h.get("domain"),
                "risk_score": h.get("risk_score"),
                "risk_level": h.get("risk_level"),
                "risk_label": h.get("risk_label"),
                "timestamp": str(h.get("timestamp") or ""),
                "report_id": h.get("report_id"),
            })
        if len(recent_critical) >= 15:
            break

    reports = get_community_reports(limit=10)
    pending = len(get_community_reports(status="pending", limit=100))

    return {
        **base,
        "feeds": feed,
        "recent_threats": recent_critical,
        "community_pending": pending,
        "community_recent": [
            {"domain": r.get("domain"), "reason": r.get("reason"), "status": r.get("status"), "created_at": str(r.get("created_at") or "")}
            for r in reports[:5]
        ],
    }
