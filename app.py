"""
SecuCode Pro v2.5 - Professional Threat Intelligence Platform
Multi-Source URL Analysis Engine + History + Admin
Developers: Tarek Mostafa · Mazen Amro
"""

import os
from functools import wraps
from flask import Flask, request, jsonify, render_template, send_from_directory
from dotenv import load_dotenv

load_dotenv()

from utils.analyzer import analyze_url
from utils import storage

app = Flask(
    __name__,
    static_folder="static",
    static_url_path="/static",
    template_folder="templates",
)

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "").strip()

from utils.extra_routes import register_extra_routes


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-Admin-Token") or request.args.get("token") or ""
        if not ADMIN_TOKEN or token != ADMIN_TOKEN:
            return jsonify({"error": "Unauthorized", "message": "Invalid or missing admin token"}), 401
        return f(*args, **kwargs)
    return decorated



@app.after_request
def add_cors_headers(response):
    """Allow browser extension and embeddable badge/API."""
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Admin-Token"
    return response


@app.route("/api/<path:path>", methods=["OPTIONS"])
@app.route("/analyze", methods=["OPTIONS"])
def cors_preflight(path=None):
    return "", 204

# ─────────────────────────────────────────────
# Static & SEO
# ─────────────────────────────────────────────
@app.route("/robots.txt")
def robots():
    return send_from_directory(app.static_folder, "robots.txt")


@app.route("/sitemap.xml")
def sitemap():
    return send_from_directory(app.static_folder, "sitemap.xml")


@app.route("/sw.js")
def service_worker():
    return send_from_directory(app.static_folder, "sw.js")


@app.route("/static/<path:filename>")
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)


# ─────────────────────────────────────────────
# Frontend pages
# ─────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/admin")
def admin_page():
    return render_template("admin.html")


@app.route("/api/index")
def api_index():
    return render_template("index.html")


# ─────────────────────────────────────────────
# Core Analysis API
# ─────────────────────────────────────────────
@app.route("/analyze", methods=["POST"])
@app.route("/api/analyze", methods=["POST"])
def analyze():
    try:
        data = request.get_json(silent=True) or {}
        url = (data.get("link") or data.get("url") or "").strip()

        if not url:
            return jsonify({"success": False, "error": "Empty URL provided"}), 400

        result = analyze_url(url)

        if result.get("success"):
            points = result.get("points")
            if points is None:
                points = result.get("risk_score", 0)
                if isinstance(points, str):
                    points = 0
            result["points"] = points

            if result.get("risk_level") == "critical":
                result["risk_score_display"] = "Critical"
            elif result.get("risk_level") == "suspicious":
                result["risk_score_display"] = "Suspicious"
            else:
                result["risk_score_display"] = "Safe"

            try:
                report_id = storage.add_scan(result)
                result["report_id"] = report_id
            except Exception:
                result["report_id"] = None

        return jsonify(result)

    except Exception as e:
        return jsonify({
            "success": False,
            "error": "Internal analysis error",
            "detail": str(e)[:150],
        }), 500


@app.route("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "engine": "SecuCode-Pro-MultiSource-v2.5",
        "version": "2.5.0",
    })


# ─────────────────────────────────────────────
# History & Stats (public read)
# ─────────────────────────────────────────────
@app.route("/api/history")
def history():
    limit = min(int(request.args.get("limit", 40)), 100)
    domain = request.args.get("domain")
    items = storage.get_history(limit=limit, domain=domain)
    return jsonify({"success": True, "count": len(items), "history": items})


@app.route("/api/stats")
def stats():
    return jsonify({"success": True, **storage.get_stats()})


@app.route("/api/report/<report_id>")
def get_report(report_id):
    item = storage.get_report(report_id)
    if not item:
        return jsonify({"success": False, "error": "Report not found"}), 404
    return jsonify({"success": True, "report": item})


# ─────────────────────────────────────────────
# Admin APIs (protected by ADMIN_TOKEN)
# ─────────────────────────────────────────────
@app.route("/api/admin/lists", methods=["GET"])
@require_admin
def admin_get_lists():
    return jsonify({"success": True, **storage.get_lists()})


@app.route("/api/admin/blacklist", methods=["POST"])
@require_admin
def admin_add_blacklist():
    data = request.get_json(silent=True) or {}
    domain = (data.get("domain") or "").strip()
    reason = (data.get("reason") or "Manual").strip()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    ok = storage.add_to_blacklist(domain, reason)
    return jsonify({"success": ok, "domain": domain})


@app.route("/api/admin/blacklist", methods=["DELETE"])
@require_admin
def admin_remove_blacklist():
    data = request.get_json(silent=True) or {}
    domain = (data.get("domain") or request.args.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    ok = storage.remove_from_blacklist(domain)
    return jsonify({"success": ok})


@app.route("/api/admin/whitelist", methods=["POST"])
@require_admin
def admin_add_whitelist():
    data = request.get_json(silent=True) or {}
    domain = (data.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    ok = storage.add_to_whitelist(domain)
    return jsonify({"success": ok, "domain": domain})


@app.route("/api/admin/whitelist", methods=["DELETE"])
@require_admin
def admin_remove_whitelist():
    data = request.get_json(silent=True) or {}
    domain = (data.get("domain") or request.args.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "domain required"}), 400
    ok = storage.remove_from_whitelist(domain)
    return jsonify({"success": ok})


@app.route("/api/admin/stats")
@require_admin
def admin_stats():
    return jsonify({"success": True, **storage.get_stats(), "lists": storage.get_lists()})




@app.route("/api/feeds/status")
def feeds_status():
    try:
        from utils.threat_feeds import feed_stats, refresh_feeds
        # non-blocking soft refresh
        refresh_feeds(force=False)
        return jsonify({"success": True, **feed_stats()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)[:120]}), 500


@app.route("/api/feeds/refresh", methods=["POST"])
@require_admin
def feeds_refresh():
    try:
        from utils.threat_feeds import refresh_feeds, feed_stats
        result = refresh_feeds(force=True)
        return jsonify({"success": True, "refresh": result, **feed_stats()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)[:120]}), 500

# ─────────────────────────────────────────────
# Local development
# ─────────────────────────────────────────────
register_extra_routes(app, require_admin)

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
