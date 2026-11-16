"""Extra high-value routes registered from app.py"""
from flask import request, jsonify, render_template, Response
from utils.analyzer import analyze_url
from utils import storage


def register_extra_routes(app, require_admin):

    @app.route("/r/<report_id>")
    @app.route("/report/<report_id>")
    def public_report(report_id):
        item = storage.get_report(report_id)
        return render_template("report.html", report=item, report_id=report_id)

    @app.route("/api/bulk", methods=["POST"])
    def bulk_analyze():
        try:
            data = request.get_json(silent=True) or {}
            urls = data.get("urls") or []
            if isinstance(urls, str):
                urls = [u.strip() for u in urls.replace(",", "\n").splitlines() if u.strip()]
            urls = [u.strip() for u in urls if u and isinstance(u, str)][:8]
            if not urls:
                return jsonify({"success": False, "error": "No URLs provided (max 8)"}), 400

            results = []
            for u in urls:
                try:
                    r = analyze_url(u)
                    if r.get("success"):
                        points = r.get("points")
                        if points is None:
                            points = r.get("risk_score", 0)
                            if isinstance(points, str):
                                points = 0
                        r["points"] = points
                        try:
                            rid = storage.add_scan(r)
                            r["report_id"] = rid
                        except Exception:
                            r["report_id"] = None
                    results.append(r)
                except Exception as e:
                    results.append({"success": False, "url": u, "error": str(e)[:80]})

            critical = sum(1 for r in results if r.get("risk_level") == "critical")
            suspicious = sum(1 for r in results if r.get("risk_level") == "suspicious")
            safe = sum(1 for r in results if r.get("risk_level") in ("safe", "low"))
            return jsonify({
                "success": True,
                "count": len(results),
                "summary": {"critical": critical, "suspicious": suspicious, "safe": safe},
                "results": results,
            })
        except Exception as e:
            return jsonify({"success": False, "error": str(e)[:120]}), 500

    @app.route("/api/badge")
    def trust_badge():
        domain = (request.args.get("domain") or request.args.get("d") or "").strip().lower()
        domain = domain.replace("https://", "").replace("http://", "").split("/")[0]
        if domain.startswith("www."):
            domain = domain[4:]

        status = "unknown"
        score = None
        color = "#64748b"
        label = "NOT SCANNED"

        if domain:
            try:
                from utils.threat_feeds import check_domain
                hit = check_domain(domain)
                if hit:
                    status = "danger"
                    color = "#ef4444"
                    label = "THREAT DETECTED"
                    score = 98
            except Exception:
                pass

            if status == "unknown":
                hist = storage.get_history(limit=5, domain=domain)
                if hist:
                    score = hist[0].get("risk_score", 0) or 0
                    level = hist[0].get("risk_level") or ""
                    if level == "critical" or score >= 75:
                        status, color, label = "danger", "#ef4444", "HIGH RISK"
                    elif level == "suspicious" or score >= 45:
                        status, color, label = "warn", "#f59e0b", "SUSPICIOUS"
                    else:
                        status, color, label = "safe", "#10b981", "VERIFIED SAFE"

        score_text = f"{score}/100" if score is not None else "—"
        domain_text = (domain[:26] + "…") if len(domain) > 26 else (domain or "secucode.pro")

        svg = (
            '<svg xmlns="http://www.w3.org/2000/svg" width="280" height="56" viewBox="0 0 280 56" role="img">'
            "<defs><linearGradient id=\"g\" x1=\"0\" y1=\"0\" x2=\"1\" y2=\"1\">"
            '<stop offset="0%" stop-color="#0f172a"/>'
            '<stop offset="100%" stop-color="#1e293b"/>'
            "</linearGradient></defs>"
            f'<rect width="280" height="56" rx="10" fill="url(#g)" stroke="#334155" stroke-width="1"/>'
            f'<rect x="0" y="0" width="6" height="56" rx="2" fill="{color}"/>'
            '<text x="18" y="24" fill="#94a3b8" font-family="Inter,Arial,sans-serif" font-size="9" font-weight="700" letter-spacing="1.2">SECUCODE PRO</text>'
            f'<text x="18" y="42" fill="#f1f5f9" font-family="Inter,Arial,sans-serif" font-size="13" font-weight="800">{domain_text}</text>'
            f'<rect x="175" y="12" width="92" height="32" rx="8" fill="{color}" fill-opacity="0.15" stroke="{color}" stroke-width="1"/>'
            f'<text x="221" y="26" text-anchor="middle" fill="{color}" font-family="Inter,Arial,sans-serif" font-size="8" font-weight="800">{label}</text>'
            f'<text x="221" y="38" text-anchor="middle" fill="#e2e8f0" font-family="Inter,Arial,sans-serif" font-size="10" font-weight="700">{score_text}</text>'
            "</svg>"
        )
        return Response(
            svg,
            mimetype="image/svg+xml",
            headers={"Cache-Control": "public, max-age=300", "Access-Control-Allow-Origin": "*"},
        )

    @app.route("/api/docs")
    @app.route("/docs")
    def api_docs():
        return render_template("docs.html")

    @app.route("/bulk")
    def bulk_page():
        return render_template("bulk.html")

    @app.route("/api/domain/<domain>")
    def domain_intel(domain):
        """Aggregated intelligence for a domain — history + feeds + lists."""
        domain = domain.lower().replace("www.", "").strip()
        hist = storage.get_history(limit=20, domain=domain)
        feed = None
        try:
            from utils.threat_feeds import check_domain
            feed = check_domain(domain)
        except Exception:
            pass
        lists = storage.get_lists()
        in_bl = domain in (lists.get("blacklist") or {})
        in_wl = domain in (lists.get("whitelist") or [])
        return jsonify({
            "success": True,
            "domain": domain,
            "feed_match": feed,
            "blacklisted": in_bl,
            "whitelisted": in_wl,
            "scan_history": hist,
            "scan_count": len(hist),
        })


    @app.route("/threats")
    def threats_page():
        return render_template("threats.html")

    @app.route("/report-url")
    def report_url_page():
        return render_template("report_url.html")

    @app.route("/api/threats/public")
    def threats_public_api():
        return jsonify({"success": True, **storage.public_threat_stats()})

    @app.route("/api/community/report", methods=["POST"])
    def community_report():
        data = request.get_json(silent=True) or {}
        url = (data.get("url") or "").strip()
        reason = (data.get("reason") or "suspicious").strip()
        details = (data.get("details") or "").strip()
        reporter = (data.get("reporter") or "anonymous").strip()
        if not url:
            return jsonify({"success": False, "error": "url required"}), 400
        result = storage.add_community_report(url, reason, details, reporter)
        code = 200 if result.get("success") else 400
        return jsonify(result), code

    @app.route("/api/community/reports")
    @require_admin
    def community_reports_list():
        status = request.args.get("status")
        items = storage.get_community_reports(status=status, limit=100)
        return jsonify({"success": True, "count": len(items), "reports": items})

    @app.route("/api/community/moderate", methods=["POST"])
    @require_admin
    def community_moderate():
        data = request.get_json(silent=True) or {}
        rid = data.get("id")
        status = data.get("status") or "pending"
        add_bl = bool(data.get("add_blacklist"))
        if rid is None:
            return jsonify({"success": False, "error": "id required"}), 400
        ok = storage.moderate_report(int(rid), status, add_blacklist=add_bl)
        return jsonify({"success": ok})
