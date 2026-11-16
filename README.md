# SecuCode Pro v2.2
Professional Multi-Source Threat Intelligence Platform

Developers: طارق مصطفى (Tarek Mostafa) · مازن عمرو (Mazen Amro)

## What's New in v2.2

- Full professional SaaS-grade dark UI
- Animated risk score ring
- History tab with interactive table
- Admin dashboard (/admin) protected by token
- Whitelist & Blacklist management
- Scan history storage (in-memory + file)
- Parallel multi-source scan + high-priority blacklist
- Premium Arabic RTL design + QR Scanner

## Sources

- VirusTotal v3
- Google Safe Browsing
- URLhaus
- AbuseIPDB
- Behavioral Analysis
- Domain Age (RDAP)

## Quick Start

```bash
pip install -r requirements.txt
cp .env.example .env
# edit keys then:
python app.py
```

### Required Vercel Environment Variables

VT_API_KEY=
GSB_API_KEY=
ABUSEIPDB_KEY=
ADMIN_TOKEN=strong_random_secret
TELEGRAM_TOKEN=          # optional
TELEGRAM_CHAT_ID=        # optional

## Pages

- /          Main scanner + history
- /admin     Admin panel (requires ADMIN_TOKEN)
- /api/analyze
- /api/history
- /api/stats

MIT License · © 2026 Tarek Mostafa & Mazen Amro
