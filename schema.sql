-- SecuCode Pro — شغّل هذا الملف مرة واحدة في Supabase
-- SQL Editor → New query → الصق → Run

CREATE TABLE IF NOT EXISTS scans (
    id                BIGSERIAL PRIMARY KEY,
    report_id         TEXT UNIQUE NOT NULL,
    url               TEXT,
    domain            TEXT,
    ip                TEXT,
    risk_score        INTEGER DEFAULT 0,
    risk_level        TEXT,
    risk_label        TEXT,
    violation_key     TEXT,
    summary           TEXT,
    available_sources INTEGER DEFAULT 0,
    sources_count     INTEGER DEFAULT 0,
    engine            TEXT,
    sources_json      JSONB,
    created_at        TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_report ON scans(report_id);
CREATE INDEX IF NOT EXISTS idx_scans_level ON scans(risk_level);

CREATE TABLE IF NOT EXISTS whitelist (
    id         BIGSERIAL PRIMARY KEY,
    domain     TEXT UNIQUE NOT NULL,
    added_by   TEXT DEFAULT 'admin',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS blacklist (
    id         BIGSERIAL PRIMARY KEY,
    domain     TEXT UNIQUE NOT NULL,
    reason     TEXT DEFAULT 'Manual',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS community_reports (
    id         BIGSERIAL PRIMARY KEY,
    url        TEXT NOT NULL,
    domain     TEXT,
    reason     TEXT,
    details    TEXT,
    reporter   TEXT DEFAULT 'anonymous',
    status     TEXT DEFAULT 'pending',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reports_status ON community_reports(status);
CREATE INDEX IF NOT EXISTS idx_reports_created ON community_reports(created_at DESC);
