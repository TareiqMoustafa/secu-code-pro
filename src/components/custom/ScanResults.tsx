import { useEffect, useRef } from 'react';
import {
  Shield, ShieldAlert, ShieldCheck, ShieldX,
  Globe, Server, Lock, Calendar, MapPin, AlertTriangle,
  CheckCircle, XCircle, Info, ExternalLink, Copy, ChevronDown, ChevronUp
} from 'lucide-react';
import { useState } from 'react';

interface ScanResult {
  riskScore: number;
  isThreat: boolean;
  reasons: string[];
  infoNotes: string[];
  url: string;
  domain: string;
  verdict: string;
  server: {
    ip: string;
    country: string;
    city: string;
    org: string;
    asn: string;
  };
  dns: {
    ip: string | null;
    country: string | null;
    city: string | null;
    org: string | null;
    asn: string | null;
  };
  ssl: {
    hasSSL: boolean;
    valid: boolean;
    issuer: string;
    expiry: string;
    daysLeft: number | null;
    grade: string;
  };
  whois: {
    registered: string | null;
    ageDays: number | null;
    registrar: string;
    isNew: boolean;
    expires: string;
  };
  ipRep: {
    score: number;
    isVpn: boolean;
    isProxy: boolean;
    isTor: boolean;
    abuseReports: number;
    risk: string;
  };
  googleSafe: {
    safe: boolean;
    threats: string[];
    checked: boolean;
  };
  vt: {
    malicious: number;
    suspicious: number;
    clean: number;
    total: number;
    reputation: number;
    engines: Record<string, string>;
  } | null;
}

interface ScanResultsProps {
  result: ScanResult | null;
}

function CollapsibleCard({ title, icon, children, defaultOpen = false }: {
  title: string;
  icon: React.ReactNode;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="cyber-border bg-[#0a0a0a]/90 backdrop-blur-sm rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between p-4 hover:bg-[#111111]/50 transition-colors"
      >
        <div className="flex items-center gap-3">
          {icon}
          <span className="font-heading text-sm font-semibold text-white">{title}</span>
        </div>
        {open ? <ChevronUp className="w-4 h-4 text-[#888]" /> : <ChevronDown className="w-4 h-4 text-[#888]" />}
      </button>
      {open && <div className="px-4 pb-4">{children}</div>}
    </div>
  );
}

function DataRow({ label, value, status }: { label: string; value: React.ReactNode; status?: 'safe' | 'warn' | 'danger' | 'info' }) {
  const statusColors = {
    safe: 'text-[#00ff41]',
    warn: 'text-[#ffaa00]',
    danger: 'text-[#ff003c]',
    info: 'text-[#00f0ff]',
  };
  return (
    <div className="flex items-center justify-between py-2 border-b border-[rgba(0,240,255,0.05)] last:border-0">
      <span className="text-xs text-[#888] font-mono-data">{label}</span>
      <span className={`text-xs font-mono-data ${status ? statusColors[status] : 'text-white'}`}>
        {value}
      </span>
    </div>
  );
}

function RiskGauge({ score }: { score: number }) {
  const getColor = () => {
    if (score < 25) return '#00ff41';
    if (score < 60) return '#ffaa00';
    return '#ff003c';
  };

  const getLabel = () => {
    if (score < 25) return 'SAFE';
    if (score < 60) return 'SUSPICIOUS';
    return 'THREAT';
  };

  const getIcon = () => {
    if (score < 25) return <ShieldCheck className="w-12 h-12 text-[#00ff41]" />;
    if (score < 60) return <ShieldAlert className="w-12 h-12 text-[#ffaa00]" />;
    return <ShieldX className="w-12 h-12 text-[#ff003c]" />;
  };

  const circumference = 2 * Math.PI * 54;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-32 h-32">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="54" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="8" />
          <circle
            cx="60" cy="60" r="54" fill="none"
            stroke={getColor()}
            strokeWidth="8"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            className="transition-all duration-1000"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          {getIcon()}
          <span className="font-heading text-2xl font-bold mt-1" style={{ color: getColor() }}>
            {score}
          </span>
        </div>
      </div>
      <span
        className="font-heading text-lg font-bold mt-2 text-glow"
        style={{ color: getColor() }}
      >
        {getLabel()}
      </span>
    </div>
  );
}

export default function ScanResults({ result }: ScanResultsProps) {
  const resultsRef = useRef<HTMLDivElement>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (result && resultsRef.current) {
      resultsRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }, [result]);

  if (!result) return null;

  const copyUrl = () => {
    navigator.clipboard.writeText(result.url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div ref={resultsRef} className="w-full max-w-6xl mx-auto px-4 py-8">
      {/* Results Header */}
      <div className="cyber-border bg-[#0a0a0a]/90 backdrop-blur-sm rounded-lg p-6 mb-6">
        <div className="flex flex-col md:flex-row items-start md:items-center gap-6">
          {/* Risk Gauge */}
          <RiskGauge score={result.riskScore} />

          {/* URL Info */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2">
              <Globe className="w-4 h-4 text-[#00f0ff]" />
              <span className="label-tag">TARGET URL</span>
            </div>
            <div className="flex items-center gap-2">
              <p className="text-white font-mono-data text-sm truncate">{result.url}</p>
              <button onClick={copyUrl} className="text-[#888] hover:text-[#00f0ff] transition-colors flex-shrink-0">
                {copied ? <CheckCircle className="w-4 h-4 text-[#00ff41]" /> : <Copy className="w-4 h-4" />}
              </button>
              <a href={result.url} target="_blank" rel="noopener noreferrer" className="text-[#888] hover:text-[#00f0ff] transition-colors flex-shrink-0">
                <ExternalLink className="w-4 h-4" />
              </a>
            </div>
            <div className="flex flex-wrap gap-4 mt-3">
              <span className="text-xs text-[#888] font-mono-data">
                Domain: <span className="text-white">{result.domain}</span>
              </span>
              <span className="text-xs text-[#888] font-mono-data">
                IP: <span className="text-white">{result.server.ip || 'N/A'}</span>
              </span>
              {result.server.country && (
                <span className="text-xs text-[#888] font-mono-data">
                  Location: <span className="text-white">{result.server.city}, {result.server.country}</span>
                </span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Threat Indicators */}
      {result.reasons.length > 0 && (
        <div className="cyber-border bg-[rgba(255,0,60,0.05)] rounded-lg p-4 mb-6 border-[rgba(255,0,60,0.2)]">
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle className="w-4 h-4 text-[#ff003c]" />
            <span className="label-tag text-[#ff003c]">THREAT INDICATORS</span>
          </div>
          <div className="space-y-2">
            {result.reasons.map((reason, i) => (
              <div key={i} className="flex items-start gap-2">
                <XCircle className="w-4 h-4 text-[#ff003c] flex-shrink-0 mt-0.5" />
                <span className="text-sm text-white/90 font-mono-data">{reason}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Info Notes */}
      {result.infoNotes.length > 0 && (
        <div className="cyber-border bg-[rgba(0,240,255,0.03)] rounded-lg p-4 mb-6">
          <div className="flex items-center gap-2 mb-3">
            <Info className="w-4 h-4 text-[#00f0ff]" />
            <span className="label-tag text-[#00f0ff]">INTELLIGENCE NOTES</span>
          </div>
          <div className="space-y-2">
            {result.infoNotes.map((note, i) => (
              <div key={i} className="flex items-start gap-2">
                <CheckCircle className="w-4 h-4 text-[#00f0ff] flex-shrink-0 mt-0.5" />
                <span className="text-sm text-[#888] font-mono-data">{note}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Detail Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* SSL Certificate */}
        <CollapsibleCard title="SSL / TLS Certificate" icon={<Lock className="w-4 h-4 text-[#00f0ff]" />}>
          <DataRow label="SSL Present" value={result.ssl.hasSSL ? 'YES' : 'NO'} status={result.ssl.hasSSL ? 'safe' : 'danger'} />
          <DataRow label="Valid" value={result.ssl.valid ? 'YES' : 'NO'} status={result.ssl.valid ? 'safe' : 'danger'} />
          <DataRow label="Issuer" value={result.ssl.issuer} />
          <DataRow label="Grade" value={`Grade ${result.ssl.grade}`} status={result.ssl.grade.startsWith('A') ? 'safe' : 'warn'} />
          {result.ssl.daysLeft !== null && (
            <DataRow
              label="Days Left"
              value={`${result.ssl.daysLeft} days`}
              status={result.ssl.daysLeft > 30 ? 'safe' : result.ssl.daysLeft > 14 ? 'warn' : 'danger'}
            />
          )}
        </CollapsibleCard>

        {/* Domain Info */}
        <CollapsibleCard title="Domain Intelligence" icon={<Calendar className="w-4 h-4 text-[#00f0ff]" />}>
          <DataRow label="Registrar" value={result.whois.registrar || 'N/A'} />
          <DataRow label="Registered" value={result.whois.registered || 'N/A'} />
          {result.whois.ageDays !== null && (
            <DataRow
              label="Age"
              value={`${result.whois.ageDays} days`}
              status={result.whois.isNew ? 'warn' : 'safe'}
            />
          )}
          <DataRow label="Is New" value={result.whois.isNew ? 'YES' : 'NO'} status={result.whois.isNew ? 'warn' : 'safe'} />
          <DataRow label="Expires" value={result.whois.expires || 'N/A'} />
        </CollapsibleCard>

        {/* Server Location */}
        <CollapsibleCard title="Server Location" icon={<MapPin className="w-4 h-4 text-[#00f0ff]" />}>
          <DataRow label="IP Address" value={result.server.ip || 'N/A'} />
          <DataRow label="Country" value={result.server.country || 'N/A'} />
          <DataRow label="City" value={result.server.city || 'N/A'} />
          <DataRow label="Organization" value={result.server.org || 'N/A'} />
          <DataRow label="ASN" value={result.server.asn || 'N/A'} />
        </CollapsibleCard>

        {/* IP Reputation */}
        <CollapsibleCard title="IP Reputation" icon={<Shield className="w-4 h-4 text-[#00f0ff]" />}>
          <DataRow label="Risk Level" value={result.ipRep.risk} status={
            result.ipRep.risk === 'LOW' ? 'safe' : result.ipRep.risk === 'MEDIUM' ? 'warn' : 'danger'
          } />
          <DataRow label="Abuse Score" value={`${result.ipRep.score}%`} status={result.ipRep.score > 50 ? 'danger' : result.ipRep.score > 20 ? 'warn' : 'safe'} />
          <DataRow label="VPN Detected" value={result.ipRep.isVpn ? 'YES' : 'NO'} status={result.ipRep.isVpn ? 'warn' : 'safe'} />
          <DataRow label="Proxy Detected" value={result.ipRep.isProxy ? 'YES' : 'NO'} status={result.ipRep.isProxy ? 'warn' : 'safe'} />
          <DataRow label="Tor Node" value={result.ipRep.isTor ? 'YES' : 'NO'} status={result.ipRep.isTor ? 'danger' : 'safe'} />
        </CollapsibleCard>

        {/* Google Safe Browsing */}
        <CollapsibleCard title="Google Safe Browsing" icon={<ShieldCheck className="w-4 h-4 text-[#00f0ff]" />}>
          <DataRow
            label="Status"
            value={result.googleSafe.safe ? 'SAFE' : 'FLAGGED'}
            status={result.googleSafe.safe ? 'safe' : 'danger'}
          />
          <DataRow label="Checked" value={result.googleSafe.checked ? 'YES' : 'NO'} />
          {result.googleSafe.threats.length > 0 && (
            <DataRow label="Threats" value={result.googleSafe.threats.join(', ')} status="danger" />
          )}
        </CollapsibleCard>

        {/* VirusTotal */}
        <CollapsibleCard title="VirusTotal" icon={<Shield className="w-4 h-4 text-[#00f0ff]" />}>
          {result.vt ? (
            <>
              <DataRow label="Malicious" value={result.vt.malicious.toString()} status={result.vt.malicious > 0 ? 'danger' : 'safe'} />
              <DataRow label="Suspicious" value={result.vt.suspicious.toString()} status={result.vt.suspicious > 0 ? 'warn' : 'safe'} />
              <DataRow label="Clean" value={result.vt.clean.toString()} status="safe" />
              <DataRow label="Total Engines" value={result.vt.total.toString()} />
              {result.vt.reputation !== 0 && (
                <DataRow label="Reputation" value={result.vt.reputation.toString()} status={result.vt.reputation < 0 ? 'warn' : 'safe'} />
              )}
              {Object.keys(result.vt.engines).length > 0 && (
                <div className="mt-3">
                  <span className="text-xs text-[#888] font-mono-data block mb-2">DETECTED BY:</span>
                  <div className="flex flex-wrap gap-1">
                    {Object.entries(result.vt.engines).slice(0, 8).map(([name, detection]) => (
                      <span key={name} className="text-[10px] bg-[rgba(255,0,60,0.1)] text-[#ff003c] px-2 py-1 rounded font-mono-data">
                        {name}: {detection}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </>
          ) : (
            <p className="text-xs text-[#888] font-mono-data">VirusTotal scan unavailable for this URL.</p>
          )}
        </CollapsibleCard>
      </div>
    </div>
  );
}
