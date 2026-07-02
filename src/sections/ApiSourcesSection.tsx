import { useEffect, useRef, useState } from 'react';
import {
  Shield, Globe, Search, Lock, Eye, Database,
  Server, Fingerprint, FileWarning, Radar, Cpu, Network
} from 'lucide-react';

const apis = [
  {
    name: 'VirusTotal',
    description: 'Aggregates 70+ antivirus engines and website scanners',
    icon: Shield,
    status: 'active',
    endpoint: 'virustotal.com/api/v3',
  },
  {
    name: 'Google Safe Browsing',
    description: 'Real-time threat intelligence from Google\'s security infrastructure',
    icon: Search,
    status: 'active',
    endpoint: 'safebrowsing.googleapis.com',
  },
  {
    name: 'URLScan.io',
    description: 'Website sandbox scanning and screenshot capture',
    icon: Eye,
    status: 'active',
    endpoint: 'urlscan.io/api/v1',
  },
  {
    name: 'PhishTank',
    description: 'Community-driven phishing database verification',
    icon: FileWarning,
    status: 'active',
    endpoint: 'phishtank.org',
  },
  {
    name: 'GreyNoise',
    description: 'Internet noise and benign scanner identification',
    icon: Radar,
    status: 'active',
    endpoint: 'greynoise.io',
  },
  {
    name: 'AbuseIPDB',
    description: 'IP address reputation and abuse reporting',
    icon: Database,
    status: 'active',
    endpoint: 'abuseipdb.com',
  },
  {
    name: 'IP Intelligence',
    description: 'Geolocation, ASN, and hosting provider data',
    icon: Globe,
    status: 'active',
    endpoint: 'ipapi.co',
  },
  {
    name: 'WHOIS Lookup',
    description: 'Domain registration and ownership information',
    icon: Fingerprint,
    status: 'active',
    endpoint: 'whoisfreaks.com',
  },
  {
    name: 'DNS Resolver',
    description: 'Multi-provider DNS resolution (Google, Cloudflare)',
    icon: Network,
    status: 'active',
    endpoint: 'dns.google',
  },
  {
    name: 'SSL Analyzer',
    description: 'Certificate validation and grading',
    icon: Lock,
    status: 'active',
    endpoint: 'internal',
  },
  {
    name: 'Threat Feed',
    description: 'Real-time malicious URL feed from URLhaus',
    icon: Server,
    status: 'active',
    endpoint: 'urlhaus.abuse.ch',
  },
  {
    name: 'AI Analysis',
    description: 'Claude-powered threat assessment and classification',
    icon: Cpu,
    status: 'active',
    endpoint: 'anthropic.com',
  },
];

function ApiCard({ api, index }: { api: typeof apis[0]; index: number }) {
  const [visible, setVisible] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) setVisible(true);
      },
      { threshold: 0.2 }
    );
    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, []);

  const Icon = api.icon;

  return (
    <div
      ref={ref}
      className={`cyber-border bg-[#0a0a0a]/80 backdrop-blur-sm rounded-lg p-4 flex items-center gap-4 transition-all duration-500 ${
        visible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'
      }`}
      style={{ transitionDelay: `${index * 50}ms` }}
    >
      <div className="flex-shrink-0 w-10 h-10 rounded bg-[rgba(0,240,255,0.06)] flex items-center justify-center border border-[rgba(0,240,255,0.1)]">
        <Icon className="w-5 h-5 text-[#00f0ff]" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <h4 className="font-heading text-sm font-semibold text-white truncate">{api.name}</h4>
          <div className="status-dot secure flex-shrink-0" style={{ width: 6, height: 6 }} />
        </div>
        <p className="text-[11px] text-[#888] font-mono-data mt-0.5 truncate">{api.description}</p>
        <p className="text-[10px] text-[#00f0ff]/40 font-mono-data mt-0.5">{api.endpoint}</p>
      </div>
    </div>
  );
}

export default function ApiSourcesSection() {
  return (
    <section id="api" className="relative py-24">
      <div className="absolute inset-0 grid-pattern opacity-20" />

      <div className="relative z-10 max-w-6xl mx-auto px-4">
        {/* Section Header */}
        <div className="text-center mb-16">
          <div className="flex items-center justify-center gap-2 mb-4">
            <Server className="w-4 h-4 text-[#00f0ff]" />
            <span className="label-tag text-[#00f0ff]">INTELLIGENCE SOURCES</span>
          </div>
          <h2 className="font-heading text-3xl sm:text-4xl font-bold text-white mb-4">
            Integrated <span className="text-[#00f0ff] text-glow">Threat Feeds</span>
          </h2>
          <p className="text-[#888] text-sm font-mono-data max-w-2xl mx-auto">
            12 specialized security APIs working in concert to provide comprehensive threat coverage.
            Every scan queries multiple independent sources for maximum accuracy.
          </p>
        </div>

        {/* API Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {apis.map((api, i) => (
            <ApiCard key={api.name} api={api} index={i} />
          ))}
        </div>

        {/* Integration Diagram */}
        <div className="mt-12 cyber-border bg-[#0a0a0a]/80 rounded-lg p-6">
          <div className="flex items-center justify-center gap-4 flex-wrap">
            <div className="text-center">
              <div className="w-16 h-16 mx-auto rounded-full bg-[rgba(0,240,255,0.1)] border border-[#00f0ff]/30 flex items-center justify-center mb-2">
                <Shield className="w-8 h-8 text-[#00f0ff]" />
              </div>
              <span className="text-xs text-white font-mono-data">URL Input</span>
            </div>

            <div className="flex flex-col items-center">
              <div className="w-16 h-px bg-gradient-to-r from-[#00f0ff]/50 to-[#00f0ff]/20" />
              <span className="text-[10px] text-[#888] font-mono-data my-1">routes to</span>
              <div className="w-16 h-px bg-gradient-to-r from-[#00f0ff]/20 to-[#00f0ff]/50" />
            </div>

            <div className="text-center">
              <div className="w-16 h-16 mx-auto rounded-full bg-[rgba(0,240,255,0.1)] border border-[#00f0ff]/30 flex items-center justify-center mb-2">
                <Cpu className="w-8 h-8 text-[#00f0ff]" />
              </div>
              <span className="text-xs text-white font-mono-data">Engine</span>
            </div>

            <div className="flex flex-col items-center">
              <div className="w-16 h-px bg-gradient-to-r from-[#00f0ff]/50 to-[#00f0ff]/20" />
              <span className="text-[10px] text-[#888] font-mono-data my-1">queries</span>
              <div className="w-16 h-px bg-gradient-to-r from-[#00f0ff]/20 to-[#00f0ff]/50" />
            </div>

            <div className="text-center">
              <div className="w-16 h-16 mx-auto rounded-full bg-[rgba(0,240,255,0.1)] border border-[#00f0ff]/30 flex items-center justify-center mb-2">
                <Database className="w-8 h-8 text-[#00f0ff]" />
              </div>
              <span className="text-xs text-white font-mono-data">12 APIs</span>
            </div>

            <div className="flex flex-col items-center">
              <div className="w-16 h-px bg-gradient-to-r from-[#00f0ff]/50 to-[#00f0ff]/20" />
              <span className="text-[10px] text-[#888] font-mono-data my-1">aggregates</span>
              <div className="w-16 h-px bg-gradient-to-r from-[#00f0ff]/20 to-[#00f0ff]/50" />
            </div>

            <div className="text-center">
              <div className="w-16 h-16 mx-auto rounded-full bg-[rgba(0,255,65,0.1)] border border-[#00ff41]/30 flex items-center justify-center mb-2">
                <Shield className="w-8 h-8 text-[#00ff41]" />
              </div>
              <span className="text-xs text-white font-mono-data">Verdict</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
