import { useEffect, useRef, useState } from 'react';
import {
  Brain, Shield, Zap, FileSearch, Globe, Lock,
  Scan, AlertTriangle, Fingerprint, Radar
} from 'lucide-react';

const features = [
  {
    id: '01',
    title: 'AI THREAT ANALYSIS',
    description: 'Neural network-powered heuristic engine that learns from billions of threat patterns to identify zero-day attacks and sophisticated phishing campaigns.',
    icon: Brain,
    capabilities: ['Behavioral pattern recognition', 'Zero-day detection', 'Predictive risk scoring'],
  },
  {
    id: '02',
    title: 'VIRUSTOTAL INTEGRATION',
    description: 'Direct integration with 70+ security engines through VirusTotal API for comprehensive malware detection and reputation analysis.',
    icon: Shield,
    capabilities: ['70+ engine scan', 'Real-time reputation', 'Historical analysis'],
  },
  {
    id: '03',
    title: 'MULTI-VECTOR DETECTION',
    description: 'Simultaneous scanning across Google Safe Browsing, URLScan.io, PhishTank, and proprietary heuristics for maximum coverage.',
    icon: Radar,
    capabilities: ['Multi-API correlation', 'False positive reduction', 'Cross-reference validation'],
  },
  {
    id: '04',
    title: 'SSL CERTIFICATE ANALYSIS',
    description: 'Deep inspection of TLS/SSL certificates including issuer validation, expiry monitoring, and grade assessment.',
    icon: Lock,
    capabilities: ['Certificate grading (A+ to F)', 'Expiry monitoring', 'Issuer verification'],
  },
  {
    id: '05',
    title: 'DNS INTELLIGENCE',
    description: 'Comprehensive DNS analysis including A/AAAA/MX/NS/TXT records, DNSSEC validation, and reverse DNS lookups.',
    icon: Globe,
    capabilities: ['Multi-record analysis', 'DNSSEC validation', 'Geolocation mapping'],
  },
  {
    id: '06',
    title: 'TYPOsquatting DETECTION',
    description: 'Advanced Levenshtein distance algorithms detect brand impersonation and homograph attacks before they reach users.',
    icon: Fingerprint,
    capabilities: ['Brand impersonation detection', 'Homograph attack识别', 'Distance algorithm analysis'],
  },
];

function FeatureCard({ feature, index }: { feature: typeof features[0]; index: number }) {
  const [visible, setVisible] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setVisible(true);
        }
      },
      { threshold: 0.2 }
    );
    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, []);

  const Icon = feature.icon;

  return (
    <div
      ref={ref}
      className={`cyber-border bg-[#0a0a0a]/80 backdrop-blur-sm rounded-lg p-6 transition-all duration-700 ${
        visible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'
      }`}
      style={{ transitionDelay: `${index * 100}ms` }}
    >
      <div className="flex items-start gap-4">
        <div className="flex-shrink-0 w-12 h-12 rounded bg-[rgba(0,240,255,0.08)] flex items-center justify-center border border-[rgba(0,240,255,0.15)]">
          <Icon className="w-6 h-6 text-[#00f0ff]" />
        </div>
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-2">
            <span className="text-[#00f0ff]/40 font-mono-data text-xs">{feature.id}.</span>
            <h3 className="font-heading text-base font-bold text-white">{feature.title}</h3>
          </div>
          <p className="text-sm text-[#888] font-mono-data leading-relaxed mb-4">
            {feature.description}
          </p>
          <div className="flex flex-wrap gap-2">
            {feature.capabilities.map((cap) => (
              <span
                key={cap}
                className="text-[10px] bg-[rgba(0,240,255,0.05)] text-[#00f0ff]/70 px-2 py-1 rounded border border-[rgba(0,240,255,0.1)] font-mono-data"
              >
                {cap}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

export default function FeaturesSection() {
  return (
    <section id="features" className="relative py-24">
      {/* Background grid */}
      <div className="absolute inset-0 grid-pattern opacity-30" />

      <div className="relative z-10 max-w-6xl mx-auto px-4">
        {/* Section Header */}
        <div className="text-center mb-16">
          <div className="flex items-center justify-center gap-2 mb-4">
            <Scan className="w-4 h-4 text-[#00f0ff]" />
            <span className="label-tag text-[#00f0ff]">CORE CAPABILITIES</span>
          </div>
          <h2 className="font-heading text-3xl sm:text-4xl font-bold text-white mb-4">
            Defense in <span className="text-[#00f0ff] text-glow">Depth</span>
          </h2>
          <p className="text-[#888] text-sm font-mono-data max-w-2xl mx-auto">
            Multi-layered security analysis combining AI heuristics, global threat intelligence feeds, 
            and real-time behavioral analysis.
          </p>
        </div>

        {/* Features Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {features.map((feature, i) => (
            <FeatureCard key={feature.id} feature={feature} index={i} />
          ))}
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-8">
          {[
            { label: 'SCANNING ENGINES', value: '70+', icon: Zap },
            { label: 'THREAT FEEDS', value: '12', icon: AlertTriangle },
            { label: 'DAILY SCANS', value: '10K+', icon: Scan },
            { label: 'DETECTION RATE', value: '99.7%', icon: FileSearch },
          ].map((stat, i) => {
            const Icon = stat.icon;
            return (
              <div
                key={i}
                className="cyber-border bg-[#0a0a0a]/80 rounded-lg p-4 text-center"
              >
                <Icon className="w-5 h-5 text-[#00f0ff] mx-auto mb-2" />
                <div className="font-heading text-2xl font-bold text-white">{stat.value}</div>
                <div className="label-tag mt-1">{stat.label}</div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
