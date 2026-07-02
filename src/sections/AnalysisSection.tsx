import { useEffect, useRef, useState } from 'react';
import {
  Cpu, Lock, Globe, Search, Eye, FileWarning,
  ChevronRight, Terminal, Activity, Shield
} from 'lucide-react';

const analysisSteps = [
  {
    title: 'DNS Intelligence & Server Geolocation',
    description: 'Resolves A, AAAA, MX, NS, and TXT records. Maps server location to physical geography using ASN and IP geolocation databases.',
    icon: Globe,
    detail: 'Multi-DNS resolver with fallback to Google DNS and Cloudflare DNS. Identifies hosting provider, country, city, and organization.',
  },
  {
    title: 'SSL/TLS Certificate Grading',
    description: 'Validates certificate chain, checks expiry, identifies issuer, and assigns a security grade from A+ to F.',
    icon: Lock,
    detail: 'Detects self-signed certificates, expired certs, and weak cipher suites. MITM attack detection through certificate validation.',
  },
  {
    title: 'Typosquatting & Phishing Detection',
    description: 'Uses Levenshtein distance algorithms to detect brand impersonation. Scans for phishing keywords and suspicious patterns.',
    icon: Eye,
    detail: 'Checks against 30+ trusted domains. Identifies homograph attacks, credential-harvesting keywords, and social engineering patterns.',
  },
  {
    title: 'IP Reputation Analysis',
    description: 'Queries AbuseIPDB and IP intelligence feeds to identify known malicious hosts, VPNs, proxies, and Tor exit nodes.',
    icon: Shield,
    detail: 'Abuse confidence scoring, VPN/proxy detection, Tor node identification, and hosting provider risk assessment.',
  },
  {
    title: 'Heuristic Risk Scoring',
    description: 'Multi-factor algorithm combining all signals into a 0-100 risk score with detailed threat classification.',
    icon: Cpu,
    detail: 'Weighted scoring across 15+ threat vectors. Dynamic threshold adjustment based on global threat landscape.',
  },
];

export default function AnalysisSection() {
  const [activeStep, setActiveStep] = useState(0);
  const sectionRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          // Auto-advance steps when section is visible
          const interval = setInterval(() => {
            setActiveStep((prev) => (prev + 1) % analysisSteps.length);
          }, 3000);
          return () => clearInterval(interval);
        }
      },
      { threshold: 0.3 }
    );
    if (sectionRef.current) observer.observe(sectionRef.current);
    return () => observer.disconnect();
  }, []);

  return (
    <section id="analysis" ref={sectionRef} className="relative py-24">
      <div className="absolute inset-0 grid-pattern opacity-20" />

      <div className="relative z-10 max-w-6xl mx-auto px-4">
        {/* Section Header */}
        <div className="text-center mb-16">
          <div className="flex items-center justify-center gap-2 mb-4">
            <Terminal className="w-4 h-4 text-[#00f0ff]" />
            <span className="label-tag text-[#00f0ff]">NEURAL ANALYSIS ENGINE</span>
          </div>
          <h2 className="font-heading text-3xl sm:text-4xl font-bold text-white mb-4">
            Beyond <span className="text-[#00f0ff] text-glow">Blacklists</span>
          </h2>
          <p className="text-[#888] text-sm font-mono-data max-w-2xl mx-auto">
            Our heuristic engine dissects SSL certificates, domain age, URL structure, 
            and geopolitical data to assign a dynamic risk score.
          </p>
        </div>

        {/* Analysis Flow */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Steps List */}
          <div className="space-y-3">
            {analysisSteps.map((step, i) => {
              const Icon = step.icon;
              const isActive = i === activeStep;
              return (
                <button
                  key={i}
                  onClick={() => setActiveStep(i)}
                  className={`w-full text-left cyber-border rounded-lg p-4 transition-all duration-300 ${
                    isActive
                      ? 'bg-[rgba(0,240,255,0.05)] border-[#00f0ff]/40'
                      : 'bg-[#0a0a0a]/60 border-[rgba(0,240,255,0.08)] hover:border-[rgba(0,240,255,0.2)]'
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <div className={`w-10 h-10 rounded flex items-center justify-center transition-colors ${
                      isActive ? 'bg-[rgba(0,240,255,0.15)]' : 'bg-[rgba(0,240,255,0.05)]'
                    }`}>
                      <Icon className={`w-5 h-5 ${isActive ? 'text-[#00f0ff]' : 'text-[#00f0ff]/40'}`} />
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className={`text-xs font-mono-data ${isActive ? 'text-[#00f0ff]' : 'text-[#00f0ff]/30'}`}>
                          0{i + 1}.
                        </span>
                        <span className={`font-heading text-sm font-semibold ${isActive ? 'text-white' : 'text-[#888]'}`}>
                          {step.title}
                        </span>
                      </div>
                    </div>
                    <ChevronRight className={`w-4 h-4 transition-transform ${isActive ? 'text-[#00f0ff] translate-x-0' : 'text-[#555] -translate-x-1'}`} />
                  </div>
                </button>
              );
            })}
          </div>

          {/* Active Step Detail */}
          <div className="cyber-border bg-[#0a0a0a]/90 backdrop-blur-sm rounded-lg p-6 border-glow-animation">
            <div className="flex items-center gap-3 mb-6">
              {(() => {
                const Icon = analysisSteps[activeStep].icon;
                return <Icon className="w-8 h-8 text-[#00f0ff]" />;
              })()}
              <div>
                <span className="label-tag text-[#00f0ff]">STEP 0{activeStep + 1}</span>
                <h3 className="font-heading text-lg font-bold text-white mt-1">
                  {analysisSteps[activeStep].title}
                </h3>
              </div>
            </div>

            <p className="text-sm text-[#aaa] font-mono-data leading-relaxed mb-6">
              {analysisSteps[activeStep].description}
            </p>

            {/* Terminal-style detail */}
            <div className="bg-[#050505] rounded border border-[rgba(0,240,255,0.1)] p-4 font-mono-data">
              <div className="flex items-center gap-2 mb-3 pb-2 border-b border-[rgba(0,240,255,0.1)]">
                <div className="w-2.5 h-2.5 rounded-full bg-[#ff003c]" />
                <div className="w-2.5 h-2.5 rounded-full bg-[#ffaa00]" />
                <div className="w-2.5 h-2.5 rounded-full bg-[#00ff41]" />
                <span className="text-[10px] text-[#555] ml-2">analysis_engine.log</span>
              </div>
              <div className="space-y-1 text-xs">
                <div className="flex gap-2">
                  <span className="text-[#00f0ff]">$</span>
                  <span className="text-[#888]">initiating_{analysisSteps[activeStep].title.toLowerCase().replace(/\s+/g, '_')}...</span>
                </div>
                <div className="flex gap-2">
                  <span className="text-[#00f0ff]">&gt;</span>
                  <span className="text-[#00ff41]">OK</span>
                  <span className="text-[#888]">- {analysisSteps[activeStep].detail}</span>
                </div>
                <div className="flex gap-2">
                  <span className="text-[#00f0ff]">&gt;</span>
                  <span className="text-[#888]">Processing time: {(Math.random() * 0.5 + 0.1).toFixed(3)}s</span>
                </div>
                <div className="flex gap-2">
                  <span className="text-[#00f0ff]">$</span>
                  <span className="text-[#00f0ff] animate-pulse">_</span>
                </div>
              </div>
            </div>

            {/* Progress indicators */}
            <div className="flex items-center gap-2 mt-6">
              <Activity className="w-4 h-4 text-[#00f0ff]" />
              <div className="flex-1 h-1 bg-[#111] rounded-full overflow-hidden">
                <div
                  className="h-full bg-[#00f0ff] rounded-full transition-all duration-500"
                  style={{ width: `${((activeStep + 1) / analysisSteps.length) * 100}%` }}
                />
              </div>
              <span className="text-xs text-[#888] font-mono-data">
                {activeStep + 1}/{analysisSteps.length}
              </span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
