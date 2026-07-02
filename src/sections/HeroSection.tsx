import { useState, useEffect, useRef, useCallback } from 'react';
import Globe from '@/components/custom/Globe';
import { Scan, Terminal, Activity, ChevronRight } from 'lucide-react';
import { trpc } from '@/providers/trpc';

interface HeroSectionProps {
  onScan: (url: string) => void;
  isScanning: boolean;
}

function ScrambleText({ text, delay = 0, className = '' }: { text: string; delay?: number; className?: string }) {
  const [display, setDisplay] = useState('');
  const [started, setStarted] = useState(false);
  const iterationRef = useRef(0);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const glyphs = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';

  useEffect(() => {
    const timeout = setTimeout(() => setStarted(true), delay);
    return () => clearTimeout(timeout);
  }, [delay]);

  useEffect(() => {
    if (!started) return;

    intervalRef.current = setInterval(() => {
      const iteration = iterationRef.current;
      let result = '';
      for (let i = 0; i < text.length; i++) {
        if (i < iteration) {
          result += text[i];
        } else if (text[i] === ' ') {
          result += ' ';
        } else {
          result += glyphs[Math.floor(Math.random() * glyphs.length)];
        }
      }
      setDisplay(result);
      iterationRef.current += 0.5;
      if (iteration >= text.length) {
        if (intervalRef.current) clearInterval(intervalRef.current);
      }
    }, 30);

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [started, text]);

  return <span className={className}>{started ? display : text.replace(/./g, ' ')}</span>;
}

function AnimatedCounter({ end, duration = 2000 }: { end: number; duration?: number }) {
  const [count, setCount] = useState(0);
  const [visible, setVisible] = useState(false);
  const ref = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setVisible(true);
        }
      },
      { threshold: 0.5 }
    );
    if (ref.current) observer.observe(ref.current);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!visible) return;
    let start = 0;
    const increment = end / (duration / 16);
    const timer = setInterval(() => {
      start += increment;
      if (start >= end) {
        setCount(end);
        clearInterval(timer);
      } else {
        setCount(Math.floor(start));
      }
    }, 16);
    return () => clearInterval(timer);
  }, [visible, end, duration]);

  return <span ref={ref}>{count.toLocaleString()}</span>;
}

export default function HeroSection({ onScan, isScanning }: HeroSectionProps) {
  const [url, setUrl] = useState('');
  const statsQuery = trpc.scan.stats.useQuery();

  const handleSubmit = useCallback((e: React.FormEvent) => {
    e.preventDefault();
    if (url.trim() && !isScanning) {
      onScan(url.trim());
    }
  }, [url, isScanning, onScan]);

  return (
    <section className="relative min-h-screen flex flex-col items-center justify-center overflow-hidden">
      {/* Background Globe */}
      <Globe />

      {/* Scan line effect */}
      <div className="scan-line" />

      {/* Grid pattern overlay */}
      <div className="absolute inset-0 grid-pattern opacity-50 pointer-events-none" style={{ zIndex: 2 }} />

      {/* Content */}
      <div className="relative z-10 text-center px-4 max-w-4xl mx-auto mt-16">
        {/* Label */}
        <div className="flex items-center justify-center gap-2 mb-6">
          <div className="status-dot secure" />
          <span className="label-tag text-[#00f0ff]">SYSTEM OPERATIONAL</span>
        </div>

        {/* Main Heading */}
        <h1 className="font-heading text-5xl sm:text-6xl md:text-7xl lg:text-8xl font-bold tracking-tight mb-4">
          <div className="text-glow">
            <ScrambleText text="THREAT" delay={300} />
          </div>
          <div className="text-[#00f0ff] text-glow">
            <ScrambleText text="INTELLIGENCE" delay={800} />
          </div>
        </h1>

        {/* Subtitle */}
        <p className="text-[#888] text-sm sm:text-base font-mono-data mt-6 mb-10 max-w-xl mx-auto">
          Analyze URLs. Detect phishing. Secure the perimeter.
        </p>

        {/* Scan Input */}
        <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-3 max-w-2xl mx-auto">
          <div className="relative flex-1">
            <Terminal className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-[#00f0ff]/50" />
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="> enter target URL..."
              className="cyber-input w-full pl-12 pr-4 py-4 rounded-lg text-sm"
              disabled={isScanning}
            />
          </div>
          <button
            type="submit"
            disabled={isScanning || !url.trim()}
            className="cyber-btn px-8 py-4 rounded-lg text-sm flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isScanning ? (
              <>
                <Activity className="w-4 h-4 animate-spin" />
                SCANNING...
              </>
            ) : (
              <>
                <Scan className="w-4 h-4" />
                SCAN NOW
              </>
            )}
          </button>
        </form>

        {/* Quick actions */}
        <div className="flex flex-wrap items-center justify-center gap-4 mt-6">
          <span className="text-[#555] text-xs font-mono-data">TRY:</span>
          {['google.com', 'suspicious-site.xyz', 'paypal-verify.com'].map((demo) => (
            <button
              key={demo}
              onClick={() => { setUrl(demo); onScan(demo); }}
              className="text-[#00f0ff]/60 hover:text-[#00f0ff] text-xs font-mono-data flex items-center gap-1 transition-colors"
            >
              <ChevronRight className="w-3 h-3" />
              {demo}
            </button>
          ))}
        </div>
      </div>

      {/* Live Stats Bar */}
      <div id="dashboard" className="relative z-10 w-full max-w-6xl mx-auto px-4 mt-16 mb-8">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            {
              label: 'SYSTEM STATUS',
              value: (
                <span className="flex items-center gap-2">
                  <div className="status-dot secure" />
                  <span className="text-[#00ff41]">SECURE</span>
                </span>
              ),
              raw: null,
            },
            {
              label: 'TOTAL SCANNED',
              value: statsQuery.data?.totalScanned || 2402991,
              raw: statsQuery.data?.totalScanned || 2402991,
            },
            {
              label: 'THREATS DETECTED',
              value: statsQuery.data?.threatsDetected || 18402,
              raw: statsQuery.data?.threatsDetected || 18402,
            },
            {
              label: 'ACTIVE NODES',
              value: (
                <span>
                  <span className="text-[#00f0ff]">{statsQuery.data?.uptime || '99.9%'}</span>
                  <span className="text-[#888] text-xs ml-1">UPTIME</span>
                </span>
              ),
              raw: null,
            },
          ].map((stat, i) => (
            <div
              key={i}
              className="cyber-border bg-[#0a0a0a]/80 backdrop-blur-sm rounded-lg p-4 border-glow-animation"
            >
              <div className="label-tag mb-2">{stat.label}</div>
              <div className="font-heading text-xl sm:text-2xl font-bold text-white">
                {stat.raw !== null ? (
                  <AnimatedCounter end={stat.raw as number} />
                ) : (
                  stat.value
                )}
              </div>
            </div>
          ))}
        </div>

        {/* Threat Feed Ticker */}
        <div className="mt-4 cyber-border bg-[#0a0a0a]/80 backdrop-blur-sm rounded-lg p-3 overflow-hidden">
          <div className="flex items-center gap-3">
            <div className="status-dot threat flex-shrink-0" />
            <span className="label-tag text-[#ff003c] flex-shrink-0">LIVE THREATS</span>
            <div className="overflow-hidden flex-1">
              <div className="marquee-track whitespace-nowrap">
                {[...Array(2)].map((_, setIdx) => (
                  <span key={setIdx} className="inline-flex gap-8 mr-8">
                    {[
                      'malware-distribution.xyz detected distributing trojans',
                      'paypa1-verification.com confirmed phishing campaign',
                      'free-gifts-winner.top social engineering attack',
                      'secure-login-verify.net credential harvesting',
                      'crypto-wallet-connect scam identified',
                      'account-suspension-alert.click urgency manipulation',
                    ].map((threat, j) => (
                      <span key={j} className="text-xs text-[#ff003c]/70 font-mono-data">
                        [{new Date().toISOString().slice(0, 10)}] {threat}
                      </span>
                    ))}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
