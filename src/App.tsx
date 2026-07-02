import { useCallback } from 'react';
import { Routes, Route } from 'react-router';
import Navigation from '@/components/custom/Navigation';
import HeroSection from '@/sections/HeroSection';
import ScanResults from '@/components/custom/ScanResults';
import FeaturesSection from '@/sections/FeaturesSection';
import AnalysisSection from '@/sections/AnalysisSection';
import ApiSourcesSection from '@/sections/ApiSourcesSection';
import Footer from '@/sections/Footer';
import { useScan } from '@/hooks/useScan';
import { Toaster } from '@/components/ui/sonner';
import { toast } from 'sonner';

function Home() {
  const { result, isScanning, scan, setResult } = useScan();

  const handleScan = useCallback(async (url: string) => {
    try {
      const data = await scan(url);
      if (data.isThreat) {
        toast.error(`THREAT DETECTED: Risk Score ${data.riskScore}/100`, {
          description: data.reasons[0] || 'Malicious URL identified',
          duration: 5000,
        });
      } else if (data.riskScore >= 25) {
        toast.warning(`SUSPICIOUS: Risk Score ${data.riskScore}/100`, {
          description: 'Potential security concerns found',
          duration: 4000,
        });
      } else {
        toast.success(`SAFE: Risk Score ${data.riskScore}/100`, {
          description: 'No threat vectors detected',
          duration: 3000,
        });
      }
    } catch (err) {
      toast.error('Scan Failed', {
        description: err instanceof Error ? err.message : 'Unable to analyze URL',
        duration: 5000,
      });
    }
  }, [scan]);

  return (
    <div className="min-h-screen bg-[#050505] text-white overflow-x-hidden">
      <Navigation />
      <HeroSection onScan={handleScan} isScanning={isScanning} />

      {/* Scan Results */}
      {result && <ScanResults result={result} />}

      {/* Loading State */}
      {isScanning && !result && (
        <div className="max-w-6xl mx-auto px-4 py-12">
          <div className="cyber-border bg-[#0a0a0a]/90 rounded-lg p-8 text-center">
            <div className="relative w-24 h-24 mx-auto mb-6">
              <div className="absolute inset-0 border-2 border-[rgba(0,240,255,0.1)] rounded-full" />
              <div className="absolute inset-0 border-2 border-t-[#00f0ff] rounded-full animate-spin" />
              <div className="absolute inset-4 border-2 border-[rgba(0,240,255,0.2)] rounded-full animate-pulse" />
            </div>
            <h3 className="font-heading text-xl font-bold text-white mb-2">
              ANALYZING TARGET...
            </h3>
            <p className="text-sm text-[#888] font-mono-data">
              Querying threat intelligence feeds and heuristic engines
            </p>
            <div className="mt-6 max-w-md mx-auto">
              <div className="h-1 bg-[#111] rounded-full overflow-hidden">
                <div className="h-full bg-gradient-to-r from-[#00f0ff] to-[#00f0ff]/50 rounded-full animate-pulse" style={{ width: '60%' }} />
              </div>
              <div className="flex justify-between mt-2 text-[10px] text-[#888] font-mono-data uppercase">
                <span>DNS</span>
                <span>SSL</span>
                <span>VT</span>
                <span>Heuristics</span>
                <span>AI</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Other Sections */}
      <FeaturesSection />
      <AnalysisSection />
      <ApiSourcesSection />
      <Footer />

      <Toaster
        position="top-right"
        toastOptions={{
          style: {
            background: '#0a0a0a',
            border: '1px solid rgba(0, 240, 255, 0.15)',
            color: '#ffffff',
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '12px',
          },
        }}
      />
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Home />} />
    </Routes>
  );
}
