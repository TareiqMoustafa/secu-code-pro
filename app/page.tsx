'use client';

import { useState } from 'react';
import { Shield, Search, Globe, Activity, Zap, History, CheckCircle2 } from 'lucide-react';
import RiskGauge from '@/components/RiskGauge';
import SourceCard from '@/components/SourceCard';

export default function Home() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const [result, setResult] = useState<any>(null);
  const [isCached, setIsCached] = useState(false);
  const [recentHistory, setRecentHistory] = useState<any[]>([]);

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setErrorMsg('');
    setResult(null);

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.trim() }),
      });
      const data = await res.json();

      if (!res.ok || !data.success) {
        setErrorMsg(data.error || 'حدث خطأ أثناء تحليل الرابط');
      } else {
        setResult(data.data);
        setIsCached(Boolean(data.cached));
        setRecentHistory((prev) => [data.data, ...prev.slice(0, 4)]);
      }
    } catch (err) {
      setErrorMsg('فشل الاتصال بالخادم، تأكد من تشغيل السيرفر.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#020617] text-slate-100 flex flex-col relative overflow-x-hidden">
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[350px] bg-cyan-500/10 blur-[120px] rounded-full pointer-events-none" />

      <header className="border-b border-slate-800/80 bg-slate-950/70 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyan-500/10 border border-cyan-500/30 rounded-lg">
              <Shield className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <span className="text-xl font-black tracking-wider text-white">
                SecuCode<span className="text-cyan-400">_Pro</span>
              </span>
              <span className="hidden sm:inline-block mr-3 text-[11px] bg-slate-800 text-cyan-300 px-2 py-0.5 rounded-full">
                v2.0 Threat Engine
              </span>
            </div>
          </div>

          <div className="flex items-center gap-4 text-xs text-slate-400">
            <span className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              6 محركات فحص نشطة
            </span>
          </div>
        </div>
      </header>

      <main className="flex-1 max-w-6xl w-full mx-auto px-6 py-12 space-y-12 z-10">
        <section className="text-center max-w-3xl mx-auto space-y-6">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-800/50 text-cyan-300 text-xs font-medium">
            <Zap className="w-3.5 h-3.5" />
            تحليل فوري متعدد المصادر للكشف عن التصيد والبرمجيات الخبيثة
          </div>

          <h1 className="text-3xl sm:text-5xl font-black tracking-tight text-white leading-tight">
            افحص أي رابط قبل زيارته بدقة{' '}
            <span className="text-transparent bg-clip-text bg-gradient-to-l from-cyan-400 to-blue-500">
              استخباراتية شاملة
            </span>
          </h1>

          <p className="text-slate-400 text-sm sm:text-base">
            يقوم محرك SecuCode_Pro بتحليل الروابط والنطاقات عبر VirusTotal و Google Safe Browsing و URLhaus و OpenPhish و AbuseIPDB وسجلات WHOIS في أجزاء من الثانية.
          </p>

          <form onSubmit={handleScan} className="relative flex flex-col sm:flex-row gap-3 pt-2">
            <div className="relative flex-1">
              <Globe className="w-5 h-5 text-slate-500 absolute right-4 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="أدخل الرابط هنا... مثال: https://example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                dir="ltr"
                className="w-full bg-slate-900/90 border border-slate-700/80 focus:border-cyan-500 rounded-xl pr-12 pl-4 py-4 text-white placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/20 transition-all text-left"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold px-8 py-4 rounded-xl transition-all shadow-lg shadow-cyan-500/20 flex items-center justify-center gap-2 disabled:opacity-50 cursor-pointer"
            >
              {loading ? (
                <>
                  <Activity className="w-5 h-5 animate-spin" />
                  جاري التحليل...
                </>
              ) : (
                <>
                  <Search className="w-5 h-5" />
                  بدء الفحص
                </>
              )}
            </button>
          </form>

          {errorMsg && (
            <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
              {errorMsg}
            </div>
          )}
        </section>

        {result && (
          <section className="space-y-6">
            <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-6 sm:p-8 backdrop-blur-md shadow-2xl">
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 items-center">
                <RiskGauge score={result.finalRiskScore} status={result.overallStatus} />

                <div className="lg:col-span-2 space-y-4">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-4">
                    <div>
                      <span className="text-xs text-slate-400 block">النطاق المستهدف (Domain)</span>
                      <h2 className="text-2xl font-bold text-white font-mono" dir="ltr">
                        {result.domain}
                      </h2>
                    </div>
                    {isCached && (
                      <span className="inline-flex items-center gap-1.5 text-xs bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 px-3 py-1 rounded-full">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        مسترجع من الذاكرة المؤقتة الذكية
                      </span>
                    )}
                  </div>

                  <div className="space-y-2 text-sm">
                    <div className="flex flex-col sm:flex-row sm:justify-between bg-slate-950/60 p-3 rounded-lg border border-slate-800/60">
                      <span className="text-slate-400">الرابط الكامل:</span>
                      <span className="text-slate-200 font-mono truncate max-w-md" dir="ltr">
                        {result.url}
                      </span>
                    </div>
                    <div className="grid grid-cols-2 gap-3">
                      <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800/60">
                        <span className="text-slate-400 block text-xs">زمن التحليل الكلي</span>
                        <span className="text-cyan-400 font-bold">{result.executionTimeMs} ms</span>
                      </div>
                      <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800/60">
                        <span className="text-slate-400 block text-xs">توقيت الفحص</span>
                        <span className="text-slate-200 font-mono text-xs">
                          {new Date(result.scannedAt).toLocaleTimeString('ar-EG')}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="mt-8 pt-8 border-t border-slate-800">
                <h3 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
                  <Activity className="w-5 h-5 text-cyan-400" />
                  تقارير محركات الاستخبارات ({Object.keys(result.sources).length} مصادر)
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {Object.entries(result.sources).map(([sourceName, sourceData]: [string, any]) => (
                    <SourceCard key={sourceName} name={sourceName} data={sourceData} />
                  ))}
                </div>
              </div>
            </div>
          </section>
        )}

        {recentHistory.length > 0 && (
          <section className="bg-slate-900/50 border border-slate-800/80 rounded-2xl p-6">
            <h3 className="text-sm font-bold text-slate-300 mb-4 flex items-center gap-2">
              <History className="w-4 h-4 text-cyan-400" />
              آخر الروابط التي قمت بفحصها الآن
            </h3>
            <div className="space-y-2">
              {recentHistory.map((item, idx) => (
                <div
                  key={idx}
                  onClick={() => setResult(item)}
                  className="flex items-center justify-between p-3 rounded-lg bg-slate-950/70 hover:bg-slate-900 border border-slate-800/60 cursor-pointer transition-colors text-xs"
                >
                  <span className="font-mono text-slate-300 truncate max-w-md" dir="ltr">
                    {item.url}
                  </span>
                  <span
                    className={`px-2.5 py-0.5 rounded font-bold ${
                      item.overallStatus === 'SAFE'
                        ? 'text-emerald-400 bg-emerald-500/10'
                        : item.overallStatus === 'SUSPICIOUS'
                        ? 'text-amber-400 bg-amber-500/10'
                        : 'text-red-400 bg-red-500/10'
                    }`}
                  >
                    {item.overallStatus} ({item.finalRiskScore}%)
                  </span>
                </div>
              ))}
            </div>
          </section>
        )}
      </main>

      <footer className="border-t border-slate-800/80 bg-slate-950 py-6 text-center text-xs text-slate-500 z-10">
        <p>
          جميع الحقوق محفوظة © 2026 | تم التطوير والهندسة بواسطة{' '}
          <span className="text-cyan-400 font-semibold">طارق مصطفى</span> و{' '}
          <span className="text-cyan-400 font-semibold">مازن عمرو</span>
        </p>
      </footer>
    </div>
  );
}
