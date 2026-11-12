'use client';

import { ShieldCheck, ShieldAlert, AlertTriangle, Clock } from 'lucide-react';

interface SourceCardProps {
  name: string;
  data: {
    isMalicious: boolean;
    riskScore: number;
    details: Record<string, any>;
    responseTimeMs: number;
    error?: string;
  };
}

export default function SourceCard({ name, data }: SourceCardProps) {
  const isError = Boolean(data.error);
  const isThreat = data.isMalicious;

  return (
    <div className="bg-slate-900/90 hover:bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-xl p-5 transition-all duration-200 flex flex-col justify-between shadow-lg">
      <div>
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            {isError ? (
              <AlertTriangle className="w-5 h-5 text-amber-400" />
            ) : isThreat ? (
              <ShieldAlert className="w-5 h-5 text-red-500" />
            ) : (
              <ShieldCheck className="w-5 h-5 text-emerald-400" />
            )}
            <h4 className="font-bold text-slate-100 text-base">{name}</h4>
          </div>

          <span
            className={`text-xs px-2.5 py-1 rounded-md font-bold ${
              isError
                ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                : isThreat
                ? 'bg-red-500/15 text-red-400 border border-red-500/30'
                : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
            }`}
          >
            {isError ? 'تعذر الفحص' : isThreat ? 'تهديد مرصود' : 'نظيف'}
          </span>
        </div>

        <div className="bg-slate-950/80 rounded-lg p-3 text-xs text-slate-300 space-y-1.5 border border-slate-800/60 font-mono overflow-x-auto">
          {isError ? (
            <p className="text-amber-400/90">السبب: {data.error}</p>
          ) : Object.keys(data.details || {}).length > 0 ? (
            Object.entries(data.details).map(([key, value]) => (
              <div key={key} className="flex justify-between gap-2">
                <span className="text-slate-500">{key}:</span>
                <span className="text-cyan-300 truncate max-w-[180px]">
                  {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                </span>
              </div>
            ))
          ) : (
            <p className="text-slate-500">لا توجد ملاحظات إضافية</p>
          )}
        </div>
      </div>

      <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
        <span className="flex items-center gap-1">
          <Clock className="w-3.5 h-3.5 text-cyan-500" />
          {data.responseTimeMs} ms
        </span>
        <span>وزن الخطر: {data.riskScore}%</span>
      </div>
    </div>
  );
}
