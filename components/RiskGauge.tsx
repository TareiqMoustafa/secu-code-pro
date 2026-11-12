'use client';

interface RiskGaugeProps {
  score: number;
  status: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
}

export default function RiskGauge({ score, status }: RiskGaugeProps) {
  const getColor = () => {
    if (status === 'MALICIOUS') return { text: 'text-red-500', stroke: '#ef4444', bg: 'bg-red-500/10', label: 'خطير جداً' };
    if (status === 'SUSPICIOUS') return { text: 'text-amber-400', stroke: '#f59e0b', bg: 'bg-amber-500/10', label: 'مشبوه' };
    return { text: 'text-emerald-400', stroke: '#10b981', bg: 'bg-emerald-500/10', label: 'آمن تماماً' };
  };

  const style = getColor();
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className={`flex flex-col items-center justify-center p-6 rounded-2xl border border-slate-800 ${style.bg} backdrop-blur-sm`}>
      <div className="relative flex items-center justify-center">
        <svg className="w-36 h-36 transform -rotate-90">
          <circle
            cx="72"
            cy="72"
            r={radius}
            stroke="currentColor"
            strokeWidth="10"
            fill="transparent"
            className="text-slate-800"
          />
          <circle
            cx="72"
            cy="72"
            r={radius}
            stroke={style.stroke}
            strokeWidth="10"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-1000 ease-out"
          />
        </svg>
        <div className="absolute flex flex-col items-center">
          <span className={`text-3xl font-black ${style.text}`}>{score}%</span>
          <span className="text-[11px] text-slate-400 font-medium">درجة الخطر</span>
        </div>
      </div>
      <div className={`mt-3 px-4 py-1 rounded-full text-xs font-bold tracking-wide uppercase border border-current ${style.text}`}>
        {style.label} ({status})
      </div>
    </div>
  );
}
