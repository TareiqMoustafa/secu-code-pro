import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'SecuCode_Pro | Professional Threat Intelligence Platform',
  description: 'منصة تحليل الروابط واستخبارات التهديدات السيبرانية المتقدمة',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="ar" dir="rtl">
      <body className="bg-slate-950 text-slate-100 antialiased min-h-screen selection:bg-cyan-500 selection:text-white">
        {children}
      </body>
    </html>
  );
}
