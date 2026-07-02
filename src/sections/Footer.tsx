import { Shield, Github, Twitter, Mail, ExternalLink, Heart } from 'lucide-react';

export default function Footer() {
  const currentYear = new Date().getFullYear();

  return (
    <footer className="relative py-16 border-t border-[rgba(0,240,255,0.08)]">
      <div className="absolute inset-0 grid-pattern opacity-10" />

      <div className="relative z-10 max-w-6xl mx-auto px-4">
        {/* Main Footer Content */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-12">
          {/* Brand */}
          <div className="md:col-span-2">
            <div className="flex items-center gap-2 mb-4">
              <Shield className="w-6 h-6 text-[#00f0ff]" />
              <span className="font-heading text-xl font-bold tracking-tight">
                SECU<span className="text-[#00f0ff]">CODE</span> PRO
              </span>
            </div>
            <p className="text-sm text-[#888] font-mono-data leading-relaxed max-w-md mb-4">
              Advanced threat intelligence platform for URL analysis and phishing detection.
              Protecting digital perimeters with multi-vector scanning and AI-powered heuristics.
            </p>
            <div className="flex items-center gap-3">
              <a
                href="https://github.com/TareiqMoustafa/secu-code-pro"
                target="_blank"
                rel="noopener noreferrer"
                className="w-9 h-9 rounded bg-[rgba(0,240,255,0.05)] border border-[rgba(0,240,255,0.1)] flex items-center justify-center text-[#888] hover:text-[#00f0ff] hover:border-[#00f0ff]/30 transition-all"
              >
                <Github className="w-4 h-4" />
              </a>
              <a
                href="#"
                className="w-9 h-9 rounded bg-[rgba(0,240,255,0.05)] border border-[rgba(0,240,255,0.1)] flex items-center justify-center text-[#888] hover:text-[#00f0ff] hover:border-[#00f0ff]/30 transition-all"
              >
                <Twitter className="w-4 h-4" />
              </a>
              <a
                href="mailto:contact@secucode.pro"
                className="w-9 h-9 rounded bg-[rgba(0,240,255,0.05)] border border-[rgba(0,240,255,0.1)] flex items-center justify-center text-[#888] hover:text-[#00f0ff] hover:border-[#00f0ff]/30 transition-all"
              >
                <Mail className="w-4 h-4" />
              </a>
            </div>
          </div>

          {/* Links */}
          <div>
            <h4 className="label-tag text-[#00f0ff] mb-4">PLATFORM</h4>
            <ul className="space-y-2">
              {['URL Scanner', 'Bulk Analysis', 'API Access', 'PDF Reports', 'Threat Feed'].map((link) => (
                <li key={link}>
                  <button className="text-sm text-[#888] hover:text-[#00f0ff] transition-colors font-mono-data flex items-center gap-1">
                    <ExternalLink className="w-3 h-3" />
                    {link}
                  </button>
                </li>
              ))}
            </ul>
          </div>

          <div>
            <h4 className="label-tag text-[#00f0ff] mb-4">RESOURCES</h4>
            <ul className="space-y-2">
              {['Documentation', 'Privacy Policy', 'Terms of Service', 'Contact'].map((link) => (
                <li key={link}>
                  <button className="text-sm text-[#888] hover:text-[#00f0ff] transition-colors font-mono-data flex items-center gap-1">
                    <ExternalLink className="w-3 h-3" />
                    {link}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="pt-8 border-t border-[rgba(0,240,255,0.06)] flex flex-col sm:flex-row items-center justify-between gap-4">
          <p className="text-xs text-[#555] font-mono-data">
            &copy; {currentYear} SECUCODE PRO. ALL SYSTEMS NOMINAL.
          </p>
          <p className="text-xs text-[#555] font-mono-data flex items-center gap-1">
            Built with <Heart className="w-3 h-3 text-[#ff003c]" /> by Tarek Mostafa
          </p>
        </div>
      </div>
    </footer>
  );
}
