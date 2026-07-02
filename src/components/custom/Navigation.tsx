import { useState, useEffect } from 'react';
import { Shield, Menu, X } from 'lucide-react';

export default function Navigation() {
  const [scrolled, setScrolled] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 50);
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const navLinks = [
    { label: 'Dashboard', href: '#dashboard' },
    { label: 'Analysis', href: '#analysis' },
    { label: 'Features', href: '#features' },
    { label: 'API', href: '#api' },
  ];

  const scrollToSection = (href: string) => {
    const el = document.querySelector(href);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
    setMobileOpen(false);
  };

  return (
    <nav
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-500 ${
        scrolled
          ? 'bg-[#050505]/90 backdrop-blur-xl border-b border-[rgba(0,240,255,0.1)]'
          : 'bg-transparent'
      }`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <div className="flex items-center gap-2">
            <Shield className="w-6 h-6 text-[#00f0ff]" />
            <span className="font-heading text-lg font-bold tracking-tight">
              SECU<span className="text-[#00f0ff]">CODE</span> PRO
            </span>
          </div>

          {/* Desktop Nav */}
          <div className="hidden md:flex items-center gap-8">
            {navLinks.map((link) => (
              <button
                key={link.label}
                onClick={() => scrollToSection(link.href)}
                className="text-sm text-[#888] hover:text-[#00f0ff] transition-colors duration-300 font-mono-data uppercase tracking-wider"
              >
                {link.label}
              </button>
            ))}
          </div>

          {/* CTA Buttons */}
          <div className="hidden md:flex items-center gap-3">
            <button className="cyber-btn-outline px-4 py-2 rounded text-xs">
              Login
            </button>
            <button className="cyber-btn px-4 py-2 rounded text-xs">
              Get Started
            </button>
          </div>

          {/* Mobile menu button */}
          <button
            className="md:hidden text-[#00f0ff]"
            onClick={() => setMobileOpen(!mobileOpen)}
          >
            {mobileOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
          </button>
        </div>
      </div>

      {/* Mobile menu */}
      {mobileOpen && (
        <div className="md:hidden bg-[#0a0a0a]/95 backdrop-blur-xl border-b border-[rgba(0,240,255,0.1)]">
          <div className="px-4 py-4 space-y-3">
            {navLinks.map((link) => (
              <button
                key={link.label}
                onClick={() => scrollToSection(link.href)}
                className="block w-full text-left text-sm text-[#888] hover:text-[#00f0ff] transition-colors py-2 font-mono-data uppercase"
              >
                {link.label}
              </button>
            ))}
            <div className="flex gap-3 pt-3 border-t border-[rgba(0,240,255,0.1)]">
              <button className="cyber-btn-outline px-4 py-2 rounded text-xs flex-1">
                Login
              </button>
              <button className="cyber-btn px-4 py-2 rounded text-xs flex-1">
                Get Started
              </button>
            </div>
          </div>
        </div>
      )}
    </nav>
  );
}
