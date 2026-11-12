import { SourceResult } from '../types';

export async function checkWhoisDomainAge(domain: string): Promise<SourceResult> {
  const startTime = Date.now();
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 6000);

    const response = await fetch(`https://rdap.org/domain/${domain}`, {
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      return { source: 'WHOIS/RDAP', isMalicious: false, riskScore: 0, details: { status: 'Domain info not found' }, responseTimeMs: Date.now() - startTime };
    }

    const data = await response.json();
    const events = data.events || [];
    const registrationEvent = events.find((e: any) => e.eventAction === 'registration');
    
    let isSuspiciouslyYoung = false;
    let ageInDays = null;

    if (registrationEvent && registrationEvent.eventDate) {
      const regDate = new Date(registrationEvent.eventDate);
      const now = new Date();
      ageInDays = Math.floor((now.getTime() - regDate.getTime()) / (1000 * 3600 * 24));
      if (ageInDays < 30) {
        isSuspiciouslyYoung = true;
      }
    }

    const riskScore = isSuspiciouslyYoung ? 60 : 0;

    return {
      source: 'WHOIS/RDAP',
      isMalicious: isSuspiciouslyYoung,
      riskScore,
      details: { ageInDays, registrationDate: registrationEvent?.eventDate || 'Unknown' },
      responseTimeMs: Date.now() - startTime,
    };
  } catch (error: any) {
    return {
      source: 'WHOIS/RDAP',
      isMalicious: false,
      riskScore: 0,
      details: {},
      responseTimeMs: Date.now() - startTime,
      error: error.message,
    };
  }
}
