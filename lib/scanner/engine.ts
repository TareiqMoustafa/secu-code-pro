import { ComprehensiveScanResult, SourceResult, ThreatLevel } from './types';
import { checkVirusTotal } from './adapters/virustotal';
import { checkSafeBrowsing } from './adapters/safebrowsing';
import { checkURLhaus } from './adapters/urlhaus';
import { checkOpenPhish } from './adapters/openphish';
import { checkAbuseIPDB } from './adapters/abuseipdb';
import { checkWhoisDomainAge } from './adapters/whois';

export async function executeThreatAnalysis(targetUrl: string): Promise<ComprehensiveScanResult> {
  const startTime = Date.now();
  
  let domain = '';
  try {
    domain = new URL(targetUrl).hostname;
  } catch {
    domain = targetUrl;
  }

  const resultsSettled = await Promise.allSettled([
    checkVirusTotal(targetUrl),
    checkSafeBrowsing(targetUrl),
    checkURLhaus(targetUrl),
    checkOpenPhish(targetUrl),
    checkAbuseIPDB(domain),
    checkWhoisDomainAge(domain),
  ]);

  const sources: Record<string, SourceResult> = {};
  resultsSettled.forEach((result) => {
    if (result.status === 'fulfilled') {
      sources[result.value.source] = result.value;
    }
  });

  let totalScore = 0;
  let activeSourcesCount = 0;
  let maliciousFlags = 0;

  Object.values(sources).forEach((source) => {
    if (!source.error) {
      totalScore += source.riskScore;
      activeSourcesCount++;
      if (source.isMalicious) maliciousFlags++;
    }
  });

  const finalRiskScore = activeSourcesCount > 0 ? Math.round(totalScore / activeSourcesCount) : 0;

  let overallStatus: ThreatLevel = 'SAFE';
  if (maliciousFlags >= 2 || finalRiskScore >= 65) {
    overallStatus = 'MALICIOUS';
  } else if (maliciousFlags === 1 || finalRiskScore >= 25) {
    overallStatus = 'SUSPICIOUS';
  }

  return {
    url: targetUrl,
    domain,
    overallStatus,
    finalRiskScore,
    sources,
    scannedAt: new Date().toISOString(),
    executionTimeMs: Date.now() - startTime,
  };
}
