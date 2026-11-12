import { SourceResult } from '../types';

export async function checkVirusTotal(url: string): Promise<SourceResult> {
  const startTime = Date.now();
  const apiKey = process.env.VIRUSTOTAL_API_KEY;

  if (!apiKey) {
    return {
      source: 'VirusTotal',
      isMalicious: false,
      riskScore: 0,
      details: { message: 'API key not configured' },
      responseTimeMs: Date.now() - startTime,
      error: 'Missing API Key',
    };
  }

  try {
    const encodedUrl = Buffer.from(url).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${encodedUrl}`, {
      headers: { 'x-apikey': apiKey },
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      if (response.status === 404) {
        return { source: 'VirusTotal', isMalicious: false, riskScore: 0, details: { status: 'URL not found' }, responseTimeMs: Date.now() - startTime };
      }
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    const stats = data.data?.attributes?.last_analysis_stats || {};
    const maliciousCount = stats.malicious || 0;
    const suspiciousCount = stats.suspicious || 0;
    
    const isMalicious = maliciousCount > 0 || suspiciousCount > 1;
    const riskScore = isMalicious ? Math.min(100, (maliciousCount * 25) + (suspiciousCount * 10)) : 0;

    return {
      source: 'VirusTotal',
      isMalicious,
      riskScore,
      details: { stats, maliciousCount, suspiciousCount },
      responseTimeMs: Date.now() - startTime,
    };
  } catch (error: any) {
    return {
      source: 'VirusTotal',
      isMalicious: false,
      riskScore: 0,
      details: {},
      responseTimeMs: Date.now() - startTime,
      error: error.message || 'Timeout or network error',
    };
  }
}
