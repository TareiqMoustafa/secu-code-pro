import { SourceResult } from '../types';

export async function checkAbuseIPDB(domain: string): Promise<SourceResult> {
  const startTime = Date.now();
  const apiKey = process.env.ABUSEIPDB_API_KEY;

  if (!apiKey) {
    return {
      source: 'AbuseIPDB',
      isMalicious: false,
      riskScore: 0,
      details: { message: 'API key not configured' },
      responseTimeMs: Date.now() - startTime,
      error: 'Missing API Key',
    };
  }

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 6000);

    const ipRes = await fetch(`https://dns.google/resolve?name=${domain}`);
    const ipData = await ipRes.json();
    const ip = ipData.Answer?.[0]?.data;

    if (!ip) {
      return { source: 'AbuseIPDB', isMalicious: false, riskScore: 0, details: { message: 'Could resolve IP' }, responseTimeMs: Date.now() - startTime };
    }

    const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`, {
      headers: { 'Key': apiKey, 'Accept': 'application/json' },
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);

    const data = await response.json();
    const abuseScore = data.data?.abuseConfidenceScore || 0;
    const isMalicious = abuseScore > 50;

    return {
      source: 'AbuseIPDB',
      isMalicious,
      riskScore: abuseScore,
      details: { ip, abuseConfidenceScore: abuseScore, totalReports: data.data?.totalReports || 0 },
      responseTimeMs: Date.now() - startTime,
    };
  } catch (error: any) {
    return {
      source: 'AbuseIPDB',
      isMalicious: false,
      riskScore: 0,
      details: {},
      responseTimeMs: Date.now() - startTime,
      error: error.message,
    };
  }
}
