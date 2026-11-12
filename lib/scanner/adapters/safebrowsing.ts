import { SourceResult } from '../types';

export async function checkSafeBrowsing(url: string): Promise<SourceResult> {
  const startTime = Date.now();
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

  if (!apiKey) {
    return {
      source: 'Google Safe Browsing',
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

    const requestBody = {
      client: { clientId: 'secucode-pro', clientVersion: '1.0.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }],
      },
    };

    const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestBody),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);

    const data = await response.json();
    const isMalicious = Boolean(data.matches && data.matches.length > 0);
    const riskScore = isMalicious ? 100 : 0;

    return {
      source: 'Google Safe Browsing',
      isMalicious,
      riskScore,
      details: { matches: data.matches || [] },
      responseTimeMs: Date.now() - startTime,
    };
  } catch (error: any) {
    return {
      source: 'Google Safe Browsing',
      isMalicious: false,
      riskScore: 0,
      details: {},
      responseTimeMs: Date.now() - startTime,
      error: error.message,
    };
  }
}
