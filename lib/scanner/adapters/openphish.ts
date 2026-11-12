import { SourceResult } from '../types';

export async function checkOpenPhish(url: string): Promise<SourceResult> {
  const startTime = Date.now();
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const response = await fetch('https://openphish.com/feed.txt', {
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);

    const text = await response.text();
    const urls = text.split('\n').map(u => u.trim());
    const isMalicious = urls.includes(url);
    const riskScore = isMalicious ? 95 : 0;

    return {
      source: 'OpenPhish',
      isMalicious,
      riskScore,
      details: { listedInFeed: isMalicious },
      responseTimeMs: Date.now() - startTime,
    };
  } catch (error: any) {
    return {
      source: 'OpenPhish',
      isMalicious: false,
      riskScore: 0,
      details: {},
      responseTimeMs: Date.now() - startTime,
      error: error.message,
    };
  }
}
