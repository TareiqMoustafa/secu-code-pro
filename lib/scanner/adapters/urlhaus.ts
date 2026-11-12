import { SourceResult } from '../types';

export async function checkURLhaus(url: string): Promise<SourceResult> {
  const startTime = Date.now();
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 6000);

    const response = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ url }),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);

    const data = await response.json();
    const isMalicious = data.query_status === 'ok';
    const riskScore = isMalicious ? 90 : 0;

    return {
      source: 'URLhaus',
      isMalicious,
      riskScore,
      details: { query_status: data.query_status, threat: data.threat || null },
      responseTimeMs: Date.now() - startTime,
    };
  } catch (error: any) {
    return {
      source: 'URLhaus',
      isMalicious: false,
      riskScore: 0,
      details: {},
      responseTimeMs: Date.now() - startTime,
      error: error.message,
    };
  }
}
