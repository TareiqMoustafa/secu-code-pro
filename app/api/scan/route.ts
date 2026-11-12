import { NextRequest, NextResponse } from 'next/server';
import { executeThreatAnalysis } from '@/lib/scanner/engine';
import { checkCacheAndLists, saveScanResult } from '@/lib/scanner/cache';

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { url } = body;

    if (!url || typeof url !== 'string') {
      return NextResponse.json({ success: false, error: 'Invalid or missing URL parameter' }, { status: 400 });
    }

    let formattedUrl = url.trim();
    if (!formattedUrl.startsWith('http://') && !formattedUrl.startsWith('https://')) {
      formattedUrl = `https://${formattedUrl}`;
    }

    let domain = '';
    try {
      domain = new URL(formattedUrl).hostname;
    } catch {
      domain = formattedUrl;
    }

    const cachedResult = await checkCacheAndLists(formattedUrl, domain);
    if (cachedResult) {
      return NextResponse.json({ success: true, data: cachedResult, cached: true }, { status: 200 });
    }

    const analysisResult = await executeThreatAnalysis(formattedUrl);
    await saveScanResult(analysisResult);

    return NextResponse.json({ success: true, data: analysisResult, cached: false }, { status: 200 });
  } catch (error: any) {
    console.error('SecuCode_Pro API Error:', error);
    return NextResponse.json({ success: false, error: 'Internal Server Error during security analysis' }, { status: 500 });
  }
}
