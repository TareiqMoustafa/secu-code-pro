import { PrismaClient } from '@prisma/client';
import { ComprehensiveScanResult } from './types';

const prisma = new PrismaClient();

export async function checkCacheAndLists(url: string, domain: string) {
  try {
    const blacklisted = await prisma.blacklist.findUnique({
      where: { domain },
    });

    if (blacklisted) {
      return {
        url,
        domain,
        overallStatus: 'MALICIOUS' as const,
        finalRiskScore: 100,
        sources: {
          'SecuCode_Pro Security Engine': {
            source: 'SecuCode_Pro Security Engine',
            isMalicious: true,
            riskScore: 100,
            details: { reason: blacklisted.reason || 'Found in system Blacklist' },
            responseTimeMs: 1,
          }
        },
        scannedAt: new Date().toISOString(),
        executionTimeMs: 1,
      };
    }

    const whitelisted = await prisma.whitelist.findUnique({
      where: { domain },
    });

    if (whitelisted) {
      return {
        url,
        domain,
        overallStatus: 'SAFE' as const,
        finalRiskScore: 0,
        sources: {
          'SecuCode_Pro Security Engine': {
            source: 'SecuCode_Pro Security Engine',
            isMalicious: false,
            riskScore: 0,
            details: { reason: 'Found in system Whitelist' },
            responseTimeMs: 1,
          }
        },
        scannedAt: new Date().toISOString(),
        executionTimeMs: 1,
      };
    }

    const recentScan = await prisma.scan.findFirst({
      where: {
        domain,
        createdAt: {
          gte: new Date(Date.now() - 24 * 60 * 60 * 1000),
        },
      },
      orderBy: { createdAt: 'desc' },
    });

    if (recentScan) {
      return {
        url: recentScan.url,
        domain: recentScan.domain,
        overallStatus: recentScan.overallStatus as any,
        finalRiskScore: recentScan.riskScore,
        sources: recentScan.sourcesData as any,
        scannedAt: recentScan.createdAt.toISOString(),
        executionTimeMs: 2,
      };
    }

    return null;
  } catch (error) {
    console.error('Cache & Lists check error:', error);
    return null;
  }
}

export async function saveScanResult(result: ComprehensiveScanResult) {
  try {
    await prisma.scan.create({
      data: {
        url: result.url,
        domain: result.domain,
        overallStatus: result.overallStatus,
        riskScore: result.finalRiskScore,
        sourcesData: result.sources as any,
      },
    });
  } catch (error) {
    console.error('Failed to save scan result to DB:', error);
  }
}
