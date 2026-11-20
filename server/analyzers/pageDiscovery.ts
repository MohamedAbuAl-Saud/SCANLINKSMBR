import * as cheerio from 'cheerio';
import { safeSingleFetch } from '../security/ssrfGuard.ts';
import type { CheckFinding, DiscoveredPageResult, PageDiscoverySummary, RiskSeverity } from '../types.ts';
import { extractRegistrableDomain } from './urlIntelligence.ts';

const MAX_DISCOVERED_PAGES = 6;
const CRAWL_TIMEOUT_MS = 6000;

const PRIORITY_KEYWORDS = [
  'login', 'signin', 'log-in', 'sign-in', 'auth', 'sso', 'account', 'portal',
  'signup', 'register', 'signup', 'join',
  'verify', 'verification', 'confirm', 'otp', '2fa',
  'password', 'reset', 'forgot', 'recover',
  'pay', 'payment', 'checkout', 'billing', 'invoice', 'wallet', 'bank', 'banking',
  'admin', 'administrator', 'dashboard', 'control',
  'download', 'installer', 'setup',
  'support', 'help', 'contact', 'security',
];

function classifyPageType(urlPath: string): DiscoveredPageResult['pageType'] {
  const p = urlPath.toLowerCase();
  if (/log[in]?|sign[in]?|auth|sso/i.test(p)) return 'login';
  if (/sign[up]?|register|join/i.test(p)) return 'signup';
  if (/verif[y]?|confirm|otp|2fa/i.test(p)) return 'verification';
  if (/pass[word]?|reset|forgot|recover/i.test(p)) return 'password_reset';
  if (/pay[ment]?|checkout|billing|invoice/i.test(p)) return 'payment';
  if (/wallet|bank|banking/i.test(p)) return 'banking';
  if (/admin|dashboard|control/i.test(p)) return 'admin';
  if (/download|installer|setup/i.test(p)) return 'download';
  if (/support|help|contact/i.test(p)) return 'support';
  if (/security|privacy/i.test(p)) return 'security';
  return 'general';
}

export async function discoverAndInspectPages(
  startUrl: string,
  initialHtmlBuffer?: Buffer
): Promise<{ pageDiscovery: PageDiscoverySummary; findings: CheckFinding[] }> {
  const now = new Date().toISOString();
  const findings: CheckFinding[] = [];
  const parsedStart = new URL(startUrl);
  const startHost = parsedStart.hostname.toLowerCase();
  const startReg = extractRegistrableDomain(startHost);

  const discoveredUrls = new Set<string>();
  discoveredUrls.add(parsedStart.toString());

  // 1. Extract links from homepage HTML if available
  if (initialHtmlBuffer) {
    try {
      const $ = cheerio.load(initialHtmlBuffer.toString('utf8'));
      $('a[href]').each((_, el) => {
        if (discoveredUrls.size >= 30) return;
        const href = ($(el).attr('href') || '').trim();
        if (!href || href.startsWith('#') || href.startsWith('javascript:') || href.startsWith('mailto:')) return;
        try {
          const resolved = new URL(href, startUrl);
          if (resolved.protocol === 'http:' || resolved.protocol === 'https:') {
            if (extractRegistrableDomain(resolved.hostname) === startReg) {
              discoveredUrls.add(resolved.toString());
            }
          }
        } catch {
          // ignore
        }
      });
    } catch {
      // ignore
    }
  }

  // 2. Fetch robots.txt and sitemap.xml safely (best-effort, bounded)
  let robotsChecked = false;
  let sitemapChecked = false;

  try {
    const robotsRes = await safeSingleFetch(`${parsedStart.origin}/robots.txt`, { timeoutMs: 3000, maxBytes: 128 * 1024 });
    if (robotsRes.status === 200 && robotsRes.buffer) {
      robotsChecked = true;
      const text = robotsRes.buffer.toString('utf8');
      const sitemapMatches = text.match(/Sitemap:\s*(https?:\/\/[^\s]+)/gi) || [];
      for (const sm of sitemapMatches) {
        const urlStr = sm.replace(/^Sitemap:\s*/i, '').trim();
        try {
          const smUrl = new URL(urlStr);
          if (extractRegistrableDomain(smUrl.hostname) === startReg) {
            const smRes = await safeSingleFetch(smUrl.toString(), { timeoutMs: 4000, maxBytes: 512 * 1024 });
            if (smRes.status === 200 && smRes.buffer) {
              sitemapChecked = true;
              const smText = smRes.buffer.toString('utf8');
              const locs = smText.match(/<loc>(https?:\/\/[^<]+)<\/loc>/gi) || [];
              for (const loc of locs.slice(0, 30)) {
                const u = loc.replace(/<\/?loc>/gi, '').trim();
                try {
                  const resolved = new URL(u);
                  if (extractRegistrableDomain(resolved.hostname) === startReg) {
                    discoveredUrls.add(resolved.toString());
                  }
                } catch {
                  // ignore
                }
              }
            }
          }
        } catch {
          // ignore
        }
      }
    }
  } catch {
    // robots/sitemap optional
  }

  // Rank and prioritize URLs by priority keywords
  const sortedCandidates = Array.from(discoveredUrls).sort((a, b) => {
    const scoreA = PRIORITY_KEYWORDS.some((k) => a.toLowerCase().includes(k)) ? 1 : 0;
    const scoreB = PRIORITY_KEYWORDS.some((k) => b.toLowerCase().includes(k)) ? 1 : 0;
    return scoreB - scoreA;
  });

  const targetInspectList = sortedCandidates.slice(0, MAX_DISCOVERED_PAGES);
  const inspectedPages: DiscoveredPageResult[] = [];
  let inspectedCount = 0;
  let skippedCount = 0;

  for (const pageUrl of targetInspectList) {
    if (pageUrl === startUrl && initialHtmlBuffer) {
      // Already inspected homepage
      const $ = cheerio.load(initialHtmlBuffer.toString('utf8'));
      const forms = $('form');
      const pwd = $('input[type="password"]');
      inspectedPages.push({
        url: pageUrl,
        title: $('title').first().text().trim(),
        pageType: classifyPageType(pageUrl),
        discoverySource: 'internal_link',
        status: 'inspected',
        statusCode: 200,
        severity: pwd.length > 0 ? 'medium' : 'informational',
        indicators: pwd.length > 0 ? ['Password input on homepage'] : [],
        reason: { en: 'Homepage static inspection completed.', ar: 'اكتمل الفحص الساكن للصفحة الرئيسية.' },
        formCount: forms.length,
        passwordInputCount: pwd.length,
        crossOriginForms: 0,
        lureCount: 0,
      });
      inspectedCount++;
      continue;
    }

    try {
      const res = await safeSingleFetch(pageUrl, { timeoutMs: CRAWL_TIMEOUT_MS, maxBytes: 1 * 1024 * 1024 });
      if (res.status === 200 && res.buffer) {
        const html = res.buffer.toString('utf8');
        const $ = cheerio.load(html);
        const forms = $('form');
        const pwd = $('input[type="password"]');
        const title = $('title').first().text().trim();
        const pageType = classifyPageType(pageUrl);

        let pageSeverity: RiskSeverity = 'informational';
        const indicators: string[] = [];
        if (pwd.length > 0) {
          pageSeverity = 'medium';
          indicators.push(`Password field(s): ${pwd.length}`);
        }
        if (forms.length > 0) {
          indicators.push(`Forms: ${forms.length}`);
        }

        inspectedPages.push({
          url: pageUrl,
          title,
          pageType,
          discoverySource: 'internal_link',
          status: 'inspected',
          statusCode: res.status,
          severity: pageSeverity,
          indicators,
          reason: {
            en: `Discovered and statically inspected (${pageType})`,
            ar: `تم اكتشاف وفحص الصفحة ساكنياً (${pageType})`,
          },
          formCount: forms.length,
          passwordInputCount: pwd.length,
          crossOriginForms: 0,
          lureCount: 0,
        });
        inspectedCount++;
      } else {
        skippedCount++;
        inspectedPages.push({
          url: pageUrl,
          pageType: classifyPageType(pageUrl),
          discoverySource: 'internal_link',
          status: 'skipped',
          statusCode: res.status,
          severity: 'informational',
          indicators: [`HTTP status ${res.status}`],
          reason: { en: `Skipped due to HTTP ${res.status}`, ar: `تم التخطي بسبب الاستجابة ${res.status}` },
          formCount: 0,
          passwordInputCount: 0,
          crossOriginForms: 0,
          lureCount: 0,
        });
      }
    } catch {
      skippedCount++;
      inspectedPages.push({
        url: pageUrl,
        pageType: classifyPageType(pageUrl),
        discoverySource: 'internal_link',
        status: 'error',
        severity: 'informational',
        indicators: ['Fetch timeout or SSRF block'],
        reason: { en: 'Could not fetch page securely', ar: 'تعذر جلب الصفحة بأمان' },
        formCount: 0,
        passwordInputCount: 0,
        crossOriginForms: 0,
        lureCount: 0,
      });
    }
  }

  const pageDiscovery: PageDiscoverySummary = {
    robotsTxtChecked: robotsChecked,
    sitemapChecked,
    totalDiscovered: discoveredUrls.size,
    inspectedCount,
    skippedCount,
    pages: inspectedPages,
  };

  if (inspectedPages.some((p) => p.passwordInputCount > 0 && p.pageType === 'login')) {
    findings.push({
      id: 'page-discovery-login',
      section: 'page_discovery',
      test: { en: 'Multi-Page Discovery & Authentication Inspection', ar: 'استكشاف الصفحات المتعددة وفحص بوابات المصادقة' },
      result: {
        en: `Discovered and inspected ${inspectedCount} public linked page(s) — login/credential portals identified`,
        ar: `تم اكتشاف وفحص ${inspectedCount} صفحة مرتبطة — رصد بوابات تسجيل دخول`,
      },
      status: 'pass',
      severity: 'informational',
      weight: 0,
      evidence: inspectedPages.map((p) => `${p.pageType}: ${p.url}`).join(' | '),
      explanation: {
        en: 'Multi-page discovery successfully inspected linked public pages on the same eTLD+1 domain.',
        ar: 'نجح فحص الصفحات المتعددة في استكشاف وفحص الصفحات العامة المرتبطة على نفس النطاق.',
      },
      recommendedAction: {
        en: 'Review discovered login forms across all sub-pages.',
        ar: 'راجع نماذج تسجيل الدخول المكتشفة في الصفحات الفرعية.',
      },
      source: 'SM Page Discovery Engine',
      timestamp: now,
      confidence: 90,
    });
  }

  return { pageDiscovery, findings };
}
