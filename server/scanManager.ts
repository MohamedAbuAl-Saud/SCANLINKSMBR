import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import net from 'node:net';
import type { EventEmitter } from 'node:events';
import { EventEmitter as NodeEventEmitter } from 'node:events';
import * as cheerio from 'cheerio';
import { validateTargetAgainstSsrf, safeSingleFetch } from './security/ssrfGuard.ts';
import { analyzeUrlIntelligence, extractRegistrableDomain } from './analyzers/urlIntelligence.ts';
import { analyzeDomainDeceptionAndIdentity } from './analyzers/domainDeception.ts';
import { traceRedirectsSafely } from './analyzers/redirectAnalyzer.ts';
import { analyzeDomainAndDns } from './analyzers/domainIntelligence.ts';
import { inspectTlsCertificate } from './analyzers/tlsInspector.ts';
import { analyzeWebsiteContentAndBrand } from './analyzers/contentAnalyzer.ts';
import { analyzeSourceIntelligence, type ExternalSourceAssetsInput } from './analyzers/sourceIntelligence.ts';
import { discoverAndInspectPages } from './analyzers/pageDiscovery.ts';
import { analyzeFileAndDownloads } from './analyzers/fileAnalyzer.ts';
import { recordProviderSuccess, runExternalThreatIntel } from './providers/threatIntelManager.ts';
import { captureWebsiteScreenshot, type ScreenshotViewportMode } from './analyzers/screenshotEngine.ts';
import { fetchSiteFaviconSafely } from './analyzers/faviconFetcher.ts';
import { computeRiskAndSections } from './analyzers/scoringEngine.ts';
import { assessDomainAuthenticity } from './analyzers/officialDomainRegistry.ts';
import { analyzeTargetXssVulnerabilities } from './analyzers/xssAnalyzer.ts';
import { validateAndNormalizeReportConsistency } from './analyzers/consistencyValidator.ts';
import { executeLevelBCloudBrowser } from './analyzers/remoteBrowserAdapter.ts';
import type { CheckFinding, ScanJobState, ScanReport, ScanStageId, ScanStageProgress } from './types.ts';

async function fetchBoundedSameOriginAssets(
  baseUrl: string,
  htmlBuffer?: Buffer
): Promise<ExternalSourceAssetsInput | undefined> {
  if (!htmlBuffer || htmlBuffer.length === 0) return undefined;
  try {
    const parsedBase = new URL(baseUrl);
    const baseReg = extractRegistrableDomain(parsedBase.hostname);
    const $ = cheerio.load(htmlBuffer.toString('utf8'));

    const DEV_BUNDLER_SCRIPT_RE =
      /(?:^|\/)(?:@vite\/client|@react-refresh|__vite_ping|vite-hmr|webpack-dev-server|__webpack_hmr|sockjs-node)(?:\?|$|#)|\/node_modules\/\.vite\//i;
    const scriptCandidates: string[] = [];
    $('script[src]').each((_, el) => {
      if (scriptCandidates.length >= 2) return;
      const src = ($(el).attr('src') || '').trim();
      if (!src || DEV_BUNDLER_SCRIPT_RE.test(src)) return;
      try {
        const resolved = new URL(src, baseUrl);
        if (
          (resolved.protocol === 'http:' || resolved.protocol === 'https:') &&
          !DEV_BUNDLER_SCRIPT_RE.test(resolved.pathname) &&
          extractRegistrableDomain(resolved.hostname) === baseReg
        ) {
          scriptCandidates.push(resolved.toString());
        }
      } catch {
        // ignore invalid src
      }
    });

    const cssCandidates: string[] = [];
    $('link[rel="stylesheet"]').each((_, el) => {
      if (cssCandidates.length >= 1) return;
      const href = ($(el).attr('href') || '').trim();
      if (!href) return;
      try {
        const resolved = new URL(href, baseUrl);
        if (
          (resolved.protocol === 'http:' || resolved.protocol === 'https:') &&
          extractRegistrableDomain(resolved.hostname) === baseReg
        ) {
          cssCandidates.push(resolved.toString());
        }
      } catch {
        // ignore invalid href
      }
    });

    if (scriptCandidates.length === 0 && cssCandidates.length === 0) return undefined;

    const fetchedScripts: { url: string; code: string }[] = [];
    const fetchedCss: { url: string; css: string }[] = [];

    await Promise.allSettled([
      ...scriptCandidates.map(async (u) => {
        const res = await safeSingleFetch(u, { timeoutMs: 2500, maxBytes: 180 * 1024 });
        if (res.status >= 200 && res.status < 300 && res.buffer.length > 0) {
          fetchedScripts.push({ url: u, code: res.buffer.toString('utf8') });
        }
      }),
      ...cssCandidates.map(async (u) => {
        const res = await safeSingleFetch(u, { timeoutMs: 2500, maxBytes: 100 * 1024 });
        if (res.status >= 200 && res.status < 300 && res.buffer.length > 0) {
          fetchedCss.push({ url: u, css: res.buffer.toString('utf8') });
        }
      }),
    ]);

    if (fetchedScripts.length === 0 && fetchedCss.length === 0) return undefined;
    return { fetchedScripts, fetchedCss };
  } catch {
    return undefined;
  }
}

const jobs = new Map<string, ScanJobState>();
const jobEmitters = new Map<string, EventEmitter>();

function createInitialStages(): ScanStageProgress[] {
  return [
    { id: 'url_validation', label: { en: 'URL validation, normalization & SSRF guard', ar: 'التحقق من الرابط والتطبيع وحماية SSRF' }, status: 'pending' },
    { id: 'dns_resolution', label: { en: 'URL structure & initial resolution', ar: 'تحليل بنية الرابط والتحضير الشبكي' }, status: 'pending' },
    { id: 'redirect_tracer', label: { en: 'Redirect chain tracing', ar: 'تتبع سلاسل إعادة التوجيه' }, status: 'pending' },
    { id: 'domain_rdap', label: { en: 'Domain deception, DNSSEC, RDAP & WHOIS lookup', ar: 'فحص خداع النطاق و DNSSEC و RDAP و WHOIS' }, status: 'pending' },
    { id: 'tls_inspection', label: { en: 'SSL/TLS certificate & cipher inspection', ar: 'فحص شهادة التشفير SSL/TLS والتشفير' }, status: 'pending' },
    { id: 'content_phishing', label: { en: 'Content, phishing, JS & file inspection', ar: 'فحص المحتوى والتصيد والملفات' }, status: 'pending' },
    { id: 'source_intelligence', label: { en: 'Website Source Intelligence & Supply Chain', ar: 'استخبارات مصدر الموقع وسلسلة التوريد' }, status: 'pending' },
    { id: 'page_discovery', label: { en: 'Multi-Page Website Discovery & Inspection', ar: 'استكشاف وفحص صفحات الموقع المتعددة' }, status: 'pending' },
    { id: 'threat_intel', label: { en: 'External threat intelligence checks', ar: 'استخبارات التهديدات الخارجية' }, status: 'pending' },
    { id: 'level_b_cloud_browser', label: { en: 'Level B external cloud browser observation', ar: 'فحص المستوى B عبر متصفح سحابي خارجي' }, status: 'pending' },
    { id: 'screenshot_capture', label: { en: 'Website screenshot capture', ar: 'التقاط المعاينة البصرية للموقع' }, status: 'pending' },
    { id: 'risk_scoring', label: { en: 'Deterministic risk calculation', ar: 'احتساب المخاطر والارتباط الأمني' }, status: 'pending' },
    { id: 'report_generation', label: { en: 'Security report generation', ar: 'توليد التقرير الأمني النهائي' }, status: 'pending' },
  ];
}

function updateStage(
  job: ScanJobState,
  stageId: ScanStageId,
  status: ScanStageProgress['status'],
  detail?: { en: string; ar: string },
  durationMs?: number
) {
  const stage = job.stages.find((s) => s.id === stageId);
  if (stage) {
    stage.status = status;
    if (detail) stage.detail = detail;
    if (durationMs !== undefined) stage.durationMs = durationMs;
  }
  const doneCount = job.stages.filter((s) => s.status !== 'pending' && s.status !== 'running').length;
  job.progressPercent = Math.round((doneCount / job.stages.length) * 100);
  jobEmitters.get(job.scanId)?.emit('update', job);
}

export function getScanJob(scanId: string): ScanJobState | undefined {
  return jobs.get(scanId);
}

export function getJobEmitter(scanId: string): EventEmitter | undefined {
  return jobEmitters.get(scanId);
}

export interface StartScanOptions {
  url: string;
  viewport?: ScreenshotViewportMode;
  disabledProviders?: string[];
}

export function startScanJob(options: StartScanOptions): ScanJobState {
  if (jobs.size >= 100) {
    const oldestKey = jobs.keys().next().value;
    if (oldestKey) {
      jobs.delete(oldestKey);
      jobEmitters.delete(oldestKey);
    }
  }

  const scanId = crypto.randomUUID();
  const job: ScanJobState = {
    scanId,
    submittedUrl: options.url,
    status: 'queued',
    progressPercent: 0,
    startedAt: new Date().toISOString(),
    stages: createInitialStages(),
  };

  jobs.set(scanId, job);
  jobEmitters.set(scanId, new NodeEventEmitter());

  void executeScanPipeline(job, options);
  return job;
}

async function executeScanPipeline(job: ScanJobState, options: StartScanOptions): Promise<void> {
  const pipelineStart = Date.now();
  job.status = 'running';
  const findings: CheckFinding[] = [];
  const viewportMode: ScreenshotViewportMode = options.viewport || 'desktop';

  try {
    // Stage 1: URL Validation, Normalization & SSRF Guard
    let t0 = Date.now();
    updateStage(job, 'url_validation', 'running');
    const validated = await validateTargetAgainstSsrf(options.url);
    updateStage(
      job,
      'url_validation',
      'completed',
      {
        en: `Normalized & resolved ${validated.asciiHostname} (${validated.pinnedIp})`,
        ar: `تم تطبيع وفحص ${validated.asciiHostname} (${validated.pinnedIp})`,
      },
      Date.now() - t0
    );

    // Stage 2: URL Structure Analysis
    t0 = Date.now();
    updateStage(job, 'dns_resolution', 'running');
    const urlIntel = analyzeUrlIntelligence(options.url, validated.normalizedUrl);
    findings.push(...urlIntel.findings);
    updateStage(
      job,
      'dns_resolution',
      urlIntel.findings.some((f) => f.status === 'failed') ? 'warning' : 'completed',
      {
        en: `${urlIntel.findings.length} structural indicator checks completed`,
        ar: `اكتمل فحص ${urlIntel.findings.length} مؤشراً لبنية الرابط`,
      },
      Date.now() - t0
    );

    // Stage 3: Redirect Chain Tracing
    t0 = Date.now();
    updateStage(job, 'redirect_tracer', 'running');
    const redirectRes = await traceRedirectsSafely(validated.normalizedUrl);
    findings.push(...redirectRes.findings);
    updateStage(
      job,
      'redirect_tracer',
      redirectRes.ssrfBlocked ? 'failed' : 'completed',
      {
        en: `${Math.max(0, redirectRes.hops.length - 1)} redirect hop(s) traced`,
        ar: `تم تتبع ${Math.max(0, redirectRes.hops.length - 1)} قفزة إعادة توجيه`,
      },
      Date.now() - t0
    );

    const finalParsed = new URL(redirectRes.finalUrl);
    const finalHost = finalParsed.hostname.toLowerCase();
    let finalPinnedIp = validated.pinnedIp;
    try {
      const revalidated = await validateTargetAgainstSsrf(redirectRes.finalUrl);
      finalPinnedIp = revalidated.pinnedIp;
    } catch {
      // Keep initial pinned IP
    }

    // Domain Deception & Identity Analysis
    const deceptionRes = analyzeDomainDeceptionAndIdentity({
      submittedUrl: options.url,
      finalUrl: redirectRes.finalUrl,
      redirects: redirectRes.hops,
      htmlBuffer: redirectRes.finalFetch?.buffer,
      contentType: redirectRes.finalFetch?.headers?.['content-type'],
    });
    findings.push(...deceptionRes.findings);

    // Pre-fetch bounded same-origin JS/CSS assets when HTML body looks inspectable (skipped if 401/403/429/503 challenge wall)
    const preliminaryStatus = redirectRes.finalFetch?.status;
    const isLikelyBlockedStatus =
      preliminaryStatus === 401 ||
      preliminaryStatus === 403 ||
      preliminaryStatus === 429 ||
      preliminaryStatus === 451 ||
      preliminaryStatus === 503;
    const preBoundedAssets =
      !isLikelyBlockedStatus && redirectRes.finalFetch?.buffer
        ? await fetchBoundedSameOriginAssets(redirectRes.finalUrl, redirectRes.finalFetch.buffer)
        : undefined;

    // Stage 6: Content, Phishing, Brand Impersonation, JS & File Analysis
    t0 = Date.now();
    updateStage(job, 'content_phishing', 'running');
    const contentRes = analyzeWebsiteContentAndBrand(
      redirectRes.finalUrl,
      redirectRes.finalFetch?.status,
      redirectRes.finalFetch?.headers ?? {},
      redirectRes.finalFetch?.buffer,
      urlIntel.suspiciousPathTokens,
      preBoundedAssets?.fetchedScripts ?? []
    );
    findings.push(...contentRes.findings);

    const fileRes = analyzeFileAndDownloads(
      redirectRes.finalUrl,
      redirectRes.finalFetch?.headers ?? {},
      redirectRes.finalFetch?.buffer
    );
    findings.push(...fileRes.findings);

    updateStage(
      job,
      'content_phishing',
      contentRes.findings.some((f) => f.status === 'failed') ? 'warning' : 'completed',
      {
        en: contentRes.data
          ? `${contentRes.data.passwordInputCount} pwd field(s), ${contentRes.data.inlineScriptCount + contentRes.data.externalScriptCount} script(s)`
          : 'Content analyzed',
        ar: 'اكتمل فحص المحتوى والتصيد',
      },
      Date.now() - t0
    );

    // Stage 7: Website Source Intelligence & Supply Chain Analysis (Static HTML + bounded same-origin JS/CSS)
    t0 = Date.now();
    updateStage(job, 'source_intelligence', 'running');
    const isContentBlockedBySite = contentRes.data?.contentReadStatus === 'blocked_by_site';
    const inspectableHtmlBuffer = isContentBlockedBySite ? undefined : redirectRes.finalFetch?.buffer;
    const boundedAssets = isContentBlockedBySite ? undefined : preBoundedAssets;
    const sourceRes = analyzeSourceIntelligence(
      redirectRes.finalUrl,
      redirectRes.finalFetch?.headers ?? {},
      inspectableHtmlBuffer,
      boundedAssets,
      redirectRes.finalFetch?.setCookies
    );
    findings.push(...sourceRes.findings);

    const xssRes = analyzeTargetXssVulnerabilities({
      submittedUrl: options.url,
      finalUrl: redirectRes.finalUrl,
      headers: redirectRes.finalFetch?.headers ?? {},
      htmlBuffer: inspectableHtmlBuffer,
      fetchedScripts: boundedAssets?.fetchedScripts,
      cookieAudit: sourceRes.sourceIntel.cookieAudit,
      contentBlocked: isContentBlockedBySite,
    });
    findings.push(xssRes.finding);
    updateStage(
      job,
      'source_intelligence',
      isContentBlockedBySite ? 'unavailable' : 'completed',
      {
        en: isContentBlockedBySite
          ? 'Target blocked HTML/source inspection (HTTP barrier)'
          : `Analyzed ${sourceRes.supplyChain.totalExternalDomains} external domain(s), ${sourceRes.formDetails.length} form(s)`,
        ar: isContentBlockedBySite
          ? 'رفض الموقع قراءة HTML والسورس (حاجز وصول HTTP)'
          : `تم تحليل ${sourceRes.supplyChain.totalExternalDomains} نطاقاً و${sourceRes.formDetails.length} نموذجاً`,
      },
      Date.now() - t0
    );

    // Stage 8: Multi-Page Discovery & Inspection
    t0 = Date.now();
    updateStage(job, 'page_discovery', 'running');
    const discoveryRes = await discoverAndInspectPages(redirectRes.finalUrl, inspectableHtmlBuffer);
    findings.push(...discoveryRes.findings);
    updateStage(
      job,
      'page_discovery',
      isContentBlockedBySite ? 'unavailable' : 'completed',
      {
        en: `Discovered and inspected ${discoveryRes.pageDiscovery.inspectedCount} public sub-page(s)`,
        ar: `تم اكتشاف وفحص ${discoveryRes.pageDiscovery.inspectedCount} صفحة فرعية`,
      },
      Date.now() - t0
    );

    // Parallel background telemetry fetches (DNS, TLS, Threat Intel, Level B Cloud Browser, Screenshot, Favicon)
    updateStage(job, 'domain_rdap', 'running');
    updateStage(job, 'tls_inspection', 'running');
    updateStage(job, 'threat_intel', 'running');
    updateStage(job, 'level_b_cloud_browser', 'running');
    updateStage(job, 'screenshot_capture', 'running');

    const dnsStart = Date.now();
    const tlsStart = Date.now();
    const intelStart = Date.now();
    const levelBStart = Date.now();
    const ssStart = Date.now();

    const finalHeaders = redirectRes.finalFetch?.headers ?? {};

    const dnsPromise = analyzeDomainAndDns(finalHost, finalHeaders).then((res) => {
      findings.push(...res.findings);
      if (res.data.rdapSource || res.data.whoisSource) recordProviderSuccess('rdap');
      if (res.data.dnsRecords.dohVerified) recordProviderSuccess('doh');
      updateStage(
        job,
        'domain_rdap',
        res.data.domainAgeDays === undefined ? 'warning' : 'completed',
        {
          en:
            res.data.domainAgeDays !== undefined
              ? `Age: ${res.data.domainAgeDays}d · ${res.data.dnsRecords.a.length} A`
              : `${res.data.dnsRecords.a.length} A record(s)`,
          ar: `فحص النطاق و DNS مكتمل`,
        },
        Date.now() - dnsStart
      );
      return res;
    });

    const tlsPromise = inspectTlsCertificate(redirectRes.finalUrl, finalPinnedIp).then((res) => {
      findings.push(...res.findings);
      if (res.data.ctSource) recordProviderSuccess('crtsh');
      updateStage(
        job,
        'tls_inspection',
        res.data.httpsAvailable && res.data.authorized && !res.data.expired ? 'completed' : 'warning',
        {
          en: res.data.httpsAvailable ? `${res.data.protocol ?? 'TLS'} · ${res.data.issuer ?? 'Verified'}` : 'No TLS endpoint',
          ar: 'اكتمل فحص شهادة TLS',
        },
        Date.now() - tlsStart
      );
      return res;
    });

    const isCdnEdgeHeader = Boolean(
      finalHeaders['cf-ray'] ||
        finalHeaders['x-amz-cf-id'] ||
        finalHeaders['x-vercel-id'] ||
        finalHeaders['x-served-by']?.includes('cache-') ||
        /cloudflare|fastly|akamai|cloudfront|vercel|netlify/i.test(finalHeaders['server'] || '')
    );

    const intelPromise = runExternalThreatIntel(
      redirectRes.finalUrl,
      finalHost,
      urlIntel.registrableDomain,
      options.disabledProviders ?? [],
      finalPinnedIp,
      isCdnEdgeHeader
    ).then((res) => {
      findings.push(...res.findings);
      const flagged = res.providers.filter((p) => p.status === 'flagged').length;
      updateStage(
        job,
        'threat_intel',
        flagged > 0 ? 'failed' : 'completed',
        {
          en: `${res.providers.filter((p) => p.status === 'clean' || p.status === 'flagged').length}/${res.providers.length} feeds responded`,
          ar: `استجاب مزودو التهديدات`,
        },
        Date.now() - intelStart
      );
      return res;
    });

    const levelBDisabled = (options.disabledProviders ?? []).includes('external_cloud_browser');
    const levelBPromise = executeLevelBCloudBrowser(redirectRes.finalUrl, {
      viewport: viewportMode,
      disabled: levelBDisabled,
    }).then((res) => {
      if (res.status === 'executed') {
        recordProviderSuccess('external_cloud_browser');
        const highRiskReqs = res.networkRequests.filter(
          (r) => r.channelCategory === 'HIGH_RISK_EXFILTRATION_CHANNEL' || r.channelCategory === 'WEBHOOK_OR_BOT_SINK'
        );
        const profilingReqs = res.networkRequests.filter((r) => r.channelCategory === 'IP_AND_DEVICE_PROFILING');
        const unverifiedPosts = res.networkRequests.filter(
          (r) => r.channelCategory === 'UNVERIFIED_EXTERNAL' && r.isSensitiveSink
        );
        const sensitivePerms = res.permissionEvents.filter((e) =>
          ['camera', 'microphone', 'geolocation', 'clipboard'].includes(e.kind)
        );
        const hasFailedRuntime = highRiskReqs.length > 0 || (sensitivePerms.length > 0 && (profilingReqs.length > 0 || unverifiedPosts.length > 0));
        const hasWarnRuntime = !hasFailedRuntime && (profilingReqs.length > 0 || sensitivePerms.length > 0 || unverifiedPosts.length > 0);
        findings.push({
          id: 'level-b-runtime-audit',
          section: 'javascript_analysis',
          test: {
            en: 'Level B Dynamic Cloud Browser Runtime Observation',
            ar: 'مراقبة التشغيل الحي للمستوى B عبر متصفح سحابي خارجي',
          },
          result: hasFailedRuntime
            ? {
                en: `Runtime session captured ${highRiskReqs.length} high-risk bot/webhook channel(s) and ${sensitivePerms.length} sensitive permission request(s)`,
                ar: `رصد التشغيل الحي ${highRiskReqs.length} قناة تسريب/بوت خطيرة و${sensitivePerms.length} محاولة لطلب صلاحية حساسة`,
              }
            : hasWarnRuntime
              ? {
                  en: `Runtime session observed ${profilingReqs.length} IP/profiling call(s), ${unverifiedPosts.length} unverified outbound POST(s), and ${sensitivePerms.length} permission event(s)`,
                  ar: `رصد التشغيل الحي ${profilingReqs.length} استعلام IP و${unverifiedPosts.length} إرسال خارجي غير موثوق و${sensitivePerms.length} حدث صلاحيات`,
                }
              : {
                  en: `Dynamic cloud session completed (${res.networkRequests.length} network requests, 0 high-risk sinks, 0 intrusive permissions)`,
                  ar: `اكتمل التنفيذ السحابي الحي (${res.networkRequests.length} طلب شبكي، 0 قنوات تسريب خطيرة، 0 صلاحيات متطفلة)`,
                },
          status: hasFailedRuntime ? 'failed' : hasWarnRuntime ? 'warning' : 'pass',
          severity: hasFailedRuntime ? 'critical' : hasWarnRuntime ? 'medium' : 'informational',
          weight: hasFailedRuntime ? 28 : hasWarnRuntime ? 10 : 0,
          evidence: `LevelBStatus: executed | NetReqs: ${res.networkRequests.length} | HighRisk: ${highRiskReqs.length} | Profiling: ${profilingReqs.length} | UnverifiedPost: ${unverifiedPosts.length} | Perms: ${sensitivePerms.length}`,
          explanation: res.executiveSummary,
          recommendedAction: {
            en: hasFailedRuntime
              ? 'Avoid interacting with this page; live browser execution confirmed external bot/webhook exfiltration or sensitive capture.'
              : 'Review runtime request and permission logs in the Level B panel.',
            ar: hasFailedRuntime
              ? 'تجنب التفاعل مع الصفحة؛ أكد التشغيل الحي وجود قنوات تسريب خارجية أو محاولات التقاط حساسة.'
              : 'راجع تفاصيل الطلبات والأذونات في صندوق فحص Level B.',
          },
          source: 'SM External Cloud Browser Service',
          timestamp: new Date().toISOString(),
          confidence: 95,
        });
      }
      const stageStatus =
        res.status === 'executed'
          ? res.networkRequests.some((r) => r.channelCategory === 'HIGH_RISK_EXFILTRATION_CHANNEL' || r.channelCategory === 'WEBHOOK_OR_BOT_SINK')
            ? 'failed'
            : 'completed'
          : 'unavailable';
      updateStage(
        job,
        'level_b_cloud_browser',
        stageStatus,
        res.status === 'executed'
          ? {
              en: `${res.networkRequests.length} reqs · ${res.permissionEvents.length} events observed`,
              ar: `رُصد ${res.networkRequests.length} طلباً و${res.permissionEvents.length} حدثاً`,
            }
          : {
              en: res.status === 'disabled' ? 'Paused for this scan' : 'Unavailable — static Level A relied upon',
              ar: res.status === 'disabled' ? 'متوقف لهذا الفحص' : 'غير متاح — اعتمد الفحص على المستوى A',
            },
        Date.now() - levelBStart
      );
      return res;
    });

    const screenshotPromise = captureWebsiteScreenshot(redirectRes.finalUrl, viewportMode).then((res) => {
      findings.push(res.finding);
      updateStage(
        job,
        'screenshot_capture',
        res.screenshot.status === 'captured' ? 'completed' : 'unavailable',
        {
          en: res.screenshot.status === 'captured' ? `Captured (${res.screenshot.viewport})` : 'Preview unavailable',
          ar: 'اكتملت المعاينة البصرية',
        },
        Date.now() - ssStart
      );
      return res;
    });

    const faviconPromise = fetchSiteFaviconSafely(
      redirectRes.finalUrl,
      redirectRes.finalFetch?.buffer,
      finalHeaders['content-type']
    ).catch(() => ({ dataUrl: undefined, sourceUrl: undefined }));

    const [dnsRes, tlsRes, intelRes, levelBRes, screenshotRes, faviconRes] = await Promise.all([
      dnsPromise,
      tlsPromise,
      intelPromise,
      levelBPromise,
      screenshotPromise,
      faviconPromise,
    ]);

    if (screenshotRes.screenshot.status !== 'captured' && levelBRes.screenshot.captured && levelBRes.screenshot.dataUrl) {
      screenshotRes.screenshot.status = 'captured';
      screenshotRes.screenshot.imageDataUrl = levelBRes.screenshot.dataUrl;
      screenshotRes.screenshot.capturedAt = levelBRes.screenshot.capturedAt;
    }

    // SSRF-safe live DNS resolution for up to 5 discovered in-page subdomains on the site's eTLD+1
    if (sourceRes.sourceIntel.discoveredSubdomains && sourceRes.sourceIntel.discoveredSubdomains.length > 0) {
      await Promise.allSettled(
        sourceRes.sourceIntel.discoveredSubdomains.slice(0, 5).map(async (sub) => {
          if (net.isIP(sub.host) !== 0) return;
          const [ipsRes, cnameRes] = await Promise.allSettled([
            dns.resolve4(sub.host),
            dns.resolveCname(sub.host),
          ]);
          if (ipsRes.status === 'fulfilled' && ipsRes.value.length > 0) {
            sub.resolvedIps = ipsRes.value.filter((ip) => !net.isIPv4(ip) || !/^10\.|^127\.|^192\.168\.|^169\.254\./.test(ip)).slice(0, 4);
          }
          if (cnameRes.status === 'fulfilled' && cnameRes.value.length > 0) {
            sub.cnameChain = cnameRes.value.slice(0, 3);
          }
        })
      );
    }

    // Domain Authenticity Verification (PSL + Official Registry + Live DNS/TLS/RDAP/ASN/OTX corroboration)
    const dnsResolved = dnsRes.data.dnsRecords.a.length > 0 || dnsRes.data.dnsRecords.aaaa.length > 0;
    const otxAllowlisted = intelRes.providers.some(
      (p) => p.providerId === 'otx' && /allowlist/i.test(p.verdictDetail.en)
    );
    const hasCoreDeception = Boolean(
      deceptionRes.data.confusableDetected ||
        deceptionRes.data.mixedScripts ||
        deceptionRes.data.bidiControlsDetected ||
        deceptionRes.data.zeroWidthDetected ||
        deceptionRes.data.authorityMasking ||
        deceptionRes.data.subdomainSpoofing ||
        deceptionRes.data.openRedirectConfirmed
    );
    const domainAuthenticity = assessDomainAuthenticity({
      hostname: finalHost,
      dnsResolved,
      dnsNameservers: dnsRes.data.nameservers,
      cdnOrProxyProvider: dnsRes.data.dnsRecords.cdnOrProxyProvider,
      rdapRegistrar: dnsRes.data.registrar,
      rdapOwner: dnsRes.data.ownerSummary.en,
      rdapRegistry: dnsRes.data.rdapSource || dnsRes.data.registry,
      asn: dnsRes.data.asn,
      networkName: dnsRes.data.networkName,
      tlsAuthorized: tlsRes.data.httpsAvailable ? tlsRes.data.authorized : false,
      tlsExpired: tlsRes.data.expired,
      tlsDomainMatches: tlsRes.data.domainMatches,
      tlsIssuer: tlsRes.data.issuer,
      otxAllowlisted,
      deceptionDetected: hasCoreDeception,
      similarityTarget: deceptionRes.data.typosquatTarget
        ? {
            brand: deceptionRes.data.typosquatTarget.brand,
            officialDomain: deceptionRes.data.typosquatTarget.officialDomain,
            reason: deceptionRes.data.typosquatTarget.technique,
          }
        : undefined,
    });

    // Stage: Risk Scoring & Correlation
    t0 = Date.now();
    updateStage(job, 'risk_scoring', 'running');
    const scored = computeRiskAndSections(findings, intelRes.providers, {
      domainAuthenticity,
      tlsData: tlsRes.data,
      dnsData: dnsRes.data,
      redirects: redirectRes.hops,
      finalUrl: redirectRes.finalUrl,
      levelB: levelBRes,
      urlDecodedSecretsCount: urlIntel.encryptionTelemetry.decodedSecretsDetected?.length ?? 0,
      dataFlowTaints: sourceRes.sourceIntel.dataFlowTaints,
      plantedBackdoors: sourceRes.sourceIntel.plantedBackdoors,
    });
    updateStage(
      job,
      'risk_scoring',
      'completed',
      {
        en: `Score ${scored.riskScore}/100 · ${scored.classification}`,
        ar: `النتيجة ${scored.riskScore}/100 · ${scored.classification}`,
      },
      Date.now() - t0
    );

    // Stage: Report Generation
    t0 = Date.now();
    updateStage(job, 'report_generation', 'running');

    const completedAt = new Date().toISOString();
    const suspectedBrandConfirmed = Boolean(
      contentRes.data?.suspectedBrand && !contentRes.data.suspectedBrand.similarityOnly
    );

    const hasHtml = Boolean(
      contentRes.data &&
        contentRes.data.htmlSizeBytes > 0 &&
        contentRes.data.contentReadStatus !== 'blocked_by_site'
    );
    const hasBlockedSite = contentRes.data?.contentReadStatus === 'blocked_by_site';
    const hasThinSpa = Boolean(
      sourceRes.sourceIntel.dynamicContentAfterJsLikely ||
        (hasHtml &&
          contentRes.data &&
          contentRes.data.visibleWordCount < 25 &&
          contentRes.data.inlineScriptCount + contentRes.data.externalScriptCount > 0)
    );
    const lookalikeLinkCount = sourceRes.sourceIntel.brandLookalikeLinks?.length ?? 0;

    const websiteIntelligenceReport: ScanReport['websiteIntelligenceReport'] = [
      {
        itemKey: 'website_purpose',
        title: { en: '1. Website Purpose & Context', ar: '١. وصف الموقع ووظيفته الفعلية' },
        status: hasHtml ? 'inspected' : 'unavailable',
        summary: hasHtml
          ? {
              en: `${contentRes.data?.claimedPurpose?.en || 'Web Page'}${domainAuthenticity.officialProduct ? ` · Verified Entity: ${domainAuthenticity.officialProduct}` : dnsRes.data.isMultiTenantPaas ? ` · Shared PaaS (${dnsRes.data.paasProvider || 'PaaS'})` : ''} — Title: "${contentRes.data?.pageTitle || 'Untitled'}"`,
              ar: `${contentRes.data?.claimedPurpose?.ar || 'صفحة ويب'}${domainAuthenticity.officialProduct ? ` · جهة موثقة: ${domainAuthenticity.officialProduct}` : dnsRes.data.isMultiTenantPaas ? ` · استضافة تشاركية (${dnsRes.data.paasProvider || 'PaaS'})` : ''} — العنوان: "${contentRes.data?.pageTitle || 'بدون عنوان'}"`,
            }
          : hasBlockedSite
            ? {
                en: `Site refused automated content inspection (${contentRes.data?.blockedReason || 'access barrier'}).`,
                ar: `الموقع لا يسمح بقراءة محتواه (${contentRes.data?.blockedReason || 'حاجز وصول'}).`,
              }
            : { en: 'Page content could not be retrieved to determine purpose.', ar: 'تعذر جلب محتوى الصفحة لتحديد وظيفة الموقع.' },
        detail: contentRes.data?.metaDescription || domainAuthenticity.registrableDomain,
      },
      {
        itemKey: 'retrieved_content_summary',
        title: { en: '2. Retrieved Content Summary', ar: '٢. المحتوى الذي تمت قراءته فعلياً' },
        status: hasHtml ? 'inspected' : 'unavailable',
        summary: hasHtml
          ? {
              en: `HTTP ${contentRes.data?.httpStatus ?? 'N/A'} (${contentRes.data?.contentReadStatus || 'full'}) · ${(contentRes.data!.htmlSizeBytes / 1024).toFixed(1)} KB HTML · ${contentRes.data!.visibleWordCount} words · ${contentRes.data!.headings?.length ?? 0} heading(s) · ${discoveryRes.pageDiscovery.inspectedCount} sub-page(s) inspected.`,
              ar: `الحالة HTTP ${contentRes.data?.httpStatus ?? 'N/A'} (${contentRes.data?.contentReadStatus === 'truncated' ? 'مقتطع ضمن الحد الآمن' : 'مكتمل'}) · ${(contentRes.data!.htmlSizeBytes / 1024).toFixed(1)} ك.ب · ${contentRes.data!.visibleWordCount} كلمة · ${contentRes.data!.headings?.length ?? 0} عنوان فرعي · ${discoveryRes.pageDiscovery.inspectedCount} صفحة.`,
            }
          : {
              en: hasBlockedSite
                ? `Content reading blocked by target (${contentRes.data?.blockedReason}). Never guessed or invented.`
                : 'No HTTP HTML payload retrieved from target.',
              ar: hasBlockedSite
                ? `تعذر قراءة المحتوى بسبب حظر الموقع (${contentRes.data?.blockedReason}). لم يتم تخمين أي محتوى.`
                : 'لم يتم استرجاع محتوى HTML من الهدف.',
            },
      },
      {
        itemKey: 'html_analysis',
        title: { en: '3. HTML Structure & Metadata Analysis', ar: '٣. نتيجة تحليل HTML والبيانات الوصفية' },
        status: hasHtml ? 'inspected' : 'unavailable',
        summary: hasHtml
          ? {
              en: `Title-body mismatch: ${sourceRes.sourceIntel.titleContentMismatch ? 'Detected' : 'None'} · Base hijack: ${sourceRes.sourceIntel.baseTagHijack ? 'Detected' : 'No'} · Hidden inputs: ${sourceRes.sourceIntel.hiddenInputs.length} · Subdomains mapped: ${sourceRes.sourceIntel.discoveredSubdomains?.length ?? 0}.`,
              ar: `تعارض العنوان والمحتوى: ${sourceRes.sourceIntel.titleContentMismatch ? 'مرصود' : 'لا يوجد'} · وسم <base> خبيث: ${sourceRes.sourceIntel.baseTagHijack ? 'نعم' : 'لا'} · مدخلات مخفية: ${sourceRes.sourceIntel.hiddenInputs.length} · نطاقات فرعية: ${sourceRes.sourceIntel.discoveredSubdomains?.length ?? 0}.`,
            }
          : { en: 'HTML structure analysis unavailable.', ar: 'تعذر تحليل بنية HTML لعدم توفر المصدر.' },
        detail: sourceRes.sourceIntel.titleMismatchDetail?.en,
      },
      {
        itemKey: 'js_static_analysis',
        title: { en: '4. JavaScript Static Code Analysis', ar: '٤. نتيجة التحليل الساكن لـ JavaScript' },
        status: !hasHtml
          ? 'unavailable'
          : contentRes.data!.inlineScriptCount + contentRes.data!.externalScriptCount === 0
            ? 'not_present'
            : 'inspected',
        summary: !hasHtml
          ? { en: 'JavaScript inspection unavailable (content blocked or unreachable).', ar: 'تعذر تحليل أكواد JavaScript لعدم قراءة الصفحة.' }
          : contentRes.data!.inlineScriptCount + contentRes.data!.externalScriptCount === 0
            ? { en: 'No inline or external JavaScript blocks detected in page.', ar: 'لا توجد أكواد JavaScript مضمنة أو خارجية في هذه الصفحة.' }
            : {
                en: `${contentRes.data!.inlineScriptCount} inline / ${contentRes.data!.externalScriptCount} external script(s) (${sourceRes.sourceIntel.externalJsInspectedCount ?? 0} fetched) · Minified: ${sourceRes.sourceIntel.isMinifiedBundlePresent ? 'Clean bundle' : 'No'} · Signals: ${sourceRes.sourceIntel.suspiciousCodeSignals.length} · DOM mutation payloads: ${sourceRes.sourceIntel.jsDomMutationPayloads?.length ?? 0}.`,
                ar: `${contentRes.data!.inlineScriptCount} سكربت داخلي / ${contentRes.data!.externalScriptCount} خارجي (قراءة ${sourceRes.sourceIntel.externalJsInspectedCount ?? 0} خارجي) · حزم مضغوطة: ${sourceRes.sourceIntel.isMinifiedBundlePresent ? 'سليمة' : 'لا'} · إشارات الكود: ${sourceRes.sourceIntel.suspiciousCodeSignals.length} · تعديل DOM بعد التحميل: ${sourceRes.sourceIntel.jsDomMutationPayloads?.length ?? 0}.`,
              },
        detail: sourceRes.sourceIntel.obfuscationVsMinifiedNote?.en,
      },
      {
        itemKey: 'dom_analysis',
        title: { en: '5. Static DOM & CSS Vector Analysis', ar: '٥. نتيجة تحليل DOM وأنماط CSS' },
        status: hasHtml ? 'inspected' : 'unavailable',
        summary: hasHtml
          ? {
              en: `Iframes: ${contentRes.data!.iframeCount} · Hidden DOM nodes: ${contentRes.data!.hiddenElementCount} · External CSS resources: ${sourceRes.sourceIntel.externalCssUrls?.length ?? sourceRes.sourceIntel.externalCssFiles.length} · Dynamic JS-rendered divergence: ${hasThinSpa ? 'Likely (Level B inactive — Static Level A only)' : 'Not indicated'}.`,
              ar: `إطارات Iframe: ${contentRes.data!.iframeCount} · عناصر مخفية: ${contentRes.data!.hiddenElementCount} · موارد CSS خارجية: ${sourceRes.sourceIntel.externalCssUrls?.length ?? sourceRes.sourceIntel.externalCssFiles.length} · تغيّر المحتوى بعد JS: ${hasThinSpa ? 'مرجّح (المستوى B غير متاح — فحص ساكن A فقط)' : 'غير مرصود'}.`,
            }
          : { en: 'DOM tree inspection unavailable.', ar: 'تعذر فحص شجرة DOM.' },
      },
      {
        itemKey: 'login_forms_analysis',
        title: { en: '6. Login, Credential & Form Security', ar: '٦. تحليل نماذج تسجيل الدخول والبيانات' },
        status: !hasHtml
          ? 'unavailable'
          : contentRes.data!.formCount > 0 || contentRes.data!.passwordInputCount > 0 || contentRes.data!.unwrappedPasswordInputCount > 0 || (contentRes.data!.personalFinanceFields?.length ?? 0) > 0
            ? 'inspected'
            : 'not_present',
        summary: !hasHtml
          ? { en: 'Form inspection unavailable.', ar: 'فحص النماذج غير متاح.' }
          : contentRes.data!.formCount === 0 && contentRes.data!.passwordInputCount === 0 && contentRes.data!.unwrappedPasswordInputCount === 0
            ? { en: 'No HTML login, password, or personal-data forms present on this page.', ar: 'لا توجد نماذج تسجيل دخول أو حقول كلمات مرور أو بيانات مالية في هذه الصفحة.' }
            : {
                en: `Forms: ${contentRes.data!.formCount} · Password fields: ${contentRes.data!.passwordInputCount} (${contentRes.data!.unwrappedPasswordInputCount} unwrapped) · PII/Finance hints: ${contentRes.data!.personalFinanceFields?.join(', ') || 'none'} · Cross-origin form actions: ${contentRes.data!.crossOriginFormActions.length} · JS hooks: ${sourceRes.sourceIntel.formExfiltrationHooks?.length ?? 0}.`,
                ar: `النماذج: ${contentRes.data!.formCount} · كلمات المرور: ${contentRes.data!.passwordInputCount} (${contentRes.data!.unwrappedPasswordInputCount} غير مغلفة) · حقول مالية/شخصية: ${contentRes.data!.personalFinanceFields?.join('، ') || 'لا يوجد'} · إرسال خارجي: ${contentRes.data!.crossOriginFormActions.length}.`,
              },
      },
      {
        itemKey: 'brand_consistency',
        title: { en: '7. Brand Claims & Ownership Consistency', ar: '٧. العلامات التجارية المكتشفة واتساق الهوية' },
        status: contentRes.data?.suspectedBrand || (contentRes.data?.oauthWidgetsDetected?.length ?? 0) > 0 || domainAuthenticity.status !== 'unknown_unverified'
          ? 'inspected'
          : 'not_present',
        summary: {
          en: `${domainAuthenticity.label.en}${contentRes.data?.oauthWidgetsDetected?.length ? ` · Benign OAuth widget(s): ${contentRes.data.oauthWidgetsDetected.join(', ')}` : ''}`,
          ar: `${domainAuthenticity.label.ar}${contentRes.data?.oauthWidgetsDetected?.length ? ` · أزرار OAuth معتادة (غير مشبوهة): ${contentRes.data.oauthWidgetsDetected.join('، ')}` : ''}`,
        },
        detail: `${domainAuthenticity.registrableDomain}${domainAuthenticity.parentCompany ? ` (${domainAuthenticity.parentCompany})` : ''}`,
      },
      {
        itemKey: 'external_third_party_domains',
        title: { en: '8. External Links & Third-Party Domains', ar: '٨. الروابط الخارجية ونطاقات الطرف الثالث' },
        status: !hasHtml
          ? 'unavailable'
          : sourceRes.supplyChain.totalExternalDomains > 0 || (contentRes.data?.externalLinkCount ?? 0) > 0
            ? 'inspected'
            : 'not_present',
        summary: !hasHtml
          ? { en: 'External DOM links unavailable (page content not readable).', ar: 'تعذر استخراج الروابط الخارجية لعدم قراءة محتوى الصفحة.' }
          : {
              en: `${sourceRes.supplyChain.totalExternalDomains} external domain(s) (${sourceRes.supplyChain.cdnDomains.length} CDN, ${sourceRes.sourceIntel.cssExternalDomains?.length ?? 0} CSS ext hosts) · Lookalike outbound links: ${lookalikeLinkCount} · Anchor mismatches: ${deceptionRes.data.visibleVsRealMismatches.length}.`,
              ar: `النطاقات الخارجية: ${sourceRes.supplyChain.totalExternalDomains} (${sourceRes.supplyChain.cdnDomains.length} شبكات CDN، ${sourceRes.sourceIntel.cssExternalDomains?.length ?? 0} مصادر CSS) · روابط مشابهة لعلامات تجارية: ${lookalikeLinkCount} · اختلاف نص الرابط: ${deceptionRes.data.visibleVsRealMismatches.length}.`,
            },
      },
      {
        itemKey: 'suspicious_behaviors',
        title: { en: '9. Suspicious Behavioral & Deception Signals', ar: '٩. مؤشرات السلوك المشبوه والتمويه' },
        status: 'inspected',
        summary: {
          en: `Redirects: ${redirectRes.hops.length - 1} · Popups: ${contentRes.data?.popupIndicators.length ?? 0} · Auto-downloads: ${contentRes.data?.autoDownloadTriggers?.length ?? 0} · Lures/fake alerts: ${(contentRes.data?.fakeAlertIndicators.length ?? 0) + (contentRes.data?.phishingKeywordsMatched.length ?? 0)} · Storage exfil hooks: ${sourceRes.sourceIntel.formExfiltrationHooks?.length ?? 0}.`,
          ar: `التحويلات: ${redirectRes.hops.length - 1} · نوافذ منبثقة: ${contentRes.data?.popupIndicators.length ?? 0} · تنزيل تلقائي: ${contentRes.data?.autoDownloadTriggers?.length ?? 0} · مؤشرات خداع: ${(contentRes.data?.fakeAlertIndicators.length ?? 0) + (contentRes.data?.phishingKeywordsMatched.length ?? 0)} · خطافات تسريب: ${sourceRes.sourceIntel.formExfiltrationHooks?.length ?? 0}.`,
        },
      },
      {
        itemKey: 'supporting_evidence',
        title: { en: '10. Supporting Evidence Summary', ar: '١٠. الأدلة التي تدعم الحكم' },
        status: scored.evidenceBuckets.confirmed.length > 0 ? 'inspected' : 'not_present',
        summary: {
          en: scored.evidenceBuckets.confirmed.slice(0, 3).map((e) => e.en).join(' | ') || 'No high-confidence failure evidence recorded.',
          ar: scored.evidenceBuckets.confirmed.slice(0, 3).map((e) => e.ar).join(' | ') || 'لم تُسجل أدلة خطورة مؤكدة.',
        },
      },
      {
        itemKey: 'opposing_conflicting_evidence',
        title: { en: '11. Opposing & Conflicting Evidence', ar: '١١. الأدلة التي تعارض الحكم أو تتضارب معه' },
        status: scored.evidenceBuckets.conflicting.length > 0 ? 'inspected' : 'not_present',
        summary: {
          en: scored.evidenceBuckets.conflicting.length > 0
            ? scored.evidenceBuckets.conflicting.map((c) => c.en).join(' | ')
            : `No direct conflict detected (${scored.evidenceBuckets.inconclusive.length} inconclusive/unavailable check(s) disclosed separately).`,
          ar: scored.evidenceBuckets.conflicting.length > 0
            ? scored.evidenceBuckets.conflicting.map((c) => c.ar).join(' | ')
            : `لا يوجد تعارض مباشر بين المصادر (مع الإفصاح عن ${scored.evidenceBuckets.inconclusive.length} فحصاً غير مكتمل أو غير متاح).`,
        },
      },
      {
        itemKey: 'inspection_completeness',
        title: { en: '12. Inspection Completeness & Capability Level', ar: '١٢. مستوى اكتمال الفحص ونطاقه' },
        status: 'inspected',
        summary: {
          en: `Coverage: ${scored.inspectionCoveragePercent}% · Level A Static Analysis: ${hasBlockedSite ? 'Blocked by target HTTP gate' : hasHtml ? 'Complete' : 'Unreachable'} (${scored.summaryStats.availableProviders}/${scored.summaryStats.totalProviders} threat feeds) · Level B External Cloud Browser: ${levelBRes.status === 'executed' ? `Executed (${levelBRes.networkRequests.length} reqs observed)` : `${levelBRes.status} (reduced confidence/coverage only)`}.`,
          ar: `نسبة التغطية: ${scored.inspectionCoveragePercent}% · المستوى A (التحليل الساكن): ${hasBlockedSite ? 'محجوب من خادم الهدف' : hasHtml ? 'مكتمل' : 'تعذر الوصول'} · المستوى B (المتصفح السحابي الخارجي): ${levelBRes.status === 'executed' ? `نُفّذ بنجاح (${levelBRes.networkRequests.length} طلب شبكي)` : 'غير متاح حالياً (تم خفض الثقة والتغطية فقط دون افتراض سلوك)'}.`,
        },
      },
    ];

    const analysisLevels: ScanReport['analysisLevels'] = {
      levelAStatic: {
        performed: true,
        status: hasBlockedSite ? 'blocked_by_site' : !hasHtml ? 'unavailable' : sourceRes.sourceIntel.dynamicContentAfterJsLikely ? 'partial' : 'complete',
        coverageItems: [
          'HTTP Response & Headers',
          'Non-Executing HTML/DOM Parser',
          'Static JavaScript & CSS Analysis',
          'Forms, Inputs & PII Audit',
          'Brand & Ownership Correlation',
          'DNS / RDAP / TLS / Redirects',
        ],
        summary: hasBlockedSite
          ? {
              en: `Level A reached target edge but target refused readable HTML (${contentRes.data?.blockedReason}). Only network, DNS, TLS, and external feed evidence was evaluated.`,
              ar: `وصل المستوى A للموقع لكن الخادم منع قراءة المحتوى (${contentRes.data?.blockedReason}). اعتمد الفحص على الشبكة وDNS وTLS ومزودي التهديدات فقط دون تخمين المحتوى.`,
            }
          : !hasHtml
            ? {
                en: 'Level A could not retrieve readable HTML content; safety is never assumed.',
                ar: 'تعذر استرجاع محتوى HTML في المستوى A؛ لا يُفترض أمان الرابط دون فحص محتواه.',
              }
            : {
                en: `Level A completed full static inspection of HTTP headers, HTML DOM (${contentRes.data!.visibleWordCount} words), CSS, ${contentRes.data!.inlineScriptCount} inline + ${sourceRes.sourceIntel.externalJsInspectedCount ?? 0} fetched external scripts, and ${sourceRes.formDetails.length} form(s).`,
                ar: `أتمّ المستوى A التحليل الساكن الكامل لاستجابة HTTP وDOM (${contentRes.data!.visibleWordCount} كلمة) وCSS و${contentRes.data!.inlineScriptCount} سكربت داخلي + ${sourceRes.sourceIntel.externalJsInspectedCount ?? 0} ملف JS خارجي و${sourceRes.formDetails.length} نموذجاً.`,
              },
      },
      levelBIsolatedBrowser: {
        performed: levelBRes.status === 'executed',
        available: levelBRes.status === 'executed',
        sandboxMode: levelBRes.status === 'executed' ? 'external_cloud_browser' : 'unavailable',
        dynamicDomDivergenceLikely: hasThinSpa,
        reason: levelBRes.executiveSummary,
      },
    };

    const report: ScanReport = {
      scanId: job.scanId,
      submittedUrl: options.url,
      normalizedUrl: validated.normalizedUrl,
      finalDestinationUrl: redirectRes.finalUrl,
      pageTitle: contentRes.data?.pageTitle || undefined,
      siteFaviconDataUrl: faviconRes.dataUrl,
      siteFaviconSourceUrl: faviconRes.sourceUrl,
      startedAt: job.startedAt,
      completedAt,
      durationMs: Date.now() - pipelineStart,
      status: scored.summaryStats.incompleteChecks > 0 ? 'partial' : 'completed',
      riskScore: scored.riskScore,
      classification: scored.classification,
      verdict: scored.verdict,
      confidenceScore: scored.confidenceScore,
      confidenceLabel: scored.confidenceLabel,
      inspectionCoveragePercent: scored.inspectionCoveragePercent,
      recommendation: scored.recommendation,
      topReasons: scored.topReasons,
      correlationNotes: scored.correlationNotes,
      conflictNotes: scored.conflictNotes,
      scoreBreakdown: scored.scoreBreakdown,
      evidenceBuckets: scored.evidenceBuckets,
      websiteIntelligenceReport,
      domainAuthenticity: scored.domainAuthenticity,
      separatedAssessments: scored.separatedAssessments,
      summaryStats: scored.summaryStats,
      sections: scored.sections,
      findings,
      redirects: redirectRes.hops,
      domainDeception: deceptionRes.data,
      urlEncryptionIntel: urlIntel.encryptionTelemetry,
      domainIntel: dnsRes.data,
      tlsIntel: tlsRes.data,
      contentIntel: contentRes.data,
      sourceIntel: sourceRes.sourceIntel,
      pageDiscovery: discoveryRes.pageDiscovery,
      formSecurityDetails: sourceRes.formDetails,
      supplyChain: sourceRes.supplyChain,
      xssAssessment: xssRes.data,
      visualIdentity: {
        attempted: true,
        screenshotAvailable: screenshotRes.screenshot.status === 'captured',
        brandMismatch: suspectedBrandConfirmed,
        titleMatchesBrandOutsideOfficial: false,
        faviconDetected: Boolean(faviconRes.dataUrl),
        similarityAssessment: {
          en: contentRes.data?.suspectedBrand
            ? contentRes.data.suspectedBrand.similarityOnly
              ? `Domain name similarity to ${contentRes.data.suspectedBrand.brand} (${contentRes.data.suspectedBrand.officialDomain}) detected; impersonation has not been proven.`
              : `Visual identity matches monitored brand "${contentRes.data.suspectedBrand.brand}" outside official domain.`
            : 'Visual identity telemetry verified.',
          ar: contentRes.data?.suspectedBrand
            ? contentRes.data.suspectedBrand.similarityOnly
              ? 'تم اكتشاف تشابه في اسم النطاق مع علامة تجارية معروفة، ولم يتم إثبات الانتحال.'
              : `تطابقت مؤشرات الهوية مع علامة "${contentRes.data.suspectedBrand.brand}" خارج النطاق الرسمي.`
            : 'تم التحقق من الهوية البصرية ومقارنتها بقاعدة البيانات.',
        },
        limitationNote: {
          en: 'Deterministic static heuristic comparison against known brand signatures; zero AI inference.',
          ar: 'مقارنة حتمية مع توقيعات العلامات التجارية دون أي استخدام للذكاء الاصطناعي.',
        },
      },
      fileAnalysis: {
        isDirectDownload: fileRes.isDirectDownload,
        directFile: fileRes.directFile,
        discoveredDownloads: fileRes.discoveredDownloads,
        dynamicAnalysisPerformed: false,
        sandboxNote: {
          en: 'Static header and magic-byte inspection only. No files executed.',
          ar: 'فحص التوقيع الساكن في الذاكرة فقط دون تشغيل أي ملفات.',
        },
      },
      threatProviders: intelRes.providers,
      screenshot: screenshotRes.screenshot,
      sandboxCapabilities: {
        ssrfGuardActive: true,
        isolatedBrowserWorker: levelBRes.status === 'executed',
        screenshotFallbackConfigured: Boolean(process.env.SCREENSHOTNEO_ACCESS_KEY),
        dynamicFileSandbox: false,
        inspectionMode: levelBRes.status === 'executed' ? 'isolated_worker' : 'controlled_server_fetch',
        disclosure: {
          en: levelBRes.status === 'executed'
            ? 'SSRF network guard active. Static Level A inspection, Level B External Cloud Browser execution, TLS inspection, and threat-feed correlation completed safely.'
            : 'SSRF network guard active. Static source inspection, multi-page crawling, TLS inspection, ScreenshotNeo preview gateway, and threat-feed correlation completed without executing target code locally.',
          ar: levelBRes.status === 'executed'
            ? 'حماية SSRF مفعلة. تم إتمام الفحص الساكن (Level A) والتنفيذ الحي عبر خدمة المتصفح السحابي الخارجي (Level B) والتشفير واستخبارات التهديدات بأمان.'
            : 'حماية SSRF مفعلة. تم إتمام فحص المصدر المتعدد الصفحات والتشفير ومعاينة ScreenshotNeo واستخبارات التهديدات دون تنفيذ أي أكواد محلياً.',
        },
      },
      analysisLevels,
      levelB: levelBRes,
    };

    const validatedReport = validateAndNormalizeReportConsistency(report);
    job.report = validatedReport;
    job.completedAt = completedAt;
    job.status = 'completed';
    updateStage(
      job,
      'report_generation',
      'completed',
      {
        en: `${scored.summaryStats.totalChecks} checks compiled in ${report.durationMs} ms`,
        ar: `تم تجميع ${scored.summaryStats.totalChecks} فحصاً خلال ${report.durationMs} مللي ثانية`,
      },
      Date.now() - t0
    );
    job.progressPercent = 100;
    jobEmitters.get(job.scanId)?.emit('update', job);
  } catch (err) {
    const message = (err as Error).message || 'Scan validation failed';
    updateStage(job, 'url_validation', 'failed', { en: message, ar: message });
    job.status = 'failed';
    job.completedAt = new Date().toISOString();
    job.error = { en: message, ar: message };
    jobEmitters.get(job.scanId)?.emit('update', job);
  }
}
