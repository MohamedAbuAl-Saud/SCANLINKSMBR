import { safeSingleFetch, type SafeFetchResult } from '../security/ssrfGuard.ts';
import type { CheckFinding, RedirectHop } from '../types.ts';
import { classifyDomainRelationship } from './officialDomainRegistry.ts';
import { extractRegistrableDomain } from './urlIntelligence.ts';

const MAX_REDIRECTS = 8;

export interface RedirectTraceResult {
  hops: RedirectHop[];
  finalUrl: string;
  finalFetch?: SafeFetchResult;
  findings: CheckFinding[];
  ssrfBlocked: boolean;
  loopDetected: boolean;
  httpDowngradeDetected: boolean;
}

export async function traceRedirectsSafely(initialUrl: string): Promise<RedirectTraceResult> {
  const now = new Date().toISOString();
  const hops: RedirectHop[] = [];
  const visited = new Set<string>();
  const initialParsed = new URL(initialUrl);
  const initialDomain = extractRegistrableDomain(initialParsed.hostname);

  let currentUrl = initialUrl;
  let prevProtocol = initialParsed.protocol;
  let finalFetch: SafeFetchResult | undefined;
  let ssrfBlocked = false;
  let loopDetected = false;
  let httpDowngradeDetected = false;
  let crossDomainCount = 0;
  let fetchError: string | undefined;

  for (let step = 1; step <= MAX_REDIRECTS + 1; step++) {
    const hopParsed = new URL(currentUrl);
    if (visited.has(currentUrl)) {
      loopDetected = true;
      hops.push({
        step,
        url: currentUrl,
        hostname: hopParsed.hostname,
        protocol: hopParsed.protocol,
        statusCode: null,
        crossDomain: false,
        downgradedToHttp: false,
        latencyMs: 0,
        blockedReason: 'Redirect loop detected',
      });
      break;
    }
    visited.add(currentUrl);

    try {
      const res = await safeSingleFetch(currentUrl, {
        method: 'GET',
        timeoutMs: 8000,
        maxBytes: 2 * 1024 * 1024,
      });

      const hopDomain = extractRegistrableDomain(hopParsed.hostname);
      const isCrossDomain = hopDomain !== initialDomain;
      const orgRel = classifyDomainRelationship(initialParsed.hostname, hopParsed.hostname);
      const isUnverifiedCrossDomain = isCrossDomain && !orgRel.isBenignOrAuthorized;
      if (isUnverifiedCrossDomain && step > 1) crossDomainCount++;

      const downgraded = step > 1 && prevProtocol === 'https:' && hopParsed.protocol === 'http:';
      if (downgraded) httpDowngradeDetected = true;
      prevProtocol = hopParsed.protocol;

      const location = res.headers['location'];
      const isRedirectStatus = res.status >= 300 && res.status < 400 && Boolean(location);
      let nextUrl: string | undefined;
      if (isRedirectStatus && location) {
        try {
          nextUrl = new URL(location, currentUrl).toString();
        } catch {
          nextUrl = location;
        }
      }

      hops.push({
        step,
        url: currentUrl,
        sourceUrl: currentUrl,
        destinationUrl: nextUrl || currentUrl,
        redirectType: step === 1 ? 'initial' : 'http_3xx',
        hostname: hopParsed.hostname,
        protocol: hopParsed.protocol,
        statusCode: res.status,
        locationHeader: location,
        resolvedIp: res.resolvedIp,
        crossDomain: isUnverifiedCrossDomain,
        isSameOrganization: orgRel.isBenignOrAuthorized,
        relationshipType: orgRel.relationship,
        relationshipDetail: orgRel.detail,
        downgradedToHttp: downgraded,
        latencyMs: res.latencyMs,
      });

      if (!isRedirectStatus) {
        finalFetch = res;
        // Inspect final HTML for static meta-refresh or window.location redirect target annotation (without executing)
        const ct = (res.headers['content-type'] || '').toLowerCase();
        if (res.buffer && (!ct || ct.includes('html'))) {
          const snippet = res.buffer.slice(0, 65536).toString('utf8');
          const metaMatch = snippet.match(/<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["'][^"']*url\s*=\s*([^"'\s>]+)/i);
          if (metaMatch?.[1]) {
            try {
              const target = new URL(metaMatch[1].trim(), currentUrl);
              const metaRel = classifyDomainRelationship(initialParsed.hostname, target.hostname);
              const metaCrossDomain =
                extractRegistrableDomain(target.hostname) !== initialDomain && !metaRel.isBenignOrAuthorized;
              if (metaCrossDomain) crossDomainCount++;
              hops.push({
                step: step + 1,
                url: target.toString(),
                sourceUrl: currentUrl,
                destinationUrl: target.toString(),
                redirectType: 'meta_refresh',
                hostname: target.hostname.toLowerCase(),
                protocol: target.protocol,
                statusCode: null,
                resolvedIp: undefined,
                crossDomain: metaCrossDomain,
                isSameOrganization: metaRel.isBenignOrAuthorized,
                relationshipType: metaRel.relationship,
                relationshipDetail: metaRel.detail,
                downgradedToHttp: hopParsed.protocol === 'https:' && target.protocol === 'http:',
                latencyMs: 0,
              });
            } catch {
              // ignore unparseable meta-refresh
            }
          } else {
            const jsRedirMatch = snippet.match(
              /(?:window|self|top)?\.?location(?:\.href)?\s*=\s*['"](https?:\/\/[^'"]+)['"]|location\.(?:replace|assign)\s*\(\s*['"](https?:\/\/[^'"]+)['"]\s*\)/i
            );
            const rawJsTarget = jsRedirMatch?.[1] || jsRedirMatch?.[2];
            if (rawJsTarget) {
              try {
                const target = new URL(rawJsTarget.trim(), currentUrl);
                if (target.hostname.toLowerCase() !== hopParsed.hostname.toLowerCase()) {
                  const jsRel = classifyDomainRelationship(initialParsed.hostname, target.hostname);
                  const jsCrossDomain =
                    extractRegistrableDomain(target.hostname) !== initialDomain && !jsRel.isBenignOrAuthorized;
                  if (jsCrossDomain) crossDomainCount++;
                  hops.push({
                    step: step + 1,
                    url: target.toString(),
                    sourceUrl: currentUrl,
                    destinationUrl: target.toString(),
                    redirectType: 'js_static',
                    hostname: target.hostname.toLowerCase(),
                    protocol: target.protocol,
                    statusCode: null,
                    resolvedIp: undefined,
                    crossDomain: jsCrossDomain,
                    isSameOrganization: jsRel.isBenignOrAuthorized,
                    relationshipType: jsRel.relationship,
                    relationshipDetail: jsRel.detail,
                    downgradedToHttp: hopParsed.protocol === 'https:' && target.protocol === 'http:',
                    latencyMs: 0,
                  });
                }
              } catch {
                // ignore unparseable static JS target
              }
            }
          }
        }
        break;
      }

      if (step > MAX_REDIRECTS) {
        hops[hops.length - 1].blockedReason = `Exceeded max redirect limit (${MAX_REDIRECTS})`;
        hops[hops.length - 1].redirectType = 'loop_or_blocked';
        break;
      }

      currentUrl = new URL(location!, currentUrl).toString();
    } catch (err) {
      const msg = (err as Error).message || 'Fetch error';
      if (msg.includes('SSRF Guard')) {
        ssrfBlocked = true;
      } else {
        fetchError = msg;
      }
      hops.push({
        step,
        url: currentUrl,
        sourceUrl: currentUrl,
        destinationUrl: currentUrl,
        redirectType: 'loop_or_blocked',
        hostname: hopParsed.hostname,
        protocol: hopParsed.protocol,
        statusCode: null,
        crossDomain: extractRegistrableDomain(hopParsed.hostname) !== initialDomain,
        downgradedToHttp: false,
        latencyMs: 0,
        blockedReason: msg,
      });
      break;
    }
  }

  const finalUrl = finalFetch ? finalFetch.url : currentUrl;
  const redirectCount = Math.max(0, hops.filter((h) => h.redirectType === 'http_3xx' || h.step > 1).length);
  const findings: CheckFinding[] = [];

  if (ssrfBlocked) {
    findings.push({
      id: 'redirect-ssrf-block',
      section: 'redirect_analysis',
      test: { en: 'Redirect SSRF & Private Network Guard', ar: 'حماية إعادة التوجيه من الشبكات الداخلية (SSRF)' },
      result: { en: 'Blocked redirect to restricted/private network target', ar: 'تم حظر إعادة توجيه إلى عنوان شبكة داخلي أو محظور' },
      status: 'failed',
      severity: 'critical',
      weight: 45,
      evidence: hops.map((h) => h.blockedReason).filter(Boolean).join(' | '),
      explanation: {
        en: 'The target attempted to redirect the scanner to a private, loopback, or cloud metadata address. Execution terminated to prevent internal network probing.',
        ar: 'حاول الرابط إعادة توجيه الفاحص إلى عنوان شبكة داخلية أو خدمة بيانات سحابية، وتم إيقاف الاتصال فوراً.',
      },
      recommendedAction: {
        en: 'Do not visit this URL; it is attempting SSRF or internal network redirection.',
        ar: 'لا تفتح هذا الرابط مطلقاً؛ تم رصد محاولة توجيه نحو شبكات داخلية.',
      },
      forensic: {
        whereDetected: { en: `Redirect hop #${hops.length}`, ar: `القفزة رقم ${hops.length}` },
        whyRisky: { en: 'External links should never route into RFC1918/localhost/metadata networks.', ar: 'لا يجوز لأي موقع عام إعادة التوجيه لعناوين شبكات داخلية أو محلية.' },
        howExploited: { en: 'SSRF exploits force servers to probe cloud metadata (169.254.169.254) or internal admin panels.', ar: 'تُستخدم لإجبار الخوادم على قراءة بيانات السحابة الداخلية أو الواجهات المحمية.' },
        userImpact: { en: 'Indicates hostile redirect behavior.', ar: 'يشير إلى سلوك توجيه عدائي.' },
        notProvenAlone: { en: 'Localhost redirects may be misconfigurations on dev sites, but remain blocked for safety.', ar: 'قد تحدث أحياناً عن طريق خطأ إعدادات في مواقع التطوير ولكنها محظورة أمنياً.' },
      },
      source: 'SM SSRF Guard',
      timestamp: now,
      confidence: 100,
    });
  } else if (fetchError && !finalFetch) {
    findings.push({
      id: 'redirect-chain-reachability',
      section: 'redirect_analysis',
      test: { en: 'HTTP Reachability & Redirect Chain', ar: 'فحص الوصول وسلسلة إعادة التوجيه' },
      result: { en: 'Target unreachable or timed out', ar: 'تعذر الوصول إلى الهدف أو انتهت المهلة' },
      status: 'unknown',
      severity: 'unknown',
      weight: 0,
      evidence: fetchError,
      explanation: {
        en: 'Could not retrieve a completed HTTP response within safety limits. Unreachable targets are never treated as safe.',
        ar: 'تعذر الحصول على استجابة HTTP مكتملة ضمن مهلة الأمان. عدم توفر الاستجابة لا يُعد دليلاً على الأمان.',
      },
      recommendedAction: {
        en: 'Treat unverified/unreachable URLs with caution until live inspection completes.',
        ar: 'تعامل مع الروابط غير القابلة للوصول بحذر ولا تفترض سلامتها.',
      },
      source: 'SM Redirect Tracer',
      timestamp: now,
      confidence: 25,
      errorState: fetchError,
    });
  } else {
    const suspiciousChain = loopDetected || httpDowngradeDetected || redirectCount >= 4 || crossDomainCount >= 2;
    findings.push({
      id: 'redirect-chain-analysis',
      section: 'redirect_analysis',
      test: { en: 'Redirect Chain, Cross-Domain & Downgrade Check', ar: 'تحليل سلسلة التوجيه والتنقل بين النطاقات وخفض الأمان' },
      result: httpDowngradeDetected
        ? { en: `HTTPS-to-HTTP downgrade detected across ${redirectCount} hop(s)`, ar: `رصد خفض تشفير من HTTPS إلى HTTP عبر ${redirectCount} قفزة` }
        : {
            en: `${redirectCount} redirect(s), ${crossDomainCount} cross-domain hop(s)`,
            ar: `${redirectCount} إعادة توجيه، ${crossDomainCount} تنقل عبر نطاقات مختلفة`,
          },
      status: loopDetected || httpDowngradeDetected ? 'failed' : suspiciousChain ? 'warning' : 'pass',
      severity: httpDowngradeDetected || loopDetected ? 'high' : suspiciousChain ? 'medium' : 'informational',
      weight: httpDowngradeDetected ? 22 : loopDetected ? 20 : suspiciousChain ? 14 : 0,
      evidence: hops.map((h) => `${h.step}: [${h.statusCode ?? 'ERR'}] ${h.hostname} (${h.url})`).join(' -> '),
      explanation: {
        en: httpDowngradeDetected
          ? 'Redirect chain downgraded traffic from encrypted HTTPS to unencrypted HTTP, exposing session cookies or payloads.'
          : loopDetected
            ? 'Infinite redirect loop detected.'
            : suspiciousChain
              ? 'Multiple cross-domain hops can indicate traffic cloaking, compromised redirectors, or phishing relays.'
              : redirectCount === 0
                ? 'Target responded directly with zero redirects.'
                : 'Redirect chain resolves cleanly.',
        ar: httpDowngradeDetected
          ? 'قامت سلسلة إعادة التوجيه بخفض الاتصال من HTTPS المشفر إلى HTTP غير المشفر.'
          : loopDetected
            ? 'تم اكتشاف حلقة إعادة توجيه لا نهائية.'
            : suspiciousChain
              ? 'تعدد القفزات عبر نطاقات مختلفة قد يشير إلى إخفاء الوجهة الفعلية.'
              : redirectCount === 0
                ? 'استجاب الرابط مباشرة دون إعادة توجيه.'
                : 'سلسلة إعادة التوجيه طبيعية.',
      },
      recommendedAction: {
        en: suspiciousChain ? 'Verify the Final Resolved Destination URL before proceeding.' : 'No action required.',
        ar: suspiciousChain ? 'تحقق من الوجهة النهائية في التقرير قبل المتابعة.' : 'لا يلزم إجراء.',
      },
      forensic: {
        whereDetected: {
          en: `HTTP redirect chain (${redirectCount} hop(s) from ${initialParsed.hostname} to ${new URL(finalUrl).hostname})`,
          ar: `سلسلة إعادة التوجيه (${redirectCount} قفزة نحو ${new URL(finalUrl).hostname})`,
        },
        whyRisky: {
          en: 'Multi-hop cloaking chains bounce victims through benign domains before landing on fresh phishing kits.',
          ar: 'تستخدم السلاسل متعددة القفزات لإخفاء النطاق النهائي المشبوه خلف نطاقات وسيطة أو مختصرة.',
        },
        howExploited: {
          en: 'Campaigns rotate final phishing URLs behind open redirectors or shorteners without altering sent links.',
          ar: 'تبديل الوجهة النهائية خلف المختصرات أو الموجهات دون تغيير الرابط المرسل للضحية.',
        },
        userImpact: { en: 'Hidden destination changes or protocol downgrade.', ar: 'انتقال صامت لنطاق مختلف أو اتصال غير مشفر.' },
        notProvenAlone: {
          en: '1–2 cross-domain hops are normal for CDNs and www canonicalization; evaluate the final domain and page content.',
          ar: '١–٢ قفزة للتحويل إلى www أو CDN أمر طبيعي ولا يثبت خطراً بمفرده.',
        },
      },
      source: 'SM Redirect Tracer',
      timestamp: now,
      confidence: 95,
    });
  }

  return {
    hops,
    finalUrl,
    finalFetch,
    findings,
    ssrfBlocked,
    loopDetected,
    httpDowngradeDetected,
  };
}
