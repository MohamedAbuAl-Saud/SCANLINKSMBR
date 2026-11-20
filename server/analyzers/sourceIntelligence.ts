import * as cheerio from 'cheerio';
import type {
  BackgroundDataCollectionItem,
  BilingualText,
  CheckFinding,
  CheckStatus,
  DiscoveredSubdomainInfo,
  ExternalDataTransmissionItem,
  FormSecurityDetail,
  RiskSeverity,
  SourceIntelligenceData,
  SupplyChainResourceSummary,
  SuspiciousCodeSignal,
  TransmittedDataType,
  WorkerDetectionInfo,
} from '../types.ts';
import { detectCompoundBrandLookalike } from './brandIntelligence.ts';
import { classifyDomainRelationship, lookupDomainOwnership } from './officialDomainRegistry.ts';
import { extractRegistrableDomain } from './urlIntelligence.ts';
import {
  analyzeScriptsWithAst,
  taintsToTransmittedTypes,
  type JsDataFlowAnalysisResult,
  type ScriptInput,
} from './jsDataFlowAnalyzer.ts';
import { classifyNetworkChannel } from './remoteBrowserAdapter.ts';
import { analyzeCookieIntelligence } from './cookieIntelligence.ts';
import { analyzeAdvertisingIntelligence } from './advertisingIntelligence.ts';

export interface ExternalSourceAssetsInput {
  fetchedScripts?: { url: string; code: string }[];
  fetchedCss?: { url: string; css: string }[];
}

function classifySubdomainRole(host: string): DiscoveredSubdomainInfo['role'] {
  const lower = host.toLowerCase();
  if (/(?:^|\.)(?:auth|login|signin|sso|oauth|accounts?|id|verify|secure)\b/.test(lower)) return 'auth';
  if (/(?:^|\.)(?:api|graphql|gateway|ws|rpc|rest|backend)\b/.test(lower)) return 'api';
  if (/(?:^|\.)(?:cdn|static|assets|media|img|images|fonts|js|css|files|dl)\b/.test(lower)) return 'cdn_static';
  if (/(?:^|\.)(?:mail|smtp|imap|mx|webmail|newsletter)\b/.test(lower)) return 'mail';
  if (/(?:^|\.)(?:admin|panel|dashboard|cpanel|manage|internal|console)\b/.test(lower)) return 'admin';
  return 'general';
}

const KNOWN_CDN_DOMAINS = new Set([
  'cdnjs.cloudflare.com',
  'cdn.jsdelivr.net',
  'unpkg.com',
  'ajax.googleapis.com',
  'code.jquery.com',
  'stackpath.bootstrapcdn.com',
  'maxcdn.bootstrapcdn.com',
  'cdn.tailwindcss.com',
  'fonts.googleapis.com',
  'fonts.gstatic.com',
]);

const KNOWN_TRACKERS = [
  { name: 'Google Analytics / GTM', pattern: /googletagmanager\.com|google-analytics\.com|ga\.js|gtag/i },
  { name: 'Meta Pixel', pattern: /connect\.facebook\.net|fbevents\.js/i },
  { name: 'Hotjar', pattern: /hotjar\.com/i },
  { name: 'Mixpanel', pattern: /mixpanel\.com/i },
  { name: 'Sentry', pattern: /sentry\.io|browser\.sentry-cdn\.com/i },
  { name: 'Cloudflare Insights', pattern: /static\.cloudflareinsights\.com/i },
];

const VULNERABLE_LIB_PATTERNS = [
  { library: 'jQuery', pattern: /jquery[.-](\d+\.\d+\.\d+)/i, maxSafe: '3.5.0', advisory: 'jQuery <3.5.0 is vulnerable to XSS in HTML parsing.' },
  { library: 'Bootstrap JS', pattern: /bootstrap[.-](\d+\.\d+\.\d+)/i, maxSafe: '4.3.1', advisory: 'Bootstrap <4.3.1 has XSS vulnerabilities in tooltip/popover data attributes.' },
  { library: 'AngularJS', pattern: /angular[.-](\d+\.\d+\.\d+)/i, maxSafe: '1.8.0', advisory: 'AngularJS 1.x has multiple prototype pollution and template injection vectors.' },
  { library: 'Lodash', pattern: /lodash[.-](\d+\.\d+\.\d+)/i, maxSafe: '4.17.21', advisory: 'Lodash <4.17.21 is vulnerable to prototype pollution and regular expression denial of service.' },
];

function decodeJsObfuscatedExpression(
  expr: string,
  varMap: Map<string, { value: string; obfuscated: boolean; from: string }>
): { value: string; obfuscated: boolean; decodedFrom?: string } | null {
  const trimmed = expr.trim().replace(/;$/, '');
  if (!trimmed) return null;

  // 1. Variable lookup
  if (/^[A-Za-z_$][A-Za-z0-9_$]{0,40}$/.test(trimmed)) {
    const resolved = varMap.get(trimmed);
    if (resolved) return { value: resolved.value, obfuscated: resolved.obfuscated, decodedFrom: resolved.from };
    return null;
  }

  // 2. atob('...')
  const atobMatch = trimmed.match(/^atob\s*\(\s*(['"`])([A-Za-z0-9+/=_-]{8,})\1\s*\)$/i);
  if (atobMatch) {
    try {
      const normalized = atobMatch[2].replace(/-/g, '+').replace(/_/g, '/');
      const decoded = Buffer.from(normalized, 'base64').toString('utf8').trim();
      if (/^https?:\/\/|^wss?:\/\/|^\/[A-Za-z0-9/_-]+/i.test(decoded)) {
        return { value: decoded, obfuscated: true, decodedFrom: `atob("${atobMatch[2].slice(0, 32)}...")` };
      }
    } catch {
      return null;
    }
  }

  // 3. decodeURIComponent('...') / unescape('...')
  const decodeUriMatch = trimmed.match(/^(?:decodeURIComponent|unescape)\s*\(\s*(['"`])([^'"`]+)\1\s*\)$/i);
  if (decodeUriMatch) {
    try {
      const decoded = decodeURIComponent(decodeUriMatch[2]).trim();
      if (/^https?:\/\/|^wss?:\/\/|^\/[A-Za-z0-9/_-]+/i.test(decoded)) {
        return { value: decoded, obfuscated: true, decodedFrom: 'decodeURIComponent(...)' };
      }
    } catch {
      return null;
    }
  }

  // 4. String.fromCharCode(...)
  const charCodeMatch = trimmed.match(/^String\.fromCharCode\s*\(\s*([0-9,\s]{10,300})\s*\)$/i);
  if (charCodeMatch) {
    const nums = charCodeMatch[1].split(',').map((n) => Number(n.trim())).filter((n) => Number.isFinite(n) && n >= 32 && n <= 126);
    if (nums.length >= 8) {
      const decoded = String.fromCharCode(...nums).trim();
      if (/^https?:\/\/|^wss?:\/\//i.test(decoded)) {
        return { value: decoded, obfuscated: true, decodedFrom: 'String.fromCharCode(...)' };
      }
    }
  }

  // 5. Concatenated string literals: 'https://' + 'evil.com' + '/collect'
  if (/^(['"`][^'"`]+['"`]\s*\+\s*)+['"`][^'"`]+['"`]$/.test(trimmed)) {
    const parts = Array.from(trimmed.matchAll(/(['"`])([^'"`]+)\1/g)).map((m) => m[2]);
    const joined = parts.join('').trim();
    if (/^https?:\/\/|^wss?:\/\/|^\/[A-Za-z0-9/_-]+/i.test(joined)) {
      return { value: joined, obfuscated: true, decodedFrom: 'String concatenation' };
    }
  }

  // 6. Plain or \xHH / \uHHHH escaped string literal
  const litMatch = trimmed.match(/^(['"`])([^'"`]{2,260})\1$/);
  if (litMatch) {
    let val = litMatch[2];
    const hasEscapes = /\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}/.test(val);
    if (hasEscapes) {
      val = val
        .replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
        .replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    }
    val = val.trim();
    if (/^https?:\/\/|^wss?:\/\/|^\/\/[A-Za-z0-9.-]+|^\/[A-Za-z0-9_./?=&-]+/i.test(val)) {
      return { value: val, obfuscated: hasEscapes, decodedFrom: hasEscapes ? 'Hex/Unicode escape string' : undefined };
    }
  }

  return null;
}

function splitCombinedSetCookieHeader(rawHeader: string): string[] {
  return rawHeader
    .split(/,(?=\s*[!#$%&'*+\-.^_`|~0-9A-Za-z]+\s*=)/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function classifyDestinationRole(
  destHost: string,
  relationshipStatus: ExternalDataTransmissionItem['relationshipStatus']
): ExternalDataTransmissionItem['destinationRole'] {
  if (/cdnjs|jsdelivr|unpkg|cloudflare|akamai|fastly|cloudfront|fonts\./i.test(destHost)) return 'cdn';
  if (/google-analytics|googletagmanager|clarity\.ms|hotjar|plausible|matomo|segment|mixpanel|posthog|sentry/i.test(destHost)) {
    return 'analytics';
  }
  if (/doubleclick|googlesyndication|facebook\.com|connect\.facebook|tiktok|criteo|taboola|outbrain|popads|adsterra|propellerads/i.test(destHost)) {
    return 'ad_network';
  }
  if (/stripe\.com|paypal\.com|checkout|pay\.|braintree|adyen/i.test(destHost)) return 'payment_gateway';
  if (/accounts\.google|login\.microsoftonline|appleid\.apple|github\.com|auth0|okta|nafath/i.test(destHost)) {
    return 'auth_provider';
  }
  if (relationshipStatus === 'same_organization' || relationshipStatus === 'authorized_provider') return 'api_backend';
  return 'unverified_third_party';
}

const DEV_BUILD_ENDPOINT_PATH_RE =
  /(?:^|\/)(?:@vite\/client|vite-hmr|__vite_ping|@react-refresh|sockjs-node|__webpack_hmr|hot-update\.(?:js|json))(?:\?|$|#)/i;

function isLoopbackHost(host: string): boolean {
  const lower = host.toLowerCase();
  return lower === 'localhost' || lower === '127.0.0.1' || lower === '[::1]' || lower === '::1';
}

function buildBackgroundCollectionsFromAst(
  astResult: JsDataFlowAnalysisResult,
  externalDataTransmissions: ExternalDataTransmissionItem[]
): BackgroundDataCollectionItem[] {
  const items: BackgroundDataCollectionItem[] = [];
  const seenCat = new Set<string>();
  const hasHarmfulExternalForCategory = (cat: BackgroundDataCollectionItem['category']): boolean => {
    if (cat === 'browser_fingerprinting') {
      return externalDataTransmissions.some((t) => t.isThirdParty && t.transmittedDataTypes.includes('device_fingerprint'));
    }
    if (cat === 'cookies_storage') {
      return externalDataTransmissions.some(
        (t) => t.isHarmful && (t.transmittedDataTypes.includes('cookies') || t.transmittedDataTypes.includes('storage_data'))
      );
    }
    if (cat === 'credentials_inputs') {
      return externalDataTransmissions.some(
        (t) => t.isHarmful && (t.transmittedDataTypes.includes('credentials') || t.transmittedDataTypes.includes('financial_pii'))
      );
    }
    if (cat === 'keystrokes_clipboard') {
      return externalDataTransmissions.some((t) => t.isHarmful && t.transmittedDataTypes.includes('keystrokes_clipboard'));
    }
    if (cat === 'background_polling') {
      return externalDataTransmissions.some((t) => t.isHarmful && t.frequency === 'periodic');
    }
    return externalDataTransmissions.some((t) => t.isHarmful);
  };

  for (const bg of astResult.backgroundCollections) {
    // Only surface items that represent real external/untrusted exfiltration OR active cross-site hardware fingerprinting
    if (bg.isBenignStandalone && !bg.transmittedExternally) continue;
    if (!hasHarmfulExternalForCategory(bg.category)) continue;
    if (seenCat.has(bg.category)) continue;
    seenCat.add(bg.category);

    const titles: Record<BackgroundDataCollectionItem['category'], BilingualText> = {
      cookies_storage: { en: 'Cookies & Browser Storage Exfiltration', ar: 'جمع وتسريب الكوكيز أو التخزين المحلي' },
      credentials_inputs: { en: 'Credential / Password Input Harvesting', ar: 'التقاط حقول كلمات المرور بالخلفية' },
      browser_fingerprinting: { en: 'Browser / Hardware Fingerprint Exfiltration', ar: 'جمع وإرسال بصمة الجهاز والمتصفح' },
      keystrokes_clipboard: { en: 'Keystroke & Clipboard Data Exfiltration', ar: 'التقاط وإرسال ضغطات المفاتيح أو الحافظة' },
      device_network_webrtc: { en: 'Device & Network Probing', ar: 'فحص الشبكة والجهاز بالخلفية' },
      background_polling: { en: 'Periodic / On-Exit Sensitive Exfiltration Loop', ar: 'إرسال دوري أو عند المغادرة لبيانات حساسة' },
    };

    items.push({
      id: `bg-${bg.category}`,
      category: bg.category,
      title: titles[bg.category],
      apisUsed: bg.apisUsed,
      triggers: bg.triggers,
      excerpt: bg.excerpt,
      riskLevel: bg.transmittedExternally ? 'high' : 'medium',
      sourceScript: bg.sourceScript,
      sourceFunction: bg.sourceFunction,
      pipelineStage: bg.transmittedExternally
        ? 'SOURCE -> COLLECTION -> TRANSMISSION -> EXTERNAL_DESTINATION'
        : 'SOURCE -> COLLECTION -> LOCAL_PROCESSING',
      transmittedExternally: bg.transmittedExternally,
      consentState: bg.consentGated ? 'post_consent' : 'pre_consent',
      detail: {
        en: `${bg.apisUsed.join(', ')} inside ${bg.sourceFunction} (${bg.sourceScript}) flows into untrusted external transmission.`,
        ar: `استدعاء (${bg.apisUsed.join('، ')}) داخل ${bg.sourceFunction} يتدفق نحو إرسال خارجي غير موثوق.`,
      },
    });
  }

  return items;
}

function buildExternalTransmissionsFromAst(params: {
  astResult: JsDataFlowAnalysisResult;
  finalUrl: string;
  finalHost: string;
  finalRegDomain: string;
  crossOriginFormActions: string[];
  hasPasswordOnPage: boolean;
  consentBannerPresent: boolean;
}): ExternalDataTransmissionItem[] {
  const {
    astResult,
    finalUrl,
    finalHost,
    finalRegDomain,
    crossOriginFormActions,
    hasPasswordOnPage,
    consentBannerPresent,
  } = params;

  const results: ExternalDataTransmissionItem[] = [];
  const seen = new Set<string>();

  const labelEn: Record<TransmittedDataType, string> = {
    credentials: 'Credentials / Passwords',
    session_tokens: 'Session / Auth Tokens',
    cookies: 'Browser Cookies',
    financial_pii: 'Financial / Payment / OTP Data',
    keystrokes_clipboard: 'Keystrokes / Clipboard Input',
    device_fingerprint: 'Device & Hardware Fingerprint',
    analytics_metrics: 'Page Analytics / UX Metrics',
    error_telemetry: 'Performance / Error Telemetry',
    functional_state: 'App Functional State',
    unknown: 'Unknown Payload',
    personal_pii: 'Personal PII',
    api_keys: 'API Keys / Secrets',
    form_inputs: 'Form Inputs',
    geolocation: 'Geolocation',
    storage_data: 'Local / Session Storage Data',
    system_telemetry: 'System Telemetry',
  };

  for (const tx of astResult.transmissions) {
    if (!tx.obfuscatedUrl && DEV_BUILD_ENDPOINT_PATH_RE.test(tx.destinationUrl)) continue;

    let resolvedUrl: URL;
    try {
      const candidate = tx.destinationUrl.startsWith('//') ? `https:${tx.destinationUrl}` : tx.destinationUrl;
      resolvedUrl = new URL(candidate, finalUrl);
    } catch {
      continue;
    }
    if (!['http:', 'https:', 'ws:', 'wss:'].includes(resolvedUrl.protocol)) continue;
    if (!tx.obfuscatedUrl && DEV_BUILD_ENDPOINT_PATH_RE.test(resolvedUrl.pathname + resolvedUrl.search)) continue;

    const destUrlStr = resolvedUrl.toString().slice(0, 180);
    const destHost = resolvedUrl.hostname.toLowerCase();
    // Skip dev loopback telemetry when target itself isn't a loopback test
    if (!tx.obfuscatedUrl && isLoopbackHost(destHost) && !isLoopbackHost(finalHost)) continue;

    const destReg = extractRegistrableDomain(destHost);
    const isThirdParty = destReg !== finalRegDomain;
    const dedupKey = `${tx.method}|${destUrlStr}`;
    if (seen.has(dedupKey)) continue;
    seen.add(dedupKey);

    const rel = classifyDomainRelationship(finalHost, destHost);
    const lookalike = !lookupDomainOwnership(destHost).matched ? detectCompoundBrandLookalike(destHost, destReg) : null;
    const relationshipStatus: ExternalDataTransmissionItem['relationshipStatus'] =
      !isThirdParty || rel.isSameOrganization
        ? 'same_organization'
        : lookalike
          ? 'suspicious_lookalike'
          : rel.isBenignOrAuthorized
            ? 'authorized_provider'
            : 'external_unknown';

    const taintsSet = new Set(tx.taintTags);
    const transmittedDataTypes = taintsToTransmittedTypes(taintsSet, destUrlStr);

    const channelClassification = classifyNetworkChannel(destUrlStr, finalHost, tx.httpMethod);
    const channelCategory = channelClassification.category;

    const hasSevereSecret =
      transmittedDataTypes.includes('credentials') ||
      transmittedDataTypes.includes('financial_pii') ||
      transmittedDataTypes.includes('keystrokes_clipboard') ||
      taintsSet.has('camera_mic') ||
      taintsSet.has('geolocation');
    const hasCookieOrStorage =
      transmittedDataTypes.includes('cookies') ||
      transmittedDataTypes.includes('session_tokens') ||
      transmittedDataTypes.includes('storage_data');
    const hasFingerprint = transmittedDataTypes.includes('device_fingerprint') || taintsSet.has('ip_profiling');
    const isUntrustedDest =
      relationshipStatus === 'external_unknown' ||
      relationshipStatus === 'suspicious_lookalike' ||
      tx.obfuscatedUrl;
    const isUntrustedThirdParty =
      isThirdParty && relationshipStatus !== 'same_organization' && relationshipStatus !== 'authorized_provider';

    const pairedWithSensitiveCollection =
      hasSevereSecret ||
      transmittedDataTypes.includes('cookies') ||
      hasFingerprint;

    let harmClassification: ExternalDataTransmissionItem['harmClassification'];
    let isHarmful = false;

    const destinationRole = classifyDestinationRole(destHost, relationshipStatus);
    const isAuthorizedAdOrAnalytics =
      relationshipStatus === 'authorized_provider' &&
      (destinationRole === 'analytics' || destinationRole === 'ad_network');

    const isVerifiedBenignTelemetry =
      !hasSevereSecret &&
      !hasCookieOrStorage &&
      !tx.hasUnknownPayload &&
      transmittedDataTypes[0] !== 'unknown' &&
      (taintsSet.has('analytics_metrics') || taintsSet.has('error_telemetry') || taintsSet.has('functional_state')) &&
      !taintsSet.has('camera_mic') &&
      !taintsSet.has('ip_profiling') &&
      !taintsSet.has('url_params');

    if (
      channelCategory === 'HIGH_RISK_EXFILTRATION_CHANNEL' ||
      channelCategory === 'WEBHOOK_OR_BOT_SINK' ||
      (hasSevereSecret && (isUntrustedThirdParty || tx.obfuscatedUrl || tx.method === 'dynamic_beacon')) ||
      (transmittedDataTypes.includes('cookies') && isUntrustedDest && isThirdParty) ||
      (transmittedDataTypes.includes('cookies') && !isThirdParty && tx.obfuscatedUrl) ||
      (relationshipStatus === 'suspicious_lookalike' && isThirdParty && pairedWithSensitiveCollection) ||
      (tx.obfuscatedUrl && isThirdParty && hasCookieOrStorage)
    ) {
      harmClassification = 'malicious_harmful';
      isHarmful = true;
    } else if (
      channelCategory === 'IP_AND_DEVICE_PROFILING' ||
      (isThirdParty && hasFingerprint) ||
      (transmittedDataTypes.includes('cookies') && isThirdParty && !(isAuthorizedAdOrAnalytics && (consentBannerPresent || tx.consentGated)))
    ) {
      harmClassification = 'suspicious_tracking';
      isHarmful = false;
    } else if (
      !isVerifiedBenignTelemetry &&
      isThirdParty &&
      relationshipStatus === 'external_unknown' &&
      (tx.httpMethod === 'POST' ||
        tx.httpMethod === 'PUT' ||
        tx.method === 'sendBeacon' ||
        tx.method === 'dynamic_beacon' ||
        tx.hasUnknownPayload ||
        tx.obfuscatedUrl ||
        resolvedUrl.search.length > 1)
    ) {
      harmClassification = 'unverified_external';
      isHarmful = false;
    } else {
      harmClassification = 'benign_functional';
      isHarmful = false;
    }

    const typesDesc = transmittedDataTypes.map((t) => labelEn[t]).join(', ');
    const consentState: ExternalDataTransmissionItem['consentState'] = tx.consentGated
      ? 'post_consent'
      : isThirdParty && (destinationRole === 'analytics' || destinationRole === 'ad_network')
        ? consentBannerPresent
          ? 'post_consent'
          : 'pre_consent'
        : 'not_required';

    const harmAssessment: BilingualText =
      harmClassification === 'malicious_harmful'
        ? {
            en: `Harmful / Malicious Exfiltration (${channelCategory}): AST verified transmission of [${typesDesc}] to ${destHost}${tx.obfuscatedUrl ? ` (URL decoded from ${tx.decodedFrom})` : ''}.`,
            ar: `تسريب ضار مؤكد (${channelCategory}): أثبت تحليل تدفق البيانات إرسال (${typesDesc}) إلى ${destHost}${tx.obfuscatedUrl ? ' (الرابط كان مموهاً)' : ''}.`,
          }
        : harmClassification === 'suspicious_tracking'
          ? {
              en: `Tracking / Profiling Telemetry (${channelCategory}): Sends or queries ${typesDesc} via ${destHost} without verified credential theft.`,
              ar: `بيانات تتبع أو استعلام IP/بصمة (${channelCategory}): يتصل بـ (${destHost}) عبر (${typesDesc}).`,
            }
          : harmClassification === 'unverified_external'
            ? {
                en: `Unverified External Transmission: Outbound ${tx.method} (${tx.httpMethod}) request to unknown host ${destHost}; static inspection cannot confirm this payload is harmless.`,
                ar: `إرسال خارجي غير موثوق: طلب ${tx.method} (${tx.httpMethod}) إلى نطاق غير معروف (${destHost})؛ لا يمكن الجزم بسلامته دون فحص أعمق.`,
              }
            : {
                en:
                  transmittedDataTypes[0] === 'unknown'
                    ? `Outbound ${tx.method} request to ${destHost}; static payload type could not be determined statically (unknown).`
                    : `Benign / Harmless Telemetry: Payload verified as ${typesDesc} (${tx.httpMethod} -> ${destHost}).`,
                ar:
                  transmittedDataTypes[0] === 'unknown'
                    ? `طلب ${tx.method} خارجي إلى ${destHost}؛ نوع الحمولة غير محدد ساكناً (unknown).`
                    : `سليم وغير ضار: تقتصر البيانات المرسلة على (${typesDesc}) دون تسريب كلمات مرور أو كوكيز.`,
              };

    results.push({
      destinationUrl: destUrlStr,
      destinationHost: destHost,
      endpointPath: resolvedUrl.pathname,
      method: tx.method,
      httpMethod: tx.httpMethod,
      isEncryptedInTransit: resolvedUrl.protocol === 'https:' || resolvedUrl.protocol === 'wss:',
      obfuscatedUrl: tx.obfuscatedUrl,
      decodedFrom: tx.decodedFrom,
      isThirdParty,
      relationshipStatus,
      pairedWithBackgroundCollection: pairedWithSensitiveCollection,
      transmittedDataTypes,
      payloadClassification: typesDesc,
      harmClassification,
      channelCategory,
      isHarmful,
      harmAssessment,
      sourceScript: tx.sourceScript,
      sourceFunction: tx.sourceFunction,
      trigger: tx.trigger,
      frequency: tx.frequency,
      consentState,
      destinationRole,
      reliability: transmittedDataTypes[0] === 'unknown' ? 'Medium' : 'High',
      purpose: {
        en:
          destinationRole === 'analytics'
            ? 'Site analytics / error telemetry'
            : destinationRole === 'ad_network'
              ? 'Advertising / marketing attribution'
              : isHarmful
                ? 'Unverified / harmful data exfiltration'
                : harmClassification === 'unverified_external'
                  ? 'Unverified third-party external endpoint communication'
                  : 'Application API or state communication',
        ar:
          destinationRole === 'analytics'
            ? 'تحليلات الموقع أو تقارير الأخطاء'
            : destinationRole === 'ad_network'
              ? 'شبكة إعلانات أو قياس حملات'
              : isHarmful
                ? 'تسريب بيانات غير مصرح به'
                : harmClassification === 'unverified_external'
                  ? 'اتصال بنقطة خارجية غير موثقة'
                  : 'اتصال وظيفي بواجهة برمجية للتطبيق',
      },
      excerpt: tx.excerpt,
      detail: isThirdParty
        ? {
            en: `${tx.method} (${tx.httpMethod}) from ${tx.sourceFunction} in ${tx.sourceScript} -> ${destHost} [${typesDesc}]`,
            ar: `${tx.method} (${tx.httpMethod}) من ${tx.sourceFunction} نحو ${destHost} [${typesDesc}]`,
          }
        : {
            en: `Same-organization ${tx.method} (${tx.httpMethod}) request to ${destHost} [${typesDesc}]`,
            ar: `طلب ${tx.method} (${tx.httpMethod}) داخل نفس النطاق (${destHost}) [${typesDesc}]`,
          },
    });
  }

  for (const formTarget of crossOriginFormActions) {
    try {
      const u = new URL(formTarget, finalUrl);
      const destHost = u.hostname.toLowerCase();
      const destReg = extractRegistrableDomain(destHost);
      const isThirdParty = destReg !== finalRegDomain;
      const key = `form_action|${u.toString()}`;
      if (seen.has(key)) continue;
      seen.add(key);

      results.push({
        destinationUrl: u.toString().slice(0, 180),
        destinationHost: destHost,
        endpointPath: u.pathname,
        method: 'form_action',
        httpMethod: 'POST',
        isEncryptedInTransit: u.protocol === 'https:',
        obfuscatedUrl: false,
        isThirdParty,
        relationshipStatus: 'external_unknown',
        pairedWithBackgroundCollection: hasPasswordOnPage,
        transmittedDataTypes: hasPasswordOnPage ? ['credentials', 'form_inputs'] : ['form_inputs'],
        payloadClassification: hasPasswordOnPage ? 'Credentials / Form Submission' : 'Form Inputs',
        harmClassification: hasPasswordOnPage ? 'malicious_harmful' : 'benign_functional',
        isHarmful: hasPasswordOnPage,
        harmAssessment: hasPasswordOnPage
          ? {
              en: `Cross-origin password <form> submits credentials directly to external host ${destHost}.`,
              ar: `نموذج كلمة مرور يرسل البيانات مباشرة إلى نطاق خارجي (${destHost}).`,
            }
          : {
              en: `Form submits non-credential inputs to external host ${destHost}.`,
              ar: `يرسل النموذج مدخلات عادية إلى مضيف خارجي (${destHost}).`,
            },
        sourceScript: 'HTML <form>',
        sourceFunction: '<form action>',
        trigger: 'form_submit',
        frequency: 'on_event',
        consentState: 'not_required',
        destinationRole: 'unverified_third_party',
        reliability: 'High',
        excerpt: `<form action="${formTarget}">`,
        detail: {
          en: `HTML form submits directly to ${destHost}`,
          ar: `نموذج HTML يرسل البيانات إلى ${destHost}`,
        },
      });
    } catch {
      // ignore invalid URL
    }
  }

  return results.slice(0, 25);
}

export function analyzeSourceIntelligence(
  finalUrl: string,
  headers: Record<string, string>,
  htmlBuffer?: Buffer,
  externalAssets?: ExternalSourceAssetsInput,
  setCookies?: string[]
): {
  sourceIntel: SourceIntelligenceData;
  formDetails: FormSecurityDetail[];
  supplyChain: SupplyChainResourceSummary;
  findings: CheckFinding[];
} {
  const now = new Date().toISOString();
  const findings: CheckFinding[] = [];

  const parsedUrl = new URL(finalUrl);
  const finalHost = parsedUrl.hostname.toLowerCase();
  const finalRegDomain = extractRegistrableDomain(finalHost);

  const securityHeaders = {
    csp: headers['content-security-policy'],
    hsts: headers['strict-transport-security'],
    xFrameOptions: headers['x-frame-options'],
    xContentTypeOptions: headers['x-content-type-options'],
    referrerPolicy: headers['referrer-policy'],
    permissionsPolicy: headers['permissions-policy'],
  };

  if (!htmlBuffer) {
    const emptySource: SourceIntelligenceData = {
      ogTags: {},
      jsonLdCount: 0,
      jsonLdTypes: [],
      baseTagHijack: false,
      securityHeaders,
      externalJsFiles: [],
      externalCssFiles: [],
      inlineJsCount: 0,
      inlineCssCount: 0,
      iframeSources: [],
      embeddedResources: [],
      hiddenInputs: [],
      suspiciousAttributes: [],
      suspiciousCodeSignals: [],
      lureExcerpts: [],
      externalCssUrls: [],
      cssExternalDomains: [],
      storageAndCookieAccess: [],
      formExfiltrationHooks: [],
      isMinifiedBundlePresent: false,
      titleContentMismatch: false,
    };
    const emptySupplyChain: SupplyChainResourceSummary = {
      totalExternalDomains: 0,
      scripts: [],
      stylesheets: [],
      iframes: [],
      fonts: [],
      imagesCount: 0,
      externalImagesCount: 0,
      apiEndpoints: [],
      trackingServices: [],
      cdnDomains: [],
      externalForms: [],
      outdatedLibraries: [],
    };
    return { sourceIntel: emptySource, formDetails: [], supplyChain: emptySupplyChain, findings };
  }

  const html = htmlBuffer.toString('utf8');
  const $ = cheerio.load(html);

  // 1. Meta Tags & Canonical
  const canonicalUrl = $('link[rel="canonical"]').attr('href')?.trim();
  const ogTags: Record<string, string> = {};
  $('meta[property^="og:"], meta[name^="og:"]').each((_, el) => {
    const prop = ($(el).attr('property') || $(el).attr('name') || '').trim();
    const content = ($(el).attr('content') || '').trim();
    if (prop) ogTags[prop] = content;
  });

  const jsonLdTypes: string[] = [];
  let jsonLdCount = 0;
  $('script[type="application/ld+json"]').each((_, el) => {
    jsonLdCount++;
    try {
      const parsed = JSON.parse($(el).html() || '{}');
      if (parsed['@type']) {
        const t = Array.isArray(parsed['@type']) ? parsed['@type'].join(', ') : String(parsed['@type']);
        jsonLdTypes.push(t);
      }
    } catch {
      // ignore
    }
  });

  // 2. Base Tag Hijacking (ignore benign same-company/authorized domains)
  const baseTagHref = $('base').attr('href')?.trim();
  let baseTagHijack = false;
  if (baseTagHref) {
    try {
      const resolvedBase = new URL(baseTagHref, finalUrl);
      const baseReg = extractRegistrableDomain(resolvedBase.hostname);
      const rel = classifyDomainRelationship(finalHost, resolvedBase.hostname);
      if (baseReg !== finalRegDomain && !rel.isBenignOrAuthorized) {
        baseTagHijack = true;
      }
    } catch {
      baseTagHijack = true;
    }
  }

  const metaRefresh = $('meta[http-equiv="refresh" i]').attr('content')?.trim();

  // 3. External & Inline Resources
  const externalJsFiles: string[] = [];
  const externalCssFiles: string[] = [];
  let inlineJsCount = 0;
  let inlineCssCount = 0;
  const iframeSources: string[] = [];
  const embeddedResources: { tag: string; src: string }[] = [];
  const externalDomainsSet = new Set<string>();

  const scriptList: { url: string; host: string; isThirdParty: boolean; isCdn: boolean }[] = [];
  const stylesheetList: { url: string; host: string; isThirdParty: boolean; isCdn: boolean }[] = [];
  const iframeList: { url: string; host: string; isThirdParty: boolean }[] = [];
  const fontList: string[] = [];
  const apiEndpointsSet = new Set<string>();
  const subdomainMap = new Map<string, Set<string>>();

  const recordSubdomainCandidate = (rawUrlOrHost: string | undefined, sourceTag: string) => {
    if (!rawUrlOrHost) return;
    try {
      const resolved = /^https?:\/\//i.test(rawUrlOrHost)
        ? new URL(rawUrlOrHost)
        : new URL(rawUrlOrHost, finalUrl);
      const h = resolved.hostname.toLowerCase().replace(/\.$/, '');
      if (!h || h === finalHost) return;
      if (extractRegistrableDomain(h) === finalRegDomain) {
        if (!subdomainMap.has(h)) subdomainMap.set(h, new Set());
        if (subdomainMap.size <= 35) subdomainMap.get(h)!.add(sourceTag);
      }
    } catch {
      // ignore invalid URL
    }
  };

  if (canonicalUrl) recordSubdomainCandidate(canonicalUrl, 'canonical');
  if (ogTags['og:url']) recordSubdomainCandidate(ogTags['og:url'], 'og:url');
  if (baseTagHref) recordSubdomainCandidate(baseTagHref, 'base');

  const brandLookalikeLinks: NonNullable<SourceIntelligenceData['brandLookalikeLinks']> = [];
  const seenLookalikeHosts = new Set<string>();
  const checkLookalikeTarget = (rawUrl: string) => {
    if (!rawUrl || !/^https?:\/\//i.test(rawUrl)) return;
    try {
      const u = new URL(rawUrl);
      const host = u.hostname.toLowerCase();
      const reg = extractRegistrableDomain(host);
      if (reg === finalRegDomain || seenLookalikeHosts.has(host)) return;
      if (lookupDomainOwnership(host).matched) return;
      const compound = detectCompoundBrandLookalike(host, reg);
      if (compound) {
        seenLookalikeHosts.add(host);
        brandLookalikeLinks.push({
          url: u.toString().slice(0, 160),
          host,
          targetBrand: compound.brand,
          officialDomain: compound.officialDomain,
          evidence: compound.evidence,
        });
      }
    } catch {
      // ignore invalid URL
    }
  };

  $('a[href]').each((_, el) => {
    const href = ($(el).attr('href') || '').trim();
    if (href && !href.startsWith('#') && !/^javascript:/i.test(href)) {
      recordSubdomainCandidate(href, 'anchor');
      checkLookalikeTarget(href);
    }
  });
  $('form[action]').each((_, el) => {
    const act = ($(el).attr('action') || '').trim();
    if (act) {
      recordSubdomainCandidate(act, 'form');
      checkLookalikeTarget(act);
    }
  });
  $('img[src], source[src], video[src]').each((_, el) => {
    const src = ($(el).attr('src') || '').trim();
    if (src) recordSubdomainCandidate(src, 'media');
  });

  $('script[src]').each((_, el) => {
    const src = ($(el).attr('src') || '').trim();
    if (src) {
      externalJsFiles.push(src.slice(0, 160));
      recordSubdomainCandidate(src, 'script');
      try {
        const u = new URL(src, finalUrl);
        const host = u.hostname.toLowerCase();
        const reg = extractRegistrableDomain(host);
        const isTP = reg !== finalRegDomain;
        const isCdn = KNOWN_CDN_DOMAINS.has(host) || KNOWN_CDN_DOMAINS.has(reg);
        if (isTP) externalDomainsSet.add(host);
        scriptList.push({ url: u.toString(), host, isThirdParty: isTP, isCdn });
      } catch {
        // ignore
      }
    }
  });

  $('script:not([src])').each((_, el) => {
    inlineJsCount++;
    const code = $(el).html() || '';
    // Extract static API endpoints & subdomains from JS code strings
    const urlMatches = code.match(/https?:\/\/[a-z0-9.-]+\.[a-z]{2,20}(?:\/[^\s"'<>]+)?/gi) || [];
    for (const m of urlMatches) {
      if (apiEndpointsSet.size < 20) apiEndpointsSet.add(m.slice(0, 120));
      recordSubdomainCandidate(m, 'inline_js');
    }
  });

  $('link[rel="stylesheet"]').each((_, el) => {
    const href = ($(el).attr('href') || '').trim();
    if (href) {
      externalCssFiles.push(href.slice(0, 160));
      recordSubdomainCandidate(href, 'stylesheet');
      try {
        const u = new URL(href, finalUrl);
        const host = u.hostname.toLowerCase();
        const reg = extractRegistrableDomain(host);
        const isTP = reg !== finalRegDomain;
        const isCdn = KNOWN_CDN_DOMAINS.has(host);
        if (isTP) externalDomainsSet.add(host);
        stylesheetList.push({ url: u.toString(), host, isThirdParty: isTP, isCdn });
      } catch {
        // ignore
      }
    }
  });

  const externalCssUrls: string[] = [];
  const cssExternalDomainsSet = new Set<string>();
  const extractCssUrls = (cssText: string) => {
    const cssRegex = /(?:@import\s+(?:url\()?['"]?([^'")\s]+)|url\(\s*['"]?(https?:\/\/[^'")\s]+)['"]?\s*\))/gi;
    let m: RegExpExecArray | null;
    while ((m = cssRegex.exec(cssText)) !== null) {
      const rawUrl = (m[1] || m[2] || '').trim();
      if (!rawUrl || /^data:/i.test(rawUrl)) continue;
      if (externalCssUrls.length < 30) externalCssUrls.push(rawUrl.slice(0, 160));
      recordSubdomainCandidate(rawUrl, 'css');
      try {
        const u = new URL(rawUrl, finalUrl);
        const h = u.hostname.toLowerCase();
        const reg = extractRegistrableDomain(h);
        if (reg !== finalRegDomain) {
          cssExternalDomainsSet.add(h);
          externalDomainsSet.add(h);
        }
      } catch {
        // ignore invalid css url
      }
    }
  };

  $('style').each((_, el) => {
    inlineCssCount++;
    extractCssUrls($(el).html() || '');
  });
  $('[style]').each((_, el) => {
    const st = $(el).attr('style') || '';
    if (/url\(/i.test(st)) extractCssUrls(st);
  });
  for (const extCss of externalAssets?.fetchedCss || []) {
    extractCssUrls(extCss.css.slice(0, 80000));
  }

  let hiddenOverlayIframes = 0;
  $('iframe[src]').each((_, el) => {
    const src = ($(el).attr('src') || '').trim();
    const st = ($(el).attr('style') || '').toLowerCase();
    if (/opacity\s*:\s*0\b|left\s*:\s*-\d{3,}|top\s*:\s*-\d{3,}|visibility\s*:\s*hidden/.test(st)) {
      hiddenOverlayIframes++;
    }
    if (src) {
      iframeSources.push(src.slice(0, 160));
      recordSubdomainCandidate(src, 'iframe');
      try {
        const u = new URL(src, finalUrl);
        const host = u.hostname.toLowerCase();
        const isTP = extractRegistrableDomain(host) !== finalRegDomain;
        iframeList.push({ url: u.toString(), host, isThirdParty: isTP });
      } catch {
        // ignore
      }
    }
  });

  $('[data-font], link[rel*="font"], @import').each((_, el) => {
    const href = $(el).attr('href') || $(el).attr('src') || '';
    if (/fonts\./i.test(href) || /\.woff2?/i.test(href)) {
      fontList.push(href.slice(0, 100));
    }
  });

  $('object, embed, svg').each((_, el) => {
    const src = $(el).attr('data') || $(el).attr('src') || '';
    embeddedResources.push({ tag: el.tagName.toLowerCase(), src: src.slice(0, 120) });
  });

  let imagesCount = 0;
  let externalImagesCount = 0;
  $('img[src]').each((_, el) => {
    imagesCount++;
    const src = ($(el).attr('src') || '').trim();
    if (/^https?:\/\//i.test(src)) {
      try {
        if (extractRegistrableDomain(new URL(src).hostname) !== finalRegDomain) {
          externalImagesCount++;
        }
      } catch {
        // ignore
      }
    }
  });

  // 4. Hidden Inputs & Suspicious Attributes
  const hiddenInputs: { name?: string; type: string; valuePreview?: string }[] = [];
  $('input[type="hidden"]').each((_, el) => {
    const name = $(el).attr('name') || $(el).attr('id');
    const val = $(el).attr('value') || '';
    hiddenInputs.push({ name, type: 'hidden', valuePreview: val.slice(0, 40) });
  });

  const suspiciousAttributes: { attribute: string; tag: string; snippet: string }[] = [];
  $('*').each((_, el) => {
    const node = el as any;
    const tag = (node.tagName || 'element').toLowerCase();
    for (const attr of node.attribs ? Object.keys(node.attribs) : []) {
      const val = node.attribs[attr] || '';
      if (
        /^on[a-z]+/i.test(attr) ||
        /javascript:|data:text\/html/i.test(val) ||
        (attr === 'formaction' && /^https?:\/\//i.test(val))
      ) {
        suspiciousAttributes.push({ attribute: attr, tag, snippet: `${attr}="${val.slice(0, 60)}"` });
      }
    }
  });

  // 5. AST + Data-Flow JavaScript Analysis (inline + safely retrieved external scripts)
  const suspiciousCodeSignals: SuspiciousCodeSignal[] = [];
  const fullHtmlText = html.slice(0, 120000);
  const scriptInputs: ScriptInput[] = [];
  $('script:not([src])').each((idx, el) => {
    const code = $(el).html() || '';
    if (code.trim()) scriptInputs.push({ source: `<script>#${idx + 1}`, code });
  });
  for (const ext of externalAssets?.fetchedScripts || []) {
    if (ext.code?.trim()) scriptInputs.push({ source: ext.url, code: ext.code });
  }
  const externalJsInspectedCount = (externalAssets?.fetchedScripts || []).length;
  const astResult = analyzeScriptsWithAst(scriptInputs);
  const inlineJsConcat = scriptInputs.map((s) => s.code).join('\n').slice(0, 150000);

  const storageAndCookieAccess: string[] = [];
  if (astResult.cookieEvents.length > 0 || /document\.cookie\b/i.test(inlineJsConcat)) {
    storageAndCookieAccess.push('document.cookie');
  }
  if (/\blocalStorage\.(?:getItem|setItem|removeItem|clear)\b/i.test(inlineJsConcat)) storageAndCookieAccess.push('localStorage');
  if (/\bsessionStorage\.(?:getItem|setItem|removeItem|clear)\b/i.test(inlineJsConcat)) storageAndCookieAccess.push('sessionStorage');

  // Form & exfiltration hooks ONLY when AST proves harmful/untrusted third-party or obfuscated flow (same-origin login/API calls stay benign)
  const isUntrustedFlowTx = (tx: JsDataFlowAnalysisResult['transmissions'][number]): boolean => {
    if (!tx.obfuscatedUrl && DEV_BUILD_ENDPOINT_PATH_RE.test(tx.destinationUrl)) return false;
    if (tx.obfuscatedUrl || tx.method === 'dynamic_beacon') return true;
    try {
      const candidate = tx.destinationUrl.startsWith('//') ? `https:${tx.destinationUrl}` : tx.destinationUrl;
      const u = new URL(candidate, finalUrl);
      const destHost = u.hostname.toLowerCase();
      if (isLoopbackHost(destHost) && !isLoopbackHost(finalHost)) return false;
      const destReg = extractRegistrableDomain(destHost);
      if (destReg === finalRegDomain) return false;
      const rel = classifyDomainRelationship(finalHost, destHost);
      return !rel.isSameOrganization && !rel.isBenignOrAuthorized;
    } catch {
      return false;
    }
  };

  const formExfiltrationHooks: string[] = [];
  const cookieFlowTx = astResult.transmissions.find((t) => t.taintTags.includes('cookies') && isUntrustedFlowTx(t));
  if (cookieFlowTx) {
    formExfiltrationHooks.push(`AST data-flow confirmed document.cookie transmitted externally via ${cookieFlowTx.method} -> ${cookieFlowTx.destinationUrl}`);
  }
  const credFlowTx = astResult.transmissions.find(
    (t) => (t.taintTags.includes('credentials') || t.taintTags.includes('financial_pii')) && isUntrustedFlowTx(t)
  );
  if (credFlowTx) {
    formExfiltrationHooks.push(`AST data-flow confirmed password/credential field transmitted to external host via ${credFlowTx.method} -> ${credFlowTx.destinationUrl}`);
  }
  const ksFlowTx = astResult.transmissions.find((t) => t.taintTags.includes('keystrokes_clipboard') && isUntrustedFlowTx(t));
  if (ksFlowTx) {
    formExfiltrationHooks.push(`AST data-flow confirmed keystroke/clipboard capture transmitted externally via ${ksFlowTx.method}`);
  }

  // Static Post-Load DOM Mutation & Client-Rendered Content Divergence Detection (AST-backed)
  const jsDomMutationPayloads: string[] = [...astResult.domMutationExcerpts];
  if (
    jsDomMutationPayloads.length === 0 &&
    /(?:\.innerHTML|\.outerHTML|insertAdjacentHTML|document\.write)\s*(?:=|\()[\s\S]{0,220}\batob\s*\(/i.test(inlineJsConcat)
  ) {
    jsDomMutationPayloads.push('JS decodes Base64 payload directly into live DOM markup via innerHTML / document.write');
  }

  const hasMaliciousObfuscationMarker =
    astResult.obfuscationMarkerCount >= 2 ||
    astResult.behavioralSignals.some((s) => s.category === 'dynamic_eval' || s.category === 'obfuscation');
  const isMinifiedBundlePresent = Boolean(
    astResult.isMinifiedBundlePresent || externalJsFiles.some((s) => /\.min\.js|bundle|chunk|vendor/i.test(s))
  );
  const obfuscationVsMinifiedNote = isMinifiedBundlePresent && !hasMaliciousObfuscationMarker
    ? {
        en: 'Detected minified/compressed JavaScript bundle without malicious obfuscation markers (_0x hex arrays or encoded eval payloads). Minified production bundles are normal and NOT treated as malicious.',
        ar: 'تم رصد أكواد JavaScript مضغوطة (Minified) دون علامات تمويه خبيث؛ ضغط الأكواد الإنتاجية أمر طبيعي ولا يُصنف كبرمجية ضارة.',
      }
    : undefined;

  for (const sig of astResult.behavioralSignals) {
    if (sig.category === 'dynamic_eval') {
      suspiciousCodeSignals.push({
        id: sig.id,
        indicator: sig.indicator,
        category: 'dynamic_eval',
        codeExcerpt: sig.excerpt,
        contextAssessment: {
          en: 'Encoded/obfuscated eval() or new Function() execution detected in AST.',
          ar: 'رُصد تنفيذ eval() أو Function() مع حمولة مشفرة أو مرمزة في شجرة الكود.',
        },
        benignContextPossible: sig.benignContextPossible,
        riskLevel: sig.confirmedMaliciousContext ? 'high' : 'low',
      });
    } else if (sig.category === 'obfuscation') {
      suspiciousCodeSignals.push({
        id: 'js-obfuscation',
        indicator: sig.indicator,
        category: 'obfuscation',
        codeExcerpt: sig.excerpt,
        contextAssessment: {
          en: 'Script contains _0x hex obfuscation arrays or decoder loops.',
          ar: 'يحتوي الكود على مصفوفات تعتيم _0x أو حلقات فك تشفير مشبوهة.',
        },
        benignContextPossible: false,
        riskLevel: 'high',
      });
    }
  }

  const dynamicFormActionRewrite = astResult.behavioralSignals.some((s) => s.category === 'form_rewrite');
  if (dynamicFormActionRewrite) {
    const rw = astResult.behavioralSignals.find((s) => s.category === 'form_rewrite')!;
    formExfiltrationHooks.push('Script dynamically rewrites <form action> submission target');
    suspiciousCodeSignals.push({
      id: 'js-form-action-rewrite',
      indicator: rw.indicator,
      category: 'exfiltration',
      codeExcerpt: rw.excerpt,
      contextAssessment: {
        en: 'AST verified runtime form.action target rewriting to an external endpoint.',
        ar: 'ثبت في AST إعادة توجيه وجهة النموذج ديناميكياً أثناء التشغيل.',
      },
      benignContextPossible: false,
      riskLevel: 'high',
    });
  }

  // Password DOM hook ONLY triggers when password value actually flows to an external network sink or malicious rewrite
  const passwordFieldDomHooks = Boolean(credFlowTx);
  if (passwordFieldDomHooks && credFlowTx) {
    suspiciousCodeSignals.push({
      id: 'js-password-exfil-hook',
      indicator: `AST verified DOM password flow to ${credFlowTx.method}`,
      category: 'exfiltration',
      codeExcerpt: credFlowTx.excerpt,
      contextAssessment: {
        en: 'AST data-flow proved password input values flow into an outbound network transmission.',
        ar: 'أثبت تحليل تدفق البيانات انتقال قيمة حقل كلمة المرور إلى إرسال شبكي خارجي.',
      },
      benignContextPossible: true,
      riskLevel: 'high',
    });
  }

  const walletDrainerPattern = astResult.behavioralSignals.some((s) => s.category === 'wallet_drainer');
  if (walletDrainerPattern) {
    const wd = astResult.behavioralSignals.find((s) => s.category === 'wallet_drainer')!;
    suspiciousCodeSignals.push({
      id: 'js-wallet-clipboard-hijack',
      indicator: wd.indicator,
      category: 'clipboard',
      codeExcerpt: wd.excerpt,
      contextAssessment: {
        en: 'Wallet address clipboard hijacking detected.',
        ar: 'تم رصد استبدال عنوان محفظة رقمية في الحافظة.',
      },
      benignContextPossible: false,
      riskLevel: 'high',
    });
  }

  const hasPasswordOnPage = $('input[type="password"]').length > 0;
  const antiDebugTraps =
    astResult.behavioralSignals.some((s) => s.category === 'anti_debug') ||
    (hasPasswordOnPage && /oncontextmenu\s*=\s*.*return\s+false/i.test(inlineJsConcat) && /F12|ctrlKey\s*&&\s*shiftKey/i.test(inlineJsConcat));
  if (antiDebugTraps) {
    suspiciousCodeSignals.push({
      id: 'js-anti-debug',
      indicator: 'Anti-inspection / debugger trap',
      category: 'dom_injection',
      codeExcerpt: 'debugger; statement or DevTools block detected',
      contextAssessment: {
        en: 'Debugger trap or inspection blocker detected in script.',
        ar: 'تم رصد مصيدة debugger أو حظر أدوات الفحص.',
      },
      benignContextPossible: false,
      riskLevel: 'medium',
    });
  }

  // Title vs Actual Content Contradiction Detection
  const titleText = $('title').first().text().trim().toLowerCase();
  const cloneDoc = cheerio.load(fullHtmlText);
  cloneDoc('script, style, noscript').remove();
  const bodyPlain = cloneDoc('body').text().replace(/\s+/g, ' ').trim().toLowerCase();
  let titleContentMismatch = false;
  let titleMismatchDetail: { en: string; ar: string } | undefined;
  const authoritativeBrandsInTitle = ['google', 'microsoft', 'paypal', 'apple', 'facebook', 'instagram', 'amazon', 'netflix', 'github'].filter((b) =>
    titleText.includes(b) && !finalRegDomain.includes(b)
  );
  if (authoritativeBrandsInTitle.length > 0 && !bodyPlain.includes(authoritativeBrandsInTitle[0]) && bodyPlain.length > 40) {
    titleContentMismatch = true;
    titleMismatchDetail = {
      en: `Page <title> references "${authoritativeBrandsInTitle[0]}" while visible body text diverges from that identity.`,
      ar: `عنوان الصفحة (<title>) يذكر "${authoritativeBrandsInTitle[0]}" بينما يختلف المحتوى المرئي الفعلي عن هذه الهوية.`,
    };
  } else if (titleText.length > 5 && /(login|sign in|security|verification)/i.test(titleText) && /(airdrop|claim prize|you won|virus infected|out[- ]of[- ]date)/i.test(bodyPlain)) {
    titleContentMismatch = true;
    titleMismatchDetail = {
      en: 'Page <title> presents a security/login header while visible body content promotes deceptive alerts or prize scams.',
      ar: 'يظهر <title> كصفحة دخول أو أمان بينما يعرض المحتوى الفعلي تنبيهات مزيفة أو عروضاً احتيالية.',
    };
  }

  // 6. Detailed Per-Form Analysis (FormSecurityDetail[])
  const formDetails: FormSecurityDetail[] = [];
  $('form').each((idx, el) => {
    const action = ($(el).attr('action') || '').trim();
    const method = ($(el).attr('method') || 'GET').toUpperCase();
    const idOrName = $(el).attr('id') || $(el).attr('name');
    let resolvedHost = finalHost;
    let isCrossOrigin = false;
    let originMismatch = false;

    if (action) {
      try {
        const u = new URL(action, finalUrl);
        resolvedHost = u.hostname.toLowerCase();
        const rel = classifyDomainRelationship(finalHost, resolvedHost);
        isCrossOrigin = extractRegistrableDomain(resolvedHost) !== finalRegDomain && !rel.isBenignOrAuthorized;
        originMismatch = isCrossOrigin;
      } catch {
        // relative action
      }
    }

    const inputTypesSet = new Set<string>();
    let pwdCount = 0;
    let emailCount = 0;
    let otpCount = 0;
    let pinCount = 0;
    let cardCount = 0;
    let hiddenCount = 0;
    let invisibleCount = 0;
    const unusualAttrs: string[] = [];
    const jsHandlers: string[] = [];

    $(el)
      .find('input, select, textarea')
      .each((_, inputEl) => {
        const t = ($(inputEl).attr('type') || 'text').toLowerCase();
        inputTypesSet.add(t);
        const nameId = ($(inputEl).attr('name') || $(inputEl).attr('id') || '').toLowerCase();
        const style = ($(inputEl).attr('style') || '').toLowerCase();

        if (t === 'hidden') {
          hiddenCount++;
        } else if (t === 'password') {
          pwdCount++;
        } else if (t === 'email' || /(?:^|[^a-z])(email|user|login)(?:$|[^a-z])/.test(nameId)) {
          emailCount++;
        } else if (/(?:^|[^a-z])(otp|2fa|pin[-_ ]?code)(?:$|[^a-z])/.test(nameId)) {
          otpCount++;
        } else if (/(?:^|[^a-z])(card[-_ ]?num|cvv|cvc|ccnum)(?:$|[^a-z])/.test(nameId)) {
          cardCount++;
        }

        if (/display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0\b/.test(style)) {
          invisibleCount++;
        }

        for (const attr of inputEl.attribs ? Object.keys(inputEl.attribs) : []) {
          if (/^on[a-z]+/i.test(attr)) jsHandlers.push(attr);
        }
      });

    let formRisk: FormSecurityDetail['riskLevel'] = 'informational';
    const reasonEn: string[] = [];
    const reasonAr: string[] = [];

    if (isCrossOrigin && pwdCount > 0) {
      formRisk = 'critical';
      reasonEn.push('Password form submits to an external cross-origin domain.');
      reasonAr.push('نموذج كلمة المرور يرسل البيانات إلى نطاق خارجي مختلف.');
    } else if (pwdCount > 0 && !action) {
      formRisk = formExfiltrationHooks.length > 0 && /Keystroke/i.test(formExfiltrationHooks.join(' ')) ? 'high' : 'informational';
      reasonEn.push('Password form handles submission via client script / SPA state (no HTML action attribute). Verify exact domain identity.');
      reasonAr.push('يتعامل نموذج كلمة المرور مع الإرسال عبر السكربت المحلي (SPA) بدون وسم action؛ تحقق من هوية النطاق.');
    } else if (pwdCount > 0) {
      formRisk = 'informational';
      reasonEn.push('Standard same-origin password authentication form.');
      reasonAr.push('نموذج تسجيل دخول قياسي يرسل البيانات لنفس النطاق.');
    }

    formDetails.push({
      pageUrl: finalUrl,
      formIndex: idx + 1,
      idOrName,
      action: action || '[empty / current page]',
      resolvedActionHost: resolvedHost,
      method,
      usesHttps: finalUrl.startsWith('https://'),
      isCrossOrigin,
      originMismatch,
      inputTypes: Array.from(inputTypesSet),
      passwordCount: pwdCount,
      emailCount,
      otpCount,
      pinCount,
      cardCount,
      hiddenCount,
      invisibleCount,
      unusualAttributes: unusualAttrs,
      jsHandlers,
      riskLevel: formRisk,
      reason: {
        en: reasonEn.join(' ') || 'Standard form structure.',
        ar: reasonAr.join(' ') || 'بنية نموذج قياسية.',
      },
    });
  });

  // 7. Supply Chain Analysis & Outdated Libraries
  const trackingServices: { name: string; host: string }[] = [];
  for (const trk of KNOWN_TRACKERS) {
    for (const sc of scriptList) {
      if (trk.pattern.test(sc.url)) {
        if (!trackingServices.some((t) => t.name === trk.name)) {
          trackingServices.push({ name: trk.name, host: sc.host });
        }
      }
    }
  }

  const cdnDomains = Array.from(externalDomainsSet).filter((d) => KNOWN_CDN_DOMAINS.has(d));
  const outdatedLibraries: { library: string; detectedVersion: string; sourceUrl: string; advisory: string }[] = [];

  for (const sc of scriptList) {
    for (const libDef of VULNERABLE_LIB_PATTERNS) {
      const match = sc.url.match(libDef.pattern);
      if (match?.[1]) {
        outdatedLibraries.push({
          library: libDef.library,
          detectedVersion: match[1],
          sourceUrl: sc.url,
          advisory: libDef.advisory,
        });
      }
    }
  }

  const supplyChain: SupplyChainResourceSummary = {
    totalExternalDomains: externalDomainsSet.size,
    scripts: scriptList,
    stylesheets: stylesheetList,
    iframes: iframeList,
    fonts: fontList,
    imagesCount,
    externalImagesCount,
    apiEndpoints: Array.from(apiEndpointsSet),
    trackingServices,
    cdnDomains,
    externalForms: formDetails.filter((f) => f.isCrossOrigin).map((f) => f.action),
    outdatedLibraries,
  };

  const discoveredSubdomains: DiscoveredSubdomainInfo[] = Array.from(subdomainMap.entries()).map(([host, srcSet]) => {
    const role = classifySubdomainRole(host);
    const hasRiskyContext = (hasPasswordOnPage || formDetails.some((f) => f.isCrossOrigin)) && (role === 'auth' || role === 'admin');
    return {
      host,
      sources: Array.from(srcSet),
      role,
      suspiciousRole: hasRiskyContext,
    };
  });

  const bodyWordCount = bodyPlain ? bodyPlain.split(' ').length : 0;
  const hasSpaMountRoot = Boolean(
    $('#root, #app, #__next, #__nuxt, app-root').length > 0 || $('noscript').text().toLowerCase().includes('javascript')
  );
  const dynamicContentAfterJsLikely = Boolean(
    jsDomMutationPayloads.length > 0 || (hasSpaMountRoot && bodyWordCount < 35 && (inlineJsCount > 0 || externalJsFiles.length > 0))
  );

  const staticVsRenderedNote = dynamicContentAfterJsLikely
    ? jsDomMutationPayloads.length > 0
      ? {
          en: `Level A Static Analysis detected client-side JS scripts designed to inject/replace DOM content or redirect after initial load (${jsDomMutationPayloads[0]}). Level B isolated browser execution is not active locally; findings are based on inspected static source payloads.`,
          ar: `رصد التحليل الساكن (المستوى A) سكربتات JavaScript تُغيّر محتوى DOM أو تُعيد التوجيه بعد التحميل الأولي (${jsDomMutationPayloads[0]}). بيئة المتصفح المعزولة (المستوى B) غير متاحة محلياً؛ لذا تستند النتائج لقراءة السورس الفعلي.`,
        }
      : {
          en: 'Page serves a thin client-rendered JavaScript shell (SPA mount root with minimal static HTML text). Full post-render DOM requires an isolated headless browser (Level B, currently inactive); Level A inspected static HTML and accessible scripts only.',
          ar: 'تعتمد الصفحة على تطبيق JavaScript يُنشئ المحتوى بعد التحميل (SPA). قراءة شجرة DOM النهائية بعد التشغيل تتطلب متصفحاً معزولاً (المستوى B غير مفعّل محلياً)، وقد جرى فحص HTML والسكربتات المتاحة ساكنياً عبر المستوى A.',
        }
    : undefined;

  if (jsDomMutationPayloads.length > 0 && !suspiciousCodeSignals.some((s) => s.id === 'js-dom-mutation')) {
    const injectsSensitiveDom = jsDomMutationPayloads.some((m) => /<form|password|<iframe|atob/i.test(m));
    suspiciousCodeSignals.push({
      id: 'js-dom-mutation',
      indicator: 'Post-load JS DOM mutation / hidden markup injection',
      category: 'dom_injection',
      codeExcerpt: jsDomMutationPayloads[0],
      contextAssessment: {
        en: injectsSensitiveDom
          ? 'Inline/fetched JS constructs forms, password inputs, or decoded HTML fragments dynamically after page load—a classic cloaking technique to bypass static scanners.'
          : 'Script modifies DOM nodes or redirects asynchronously after a timer.',
        ar: injectsSensitiveDom
          ? 'يحقن الجافاسكربت نماذج إدخال أو حقول كلمة مرور أو شيفرة HTML مفكوكة بعد تحميل الصفحة؛ وهو أسلوب إخفاء لتفادي فحص HTML الساكن.'
          : 'يُعدّل السكربت عناصر الصفحة أو يوجهها بعد مؤقت زمني.',
      },
      benignContextPossible: !injectsSensitiveDom,
      riskLevel: injectsSensitiveDom ? 'high' : 'low',
    });
  }

  const rawSetCookiesList =
    setCookies && setCookies.length > 0
      ? setCookies
      : headers['set-cookie']
        ? splitCombinedSetCookieHeader(headers['set-cookie'])
        : [];

  const crossOriginActionsForTx = formDetails.filter((f) => f.isCrossOrigin).map((f) => f.action);

  const preliminaryTxHosts = astResult.transmissions.map((tx) => {
    try {
      return new URL(tx.destinationUrl, finalUrl).hostname.toLowerCase();
    } catch {
      return '';
    }
  }).filter(Boolean);

  const cookieIntelResult = analyzeCookieIntelligence({
    finalUrl,
    rawSetCookies: rawSetCookiesList,
    $,
    htmlText: fullHtmlText,
    jsResult: astResult,
    externalTxHosts: preliminaryTxHosts,
  });
  const cookieAudit = cookieIntelResult.audit;

  const externalDataTransmissions = buildExternalTransmissionsFromAst({
    astResult,
    finalUrl,
    finalHost,
    finalRegDomain,
    crossOriginFormActions: crossOriginActionsForTx,
    hasPasswordOnPage,
    consentBannerPresent: cookieAudit.hasConsentNoticeOrBanner,
  });

  const backgroundDataCollection = buildBackgroundCollectionsFromAst(astResult, externalDataTransmissions);

  const { advertisingIntel, malvertisingSignals } = analyzeAdvertisingIntelligence({
    finalUrl,
    $,
    htmlText: fullHtmlText,
    externalDomains: Array.from(externalDomainsSet),
    jsResult: astResult,
    cookieAudit,
  });

  const workersDetected: WorkerDetectionInfo = {
    hasServiceWorker: astResult.serviceWorkerUrls.length > 0,
    hasWebWorker: astResult.webWorkerUrls.length > 0,
    serviceWorkerUrls: astResult.serviceWorkerUrls,
    webWorkerUrls: astResult.webWorkerUrls,
    isMaliciousOrSuspicious:
      [...astResult.serviceWorkerUrls, ...astResult.webWorkerUrls].some((u) => /^(?:data:|blob:)|eval|atob/i.test(u)),
    summary:
      astResult.serviceWorkerUrls.length > 0 || astResult.webWorkerUrls.length > 0
        ? {
            en: `Registered ${astResult.serviceWorkerUrls.length} Service Worker(s) and ${astResult.webWorkerUrls.length} Web Worker(s).`,
            ar: `تم رصد ${astResult.serviceWorkerUrls.length} Service Worker و ${astResult.webWorkerUrls.length} Web Worker.`,
          }
        : {
            en: 'No Service Worker or Web Worker registrations detected in static JS.',
            ar: 'لم يُرصد تسجيل أي Service Worker أو Web Worker في الأكواد الساكنة.',
          },
  };

  for (const tx of externalDataTransmissions) {
    if (tx.isThirdParty && apiEndpointsSet.size < 25) {
      apiEndpointsSet.add(tx.destinationUrl.slice(0, 120));
    }
  }

  const sourceIntel: SourceIntelligenceData = {
    canonicalUrl,
    ogTags,
    jsonLdCount,
    jsonLdTypes,
    baseTagHref,
    baseTagHijack,
    metaRefresh,
    securityHeaders,
    externalJsFiles,
    externalCssFiles,
    inlineJsCount,
    inlineCssCount,
    iframeSources,
    embeddedResources,
    hiddenInputs,
    suspiciousAttributes,
    suspiciousCodeSignals,
    lureExcerpts: [],
    externalCssUrls,
    cssExternalDomains: Array.from(cssExternalDomainsSet),
    storageAndCookieAccess,
    formExfiltrationHooks,
    isMinifiedBundlePresent,
    obfuscationVsMinifiedNote,
    titleContentMismatch,
    titleMismatchDetail,
    discoveredSubdomains,
    brandLookalikeLinks,
    jsDomMutationPayloads,
    dynamicContentAfterJsLikely,
    staticVsRenderedNote,
    externalJsInspectedCount,
    jsBehaviorSummary: {
      dynamicFormActionRewrite,
      passwordFieldDomHooks,
      walletDrainerPattern,
      antiDebugTraps,
      hiddenOverlayIframes,
      obfuscationMarkerCount: astResult.obfuscationMarkerCount,
    },
    backgroundDataCollection,
    externalDataTransmissions,
    dataFlowTaints: astResult.dataFlowTaints.map((t) => {
      if (
        t.triggerContext === 'user_click' &&
        /fast\s*download|download\s*now|verify\s*now|continue\s*download|تحميل\s*سريع|متابعة/i.test(
          $('button, a, input[type="button"], input[type="submit"]').text()
        )
      ) {
        return { ...t, triggerContext: 'DECEPTIVE_INTERACTION_TRIGGER' as const };
      }
      return t;
    }),
    plantedBackdoors: astResult.plantedBackdoors,
    cookieAudit,
    advertisingIntel,
    workersDetected,
    malvertisingSignals,
  };

  // Findings generation for Source Intelligence, JS Behavior, HTML Semantics & Discovered Subdomains
  if (baseTagHijack) {
    findings.push({
      id: 'source-base-tag-hijack',
      section: 'source_intelligence',
      test: { en: 'Base HTML Tag Hijack Check', ar: 'فحص التلاعب بوسم القاعدة HTML <base>' },
      result: { en: `Deceptive <base href="${baseTagHref}"> points to external host`, ar: `وسم <base href="${baseTagHref}"> يشير لنطاق خارجي` },
      status: 'failed',
      severity: 'high',
      weight: 24,
      evidence: `Base href: ${baseTagHref}`,
      explanation: {
        en: 'A malicious <base> tag redirects all relative links and resource paths to an attacker-controlled domain.',
        ar: 'يعيد وسم <base> الخبيث توجيه كافة الروابط النسبية وملفات الموقع نحو خادم يسيطر عليه المهاجم.',
      },
      recommendedAction: {
        en: 'Do not interact with this page; base-tag hijacking is a classic phishing cloaking technique.',
        ar: 'لا تتفاعل مع هذه الصفحة؛ التلاعب بوسم القاعدة هو أسلوب تصيد كلاسيكي.',
      },
      source: 'SM Source Intelligence',
      timestamp: now,
      confidence: 98,
    });
  }

  // Source Finding A: JavaScript Static Behavioral Forensics
  const highJsSignals = suspiciousCodeSignals.filter((s) => s.riskLevel === 'high' || s.riskLevel === 'critical');
  const medJsSignals = suspiciousCodeSignals.filter((s) => s.riskLevel === 'medium');
  const hasSeriousJsBehavior =
    highJsSignals.length >= 1 ||
    (hasMaliciousObfuscationMarker && formExfiltrationHooks.length > 0) ||
    dynamicFormActionRewrite ||
    walletDrainerPattern;
  const hostOwnershipSrc = classifyDomainRelationship(finalHost, finalHost);
  const suppressSpaHookOnOfficial = hostOwnershipSrc.isSameOrganization && highJsSignals.every((s) => s.benignContextPossible);

  const jsBehaviorFailed = hasSeriousJsBehavior && !suppressSpaHookOnOfficial;
  const jsBehaviorWarn = !jsBehaviorFailed && medJsSignals.length > 0 && !suppressSpaHookOnOfficial;

  findings.push({
    id: 'source-js-behavior',
    section: 'javascript_analysis',
    test: { en: 'Deep Source & JavaScript Behavioral Inspection (AST)', ar: 'التحليل العميق لسورس الموقع وسلوكيات JavaScript (AST)' },
    result: jsBehaviorFailed
      ? {
          en: `${highJsSignals.length} high-risk JS pattern(s): ${highJsSignals.map((s) => s.indicator).slice(0, 2).join('; ')}`,
          ar: `رصد ${highJsSignals.length} سلوكاً خطيراً في أكواد JavaScript: ${highJsSignals.map((s) => s.indicator).slice(0, 2).join('؛ ')}`,
        }
      : jsBehaviorWarn
        ? {
            en: `${medJsSignals.length} defensive/anti-analysis JS indicator(s) recorded`,
            ar: `رصد ${medJsSignals.length} مؤشر تعطيل فحص في كود JavaScript`,
          }
        : isMinifiedBundlePresent && !hasMaliciousObfuscationMarker
          ? {
              en: `AST inspected ${inlineJsCount} inline & ${externalJsFiles.length} external JS files (standard minified production bundles verified clean)`,
              ar: `فحص AST لـ ${inlineJsCount} سكربت داخلي و ${externalJsFiles.length} خارجي (حزم مضغوطة قياسية سليمة دون تمويه خبيث)`,
            }
          : {
              en: `AST inspected ${inlineJsCount} inline & ${externalJsFiles.length} external JS files — no exfiltration or malicious obfuscation detected`,
              ar: `فحص AST لـ ${inlineJsCount} سكربت داخلي و ${externalJsFiles.length} خارجي — خالية من التمويه الخبيث وخطافات التسريب`,
            },
    status: jsBehaviorFailed ? 'failed' : jsBehaviorWarn ? 'warning' : 'pass',
    severity: jsBehaviorFailed ? 'high' : jsBehaviorWarn ? 'medium' : 'informational',
    weight: jsBehaviorFailed ? (highJsSignals.length >= 2 || dynamicFormActionRewrite || walletDrainerPattern ? 26 : 20) : jsBehaviorWarn ? 10 : 0,
    evidence: `ASTParsed: ${astResult.scriptsParsed} | InlineJS: ${inlineJsCount} | ExtJS: ${externalJsFiles.length} | MinifiedOnly: ${isMinifiedBundlePresent && !hasMaliciousObfuscationMarker} | HighSignals: [${highJsSignals.map((s) => s.indicator).join(', ') || 'none'}] | ExfilHooks: [${formExfiltrationHooks.join('; ') || 'none'}] | StorageAccess: [${storageAndCookieAccess.join(', ') || 'none'}]`,
    sourceCodeEvidence: highJsSignals[0]?.codeExcerpt || medJsSignals[0]?.codeExcerpt,
    explanation: {
      en: jsBehaviorFailed
        ? 'AST static inspection identified high-risk runtime behavior such as encoded eval() unpacking, _0x obfuscation arrays, dynamic form.action rewriting, or verified credential/clipboard exfiltration.'
        : 'AST static analysis verified clean script patterns without encoded payload unpacking or unverified credential exfiltration.',
      ar: jsBehaviorFailed
        ? 'كشف التحليل الدلالي (AST) أنماطاً خطيرة مثل فك تشفير eval أو مصفوفات _0x أو تغيير وجهة إرسال النماذج أو تسريب البيانات.'
        : 'أكد التحليل الدلالي AST سلامة السكربتات وخلوها من التمويه الخبيث أو سرقة البيانات.',
    },
    recommendedAction: {
      en: jsBehaviorFailed ? 'Do not enter credentials or allow clipboard/wallet access on this page.' : 'No action required.',
      ar: jsBehaviorFailed ? 'لا تُدخل أي بيانات أو تمنح صلاحيات للحافظة أو المحفظة في هذه الصفحة.' : 'لا يلزم إجراء.',
    },
    source: 'SM AST JS Forensics',
    timestamp: now,
    confidence: jsBehaviorFailed ? 94 : 90,
  });

  // Source Finding A2: Background JS Data Collection & External Service Exfiltration (AST Data-Flow Verified)
  const harmfulExternalTx = externalDataTransmissions.filter((t) => t.isHarmful);
  const trackingExternalTx = externalDataTransmissions.filter((t) => t.harmClassification === 'suspicious_tracking');
  const unverifiedExternalTx = externalDataTransmissions.filter((t) => t.harmClassification === 'unverified_external');
  const unverifiedTrackingTx = trackingExternalTx.filter(
    (t) => t.transmittedDataTypes.includes('device_fingerprint') || t.relationshipStatus === 'external_unknown'
  );
  const benignExternalTx = externalDataTransmissions.filter((t) => t.harmClassification === 'benign_functional');
  const hasHighRiskBgExfil = harmfulExternalTx.length > 0;
  const hasMediumBgCollectionWarn = !hasHighRiskBgExfil && trackingExternalTx.length > 0;
  const hasUnverifiedExternalWarn = !hasHighRiskBgExfil && !hasMediumBgCollectionWarn && unverifiedExternalTx.length > 0;
  const trackingHasSubstantiveRisk = unverifiedTrackingTx.length > 0;

  if (backgroundDataCollection.length > 0 || externalDataTransmissions.length > 0) {
    const primaryHarmfulTypes = Array.from(new Set(harmfulExternalTx.flatMap((t) => t.transmittedDataTypes)));
    findings.push({
      id: 'source-background-exfiltration',
      section: 'javascript_analysis',
      test: {
        en: 'Background JS Data Collection & External Service Transmission',
        ar: 'كشف جمع البيانات بالخلفية عبر JavaScript وتقييم خطورة البيانات المرسلة',
      },
      result: hasHighRiskBgExfil
        ? {
            en: `Harmful exfiltration of [${primaryHarmfulTypes.join(', ')}] to ${harmfulExternalTx.map((t) => t.destinationHost).slice(0, 3).join(', ')}`,
            ar: `تسريب بيانات ضار (${primaryHarmfulTypes.join('، ')}) إلى خادم خارجي (${harmfulExternalTx.map((t) => t.destinationHost).slice(0, 3).join('، ')})`,
          }
        : hasMediumBgCollectionWarn
          ? {
              en: `Tracking / profiling telemetry sent to ${trackingExternalTx.map((t) => t.destinationHost).slice(0, 3).join(', ') || 'external host'} (no credential theft detected)`,
              ar: `إرسال بيانات تتبع أو بصمة متصفح إلى (${trackingExternalTx.map((t) => t.destinationHost).slice(0, 3).join('، ') || 'خادم خارجي'}) دون سرقة كلمات مرور`,
            }
          : hasUnverifiedExternalWarn
            ? {
                en: `${unverifiedExternalTx.length} unverified external outbound request(s) to ${unverifiedExternalTx.map((t) => t.destinationHost).slice(0, 3).join(', ')} (cannot confirm benign)`,
                ar: `رصد ${unverifiedExternalTx.length} إرسال خارجي غير موثوق إلى (${unverifiedExternalTx.map((t) => t.destinationHost).slice(0, 3).join('، ')}) لا يمكن الجزم بسلامته`,
              }
            : {
                en: `Benign/harmless payload telemetry verified across ${benignExternalTx.length || externalDataTransmissions.length} endpoint(s) (no credential/cookie exfiltration)`,
                ar: `البيانات المرسلة سليمة وغير ضارة عبر ${benignExternalTx.length || externalDataTransmissions.length} وجهة (بدون تسريب كلمات مرور أو كوكيز)`,
              },
      status: hasHighRiskBgExfil ? 'failed' : hasMediumBgCollectionWarn || hasUnverifiedExternalWarn ? 'warning' : 'pass',
      severity: hasHighRiskBgExfil ? 'high' : trackingHasSubstantiveRisk || hasUnverifiedExternalWarn ? 'medium' : hasMediumBgCollectionWarn ? 'low' : 'informational',
      weight: hasHighRiskBgExfil ? (harmfulExternalTx.some((t) => t.obfuscatedUrl) ? 30 : 26) : hasUnverifiedExternalWarn ? 12 : trackingHasSubstantiveRisk ? 10 : 0,
      evidence: `HarmfulTx: ${harmfulExternalTx.length} | UnverifiedTx: ${unverifiedExternalTx.length} | TrackingTx: ${trackingExternalTx.length} | BenignTx: ${benignExternalTx.length} | BgCollectors: [${backgroundDataCollection.map((b) => `${b.category}(${b.apisUsed.join('+')})`).join('; ') || 'none'}] | ExternalTx: [${externalDataTransmissions.map((t) => `${t.method}:${t.destinationUrl}[${t.transmittedDataTypes.join('+')}=>${t.harmClassification}]`).join('; ') || 'none'}]`,
      sourceCodeEvidence: (harmfulExternalTx[0] || unverifiedExternalTx[0] || trackingExternalTx[0] || externalDataTransmissions[0])?.excerpt,
      destination: (harmfulExternalTx[0] || unverifiedExternalTx[0] || externalDataTransmissions[0])?.destinationHost,
      dataClassification: (harmfulExternalTx[0] || unverifiedExternalTx[0] || externalDataTransmissions[0])?.payloadClassification,
      explanation: {
        en: hasHighRiskBgExfil
          ? `AST taint propagation confirmed harmful transmission of sensitive user/session data (${primaryHarmfulTypes.join(', ')}) to external endpoint(s).`
          : hasMediumBgCollectionWarn
            ? 'Payload inspection detected device/IP profiling or cross-site tracking telemetry rather than password theft.'
            : hasUnverifiedExternalWarn
              ? 'Outbound external requests target unverified third-party domains with unknown payloads; they are NOT assumed benign.'
              : 'AST taint analysis verified outbound requests do not carry stolen credentials, auth cookies, or keystrokes.',
        ar: hasHighRiskBgExfil
          ? `تأكد تحليل تدفق البيانات (AST) من إرسال بيانات حساسة وخطيرة (${primaryHarmfulTypes.join('، ')}) إلى خادم خارجي.`
          : hasMediumBgCollectionWarn
            ? 'البيانات المرسلة تتعلق باستعلام IP أو بصمة الجهاز والتتبع.'
            : hasUnverifiedExternalWarn
              ? 'تتجه طلبات شبكية خارجية لنطاقات غير معروفة بحمولات غير مؤكدة ولا تُصنّف سليمة.'
              : 'تأكد تحليل تدفق البيانات من خلو الإرسال الشبكي من تسريب كلمات المرور أو الكوكيز أو ضغطات المفاتيح.',
      },
      recommendedAction: {
        en: hasHighRiskBgExfil
          ? 'Do not sign in or enter sensitive data; harmful data exfiltration was confirmed.'
          : hasUnverifiedExternalWarn
            ? 'Inspect the destination endpoints before submitting personal information.'
            : 'No security risk action needed.',
        ar: hasHighRiskBgExfil
          ? 'لا تُدخل أي كلمات مرور أو بيانات حساسة؛ تم تأكيد إرسال بيانات ضارة لخادم خارجي.'
          : hasUnverifiedExternalWarn
            ? 'افحص الوجهات الخارجية قبل إرسال أي بيانات شخصية.'
            : 'لا يلزم إجراء أمني.',
      },
      source: 'SM AST Telemetry & Payload Inspector',
      timestamp: now,
      confidence: hasHighRiskBgExfil ? 95 : 90,
    });
  }

  // Source Finding A2-B: Static AST Data-Flow Taint Confirmation (e.g. Camera/Geo/Clipboard/IP -> Telegram/Webhook)
  const confirmedTaints = (sourceIntel.dataFlowTaints || []).filter((t) => t.confirmedStaticFlow);
  if (confirmedTaints.length > 0) {
    findings.push({
      id: 'source-ast-dataflow-exfil',
      section: 'javascript_analysis',
      test: {
        en: 'CONFIRMED_DATA_EXFILTRATION_FLOW (Static AST)',
        ar: 'تأكيد تدفق تسريب البيانات (تحليل AST الساكن)',
      },
      result: {
        en: `${confirmedTaints.length} static data-flow exfiltration chain(s): ${confirmedTaints[0].source} -> ${confirmedTaints[0].sink}`,
        ar: `رصد ${confirmedTaints.length} سلسلة تسريب بيانات مؤكدة في الكود الساكن: ${confirmedTaints[0].source} -> ${confirmedTaints[0].sink}`,
      },
      status: 'failed',
      severity: confirmedTaints.some((t) => t.sinkChannel === 'HIGH_RISK_EXFILTRATION_CHANNEL' || t.sinkChannel === 'WEBHOOK_OR_BOT_SINK') ? 'critical' : 'high',
      weight: confirmedTaints.some((t) => t.sinkChannel === 'HIGH_RISK_EXFILTRATION_CHANNEL') ? 32 : 24,
      evidence: confirmedTaints.map((t) => `${t.sourceKind}:${t.source} -> ${t.sink} [${t.triggerContext}]`).join(' | '),
      sourceCodeEvidence: confirmedTaints[0].excerpt,
      explanation: confirmedTaints[0].detail,
      recommendedAction: {
        en: 'Leave this page immediately and deny all browser permissions; static AST verified sensitive capture flows into an external sink.',
        ar: 'غادر الصفحة فوراً وارفض جميع الأذونات؛ أثبت التحليل الساكن تدفق بيانات حساسة نحو قناة إرسال خارجية.',
      },
      source: 'SM AST Taint Tracer',
      timestamp: now,
      confidence: 96,
    });
  }

  // Source Finding A2-C: Planted Backdoors, Exposed Secrets & Cross-Window Message Hygiene
  if (astResult.plantedBackdoors.length > 0) {
    const hasCriticalBackdoor = astResult.plantedBackdoors.some((b) => b.severity === 'critical' || b.severity === 'high');
    const isPostMessageOnly = astResult.plantedBackdoors.every(
      (b) => b.kind === 'unvalidated_message_listener' || b.kind === 'unsafe_postmessage_wildcard'
    );
    findings.push({
      id: 'source-planted-backdoors',
      section: 'source_intelligence',
      test: isPostMessageOnly
        ? {
            en: 'Cross-Window Messaging & Origin Validation Hygiene',
            ar: 'سلامة رسائل النوافذ (postMessage) والتحقق من المصدر',
          }
        : {
            en: 'Suspicious Backdoors, Exposed Bot Tokens & Control Hooks',
            ar: 'كشف الأبواب الخلفية المزروعة ومفاتيح البوتات المكشوفة',
          },
      result: isPostMessageOnly
        ? {
            en: `${astResult.plantedBackdoors.length} postMessage origin-validation notice(s): ${astResult.plantedBackdoors[0].kind}`,
            ar: `ملاحظة حول التحقق من مصدر الرسائل (${astResult.plantedBackdoors.length}): ${astResult.plantedBackdoors[0].kind}`,
          }
        : {
            en: `${astResult.plantedBackdoors.length} planted backdoor/secret signal(s): ${astResult.plantedBackdoors[0].kind}`,
            ar: `رصد ${astResult.plantedBackdoors.length} مؤشر لباب خلفي أو سر مكشوف (${astResult.plantedBackdoors[0].kind})`,
          },
      status: hasCriticalBackdoor ? 'failed' : 'warning',
      severity: hasCriticalBackdoor ? 'critical' : isPostMessageOnly ? 'low' : 'medium',
      weight: hasCriticalBackdoor ? 26 : isPostMessageOnly ? 4 : 12,
      evidence: astResult.plantedBackdoors.map((b) => `${b.kind}: ${b.evidence}`).join(' | '),
      explanation: astResult.plantedBackdoors[0].detail,
      recommendedAction: hasCriticalBackdoor
        ? {
            en: 'Treat this page as compromised or maliciously instrumented; do not trust interactive controls or secrets in client scripts.',
            ar: 'تعامل مع هذه الصفحة كمخترقة أو مزروعة بأدوات تحكم خفية ولا تُدخل بيانات حساسة.',
          }
        : isPostMessageOnly
          ? {
              en: 'Verify event.origin strictly against an explicit allowlist inside window message listeners before consuming event.data, and specify a strict targetOrigin instead of "*" in postMessage calls.',
              ar: 'تحقق من event.origin مقابل قائمة نطاقات موثوقة داخل مستمع رسائل window.addEventListener("message") قبل قراءة event.data، وحدد targetOrigin صريحاً بدلاً من "*".',
            }
          : {
              en: 'Inspect suspicious control logic and verify client script integrity before submitting sensitive data.',
              ar: 'راجع شيفرة التحكم المشبوهة وتحقق من سلامة السكربتات قبل إدخال بيانات حساسة.',
            },
      source: 'SM Backdoor & Secret Detector',
      timestamp: now,
      confidence: hasCriticalBackdoor ? 94 : 85,
    });
  }

  // Source Finding A3: Cookie Security, Classification & Consent Audit
  if (cookieAudit.totalCookiesInspected > 0 || rawSetCookiesList.length > 0) {
    findings.push(cookieIntelResult.finding);
  }

  // Source Finding A4: Advertising, Tracking & Malvertising Intelligence (8-state model)
  if (advertisingIntel.status !== 'no_advertising_detected') {
    const isMalAd = advertisingIntel.status === 'malicious_advertising';
    const isSuspAd = advertisingIntel.status === 'suspicious_advertising';
    const isUndeclaredAd = advertisingIntel.status === 'undeclared_tracking';
    findings.push({
      id: 'source-advertising-audit',
      section: 'source_intelligence',
      test: { en: 'Advertising, Tracking & Malvertising Intelligence', ar: 'استخبارات الإعلانات والتتبع والإعلانات الخبيثة' },
      result: advertisingIntel.label,
      status: isMalAd ? 'failed' : isSuspAd || isUndeclaredAd ? 'warning' : 'pass',
      severity: isMalAd ? 'high' : isSuspAd ? 'medium' : isUndeclaredAd ? 'low' : 'informational',
      weight: isMalAd ? 22 : isSuspAd ? 10 : 0,
      evidence: `AdState: ${advertisingIntel.status} | AdNetworks: [${advertisingIntel.adNetworksDetected.join(', ') || 'none'}] | Analytics: [${advertisingIntel.analyticsPlatformsDetected.join(', ') || 'none'}] | Malvertising: [${advertisingIntel.malvertisingIndicators.join('; ') || 'none'}]`,
      consentContext: advertisingIntel.status,
      explanation: advertisingIntel.summary,
      recommendedAction: {
        en: isMalAd
          ? 'Close this page; aggressive popunder, forced redirect, cryptomining, or notification bait detected.'
          : 'Standard declared advertising or privacy preference context.',
        ar: isMalAd
          ? 'أغلق الصفحة؛ تم رصد إعلانات خبيثة أو نوافذ قسرية أو تعدين أو تضليل إشعارات.'
          : 'بيانات سياقية حول الإعلانات والتحليلات.',
      },
      source: 'SM Advertising Intelligence',
      timestamp: now,
      confidence: 90,
    });
  }

  // Source Finding B: HTML Semantics, Title-vs-Body & Clickjacking Structure
  let metaRefreshExternal = false;
  if (metaRefresh) {
    const urlPart = metaRefresh.match(/url\s*=\s*['"]?([^'";\s]+)/i)?.[1];
    if (urlPart) {
      try {
        const u = new URL(urlPart, finalUrl);
        if (extractRegistrableDomain(u.hostname) !== finalRegDomain && !classifyDomainRelationship(finalHost, u.hostname).isBenignOrAuthorized) {
          metaRefreshExternal = true;
        }
      } catch {
        // ignore
      }
    }
  }
  const crossOriginFormActionAttr = suspiciousAttributes.some((a) => a.attribute === 'formaction');
  const hasHtmlStructureFail = titleContentMismatch || metaRefreshExternal || crossOriginFormActionAttr;
  const hasHtmlStructureWarn = !hasHtmlStructureFail && hiddenOverlayIframes > 0;

  findings.push({
    id: 'source-html-structure',
    section: 'source_intelligence',
    test: { en: 'HTML DOM Structure, Meta & Title Integrity', ar: 'فحص بنية HTML وسلامة العنوان والوسوم المخفية' },
    result: titleContentMismatch && titleMismatchDetail
      ? titleMismatchDetail
      : metaRefreshExternal
        ? { en: `External <meta http-equiv="refresh"> redirects off-domain (${metaRefresh?.slice(0, 60)})`, ar: `وسم <meta refresh> يحوّل إلى نطاق خارجي غير مرتبط` }
        : crossOriginFormActionAttr
          ? { en: 'Button formaction attribute overrides submission to external domain', ar: 'سمة formaction تعيد توجيه إرسال النموذج إلى نطاق خارجي' }
          : hiddenOverlayIframes > 0
            ? { en: `${hiddenOverlayIframes} invisible/off-screen iframe overlay detected in HTML`, ar: `رصد ${hiddenOverlayIframes} إطار iframe مخفي قد يُستخدم لخطف النقرات` }
            : {
                en: `HTML structure verified clean (${hiddenInputs.length} hidden inputs, 0 external meta redirects, consistent <title>)`,
                ar: `بنية HTML متسقة وسليمة (${hiddenInputs.length} مدخلات مخفية، 0 تحويلات meta خارجية، عنوان متطابق)`,
              },
    status: hasHtmlStructureFail ? 'failed' : hasHtmlStructureWarn ? 'warning' : 'pass',
    severity: hasHtmlStructureFail ? 'high' : hasHtmlStructureWarn ? 'medium' : 'informational',
    weight: hasHtmlStructureFail ? 20 : hasHtmlStructureWarn ? 10 : 0,
    evidence: `TitleMismatch: ${titleContentMismatch} | MetaRefreshExternal: ${metaRefreshExternal} | CrossOriginFormaction: ${crossOriginFormActionAttr} | HiddenOverlayIframes: ${hiddenOverlayIframes} | JSON-LD: ${jsonLdCount}`,
    explanation: {
      en: hasHtmlStructureFail
        ? 'Retrieved HTML markup contains deceptive metadata (<title> brand mismatch against body copy, off-domain meta refresh redirect, or cross-origin formaction override).'
        : 'Retrieved HTML markup semantics (<title>, meta tags, form targets, iframes) align consistently with the page domain.',
      ar: hasHtmlStructureFail
        ? 'يكشف فحص كود HTML الفعلي عن تلاعب واضح في البنية أو انتحال في وسم <title> مقابل المحتوى أو إعادة توجيه مخفية.'
        : 'وسوم HTML وبنية الصفحة تتطابق بسلاسة مع النطاق والغرض المعروض.',
    },
    recommendedAction: {
      en: hasHtmlStructureFail ? 'Verify the true domain and avoid submitting data on pages with conflicting metadata.' : 'No action required.',
      ar: hasHtmlStructureFail ? 'تحقق من النطاق الحقيقي وتجنب إدخال البيانات في صفحات متضاربة البنية.' : 'لا يلزم إجراء.',
    },
    source: 'SM HTML Source Inspector',
    timestamp: now,
    confidence: 92,
  });

  // Source Finding C: In-Page Discovered Subdomains & Third-Party Topology
  const suspiciousSubdomains = discoveredSubdomains.filter((s) => s.suspiciousRole);
  findings.push({
    id: 'source-discovered-subdomains',
    section: 'source_intelligence',
    test: { en: 'Discovered Site Subdomains & Reference Topology', ar: 'اكتشاف النطاقات الفرعية وروابط البنية داخل الموقع' },
    result:
      discoveredSubdomains.length > 0
        ? {
            en: `${discoveredSubdomains.length} sibling subdomain(s) discovered under ${finalRegDomain}: ${discoveredSubdomains.slice(0, 4).map((s) => s.host).join(', ')}`,
            ar: `تم اكتشاف ${discoveredSubdomains.length} نطاق فرعي ضمن ${finalRegDomain}: ${discoveredSubdomains.slice(0, 4).map((s) => s.host).join('، ')}`,
          }
        : {
            en: `No additional subdomains under ${finalRegDomain} referenced in page HTML (${externalDomainsSet.size} external resource host(s))`,
            ar: `لم ترد نطاقات فرعية إضافية تحت ${finalRegDomain} في كود الصفحة (${externalDomainsSet.size} مضيف موارد خارجي)`,
          },
    status: suspiciousSubdomains.length > 0 ? 'warning' : 'pass',
    severity: 'informational',
    weight: 0,
    evidence: `Subdomains[${discoveredSubdomains.length}]: [${discoveredSubdomains.map((s) => `${s.host}(${s.role})`).join(', ') || 'none'}] | ExtResourceDomains: [${Array.from(externalDomainsSet).slice(0, 8).join(', ') || 'none'}]`,
    explanation: {
      en: 'Enumerates subdomains and external asset origins referenced directly inside HTML anchors, scripts, forms, stylesheets, and inline JavaScript.',
      ar: 'يستخرج النطاقات الفرعية ومصادر الموارد المذكورة داخل كود HTML والنماذج والسكربتات لتحليل البنية الفعلية للموقع.',
    },
    recommendedAction: {
      en: 'Inspect unfamiliar authentication or admin subdomains discovered inside third-party pages.',
      ar: 'راجع أي نطاقات فرعية غريبة مرتبطة بتسجيل الدخول أو الإرسال.',
    },
    source: 'SM Subdomain & Source Mapper',
    timestamp: now,
    confidence: 90,
  });

  if (brandLookalikeLinks.length > 0) {
    findings.push({
      id: 'source-brand-lookalike-links',
      section: 'source_intelligence',
      test: { en: 'Outbound Brand-Lookalike Link Analysis', ar: 'فحص الروابط الصادرة المشابهة للعلامات التجارية' },
      result: {
        en: `${brandLookalikeLinks.length} outbound link(s)/form(s) point to brand-lookalike host (${brandLookalikeLinks[0].host})`,
        ar: `رصد ${brandLookalikeLinks.length} رابط أو نموذج يشير إلى نطاق مشابه لعلامة تجارية (${brandLookalikeLinks[0].host})`,
      },
      status: 'warning',
      severity: 'low',
      weight: 4,
      relatedUrl: brandLookalikeLinks[0].url,
      evidence: brandLookalikeLinks.map((l) => `${l.host} -> ${l.targetBrand} (${l.officialDomain})`).join(' | '),
      explanation: {
        en: 'Source code inspection identified outbound hyperlinks or form endpoints whose domain names resemble known brands (similarity alone is not proof of phishing without active deception).',
        ar: 'كشف تحليل السورس عن روابط خارجية تتشابه اسمياً مع علامات تجارية معروفة؛ التشابه وحده لا يثبت التصيد دون مؤشر استغلال.',
      },
      recommendedAction: {
        en: 'Verify any outbound authentication or payment links before following them.',
        ar: 'تحقق من أي روابط أو وجهات إرسال قبل الانتقال إليها.',
      },
      source: 'SM Source Link Analyzer',
      timestamp: now,
      confidence: 88,
    });
  }

  if (!securityHeaders.csp) {
    findings.push({
      id: 'source-csp-missing',
      section: 'source_intelligence',
      test: { en: 'Content Security Policy (CSP) Header', ar: 'ترويسة سياسة أمان المحتوى (CSP)' },
      result: { en: 'Content-Security-Policy header is missing', ar: 'ترويسة Content-Security-Policy مفقودة' },
      status: 'warning',
      severity: 'informational',
      weight: 0,
      evidence: 'Missing CSP header in HTTP response',
      explanation: {
        en: 'Absence of a Content Security Policy allows browser execution of injected scripts if an XSS vulnerability occurs.',
        ar: 'غياب سياسة CSP يتيح للمتصفح تنفيذ أي سكربت محقون في حال وجود ثغرة XSS.',
      },
      recommendedAction: {
        en: 'Implement a strict CSP policy in production.',
        ar: 'تفعيل سياسة CSP صارمة في بيئة الإنتاج.',
      },
      source: 'SM Header Inspector',
      timestamp: now,
      confidence: 100,
    });
  }

  return { sourceIntel, formDetails, supplyChain, findings };
}
