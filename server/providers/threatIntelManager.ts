import net from 'node:net';
import type {
  BilingualText,
  CheckFinding,
  ProviderOperationalState,
  ThreatProviderResult,
} from '../types.ts';
import { lookupDomainOwnership } from '../analyzers/officialDomainRegistry.ts';

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

const providerCache = new Map<string, CacheEntry<any>>();
const lastSuccessMap = new Map<string, string>();
let openPhishSetCache: { urls: Set<string>; hosts: Set<string>; expiresAt: number } | null = null;
let feodoIpSetCache: { ips: Map<string, string>; expiresAt: number } | null = null;

export function recordProviderSuccess(providerId: string): void {
  lastSuccessMap.set(providerId, new Date().toISOString());
}

function getCached<T>(key: string): T | undefined {
  const entry = providerCache.get(key);
  if (!entry) return undefined;
  if (Date.now() > entry.expiresAt) {
    providerCache.delete(key);
    return undefined;
  }
  return entry.value as T;
}

function setCached<T>(key: string, value: T, ttlMs: number): void {
  if (providerCache.size > 500) {
    const firstKey = providerCache.keys().next().value;
    if (firstKey) providerCache.delete(firstKey);
  }
  providerCache.set(key, { value, expiresAt: Date.now() + ttlMs });
}

async function fetchWithRetry(url: string, init: RequestInit, timeoutMs = 6000, retries = 1): Promise<Response> {
  let lastErr: Error | undefined;
  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, { ...init, signal: controller.signal });
      clearTimeout(timer);
      return res;
    } catch (err) {
      clearTimeout(timer);
      lastErr = err as Error;
    }
  }
  throw lastErr || new Error('Upstream request failed');
}

export interface ProviderSummaryDescriptor {
  id: string;
  name: string;
  category: string;
  requiresKey: boolean;
  envVarName?: string;
  configured: boolean;
  operationalState: ProviderOperationalState;
  freeTierAvailable: boolean;
  freeTierNote: BilingualText;
  lastSuccessfulLookup?: string;
  toggleableInScan: boolean;
}

export function listConfiguredProviders(): ProviderSummaryDescriptor[] {
  const hasUrlhaus = Boolean(process.env.URLHAUS_AUTH_KEY);
  const hasVt = Boolean(process.env.VIRUSTOTAL_API_KEY);
  const hasUrlscanKey = Boolean(process.env.URLSCAN_API_KEY);
  const hasOtxKey = Boolean(process.env.OTX_API_KEY);
  const hasScreenshotNeo = Boolean(process.env.SCREENSHOTNEO_ACCESS_KEY);
  const hasCloudBrowser = Boolean(
    (process.env.CLOUD_BROWSER_ENDPOINT || '').trim() && (process.env.CLOUD_BROWSER_API_KEY || '').trim()
  );

  return [
    {
      id: 'virustotal',
      name: 'VirusTotal API v3',
      category: 'Multi-Engine Reputation (URL / Domain / IP)',
      requiresKey: true,
      configured: hasVt,
      operationalState: hasVt ? 'active' : 'auth_required',
      freeTierAvailable: true,
      freeTierNote: {
        en: hasVt
          ? 'Authenticated cloud engine active on backend. Inspects URL, Domain, and IP telemetry with multi-engine detection counts.'
          : 'Authenticated cloud service currently inactive on this server. Excluded from safety signals until activated.',
        ar: hasVt
          ? 'محرك سحابي مفعّل ومؤمّن على الخادم. يفحص سمعة الرابط والنطاق وعنوان IP عبر عشرات محركات الحماية.'
          : 'الخدمة غير مفعّلة على الخادم حالياً. لا تُحتسب ضمن مؤشرات الأمان عند غياب التفعيل.',
      },
      lastSuccessfulLookup: lastSuccessMap.get('virustotal'),
      toggleableInScan: true,
    },
    {
      id: 'urlhaus',
      name: 'URLhaus (abuse.ch)',
      category: 'Malware URLs & Hosts',
      requiresKey: true,
      configured: hasUrlhaus,
      operationalState: hasUrlhaus ? 'active' : 'auth_required',
      freeTierAvailable: true,
      freeTierNote: {
        en: hasUrlhaus
          ? 'Authenticated malware threat feed active on backend. Inspects submitted URLs and resolved hostnames.'
          : 'Authenticated malware feed currently inactive on this server. Excluded from safety signals until activated.',
        ar: hasUrlhaus
          ? 'قاعدة بيانات البرمجيات الخبيثة مفعّلة على الخادم. تفحص الرابط المرسل واسم المضيف مباشرة.'
          : 'الخدمة غير مفعّلة على الخادم حالياً. لا تُحتسب ضمن مؤشرات الأمان عند غياب التفعيل.',
      },
      lastSuccessfulLookup: lastSuccessMap.get('urlhaus'),
      toggleableInScan: true,
    },
    {
      id: 'openphish',
      name: 'OpenPhish Community Feed',
      category: 'Phishing Feed',
      requiresKey: false,
      configured: true,
      operationalState: 'active',
      freeTierAvailable: true,
      freeTierNote: {
        en: 'Active without API key. Queries the live public phishing feed cached locally for 30 minutes.',
        ar: 'نشط بدون مفتاح API. يفحص قائمة التصيد العامة المباشرة مع تخزين مؤقت لمدة 30 دقيقة.',
      },
      lastSuccessfulLookup: lastSuccessMap.get('openphish'),
      toggleableInScan: true,
    },
    {
      id: 'otx',
      name: 'AlienVault OTX',
      category: 'Threat Intelligence (Domain & IP)',
      requiresKey: false,
      configured: true,
      operationalState: 'active',
      freeTierAvailable: true,
      freeTierNote: {
        en: hasOtxKey
          ? 'Authenticated threat-pulse connection active on backend for domain and IP lookups.'
          : 'Public indicator endpoint active for both domain and IPv4 pulses with allowlist filtering.',
        ar: hasOtxKey
          ? 'اتصال مؤمّن ونشط عبر الخادم لاستعلام نبضات التهديد للنطاقات وعناوين IP.'
          : 'الاستعلام العام نشط لفحص النطاق وعنوان IPv4 مع تصفية قوائم التحقق المرجعية.',
      },
      lastSuccessfulLookup: lastSuccessMap.get('otx'),
      toggleableInScan: true,
    },
    {
      id: 'urlscan',
      name: 'URLScan.io Public Search',
      category: 'Website Intelligence',
      requiresKey: false,
      configured: true,
      operationalState: 'active',
      freeTierAvailable: true,
      freeTierNote: {
        en: hasUrlscanKey
          ? 'Authenticated URLScan connection active on backend with expanded inspection quotas.'
          : 'Public search active without API key (subject to upstream limits).',
        ar: hasUrlscanKey
          ? 'اتصال URLScan مؤمّن ومفعّل على الخادم بحصة استعلامات موسعة.'
          : 'البحث العام نشط تلقائياً بدون مفتاح (خاضع لحدود المزود).',
      },
      lastSuccessfulLookup: lastSuccessMap.get('urlscan'),
      toggleableInScan: true,
    },
    {
      id: 'rdap',
      name: 'IANA / Registry RDAP & WHOIS',
      category: 'Domain Intelligence',
      requiresKey: false,
      configured: true,
      operationalState: 'active',
      freeTierAvailable: true,
      freeTierNote: {
        en: 'Queries official IANA RDAP bootstrap servers, ARIN IP RDAP, and port-43 WHOIS fallback without paid keys.',
        ar: 'يستعلم خوادم RDAP الرسمية وARIN وبروتوكول WHOIS مباشرة بدون مفاتيح مدفوعة.',
      },
      lastSuccessfulLookup: lastSuccessMap.get('rdap'),
      toggleableInScan: false,
    },
    {
      id: 'doh',
      name: 'Cloudflare DoH & OS DNS',
      category: 'DNS & DNSSEC Resolution',
      requiresKey: false,
      configured: true,
      operationalState: 'active',
      freeTierAvailable: true,
      freeTierNote: {
        en: 'Combines OS DNS (A/AAAA/SOA/PTR/MX/NS/TXT) with Cloudflare DNS-over-HTTPS + DNSSEC verification.',
        ar: 'يجمع بين محلل النظام و Cloudflare DoH للتحقق من السجلات و DNSSEC.',
      },
      lastSuccessfulLookup: lastSuccessMap.get('doh'),
      toggleableInScan: false,
    },
    {
      id: 'crtsh',
      name: 'Certificate Transparency (crt.sh)',
      category: 'Certificate Logs',
      requiresKey: false,
      configured: true,
      operationalState: 'active',
      freeTierAvailable: true,
      freeTierNote: {
        en: 'Public Certificate Transparency log search via crt.sh; subject to upstream load.',
        ar: 'بحث عام في سجلات شفافية الشهادات crt.sh.',
      },
      lastSuccessfulLookup: lastSuccessMap.get('crtsh'),
      toggleableInScan: false,
    },
    {
      id: 'shodan_internetdb',
      name: 'Shodan InternetDB (Open IP & CVE)',
      category: 'IP Ports, CVEs & Threat Tags',
      requiresKey: false,
      configured: true,
      operationalState: 'active',
      freeTierAvailable: true,
      freeTierNote: {
        en: 'Open public IP telemetry (zero key): inspects exposed ports, known CVEs, CPEs, and compromised/malware host tags.',
        ar: 'استخبارات IP مفتوحة بدون مفتاح: تفحص المنافذ المفتوحة والثغرات CVE ووسوم الاختراق والبرمجيات الخبيثة.',
      },
      lastSuccessfulLookup: lastSuccessMap.get('shodan_internetdb'),
      toggleableInScan: true,
    },
    {
      id: 'feodotracker',
      name: 'Feodo Tracker C2 (abuse.ch)',
      category: 'Botnet Command & Control IPs',
      requiresKey: false,
      configured: true,
      operationalState: 'active',
      freeTierAvailable: true,
      freeTierNote: {
        en: 'Open abuse.ch live botnet C2 IP blocklist cached every 30 minutes without requiring an API key.',
        ar: 'قائمة abuse.ch المفتوحة لعناوين IP لخوادم التحكم بالبوت نت (C2) بدون مفتاح API.',
      },
      lastSuccessfulLookup: lastSuccessMap.get('feodotracker'),
      toggleableInScan: true,
    },
    {
      id: 'cloudflare_security_dns',
      name: 'Cloudflare Security DNS (1.1.1.2)',
      category: 'Malware & Phishing DNS Sinkhole',
      requiresKey: false,
      configured: true,
      operationalState: 'active',
      freeTierAvailable: true,
      freeTierNote: {
        en: 'Automatic zero-key DNS security lookup via security.cloudflare-dns.com blocking known malware & phishing hostnames.',
        ar: 'فحص أمني تلقائي بدون مفتاح عبر Cloudflare Security DNS (1.1.1.2) لكشف النطاقات المحجوبة للبرمجيات الخبيثة والتصيد.',
      },
      lastSuccessfulLookup: lastSuccessMap.get('cloudflare_security_dns'),
      toggleableInScan: true,
    },
    {
      id: 'phishstats',
      name: 'PhishStats Public API',
      category: 'Live Phishing Intelligence',
      requiresKey: false,
      configured: true,
      operationalState: 'active',
      freeTierAvailable: true,
      freeTierNote: {
        en: 'Automatic zero-key query against the PhishStats live phishing telemetry database (URL & host).',
        ar: 'استعلام تلقائي مباشر بدون مفتاح في قاعدة بيانات PhishStats لمؤشرات التصيد الاحتيالي.',
      },
      lastSuccessfulLookup: lastSuccessMap.get('phishstats'),
      toggleableInScan: true,
    },
    {
      id: 'screenshot_neo',
      name: 'ScreenshotNeo Visual Gateway',
      category: 'Visual Preview',
      requiresKey: true,
      configured: hasScreenshotNeo,
      operationalState: hasScreenshotNeo ? 'active' : 'auth_required',
      freeTierAvailable: true,
      freeTierNote: {
        en: hasScreenshotNeo
          ? 'Authenticated visual capture gateway active on backend for live WebP website previews.'
          : 'Visual capture gateway currently inactive on this server.',
        ar: hasScreenshotNeo
          ? 'بوابة الالتقاط البصري مفعّلة ومؤمّنة على الخادم لتصوير معاينة الموقع بصيغة WebP.'
          : 'بوابة الالتقاط البصري غير مفعّلة على هذا الخادم حالياً.',
      },
      lastSuccessfulLookup: lastSuccessMap.get('screenshot_neo'),
      toggleableInScan: false,
    },
    {
      id: 'external_cloud_browser',
      name: 'External Cloud Browser Service (Level B)',
      category: 'Dynamic Runtime Execution',
      requiresKey: true,
      configured: hasCloudBrowser,
      operationalState: hasCloudBrowser ? 'active' : 'auth_required',
      freeTierAvailable: false,
      freeTierNote: {
        en: hasCloudBrowser
          ? 'External Cloud Browser Service is active on backend for isolated Level B runtime network, permission, and screenshot observation.'
          : 'External Cloud Browser Service credentials are not configured in server environment; Level B skips gracefully without false risk penalties.',
        ar: hasCloudBrowser
          ? 'خدمة المتصفح السحابي الخارجي مفعّلة على الخادم لمراقبة المستوى B (الطلبات الشبكية، الأذونات، ولقطات الشاشة) دون استهلاك موارد الخادم.'
          : 'بيانات خدمة المتصفح السحابي الخارجي غير مضبوطة في الخادم؛ يعتمد الفحص على المستوى A مع خصم الثقة والتغطية فقط.',
      },
      lastSuccessfulLookup: lastSuccessMap.get('external_cloud_browser'),
      toggleableInScan: true,
    },
  ];
}

async function checkOpenPhish(targetUrl: string, hostname: string): Promise<ThreatProviderResult> {
  const start = Date.now();
  try {
    if (!openPhishSetCache || Date.now() > openPhishSetCache.expiresAt) {
      const res = await fetchWithRetry('https://openphish.com/feed.txt', { method: 'GET' }, 6000, 0);
      if (!res.ok) {
        const rateLimited = res.status === 429;
        return {
          providerId: 'openphish',
          providerName: 'OpenPhish Community Feed',
          category: 'Phishing Feed',
          enabled: true,
          configured: true,
          operationalState: rateLimited ? 'rate_limited' : 'unavailable',
          status: rateLimited ? 'rate_limited' : 'unavailable',
          verdictDetail: {
            en: `Feed returned HTTP ${res.status}`,
            ar: `أرجعت الخدمة رمز الحالة HTTP ${res.status}`,
          },
          inspectedTargets: [`URL: ${targetUrl}`, `Host: ${hostname}`],
          latencyMs: Date.now() - start,
          requiresKey: false,
        };
      }
      const text = await res.text();
      const urls = new Set<string>();
      const hosts = new Set<string>();
      for (const line of text.split('\n')) {
        const clean = line.trim();
        if (!clean) continue;
        urls.add(clean.toLowerCase());
        try {
          hosts.add(new URL(clean).hostname.toLowerCase());
        } catch {
          // ignore
        }
      }
      openPhishSetCache = { urls, hosts, expiresAt: Date.now() + 30 * 60 * 1000 };
    }

    const now = new Date().toISOString();
    lastSuccessMap.set('openphish', now);
    const exactHit = openPhishSetCache.urls.has(targetUrl.toLowerCase());
    const hostHit = openPhishSetCache.hosts.has(hostname.toLowerCase());
    return {
      providerId: 'openphish',
      providerName: 'OpenPhish Community Feed',
      category: 'Phishing Feed',
      enabled: true,
      configured: true,
      operationalState: 'active',
      status: exactHit || hostHit ? 'flagged' : 'clean',
      verdictDetail: exactHit
        ? { en: 'Exact URL listed in active OpenPhish feed', ar: 'الرابط مدرج حرفياً في قائمة OpenPhish للتصيد' }
        : hostHit
          ? { en: 'Hostname appears in active OpenPhish feed', ar: 'اسم النطاق مدرج في قائمة OpenPhish للتصيد' }
          : {
              en: `Not listed in OpenPhish community feed (${openPhishSetCache.urls.size} active entries)`,
              ar: `غير مدرج في قائمة OpenPhish النشطة (${openPhishSetCache.urls.size} رابط)`,
            },
      inspectedTargets: [`URL: ${targetUrl}`, `Host: ${hostname}`],
      matchScope: exactHit ? 'exact_url' : hostHit ? 'hostname' : 'none',
      dataSource: 'https://openphish.com/feed.txt',
      lastAnalyzedAt: now,
      latencyMs: Date.now() - start,
      lastSuccessfulLookup: now,
      cached: true,
      requiresKey: false,
    };
  } catch (err) {
    return {
      providerId: 'openphish',
      providerName: 'OpenPhish Community Feed',
      category: 'Phishing Feed',
      enabled: true,
      configured: true,
      operationalState: 'unavailable',
      status: 'error',
      matchScope: 'none',
      dataSource: 'https://openphish.com/feed.txt',
      verdictDetail: {
        en: `Feed unavailable: ${(err as Error).message}`,
        ar: `تعذر الاتصال بـ OpenPhish: ${(err as Error).message}`,
      },
      latencyMs: Date.now() - start,
      requiresKey: false,
    };
  }
}

async function checkUrlhaus(
  targetUrl: string,
  hostname: string,
  isMultiPurposeOfficial = false
): Promise<ThreatProviderResult> {
  const apiKey = process.env.URLHAUS_AUTH_KEY;
  if (!apiKey) {
    return {
      providerId: 'urlhaus',
      providerName: 'URLhaus (abuse.ch)',
      category: 'Malware URLs & Hosts',
      enabled: false,
      configured: false,
      operationalState: 'auth_required',
      status: 'auth_required',
      verdictDetail: {
        en: 'Service credentials not activated on server; excluded from clean signals.',
        ar: 'بيانات الاعتماد غير مفعّلة على الخادم؛ لا يُحتسب ضمن مؤشرات السلامة.',
      },
      requiresKey: true,
    };
  }
  const cacheKey = `urlhaus:${targetUrl}:${hostname}`;
  const cached = getCached<ThreatProviderResult>(cacheKey);
  if (cached) return { ...cached, cached: true };

  const start = Date.now();
  try {
    const [urlRes, hostRes] = await Promise.all([
      fetchWithRetry(
        'https://urlhaus-api.abuse.ch/v1/url/',
        {
          method: 'POST',
          headers: { 'Auth-Key': apiKey, 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ url: targetUrl }),
        },
        5500,
        1
      ),
      fetchWithRetry(
        'https://urlhaus-api.abuse.ch/v1/host/',
        {
          method: 'POST',
          headers: { 'Auth-Key': apiKey, 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ host: hostname }),
        },
        5500,
        0
      ).catch(() => null),
    ]);

    if (!urlRes.ok) {
      const rl = urlRes.status === 429;
      return {
        providerId: 'urlhaus',
        providerName: 'URLhaus (abuse.ch)',
        category: 'Malware URLs & Hosts',
        enabled: true,
        configured: true,
        operationalState: rl ? 'rate_limited' : 'unavailable',
        status: rl ? 'rate_limited' : 'error',
        verdictDetail: { en: `URLhaus HTTP ${urlRes.status}`, ar: `استجابة URLhaus رمز ${urlRes.status}` },
        latencyMs: Date.now() - start,
        requiresKey: true,
      };
    }

    const json = await urlRes.json();
    const hostJson = hostRes && hostRes.ok ? await hostRes.json().catch(() => null) : null;
    const now = new Date().toISOString();
    lastSuccessMap.set('urlhaus', now);

    const urlFlagged = json.query_status === 'ok';
    const hostUrlCount = Number(hostJson?.url_count || 0);
    const hostOnlineMalware = Array.isArray(hostJson?.urls)
      ? hostJson.urls.filter((u: any) => u?.url_status === 'online').length
      : 0;
    // On multi-purpose official platforms (e.g., github.com, google.com), unrelated user-hosted paths elsewhere on the host
    // must NOT falsely flag the root or other official pages when the exact submitted URL is clean.
    const flagged = urlFlagged || (!isMultiPurposeOfficial && hostOnlineMalware > 0);
    const suspicious = !flagged && !isMultiPurposeOfficial && hostUrlCount > 0;

    const result: ThreatProviderResult = {
      providerId: 'urlhaus',
      providerName: 'URLhaus (abuse.ch)',
      category: 'Malware URLs & Hosts',
      enabled: true,
      configured: true,
      operationalState: 'active',
      status: flagged ? 'flagged' : suspicious ? 'suspicious' : 'clean',
      verdictDetail: urlFlagged
        ? {
            en: `Exact URL flagged for malware distribution (${json.threat || 'malware_download'})`,
            ar: `الرابط مدرج كناشر برمجيات خبيثة (${json.threat || 'malware'})`,
          }
        : !isMultiPurposeOfficial && hostOnlineMalware > 0
          ? {
              en: `Host "${hostname}" actively serves ${hostOnlineMalware} online malware payload(s) in URLhaus`,
              ar: `المضيف "${hostname}" ينشر ${hostOnlineMalware} ملفاً خبيثاً نشطاً في URLhaus`,
            }
          : suspicious
            ? {
                en: `Host has ${hostUrlCount} historical malware URL record(s) in URLhaus`,
                ar: `للمضيف ${hostUrlCount} سجل تاريخي للبرمجيات الخبيثة في URLhaus`,
              }
            : {
                en:
                  isMultiPurposeOfficial && hostUrlCount > 0
                    ? `0 exact matches for submitted URL in URLhaus (note: ${hostUrlCount} unrelated path record(s) exist on multi-purpose platform)`
                    : '0 matching URL or active host entries in URLhaus database',
                ar:
                  isMultiPurposeOfficial && hostUrlCount > 0
                    ? `لا توجد إصابات للرابط المحدد في URLhaus (${hostUrlCount} سجلاً غير مرتبط على نفس المنصة متعددة الاستخدامات)`
                    : '0 سجلات خبيثة للرابط أو المضيف في قاعدة بيانات URLhaus',
              },
      inspectedTargets: [`URL: ${targetUrl}`, `Host: ${hostname}`],
      matchScope: urlFlagged
        ? 'exact_url'
        : !isMultiPurposeOfficial && (hostOnlineMalware > 0 || hostUrlCount > 0)
          ? 'hostname'
          : 'none',
      dataSource: 'https://urlhaus-api.abuse.ch/v1/',
      lastAnalyzedAt: json.date_added || now,
      latencyMs: Date.now() - start,
      lastSuccessfulLookup: now,
      referenceUrl: json.urlhaus_reference || hostJson?.urlhaus_reference,
      requiresKey: true,
    };
    setCached(cacheKey, result, 15 * 60 * 1000);
    return result;
  } catch (err) {
    return {
      providerId: 'urlhaus',
      providerName: 'URLhaus (abuse.ch)',
      category: 'Malware URLs & Hosts',
      enabled: true,
      configured: true,
      operationalState: 'unavailable',
      status: 'error',
      matchScope: 'none',
      dataSource: 'https://urlhaus-api.abuse.ch/v1/',
      verdictDetail: { en: (err as Error).message, ar: (err as Error).message },
      latencyMs: Date.now() - start,
      requiresKey: true,
    };
  }
}

async function checkVirusTotal(
  targetUrl: string,
  registrableDomain: string,
  primaryIp?: string,
  isSharedOrOfficial = false
): Promise<ThreatProviderResult> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return {
      providerId: 'virustotal',
      providerName: 'VirusTotal API v3',
      category: 'Multi-Engine Reputation (URL / Domain / IP)',
      enabled: false,
      configured: false,
      operationalState: 'auth_required',
      status: 'auth_required',
      matchScope: 'none',
      dataSource: 'https://www.virustotal.com/api/v3/',
      verdictDetail: {
        en: 'Service credentials not activated on server; excluded from clean signals.',
        ar: 'بيانات الاعتماد غير مفعّلة على الخادم؛ لا يُحتسب ضمن مؤشرات السلامة.',
      },
      requiresKey: true,
    };
  }

  const cacheKey = `vt:${targetUrl}:${registrableDomain}:${primaryIp || ''}:${isSharedOrOfficial}`;
  const cached = getCached<ThreatProviderResult>(cacheKey);
  if (cached) return { ...cached, cached: true };

  const start = Date.now();
  try {
    // VirusTotal v3 uses unpadded base64url URL identifier for /api/v3/urls/{id}
    const urlId = Buffer.from(targetUrl).toString('base64url');
    const urlRes = await fetchWithRetry(
      `https://www.virustotal.com/api/v3/urls/${urlId}`,
      { method: 'GET', headers: { 'x-apikey': apiKey } },
      6000,
      0
    );

    if (urlRes.status === 429) {
      return {
        providerId: 'virustotal',
        providerName: 'VirusTotal API v3',
        category: 'Multi-Engine Reputation (URL / Domain / IP)',
        enabled: true,
        configured: true,
        operationalState: 'rate_limited',
        status: 'rate_limited',
        matchScope: 'none',
        dataSource: 'https://www.virustotal.com/api/v3/',
        verdictDetail: { en: 'VirusTotal API quota exceeded (HTTP 429)', ar: 'تجاوز حد طلبات VirusTotal المؤقت (429)' },
        latencyMs: Date.now() - start,
        requiresKey: true,
      };
    }

    let urlStats: any = null;
    let urlLastDate: number | undefined;
    let domainStats: any = null;
    let ipStats: any = null;
    const inspectedTargets: string[] = [];

    if (urlRes.ok) {
      const urlJson = await urlRes.json();
      urlStats = urlJson?.data?.attributes?.last_analysis_stats;
      urlLastDate = urlJson?.data?.attributes?.last_analysis_date;
      inspectedTargets.push(`URL: ${targetUrl}`);
    }

    // Also inspect domain & IP
    const isIpHost = net.isIP(registrableDomain.replace(/^\[|\]$/g, '')) !== 0;
    if (!isIpHost) {
      const domRes = await fetchWithRetry(
        `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(registrableDomain)}`,
        { method: 'GET', headers: { 'x-apikey': apiKey } },
        5500,
        0
      ).catch(() => null);
      if (domRes?.ok) {
        const dj = await domRes.json();
        domainStats = dj?.data?.attributes?.last_analysis_stats;
        if (!urlLastDate) urlLastDate = dj?.data?.attributes?.last_analysis_date;
        inspectedTargets.push(`Domain: ${registrableDomain}`);
      }
    }

    if (primaryIp) {
      const ipRes = await fetchWithRetry(
        `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(primaryIp)}`,
        { method: 'GET', headers: { 'x-apikey': apiKey } },
        5500,
        0
      ).catch(() => null);
      if (ipRes?.ok) {
        const ij = await ipRes.json();
        ipStats = ij?.data?.attributes?.last_analysis_stats;
        inspectedTargets.push(`IP: ${primaryIp}`);
      }
    }

    const activeStats = urlStats || domainStats || ipStats;
    const now = new Date().toISOString();
    lastSuccessMap.set('virustotal', now);

    if (!activeStats) {
      return {
        providerId: 'virustotal',
        providerName: 'VirusTotal API v3',
        category: 'Multi-Engine Reputation (URL / Domain / IP)',
        enabled: true,
        configured: true,
        operationalState: 'active',
        status: 'unknown',
        matchScope: 'none',
        dataSource: 'https://www.virustotal.com/api/v3/',
        verdictDetail: {
          en: 'No cached VirusTotal analysis record found for this URL, domain, or IP',
          ar: 'لا يوجد سجل تحليل مخزن لهذا الرابط أو النطاق في VirusTotal',
        },
        inspectedTargets: [`URL: ${targetUrl}`, `Domain: ${registrableDomain}`],
        latencyMs: Date.now() - start,
        lastSuccessfulLookup: now,
        requiresKey: true,
      };
    }

    const urlMal = Number(urlStats?.malicious || 0);
    const urlSusp = Number(urlStats?.suspicious || 0);
    const domMal = Number(domainStats?.malicious || 0);
    const ipMal = Number(ipStats?.malicious || 0);
    const ipOnlyOnSharedHost = urlMal === 0 && domMal === 0 && ipMal > 0 && isSharedOrOfficial;

    const malicious = ipOnlyOnSharedHost
      ? 0
      : Math.max(urlMal, domMal, urlMal === 0 && domMal === 0 ? ipMal : 0);
    const suspicious = Math.max(urlSusp, Number(domainStats?.suspicious || 0));
    const harmless = Number(activeStats.harmless || 0);
    const undetected = Number(activeStats.undetected || 0);

    const status: ThreatProviderResult['status'] =
      urlMal >= 1 || (!isSharedOrOfficial && domMal >= 2)
        ? 'flagged'
        : suspicious >= 2 || (!ipOnlyOnSharedHost && ipMal >= 3) || (!isSharedOrOfficial && domMal === 1)
          ? 'suspicious'
          : 'clean';

    const matchScope: ThreatProviderResult['matchScope'] =
      urlMal >= 1
        ? 'exact_url'
        : domMal >= 1
          ? 'registrable_domain'
          : !ipOnlyOnSharedHost && ipMal > 0
            ? 'ip_address'
            : 'none';

    const result: ThreatProviderResult = {
      providerId: 'virustotal',
      providerName: 'VirusTotal API v3',
      category: 'Multi-Engine Reputation (URL / Domain / IP)',
      enabled: true,
      configured: true,
      operationalState: 'active',
      status,
      matchScope,
      dataSource: 'https://www.virustotal.com/api/v3/',
      engineStats: { malicious, suspicious, harmless, undetected },
      inspectedTargets,
      lastAnalyzedAt: urlLastDate ? new Date(urlLastDate * 1000).toISOString() : now,
      verdictDetail: {
        en: `${malicious} malicious, ${suspicious} suspicious, ${harmless} harmless (${inspectedTargets.length} target(s): URL=${urlMal}, Domain=${domMal}, IP=${ipMal}${ipOnlyOnSharedHost ? '; shared CDN/cloud IP hits excluded' : ''})`,
        ar: `${malicious} محرك خبيث، ${suspicious} مشبوه، ${harmless} سليم (URL=${urlMal}، النطاق=${domMal}، IP=${ipMal}${ipOnlyOnSharedHost ? '؛ تم استبعاد بلاغات IP المشترك فقط' : ''})`,
      },
      latencyMs: Date.now() - start,
      lastSuccessfulLookup: now,
      referenceUrl: urlStats
        ? `https://www.virustotal.com/gui/url/${urlId}`
        : `https://www.virustotal.com/gui/domain/${encodeURIComponent(registrableDomain)}`,
      requiresKey: true,
    };
    setCached(cacheKey, result, 20 * 60 * 1000);
    return result;
  } catch (err) {
    return {
      providerId: 'virustotal',
      providerName: 'VirusTotal API v3',
      category: 'Multi-Engine Reputation (URL / Domain / IP)',
      enabled: true,
      configured: true,
      operationalState: 'unavailable',
      status: 'error',
      matchScope: 'none',
      dataSource: 'https://www.virustotal.com/api/v3/',
      verdictDetail: { en: (err as Error).message, ar: (err as Error).message },
      latencyMs: Date.now() - start,
      requiresKey: true,
    };
  }
}

async function checkUrlScanSearch(
  targetUrl: string,
  registrableDomain: string,
  isMultiPurposeOfficial = false
): Promise<ThreatProviderResult> {
  const cacheKey = `urlscan:${registrableDomain}:${isMultiPurposeOfficial ? targetUrl : 'domain'}`;
  const cached = getCached<ThreatProviderResult>(cacheKey);
  if (cached) return { ...cached, cached: true };

  const start = Date.now();
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (process.env.URLSCAN_API_KEY) {
    headers['API-Key'] = process.env.URLSCAN_API_KEY;
  }
  try {
    const res = await fetchWithRetry(
      `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(registrableDomain)}&size=5`,
      { method: 'GET', headers },
      5500,
      0
    );
    if (!res.ok) {
      const rl = res.status === 429;
      return {
        providerId: 'urlscan',
        providerName: 'URLScan.io Public Search',
        category: 'Website Intelligence',
        enabled: true,
        configured: true,
        operationalState: rl ? 'rate_limited' : 'unavailable',
        status: rl ? 'rate_limited' : 'unavailable',
        verdictDetail: { en: `URLScan HTTP ${res.status}`, ar: `استجابة URLScan رمز ${res.status}` },
        latencyMs: Date.now() - start,
        requiresKey: false,
      };
    }
    const json = await res.json();
    const now = new Date().toISOString();
    lastSuccessMap.set('urlscan', now);
    const results = Array.isArray(json.results) ? json.results : [];

    // On multi-purpose platforms (github.com, google.com, youtube.com, etc.), only treat a URLScan hit as malicious
    // if the scanned path matches the submitted URL (not arbitrary user repositories/content elsewhere on the domain).
    let targetPathNorm = '/';
    try {
      const tp = new URL(targetUrl);
      targetPathNorm = (tp.pathname || '/').replace(/\/+$/, '') || '/';
    } catch {
      targetPathNorm = '/';
    }

    const maliciousCount = results.filter((r: any) => {
      if (r?.verdicts?.overall?.malicious !== true) return false;
      if (!isMultiPurposeOfficial) return true;
      const scannedUrlStr = r?.page?.url || r?.task?.url;
      if (!scannedUrlStr) return false;
      try {
        const sp = new URL(scannedUrlStr);
        const scannedPath = (sp.pathname || '/').replace(/\/+$/, '') || '/';
        return scannedPath === targetPathNorm && sp.hostname.toLowerCase() === new URL(targetUrl).hostname.toLowerCase();
      } catch {
        return false;
      }
    }).length;
    const rawMaliciousCount = results.filter((r: any) => r?.verdicts?.overall?.malicious === true).length;

    const latestLink = results[0]?.result;
    const latestTime = results[0]?.task?.time;
    const result: ThreatProviderResult = {
      providerId: 'urlscan',
      providerName: 'URLScan.io Public Search',
      category: 'Website Intelligence',
      enabled: true,
      configured: true,
      operationalState: 'active',
      status: maliciousCount > 0 ? 'flagged' : results.length === 0 && !isMultiPurposeOfficial ? 'unknown' : 'clean',
      engineStats: {
        malicious: maliciousCount,
        suspicious: 0,
        harmless: Math.max(0, results.length - maliciousCount),
        undetected: 0,
      },
      inspectedTargets: [`Domain: ${registrableDomain}`, `URL: ${targetUrl}`],
      matchScope: maliciousCount > 0 ? (isMultiPurposeOfficial ? 'exact_url' : 'registrable_domain') : 'none',
      dataSource: 'https://urlscan.io/api/v1/search/',
      lastAnalyzedAt: latestTime || now,
      verdictDetail:
        results.length === 0
          ? { en: 'No prior public scans indexed for this domain on URLScan.io', ar: 'لا توجد فحوصات سابقة مفهرسة لهذا النطاق في URLScan.io' }
          : maliciousCount > 0
            ? {
                en: `${maliciousCount} of ${results.length} recent public scans flagged malicious`,
                ar: `تم تصنيف ${maliciousCount} من أصل ${results.length} فحصاً عاماً كخبيث`,
              }
            : isMultiPurposeOfficial && rawMaliciousCount > 0
              ? {
                  en: `0 malicious URLScan hits for submitted target (${rawMaliciousCount} unrelated user-submitted path(s) on platform excluded)`,
                  ar: `0 بلاغات خبيثة للرابط المحدد (${rawMaliciousCount} بلاغ لصفحات أخرى غير مرتبطة على المنصة)`,
                }
              : {
                  en: `${results.length} recent public scan(s) indexed — 0 malicious verdicts`,
                  ar: `${results.length} فحص عام مفهرس — 0 بلاغات خبيثة`,
                },
      latencyMs: Date.now() - start,
      lastSuccessfulLookup: now,
      referenceUrl: latestLink ? String(latestLink).replace('/api/v1/result/', '/result/') : undefined,
      requiresKey: false,
    };
    setCached(cacheKey, result, 15 * 60 * 1000);
    return result;
  } catch (err) {
    return {
      providerId: 'urlscan',
      providerName: 'URLScan.io Public Search',
      category: 'Website Intelligence',
      enabled: true,
      configured: true,
      operationalState: 'unavailable',
      status: 'error',
      matchScope: 'none',
      dataSource: 'https://urlscan.io/api/v1/search/',
      verdictDetail: { en: (err as Error).message, ar: (err as Error).message },
      latencyMs: Date.now() - start,
      requiresKey: false,
    };
  }
}

async function checkAlienVaultOtx(
  registrableDomain: string,
  primaryIp?: string,
  isOfficialPlatform = false
): Promise<ThreatProviderResult> {
  const cacheKey = `otx:${registrableDomain}:${primaryIp || ''}:${isOfficialPlatform}`;
  const cached = getCached<ThreatProviderResult>(cacheKey);
  if (cached) return { ...cached, cached: true };

  const start = Date.now();
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (process.env.OTX_API_KEY) {
    headers['X-OTX-API-KEY'] = process.env.OTX_API_KEY;
  }
  try {
    const isV4 = Boolean(primaryIp && net.isIPv4(primaryIp));
    const [domRes, ipRes] = await Promise.all([
      fetchWithRetry(
        `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(registrableDomain)}/general`,
        { method: 'GET', headers },
        5500,
        0
      ),
      isV4
        ? fetchWithRetry(
            `https://otx.alienvault.com/api/v1/indicators/IPv4/${encodeURIComponent(primaryIp!)}/general`,
            { method: 'GET', headers },
            5500,
            0
          ).catch(() => null)
        : Promise.resolve(null),
    ]);

    if (!domRes.ok) {
      const rl = domRes.status === 429;
      return {
        providerId: 'otx',
        providerName: 'AlienVault OTX',
        category: 'Threat Intelligence (Domain & IP)',
        enabled: true,
        configured: Boolean(process.env.OTX_API_KEY),
        operationalState: rl ? 'rate_limited' : 'unavailable',
        status: rl ? 'rate_limited' : 'unavailable',
        verdictDetail: { en: `OTX HTTP ${domRes.status}`, ar: `استجابة OTX رمز ${domRes.status}` },
        latencyMs: Date.now() - start,
        requiresKey: false,
      };
    }

    const json = await domRes.json();
    const ipJson = ipRes && ipRes.ok ? await ipRes.json().catch(() => null) : null;
    const now = new Date().toISOString();
    lastSuccessMap.set('otx', now);

    const domPulseCount = Number(json?.pulse_info?.count || 0);
    const ipPulseCount = Number(ipJson?.pulse_info?.count || 0);
    const validations: any[] = Array.isArray(json?.validation) ? json.validation : [];
    const isAllowlisted = validations.some((v) =>
      ['whitelist', 'majestic', 'akamai', 'alexa', 'cisco_umbrella', 'tranco'].includes(
        String(v?.source || '').toLowerCase()
      )
    );
    const suppressPulses = isAllowlisted || isOfficialPlatform;
    // Calibration: low-count research mentions (1-2 pulses) are advisory notes only; require >=3 pulses for suspicious and >=8 for flagged
    const flagged = !suppressPulses && domPulseCount >= 8;
    const suspicious = !flagged && !suppressPulses && (domPulseCount >= 3 || ipPulseCount >= 12);
    const advisoryOnlyPulses = !flagged && !suspicious && !suppressPulses && (domPulseCount > 0 || ipPulseCount > 0);

    const inspectedTargets = [`Domain: ${registrableDomain}`, ...(isV4 ? [`IP: ${primaryIp}`] : [])];

    const result: ThreatProviderResult = {
      providerId: 'otx',
      providerName: 'AlienVault OTX',
      category: 'Threat Intelligence (Domain & IP)',
      enabled: true,
      configured: true,
      operationalState: 'active',
      status: flagged ? 'flagged' : suspicious ? 'suspicious' : 'clean',
      inspectedTargets,
      matchScope:
        flagged || suspicious
          ? domPulseCount >= 3
            ? 'registrable_domain'
            : 'ip_address'
          : 'none',
      dataSource: 'https://otx.alienvault.com/api/v1/',
      lastAnalyzedAt: now,
      verdictDetail: suppressPulses
        ? {
            en: `${isAllowlisted ? `Domain in OTX allowlist (${validations.map((v) => v.source).slice(0, 2).join(', ')})` : 'Official verified platform'}; domain pulses=${domPulseCount}, IP pulses=${ipPulseCount} (shared/research mentions excluded)`,
            ar: `${isAllowlisted ? 'النطاق موثق في قوائم OTX المرجعية' : 'منصة رسمية موثقة'}؛ نبضات النطاق=${domPulseCount}، نبضات IP=${ipPulseCount}`,
          }
        : advisoryOnlyPulses
          ? {
              en: `Advisory warning only (no risk penalty): OTX pulses domain=${domPulseCount}, IP=${ipPulseCount} — below escalation threshold`,
              ar: `تحذير معلوماتي فقط (لا يؤثر في التقييم): نبضات التهديد في OTX: النطاق=${domPulseCount}، IP=${ipPulseCount}`,
            }
          : domPulseCount > 0 || ipPulseCount > 0
            ? {
                en: `OTX pulses: domain=${domPulseCount}, IP=${ipPulseCount}`,
                ar: `نبضات التهديد في OTX: النطاق=${domPulseCount}، IP=${ipPulseCount}`,
              }
            : {
                en: '0 threat pulses across domain and IPv4 indicators',
                ar: '0 نبضات تهديد مرتبطة بالنطاق أو عنوان IPv4',
              },
      latencyMs: Date.now() - start,
      lastSuccessfulLookup: now,
      referenceUrl: `https://otx.alienvault.com/indicator/domain/${encodeURIComponent(registrableDomain)}`,
      requiresKey: false,
    };
    setCached(cacheKey, result, 15 * 60 * 1000);
    return result;
  } catch (err) {
    return {
      providerId: 'otx',
      providerName: 'AlienVault OTX',
      category: 'Threat Intelligence (Domain & IP)',
      enabled: true,
      configured: Boolean(process.env.OTX_API_KEY),
      operationalState: 'unavailable',
      status: 'error',
      verdictDetail: { en: (err as Error).message, ar: (err as Error).message },
      latencyMs: Date.now() - start,
      requiresKey: false,
    };
  }
}

async function checkShodanInternetDb(primaryIp?: string, isCdnOrOfficial = false): Promise<ThreatProviderResult> {
  if (!primaryIp) {
    return {
      providerId: 'shodan_internetdb',
      providerName: 'Shodan InternetDB (Open IP & CVE)',
      category: 'IP Ports, CVEs & Threat Tags',
      enabled: true,
      configured: true,
      operationalState: 'unavailable',
      status: 'unknown',
      verdictDetail: { en: 'No IP address available for Shodan lookup', ar: 'لا يوجد عنوان IP متاح لفحص Shodan' },
      requiresKey: false,
    };
  }
  const cacheKey = `shodan:${primaryIp}:${isCdnOrOfficial}`;
  const cached = getCached<ThreatProviderResult>(cacheKey);
  if (cached) return { ...cached, cached: true };

  const start = Date.now();
  try {
    const res = await fetchWithRetry(
      `https://internetdb.shodan.io/${encodeURIComponent(primaryIp)}`,
      { method: 'GET', headers: { Accept: 'application/json' } },
      5000,
      0
    );
    const now = new Date().toISOString();
    if (res.status === 404) {
      lastSuccessMap.set('shodan_internetdb', now);
      return {
        providerId: 'shodan_internetdb',
        providerName: 'Shodan InternetDB (Open IP & CVE)',
        category: 'IP Ports, CVEs & Threat Tags',
        enabled: true,
        configured: true,
        operationalState: 'active',
        status: 'clean',
        inspectedTargets: [`IP: ${primaryIp}`],
        lastAnalyzedAt: now,
        verdictDetail: {
          en: `IP ${primaryIp} has 0 indexed open ports or threat tags in Shodan InternetDB`,
          ar: `عنوان IP (${primaryIp}) لا يحتوي على منافذ مكشوفة أو وسوم تهديد في Shodan InternetDB`,
        },
        latencyMs: Date.now() - start,
        lastSuccessfulLookup: now,
        referenceUrl: `https://www.shodan.io/host/${encodeURIComponent(primaryIp)}`,
        requiresKey: false,
      };
    }
    if (!res.ok) {
      return {
        providerId: 'shodan_internetdb',
        providerName: 'Shodan InternetDB (Open IP & CVE)',
        category: 'IP Ports, CVEs & Threat Tags',
        enabled: true,
        configured: true,
        operationalState: 'unavailable',
        status: 'unavailable',
        verdictDetail: { en: `Shodan InternetDB HTTP ${res.status}`, ar: `استجابة Shodan رمز ${res.status}` },
        latencyMs: Date.now() - start,
        requiresKey: false,
      };
    }

    const json = await res.json();
    lastSuccessMap.set('shodan_internetdb', now);
    const tags: string[] = Array.isArray(json?.tags) ? json.tags.map(String) : [];
    const ports: number[] = Array.isArray(json?.ports) ? json.ports.map(Number) : [];
    const vulns: string[] = Array.isArray(json?.vulns) ? json.vulns.map(String) : [];

    const badTags = tags.filter((t) => /compromised|malware|botnet|doublepulsar|c2|ransom/i.test(t));
    const isSharedCloudTag = isCdnOrOfficial || tags.some((t) => /cloud|cdn/i.test(t));
    const status: ThreatProviderResult['status'] =
      badTags.length > 0 ? 'flagged' : !isSharedCloudTag && vulns.length > 5 ? 'suspicious' : 'clean';

    const result: ThreatProviderResult = {
      providerId: 'shodan_internetdb',
      providerName: 'Shodan InternetDB (Open IP & CVE)',
      category: 'IP Ports, CVEs & Threat Tags',
      enabled: true,
      configured: true,
      operationalState: 'active',
      status,
      inspectedTargets: [`IP: ${primaryIp}`],
      matchScope: badTags.length > 0 || (!isSharedCloudTag && vulns.length > 5) ? 'ip_address' : 'none',
      dataSource: 'https://internetdb.shodan.io/',
      lastAnalyzedAt: now,
      verdictDetail: {
        en:
          badTags.length > 0
            ? `IP flagged in Shodan tags: ${badTags.join(', ')} (${ports.length} ports, ${vulns.length} CVEs)`
            : `${ports.length} open port(s) [${ports.slice(0, 6).join(', ') || 'none'}], ${vulns.length} CVE(s), tags: [${tags.join(', ') || 'none'}]`,
        ar:
          badTags.length > 0
            ? `عنوان IP موسوم بتهديد في Shodan: ${badTags.join('، ')} (${ports.length} منفذ، ${vulns.length} ثغرة)`
            : `${ports.length} منفذ مفتوح، ${vulns.length} ثغرة CVE مسجلة، الوسوم: [${tags.join('، ') || 'لا يوجد'}]`,
      },
      latencyMs: Date.now() - start,
      lastSuccessfulLookup: now,
      referenceUrl: `https://www.shodan.io/host/${encodeURIComponent(primaryIp)}`,
      requiresKey: false,
    };
    setCached(cacheKey, result, 15 * 60 * 1000);
    return result;
  } catch (err) {
    return {
      providerId: 'shodan_internetdb',
      providerName: 'Shodan InternetDB (Open IP & CVE)',
      category: 'IP Ports, CVEs & Threat Tags',
      enabled: true,
      configured: true,
      operationalState: 'unavailable',
      status: 'error',
      verdictDetail: { en: (err as Error).message, ar: (err as Error).message },
      latencyMs: Date.now() - start,
      requiresKey: false,
    };
  }
}

async function checkFeodoTracker(primaryIp?: string): Promise<ThreatProviderResult> {
  if (!primaryIp) {
    return {
      providerId: 'feodotracker',
      providerName: 'Feodo Tracker C2 (abuse.ch)',
      category: 'Botnet Command & Control IPs',
      enabled: true,
      configured: true,
      operationalState: 'unavailable',
      status: 'unknown',
      verdictDetail: { en: 'No IP address resolved for Feodo C2 check', ar: 'لا يوجد عنوان IP لفحص قائمة Feodo C2' },
      requiresKey: false,
    };
  }
  const start = Date.now();
  try {
    if (!feodoIpSetCache || Date.now() > feodoIpSetCache.expiresAt) {
      const res = await fetchWithRetry(
        'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json',
        { method: 'GET', headers: { Accept: 'application/json' } },
        6000,
        0
      );
      if (!res.ok) {
        return {
          providerId: 'feodotracker',
          providerName: 'Feodo Tracker C2 (abuse.ch)',
          category: 'Botnet Command & Control IPs',
          enabled: true,
          configured: true,
          operationalState: 'unavailable',
          status: 'unavailable',
          verdictDetail: { en: `Feodo Tracker HTTP ${res.status}`, ar: `استجابة Feodo Tracker رمز ${res.status}` },
          latencyMs: Date.now() - start,
          requiresKey: false,
        };
      }
      const list = await res.json();
      const ips = new Map<string, string>();
      if (Array.isArray(list)) {
        for (const row of list) {
          if (row?.ip_address) {
            ips.set(String(row.ip_address).trim(), String(row.malware || 'Botnet C2'));
          }
        }
      }
      feodoIpSetCache = { ips, expiresAt: Date.now() + 30 * 60 * 1000 };
    }

    const now = new Date().toISOString();
    lastSuccessMap.set('feodotracker', now);
    const hitMalware = feodoIpSetCache.ips.get(primaryIp);

    return {
      providerId: 'feodotracker',
      providerName: 'Feodo Tracker C2 (abuse.ch)',
      category: 'Botnet Command & Control IPs',
      enabled: true,
      configured: true,
      operationalState: 'active',
      status: hitMalware ? 'flagged' : 'clean',
      inspectedTargets: [`IP: ${primaryIp}`],
      matchScope: hitMalware ? 'ip_address' : 'none',
      dataSource: 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json',
      lastAnalyzedAt: now,
      verdictDetail: hitMalware
        ? {
            en: `IP ${primaryIp} is an active Botnet C2 server (${hitMalware}) in Feodo Tracker`,
            ar: `عنوان IP (${primaryIp}) مدرج كخادم تحكم بوت نت نشط (${hitMalware}) في Feodo Tracker`,
          }
        : {
            en: `Not listed in active Feodo Tracker Botnet C2 blocklist (${feodoIpSetCache.ips.size} active C2 IPs)`,
            ar: `غير مدرج في قائمة Feodo Tracker لخوادم التحكم الخبيثة (${feodoIpSetCache.ips.size} خادم نشط)`,
          },
      latencyMs: Date.now() - start,
      lastSuccessfulLookup: now,
      cached: true,
      referenceUrl: 'https://feodotracker.abuse.ch/browse/',
      requiresKey: false,
    };
  } catch (err) {
    return {
      providerId: 'feodotracker',
      providerName: 'Feodo Tracker C2 (abuse.ch)',
      category: 'Botnet Command & Control IPs',
      enabled: true,
      configured: true,
      operationalState: 'unavailable',
      status: 'error',
      verdictDetail: { en: (err as Error).message, ar: (err as Error).message },
      latencyMs: Date.now() - start,
      requiresKey: false,
    };
  }
}

async function checkCloudflareSecurityDns(
  hostname: string,
  isOfficialPlatform = false
): Promise<ThreatProviderResult> {
  const cleanHost = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!cleanHost || net.isIP(cleanHost) !== 0) {
    return {
      providerId: 'cloudflare_security_dns',
      providerName: 'Cloudflare Security DNS (1.1.1.2)',
      category: 'Malware & Phishing DNS Sinkhole',
      enabled: true,
      configured: true,
      operationalState: 'active',
      status: 'unknown',
      verdictDetail: {
        en: 'Direct IP target skipped by hostname-based Cloudflare Security DNS filter',
        ar: 'تم تجاوز فحص فلتر النطاقات لكون الهدف عنوان IP مباشر',
      },
      requiresKey: false,
    };
  }

  const cacheKey = `cfsec:${cleanHost}:${isOfficialPlatform}`;
  const cached = getCached<ThreatProviderResult>(cacheKey);
  if (cached) return { ...cached, cached: true };

  const start = Date.now();
  try {
    const res = await fetchWithRetry(
      `https://security.cloudflare-dns.com/dns-query?name=${encodeURIComponent(cleanHost)}&type=A`,
      { method: 'GET', headers: { Accept: 'application/dns-json' } },
      4500,
      0
    );
    if (!res.ok) {
      return {
        providerId: 'cloudflare_security_dns',
        providerName: 'Cloudflare Security DNS (1.1.1.2)',
        category: 'Malware & Phishing DNS Sinkhole',
        enabled: true,
        configured: true,
        operationalState: 'unavailable',
        status: 'unavailable',
        verdictDetail: {
          en: `Cloudflare Security DNS HTTP ${res.status}`,
          ar: `استجابة Cloudflare Security DNS رمز ${res.status}`,
        },
        latencyMs: Date.now() - start,
        requiresKey: false,
      };
    }

    const json = await res.json();
    const now = new Date().toISOString();
    lastSuccessMap.set('cloudflare_security_dns', now);

    const answers: any[] = Array.isArray(json?.Answer) ? json.Answer : [];
    const comments: string[] = Array.isArray(json?.Comment) ? json.Comment.map(String) : [];
    const sinkholed = answers.some((a) => a?.data === '0.0.0.0' || a?.data === '::');
    const blockedComment = comments.some((c) => /blocked|malware|phishing|EDE/i.test(c));
    const isBlocked = !isOfficialPlatform && (sinkholed || blockedComment);

    const result: ThreatProviderResult = {
      providerId: 'cloudflare_security_dns',
      providerName: 'Cloudflare Security DNS (1.1.1.2)',
      category: 'Malware & Phishing DNS Sinkhole',
      enabled: true,
      configured: true,
      operationalState: 'active',
      status: isBlocked ? 'flagged' : 'clean',
      inspectedTargets: [`Host: ${cleanHost}`],
      matchScope: isBlocked ? 'hostname' : 'none',
      dataSource: 'https://security.cloudflare-dns.com/dns-query',
      lastAnalyzedAt: now,
      verdictDetail: isBlocked
        ? {
            en: `Hostname "${cleanHost}" was sinkholed (0.0.0.0) by Cloudflare 1.1.1.2 Malware & Phishing filter`,
            ar: `حظر مرشح Cloudflare الأمني (1.1.1.2) النطاق "${cleanHost}" كبرمجية خبيثة أو تصيد`,
          }
        : {
            en: `Not sinkholed by Cloudflare 1.1.1.2 Malware & Phishing DNS resolver (${answers.length} record(s))`,
            ar: `غير محجوب في مرشح Cloudflare الأمني (1.1.1.2) للبرمجيات الخبيثة والتصيد`,
          },
      latencyMs: Date.now() - start,
      lastSuccessfulLookup: now,
      referenceUrl: 'https://radar.cloudflare.com/',
      requiresKey: false,
    };
    setCached(cacheKey, result, 15 * 60 * 1000);
    return result;
  } catch (err) {
    return {
      providerId: 'cloudflare_security_dns',
      providerName: 'Cloudflare Security DNS (1.1.1.2)',
      category: 'Malware & Phishing DNS Sinkhole',
      enabled: true,
      configured: true,
      operationalState: 'unavailable',
      status: 'error',
      verdictDetail: { en: (err as Error).message, ar: (err as Error).message },
      latencyMs: Date.now() - start,
      requiresKey: false,
    };
  }
}

async function checkPhishStats(
  targetUrl: string,
  hostname: string,
  isOfficialPlatform = false
): Promise<ThreatProviderResult> {
  const cleanHost = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  const cacheKey = `phishstats:${targetUrl}:${cleanHost}:${isOfficialPlatform}`;
  const cached = getCached<ThreatProviderResult>(cacheKey);
  if (cached) return { ...cached, cached: true };

  const start = Date.now();
  try {
    const whereClause = isOfficialPlatform
      ? `(url,eq,${targetUrl})`
      : `(url,eq,${targetUrl})~or(domain,eq,${cleanHost})`;
    const res = await fetchWithRetry(
      `https://api.phishstats.info/api/phishing?_where=${encodeURIComponent(whereClause)}&_size=3`,
      { method: 'GET', headers: { Accept: 'application/json' } },
      4500,
      0
    );
    if (!res.ok) {
      const rl = res.status === 429;
      return {
        providerId: 'phishstats',
        providerName: 'PhishStats Public API',
        category: 'Live Phishing Intelligence',
        enabled: true,
        configured: true,
        operationalState: rl ? 'rate_limited' : 'unavailable',
        status: rl ? 'rate_limited' : 'unavailable',
        verdictDetail: {
          en: `PhishStats HTTP ${res.status}`,
          ar: `استجابة PhishStats رمز ${res.status}`,
        },
        latencyMs: Date.now() - start,
        requiresKey: false,
      };
    }

    const rows = await res.json();
    const now = new Date().toISOString();
    lastSuccessMap.set('phishstats', now);
    const list = Array.isArray(rows) ? rows : [];
    const maxScore = list.reduce((m, r) => Math.max(m, Number(r?.score || 0)), 0);
    const hitCount = list.length;

    const status: ThreatProviderResult['status'] =
      hitCount > 0 && (maxScore >= 5 || list.some((r) => String(r?.url || '').toLowerCase() === targetUrl.toLowerCase()))
        ? 'flagged'
        : hitCount > 0
          ? 'suspicious'
          : 'clean';

    const result: ThreatProviderResult = {
      providerId: 'phishstats',
      providerName: 'PhishStats Public API',
      category: 'Live Phishing Intelligence',
      enabled: true,
      configured: true,
      operationalState: 'active',
      status,
      inspectedTargets: [`URL: ${targetUrl}`, `Host: ${cleanHost}`],
      matchScope:
        hitCount > 0
          ? list.some((r) => String(r?.url || '').toLowerCase() === targetUrl.toLowerCase())
            ? 'exact_url'
            : 'hostname'
          : 'none',
      dataSource: 'https://api.phishstats.info/api/phishing',
      lastAnalyzedAt: list[0]?.date || now,
      verdictDetail:
        hitCount > 0
          ? {
              en: `${hitCount} PhishStats phishing record(s) matched (max score ${maxScore}/10)`,
              ar: `تطابق مع ${hitCount} بلاغ تصيد في PhishStats (أعلى درجة ${maxScore}/10)`,
            }
          : {
              en: '0 matching phishing records in PhishStats live database',
              ar: '0 سجلات تصيد مطابقة في قاعدة بيانات PhishStats المباشرة',
            },
      latencyMs: Date.now() - start,
      lastSuccessfulLookup: now,
      referenceUrl: 'https://phishstats.info/',
      requiresKey: false,
    };
    setCached(cacheKey, result, 15 * 60 * 1000);
    return result;
  } catch (err) {
    return {
      providerId: 'phishstats',
      providerName: 'PhishStats Public API',
      category: 'Live Phishing Intelligence',
      enabled: true,
      configured: true,
      operationalState: 'unavailable',
      status: 'error',
      verdictDetail: { en: (err as Error).message, ar: (err as Error).message },
      latencyMs: Date.now() - start,
      requiresKey: false,
    };
  }
}

export async function runExternalThreatIntel(
  targetUrl: string,
  hostname: string,
  registrableDomain: string,
  disabledProviders: string[] = [],
  primaryIp?: string,
  isCdnEdge = false
): Promise<{ providers: ThreatProviderResult[]; findings: CheckFinding[] }> {
  const now = new Date().toISOString();
  const disabled = new Set(disabledProviders);
  const ownership = lookupDomainOwnership(hostname);
  const isOfficialPlatform = Boolean(ownership.matched);

  const disabledResult = (
    providerId: string,
    providerName: string,
    category: string,
    requiresKey: boolean,
    configured: boolean
  ): ThreatProviderResult => ({
    providerId,
    providerName,
    category,
    enabled: false,
    configured,
    operationalState: 'disabled',
    status: 'disabled',
    verdictDetail: { en: 'Disabled by user scan configuration', ar: 'معطل حسب إعدادات الفحص المحددة' },
    requiresKey,
  });

  const isSharedOrOfficial = Boolean(ownership.matched || ownership.isUserContentPaas || isCdnEdge);

  const tasks: Promise<ThreatProviderResult>[] = [
    disabled.has('virustotal')
      ? Promise.resolve(
          disabledResult(
            'virustotal',
            'VirusTotal API v3',
            'Multi-Engine Reputation (URL / Domain / IP)',
            true,
            Boolean(process.env.VIRUSTOTAL_API_KEY)
          )
        )
      : checkVirusTotal(targetUrl, registrableDomain, primaryIp, isSharedOrOfficial),
    disabled.has('urlhaus')
      ? Promise.resolve(
          disabledResult(
            'urlhaus',
            'URLhaus (abuse.ch)',
            'Malware URLs & Hosts',
            true,
            Boolean(process.env.URLHAUS_AUTH_KEY)
          )
        )
      : checkUrlhaus(targetUrl, hostname, isOfficialPlatform),
    disabled.has('openphish')
      ? Promise.resolve(disabledResult('openphish', 'OpenPhish Community Feed', 'Phishing Feed', false, true))
      : checkOpenPhish(targetUrl, hostname),
    disabled.has('cloudflare_security_dns')
      ? Promise.resolve(
          disabledResult(
            'cloudflare_security_dns',
            'Cloudflare Security DNS (1.1.1.2)',
            'Malware & Phishing DNS Sinkhole',
            false,
            true
          )
        )
      : checkCloudflareSecurityDns(hostname, isOfficialPlatform),
    disabled.has('phishstats')
      ? Promise.resolve(
          disabledResult('phishstats', 'PhishStats Public API', 'Live Phishing Intelligence', false, true)
        )
      : checkPhishStats(targetUrl, hostname, isOfficialPlatform),
    disabled.has('otx')
      ? Promise.resolve(
          disabledResult('otx', 'AlienVault OTX', 'Threat Intelligence (Domain & IP)', false, true)
        )
      : checkAlienVaultOtx(registrableDomain, primaryIp, isOfficialPlatform),
    disabled.has('urlscan')
      ? Promise.resolve(
          disabledResult('urlscan', 'URLScan.io Public Search', 'Website Intelligence', false, true)
        )
      : checkUrlScanSearch(targetUrl, registrableDomain, isOfficialPlatform),
    disabled.has('shodan_internetdb')
      ? Promise.resolve(
          disabledResult('shodan_internetdb', 'Shodan InternetDB (Open IP & CVE)', 'IP Ports, CVEs & Threat Tags', false, true)
        )
      : checkShodanInternetDb(primaryIp, isCdnEdge || isOfficialPlatform),
    disabled.has('feodotracker')
      ? Promise.resolve(
          disabledResult('feodotracker', 'Feodo Tracker C2 (abuse.ch)', 'Botnet Command & Control IPs', false, true)
        )
      : checkFeodoTracker(primaryIp),
  ];

  const providers = await Promise.all(tasks);
  const findings: CheckFinding[] = [];

  for (const p of providers) {
    const status =
      p.status === 'flagged'
        ? 'failed'
        : p.status === 'suspicious'
          ? 'warning'
          : p.status === 'clean'
            ? 'pass'
            : 'unknown';

    findings.push({
      id: `intel-${p.providerId}`,
      section: 'external_threat_intel',
      test: { en: p.providerName, ar: p.providerName },
      result: p.verdictDetail,
      status,
      severity:
        p.status === 'flagged'
          ? 'critical'
          : p.status === 'suspicious'
            ? 'low'
            : p.status === 'clean'
              ? 'informational'
              : 'unknown',
      weight: p.status === 'flagged' ? 40 : p.status === 'suspicious' ? 8 : 0,
      evidence: `Provider: ${p.providerName} | State: ${p.operationalState} | Status: ${p.status} | MatchScope: ${p.matchScope || 'none'} | DataSource: ${p.dataSource || p.providerName} | Targets: [${p.inspectedTargets?.join(', ') || 'URL/Domain'}] | LastAnalyzed: ${p.lastAnalyzedAt ?? 'N/A'}`,
      explanation: {
        en:
          p.status === 'flagged'
            ? `External threat intelligence provider ${p.providerName} actively flagged this URL/domain/IP for malicious or phishing activity.`
            : p.status === 'suspicious'
              ? `${p.providerName} reported historical or low-threshold suspicious hits across the domain or shared hosting IP.`
              : p.status === 'clean'
                ? `No malicious listing found in ${p.providerName} at scan time. Absence of a listing does not prove a new page is safe.`
                : `Provider ${p.providerName} did not return a definitive listing (${p.status}). Unknown or unavailable feeds never count as clean.`,
        ar:
          p.status === 'flagged'
            ? `أبلغ مزود استخبارات التهديدات (${p.providerName}) عن نشاط خبيث أو تصيدي مرتبط بهذا الرابط أو النطاق.`
            : p.status === 'suspicious'
              ? `رصد ${p.providerName} مؤشرات اشتباه أو سجلات تاريخية على النطاق أو عنوان الخادم.`
              : p.status === 'clean'
                ? `لم يتم رصد بلاغات مسجلة لدى ${p.providerName} وقت الفحص. غياب البلاغ لا يثبت أمان الصفحات المستحدثة.`
                : `لم يُرجع ${p.providerName} نتيجة قاطعة (${p.status}). المزود غير المتاح أو غير المهيأ لا يُحتسب أبداً كفحص سليم.`,
      },
      recommendedAction:
        p.status === 'flagged'
          ? {
              en: 'Block access immediately and treat this link as confirmed malicious.',
              ar: 'احظر الوصول فوراً وتعامل مع هذا الرابط كتهديد مؤكد.',
            }
          : p.status === 'clean'
            ? {
                en: 'Correlate with local structural, deception, TLS, and page-content checks.',
                ar: 'قارن النتيجة مع فحوصات بنية الرابط وخداع النطاق والمحتوى المحلي.',
              }
            : {
                en: 'Do not assume safety from unindexed or unavailable threat feeds; inspect local behavioral findings.',
                ar: 'لا تفترض الأمان لعدم وجود سجل في المزود؛ راجع نتائج الفحص المحلي.',
              },
      source: p.providerName,
      timestamp: now,
      confidence: p.status === 'flagged' || p.status === 'clean' ? 92 : p.status === 'suspicious' ? 75 : 20,
      errorState: p.status !== 'clean' && p.status !== 'flagged' ? p.verdictDetail.en : undefined,
    });
  }

  return { providers, findings };
}
