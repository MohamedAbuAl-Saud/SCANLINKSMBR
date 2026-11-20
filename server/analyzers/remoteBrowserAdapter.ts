import {
  BilingualText,
  LevelBExecutionData,
  LevelBNetworkChannelCategory,
  LevelBNetworkRequestItem,
  LevelBPermissionEventItem,
} from '../types.ts';
import { validateTargetAgainstSsrf } from '../security/ssrfGuard.ts';

export type ScreenshotViewport = LevelBExecutionData['screenshot']['viewport'];

export interface LevelBExecutionOptions {
  viewport?: ScreenshotViewport;
  disabled?: boolean;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  ssrfValidator?: (url: string) => Promise<unknown>;
}

const DEFAULT_TIMEOUT_MS = 20000;
const MAX_NETWORK_REQUESTS = 120;
const MAX_PERMISSION_EVENTS = 60;

const PROVIDER_LABEL: BilingualText = {
  en: 'External Cloud Browser Service',
  ar: 'خدمة متصفح خارجي سحابي',
};

const PROFILING_HOSTS = [
  'ipapi.co',
  'ipinfo.io',
  'api.ipify.org',
  'ipwho.is',
  'ifconfig.me',
  'ip-api.com',
  'extreme-ip-lookup.com',
  'geoip-db.com',
];

const KNOWN_ANALYTICS_HOSTS = [
  'www.google-analytics.com',
  'analytics.google.com',
  'www.googletagmanager.com',
  'stats.g.doubleclick.net',
  'connect.facebook.net',
  'plausible.io',
  'cdn.segment.com',
  'api.amplitude.com',
  'cdn.jsdelivr.net',
  'cdnjs.cloudflare.com',
  'fonts.googleapis.com',
  'fonts.gstatic.com',
  'unpkg.com',
];

export function classifyNetworkChannel(
  targetUrl: string,
  pageHost: string,
  method = 'GET',
): {
  category: LevelBNetworkChannelCategory;
  isSensitiveSink: boolean;
  isThirdParty: boolean;
  domain: string;
  path: string;
  note: BilingualText;
} {
  let domain = '';
  let path = '/';
  try {
    const parsed = new URL(targetUrl);
    domain = parsed.hostname.toLowerCase();
    path = parsed.pathname + (parsed.search ? parsed.search.slice(0, 64) : '');
  } catch {
    domain = 'unknown';
    path = targetUrl.slice(0, 80);
  }

  const normalizedPageHost = pageHost.toLowerCase();
  const isSameHost =
    Boolean(domain) &&
    (domain === normalizedPageHost ||
      domain.endsWith(`.${normalizedPageHost}`) ||
      normalizedPageHost.endsWith(`.${domain}`));

  const lowerFull = `${domain}${path}`.toLowerCase();
  const upperMethod = (method || 'GET').toUpperCase();

  if (
    domain.includes('api.telegram.org') ||
    /\/bot\d{5,}:/i.test(targetUrl) ||
    /\/(sendmessage|sendphoto|senddocument|sendvideo|sendaudio|sendvoice)\b/i.test(lowerFull)
  ) {
    return {
      category: 'HIGH_RISK_EXFILTRATION_CHANNEL',
      isSensitiveSink: true,
      isThirdParty: !isSameHost,
      domain,
      path: redactSensitiveSegments(path),
      note: {
        en: 'High-risk messaging bot API exfiltration channel (Telegram Bot API / automated relay).',
        ar: 'قناة تسريب عالية الخطورة عبر واجهة بوت مراسلة (Telegram Bot API / ترحيل آلي).',
      },
    };
  }

  if (
    /discord(?:app)?\.com\/api\/webhooks\//i.test(lowerFull) ||
    /hooks\.slack\.com\/services\//i.test(lowerFull) ||
    /webhook\.site\//i.test(lowerFull) ||
    /pipedream\.net/i.test(domain) ||
    /requestbin/i.test(domain) ||
    (!isSameHost && /(?:\/webhooks?|\/collect|\/exfil|\/capture|\/logs?)(?:$|[/?#])/i.test(lowerFull) && upperMethod === 'POST')
  ) {
    return {
      category: 'WEBHOOK_OR_BOT_SINK',
      isSensitiveSink: true,
      isThirdParty: !isSameHost,
      domain,
      path: redactSensitiveSegments(path),
      note: {
        en: 'External webhook or automated data-collection sink detected during runtime.',
        ar: 'نقطة استقبال Webhook خارجية أو قناة جمع بيانات آلية تم رصدها أثناء التشغيل.',
      },
    };
  }

  if (PROFILING_HOSTS.some((h) => domain === h || domain.endsWith(`.${h}`))) {
    return {
      category: 'IP_AND_DEVICE_PROFILING',
      isSensitiveSink: true,
      isThirdParty: !isSameHost,
      domain,
      path: redactSensitiveSegments(path),
      note: {
        en: 'External IP / geolocation profiling lookup endpoint.',
        ar: 'نقطة استعلام خارجية لتحديد عنوان IP والموقع الجغرافي وبصمة الجهاز.',
      },
    };
  }

  if (isSameHost || KNOWN_ANALYTICS_HOSTS.some((h) => domain === h || domain.endsWith(`.${h}`))) {
    return {
      category: 'FIRST_PARTY_OR_KNOWN',
      isSensitiveSink: false,
      isThirdParty: !isSameHost,
      domain,
      path: redactSensitiveSegments(path),
      note: isSameHost
        ? {
            en: 'First-party or same-origin resource request.',
            ar: 'طلب لمورد من نفس النطاق أو نفس الجهة.',
          }
        : {
            en: 'Known CDN, font, or standard analytics endpoint.',
            ar: 'نقطة CDN أو خطوط أو تحليلات قياسية معروفة.',
          },
    };
  }

  return {
    category: 'UNVERIFIED_EXTERNAL',
    isSensitiveSink: upperMethod === 'POST' || upperMethod === 'PUT',
    isThirdParty: true,
    domain,
    path: redactSensitiveSegments(path),
    note: {
      en: 'Unverified third-party external endpoint; payload purpose cannot be assumed benign without verification.',
      ar: 'نقطة اتصال خارجية غير موثقة؛ لا يمكن افتراض سلامة الغرض من الإرسال دون تحقق.',
    },
  };
}

function redactSensitiveSegments(raw: string): string {
  return raw
    .replace(/(bot\d{5,}:)[A-Za-z0-9_-]{12,}/gi, '$1***REDACTED***')
    .replace(/([?&](?:token|key|apikey|api_key|secret|auth|password)=)[^&]+/gi, '$1***');
}

function sanitizeErrorReason(
  rawMessage: string,
  secretValues: string[],
): BilingualText {
  let clean = rawMessage || 'Remote execution unavailable.';
  for (const s of secretValues) {
    if (s && s.length >= 4) {
      clean = clean.split(s).join('[REDACTED]');
    }
  }
  clean = clean.replace(/https?:\/\/[^\s]+/gi, '[EXTERNAL_ENDPOINT]');

  if (/timeout|aborted/i.test(clean)) {
    return {
      en: 'External Cloud Browser Service timed out before completing dynamic runtime observation.',
      ar: 'انتهت مهلة خدمة المتصفح السحابي الخارجي قبل إكمال المراقبة الديناميكية وقت التشغيل.',
    };
  }
  if (/401|403|unauthorized|forbidden/i.test(clean)) {
    return {
      en: 'External Cloud Browser Service rejected credentials configured in server environment.',
      ar: 'رفضت خدمة المتصفح السحابي الخارجي بيانات الاعتماد المضبوطة في بيئة الخادم.',
    };
  }
  return {
    en: 'External Cloud Browser Service encountered a network or execution error and did not return runtime telemetry.',
    ar: 'واجهت خدمة المتصفح السحابي الخارجي خطأ في الشبكة أو التنفيذ ولم تُعد بيانات تشغيل ديناميكية.',
  };
}

function buildRuntimeObserverScript(targetUrl: string, viewport: ScreenshotViewport): string {
  const width = viewport === 'mobile' ? 390 : 1280;
  const height = viewport === 'mobile' ? 844 : 720;
  const fullPage = viewport === 'full_page';

  return `
export default async function ({ page }) {
  const startedAt = Date.now();
  const networkRequests = [];
  const permissionEvents = [];
  const redirects = [];

  await page.setViewport({ width: ${width}, height: ${height} });

  await page.evaluateOnNewDocument(() => {
    const events = [];
    window.__scanLinkLevelBEvents = events;

    const record = (kind, api, trigger, detail) => {
      events.push({ kind, api, trigger, outcome: 'attempted', detail });
    };

    if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
      const orig = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
      navigator.mediaDevices.getUserMedia = function (constraints) {
        const hasVideo = Boolean(constraints && constraints.video);
        const hasAudio = Boolean(constraints && constraints.audio);
        record(hasVideo ? 'camera' : 'microphone', 'navigator.mediaDevices.getUserMedia', 'on_load',
          hasVideo && hasAudio ? 'Camera and microphone access requested' : hasVideo ? 'Camera access requested' : 'Microphone access requested');
        return orig(constraints).catch(() => Promise.reject(new DOMException('Permission blocked in sandbox', 'NotAllowedError')));
      };
    }

    if (navigator.geolocation) {
      const origGet = navigator.geolocation.getCurrentPosition.bind(navigator.geolocation);
      navigator.geolocation.getCurrentPosition = function () {
        record('geolocation', 'navigator.geolocation.getCurrentPosition', 'on_load', 'Geolocation coordinate access attempted');
        return origGet.apply(this, arguments);
      };
    }

    if (navigator.clipboard && navigator.clipboard.readText) {
      const origRead = navigator.clipboard.readText.bind(navigator.clipboard);
      navigator.clipboard.readText = function () {
        record('clipboard', 'navigator.clipboard.readText', 'on_load', 'Clipboard read attempted');
        return origRead().catch(() => '');
      };
    }

    if (typeof Notification !== 'undefined' && Notification.requestPermission) {
      const origNotif = Notification.requestPermission.bind(Notification);
      Notification.requestPermission = function () {
        record('notifications', 'Notification.requestPermission', 'on_load', 'Notification permission prompt attempted');
        return origNotif().catch(() => 'denied');
      };
    }
  });

  page.on('request', (req) => {
    if (networkRequests.length < ${MAX_NETWORK_REQUESTS}) {
      networkRequests.push({
        url: req.url(),
        method: req.method(),
        resourceType: req.resourceType(),
      });
    }
  });

  page.on('response', (res) => {
    const status = res.status();
    if (status >= 300 && status < 400) {
      redirects.push({ step: redirects.length + 1, url: res.url(), statusCode: status });
    }
  });

  await page.goto(${JSON.stringify(targetUrl)}, { waitUntil: 'networkidle2', timeout: 15000 }).catch(() => null);
  await new Promise((r) => setTimeout(r, 1500));

  const runtimeData = await page.evaluate(() => {
    const events = Array.isArray(window.__scanLinkLevelBEvents) ? window.__scanLinkLevelBEvents : [];
    const forms = document.querySelectorAll('form');
    const sensitiveInputs = document.querySelectorAll('input[type="password"], input[type="email"], input[name*="card" i], input[name*="otp" i], input[name*="pin" i]');
    const iframes = document.querySelectorAll('iframe');
    const scripts = document.querySelectorAll('script');
    const text = (document.body && document.body.innerText) ? document.body.innerText : '';
    const words = text.trim() ? text.trim().split(/\\s+/).length : 0;
    return {
      title: document.title || '',
      events,
      domSummary: {
        title: document.title || '',
        dynamicFormCount: forms.length,
        sensitiveInputCount: sensitiveInputs.length,
        dynamicIframeCount: iframes.length,
        dynamicScriptCount: scripts.length,
        wordCount: words,
        notableElements: Array.from(document.querySelectorAll('button, input[type="submit"]'))
          .slice(0, 8)
          .map((el) => (el.textContent || el.getAttribute('value') || '').trim())
          .filter(Boolean),
      },
    };
  }).catch(() => ({ title: '', events: [], domSummary: { title: '', dynamicFormCount: 0, sensitiveInputCount: 0, dynamicIframeCount: 0, dynamicScriptCount: 0, wordCount: 0, notableElements: [] } }));

  const screenshotBase64 = await page.screenshot({ encoding: 'base64', type: 'png', fullPage: ${fullPage} }).catch(() => null);

  return {
    data: {
      finalUrl: page.url(),
      durationMs: Date.now() - startedAt,
      redirects,
      networkRequests,
      permissionEvents: runtimeData.events,
      domSummary: runtimeData.domSummary,
      screenshotBase64,
      viewport: ${JSON.stringify(viewport)},
      width: ${width},
      height: ${height},
    },
  };
}`.trim();
}

export async function executeLevelBCloudBrowser(
  targetUrl: string,
  options: LevelBExecutionOptions = {},
): Promise<LevelBExecutionData> {
  const viewport: ScreenshotViewport = options.viewport || 'desktop';
  const fetchFn = options.fetchImpl || fetch;

  if (options.disabled) {
    return {
      status: 'disabled',
      executionMode: 'unavailable',
      providerLabel: PROVIDER_LABEL,
      redirects: [],
      screenshot: {
        captured: false,
        viewport,
        missingReason: {
          en: 'Level B dynamic cloud browser execution was paused for this scan.',
          ar: 'تم إيقاف تنفيذ المتصفح السحابي الديناميكي (Level B) لهذا الفحص بناءً على اختيار المستخدم.',
        },
      },
      networkRequests: [],
      permissionEvents: [],
      confidenceImpact: -12,
      coverageImpact: -22,
      errorReason: {
        en: 'Disabled by user scan configuration.',
        ar: 'معطّل من إعدادات الفحص.',
      },
      executiveSummary: {
        en: 'Level B runtime observation was disabled for this scan; assessment relies strictly on Level A static and external intelligence.',
        ar: 'تم تعطيل المراقبة الديناميكية (Level B) لهذا الفحص؛ يعتمد الحكم حصراً على التحليل الثابت (Level A) ومصادر التهديد.',
      },
    };
  }

  const endpoint = (process.env.CLOUD_BROWSER_ENDPOINT || '').trim();
  const apiKey = (process.env.CLOUD_BROWSER_API_KEY || '').trim();
  const configuredTimeout = Number(process.env.CLOUD_BROWSER_TIMEOUT_MS || options.timeoutMs || DEFAULT_TIMEOUT_MS);
  const timeoutMs = Number.isFinite(configuredTimeout) && configuredTimeout >= 3000
    ? Math.min(configuredTimeout, 45000)
    : DEFAULT_TIMEOUT_MS;

  if (!endpoint || !apiKey) {
    return {
      status: 'unavailable',
      executionMode: 'unavailable',
      providerLabel: PROVIDER_LABEL,
      redirects: [],
      screenshot: {
        captured: false,
        viewport,
        missingReason: {
          en: 'External Cloud Browser Service credentials are not configured on the server; no runtime screenshot could be captured.',
          ar: 'بيانات اعتماد خدمة المتصفح السحابي الخارجي غير مضبوطة على الخادم؛ لم يتسنَّ التقاط لقطة شاشة وقت التشغيل.',
        },
      },
      networkRequests: [],
      permissionEvents: [],
      confidenceImpact: -12,
      coverageImpact: -22,
      errorReason: {
        en: 'External Cloud Browser Service is not configured in server environment settings.',
        ar: 'خدمة المتصفح السحابي الخارجي غير مفعّلة في إعدادات بيئة الخادم (.env).',
      },
      executiveSummary: {
        en: 'Level B was not executed because External Cloud Browser Service settings are absent in server environment variables. Only confidence and inspection coverage are reduced; no unverified runtime behavior is assumed.',
        ar: 'لم يُنفَّذ فحص Level B لعدم توفر إعدادات خدمة المتصفح السحابي الخارجي في متغيرات بيئة الخادم. تم خصم التأثير من نسبة الثقة والتغطية فقط دون افتراض أي سلوك غير مرصود.',
      },
    };
  }

  let parsedEndpoint: URL;
  try {
    parsedEndpoint = new URL(endpoint);
    if (parsedEndpoint.protocol !== 'https:' && parsedEndpoint.protocol !== 'http:') {
      throw new Error('Invalid endpoint protocol');
    }
  } catch {
    return {
      status: 'failed',
      executionMode: 'unavailable',
      providerLabel: PROVIDER_LABEL,
      redirects: [],
      screenshot: {
        captured: false,
        viewport,
        missingReason: {
          en: 'Configured external cloud browser endpoint format is invalid.',
          ar: 'تنسيق نقطة اتصال خدمة المتصفح السحابي الخارجي غير صالح.',
        },
      },
      networkRequests: [],
      permissionEvents: [],
      confidenceImpact: -15,
      coverageImpact: -22,
      errorReason: {
        en: 'Invalid cloud browser service endpoint configuration.',
        ar: 'إعداد نقطة اتصال خدمة المتصفح السحابي غير صالح.',
      },
      executiveSummary: {
        en: 'Level B execution failed due to invalid server endpoint configuration; confidence and coverage were adjusted without penalizing target risk.',
        ar: 'تعذّر تنفيذ Level B بسبب عدم صلاحية إعداد نقطة الاتصال على الخادم؛ تم تعديل الثقة والتغطية فقط دون رفع درجة خطورة الرابط.',
      },
    };
  }

  const ssrfValidatorFn = options.ssrfValidator || validateTargetAgainstSsrf;
  try {
    await ssrfValidatorFn(targetUrl);
  } catch (ssrfErr: any) {
    const ssrfReason = typeof ssrfErr?.message === 'string' && ssrfErr.message
      ? ssrfErr.message
      : 'Target failed private-network SSRF validation.';
    return {
      status: 'blocked_by_ssrf',
      executionMode: 'unavailable',
      providerLabel: PROVIDER_LABEL,
      redirects: [],
      screenshot: {
        captured: false,
        viewport,
        missingReason: {
          en: 'Blocked by SSRF security guard before dispatch to external cloud browser.',
          ar: 'تم الحظر بواسطة حماية SSRF قبل إرسال الرابط إلى خدمة المتصفح السحابي الخارجي.',
        },
      },
      networkRequests: [],
      permissionEvents: [],
      confidenceImpact: -10,
      coverageImpact: -18,
      errorReason: {
        en: ssrfReason,
        ar: 'فشل الرابط في التحقق الأمني ضد الشبكات الخاصة أو تعذر حل DNS (SSRF Guard).',
      },
      executiveSummary: {
        en: 'Target URL failed SSRF validation and was not forwarded to the external cloud browser service.',
        ar: 'فشل الرابط في فحص الحماية من الشبكات الخاصة ولم يُرسل إلى خدمة المتصفح السحابي الخارجي.',
      },
    };
  }

  const startedAt = Date.now();
  try {
    const scriptCode = buildRuntimeObserverScript(targetUrl, viewport);
    const response = await fetchFn(parsedEndpoint.toString(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
        'x-api-key': apiKey,
      },
      body: JSON.stringify({
        url: targetUrl,
        viewport,
        code: scriptCode,
        context: { url: targetUrl, viewport },
      }),
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const rawJson = (await response.json()) as Record<string, any>;
    const payload = (rawJson?.data && typeof rawJson.data === 'object' ? rawJson.data : rawJson) as Record<string, any>;

    const finalUrl = typeof payload.finalUrl === 'string' && payload.finalUrl ? payload.finalUrl : targetUrl;
    let finalHost = '';
    try {
      finalHost = new URL(finalUrl).hostname.toLowerCase();
    } catch {
      finalHost = '';
    }

    const rawRequests: any[] = Array.isArray(payload.networkRequests) ? payload.networkRequests : [];
    const networkRequests: LevelBNetworkRequestItem[] = rawRequests
      .slice(0, MAX_NETWORK_REQUESTS)
      .map((item) => {
        const reqUrl = String(item?.url || '');
        const reqMethod = String(item?.method || 'GET').toUpperCase();
        const classified = classifyNetworkChannel(reqUrl, finalHost, reqMethod);
        return {
          url: redactSensitiveSegments(reqUrl),
          domain: classified.domain,
          path: classified.path,
          method: reqMethod,
          resourceType: item?.resourceType ? String(item.resourceType) : undefined,
          channelCategory: classified.category,
          isSensitiveSink: classified.isSensitiveSink,
          isThirdParty: classified.isThirdParty,
          statusCode: typeof item?.statusCode === 'number' ? item.statusCode : undefined,
          note: classified.note,
        };
      });

    const rawEvents: any[] = Array.isArray(payload.permissionEvents) ? payload.permissionEvents : [];
    const permissionEvents: LevelBPermissionEventItem[] = rawEvents
      .slice(0, MAX_PERMISSION_EVENTS)
      .map((ev) => ({
        kind: (['camera', 'microphone', 'geolocation', 'clipboard', 'notifications', 'auto_timer', 'lure_interaction'].includes(
          String(ev?.kind),
        )
          ? String(ev.kind)
          : 'other') as LevelBPermissionEventItem['kind'],
        api: String(ev?.api || 'runtime_api'),
        trigger: (['on_load', 'timer', 'user_click'].includes(String(ev?.trigger))
          ? String(ev.trigger)
          : 'unknown') as LevelBPermissionEventItem['trigger'],
        outcome: (['attempted', 'granted', 'blocked', 'observed', 'not_triggered'].includes(String(ev?.outcome))
          ? String(ev.outcome)
          : 'observed') as LevelBPermissionEventItem['outcome'],
        detail:
          ev?.detail && typeof ev.detail === 'object' && ev.detail.en
            ? ev.detail
            : {
                en: String(ev?.detail || 'Runtime permission or behavior event observed.'),
                ar: String(ev?.detailAr || ev?.detail || 'تم رصد حدث صلاحية أو سلوك ديناميكي وقت التشغيل.'),
              },
      }));

    const rawRedirects: any[] = Array.isArray(payload.redirects) ? payload.redirects : [];
    const redirects = rawRedirects.slice(0, 20).map((r, idx) => ({
      step: typeof r?.step === 'number' ? r.step : idx + 1,
      url: redactSensitiveSegments(String(r?.url || '')),
      statusCode: typeof r?.statusCode === 'number' ? r.statusCode : undefined,
      note: r?.note ? String(r.note) : undefined,
    }));

    const rawDataUrl =
      typeof payload.screenshotDataUrl === 'string'
        ? payload.screenshotDataUrl
        : typeof payload.screenshotBase64 === 'string' && payload.screenshotBase64.length > 50
          ? payload.screenshotBase64.startsWith('data:image/')
            ? payload.screenshotBase64
            : `data:image/png;base64,${payload.screenshotBase64}`
          : undefined;

    const capturedAt = new Date().toISOString();
    const sensitiveCount = networkRequests.filter((r) => r.isSensitiveSink).length;
    const durationMs = typeof payload.durationMs === 'number' ? payload.durationMs : Date.now() - startedAt;

    return {
      status: 'executed',
      executionMode: 'external_cloud_browser',
      providerLabel: PROVIDER_LABEL,
      executedAt: capturedAt,
      durationMs,
      finalUrl,
      redirects,
      screenshot: rawDataUrl
        ? {
            captured: true,
            dataUrl: rawDataUrl,
            viewport,
            width: typeof payload.width === 'number' ? payload.width : viewport === 'mobile' ? 390 : 1280,
            height: typeof payload.height === 'number' ? payload.height : viewport === 'mobile' ? 844 : 720,
            capturedAt,
          }
        : {
            captured: false,
            viewport,
            missingReason: {
              en: 'Remote browser session executed, but no image frame was returned.',
              ar: 'تم تنفيذ جلسة المتصفح السحابي، ولكن لم تُعَد صورة لقطة شاشة.',
            },
          },
      networkRequests,
      permissionEvents,
      domSummary: payload.domSummary
        ? {
            title: payload.domSummary.title ? String(payload.domSummary.title) : undefined,
            dynamicFormCount: Number(payload.domSummary.dynamicFormCount || 0),
            sensitiveInputCount: Number(payload.domSummary.sensitiveInputCount || 0),
            dynamicIframeCount: Number(payload.domSummary.dynamicIframeCount || 0),
            dynamicScriptCount: Number(payload.domSummary.dynamicScriptCount || 0),
            wordCount: Number(payload.domSummary.wordCount || 0),
            notableElements: Array.isArray(payload.domSummary.notableElements)
              ? payload.domSummary.notableElements.slice(0, 12).map(String)
              : [],
          }
        : undefined,
      confidenceImpact: 0,
      coverageImpact: 0,
      executiveSummary: {
        en: `Level B dynamic execution completed via External Cloud Browser Service (${networkRequests.length} runtime requests observed, ${sensitiveCount} sensitive sinks, ${permissionEvents.length} permission/runtime events).`,
        ar: `اكتمل التنفيذ الديناميكي (Level B) عبر خدمة المتصفح السحابي الخارجي (رُصد ${networkRequests.length} طلب شبكي، منها ${sensitiveCount} وجهة حساسة، و${permissionEvents.length} حدث صلاحيات/تشغيل).`,
      },
    };
  } catch (err: any) {
    const safeReason = sanitizeErrorReason(String(err?.message || err || ''), [apiKey, endpoint]);
    return {
      status: 'failed',
      executionMode: 'unavailable',
      providerLabel: PROVIDER_LABEL,
      durationMs: Date.now() - startedAt,
      redirects: [],
      screenshot: {
        captured: false,
        viewport,
        missingReason: safeReason,
      },
      networkRequests: [],
      permissionEvents: [],
      confidenceImpact: -15,
      coverageImpact: -22,
      errorReason: safeReason,
      executiveSummary: {
        en: 'Level B runtime execution failed cleanly without affecting risk score; inspection confidence and coverage were reduced accordingly.',
        ar: 'تعذّر إكمال التنفيذ الديناميكي (Level B)؛ تم خصم التأثير من الثقة والتغطية فقط دون تضخيم درجة الخطورة.',
      },
    };
  }
}
