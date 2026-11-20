import * as cheerio from 'cheerio';
import type {
  BilingualText,
  CheckFinding,
  CookieAstOperation,
  CookieAuditItem,
  CookieAuditSummary,
  CookieCategory,
  CookieConsentVerification,
} from '../types.ts';
import type { JsDataFlowAnalysisResult } from './jsDataFlowAnalyzer.ts';
import { extractRegistrableDomain } from './urlIntelligence.ts';

const SECURITY_COOKIE_NAME_RE =
  /^(?:csrf|xsrf|_csrf|csrftoken|xsrf-token|__requestverificationtoken|__host-.*|__secure-.*|cf_clearance|__cf_bm|_cfuvid|ak_bmsc|bm_sv|bm_sz|incap_ses_.*|visid_incap_.*|awsalb|awsalbcors)$/i;

const ESSENTIAL_COOKIE_NAME_RE =
  /^(?:session(?:id|_id)?|phpsessid|jsessionid|asp\.net_sessionid|connect\.sid|sid|uid|auth|token|refresh_token|remember(?:_me)?|logged_in|cart(?:_id)?|basket|checkout|consent|cookie_consent|cookieconsent_status|cc_cookie|onetrust.*|optanonconsent|cookieyes.*|complianz.*|cmplz_.*|moove_gdpr.*|euconsent.*|viewed_cookie_policy|wp-settings.*|wordpress_.*|next-auth.*|crumb|route|g_state)$/i;

const FUNCTIONAL_COOKIE_NAME_RE =
  /^(?:theme|dark_?mode|lang|locale|i18n.*|language|currency|tz|timezone|country|region|sidebar|layout|pref(?:erence)?s?|ui_.*|ab_test|variant)$/i;

const ANALYTICS_COOKIE_CATALOG: Record<string, string> = {
  _ga: 'Google Analytics',
  _gid: 'Google Analytics',
  _gat: 'Google Analytics',
  _clck: 'Microsoft Clarity',
  _clsk: 'Microsoft Clarity',
  _hjid: 'Hotjar Analytics',
  _hjfirstseen: 'Hotjar Analytics',
  _hjincludedinsession: 'Hotjar Analytics',
  _hjabsolutesessioninprogress: 'Hotjar Analytics',
  ajs_anonymous_id: 'Segment Analytics',
  ajs_user_id: 'Segment Analytics',
  _ym_uid: 'Yandex Metrica',
  _ym_d: 'Yandex Metrica',
  _pk_id: 'Matomo Analytics',
  _pk_ses: 'Matomo Analytics',
  mp_: 'Mixpanel Analytics',
  ph_: 'PostHog Analytics',
  amplitude_id: 'Amplitude Analytics',
};

const AD_COOKIE_CATALOG: Record<string, string> = {
  _fbp: 'Meta / Facebook Pixel',
  _fbc: 'Meta / Facebook Click ID',
  fr: 'Facebook Advertising',
  _gcl_au: 'Google AdSense / Conversion Linker',
  _gcl_aw: 'Google Ads Conversion',
  _gcl_dc: 'DoubleClick / Campaign Manager',
  ide: 'Google DoubleClick Ads',
  dsid: 'Google DoubleClick Ads',
  anid: 'Google Advertising',
  nid: 'Google Preferences / Ads',
  _uetsid: 'Microsoft Bing Ads',
  _uetvid: 'Microsoft Bing Ads',
  muid: 'Microsoft Advertising',
  _ttp: 'TikTok Pixel',
  ttclid: 'TikTok Ads',
  _rdt_uuid: 'Reddit Pixel',
  _pin_unauth: 'Pinterest Tag',
  _scid: 'Snapchat Pixel',
  cto_bundle: 'Criteo Retargeting',
  __gads: 'Google AdSense',
  __gpi: 'Google Publisher Tag',
  uuid2: 'AppNexus / Xandr Ads',
  tapad_id: 'Tapad Cross-Device',
  pubmatic: 'PubMatic Ads',
  rubicon: 'Magnite / Rubicon Ads',
};

function sanitizeCookieValue(rawVal: string | undefined): string | undefined {
  if (!rawVal) return undefined;
  const trimmed = rawVal.trim();
  if (!trimmed) return undefined;
  if (trimmed.length <= 10) return `${trimmed.slice(0, 3)}***`;
  return `${trimmed.slice(0, 6)}...[${trimmed.length} chars redacted]`;
}

function lookupAnalyticsVendor(name: string): string | undefined {
  const lower = name.toLowerCase();
  if (lower.startsWith('_ga')) return 'Google Analytics';
  if (lower.startsWith('_hj')) return 'Hotjar Analytics';
  if (lower.startsWith('_pk_')) return 'Matomo Analytics';
  if (lower.startsWith('mp_')) return 'Mixpanel Analytics';
  if (lower.startsWith('ph_')) return 'PostHog Analytics';
  for (const [k, vendor] of Object.entries(ANALYTICS_COOKIE_CATALOG)) {
    if (lower === k || lower.startsWith(k)) return vendor;
  }
  return undefined;
}

function lookupAdVendor(name: string): string | undefined {
  const lower = name.toLowerCase();
  for (const [k, vendor] of Object.entries(AD_COOKIE_CATALOG)) {
    if (lower === k || lower.startsWith(k)) return vendor;
  }
  if (/(?:aff_?id|sub_?id|ad_?track|retarget|pixel_id|clickid)/i.test(lower)) {
    return 'Advertising / Affiliate Tracker';
  }
  return undefined;
}

function detectConsentMechanism(
  $: cheerio.CheerioAPI,
  htmlText: string,
  jsResult: JsDataFlowAnalysisResult
): {
  hasBanner: boolean;
  mechanismType: CookieConsentVerification['mechanismType'];
  explainsPurpose: boolean;
  hasRejectOrManageOption: boolean;
  details: BilingualText;
} {
  const bannerSelector = $(
    '[id*="cookie" i], [class*="cookie" i], [id*="consent" i], [class*="consent" i], [id*="gdpr" i], [class*="gdpr" i], [aria-label*="cookie" i], [aria-label*="consent" i], #onetrust-banner-sdk, #CybotCookiebotDialog, .cc-window, .qc-cmp2-container'
  );
  const bannerText = bannerSelector.text().replace(/\s+/g, ' ').trim();
  const visibleBodyText = $('body').text().replace(/\s+/g, ' ');
  const combinedConsentText = `${bannerText} ${visibleBodyText.slice(0, 12000)}`.toLowerCase();

  const hasCmpVendor =
    /onetrust|cookiebot|didomi|quantcast|trustarc|termly|cookieyes|complianz|iubenda|usercentrics|__tcfapi|__uspapi|klaro|tarteaucitron|axeptio|osano|borlabs|consentmanager|moove_gdpr|cmplz/i.test(
      htmlText
    ) || jsResult.consentMechanismInJs.hasConsentApiOrGate;

  const hasConsentPhrase =
    /(?:we use cookies|this (?:site|website) uses cookies|cookie (?:policy|notice|preferences|settings|consent)|accept (?:all )?cookies|agree to cookies|privacy preferences|by continuing to (?:use|browse) this (?:site|website)|نستخدم ملفات تعريف الارتباط|ملفات تعريف الارتباط|سياسة الكوكيز|موافقة على الكوكيز|قبول الكوكيز|موافق على استخدام|استخدام الموقع وملفات)/i.test(
      combinedConsentText
    ) || jsResult.consentMechanismInJs.hasConsentUiTextInJs;

  const hasModal = bannerSelector.is('[role="dialog"], [aria-modal="true"], .modal') || /cookie.*modal/i.test(htmlText);
  const hasBanner = bannerSelector.length > 0 || hasCmpVendor || hasConsentPhrase;

  const explainsPurpose =
    /(?:analytics|marketing|advertising|personaliz|functional|necessary|essential|preferences|security|improve|experience|تحسين|إحصائيات|إعلانات|ضرورية|الوظيفية|التفضيلات)/i.test(
      bannerText || combinedConsentText
    );

  const rejectTexts = $('button, a, [role="button"]')
    .map((_, el) => $(el).text().trim())
    .get()
    .join(' ');
  const hasRejectOrManageOption =
    /(?:reject|decline|deny|necessary only|essential only|only necessary|manage|settings|preferences|customize|refuse|رفض|الضروري فقط|إدارة التفضيلات|تخصيص)/i.test(
      `${rejectTexts} ${bannerText}`
    ) || jsResult.consentMechanismInJs.hasRejectOrWithdrawHandler;

  const mechanismType: CookieConsentVerification['mechanismType'] = hasCmpVendor
    ? 'banner'
    : hasModal
      ? 'modal_dialog'
      : bannerSelector.length > 0
        ? 'banner'
        : hasConsentPhrase
          ? 'explicit_notice'
          : 'none';

  return {
    hasBanner,
    mechanismType,
    explainsPurpose: hasBanner ? explainsPurpose : false,
    hasRejectOrManageOption: hasBanner ? hasRejectOrManageOption : false,
    details: hasBanner
      ? {
          en: `Cookie consent mechanism detected (${mechanismType})${explainsPurpose ? ' with purpose explanation' : ''}${hasRejectOrManageOption ? ' and Reject/Manage option' : ' (no static Reject/Manage button observed)'}.`,
          ar: `تم رصد آلية إشعار/موافقة للكوكيز (${mechanismType})${explainsPurpose ? ' تشرح الغرض' : ''}${hasRejectOrManageOption ? ' وتتيح الرفض أو الإدارة' : ' (لم يُلاحظ زر رفض صريح ثابت)'}.`,
        }
      : {
          en: 'No cookie consent banner or CMP script detected in initial static HTML/JS.',
          ar: 'لم يُرصد شريط إشعار أو موافقة للكوكيز في HTML/JS الأولي.',
        },
  };
}

export function analyzeCookieIntelligence(params: {
  finalUrl: string;
  rawSetCookies: string[];
  $: cheerio.CheerioAPI;
  htmlText: string;
  jsResult: JsDataFlowAnalysisResult;
  externalTxHosts: string[];
}): {
  audit: CookieAuditSummary;
  finding: CheckFinding;
} {
  const { finalUrl, rawSetCookies, $, htmlText, jsResult, externalTxHosts } = params;
  const now = new Date().toISOString();
  const parsedFinal = new URL(finalUrl);
  const finalRegDomain = extractRegistrableDomain(parsedFinal.hostname);

  const consentUi = detectConsentMechanism($, htmlText, jsResult);
  const cookiesDetected: CookieAuditItem[] = [];
  const cookieStuffingSignals: string[] = [];

  // Hidden cookie-stuffing ad affiliate pixels check (only genuine hidden 1x1/opacity:0 affiliate pixel drops)
  $('img[src], iframe[src]').each((_, el) => {
    const src = ($(el).attr('src') || '').trim();
    const style = ($(el).attr('style') || '').toLowerCase();
    const width = $(el).attr('width');
    const height = $(el).attr('height');
    const isHidden =
      style.includes('display:none') ||
      style.includes('display: none') ||
      style.includes('visibility:hidden') ||
      style.includes('opacity:0') ||
      ((width === '0' || width === '1') && (height === '0' || height === '1'));

    if (!isHidden || !src || src.startsWith('data:')) return;
    try {
      const targetUrl = new URL(src, finalUrl);
      const host = targetUrl.hostname.toLowerCase();
      const targetReg = extractRegistrableDomain(host);
      if (
        targetReg &&
        targetReg !== finalRegDomain &&
        (/(?:doubleclick|adnxs|criteo|taboola|outbrain|popads|adsterra|propellerads|clickbank|cj\.com|shareasale|awin1|impact\.com)/i.test(host) ||
          /(?:aff_?id|sub_?id|affid|subid|cookie_stuff|affiliate)/i.test(targetUrl.search))
      ) {
        cookieStuffingSignals.push(`Hidden ${el.tagName} pixel -> ${host}${targetUrl.pathname}`);
      }
    } catch {
      // ignore invalid URL
    }
  });

  // Check whether AST observed actual document.cookie -> external untrusted transmission (theft)
  const harmfulCookieExfilTx = jsResult.transmissions.find((tx) => {
    if (!tx.taintTags.includes('cookies')) return false;
    try {
      const destHost = new URL(tx.destinationUrl, finalUrl).hostname.toLowerCase();
      return extractRegistrableDomain(destHost) !== finalRegDomain;
    } catch {
      return false;
    }
  });
  const hasCookieTheftInJs = Boolean(harmfulCookieExfilTx);
  const theftDestHost = harmfulCookieExfilTx
    ? (() => {
        try {
          return new URL(harmfulCookieExfilTx.destinationUrl, finalUrl).hostname.toLowerCase();
        } catch {
          return undefined;
        }
      })()
    : undefined;

  // 1. Parse HTTP Set-Cookie headers with full RFC6265 attribute extraction
  for (const raw of rawSetCookies) {
    const parts = raw.split(';').map((p) => p.trim()).filter(Boolean);
    if (!parts.length) continue;
    const eqIdx = parts[0].indexOf('=');
    const name = (eqIdx > 0 ? parts[0].slice(0, eqIdx) : parts[0]).trim();
    const rawValue = eqIdx > 0 ? parts[0].slice(eqIdx + 1) : '';
    const lowerName = name.toLowerCase();
    const attrsLower = parts.slice(1).map((a) => a.toLowerCase());

    const httpOnly = attrsLower.includes('httponly');
    const secure = attrsLower.includes('secure');
    const sameSiteAttr = parts.slice(1).find((a) => a.toLowerCase().startsWith('samesite='));
    const sameSite = sameSiteAttr ? sameSiteAttr.split('=')[1]?.trim() : undefined;
    const domainAttr = parts.slice(1).find((a) => a.toLowerCase().startsWith('domain='));
    const cookieDomain = domainAttr ? domainAttr.split('=')[1]?.trim().replace(/^\./, '').toLowerCase() : undefined;
    const pathAttr = parts.slice(1).find((a) => a.toLowerCase().startsWith('path='));
    const cookiePath = pathAttr ? pathAttr.split('=')[1]?.trim() : '/';
    const expiresAttr = parts.slice(1).find((a) => a.toLowerCase().startsWith('expires='));
    const cookieExpires = expiresAttr ? expiresAttr.split('=').slice(1).join('=').trim() : undefined;
    const maxAgeAttr = parts.slice(1).find((a) => a.toLowerCase().startsWith('max-age='));
    const maxAgeVal = maxAgeAttr ? Number(maxAgeAttr.split('=')[1]?.trim()) : undefined;

    const persistence: 'session' | 'persistent' =
      cookieExpires || (maxAgeVal !== undefined && !Number.isNaN(maxAgeVal) && maxAgeVal > 0) ? 'persistent' : 'session';

    const cookieReg = cookieDomain ? extractRegistrableDomain(cookieDomain) : finalRegDomain;
    const party: 'first_party' | 'third_party' =
      cookieDomain && cookieReg && cookieReg !== finalRegDomain ? 'third_party' : 'first_party';

    const analyticsVendor = lookupAnalyticsVendor(name);
    const adVendor = lookupAdVendor(name);
    const isSecurityCookie =
      SECURITY_COOKIE_NAME_RE.test(lowerName) || name.startsWith('__Host-') || name.startsWith('__Secure-');
    const isFunctionalCookie = FUNCTIONAL_COOKIE_NAME_RE.test(lowerName);
    const isEssentialCookie = ESSENTIAL_COOKIE_NAME_RE.test(lowerName);
    const isConsentSelfCookie = /^(?:cookie_consent|consent|cc_cookie|cookieconsent_status|optanonconsent)$/i.test(lowerName);

    let category: CookieCategory;
    let isMalicious = false;
    let isEssentialForSite = false;
    let domainOrVendor = cookieDomain || parsedFinal.hostname;
    let detail: BilingualText;
    let purposeAssessment: BilingualText;

    if (hasCookieTheftInJs && !httpOnly && (isEssentialCookie || isSecurityCookie || /session|auth|token|sid/i.test(lowerName))) {
      // Actual proven cookie theft in JS accessing an unprotected session/auth cookie
      category = 'malicious';
      isMalicious = true;
      detail = {
        en: `HTTP cookie "${name}" lacks HttpOnly and is actively exposed to JS cookie theft (${theftDestHost || 'external host'}).`,
        ar: `الكوكي "${name}" تفتقر إلى HttpOnly ومعرضة فعلياً للسرقة عبر JavaScript المرسِل للخارج.`,
      };
      purposeAssessment = { en: 'Session/Auth token compromised by JS exfiltration', ar: 'رمز جلسة مُسرّب عبر سكربت' };
    } else if (adVendor) {
      category = 'advertising';
      domainOrVendor = adVendor;
      detail = {
        en: `Advertising / retargeting HTTP cookie (${adVendor})${consentUi.hasBanner ? ' with consent notice present' : ' set before consent banner disclosure'}.`,
        ar: `كوكي إعلانات وإعادة استهداف (${adVendor})${consentUi.hasBanner ? ' مع وجود إشعار موافقة' : ' فُرضت قبل إشعار الموافقة'}.`,
      };
      purposeAssessment = { en: `Advertising / Marketing (${adVendor})`, ar: `إعلانات وتسويق (${adVendor})` };
    } else if (analyticsVendor) {
      category = 'analytics';
      domainOrVendor = analyticsVendor;
      detail = {
        en: `Analytics measurement HTTP cookie (${analyticsVendor}).`,
        ar: `كوكي تحليلات وقياس أداء (${analyticsVendor}).`,
      };
      purposeAssessment = { en: `Analytics (${analyticsVendor})`, ar: `إحصائيات وتحليلات (${analyticsVendor})` };
    } else if (party === 'third_party') {
      // Rule: third-party Domain attribute alone is NOT malicious! Classify cleanly as third_party (or advertising if ad)
      category = 'third_party';
      domainOrVendor = cookieDomain || 'External Domain';
      detail = {
        en: `Third-party scoped HTTP cookie for external domain (${cookieDomain}); not malicious unless paired with abuse/stuffing.`,
        ar: `كوكي طرف ثالث مخصصة لنطاق خارجي (${cookieDomain})؛ ليست خبيثة بذاتها.`,
      };
      purposeAssessment = { en: `Third-Party Scope (${cookieDomain})`, ar: `نطاق طرف ثالث (${cookieDomain})` };
    } else if (isSecurityCookie || (isEssentialCookie && httpOnly && secure && /session|auth|token/i.test(lowerName))) {
      category = 'security_cookie';
      isEssentialForSite = true;
      detail = {
        en: `Hardened security / session-protection cookie (${httpOnly ? 'HttpOnly ' : ''}${secure ? 'Secure ' : ''}${sameSite ? `SameSite=${sameSite}` : ''}).`,
        ar: `كوكي أمان وحماية جلسات محصنة (${httpOnly ? 'HttpOnly ' : ''}${secure ? 'Secure ' : ''}${sameSite ? `SameSite=${sameSite}` : ''}).`,
      };
      purposeAssessment = { en: 'Security & Session Protection', ar: 'الأمان وحماية الجلسة' };
    } else if (isFunctionalCookie) {
      category = 'functional_preference';
      isEssentialForSite = true;
      detail = {
        en: `Functional UI preference cookie ("${name}") storing language, theme, or display settings.`,
        ar: `كوكي وظيفية لتفضيلات الواجهة ("${name}") مثل اللغة أو المظهر.`,
      };
      purposeAssessment = { en: 'Functional UI Preferences', ar: 'تفضيلات الواجهة واللغة' };
    } else if (isEssentialCookie || isConsentSelfCookie) {
      category = 'essential_necessary';
      isEssentialForSite = true;
      const weakSession = /session|auth|token/i.test(lowerName) && (!httpOnly || (parsedFinal.protocol === 'https:' && !secure));
      detail = {
        en: weakSession
          ? `Essential session cookie ("${name}") missing ${!httpOnly ? 'HttpOnly' : 'Secure'} hardening flag (security posture note only).`
          : `Strictly necessary HTTP cookie ("${name}") supporting core site session or cart operation.`,
        ar: weakSession
          ? `كوكي جلسة ضرورية ("${name}") تفتقر لخاصية ${!httpOnly ? 'HttpOnly' : 'Secure'} (ملاحظة تحصين فقط).`
          : `كوكي ضرورية أساسية ("${name}") لتشغيل الجلسة أو سلة المشتريات.`,
      };
      purposeAssessment = { en: 'Essential / Strictly Necessary', ar: 'أساسية لعمل الموقع' };
    } else {
      category = 'essential_necessary';
      isEssentialForSite = true;
      detail = {
        en: `First-party HTTP cookie ("${name}") set by ${parsedFinal.hostname}.`,
        ar: `كوكي طرف أول ("${name}") صادرة عن ${parsedFinal.hostname}.`,
      };
      purposeAssessment = { en: 'First-Party Operational Cookie', ar: 'كوكي تشغيلية للطرف الأول' };
    }

    const requiresConsent = category === 'advertising' || category === 'analytics' || category === 'third_party';
    cookiesDetected.push({
      name,
      source: 'http_set_cookie',
      category,
      isThirdPartyOrAdNetwork: party === 'third_party' || category === 'advertising',
      isMaliciousOrHarmful: isMalicious,
      isDeclaredOrConsented: !requiresConsent || consentUi.hasBanner,
      isEssentialForSite,
      securityFlags: { httpOnly, secure, sameSite },
      domainOrVendor,
      domain: cookieDomain || parsedFinal.hostname,
      path: cookiePath,
      expires: cookieExpires,
      maxAge: maxAgeVal !== undefined && !Number.isNaN(maxAgeVal) ? maxAgeVal : undefined,
      persistence,
      party,
      sanitizedValuePreview: sanitizeCookieValue(rawValue),
      purposeAssessment,
      preConsentObserved: true,
      postConsentRequired: requiresConsent,
      hasTrackingIdentifiers: category === 'advertising' || category === 'analytics',
      transmittedExternally: isMalicious,
      externalDestinationHost: isMalicious ? theftDestHost : undefined,
      excerpt: raw.slice(0, 140),
      detail,
    });
  }

  // 2. Process AST JavaScript Cookie Events (Writes & Reads)
  const seenJsCookieNames = new Set<string>();
  const jsReads = jsResult.cookieEvents.filter((ev) => ev.kind === 'read');
  const jsWrites = jsResult.cookieEvents.filter((ev) => ev.kind === 'write');

  for (const wEv of jsWrites) {
    const name = wEv.cookieName || 'js_cookie_write';
    const key = `write:${name}`;
    if (seenJsCookieNames.has(key)) continue;
    seenJsCookieNames.add(key);

    const lower = name.toLowerCase();
    const analyticsVendor = lookupAnalyticsVendor(name);
    const adVendor = lookupAdVendor(name);
    const isFunctional = FUNCTIONAL_COOKIE_NAME_RE.test(lower);
    const isEssential = ESSENTIAL_COOKIE_NAME_RE.test(lower);
    const isSecurity = SECURITY_COOKIE_NAME_RE.test(lower);

    let category: CookieCategory;
    let isMalicious = false;
    let isEssentialForSite = false;
    let detail: BilingualText;
    let purposeAssessment: BilingualText;

    // Malicious ONLY on confirmed malicious script/popunder/stuffing injection OR proven cookie exfiltration
    if (wEv.usesMaliciousInjection || /popunder|stuffing/i.test(lower)) {
      category = 'malicious';
      isMalicious = true;
      detail = {
        en: `Malicious/injected JS cookie write ("${name}") delivering popunder, script, or stuffing payload in ${wEv.sourceScript}.`,
        ar: `حقن كوكي خبيث عبر JavaScript ("${name}") بحمولة ضارة أو إعلانات قسرية في ${wEv.sourceScript}.`,
      };
      purposeAssessment = { en: 'Malicious / Injected Cookie Payload', ar: 'حقن كوكي خبيث أو ضار' };
    } else if (wEv.usesObfuscationOrDynamicPayload) {
      category = 'suspicious';
      detail = {
        en: `Encoded/dynamic JS cookie write ("${name}") without proven malicious payload or external exfiltration.`,
        ar: `كتابة كوكي برمجية مرمزة ("${name}") دون دليل حقن خبيث أو تسريب خارجي (ملاحظة فحص فقط).`,
      };
      purposeAssessment = { en: 'Encoded Client Cookie (Non-Malicious)', ar: 'كوكي مرمزة محلياً (غير خبيثة)' };
    } else if (adVendor) {
      category = 'advertising';
      detail = {
        en: `JavaScript sets advertising tracking cookie "${name}" (${adVendor})${wEv.consentGated ? ' behind consent gate' : ''}.`,
        ar: `تضبط JavaScript كوكي إعلانات "${name}" (${adVendor})${wEv.consentGated ? ' بعد شرط الموافقة' : ''}.`,
      };
      purposeAssessment = { en: `Advertising (${adVendor})`, ar: `إعلانات (${adVendor})` };
    } else if (analyticsVendor) {
      category = 'analytics';
      detail = {
        en: `JavaScript sets analytics cookie "${name}" (${analyticsVendor})${wEv.consentGated ? ' behind consent gate' : ''}.`,
        ar: `تضبط JavaScript كوكي تحليلات "${name}" (${analyticsVendor})${wEv.consentGated ? ' بعد شرط الموافقة' : ''}.`,
      };
      purposeAssessment = { en: `Analytics (${analyticsVendor})`, ar: `تحليلات (${analyticsVendor})` };
    } else if (isFunctional) {
      category = 'functional_preference';
      isEssentialForSite = true;
      detail = {
        en: `Client-side functional preference cookie ("${name}") written safely by site UI script.`,
        ar: `كوكي تفضيلات واجهة ("${name}") تكتبها سكربتات الموقع بشكل طبيعي.`,
      };
      purposeAssessment = { en: 'Functional Preferences', ar: 'تفضيلات الوظائف' };
    } else if (isSecurity) {
      category = 'security_cookie';
      isEssentialForSite = true;
      detail = {
        en: `Security/anti-abuse cookie ("${name}") managed client-side.`,
        ar: `كوكي أمان وحماية ("${name}") تُدار برمجياً.`,
      };
      purposeAssessment = { en: 'Security Protection', ar: 'الحماية والأمان' };
    } else if (isEssential) {
      category = 'essential_necessary';
      isEssentialForSite = true;
      detail = {
        en: `Essential client-side state cookie ("${name}").`,
        ar: `كوكي تشغيلية ضرورية ("${name}").`,
      };
      purposeAssessment = { en: 'Essential State', ar: 'حالة أساسية' };
    } else {
      category = 'functional_preference';
      isEssentialForSite = true;
      detail = {
        en: `First-party JavaScript cookie ("${name}") written without obfuscation or exfiltration.`,
        ar: `كوكي طرف أول مكتوبة عبر JavaScript ("${name}") دون تمويه أو تسريب.`,
      };
      purposeAssessment = { en: 'First-Party Client State', ar: 'حالة طرف أول' };
    }

    const requiresConsent = category === 'advertising' || category === 'analytics';
    cookiesDetected.push({
      name,
      source: 'js_cookie_write',
      category,
      isThirdPartyOrAdNetwork: Boolean(adVendor),
      isMaliciousOrHarmful: isMalicious,
      isDeclaredOrConsented: !requiresConsent || consentUi.hasBanner || wEv.consentGated,
      isEssentialForSite,
      domainOrVendor: adVendor || analyticsVendor || parsedFinal.hostname,
      domain: parsedFinal.hostname,
      path: '/',
      persistence: 'session',
      party: 'first_party',
      purposeAssessment,
      preConsentObserved: !wEv.consentGated,
      postConsentRequired: requiresConsent,
      hasTrackingIdentifiers: requiresConsent,
      transmittedExternally: isMalicious && hasCookieTheftInJs,
      externalDestinationHost: isMalicious && hasCookieTheftInJs ? theftDestHost : undefined,
      astOperations: wEv.operations,
      excerpt: wEv.excerpt,
      detail,
    });
  }

  // Record document.cookie reads cleanly with exact AST operations
  // Mandatory Rule 2: Reading/parsing/validating/filtering/decoding document.cookie is NEVER malicious!
  if (jsReads.length > 0) {
    const allOps = Array.from(new Set(jsReads.flatMap((r) => r.operations))) as CookieAstOperation[];
    const sampleEv = jsReads[0];
    const anyFlowsExternal = hasCookieTheftInJs || jsReads.some((r) => r.flowsToExternalTx);
    if (anyFlowsExternal && !allOps.includes('theft')) allOps.push('transmit', 'theft');

    cookiesDetected.push({
      name: 'document.cookie (JS Access)',
      source: 'js_cookie_read',
      category: anyFlowsExternal ? 'malicious' : 'functional_preference',
      isThirdPartyOrAdNetwork: false,
      isMaliciousOrHarmful: anyFlowsExternal,
      isDeclaredOrConsented: !anyFlowsExternal,
      isEssentialForSite: !anyFlowsExternal,
      domainOrVendor: parsedFinal.hostname,
      party: 'first_party',
      purposeAssessment: anyFlowsExternal
        ? { en: `Active Cookie Theft to ${theftDestHost || 'External Host'}`, ar: `سرقة كوكيز نشطة إلى ${theftDestHost || 'خادم خارجي'}` }
        : { en: `Local AST Ops: ${allOps.join(' -> ')} (No External Transmission)`, ar: `عمليات محلية فقط: ${allOps.join(' -> ')} (دون إرسال خارجي)` },
      preConsentObserved: true,
      postConsentRequired: false,
      transmittedExternally: anyFlowsExternal,
      externalDestinationHost: anyFlowsExternal ? theftDestHost : undefined,
      astOperations: allOps,
      excerpt: sampleEv.excerpt,
      detail: anyFlowsExternal
        ? {
            en: `AST data-flow confirmed document.cookie is read and transmitted externally to "${theftDestHost || externalTxHosts[0] || 'unknown host'}".`,
            ar: `أكد تتبع تدفق البيانات في AST قراءة document.cookie وإرسالها خارجياً إلى "${theftDestHost || externalTxHosts[0] || 'خادم خارجي'}".`,
          }
        : {
            en: `JavaScript reads document.cookie strictly for local UI/state parsing (${allOps.join(', ')}) with 0 external transmission.`,
            ar: `تقرأ JavaScript قيمة document.cookie محلياً فقط (${allOps.join('، ')}) لفحص الحالة أو التفضيلات دون أي إرسال خارجي.`,
          },
    });
  }

  // Hidden cookie stuffing creates an explicit malicious finding if any ad stuffing pixels exist
  if (cookieStuffingSignals.length > 0 && !cookiesDetected.some((c) => c.isMaliciousOrHarmful)) {
    cookiesDetected.push({
      name: 'hidden_cookie_stuffing_pixel',
      source: 'js_cookie_write',
      category: 'malicious',
      isThirdPartyOrAdNetwork: true,
      isMaliciousOrHarmful: true,
      isDeclaredOrConsented: false,
      isEssentialForSite: false,
      domainOrVendor: 'Hidden Affiliate / Ad Pixel',
      party: 'third_party',
      excerpt: cookieStuffingSignals[0],
      detail: {
        en: `Hidden pixel cookie-stuffing indicator detected: ${cookieStuffingSignals[0]}.`,
        ar: `تم رصد مؤشر حشو كوكيز مخفي عبر بكسل إعلاني: ${cookieStuffingSignals[0]}.`,
      },
    });
  }

  // Build Category Counts across all 8 canonical categories
  const categoryCounts: Record<CookieCategory, number> = {
    essential_necessary: 0,
    functional_preference: 0,
    security_cookie: 0,
    analytics: 0,
    advertising: 0,
    third_party: 0,
    suspicious: 0,
    malicious: 0,
  };
  for (const ck of cookiesDetected) {
    categoryCounts[ck.category] = (categoryCounts[ck.category] || 0) + 1;
  }

  const httpSetCookieCount = cookiesDetected.filter((c) => c.source === 'http_set_cookie').length;
  const jsCookieWriteCount = jsWrites.length;
  const jsCookieReadCount = jsReads.length;
  const essentialFunctionalCount =
    categoryCounts.essential_necessary + categoryCounts.functional_preference + categoryCounts.security_cookie;
  const securityCookieCount = categoryCounts.security_cookie;
  const analyticsCookieCount = categoryCounts.analytics;
  const adCookieCount = categoryCounts.advertising;
  const thirdPartyCookieCount = categoryCounts.third_party;
  const suspiciousCookieCount = categoryCounts.suspicious;
  const maliciousCookieCount = categoryCounts.malicious;

  const setsAdvertisingCookies = adCookieCount > 0;
  const hasMaliciousCookieBehavior = maliciousCookieCount > 0 || cookieStuffingSignals.length > 0;

  // Consent & Transparency Verification (Rule 10 & Spec 2B)
  const optionalTrackingCookies = cookiesDetected.filter(
    (c) => c.category === 'advertising' || c.category === 'analytics' || c.category === 'third_party'
  );
  const preConsentTrackingViolations = optionalTrackingCookies.filter(
    (c) => c.preConsentObserved && !consentUi.hasBanner
  ).length;

  const requiresConsent = optionalTrackingCookies.length > 0;
  const preConsentEssentialOnly = preConsentTrackingViolations === 0 && optionalTrackingCookies.length === 0;
  const privacyViolationDetected = preConsentTrackingViolations > 0 && !hasMaliciousCookieBehavior;

  const behavioralCompliance: CookieConsentVerification['behavioralCompliance'] = !requiresConsent
    ? 'pre_consent_essential_only'
    : preConsentTrackingViolations > 0
      ? 'undeclared_tracking_pre_consent'
      : consentUi.hasBanner
        ? 'compliant'
        : 'unknown';

  const postRejectBehavior: CookieConsentVerification['postRejectBehavior'] = !requiresConsent
    ? 'not_applicable'
    : consentUi.hasRejectOrManageOption
      ? 'not_observable_statically'
      : 'not_observable_statically';

  const consentVerification: CookieConsentVerification = {
    hasConsentMechanism: consentUi.hasBanner,
    mechanismType: consentUi.mechanismType,
    explainsPurpose: consentUi.explainsPurpose,
    hasRejectOrManageOption: consentUi.hasRejectOrManageOption,
    requiresConsent,
    preConsentCookiesCount: cookiesDetected.filter((c) => c.preConsentObserved).length,
    postConsentOptionalCount: cookiesDetected.filter((c) => c.postConsentRequired).length,
    preConsentTrackingViolations,
    preConsentEssentialOnly,
    privacyViolationDetected,
    postRejectBehavior,
    behavioralCompliance,
    details: !requiresConsent
      ? {
          en:
            cookiesDetected.length > 0
              ? 'Only essential, functional, or security cookies detected; privacy consent banner is not strictly required (0 penalty).'
              : 'No cookies observed.',
          ar:
            cookiesDetected.length > 0
              ? 'الكوكيز المرصودة ضرورية أو وظيفية أو أمنية فقط؛ لا يلزم شريط موافقة إعلاني (0 تأثير على الخطورة).'
              : 'لم تُرصد أي كوكيز.',
        }
      : preConsentTrackingViolations > 0
        ? {
            en: `Privacy / Consent Violation: ${preConsentTrackingViolations} analytics/advertising cookie(s) set before user consent with no visible consent banner (privacy note only, NOT malicious).`,
            ar: `مخالفة خصوصية/موافقة: فُرضت ${preConsentTrackingViolations} كوكيز تحليلات/إعلانات قبل موافقة المستخدم دون إشعار واضح (ملاحظة خصوصية وليست سلوكاً خبيثاً).`,
          }
        : consentUi.hasRejectOrManageOption
          ? {
              en: 'Site provides cookie consent notice explaining purposes with Reject/Manage choices.',
              ar: 'يوفر الموقع إشعار موافقة للكوكيز يوضح الغرض مع خيار الرفض أو الإدارة.',
            }
          : {
              en: 'Cookie consent notice present, though a clear static Reject/Manage Preferences control was not verified without browser interaction.',
              ar: 'يوجد إشعار للكوكيز، لكن لم يُتحقق ساكناً من زر رفض/إدارة تفاعلي صريح دون متصفح معزول.',
            },
  };

  const summary: BilingualText = hasMaliciousCookieBehavior
    ? {
        en: `Malicious cookie behavior detected (${maliciousCookieCount} harmful item(s)${cookieStuffingSignals.length ? `, ${cookieStuffingSignals.length} stuffing pixel(s)` : ''}).`,
        ar: `تم رصد سلوك كوكيز خبيث (${maliciousCookieCount} عنصر ضار${cookieStuffingSignals.length ? `، و ${cookieStuffingSignals.length} بكسل حشو مخفي` : ''}).`,
      }
    : cookiesDetected.length === 0
      ? {
          en: 'No HTTP Set-Cookie headers or JavaScript cookie operations detected.',
          ar: 'لم يتم رصد ترويسات Set-Cookie أو عمليات كوكيز في الكود.',
        }
      : {
          en: `Inspected ${cookiesDetected.length} cookie signal(s): ${essentialFunctionalCount} essential/functional/security, ${analyticsCookieCount} analytics, ${adCookieCount} advertising, 0 malicious.`,
          ar: `تم فحص ${cookiesDetected.length} مؤشر كوكيز: ${essentialFunctionalCount} أساسية/وظيفية/أمنية، ${analyticsCookieCount} تحليلات، ${adCookieCount} إعلانات، 0 خبيثة.`,
        };

  const audit: CookieAuditSummary = {
    totalCookiesInspected: cookiesDetected.length,
    httpSetCookieCount,
    jsCookieWriteCount,
    jsCookieReadCount,
    setsAdvertisingCookies,
    hasMaliciousCookieBehavior,
    hasConsentNoticeOrBanner: consentUi.hasBanner,
    consentNoticeDetails: consentUi.details,
    consentVerification,
    essentialFunctionalCount,
    securityCookieCount,
    analyticsCookieCount,
    adCookieCount,
    thirdPartyCookieCount,
    suspiciousCookieCount,
    maliciousCookieCount,
    categoryCounts,
    cookieStuffingSignals,
    cookiesDetected: cookiesDetected.slice(0, 35),
    summary,
  };

  // Finding strictly respects Rules 1, 2, 10:
  // - Benign/essential cookies (even without consent banner) -> 'pass', weight: 0, informational
  // - Undeclared pre-consent analytics/ad tracking -> 'warning', severity: 'low', weight: 0 (Privacy / Consent Violation, NEVER malicious!)
  // - Proven malicious cookie theft / obfuscated stuffing -> 'failed', severity: 'high', weight: 24
  const findingStatus = hasMaliciousCookieBehavior ? 'failed' : privacyViolationDetected ? 'warning' : 'pass';
  const findingSeverity = hasMaliciousCookieBehavior ? 'high' : privacyViolationDetected ? 'low' : 'informational';
  const findingWeight = hasMaliciousCookieBehavior ? 24 : 0;

  const finding: CheckFinding = {
    id: 'source-cookie-audit',
    section: 'source_intelligence',
    test: { en: 'Cookie Intelligence, Classification & Consent Audit', ar: 'استخبارات وتصنيف الكوكيز والتحقق من الموافقة' },
    result: hasMaliciousCookieBehavior
      ? {
          en: `Confirmed malicious cookie theft / obfuscated injection (${maliciousCookieCount} harmful, ${cookieStuffingSignals.length} stuffing)`,
          ar: `سرقة أو حقن كوكيز خبيث مؤكد (${maliciousCookieCount} ضارة، ${cookieStuffingSignals.length} حشو مخفي)`,
        }
      : privacyViolationDetected
        ? {
            en: `Warning only: ${preConsentTrackingViolations} tracking/ad cookie(s) without visible consent prompt in HTML/JS (no risk escalation)`,
            ar: `تحذير فقط: رُصدت ${preConsentTrackingViolations} كوكي إعلانات/تحليلات دون طلب إذن في HTML/JS (لا ترفع التصنيف الأمني)`,
          }
        : {
            en:
              cookiesDetected.length > 0
                ? `${essentialFunctionalCount} essential/functional/security, ${analyticsCookieCount} analytics, ${adCookieCount} ad cookie(s) — 0 malicious (0 risk penalty)`
                : 'No cookies or cookie abuse detected',
            ar:
              cookiesDetected.length > 0
                ? `${essentialFunctionalCount} أساسية/وظيفية/أمنية، ${analyticsCookieCount} تحليلات، ${adCookieCount} إعلانات — 0 خبيثة (دون تأثير على الخطورة)`
                : 'لا توجد كوكيز أو إساءة استخدام للكوكيز',
          },
    status: findingStatus,
    severity: findingSeverity,
    weight: findingWeight,
    evidence: `CookiesTotal: ${cookiesDetected.length} | Essential/Func/Sec: ${essentialFunctionalCount} | Analytics: ${analyticsCookieCount} | Ad: ${adCookieCount} | ThirdParty: ${thirdPartyCookieCount} | Malicious: ${maliciousCookieCount} | ConsentBanner: ${consentUi.hasBanner} | RejectOption: ${consentUi.hasRejectOrManageOption} | PreConsentViolations: ${preConsentTrackingViolations}`,
    sourceCodeEvidence: cookiesDetected.find((c) => c.isMaliciousOrHarmful)?.excerpt || cookiesDetected[0]?.excerpt,
    consentContext: consentVerification.behavioralCompliance,
    dataClassification: hasMaliciousCookieBehavior ? 'Malicious Cookie Abuse / Theft' : privacyViolationDetected ? 'Privacy / Consent Warning Only' : 'Benign / Essential Cookie Usage',
    destination: theftDestHost,
    explanation: {
      en: hasMaliciousCookieBehavior
        ? 'AST data-flow analysis proved severe cookie exfiltration to an external server, malicious script/popunder injection, or hidden ad cookie-stuffing.'
        : privacyViolationDetected
          ? 'HTML and JavaScript were inspected first: site sets analytics or advertising cookies without requesting user consent. Issued as a warning ONLY without elevating security risk classification.'
          : 'Cookie purposes were verified against HTML/JS context: cookies are legitimate/consented with zero malicious injection or exfiltration.',
      ar: hasMaliciousCookieBehavior
        ? 'أثبت تحليل HTML وJS وتدفق البيانات وجود خطر شديد مؤكد: سرقة كوكيز وإرسالها لخادم خارجي أو حقن خبيث أو حشو إعلانات مخفي.'
        : privacyViolationDetected
          ? 'بعد قراءة HTML وJS: الموقع يضع كوكيز إعلانات أو تحليلات دون طلب إذن واضح للمستخدم. يظهر هذا كتحذير خصوصية فقط ولا يرفع التصنيف الأمني ما لم يوجد حقن خبيث أو خطر شديد.'
          : 'تم التحقق من سبب وجود الكوكيز في HTML/JS: الكوكيز مشروعة أو حاصلة على إذن وموافقة دون أي حقن خبيث أو تسريب.',
    },
    recommendedAction: {
      en: hasMaliciousCookieBehavior
        ? 'Clear site cookies/storage immediately and avoid authenticating on this page.'
        : privacyViolationDetected
          ? 'Informational warning: you may decline optional analytics/ad cookies in browser settings.'
          : 'No security action required.',
      ar: hasMaliciousCookieBehavior
        ? 'امسح كوكيز المتصفح فوراً وتجنب تسجيل الدخول في هذه الصفحة.'
        : privacyViolationDetected
          ? 'تحذير إرشادي فقط: يمكنك إدارة أو رفض كوكيز الإعلانات والتحليلات من إعدادات المتصفح.'
          : 'لا يلزم إجراء أمني.',
    },
    source: 'SM Cookie Intelligence Engine',
    timestamp: now,
    confidence: 92,
  };

  return { audit, finding };
}
