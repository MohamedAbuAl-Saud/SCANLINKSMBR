import * as cheerio from 'cheerio';
import type {
  AdvertisingIntelligenceState,
  AdvertisingIntelligenceSummary,
  BilingualText,
  CookieAuditSummary,
  MalvertisingSignalsInfo,
} from '../types.ts';
import type { JsDataFlowAnalysisResult } from './jsDataFlowAnalyzer.ts';

const LEGITIMATE_AD_NETWORK_DOMAINS: { pattern: RegExp; name: string }[] = [
  { pattern: /googlesyndication\.com|googleadservices\.com/i, name: 'Google AdSense / Ads' },
  { pattern: /doubleclick\.net/i, name: 'Google DoubleClick' },
  { pattern: /amazon-adsystem\.com/i, name: 'Amazon Ads' },
  { pattern: /connect\.facebook\.net|facebook\.com\/tr/i, name: 'Meta Pixel' },
  { pattern: /ads-twitter\.com|t\.co\/i\/adsct/i, name: 'X / Twitter Ads' },
  { pattern: /snap\.licdn\.com/i, name: 'LinkedIn Insight Tag' },
  { pattern: /analytics\.tiktok\.com/i, name: 'TikTok Pixel' },
  { pattern: /bat\.bing\.com/i, name: 'Microsoft Bing Ads' },
  { pattern: /taboola\.com/i, name: 'Taboola' },
  { pattern: /outbrain\.com/i, name: 'Outbrain' },
  { pattern: /criteo\.(?:com|net)/i, name: 'Criteo' },
];

const ANALYTICS_PLATFORM_DOMAINS: { pattern: RegExp; name: string }[] = [
  { pattern: /google-analytics\.com|googletagmanager\.com/i, name: 'Google Analytics / GTM' },
  { pattern: /clarity\.ms/i, name: 'Microsoft Clarity' },
  { pattern: /static\.hotjar\.com/i, name: 'Hotjar' },
  { pattern: /plausible\.io/i, name: 'Plausible Analytics' },
  { pattern: /matomo/i, name: 'Matomo' },
  { pattern: /cdn\.segment\.com/i, name: 'Segment' },
  { pattern: /cdn\.mxpnl\.com|api\.mixpanel\.com/i, name: 'Mixpanel' },
  { pattern: /app\.posthog\.com|us\.i\.posthog\.com/i, name: 'PostHog' },
  { pattern: /browser\.sentry-cdn\.com|sentry\.io/i, name: 'Sentry Telemetry' },
];

const AGGRESSIVE_MALVERTISING_DOMAINS: { pattern: RegExp; name: string }[] = [
  { pattern: /popads\.net/i, name: 'PopAds (Aggressive Popunder)' },
  { pattern: /popcash\.net/i, name: 'PopCash (Aggressive Popunder)' },
  { pattern: /propellerads|propu\.sh/i, name: 'PropellerAds (Aggressive Ad Network)' },
  { pattern: /adsterra|highperformanceformat\.com/i, name: 'Adsterra' },
  { pattern: /hilltopads\.net/i, name: 'HilltopAds' },
  { pattern: /clickadu\.com/i, name: 'Clickadu' },
  { pattern: /exoclick\.com/i, name: 'ExoClick' },
  { pattern: /juicyads\.com/i, name: 'JuicyAds' },
  { pattern: /onclickalgo|go\.oclasrv/i, name: 'Popunder Ad Redirector' },
];

export function analyzeAdvertisingIntelligence(params: {
  finalUrl: string;
  $: cheerio.CheerioAPI;
  htmlText: string;
  externalDomains: string[];
  jsResult: JsDataFlowAnalysisResult;
  cookieAudit: CookieAuditSummary;
  inspectionIncomplete?: boolean;
}): {
  advertisingIntel: AdvertisingIntelligenceSummary;
  malvertisingSignals: MalvertisingSignalsInfo;
} {
  const { $, htmlText, externalDomains, jsResult, cookieAudit, inspectionIncomplete } = params;

  const adNetworks = new Set<string>();
  const analyticsPlatforms = new Set<string>();
  const aggressiveNetworks = new Set<string>();

  const resourceUrls: string[] = [...externalDomains];
  $('script[src], iframe[src], img[src], link[href]').each((_, el) => {
    const val = $(el).attr('src') || $(el).attr('href') || '';
    if (val) resourceUrls.push(val);
  });

  for (const res of resourceUrls) {
    for (const net of LEGITIMATE_AD_NETWORK_DOMAINS) {
      if (net.pattern.test(res)) adNetworks.add(net.name);
    }
    for (const ana of ANALYTICS_PLATFORM_DOMAINS) {
      if (ana.pattern.test(res)) analyticsPlatforms.add(ana.name);
    }
    for (const agg of AGGRESSIVE_MALVERTISING_DOMAINS) {
      if (agg.pattern.test(res)) aggressiveNetworks.add(agg.name);
    }
  }

  for (const ck of cookieAudit.cookiesDetected) {
    if (ck.category === 'advertising' && ck.domainOrVendor) {
      adNetworks.add(ck.domainOrVendor);
    } else if (ck.category === 'analytics' && ck.domainOrVendor) {
      analyticsPlatforms.add(ck.domainOrVendor);
    }
  }

  // Malvertising Behavioral Signals
  const popunderDetected = jsResult.behavioralSignals.some((s) => s.category === 'popunder');
  const cryptominerDetected = jsResult.behavioralSignals.some((s) => s.category === 'cryptominer');
  const forcedRedirectDetected =
    jsResult.behavioralSignals.some((s) => s.category === 'redirect' && s.confirmedMaliciousContext) ||
    aggressiveNetworks.size > 0 && /window\.open|location\.replace/i.test(htmlText);

  const visibleText = $('body').text().toLowerCase();
  const fakeDownloadDetected =
    /(?:download\s*(?:ready|now)|your\s*file\s*is\s*ready|click\s*here\s*to\s*download\s*(?:fast|free))/i.test(visibleText) &&
    aggressiveNetworks.size > 0;
  const notificationAbuseDetected =
    /(?:click\s+['"]?allow['"]?\s+to\s+(?:continue|verify|prove|watch|download)|allow\s+notifications\s+to\s+(?:continue|watch|download)|اضغط\s+(?:على\s+)?سماح\s+(?:للمتابعة|للتحقق|للتنزيل))/i.test(
      visibleText
    );

  let hiddenIframesCount = 0;
  $('iframe').each((_, el) => {
    const style = ($(el).attr('style') || '').toLowerCase();
    const w = $(el).attr('width');
    const h = $(el).attr('height');
    if (
      style.includes('display:none') ||
      style.includes('display: none') ||
      style.includes('visibility:hidden') ||
      style.includes('opacity:0') ||
      ((w === '0' || w === '1') && (h === '0' || h === '1'))
    ) {
      hiddenIframesCount++;
    }
  });

  const malvertisingIndicators: string[] = [];
  if (popunderDetected) malvertisingIndicators.push('Popunder window hijacking detected in JavaScript');
  if (forcedRedirectDetected) malvertisingIndicators.push('Forced ad redirect loop detected');
  if (fakeDownloadDetected) malvertisingIndicators.push('Deceptive download ad lure detected alongside aggressive ad network');
  if (notificationAbuseDetected) malvertisingIndicators.push('Coercive notification permission bait ("Click Allow to continue")');
  if (cryptominerDetected) malvertisingIndicators.push('In-browser cryptocurrency miner script detected');
  if (aggressiveNetworks.size > 0) {
    malvertisingIndicators.push(`Aggressive popunder/redirect ad network(s): ${Array.from(aggressiveNetworks).join(', ')}`);
  }
  if (cookieAudit.cookieStuffingSignals.length > 0) {
    malvertisingIndicators.push(...cookieAudit.cookieStuffingSignals);
  }

  const privacyViolations: string[] = [];
  if (cookieAudit.consentVerification?.privacyViolationDetected) {
    privacyViolations.push(cookieAudit.consentVerification.details.en);
  }

  const details: BilingualText[] = malvertisingIndicators.map((ind) => ({
    en: ind,
    ar: ind,
  }));

  const adList = Array.from(new Set([...adNetworks, ...aggressiveNetworks]));
  const anaList = Array.from(analyticsPlatforms);

  // Determine exact 8-state classification (Section 5)
  let status: AdvertisingIntelligenceState;
  let label: BilingualText;

  const hasMaliciousAd =
    popunderDetected ||
    cryptominerDetected ||
    notificationAbuseDetected ||
    fakeDownloadDetected ||
    forcedRedirectDetected ||
    cookieAudit.cookieStuffingSignals.length > 0;

  if (inspectionIncomplete) {
    status = 'unknown_incomplete';
    label = { en: 'Unknown / Incomplete Inspection', ar: 'غير معروف / فحص غير مكتمل' };
  } else if (hasMaliciousAd) {
    status = 'malicious_advertising';
    label = { en: 'Malicious Advertising (Malvertising)', ar: 'إعلانات خبيثة (Malvertising)' };
  } else if (aggressiveNetworks.size > 0 || (hiddenIframesCount >= 2 && adList.length > 0)) {
    status = 'suspicious_advertising';
    label = { en: 'Suspicious Advertising', ar: 'إعلانات مشبوهة' };
  } else if (cookieAudit.consentVerification?.behavioralCompliance === 'undeclared_tracking_pre_consent') {
    status = 'undeclared_tracking';
    label = { en: 'Undeclared Tracking (Privacy Notice)', ar: 'تتبع غير مُصرَّح به (ملاحظة خصوصية)' };
  } else if (adList.length > 0 && cookieAudit.hasConsentNoticeOrBanner) {
    status = 'legitimate_advertising';
    label = { en: 'Legitimate Advertising', ar: 'إعلانات مشروعة ومصرح بها' };
  } else if (anaList.length > 0 && cookieAudit.hasConsentNoticeOrBanner) {
    status = 'declared_analytics';
    label = { en: 'Declared Analytics', ar: 'تحليلات مُعلنة ومصرح بها' };
  } else if (adList.length > 0 || anaList.length > 0 || cookieAudit.consentVerification?.postConsentOptionalCount) {
    status = 'consent_dependent_tracking';
    label = { en: 'Consent-Dependent Tracking', ar: 'تتبع مشروط بالموافقة' };
  } else {
    status = 'no_advertising_detected';
    label = { en: 'No Advertising Detected', ar: 'لم تُرصد شبكات إعلانية' };
  }

  const firstPartyResponsibilityNote: BilingualText = hasMaliciousAd
    ? {
        en: 'First-party site embeds or executes deceptive ad/popunder/bait behavior directly on its origin or via unmanaged third-party ad tags.',
        ar: 'ينفذ الموقع نفسه أو عبر وسوم غير منضبطة سلوكاً إعلانياً مضللاً أو نوافذ منبثقة/إشعارات قسرية.',
      }
    : adList.length > 0
      ? {
          en: 'First-party site operates standard ad/analytics scripts and maintains responsibility for consent transparency.',
          ar: 'يضم الموقع وسوم إعلانات أو تحليلات قياسية، وتقتصر مسؤوليته على الإفصاح وموافقة الخصوصية.',
        }
      : {
          en: 'No advertising scripts or ad trackers embedded by this site.',
          ar: 'لا يضم الموقع سكربتات إعلانية أو شبكات تتبع تسويقي.',
        };

  const thirdPartyAdResponsibilityNote: BilingualText | undefined =
    adList.length > 0
      ? {
          en: `External third-party network(s) (${adList.join(', ')}) set their own pixels/cookies independently of core site authentication.`,
          ar: `شبكات الإعلان الخارجية (${adList.join('، ')}) تضبط كوكيز وبكسلات مستقلة عن بنية تسجيل دخول الموقع.`,
        }
      : undefined;

  const summary: BilingualText = {
    en: `${label.en}${adList.length ? ` · Ad Networks: ${adList.join(', ')}` : ''}${anaList.length ? ` · Analytics: ${anaList.join(', ')}` : ''}`,
    ar: `${label.ar}${adList.length ? ` · شبكات الإعلان: ${adList.join('، ')}` : ''}${anaList.length ? ` · التحليلات: ${anaList.join('، ')}` : ''}`,
  };

  return {
    advertisingIntel: {
      status,
      label,
      adNetworksDetected: adList,
      analyticsPlatformsDetected: anaList,
      firstPartyResponsibilityNote,
      thirdPartyAdResponsibilityNote,
      malvertisingIndicators,
      privacyViolations,
      summary,
    },
    malvertisingSignals: {
      popunderDetected,
      forcedRedirectDetected,
      fakeDownloadDetected,
      notificationAbuseDetected,
      cryptominerDetected,
      hiddenIframesCount,
      adNetworksDetected: adList,
      details,
    },
  };
}
