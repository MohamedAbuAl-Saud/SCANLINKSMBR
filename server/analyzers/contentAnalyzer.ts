import * as cheerio from 'cheerio';
import type { CheckFinding, ContentInspectionData } from '../types.ts';
import { detectBrandImpersonation } from './brandIntelligence.ts';
import { analyzeScriptsWithAst } from './jsDataFlowAnalyzer.ts';
import { classifyDomainRelationship, lookupDomainOwnership } from './officialDomainRegistry.ts';
import { detectPaasHosting, extractRegistrableDomain } from './urlIntelligence.ts';

interface ContentRule {
  pattern: RegExp;
  label: string;
  category: 'credential_lure' | 'fake_alert' | 'urgency' | 'fraud_giveaway' | 'phishing_artifact';
  weight: number;
}

const CONTENT_LURE_RULES: ContentRule[] = [
  {
    pattern: /verify your (account|identity|wallet|payment|login)/i,
    label: 'Account verification lure',
    category: 'urgency',
    weight: 10,
  },
  {
    pattern: /(account|card|profile) (has been |is )?(suspended|locked|restricted|limited|disabled)/i,
    label: 'Account suspension fear threat',
    category: 'urgency',
    weight: 14,
  },
  {
    pattern: /confirm your (password|pin|otp|seed phrase|recovery phrase|credentials)/i,
    label: 'Credential/OTP/seed harvesting prompt',
    category: 'credential_lure',
    weight: 16,
  },
  {
    pattern: /(credit card|cvv|cvc|card number|expiration date|billing address)/i,
    label: 'Payment card collection terminology',
    category: 'credential_lure',
    weight: 9,
  },
  {
    pattern: /(software is out[- ]of[- ]date|outdated browser|update your (flash|browser|player)|system infected|virus detected|critical security alert)/i,
    label: 'Fake software update or system security warning',
    category: 'fake_alert',
    weight: 18,
  },
  {
    pattern: /(mimics a dialogue|trick you into clicking|phishing page|social engineering content)/i,
    label: 'Explicit social-engineering / phishing page markers',
    category: 'phishing_artifact',
    weight: 26,
  },
  {
    pattern: /(claim your (prize|reward|gift|airdrop)|you (have )?won \$?\d+)/i,
    label: 'Giveaway / prize fraud lure',
    category: 'fraud_giveaway',
    weight: 14,
  },
  {
    pattern: /(guaranteed (return|profit)|double your (crypto|bitcoin|usdt))/i,
    label: 'Fraudulent investment promise',
    category: 'fraud_giveaway',
    weight: 16,
  },
  {
    pattern: /(?:your (?:computer|pc|device|windows) has been (?:blocked|locked)|windows defender (?:security center|virus alert|smartscreen warning)|error code[:\s]*0x[0-9a-f]+|call (?:our |toll[- ]?free )?(?:microsoft|apple|windows|tech) support|toll[- ]?free.*\b1[- ]?8\d{2}[- ]?\d{3}[- ]?\d{4})/i,
    label: 'Fake technical support / system lockout warning',
    category: 'fake_alert',
    weight: 22,
  },
  {
    pattern: /(تأكيد حسابك|تم تعليق حسابك|تحديث بيانات البطاقة|رمز التحقق|تحديث البرنامج|تم حظر جهازك|اتصل بالدعم الفني)/i,
    label: 'Arabic social-engineering / suspension lure',
    category: 'urgency',
    weight: 14,
  },
];

const JS_OBFUSCATION_PATTERNS: { pattern: RegExp; label: string; severity: 'medium' | 'high'; kind: 'obf' | 'redirect' | 'popup' | 'other' }[] = [
  {
    pattern: /eval\s*\(\s*(atob|unescape|decodeURIComponent|function\s*\(\s*p\s*,\s*a\s*,\s*c)/i,
    label: 'Obfuscated eval/packed JavaScript',
    severity: 'high',
    kind: 'obf',
  },
  {
    pattern: /_0x[0-9a-f]{4,}/i,
    label: 'Hex-encoded obfuscator variable arrays (_0x...)',
    severity: 'high',
    kind: 'obf',
  },
  {
    pattern: /document\.write\s*\(\s*(unescape|atob)/i,
    label: 'Encoded document.write injection',
    severity: 'high',
    kind: 'obf',
  },
  {
    pattern: /(?:window|top|self)\.location(?:\.href|\.replace|\.assign)?\s*=|location\.(?:replace|assign)\s*\(/i,
    label: 'Dynamic client-side JavaScript redirect',
    severity: 'medium',
    kind: 'redirect',
  },
  {
    pattern: /onbeforeunload\s*=/i,
    label: 'Exit-trap handler (onbeforeunload)',
    severity: 'medium',
    kind: 'popup',
  },
  {
    pattern: /contextmenu[\s\S]{0,80}ctrlKey\s*&&\s*shiftKey[\s\S]{0,80}F12/i,
    label: 'Anti-inspection / DevTools blocking script',
    severity: 'medium',
    kind: 'other',
  },
];

export function analyzeWebsiteContentAndBrand(
  finalUrl: string,
  httpStatus: number | undefined,
  headers: Record<string, string>,
  rawBuffer: Buffer | undefined,
  urlTokens: string[] = [],
  externalScripts: { url: string; code: string }[] = []
): { data?: ContentInspectionData; findings: CheckFinding[] } {
  const now = new Date().toISOString();
  const findings: CheckFinding[] = [];
  const contentType = headers['content-type'] || '';

  if (!rawBuffer || httpStatus === undefined) {
    findings.push({
      id: 'content-unavailable',
      section: 'website_content',
      test: { en: 'HTML Content Inspection', ar: 'فحص محتوى صفحة الويب' },
      result: { en: 'Content could not be retrieved', ar: 'تعذر استرجاع محتوى الصفحة' },
      status: 'unknown',
      severity: 'unknown',
      weight: 0,
      evidence: 'No HTTP response body available',
      explanation: {
        en: 'Content inspection could not run because no HTTP body was returned. Unreachable pages are never marked safe.',
        ar: 'تعذر فحص محتوى الصفحة لعدم وجود استجابة صالحة. غياب المحتوى لا يُعد دليلاً على الأمان.',
      },
      recommendedAction: {
        en: 'Do not assume an unreachable URL is safe.',
        ar: 'لا تفترض أمان رابط تعذر الوصول إليه.',
      },
      source: 'SM Content Inspector',
      timestamp: now,
      confidence: 20,
    });
    return { findings };
  }

  const isHtml =
    contentType.toLowerCase().includes('text/html') ||
    contentType.toLowerCase().includes('application/xhtml') ||
    rawBuffer.slice(0, 512).toString('utf8').toLowerCase().includes('<html');

  if (!isHtml) {
    findings.push({
      id: 'content-non-html',
      section: 'website_content',
      test: { en: 'Response Content Type', ar: 'نوع محتوى الاستجابة' },
      result: { en: `Non-HTML payload (${contentType || 'unknown'})`, ar: `استجابة ليست HTML (${contentType || 'غير محدد'})` },
      status: 'pass',
      severity: 'informational',
      weight: 0,
      evidence: `HTTP ${httpStatus} | Content-Type: ${contentType || 'none'} | Size: ${rawBuffer.length} bytes`,
      explanation: {
        en: 'Target returned a non-HTML resource (file download, image, or API stream). Review File & Download Analysis for binary signature details.',
        ar: 'أعاد الخادم محتوى غير HTML مثل ملف تنزيل أو بيانات خام.',
      },
      recommendedAction: {
        en: 'Inspect the File & Download Analysis section before opening.',
        ar: 'راجع قسم تحليل الملفات والتنزيلات قبل فتح أي محتوى.',
      },
      source: 'SM Content Inspector',
      timestamp: now,
      confidence: 95,
    });
    return { findings };
  }

  const html = rawBuffer.toString('utf8');
  const $ = cheerio.load(html);
  const parsedFinal = new URL(finalUrl);
  const finalHost = parsedFinal.hostname.toLowerCase();
  const finalRegDomain = extractRegistrableDomain(finalHost);
  const paas = detectPaasHosting(finalHost);
  const hostOwnership = lookupDomainOwnership(finalHost);

  const pageTitle = $('title').first().text().trim().slice(0, 160);
  const ogSiteName = $('meta[property="og:site_name"]').attr('content')?.trim() || '';
  const metaDescription = $('meta[name="description"]').attr('content')?.trim().slice(0, 240);

  const clone = cheerio.load(html);
  clone('script, style, noscript').remove();
  const visibleText = clone('body').text().replace(/\s+/g, ' ').trim();
  const visibleWordCount = visibleText ? visibleText.split(' ').length : 0;

  // Detect WAF / Access-Blocked / Non-Readable Site responses (HTTP 401/403/429/451/503 challenge or empty body)
  const challengeText = `${pageTitle} ${visibleText.slice(0, 1500)}`.toLowerCase();
  const isAccessBarrierStatus = httpStatus === 401 || httpStatus === 403 || httpStatus === 429 || httpStatus === 451 || httpStatus === 503;
  const hasChallengeWallMarker =
    /(?:just a moment|checking your browser|enable javascript and cookies|cf-browser-verification|attention required|access denied|403 forbidden|you have been blocked|request blocked|bot protection|please verify you are human|perimeterx|datadome|incapsula)/i.test(
      challengeText
    );
  const isContentBlockedBySite =
    rawBuffer.length === 0 ||
    (isAccessBarrierStatus && (hasChallengeWallMarker || visibleWordCount < 35 || $('form').length === 0));

  if (isContentBlockedBySite) {
    const blockedReason = `HTTP ${httpStatus}${hasChallengeWallMarker ? ' challenge / bot protection barrier' : ' restricted access or unreadable body'}`;
    findings.push({
      id: 'content-unavailable',
      section: 'website_content',
      test: { en: 'HTML Content Inspection & Readability', ar: 'فحص محتوى صفحة الويب وإمكانية القراءة' },
      result: {
        en: `Site blocked content inspection (${blockedReason})`,
        ar: `الموقع لا يسمح بقراءة محتواه (${blockedReason})`,
      },
      status: 'unknown',
      severity: 'unknown',
      weight: 0,
      evidence: `${blockedReason} | Size: ${rawBuffer.length}B | Title: ${pageTitle || 'NONE'}`,
      explanation: {
        en: 'The target server refused automated HTML inspection (HTTP access block, CAPTCHA, or WAF challenge). Level A did not fabricate or guess unseen page content.',
        ar: 'رفض الخادم الهدف قراءة محتوى الصفحة الفعلي بسبب حظر الوصول أو جدار الحماية أو بوابة التحقق. لا يتم تخمين المحتوى المخفي أو اعتبار الموقع آمناً.',
      },
      recommendedAction: {
        en: 'Do not assume an unreadable or access-restricted website is safe.',
        ar: 'لا تفترض سلامة موقع يرفض قراءة محتواه أو يعرض بوابة حظر.',
      },
      source: 'SM Content Inspector',
      timestamp: now,
      confidence: 25,
      errorState: blockedReason,
    });
    return {
      data: {
        httpStatus,
        contentType,
        htmlSizeBytes: rawBuffer.length,
        pageTitle: pageTitle || undefined,
        metaDescription: metaDescription || undefined,
        visibleWordCount,
        formCount: 0,
        passwordInputCount: 0,
        unwrappedPasswordInputCount: 0,
        usernameInputCount: 0,
        sensitiveInputHints: [],
        crossOriginFormActions: [],
        externalLinkCount: 0,
        externalResourceDomains: [],
        externalScriptDomains: [],
        iframeCount: 0,
        hiddenElementCount: 0,
        inlineScriptCount: 0,
        externalScriptCount: 0,
        popupIndicators: [],
        autoRedirectIndicators: [],
        jsIndicators: [],
        notificationApiDetected: false,
        fakeAlertIndicators: [],
        phishingKeywordsMatched: [],
        contentReadStatus: 'blocked_by_site',
        blockedReason,
        claimedPurpose: {
          en: 'Access-Blocked / Bot Protection Gate (Content Unreadable)',
          ar: 'بوابة حظر وصول أو حماية بوتات (المحتوى غير مقروء)',
        },
      },
      findings,
    };
  }

  const headings = $('h1, h2, h3')
    .map((_, el) => $(el).text().replace(/\s+/g, ' ').trim())
    .get()
    .filter((t) => t.length >= 2)
    .slice(0, 8);

  const buttonLabels = $('button, input[type="submit"], input[type="button"], a[role="button"]')
    .map((_, el) => ($(el).is('input') ? $(el).attr('value') || '' : $(el).text()).replace(/\s+/g, ' ').trim())
    .get()
    .filter((t) => t.length >= 2 && t.length <= 60)
    .slice(0, 10);

  const logoAltTexts = $('img[alt]')
    .map((_, el) => ($(el).attr('alt') || '').trim())
    .get()
    .filter((alt) => alt.length >= 2 && alt.length <= 60)
    .slice(0, 10);

  const oauthWidgetsDetected: string[] = [];
  const oauthCheckText = `${buttonLabels.join(' | ')} | ${$('a').map((_, el) => $(el).text()).get().join(' | ')}`.toLowerCase();
  const oauthPatterns: { pat: RegExp; label: string }[] = [
    { pat: /(?:sign in|continue|login) with google/i, label: 'Sign in with Google' },
    { pat: /(?:sign in|continue|login) with microsoft/i, label: 'Sign in with Microsoft' },
    { pat: /(?:sign in|continue|login) with facebook/i, label: 'Continue with Facebook' },
    { pat: /(?:sign in|continue|login) with apple/i, label: 'Sign in with Apple' },
    { pat: /(?:sign in|continue|login) with github/i, label: 'Sign in with GitHub' },
  ];
  for (const op of oauthPatterns) {
    if (op.pat.test(oauthCheckText)) oauthWidgetsDetected.push(op.label);
  }

  const forms = $('form');
  const passwordInputs = $('input[type="password"]');
  let unwrappedPasswordInputCount = 0;
  passwordInputs.each((_, el) => {
    if ($(el).closest('form').length === 0) {
      unwrappedPasswordInputCount++;
    }
  });

  let usernameInputCount = 0;
  const sensitiveInputHints: string[] = [];
  const personalFinanceFields: string[] = [];
  const crossOriginFormActions: string[] = [];

  $('input, select, textarea').each((_, el) => {
    const type = ($(el).attr('type') || 'text').toLowerCase();
    // Hidden anti-CSRF tokens like GitHub authenticity_token must never trigger OTP/seed warnings
    if (type === 'hidden') return;

    const idNamePh = (
      $(el).attr('name') ||
      $(el).attr('id') ||
      $(el).attr('placeholder') ||
      $(el).attr('autocomplete') ||
      ''
    ).toLowerCase();
    const prevLabel = $(el).parent().text().toLowerCase();

    if (type === 'password') {
      sensitiveInputHints.push('password');
    } else if (
      type === 'email' ||
      /(?:^|[^a-z])(user|username|email|login|account|uname)(?:$|[^a-z])/.test(idNamePh) ||
      /(?:username|email|user id)/.test(prevLabel)
    ) {
      usernameInputCount++;
    }

    if (
      /(?:^|[^a-z])(card[-_ ]?number|credit[-_ ]?card|cvv|cvc|ccnum|iban|bank[-_ ]?account|routing[-_ ]?number)(?:$|[^a-z])/.test(
        idNamePh
      ) ||
      /card number|cvv|iban|bank account/.test(prevLabel)
    ) {
      sensitiveInputHints.push('payment-card');
      personalFinanceFields.push('payment/bank');
    }
    if (/(?:^|[^a-z])(ssn|national[-_ ]?id|passport|tax[-_ ]?id|license)(?:$|[^a-z])/.test(idNamePh)) {
      personalFinanceFields.push('government-id');
    }
    if (/(?:^|[^a-z])(phone|mobile|tel|address|street|zip|postal)(?:$|[^a-z])/.test(idNamePh) || type === 'tel') {
      personalFinanceFields.push('contact-pii');
    }
    if (
      /(?:^|[^a-z])(otp|2fa|seed[-_ ]?phrase|mnemonic|recovery[-_ ]?phrase|pin[-_ ]?code)(?:$|[^a-z])/.test(idNamePh) ||
      /verification code|seed phrase/.test(prevLabel)
    ) {
      sensitiveInputHints.push('otp/seed');
    }
  });

  // Check per-form: only flag forms that ACTUALLY contain password/card/otp inputs AND submit to an unverified external origin
  let hasCrossOriginSensitiveForm = false;
  forms.each((_, el) => {
    const action = ($(el).attr('action') || '').trim();
    if (action && /^https?:\/\//i.test(action)) {
      try {
        const actionHostname = new URL(action).hostname.toLowerCase();
        const actionHost = extractRegistrableDomain(actionHostname);
        const rel = classifyDomainRelationship(finalHost, actionHostname);
        if (actionHost !== finalRegDomain && !rel.isBenignOrAuthorized) {
          const formHasSensitive =
            $(el).find('input[type="password"]').length > 0 ||
            $(el)
              .find('input')
              .toArray()
              .some((inp) => /card[-_ ]?num|cvv|otp|2fa|seed/i.test($(inp).attr('name') || $(inp).attr('id') || ''));
          if (formHasSensitive) {
            hasCrossOriginSensitiveForm = true;
            crossOriginFormActions.push(action.slice(0, 120));
          }
        }
      } catch {
        // ignore
      }
    }
  });

  const externalDomainsSet = new Set<string>();
  const externalScriptDomainsSet = new Set<string>();
  let externalLinkCount = 0;
  let internalLinkCount = 0;
  $('a[href], img[src], script[src], link[href], iframe[src]').each((_, el) => {
    const ref = $(el).attr('href') || $(el).attr('src') || '';
    if (!ref || ref.startsWith('#') || /^javascript:/i.test(ref)) return;
    if (/^https?:\/\//i.test(ref)) {
      try {
        const h = extractRegistrableDomain(new URL(ref).hostname);
        if (h !== finalRegDomain) {
          externalDomainsSet.add(h);
          if ($(el).is('a')) externalLinkCount++;
          if ($(el).is('script')) externalScriptDomainsSet.add(h);
        } else if ($(el).is('a')) {
          internalLinkCount++;
        }
      } catch {
        // ignore
      }
    } else if ($(el).is('a')) {
      internalLinkCount++;
    }
  });

  const iframes = $('iframe');
  let hiddenElementCount = 0;
  $('[style]').each((_, el) => {
    const st = ($(el).attr('style') || '').toLowerCase();
    if (/display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0\b|left\s*:\s*-\d{3,}px/.test(st)) {
      hiddenElementCount++;
    }
  });

  let inlineScriptCount = 0;
  let externalScriptCount = 0;
  const jsIndicators: string[] = [];
  const popupIndicators: string[] = [];
  const autoRedirectIndicators: string[] = [];
  let notificationApiDetected = false;

  $('script').each((_, el) => {
    const src = $(el).attr('src');
    if (src) {
      externalScriptCount++;
    } else {
      inlineScriptCount++;
      const code = $(el).html() || '';
      for (const pat of JS_OBFUSCATION_PATTERNS) {
        if (pat.pattern.test(code)) {
          if (!jsIndicators.includes(pat.label)) jsIndicators.push(pat.label);
          if (pat.kind === 'popup' && !popupIndicators.includes(pat.label)) popupIndicators.push(pat.label);
          if (pat.kind === 'redirect' && !autoRedirectIndicators.includes(pat.label)) autoRedirectIndicators.push(pat.label);
          if (pat.label.includes('notification')) notificationApiDetected = true;
        }
      }
    }
  });

  const metaRefresh = $('meta[http-equiv="refresh" i]').attr('content');
  if (metaRefresh) {
    const label = `HTML meta-refresh redirect: ${metaRefresh.slice(0, 80)}`;
    jsIndicators.push(label);
    autoRedirectIndicators.push(label);
  }

  const combinedText = `${pageTitle} ${metaDescription || ''} ${visibleText.slice(0, 16000)}`;
  const phishingMatches: string[] = [];
  const fakeAlertIndicators: string[] = [];
  const fakeSupportIndicators: string[] = [];
  let lureWeight = 0;

  for (const rule of CONTENT_LURE_RULES) {
    if (rule.pattern.test(combinedText)) {
      phishingMatches.push(rule.label);
      lureWeight += rule.weight;
      if (rule.category === 'fake_alert' || rule.category === 'phishing_artifact') {
        fakeAlertIndicators.push(rule.label);
        if (/support|lockout/i.test(rule.label)) {
          fakeSupportIndicators.push(rule.label);
        }
      }
    }
  }

  const waitingOrInterstitialDetected = Boolean(
    metaRefresh ||
      (visibleWordCount < 140 &&
        /(?:please wait|redirecting you|loading your document|checking security|verifying your browser|يرجى الانتظار|جاري التحويل)/i.test(
          combinedText
        ))
  );

  const combinedPurposeText = `${pageTitle} ${headings.join(' ')} ${buttonLabels.join(' ')}`.toLowerCase();
  const uniquePiiFields = Array.from(new Set(personalFinanceFields));
  const claimedPurpose =
    passwordInputs.length > 0 || /(?:sign in|log in|login|authenticate|تسجيل الدخول)/i.test(combinedPurposeText)
      ? { en: 'Authentication / Sign-In Portal', ar: 'بوابة تسجيل دخول / مصادقة' }
      : uniquePiiFields.includes('payment/bank') || /(?:checkout|billing|payment|invoice|دفع|فواتير)/i.test(combinedPurposeText)
        ? { en: 'Payment / Financial Collection Page', ar: 'صفحة دفع أو جمع بيانات مالية' }
        : fakeSupportIndicators.length > 0 || /(?:help center|support|ticket|الدعم الفني)/i.test(combinedPurposeText)
          ? { en: 'Technical Support / Help Portal', ar: 'بوابة دعم فني أو مساعدة' }
          : waitingOrInterstitialDetected
            ? { en: 'Waiting / Redirect Interstitial Page', ar: 'صفحة انتظار أو إعادة توجيه' }
            : /(?:university|course|lecture|syllabus|tutorial|docs|documentation|guide|edu|أكاديمية|دورة|محاضرات)/i.test(
                  `${finalHost} ${combinedPurposeText} ${visibleText.slice(0, 600).toLowerCase()}`
                )
              ? { en: 'Educational / Documentation Resource', ar: 'محتوى تعليمي أو توثيقي' }
              : /(?:download|installer|setup|release|تحميل|تنزيل)/i.test(combinedPurposeText)
                ? { en: 'Software Download / Distribution Page', ar: 'صفحة تنزيل برامج أو ملفات' }
                : /(?:shop|store|cart|product|متجر|تسوق)/i.test(combinedPurposeText)
                  ? { en: 'E-Commerce / Storefront', ar: 'متجر إلكتروني' }
                  : { en: 'General Web Page / Application', ar: 'صفحة ويب أو تطبيق عام' };

  const hasPasswordField = passwordInputs.length > 0;
  const hasUniqueSensHints = Array.from(new Set(sensitiveInputHints));
  const suspectedBrand = detectBrandImpersonation({
    fullHost: finalHost,
    registrableDomain: finalRegDomain,
    pageTitle,
    visibleTextSample: visibleText.slice(0, 6000),
    hasCredentialFields: hasPasswordField || hasUniqueSensHints.some((h) => h !== 'password') || hasUniqueSensHints.length > 0,
    ogSiteName,
  });

  // 1. Website Content Structure Finding
  const missingTitleWithLogin = !pageTitle && hasPasswordField && !hostOwnership.matched;
  findings.push({
    id: 'content-structure',
    section: 'website_content',
    test: { en: 'HTML DOM Structure, Iframes & Metadata Integrity', ar: 'بنية HTML والإطارات واكتمال البيانات الوصفية' },
    result: {
      en: `Title: "${pageTitle || 'Missing <title>'}" · ${visibleWordCount} words · ${forms.length} form(s), ${passwordInputs.length} password field(s), ${iframes.length} iframe(s)`,
      ar: `العنوان: "${pageTitle || 'بدون عنوان <title>'}" · ${visibleWordCount} كلمة · ${forms.length} نموذج، ${passwordInputs.length} حقل مرور، ${iframes.length} إطار`,
    },
    status: missingTitleWithLogin || (visibleWordCount < 10 && iframes.length > 0 && !hostOwnership.matched) ? 'warning' : 'pass',
    severity: missingTitleWithLogin ? 'medium' : 'informational',
    weight: missingTitleWithLogin ? 10 : 0,
    evidence: `HTTP ${httpStatus} | Size: ${rawBuffer.length}B | Title: ${pageTitle || 'NONE'} | Iframes: ${iframes.length} | Hidden nodes: ${hiddenElementCount} | ExtDomains: ${externalDomainsSet.size}`,
    explanation: {
      en: missingTitleWithLogin
        ? 'The page omits a standard <title> tag while requesting a password—a pattern common in hastily built phishing templates.'
        : 'HTML structure, forms, frames, external links, and visible copy were parsed in a non-executing backend parser.',
      ar: missingTitleWithLogin
        ? 'تفتقر الصفحة إلى وسم <title> القياسي بينما تطلب كلمة مرور، وهو نمط شائع في قوالب التصيد السريعة.'
        : 'تم تحليل بنية HTML والنماذج والإطارات والروابط الخارجية في الخادم دون تنفيذ أي سكربتات.',
    },
    recommendedAction: {
      en: missingTitleWithLogin ? 'Inspect credential form and domain identity carefully.' : 'No structural action required.',
      ar: missingTitleWithLogin ? 'افحص نموذج تسجيل الدخول وهوية النطاق بعناية.' : 'لا يلزم إجراء.',
    },
    forensic: {
      whereDetected: { en: `HTML DOM of "${finalUrl}"`, ar: `بنية DOM للصفحة "${finalUrl}"` },
      whyRisky: {
        en: 'Hidden divs, zero-word iframe wrappers, or missing titles frequently hide cloaked login forms.',
        ar: 'تُستخدم الإطارات المخفية وغياب العناوين لإخفاء نماذج التصيد السريعة.',
      },
      howExploited: {
        en: 'Phishing kits load an attacker form inside a full-screen <iframe> or strip metadata to evade keyword scanners.',
        ar: 'يحمّل القالب الخبيث نموذج تسجيل دخول داخل iframe أو يحذف الوسوم القياسية لتفادي الفحص.',
      },
      userImpact: { en: 'Deceptive UI presentation.', ar: 'عرض واجهة مضللة للمستخدم.' },
      notProvenAlone: {
        en: 'Presence of iframes or external links alone is normal on modern web pages and never proves malice by itself.',
        ar: 'وجود iframes أو روابط خارجية أمر شائع في المواقع العادية ولا يثبت وحده خطراً.',
      },
    },
    source: 'SM HTML/DOM Inspector',
    timestamp: now,
    confidence: 95,
  });

  // 2. Credential Harvesting Context Evaluation
  // Only flag login/password forms as high-risk FAILED when genuinely suspicious/hostile:
  // - Cross-origin credential exfiltration to an unverified external domain, OR
  // - Non-official domain with phishing lures / fake alerts / impersonation / missing <title> / unwrapped password with phishing path or lures
  const hasCrossOriginCreds = hasCrossOriginSensitiveForm && hasPasswordField;
  const hasPhishingPathContext = urlTokens.some((t) => ['phish', 'phishing', 'update', 'verify', 'suspend', 'locked'].includes(t));
  const hasUnverifiedBrandImpersonation = Boolean(suspectedBrand && !suspectedBrand.similarityOnly);
  const paasSuspiciousCredentialSignal =
    paas.isPaas &&
    (unwrappedPasswordInputCount > 0 ||
      hasPhishingPathContext ||
      phishingMatches.length > 0 ||
      fakeAlertIndicators.length > 0 ||
      hasUnverifiedBrandImpersonation ||
      visibleWordCount < 15);
  const passwordWithRiskContext =
    hasPasswordField &&
    !hostOwnership.matched &&
    (paasSuspiciousCredentialSignal ||
      phishingMatches.length > 0 ||
      fakeAlertIndicators.length > 0 ||
      hasUnverifiedBrandImpersonation ||
      missingTitleWithLogin ||
      (unwrappedPasswordInputCount > 0 && hasPhishingPathContext));

  let credStatus: 'pass' | 'warning' | 'failed' = 'pass';
  let credSeverity: CheckFinding['severity'] = 'informational';
  let credWeight = 0;

  if (hasCrossOriginCreds) {
    credStatus = 'failed';
    credSeverity = 'critical';
    credWeight = 38;
  } else if (passwordWithRiskContext) {
    credStatus = 'failed';
    credSeverity = phishingMatches.length > 0 || fakeAlertIndicators.length > 0 || hasUnverifiedBrandImpersonation ? 'critical' : 'high';
    credWeight = credSeverity === 'critical' ? 35 : 26;
  } else if (hasUniqueSensHints.length > 0 && !hostOwnership.matched) {
    // Legitimate normal login form on a regular domain or normal PaaS web app with zero lures/impersonation:
    // Record as informational/contextual pass (weight 0) so standard login pages are never misclassified as malware/phishing.
    credStatus = paas.isPaas && hasPasswordField ? 'warning' : 'pass';
    credSeverity = 'informational';
    credWeight = 0;
  }

  findings.push({
    id: 'phishing-credential-harvesting',
    section: 'phishing_detection',
    test: { en: 'Credential & Password Harvesting Analysis', ar: 'تحليل حقول كلمات المرور وحصد البيانات' },
    result: hasCrossOriginCreds
      ? { en: 'Password form submits to an external domain', ar: 'نموذج كلمة المرور يرسل البيانات إلى نطاق خارجي' }
      : passwordWithRiskContext
        ? {
            en: `High-risk credential input (${passwordInputs.length} password field(s), ${unwrappedPasswordInputCount} outside <form>) in suspicious context`,
            ar: `حقل كلمة مرور عالي الخطورة (${passwordInputs.length} حقل، ${unwrappedPasswordInputCount} خارج <form>) ضمن سياق مشبوه`,
          }
        : hasUniqueSensHints.length > 0
          ? { en: `Sensitive inputs present (${hasUniqueSensHints.join(', ')})`, ar: `حقول إدخال حساسة (${hasUniqueSensHints.join(', ')})` }
          : { en: 'No password, payment, or OTP inputs detected', ar: 'لا توجد حقول كلمات مرور أو دفع أو رموز تحقق' },
    status: credStatus,
    severity: credSeverity,
    weight: credWeight,
    evidence: `Password fields: ${passwordInputs.length} (unwrapped in <div>: ${unwrappedPasswordInputCount}) | Username hints: ${usernameInputCount} | Sensitive: [${hasUniqueSensHints.join(', ') || 'none'}] | Cross-origin actions: [${crossOriginFormActions.join(', ') || 'none'}] | PaaS: ${paas.isPaas}`,
    explanation: {
      en: hasCrossOriginCreds
        ? 'A password input submits credentials to a third-party domain, directly exposing login secrets to an external attacker.'
        : passwordWithRiskContext
          ? 'The page collects username/password credentials outside standard form protections or alongside deceptive/PaaS/phishing context indicators.'
          : hasUniqueSensHints.length > 0
            ? 'The page requests sensitive inputs. Confirm the exact registrable domain before submitting credentials.'
            : 'No credential or payment card collection fields were detected in the retrieved HTML.',
      ar: hasCrossOriginCreds
        ? 'يرسل نموذج كلمة المرور البيانات إلى نطاق خارجي مختلف، مما يعرّض حساب المستخدم للسرقة المباشرة.'
        : passwordWithRiskContext
          ? 'تطلب الصفحة اسم مستخدم وكلمة مرور خارج نموذج قياسي أو ضمن سياق استضافة مشتركة/تصيد مشبوه.'
          : hasUniqueSensHints.length > 0
            ? 'تحتوي الصفحة على حقول حساسة؛ تحقق دائماً من النطاق الفعلي قبل إدخال بياناتك.'
            : 'لم يتم رصد حقول لجمع كلمات المرور أو بطاقات الدفع في كود HTML.',
    },
    recommendedAction: {
      en: credStatus === 'failed' ? 'Do NOT enter usernames, passwords, OTPs, or payment details on this page.' : 'Verify domain identity before authenticating.',
      ar: credStatus === 'failed' ? 'لا تدخل أي اسم مستخدم أو كلمة مرور أو رمز تحقق أو بيانات بطاقة في هذه الصفحة.' : 'تحقق من هوية النطاق قبل تسجيل الدخول.',
    },
    forensic: {
      whereDetected: {
        en: `DOM <input> & <form> nodes (${passwordInputs.length} password input(s), ${unwrappedPasswordInputCount} outside <form>)`,
        ar: `عناصر الإدخال والنماذج في HTML (${passwordInputs.length} حقل كلمة مرور، ${unwrappedPasswordInputCount} خارج <form>)`,
      },
      whyRisky: {
        en: hasCrossOriginCreds
          ? 'Form action exfiltrates typed secrets directly to a separate domain.'
          : 'Unwrapped password fields paired with social-engineering text or unverified domains indicate scripted credential exfiltration.',
        ar: hasCrossOriginCreds
          ? 'يرسل النموذج كلمة المرور مباشرة إلى خادم خارجي مختلف.'
          : 'حقول كلمة المرور غير المغلفة بنموذج أو المرتبطة بعبارات تضليل تُستخدم لالتقاط بيانات الدخول عبر سكربت خفي.',
      },
      howExploited: {
        en: 'Captured credentials are transmitted to attacker webhooks or stored for account hijacking.',
        ar: 'تُرسل البيانات المسروقة لخادم المهاجم للسيطرة على حساب الضحية أو بيانات البطاقة.',
      },
      userImpact: { en: 'Direct account compromise, MFA bypass, or financial loss.', ar: 'سرقة الحساب أو البيانات المالية فوراً.' },
      notProvenAlone: {
        en: 'A standard password form on an official, verified domain is normal; risk arises when paired with cross-origin submission, fake lures, PaaS anonymity, or brand spoofing.',
        ar: 'وجود حقل كلمة مرور في حد ذاته طبيعي في صفحات تسجيل الدخول الرسمية، وتنشأ الخطورة عند اقترانه بنطاق غير موثوق أو إرسال خارجي أو مؤشرات تضليل.',
      },
    },
    source: 'SM Phishing Credential Analyzer',
    timestamp: now,
    confidence: 94,
  });

  // 3. Social Engineering, Fake Software Alerts & Fraud Lures
  const multiIndicatorLures = phishingMatches.length >= 2 || fakeAlertIndicators.length >= 1;
  findings.push({
    id: 'phishing-social-engineering',
    section: 'phishing_detection',
    test: { en: 'Social Engineering, Fake Warnings & Fraud Lures', ar: 'الهندسة الاجتماعية والتنبيهات المزيفة وإغراءات الاحتيال' },
    result:
      phishingMatches.length > 0
        ? {
            en: `${phishingMatches.length} deceptive indicator(s): ${phishingMatches.slice(0, 2).join('; ')}`,
            ar: `تم رصد ${phishingMatches.length} مؤشر خداع أو هندسة اجتماعية`,
          }
        : { en: 'No social-engineering or fake alert patterns matched', ar: 'لم يتم رصد عبارات هندسة اجتماعية أو تنبيهات مزيفة' },
    status: multiIndicatorLures ? 'failed' : phishingMatches.length === 1 ? 'warning' : 'pass',
    severity: fakeAlertIndicators.length >= 1 && phishingMatches.length >= 2 ? 'critical' : multiIndicatorLures ? 'high' : phishingMatches.length === 1 ? 'medium' : 'informational',
    weight: Math.min(36, lureWeight),
    evidence: phishingMatches.length > 0 ? phishingMatches.join(' ; ') : 'No social engineering lures matched',
    explanation: {
      en:
        phishingMatches.length > 0
          ? `Detected indicators: ${phishingMatches.join(', ')}. Social-engineering pages imitate software updates, developer dialogues, or urgent security alerts.`
          : 'Visible page copy did not match social-engineering, fake update, or giveaway fraud patterns.',
      ar:
        phishingMatches.length > 0
          ? `تم رصد مؤشرات خداع (${phishingMatches.join('، ')}). تستخدم هذه الصفحات تحذيرات تحديث مزيفة أو استعجالاً مفتعلاً لخداع المستخدم.`
          : 'لم يحتوِ النص المرئي على أنماط تحذيرات مزيفة أو هندسة اجتماعية معروفة.',
    },
    recommendedAction: {
      en: phishingMatches.length > 0 ? 'Ignore urgent update/verification prompts on this page and close the tab.' : 'No action required.',
      ar: phishingMatches.length > 0 ? 'تجاهل أي تنبيهات تحديث أو تحقق عاجلة في هذه الصفحة وأغلقها فوراً.' : 'لا يلزم إجراء.',
    },
    forensic: {
      whereDetected: { en: 'Visible page body text and metadata', ar: 'النص المرئي والوصف داخل الصفحة' },
      whyRisky: {
        en: 'Psychological urgency and fake system dialogues pressure users into acting without verifying the URL.',
        ar: 'تضغط رسائل الاستعجال والتحديث الوهمية على المستخدم للتصرف بسرعة دون تدقيق الرابط.',
      },
      howExploited: {
        en: 'Pages display fake lockouts, prize claims, or "software out-of-date" warnings leading to credential theft or malware downloads.',
        ar: 'عرض تحذير مزيف بتعليق الحساب أو تحديث متصفح وهمي لسرقة كلمة المرور أو تحميل ملف ضار.',
      },
      userImpact: { en: 'Credential loss, scam payments, or trojan installation.', ar: 'فقدان الحساب أو الاحتيال المالي أو تثبيت برمجية خبيثة.' },
      notProvenAlone: {
        en: 'Educational security pages discussing phishing terminology can match text keywords; correlate with password inputs and threat feeds.',
        ar: 'قد تتطابق بعض المقالات التوعوية مع الكلمات المفتاحية؛ لذا يتم الربط مع وجود حقول إدخال ومصادر أخرى.',
      },
    },
    source: 'SM Social Engineering Detector',
    timestamp: now,
    confidence: phishingMatches.length > 0 ? 92 : 85,
  });

  // 4. Brand Impersonation / Brand Similarity
  const brandSimOnly = Boolean(suspectedBrand?.similarityOnly);
  const brandConfirmedImpersonation = Boolean(suspectedBrand && !suspectedBrand.similarityOnly);
  findings.push({
    id: 'brand-impersonation',
    section: 'brand_impersonation',
    test: { en: 'Brand Impersonation & Visual Identity Check', ar: 'فحص انتحال العلامات التجارية والهوية' },
    result: brandConfirmedImpersonation && suspectedBrand
      ? {
          en: `Possible impersonation of ${suspectedBrand.brand} (${suspectedBrand.confidence}% confidence)`,
          ar: `اشتباه بانتحال علامة ${suspectedBrand.brand} (ثقة ${suspectedBrand.confidence}%)`,
        }
      : brandSimOnly && suspectedBrand
        ? {
            en: `Domain name similarity to ${suspectedBrand.brand} detected; impersonation has not been proven`,
            ar: 'تم اكتشاف تشابه في اسم النطاق مع علامة تجارية معروفة، ولم يتم إثبات الانتحال',
          }
        : { en: 'No targeted brand impersonation detected', ar: 'لم يتم رصد انتحال لعلامات تجارية معروفة' },
    status: brandConfirmedImpersonation ? 'failed' : brandSimOnly ? 'warning' : 'pass',
    severity: brandConfirmedImpersonation ? 'high' : brandSimOnly ? 'medium' : 'informational',
    weight: brandConfirmedImpersonation ? 28 : brandSimOnly ? 8 : 0,
    evidence: suspectedBrand
      ? `Brand: ${suspectedBrand.brand} | Official: ${suspectedBrand.officialDomain} | SimilarityOnly: ${brandSimOnly} | Signals: ${suspectedBrand.evidence.join(' ; ')}`
      : 'No mismatch against local brand intelligence database',
    explanation: {
      en: brandConfirmedImpersonation && suspectedBrand
        ? `Page identity or credentials claim "${suspectedBrand.brand}" while hosted on "${finalRegDomain}" instead of official "${suspectedBrand.officialDomain}".`
        : brandSimOnly && suspectedBrand
          ? `Domain name resembles "${suspectedBrand.brand}" (${suspectedBrand.officialDomain}), without credential harvesting or page-title impersonation evidence.`
          : 'Domain spelling and page references did not trigger impersonation rules against monitored official brands.',
      ar: brandConfirmedImpersonation && suspectedBrand
        ? `تشير الصفحة إلى علامة "${suspectedBrand.brand}" بينما النطاق الفعلي هو "${finalRegDomain}" بدلاً من النطاق الرسمي "${suspectedBrand.officialDomain}".`
        : brandSimOnly
          ? 'تم اكتشاف تشابه في اسم النطاق مع علامة تجارية معروفة، ولم يتم إثبات الانتحال عبر محتوى الصفحة.'
          : 'لم تُظهر الصفحة مؤشرات انتحال ضد قاعدة بيانات العلامات التجارية الرسمية.',
    },
    recommendedAction: {
      en: suspectedBrand ? `Navigate directly to ${suspectedBrand.officialDomain} if seeking the official brand.` : 'No action required.',
      ar: suspectedBrand ? `توجه مباشرة إلى (${suspectedBrand.officialDomain}) إذا كنت تقصد الخدمة الرسمية.` : 'لا يلزم إجراء.',
    },
    source: 'SM Brand Intelligence DB',
    timestamp: now,
    confidence: suspectedBrand ? suspectedBrand.confidence : 82,
  });

  // 5. JavaScript Static Analysis (Obfuscation, Popups, Auto-Redirects, Notifications, External Scripts)
  const highRiskJs = jsIndicators.some((j) => j.includes('Obfuscated') || j.includes('Encoded') || j.includes('Hex-encoded'));
  const hasRealJsWarning = !hostOwnership.matched && jsIndicators.some((j) => j.includes('Exit-trap') || j.includes('DevTools blocking'));
  findings.push({
    id: 'js-static-analysis',
    section: 'javascript_analysis',
    test: { en: 'Static JavaScript, Popups & Auto-Redirect Inspection', ar: 'الفحص الساكن لـ JavaScript والنوافذ والتوجيه التلقائي' },
    result:
      highRiskJs || hasRealJsWarning
        ? {
            en: `${jsIndicators.length} script indicator(s): ${jsIndicators.slice(0, 2).join('; ')}`,
            ar: `رصد ${jsIndicators.length} مؤشر في السكربتات والتوجيه التلقائي`,
          }
        : {
            en: `${inlineScriptCount} inline, ${externalScriptCount} external script(s) (${externalScriptDomainsSet.size} ext origin(s)) — no obfuscation`,
            ar: `${inlineScriptCount} سكربت داخلي، ${externalScriptCount} خارجي (${externalScriptDomainsSet.size} مصدر) — لا تشويش`,
          },
    status: highRiskJs ? 'failed' : hasRealJsWarning ? 'warning' : 'pass',
    severity: highRiskJs ? 'high' : hasRealJsWarning ? 'low' : 'informational',
    weight: highRiskJs ? 20 : hasRealJsWarning ? 4 : 0,
    evidence: `${jsIndicators.length > 0 ? `Indicators: [${jsIndicators.join('; ')}] | ` : ''}Inline: ${inlineScriptCount} | External: ${externalScriptCount} | ExtScriptDomains: [${Array.from(externalScriptDomainsSet).slice(0, 8).join(', ') || 'none'}]`,
    explanation: {
      en:
        highRiskJs || hasRealJsWarning
          ? 'Static script inspection detected obfuscation or encoded injection patterns without executing target code.'
          : 'Inline script inspection found no malicious obfuscation or encoded injection signatures (standard navigation APIs excluded).',
      ar:
        highRiskJs || hasRealJsWarning
          ? 'رصد التحليل الساكن أنماط تشويش برمجي أو حقن مشفر في السكربتات دون تنفيذها.'
          : 'لم يتم العثور على أنماط تشويش خبيثة في السكربتات المضمنة.',
    },
    recommendedAction: {
      en: highRiskJs ? 'Avoid interacting with heavily obfuscated scripts on unverified pages.' : 'No action required.',
      ar: highRiskJs ? 'تجنب التفاعل مع الصفحات التي تستخدم سكربتات مشوشة بشكل مريب.' : 'لا يلزم إجراء.',
    },
    forensic: {
      whereDetected: {
        en: `Inline <script> & <meta http-equiv="refresh"> tags (${externalScriptDomainsSet.size} third-party script host(s))`,
        ar: `وسوم <script> المضمنة و <meta refresh> (${externalScriptDomainsSet.size} مصدر سكربت خارجي)`,
      },
      whyRisky: {
        en: 'Obfuscated JavaScript conceals credential exfiltration endpoints or dynamic phishing DOM injection from signature scanners.',
        ar: 'يُخفي الجافاسكربت المشوش روابط إرسال البيانات المسروقة أو يولد نموذج التصيد ديناميكياً لتفادي الفحص.',
      },
      howExploited: {
        en: 'At runtime, decoded eval() payloads inject fake login overlays, hook form submits, or trap browsers with forced popups.',
        ar: 'عند التشغيل يفك السكربت شفرة نموذج مزيف أو يمنع إغلاق الصفحة أو يرسل كلمات المرور في الخلفية.',
      },
      userImpact: { en: 'Stealth script execution or forced malicious redirects.', ar: 'تشغيل كود خفي أو نقل المستخدم لمواقع غير مرغوبة.' },
      notProvenAlone: {
        en: 'Standard navigation, window.open, clipboard, or meta-refresh calls are normal web APIs and never prove malice alone.',
        ar: 'استدعاءات المتصفح القياسية مثل window.open أو الحافظة طبيعية في تطبيقات الويب الحديثة ولا تثبت وحدها خطراً.',
      },
    },
    source: 'SM Static JS Analyzer',
    timestamp: now,
    confidence: 86,
  });

  // 6. Browser Site Permissions Audit: On-Entry Trigger Detection & Stated-Usage Consistency Verification
  const inlineScriptEntries = $('script:not([src])')
    .map((idx, el) => ({ source: `inline-script#${idx + 1}`, code: $(el).html() || '' }))
    .get()
    .filter((entry) => entry.code.trim().length > 0);
  const allInlineJs = inlineScriptEntries.map((e) => e.code).join('\n');
  const inspectableScriptEntries = [
    ...inlineScriptEntries,
    ...externalScripts.map((s) => ({ source: s.url, code: s.code || '' })).filter((s) => s.code.trim().length > 0),
  ];

  const siteContextText = `${pageTitle} ${metaDescription || ''} ${headings.join(' ')} ${buttonLabels.join(' ')} ${visibleText.slice(0, 6000)}`.toLowerCase();
  const hasDeceptivePermissionBait =
    /(?:(?:click|press|tap)\s+['"]?allow['"]?\s+(?:to\s+(?:continue|verify|prove|watch|download|unblock|proceed)|if\s+you\s+are\s+(?:human|not\s+a\s+robot))|verify\s+you\s+are\s+(?:human|not\s+a\s+robot)[\s\S]{0,80}allow|allow\s+notifications?\s+to\s+(?:continue|download|watch|verify)|اضغط\s+(?:على\s+)?سماح\s+(?:للمتابعة|للتحقق|للتنزيل))/i.test(
      siteContextText
    );

  interface PermissionRuleDef {
    id: string;
    pattern: RegExp;
    api: string;
    label: { en: string; ar: string };
    legitimateContextPattern: RegExp | null;
    alwaysIntrusiveOnEntry?: boolean;
  }

  const PERMISSION_RULES: PermissionRuleDef[] = [
    {
      id: 'notifications',
      pattern: /Notification\.requestPermission\s*\(|pushManager\.subscribe\s*\(/gi,
      api: 'Notification.requestPermission / PushManager',
      label: { en: 'Push Notifications', ar: 'الإشعارات الفورية (Notifications)' },
      legitimateContextPattern: /\b(?:subscribe|notification\s*settings|enable\s*alerts|breaking\s*news\s*alerts|push\s*updates|تفعيل\s*الإشعارات|إشعارات\s*الأخبار)\b/i,
    },
    {
      id: 'geolocation',
      pattern: /navigator\.geolocation\.(?:getCurrentPosition|watchPosition)\s*\(/gi,
      api: 'navigator.geolocation.getCurrentPosition',
      label: { en: 'Precise Geolocation', ar: 'الموقع الجغرافي الدقيق (Geolocation)' },
      legitimateContextPattern: /\b(?:map|maps|directions|weather|forecast|store\s*locator|near\s*me|nearby|delivery|pickup|ride|gps|find\s*branch|خريطة|الطقس|التوصيل|أقرب\s*فرع|تحديد\s*الموقع)\b/i,
    },
    {
      id: 'camera_mic',
      pattern: /navigator\.mediaDevices\.getUserMedia\s*\(/gi,
      api: 'navigator.mediaDevices.getUserMedia',
      label: { en: 'Camera / Microphone', ar: 'الكاميرا والميكروفون (Camera / Mic)' },
      legitimateContextPattern: /\b(?:video\s*call|meeting|webinar|conference|webcam|camera\s*test|mic\s*test|qr\s*scan|voice\s*chat|audio\s*recorder|photo\s*booth|telehealth|livestream|كاميرا|ميكروفون|مكالمة|اجتماع|بث\s*مباشر|مسح\s*الرمز)\b/i,
    },
    {
      id: 'screen_capture',
      pattern: /navigator\.mediaDevices\.getDisplayMedia\s*\(/gi,
      api: 'navigator.mediaDevices.getDisplayMedia',
      label: { en: 'Screen Capture / Recording', ar: 'تصوير ومشاركة الشاشة (Screen Capture)' },
      legitimateContextPattern: /\b(?:screen\s*shar|screen\s*record|present\s*screen|meeting|webinar|remote\s*desktop|مشاركة\s*الشاشة|تسجيل\s*الشاشة)\b/i,
    },
    {
      id: 'clipboard_read',
      pattern: /navigator\.clipboard\.(?:read|readText)\s*\(/gi,
      api: 'navigator.clipboard.readText',
      label: { en: 'Clipboard Read Access', ar: 'قراءة الحافظة (Clipboard Read)' },
      legitimateContextPattern: /\b(?:paste\s*from\s*clipboard|paste\s*button|import\s*clipboard|لصق\s*من\s*الحافظة)\b/i,
      alwaysIntrusiveOnEntry: true,
    },
    {
      id: 'clipboard_write',
      pattern: /navigator\.clipboard\.(?:write|writeText)\s*\(/gi,
      api: 'navigator.clipboard.writeText',
      label: { en: 'Clipboard Write Access', ar: 'الكتابة في الحافظة (Clipboard Write)' },
      legitimateContextPattern: /\b(?:copy|share|snippet|invite\s*link|referral|نسخ|مشاركة)\b/i,
    },
    {
      id: 'usb',
      pattern: /navigator\.usb\.requestDevice\s*\(/gi,
      api: 'navigator.usb.requestDevice',
      label: { en: 'WebUSB Hardware Access', ar: 'الوصول لأجهزة USB (WebUSB)' },
      legitimateContextPattern: /\b(?:firmware|flasher|arduino|esp32|adb|fastboot|usb\s*device|hardware\s*wallet|تحديث\s*الجهاز)\b/i,
    },
    {
      id: 'bluetooth',
      pattern: /navigator\.bluetooth\.requestDevice\s*\(/gi,
      api: 'navigator.bluetooth.requestDevice',
      label: { en: 'WebBluetooth Access', ar: 'أجهزة البلوتوث (WebBluetooth)' },
      legitimateContextPattern: /\b(?:bluetooth|ble\s*device|pair\s*sensor|smartwatch|ecg|بلوتوث|اقتران\s*جهاز)\b/i,
    },
    {
      id: 'hid_serial',
      pattern: /navigator\.(?:hid|serial)\.request(?:Device|Port)\s*\(/gi,
      api: 'navigator.hid / navigator.serial',
      label: { en: 'WebHID / Serial Port Access', ar: 'منافذ HID / Serial' },
      legitimateContextPattern: /\b(?:serial\s*terminal|baud|com\s*port|firmware|gamepad\s*config|keyboard\s*remap|منفذ\s*تسلسلي)\b/i,
    },
    {
      id: 'midi',
      pattern: /navigator\.requestMIDIAccess\s*\(/gi,
      api: 'navigator.requestMIDIAccess',
      label: { en: 'WebMIDI Device Access', ar: 'أجهزة الصوت MIDI' },
      legitimateContextPattern: /\b(?:midi|synthesizer|daw|piano|audio\s*studio|موسيقى|ميديا)\b/i,
    },
    {
      id: 'sensors_wakelock',
      pattern: /(?:DeviceMotionEvent|DeviceOrientationEvent)\.requestPermission\s*\(|navigator\.wakeLock\.request\s*\(/gi,
      api: 'DeviceMotion / Orientation / WakeLock',
      label: { en: 'Device Sensors / WakeLock', ar: 'مستشعرات الحركة وبقاء الشاشة' },
      legitimateContextPattern: /\b(?:compass|gyro|vr|ar\s*view|step\s*counter|video\s*player|presentation|timer|بوصلة|واقع\s*معزز|مشغل\s*فيديو)\b/i,
    },
  ];

  const userGestureRegex = /(?:addEventListener\s*\(\s*['"](?:click|pointerdown|pointerup|mousedown|mouseup|touchstart|touchend|submit|keydown)['"]|\.onclick\s*=|\.onsubmit\s*=|\bonClick\s*[=:]|function\s+(?:handle|on)[A-Za-z0-9_]*(?:Click|Submit|Copy|Paste|Start|Record|Connect|Locate|Subscribe)\b)/gi;
  const autoEntryRegex = /(?:DOMContentLoaded|window\.onload|addEventListener\s*\(\s*['"]load['"]|\$\(\s*document\s*\)\.ready|useEffect\s*\(|setTimeout\s*\(|setInterval\s*\(|\(\s*(?:async\s+)?function\s*\(\s*\)\s*\{|\(\s*(?:async\s+)?\(\s*\)\s*=>\s*\{)/gi;

  const detectedPermissionEntries: NonNullable<ContentInspectionData['permissionAudit']>['permissions'] = [];
  const entryTriggerEvidence: string[] = [];

  const isAuthOrUnrelatedStatedPage =
    passwordInputs.length > 0 ||
    waitingOrInterstitialDetected ||
    visibleWordCount < 20 ||
    phishingMatches.length > 0 ||
    /(?:Software Download|Technical Support|Payment|Waiting \/ Redirect)/i.test(claimedPurpose.en);

  const astPermAnalysis = analyzeScriptsWithAst(inspectableScriptEntries.map((e) => ({ source: e.source, code: e.code })));

  for (const rule of PERMISSION_RULES) {
    let matchedInCode = false;
    let triggeredOnEntry = false;
    let triggerSource = '';

    // 1. Prefer AST Call-Graph Permission Site Detection (accurate helper-function click tracing)
    const astMatchedSites = astPermAnalysis.permissionSites.filter((site) => {
      rule.pattern.lastIndex = 0;
      const apiToken = site.api.replace(/\s+/g, '');
      return rule.pattern.test(`${apiToken}()`) || (rule.id === 'hid_serial' && /navigator\.(?:hid|serial)/i.test(site.api)) || (rule.id === 'sensors_wakelock' && /(?:DeviceMotion|DeviceOrientation|wakeLock)/i.test(site.api));
    });

    if (astMatchedSites.length > 0) {
      matchedInCode = true;
      const entrySite = astMatchedSites.find((s) => s.triggeredOnEntry);
      if (entrySite) {
        triggeredOnEntry = true;
        triggerSource = `${entrySite.sourceScript} [${entrySite.sourceFunction}]: ${entrySite.triggerDescription}`;
      } else {
        triggeredOnEntry = false;
        const clickSite = astMatchedSites[0];
        triggerSource = `${clickSite.sourceScript} [${clickSite.sourceFunction}]: ${clickSite.triggerDescription}`;
      }
    } else if (astPermAnalysis.scriptsFallback > 0) {
      // Fallback only when a script could not be parsed by acorn AST
      for (const entry of inspectableScriptEntries) {
        rule.pattern.lastIndex = 0;
        const match = rule.pattern.exec(entry.code);
        if (!match) continue;
        matchedInCode = true;

        const beforeWindow = entry.code.slice(Math.max(0, match.index - 450), match.index);
        userGestureRegex.lastIndex = 0;
        let lastUserGestureIdx = -1;
        let gMatch: RegExpExecArray | null;
        while ((gMatch = userGestureRegex.exec(beforeWindow)) !== null) {
          lastUserGestureIdx = gMatch.index;
        }

        autoEntryRegex.lastIndex = 0;
        let lastAutoEntryIdx = -1;
        let aMatch: RegExpExecArray | null;
        while ((aMatch = autoEntryRegex.exec(beforeWindow)) !== null) {
          lastAutoEntryIdx = aMatch.index;
        }

        const isAutoCall =
          lastUserGestureIdx === -1 ||
          lastAutoEntryIdx > lastUserGestureIdx ||
          Boolean(rule.alwaysIntrusiveOnEntry && lastUserGestureIdx === -1);

        if (isAutoCall) {
          triggeredOnEntry = true;
          triggerSource =
            lastAutoEntryIdx !== -1
              ? `${entry.source}: auto-load / timer / mount hook`
              : `${entry.source}: top-level script execution on entry`;
          break;
        } else {
          triggerSource = `${entry.source}: bound to user-click / interaction handler`;
        }
      }
    }

    if (!matchedInCode) continue;

    const contextMatches = Boolean(rule.legitimateContextPattern && rule.legitimateContextPattern.test(siteContextText));
    const hasDeceptiveActionLure =
      !contextMatches &&
      !triggeredOnEntry &&
      /\b(?:fast\s*download|download\s*now|direct\s*download|continue\s*to\s*file|verify\s*to\s*unlock|unlock\s*link|start\s*download|تحميل\s*سريع|تنزيل\s*الآن|تحقق\s*للمتابعة)\b/i.test(
        `${buttonLabels.join(' ')} ${headings.join(' ')}`
      );
    let consistentWithSitePurpose = contextMatches && !hasDeceptivePermissionBait && !waitingOrInterstitialDetected;

    if (rule.id === 'notifications' && (triggeredOnEntry || hasDeceptivePermissionBait)) {
      // Prompting for browser notifications immediately on page entry or with deceptive coercion is never legitimate site usage
      consistentWithSitePurpose = false;
    }
    if ((rule.id === 'camera_mic' || rule.id === 'screen_capture' || rule.id === 'geolocation' || rule.id === 'clipboard_read') && isAuthOrUnrelatedStatedPage && !contextMatches) {
      consistentWithSitePurpose = false;
    }
    if (triggeredOnEntry && !contextMatches) {
      consistentWithSitePurpose = false;
    }

    if (triggeredOnEntry) {
      entryTriggerEvidence.push(`STATIC_AUTO_TRIGGER_ON_LOAD: ${rule.label.en} (${triggerSource})`);
    } else if (hasDeceptiveActionLure) {
      entryTriggerEvidence.push(`DECEPTIVE_INTERACTION_TRIGGER: ${rule.label.en} (${triggerSource})`);
    }

    const reason: { en: string; ar: string } = !consistentWithSitePurpose
      ? hasDeceptivePermissionBait
        ? {
            en: `Page uses deceptive coercion ("click Allow to continue/verify") to obtain ${rule.label.en}, which contradicts genuine site utility.`,
            ar: `تستخدم الصفحة عبارات تضليلية ("اضغط سماح للمتابعة أو التحقق") لانتزاع إذن ${rule.label.ar}، مما يكشف عدم صحة الاستخدام المعلن.`,
          }
        : hasDeceptiveActionLure
          ? {
              en: `DECEPTIVE_INTERACTION_TRIGGER: ${rule.label.en} is wired to a deceptive action/download button (${buttonLabels.slice(0, 2).join(', ') || 'UI lure'}) unrelated to stated site purpose.`,
              ar: `محفّز تفاعل خادع (DECEPTIVE_INTERACTION_TRIGGER): يرتبط طلب ${rule.label.ar} بزر تنزيل أو تحقق خادع لا يتوافق مع الوظيفة المعلنة.`,
            }
          : triggeredOnEntry
            ? {
                en: `STATIC_AUTO_TRIGGER_ON_LOAD: Requests ${rule.label.en} immediately on page entry while stated site purpose (${claimedPurpose.en}) lacks matching functional justification.`,
                ar: `محفّز تشغيل تلقائي (STATIC_AUTO_TRIGGER_ON_LOAD): يطلب إذن ${rule.label.ar} تلقائياً فور دخول الموقع بينما الغرض المعلن (${claimedPurpose.ar}) لا يبرر هذا الإذن.`,
              }
            : {
                en: `Requests ${rule.label.en} without corresponding functional context in stated site content (${claimedPurpose.en}).`,
                ar: `يطلب إذن ${rule.label.ar} دون وجود مبرر وظيفي مطابق في المحتوى المعلن للموقع (${claimedPurpose.ar}).`,
              }
      : {
          en: `Requested permission aligns with stated site context (${claimedPurpose.en}) via user interaction.`,
          ar: `يتوافق الإذن المطلوب مع الوظيفة المعلنة في الموقع (${claimedPurpose.ar}) عبر تفاعل صريح من المستخدم.`,
        };

    detectedPermissionEntries.push({
      id: rule.id,
      label: rule.label,
      api: rule.api,
      triggeredOnEntry,
      triggerContext: triggeredOnEntry
        ? { en: 'STATIC_AUTO_TRIGGER_ON_LOAD · Automatic on site entry / page load', ar: 'STATIC_AUTO_TRIGGER_ON_LOAD · تلقائي فور دخول الموقع' }
        : hasDeceptiveActionLure
          ? { en: 'DECEPTIVE_INTERACTION_TRIGGER · Disguised behind download/verify button', ar: 'DECEPTIVE_INTERACTION_TRIGGER · مخفي خلف زر تنزيل أو تحقق خادع' }
          : { en: 'Triggered by explicit user action', ar: 'يُطلب عند تفاعل المستخدم فقط' },
      consistentWithSitePurpose,
      reason,
    });
  }

  // Also detect <iframe allow="camera; microphone; geolocation; ..."> delegation attributes
  $('iframe[allow]').each((_, el) => {
    const allowAttr = ($(el).attr('allow') || '').toLowerCase();
    const sensitiveTokens = ['camera', 'microphone', 'geolocation', 'display-capture', 'clipboard-read', 'usb', 'serial', 'hid']
      .filter((t) => allowAttr.includes(t));
    if (sensitiveTokens.length > 0) {
      const labelEn = `Iframe Permission Delegation (${sensitiveTokens.join(', ')})`;
      const already = detectedPermissionEntries.some((p) => p.id === 'iframe_allow');
      if (!already) {
        const contextOk = sensitiveTokens.every((t) => {
          if (t === 'camera' || t === 'microphone') return /\b(?:call|meeting|webcam|video|كاميرا|مكالمة)\b/i.test(siteContextText);
          if (t === 'geolocation') return /\b(?:map|weather|delivery|خريطة)\b/i.test(siteContextText);
          return false;
        }) && !hasDeceptivePermissionBait && !waitingOrInterstitialDetected;
        detectedPermissionEntries.push({
          id: 'iframe_allow',
          label: { en: labelEn, ar: `تفويض صلاحيات داخل إطار iframe (${sensitiveTokens.join('، ')})` },
          api: `<iframe allow="${allowAttr.slice(0, 80)}">`,
          triggeredOnEntry: true,
          triggerContext: { en: 'Embedded iframe loads with elevated permission policy on entry', ar: 'إطار مضمّن مهيأ بصلاحيات حساسة فور دخول الصفحة' },
          consistentWithSitePurpose: contextOk,
          reason: contextOk
            ? { en: 'Iframe permissions match embedded media/map context.', ar: 'صلاحيات الإطار تتوافق مع وظيفة الوسائط أو الخريطة المعلنة.' }
            : { en: 'Embedded iframe requests elevated hardware/location access unrelated to stated site content.', ar: 'يطلب الإطار المضمّن صلاحيات أجهزة أو موقع غير متطابقة مع المحتوى المعلن للموقع.' },
        });
        entryTriggerEvidence.push(`${labelEn} (iframe allow attribute on load)`);
      }
    }
  });

  const requestedPermissions = detectedPermissionEntries.map((p) => p.label.en);
  const anyTriggeredOnEntry = detectedPermissionEntries.some((p) => p.triggeredOnEntry);
  const allUsageConsistent =
    detectedPermissionEntries.length === 0 ||
    (detectedPermissionEntries.every((p) => p.consistentWithSitePurpose) && !hasDeceptivePermissionBait);
  const escalatePermissionRiskToHigh =
    detectedPermissionEntries.length > 0 && (anyTriggeredOnEntry || !allUsageConsistent || hasDeceptivePermissionBait);

  const usageVerificationVerdict: { en: string; ar: string } =
    detectedPermissionEntries.length === 0
      ? {
          en: 'No browser permission prompts detected.',
          ar: 'لم يطلب الموقع أي أذونات متصفح حساسة.',
        }
      : allUsageConsistent && !anyTriggeredOnEntry
        ? {
            en: `Stated usage matches context (${claimedPurpose.en}) and triggers only on explicit user action.`,
            ar: `الاستخدام المعلن في الموقع صحيح ومتطابق مع الوظيفة (${claimedPurpose.ar}) ولا يطلب الإذن تلقائياً عند الدخول.`,
          }
        : {
            en: anyTriggeredOnEntry && !allUsageConsistent
              ? `Deceptive / Unjustified On-Entry Permissions: Site automatically requests ${requestedPermissions.join(', ')} upon entry while its stated purpose (${claimedPurpose.en}) does not truthfully match or justify them — escalated to HIGH RISK.`
              : anyTriggeredOnEntry
                ? `Intrusive On-Entry Permission Request: Site requests ${requestedPermissions.join(', ')} immediately upon loading without waiting for user intent — escalated to HIGH RISK.`
                : `Stated Usage Mismatch: Site requests ${requestedPermissions.join(', ')} inconsistent with its claimed purpose (${claimedPurpose.en}) — escalated to HIGH RISK.`,
            ar: anyTriggeredOnEntry && !allUsageConsistent
              ? `تناقض في الاستخدام المعلن وطلب فوري عند الدخول: يطلب الموقع أذونات (${detectedPermissionEntries.map((p) => p.label.ar).join('، ')}) بمجرد الدخول بينما الوصف والاستخدام المعلن في الموقع (${claimedPurpose.ar}) غير صحيح ولا يبررها — تم رفع مستوى الخطورة إلى مرتفعة.`
              : anyTriggeredOnEntry
                ? `طلب أذونات تلقائياً فور دخول الموقع: يبادر الموقع بطلب (${detectedPermissionEntries.map((p) => p.label.ar).join('، ')}) بمجرد فتح الصفحة وقبل تفاعل المستخدم — تم رفع مستوى الفحص إلى خطورة مرتفعة.`
                : `عدم تطابق الاستخدام المعلن: الأذونات المطلوبة (${detectedPermissionEntries.map((p) => p.label.ar).join('، ')}) لا تتوافق مع الاستخدام المعلن للموقع (${claimedPurpose.ar}) — تم رفع مستوى الفحص إلى خطورة مرتفعة.`,
          };

  const permissionAudit: ContentInspectionData['permissionAudit'] =
    detectedPermissionEntries.length > 0 || permPolicyHeaderCheck(headers, $)
      ? {
          permissions: detectedPermissionEntries,
          triggeredOnEntry: anyTriggeredOnEntry,
          entryTriggerEvidence,
          statedPurposeSummary: claimedPurpose,
          statedUsageConsistent: allUsageConsistent,
          usageVerificationVerdict,
          riskEscalatedToHigh: escalatePermissionRiskToHigh,
        }
      : undefined;

  const permPolicyHeader = headers['permissions-policy'] || $('meta[http-equiv="Permissions-Policy" i]').attr('content');
  const sensitivePermCount = detectedPermissionEntries.filter((p) =>
    /notifications|geolocation|camera|screen|clipboard|usb|bluetooth|hid|iframe/i.test(p.id)
  ).length;

  findings.push({
    id: 'content-permissions-audit',
    section: 'javascript_analysis',
    test: {
      en: 'Browser Permissions, On-Entry Triggers & Stated Usage Verification',
      ar: 'فحص أذونات المتصفح عند الدخول والتحقق من صحة الاستخدام المعلن',
    },
    result:
      detectedPermissionEntries.length > 0
        ? escalatePermissionRiskToHigh
          ? {
              en: `HIGH RISK: ${detectedPermissionEntries.length} permission(s) (${requestedPermissions.join(', ')}) — ${anyTriggeredOnEntry ? 'auto-requested on entry' : 'user-triggered'}, ${allUsageConsistent ? 'no user intent gate' : 'stated site usage does NOT match'}`,
              ar: `خطورة مرتفعة: يطلب الموقع ${detectedPermissionEntries.length} إذن (${detectedPermissionEntries.map((p) => p.label.ar).join('، ')}) ${anyTriggeredOnEntry ? 'بمجرد الدخول' : ''} — ${allUsageConsistent ? 'دون انتظار تفاعل المستخدم' : 'الاستخدام المعلن في الموقع غير صحيح أو غير متطابق'}`,
            }
          : {
              en: `${detectedPermissionEntries.length} permission API(s) detected via user action and consistent with stated purpose`,
              ar: `رصد ${detectedPermissionEntries.length} إذن متصفح متوافق مع الاستخدام المعلن ويُطلب عند التفاعل فقط`,
            }
        : {
            en: `No intrusive permission APIs detected in inspected scripts${permPolicyHeader ? ' · Permissions-Policy enforced' : ''}`,
            ar: `لم تُرصد طلبات أذونات حساسة في السكربتات المفحوصة${permPolicyHeader ? ' · ترويسة Permissions-Policy مفعلة' : ''}`,
          },
    status: escalatePermissionRiskToHigh ? 'failed' : 'pass',
    severity: escalatePermissionRiskToHigh ? 'high' : 'informational',
    weight: escalatePermissionRiskToHigh ? 34 : 0,
    evidence: `Detected APIs: [${requestedPermissions.join(', ') || 'none'}] | OnEntry: ${anyTriggeredOnEntry} | UsageConsistent: ${allUsageConsistent} | EscalateHigh: ${escalatePermissionRiskToHigh} | ClaimedPurpose: ${claimedPurpose.en} | Permissions-Policy: ${permPolicyHeader ? permPolicyHeader.slice(0, 120) : 'Missing'}`,
    explanation: {
      en:
        detectedPermissionEntries.length > 0
          ? usageVerificationVerdict.en
          : 'No intrusive device permission requests (camera, mic, geolocation, USB, notifications, clipboard hijacking) were detected.',
      ar:
        detectedPermissionEntries.length > 0
          ? usageVerificationVerdict.ar
          : 'لم يتم رصد طلبات صلاحيات متصفح متطفلة (مثل الكاميرا، الميكروفون، الموقع، الحافظة، أو الإشعارات).',
    },
    recommendedAction: {
      en: escalatePermissionRiskToHigh
        ? 'Leave the site or block all browser permission popups (Camera, Mic, Location, Notifications, Clipboard) immediately; the request occurs on entry or contradicts the stated website purpose.'
        : detectedPermissionEntries.length > 0
          ? 'Verify you intentionally triggered the feature before granting any browser permission.'
          : 'No permission action required.',
      ar: escalatePermissionRiskToHigh
        ? 'ارفض فوراً جميع نوافذ الأذونات (الكاميرا، الميكروفون، الموقع، الإشعارات، الحافظة) وغادر الصفحة؛ الموقع يطلبها عند الدخول مباشرة أو يقدّم تبريراً غير صحيح.'
        : detectedPermissionEntries.length > 0
          ? 'تأكد من أنك فعّلت الميزة عن قصد قبل الموافقة على أي إذن.'
          : 'لا يلزم إجراء.',
    },
    forensic: {
      whereDetected: {
        en: entryTriggerEvidence.length > 0
          ? entryTriggerEvidence.join(' ; ')
          : `HTML/JS script handlers (${inspectableScriptEntries.length} script block(s) inspected)`,
        ar: entryTriggerEvidence.length > 0
          ? `تم الرصد في: ${entryTriggerEvidence.join(' ؛ ')}`
          : `فحص ${inspectableScriptEntries.length} مقطع سكربت مضمّن وخارجي`,
      },
      whyRisky: {
        en: 'Malicious or deceptive websites trigger permission dialogs immediately upon landing or fabricate explanations ("verify you are human" / unrelated tools) to hijack notifications, camera/mic streams, location tracking, or clipboard contents.',
        ar: 'تستغل المواقع الخبيثة طلب الأذونات فور دخول الصفحة أو تدعي استخداماً غير حقيقي ("اضغط سماح للتحقق" أو وظيفة غير موجودة) لإرسال إشعارات احتيالية أو الوصول للكاميرا والموقع أو قراءة الحافظة.',
      },
      howExploited: {
        en: 'Once granted, Push Notifications deliver persistent OS-level malware/scam popups even after closing the tab; geolocation exposes physical location; getUserMedia accesses camera/mic.',
        ar: 'بمجرد الموافقة، تبث الإشعارات تنبيهات احتيالية مستمرة حتى بعد إغلاق التبويب، ويكشف الموقع الجغرافي مكانك، وتصل الكاميرا والميكروفون للوسائط.',
      },
      userImpact: {
        en: 'Privacy breach, persistent spam notifications, location disclosure, or unauthorized media/clipboard capture.',
        ar: 'انتهاك الخصوصية، إشعارات احتيالية دائمة، كشف الموقع الفعلي، أو الوصول غير المصرح للكاميرا والحافظة.',
      },
      notProvenAlone: {
        en: 'Legitimate video conferencing, maps, or copy-to-clipboard buttons request permissions strictly upon explicit user interaction and match the visible page functionality.',
        ar: 'المواقع الموثوقة كالاجتماعات والخرائط تطلب الإذن فقط عند ضغط المستخدم على الزر وبما يتوافق بوضوح مع وظيفة الصفحة المعلنة.',
      },
    },
    source: 'SM Permissions & Context Verifier',
    timestamp: now,
    confidence: escalatePermissionRiskToHigh ? 95 : 92,
  });

  // 7. Automatic / Drive-By File Download & HTML Smuggling Detector
  const autoDownloadTriggers: string[] = [];
  const execOrArchiveExtRegex = /\.(?:exe|msi|apk|dmg|pkg|iso|img|bat|cmd|ps1|vbs|vbe|scr|jar|hta|zip|rar|7z)(?:$|[?#])/i;

  if (metaRefresh && execOrArchiveExtRegex.test(metaRefresh)) {
    autoDownloadTriggers.push(`Meta-refresh auto-download target (${metaRefresh.slice(0, 80)})`);
  }
  if ((headers['content-disposition'] || '').toLowerCase().includes('attachment')) {
    autoDownloadTriggers.push('Server forces Content-Disposition: attachment');
  }
  if (
    /\.download\s*=|setAttribute\s*\(\s*['"]download['"]/i.test(allInlineJs) &&
    /\.click\s*\(|dispatchEvent\s*\(/i.test(allInlineJs)
  ) {
    autoDownloadTriggers.push('Scripted programmatic <a download>.click() auto-download');
  }
  if (
    /URL\.createObjectURL\s*\(|new\s+Blob\s*\(|data:application\/(?:octet-stream|x-msdownload|zip|x-dosexec)/i.test(allInlineJs) &&
    /\.download\s*=|createElement\s*\(\s*['"]a['"]\s*\)/i.test(allInlineJs)
  ) {
    autoDownloadTriggers.push('HTML smuggling (Blob / Data-URI in-browser file assembly)');
  }
  if (
    /(?:location\.href|location\.replace|location\.assign|window\.location)\s*[=(]\s*['"][^'"]*\.(?:exe|msi|apk|dmg|iso|bat|ps1|scr|zip|rar)/i.test(
      allInlineJs
    )
  ) {
    autoDownloadTriggers.push('JavaScript redirect targeting downloadable executable/archive');
  }
  $('iframe[src]').each((_, el) => {
    const src = ($(el).attr('src') || '').trim();
    const st = ($(el).attr('style') || '').toLowerCase();
    const isHiddenFrame =
      /display\s*:\s*none|visibility\s*:\s*hidden|width\s*:\s*0|height\s*:\s*0/.test(st) ||
      $(el).attr('width') === '0' ||
      $(el).attr('height') === '0';
    if (execOrArchiveExtRegex.test(src) || (isHiddenFrame && src)) {
      if (execOrArchiveExtRegex.test(src)) {
        autoDownloadTriggers.push(`Hidden/embedded iframe pointing to downloadable file (${src.slice(0, 80)})`);
      }
    }
  });

  findings.push({
    id: 'content-auto-download',
    section: 'file_download_analysis',
    test: { en: 'Automatic / Drive-By File Download Detection', ar: 'كشف التنزيل التلقائي للملفات وتهريب HTML' },
    result:
      autoDownloadTriggers.length > 0
        ? {
            en: `${autoDownloadTriggers.length} automatic download trigger(s): ${autoDownloadTriggers[0]}`,
            ar: `تم رصد ${autoDownloadTriggers.length} مؤشر تنزيل تلقائي للملفات: ${autoDownloadTriggers[0]}`,
          }
        : {
            en: 'No drive-by download or HTML smuggling triggers detected',
            ar: 'لم يتم رصد أي محفزات لتنزيل الملفات تلقائياً أو تهريب HTML',
          },
    status: autoDownloadTriggers.length > 0 ? 'failed' : 'pass',
    severity: autoDownloadTriggers.some((t) => /smuggling|executable|\.click|Meta-refresh/i.test(t))
      ? 'critical'
      : autoDownloadTriggers.length > 0
        ? 'high'
        : 'informational',
    weight: autoDownloadTriggers.length > 0 ? 32 : 0,
    evidence:
      autoDownloadTriggers.length > 0
        ? autoDownloadTriggers.join(' ; ')
        : 'Checked meta-refresh, scripted a[download].click(), Blob HTML smuggling, hidden download iframes, and JS binary redirects',
    explanation: {
      en:
        autoDownloadTriggers.length > 0
          ? 'The page contains mechanisms that automatically trigger a file download or assemble a payload locally via JavaScript (HTML smuggling) without explicit user confirmation.'
          : 'No scripted automatic download triggers, hidden download iframes, or Blob/Data-URI payload assembly patterns were found.',
      ar:
        autoDownloadTriggers.length > 0
          ? 'تحتوي الصفحة على آليات تبدأ تنزيل ملف تلقائياً أو تبني ملفاً خبيثاً داخل المتصفح عبر JavaScript دون موافقة صريحة من المستخدم.'
          : 'لم يتم العثور على آليات تنزيل تلقائي أو إطارات تنزيل خفية أو تهريب ملفات عبر Blob.',
    },
    recommendedAction: {
      en:
        autoDownloadTriggers.length > 0
          ? 'Cancel any automatic download immediately and do NOT open downloaded executables, ISOs, or archives.'
          : 'No action required.',
      ar:
        autoDownloadTriggers.length > 0
          ? 'ألغِ أي تنزيل يبدأ تلقائياً فوراً ولا تفتح الملفات التنفيذية أو المضغوطة المحملة.'
          : 'لا يلزم إجراء.',
    },
    source: 'SM Drive-By Download Detector',
    timestamp: now,
    confidence: 94,
  });

  // 8. Malicious Ads, Popunder Networks & Clickjacking Overlay Detector
  const MALVERTISING_HOST_PATTERNS: { pattern: RegExp; label: string }[] = [
    { pattern: /popads\.net|popcash\.net/i, label: 'Popunder Ad Network (PopAds/PopCash)' },
    { pattern: /propellerads\.com|monetag\.com|onclickads\.net/i, label: 'Aggressive Popunder/Redirect Network (PropellerAds/Monetag)' },
    { pattern: /adsterra\.com|effectivegatecpm\.com|highperformanceformat\.com|topcreativeformat\.com/i, label: 'High-Risk Redirect/Ad Network (Adsterra)' },
    { pattern: /hilltopads\.net|admaven\.com|juicyads\.com|exoclick\.com|trafficjunky/i, label: 'Popunder / Adult Malvertising Network' },
    { pattern: /coinhive|cryptonight|minero\.cc|webmine/i, label: 'In-Browser Cryptojacking Script' },
  ];
  const maliciousAdIndicators: string[] = [];
  const allReferencedUrls = [
    ...Array.from(externalDomainsSet),
    ...$('script[src], iframe[src]').map((_, el) => $(el).attr('src') || '').get(),
  ];

  for (const rule of MALVERTISING_HOST_PATTERNS) {
    if (allReferencedUrls.some((u) => rule.pattern.test(u)) || rule.pattern.test(allInlineJs)) {
      if (!maliciousAdIndicators.includes(rule.label)) {
        maliciousAdIndicators.push(rule.label);
      }
    }
  }

  if (
    /(?:document|window|document\.body)\.(?:onclick|onmousedown|addEventListener\s*\(\s*['"](?:click|mousedown)['"])[\s\S]{0,160}window\.open/i.test(
      allInlineJs
    )
  ) {
    maliciousAdIndicators.push('Global page click-hijack triggering popunder window.open()');
  }

  let clickjackOverlayCount = 0;
  $('[style]').each((_, el) => {
    const st = ($(el).attr('style') || '').toLowerCase();
    const isOverlay =
      /position\s*:\s*fixed/.test(st) &&
      /z-index\s*:\s*\d{4,}/.test(st) &&
      /opacity\s*:\s*0(?:\.0+)?\b/.test(st);
    if (isOverlay) clickjackOverlayCount++;
  });
  if (clickjackOverlayCount > 0) {
    maliciousAdIndicators.push(`Full-screen transparent/high-z-index clickjacking overlay (${clickjackOverlayCount})`);
  }

  if (/(?:your (?:device|phone|pc) is infected|download now to clean|adblock detected.*allow|tap allow to continue)/i.test(combinedText)) {
    maliciousAdIndicators.push('Scareware / deceptive ad banner bait');
  }

  findings.push({
    id: 'content-malicious-ads',
    section: 'javascript_analysis',
    test: { en: 'Malicious Ads, Popunders & Clickjacking Detection', ar: 'كشف الإعلانات الخبيثة والنوافذ المنبثقة وخطف النقرات' },
    result:
      maliciousAdIndicators.length > 0
        ? {
            en: `${maliciousAdIndicators.length} malvertising/ad-abuse indicator(s): ${maliciousAdIndicators.slice(0, 2).join('; ')}`,
            ar: `رصد ${maliciousAdIndicators.length} مؤشر إعلان خبيث أو خطف نقرات`,
          }
        : {
            en: 'No known malvertising networks, popunder traps, or transparent click overlays detected',
            ar: 'لم يتم رصد شبكات إعلانات خبيثة أو فخاخ نوافذ منبثقة أو طبقات خطف نقرات',
          },
    status: maliciousAdIndicators.length >= 2 ? 'failed' : maliciousAdIndicators.length === 1 ? 'warning' : 'pass',
    severity: maliciousAdIndicators.length >= 2 ? 'high' : maliciousAdIndicators.length === 1 ? 'medium' : 'informational',
    weight: maliciousAdIndicators.length >= 2 ? 22 : maliciousAdIndicators.length === 1 ? 10 : 0,
    evidence:
      maliciousAdIndicators.length > 0
        ? maliciousAdIndicators.join(' ; ')
        : 'Checked external script/iframe hosts against aggressive popunder/malvertising feeds, global click hijacks, and transparent overlay traps',
    explanation: {
      en:
        maliciousAdIndicators.length > 0
          ? 'Detected aggressive popunder scripts, known malvertising networks, invisible clickjacking overlays, or scareware ad banners that hijack user clicks.'
          : 'No aggressive popunder ad injectors, scareware banners, or full-screen invisible click-capture overlays were found.',
      ar:
        maliciousAdIndicators.length > 0
          ? 'رُصدت شبكات إعلانات مزعجة أو خبيثة أو سكربتات خطف نقرات تفتح نوافذ منبثقة خفية أو تخدع المستخدم لتنزيل ملفات.'
          : 'لم يتم رصد حقن إعلانات خبيثة أو طبقات نقر شفافة تخطف تفاعل المستخدم.',
    },
    recommendedAction: {
      en:
        maliciousAdIndicators.length > 0
          ? 'Do not click ad banners or hidden overlays on this page; leave immediately if popups open automatically.'
          : 'No action required.',
      ar:
        maliciousAdIndicators.length > 0
          ? 'لا تنقر على الإعلانات أو الطبقات المخفية في هذه الصفحة وأغلقها فوراً عند فتح نوافذ تلقائية.'
          : 'لا يلزم إجراء.',
    },
    source: 'SM Malvertising Detector',
    timestamp: now,
    confidence: 90,
  });

  return {
    data: {
      httpStatus,
      contentType,
      htmlSizeBytes: rawBuffer.length,
      pageTitle: pageTitle || undefined,
      metaDescription: metaDescription || undefined,
      visibleWordCount,
      formCount: forms.length,
      passwordInputCount: passwordInputs.length,
      unwrappedPasswordInputCount,
      usernameInputCount,
      sensitiveInputHints: hasUniqueSensHints,
      crossOriginFormActions,
      externalLinkCount,
      externalResourceDomains: Array.from(externalDomainsSet).slice(0, 20),
      externalScriptDomains: Array.from(externalScriptDomainsSet).slice(0, 15),
      iframeCount: iframes.length,
      hiddenElementCount,
      inlineScriptCount,
      externalScriptCount,
      popupIndicators,
      autoRedirectIndicators,
      jsIndicators,
      notificationApiDetected:
        notificationApiDetected || detectedPermissionEntries.some((p) => p.id === 'notifications'),
      requestedPermissions,
      autoDownloadTriggers,
      maliciousAdIndicators,
      fakeAlertIndicators,
      phishingKeywordsMatched: phishingMatches,
      contentReadStatus: rawBuffer.length >= 1.9 * 1024 * 1024 ? 'truncated' : 'full',
      headings,
      buttonLabels,
      internalLinkCount,
      logoAltTexts,
      waitingOrInterstitialDetected,
      oauthWidgetsDetected,
      fakeSupportIndicators,
      personalFinanceFields: uniquePiiFields,
      claimedPurpose,
      permissionAudit,
      suspectedBrand,
    },
    findings,
  };
}

function permPolicyHeaderCheck(headers: Record<string, string>, $: cheerio.CheerioAPI): boolean {
  return Boolean(headers['permissions-policy'] || $('meta[http-equiv="Permissions-Policy" i]').attr('content'));
}
