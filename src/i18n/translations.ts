import type {
  AdvertisingIntelligenceState,
  CheckStatus,
  CookieCategory,
  FileDownloadCategory,
  FinalVerdict,
  Language,
  ProviderOperationalState,
  RiskClassification,
  RiskSeverity,
} from '../types/scan';

export const CURRENT_YEAR = new Date().getFullYear();

export const UI_COPY = {
  brand: {
    name: { en: 'Scan Link SM', ar: 'Scan Link SM' },
    tagline: { en: 'Scan Smart. Stay Safe.', ar: 'افحص بذكاء. ابقَ آمناً.' },
    owner: { en: 'Mohamed Abu AlSaud SM', ar: 'Mohamed Abu AlSaud SM' },
    contactHandle: '@A_Y_TR',
    telegramUrl: 'https://t.me/A_Y_TR',
  },
  nav: {
    home: { en: 'Home', ar: 'الرئيسية' },
    scanner: { en: 'URL Scanner', ar: 'فاحص الروابط' },
    providers: { en: 'Providers', ar: 'مزودي البيانات' },
    history: { en: 'Scan History', ar: 'سجل الفحوصات' },
    about: { en: 'About', ar: 'عن المنصة' },
    privacy: { en: 'Privacy Policy', ar: 'سياسة الخصوصية' },
    terms: { en: 'Terms of Use', ar: 'شروط الاستخدام' },
  },
  hero: {
    headline: {
      en: 'Deterministic Website & URL Threat Intelligence',
      ar: 'استخبارات أمنية حتمية لفحص المواقع والروابط',
    },
    description: {
      en: 'Inspect suspicious links, trace hidden redirects, detect credential-harvesting pages, verify brand impersonation, inspect certificates, and correlate verified threat feeds.',
      ar: 'افحص الروابط المشبوهة، وتتبع سلاسل التوجيه المخفية، واكشف صفحات سرقة البيانات وانتحال العلامات، وتحقق من الشهادات وقواعد التهديدات الموثقة.',
    },
    inputPlaceholder: {
      en: 'Enter the URL to scan',
      ar: 'أدخل الرابط المراد فحصه',
    },
    paste: { en: 'Paste', ar: 'لصق' },
    clear: { en: 'Clear', ar: 'مسح' },
    scan: { en: 'Analyze URL', ar: 'فحص الرابط' },
    scanning: { en: 'Analyzing...', ar: 'جارٍ الفحص...' },
    optionsToggle: { en: 'Scan Options', ar: 'خيارات الفحص' },
    viewportLabel: { en: 'Screenshot Viewport', ar: 'منظور لقطة الشاشة' },
    viewportDesktop: { en: 'Desktop (1280×800)', ar: 'سطح المكتب (1280×800)' },
    viewportMobile: { en: 'Mobile (390×844)', ar: 'الجوال (390×844)' },
    viewportFull: { en: 'Full Page', ar: 'الصفحة كاملة' },
    securityNotice: {
      en: 'Only submit URLs you are authorized to inspect. Never paste private URLs containing session tokens, API keys, or personal credentials.',
      ar: 'افحص فقط الروابط المصرح لك بتحليلها. لا تُدخل روابط خاصة تتضمن رموز جلسات أو مفاتيح سرية أو كلمات مرور.',
    },
    examplesLabel: { en: 'Test targets:', ar: 'روابط اختبار:' },
    recentScansLabel: { en: 'Recent Local Scans', ar: 'أحدث الفحوصات المحلية' },
    clipboardDenied: {
      en: 'Clipboard permission was denied by your browser. Paste the URL manually.',
      ar: 'رفض المتصفح إذن الحافظة. يرجى لصق الرابط يدوياً.',
    },
    invalidUrl: {
      en: 'Please enter a valid HTTP or HTTPS URL or public domain name.',
      ar: 'يرجى إدخال رابط HTTP أو HTTPS أو اسم نطاق عام صحيح.',
    },
  },
  homeSections: {
    labTitle: {
      en: 'Sixteen-Layer Deterministic Inspection Pipeline',
      ar: 'محرك فحص حتمي من ست عشرة طبقة أمنية',
    },
    labSubtitle: {
      en: 'No AI guesswork. Every classification stems from SSRF-guarded network telemetry, HTML inspection, rule correlation, and live threat feeds.',
      ar: 'بدون تخمين أو نماذج ذكاء اصطناعي. يعتمد كل تصنيف على بيانات الشبكة المحمية وفحص المحتوى وقواعد الارتباط ومزودي التهديدات.',
    },
    providersTitle: {
      en: 'Threat Intelligence Providers & Runtime Capabilities',
      ar: 'حالة مزودي استخبارات التهديدات وقدرات بيئة التشغيل',
    },
    providersSubtitle: {
      en: 'Unavailable or authentication-gated feeds are disclosed transparently and never treated as clean checks.',
      ar: 'يتم عرض حالة كل مزود بشفافية تامة؛ ولا يُحتسب المزود غير المتاح أو غير المهيأ كدليل على الأمان أبداً.',
    },
  },
  providersPage: {
    title: { en: 'Provider Configuration & Operational Status', ar: 'إعدادات وحالة مزودي البيانات' },
    subtitle: {
      en: 'Inspect real-time connectivity, interactive network mesh, and choose which providers to enable for your scans.',
      ar: 'استعرض الحالة التشغيلية الحقيقية وخريطة الشبكة التفاعلية، وتحكم في مزودي البيانات المفعّلين أثناء الفحص.',
    },
    refresh: { en: 'Refresh Status', ar: 'تحديث الحالة' },
    lastLookup: { en: 'Last Successful Lookup', ar: 'آخر استعلام ناجح' },
    neverRun: { en: 'Not queried yet in this session', ar: 'لم يُستعلم بعد في هذه الجلسة' },
    envKeyLabel: { en: 'Backend Env Variable', ar: 'متغير البيئة في الخادم' },
    noKeyNeeded: { en: 'No API key required (Public Endpoint)', ar: 'لا يتطلب مفتاحاً (وصول عام مباشر)' },
    sessionToggle: { en: 'Enabled for Scans', ar: 'مفعّل في الفحوصات' },
    privacyBanner: {
      en: 'All third-party API keys reside strictly on the backend server and are never sent to browser code.',
      ar: 'تبقى جميع مفاتيح واجهات البرمجة حصراً على الخادم ولا يتم كشفها في المتصفح مطلقاً.',
    },
  },
  progress: {
    title: { en: 'Live Security Pipeline Execution', ar: 'تنفيذ مراحل الفحص الأمني المباشر' },
    subtitle: {
      en: 'Stage indicators reflect real backend completion events via Server-Sent Events.',
      ar: 'تعكس المؤشرات حالة إتمام الوحدات الخلفية فعلياً لحظة بلحظة.',
    },
    target: { en: 'Target URL', ar: 'الرابط قيد الفحص' },
    cancelReturn: { en: 'New Scan', ar: 'فحص جديد' },
    stageStatus: {
      pending: { en: 'Queued', ar: 'في الانتظار' },
      running: { en: 'Running', ar: 'قيد التنفيذ' },
      completed: { en: 'Completed', ar: 'مكتمل' },
      warning: { en: 'Observations', ar: 'ملاحظات' },
      failed: { en: 'Alert / Failed', ar: 'تنبيه / فشل' },
      unavailable: { en: 'Unavailable', ar: 'غير متاح' },
    },
  },
  report: {
    title: { en: 'Website Security Intelligence Report', ar: 'تقرير الاستخبارات الأمنية للموقع' },
    pageTitle: { en: 'Website Title', ar: 'عنوان الموقع' },
    noPageTitle: { en: 'No <title> element present', ar: 'لا يوجد وسم <title> في الصفحة' },
    riskScore: { en: 'Risk Score', ar: 'درجة المخاطر' },
    classification: { en: 'Classification', ar: 'مستوى التصنيف' },
    verdict: { en: 'Final Verdict', ar: 'الحكم النهائي' },
    confidence: { en: 'Analysis Confidence', ar: 'موثوقية التحليل' },
    inspectionCoverage: { en: 'Inspection Coverage', ar: 'تغطية الفحص' },
    recommendation: { en: 'Security Recommendation', ar: 'التوصية الأمنية' },
    topReasonsHeading: { en: 'Top Factors Driving This Score', ar: 'أبرز الأسباب المؤثرة في التقييم' },
    correlationHeading: { en: 'Multi-Signal Risk Correlation', ar: 'تحليل الارتباط الأمني بين المؤشرات' },
    conflictHeading: { en: 'Conflicting Evidence Disclosure', ar: 'إفصاح تعارض المصادر والأدلة' },
    domainAuthHeading: { en: 'Official Domain & Page Authenticity Verification', ar: 'التحقق الشامل من النطاق الرسمي والصفحة' },
    separatedPillarsHeading: { en: 'Five Separated Security Assessments', ar: 'التقييمات الخمسة المفصولة مستقلاً' },
    scoreBreakdownHeading: { en: 'Deterministic Score Breakdown & Evidence Matrix', ar: 'تفصيل احتساب المخاطر وتصنيف الأدلة' },
    websiteIntelReportHeading: { en: 'SM Website Intelligence Report (12 Dimensions)', ar: 'تقرير SM للاستخبارات المعمقة للموقع (١٢ محوراً)' },
    submittedUrl: { en: 'Submitted URL', ar: 'الرابط المُدخل' },
    finalUrl: { en: 'Final Destination', ar: 'الوجهة النهائية' },
    scanDuration: { en: 'Duration', ar: 'مدة الفحص' },
    rescan: { en: 'Re-Scan', ar: 'إعادة الفحص' },
    exportJson: { en: 'Export JSON', ar: 'تصدير JSON' },
    exportPdf: { en: 'Download PDF', ar: 'تحميل PDF' },
    exportingPdf: { en: 'Preparing PDF...', ar: 'جارٍ تجهيز PDF...' },
    newScan: { en: 'Scan Another URL', ar: 'فحص رابط آخر' },
    screenshotStatus: { en: 'Screenshot Status', ar: 'حالة المعاينة البصرية' },
    captureMethod: { en: 'Capture Method', ar: 'طريقة الالتقاط' },
    viewport: { en: 'Viewport', ar: 'الأبعاد' },
    stats: {
      total: { en: 'Total Checks', ar: 'إجمالي الفحوصات' },
      passed: { en: 'Passed', ar: 'ناجح' },
      warning: { en: 'Warnings', ar: 'تحذيرات' },
      failed: { en: 'Failed', ar: 'فشل' },
      critical: { en: 'Critical / High', ar: 'حرج / مرتفع' },
      providers: { en: 'Available Providers', ar: 'المزودون المتاحون' },
      incomplete: { en: 'Incomplete / Unknown', ar: 'غير مكتمل / مجهول' },
    },
    charts: {
      distribution: { en: 'Check Outcomes Distribution', ar: 'توزيع نتائج الفحوصات' },
      sectionProfile: { en: 'Security Layer Breakdown', ar: 'ملخص الطبقات الأمنية' },
    },
    table: {
      title: { en: 'Detailed Security Evidence Table', ar: 'جدول الأدلة والفحوصات التفصيلي' },
      searchPlaceholder: { en: 'Filter by test, evidence, or source...', ar: 'ابحث في اسم الفحص أو الدليل أو المصدر...' },
      allStatuses: { en: 'All Statuses', ar: 'كل الحالات' },
      allSections: { en: 'All 16 Sections', ar: 'كل الأقسام' },
      colTest: { en: 'Test', ar: 'الفحص' },
      colResult: { en: 'Result', ar: 'النتيجة' },
      colStatus: { en: 'Status', ar: 'الحالة' },
      colSeverity: { en: 'Severity', ar: 'الشدة' },
      colEvidence: { en: 'Evidence', ar: 'الدليل التقني' },
      colSource: { en: 'Source', ar: 'المصدر' },
      colTime: { en: 'Timestamp', ar: 'الوقت' },
      noMatches: { en: 'No findings match the current filter.', ar: 'لا توجد نتائج تطابق التصفية الحالية.' },
      expandDetails: { en: 'Inspect', ar: 'تفاصيل' },
      recommendedAction: { en: 'Recommended Action', ar: 'الإجراء الموصى به' },
      whereDetected: { en: 'Where Detected', ar: 'موقع الرصد' },
      whyRisky: { en: 'Why It Is Risky', ar: 'لماذا يُعد خطراً' },
      howExploited: { en: 'How Attackers Exploit It', ar: 'كيف يُستغل هجومياً' },
      userImpact: { en: 'Potential User Impact', ar: 'التأثير المحتمل على المستخدم' },
      notProvenAlone: { en: 'What This Alone Does NOT Prove', ar: 'ما لا يثبته هذا المؤشر بمفرده' },
    },
    sectionsHeading: { en: 'Sixteen-Section Forensic Breakdown', ar: 'التحليل الجنائي الموزع على ١٦ قسماً' },
    sandboxNoticeTitle: { en: 'Isolation & Non-Execution Disclosure', ar: 'إفصاح بيئة العزل وعدم التنفيذ' },
    deceptionDetails: { en: 'Domain Deception & Identity Analysis', ar: 'تحليل خداع النطاق والانتحال البصري' },
    redirectChain: { en: 'Redirect Chain Telemetry', ar: 'تتبع سلسلة إعادة التوجيه' },
    domainDetails: { en: 'Domain, Registration & DNS Intelligence', ar: 'بيانات النطاق والتسجيل وسجلات DNS' },
    tlsDetails: { en: 'SSL/TLS Certificate Telemetry', ar: 'تفاصيل شهادة SSL/TLS' },
    contentDetails: { en: 'Website Content & Brand Impersonation', ar: 'محتوى الموقع وانتحال العلامات' },
    fileDetails: { en: 'File & Download Inspection', ar: 'فحص الملفات وروابط التنزيل' },
    threatFeeds: { en: 'External Threat Intelligence Feeds', ar: 'مزودو استخبارات التهديدات الخارجية' },
    screenshotSection: { en: 'Website Visual Evidence', ar: 'المعاينة البصرية للموقع' },
    zoomScreenshot: { en: 'Enlarge Screenshot', ar: 'تكبير الصورة' },
    closeZoom: { en: 'Close Preview', ar: 'إغلاق المعاينة' },
  },
  history: {
    title: { en: 'Local Scan History', ar: 'سجل الفحوصات المحلي' },
    subtitle: {
      en: 'Stored exclusively inside your browser when local storage consent is granted. Never uploaded or linked to accounts.',
      ar: 'يُحفظ السجل محلياً داخل متصفحك فقط عند منح الموافقة، ولا يُرفع لأي خادم خارجي.',
    },
    consentDisabled: {
      en: 'Local scan history storage is currently paused. Enable consented storage to persist reports across sessions.',
      ar: 'حفظ السجل المحلي متوقف حالياً. فعّل الموافقة لحفظ التقارير بين الجلسات.',
    },
    enableConsent: { en: 'Enable Local History Storage', ar: 'تفعيل حفظ السجل محلياً' },
    searchPlaceholder: { en: 'Filter saved URLs or classifications...', ar: 'ابحث في الروابط أو التصنيف...' },
    clearAll: { en: 'Clear All', ar: 'مسح الكل' },
    openReport: { en: 'Open Report', ar: 'فتح التقرير' },
    delete: { en: 'Delete', ar: 'حذف' },
    emptyTitle: { en: 'No scans yet', ar: 'لا توجد عمليات فحص حتى الآن' },
    emptyDesc: {
      en: 'Start a URL or website security scan to view your saved deterministic reports here.',
      ar: 'ابدأ فحص أي رابط أو موقع من الصفحة الرئيسية لعرض تقاريرك المفحوصة والنتائج التفصيلية هنا.',
    },
    loadingText: { en: 'Loading local scan archive...', ar: 'جارٍ تحميل سجل الفحوصات المحلي...' },
    noSearchMatches: {
      en: 'No scan records match your search filter.',
      ar: 'لا توجد سجلات تطابق عبارة البحث الحالية.',
    },
    goToScanner: { en: 'Start New Scan', ar: 'ابدأ فحصاً جديداً' },
    backToHome: { en: 'Back to Home', ar: 'العودة إلى الرئيسية' },
    screenshotYes: { en: 'Screenshot Ready', ar: 'توجد لقطة شاشة' },
    screenshotNo: { en: 'No Screenshot', ar: 'بدون لقطة شاشة' },
  },
  about: {
    title: { en: 'About Scan Link SM', ar: 'حول منصة Scan Link SM' },
    description: {
      en: 'Scan Link SM is a specialized platform for inspecting URLs and websites and analyzing security threat indicators, helping users understand potential risks and make more informed decisions before visiting websites.',
      ar: 'Scan Link SM منصة متخصصة في فحص الروابط والمواقع وتحليل مؤشرات التهديدات الأمنية، بهدف مساعدة المستخدمين على فهم المخاطر المحتملة واتخاذ قرارات أكثر وعيًا قبل زيارة المواقع.',
    },
    missionTitle: { en: 'Deterministic Security Principles', ar: 'مبادئ الأمان والشفافية' },
    missionBody: {
      en: 'Scan Link SM relies strictly on deterministic structural rules, verified domain ownership checks, live network telemetry, and external threat feeds—with zero AI guesswork. It never claims a site is 100% safe, never marks unreachable targets as clean, and keeps all provider keys strictly server-side.',
      ar: 'تعتمد منصة Scan Link SM كلياً على قواعد تحليل حتمية، والتحقق الموثق من ملكية النطاقات، وبيانات الشبكة الحقيقية دون أي تخمين أو نماذج ذكاء اصطناعي. لا تدعي المنصة أبداً أمان أي موقع بنسبة 100%، ولا تعتبر نقص البيانات دليلاً على السلامة.',
    },
    methodologyTitle: { en: 'Deep Multi-Layer Inspection Pipeline', ar: 'منهجية التحليل المتعمقة متعددة الطبقات' },
    developerTitle: { en: 'Owner & Developer', ar: 'المالك والمطور' },
    developerName: { en: 'Mohamed Abu AlSaud SM', ar: 'Mohamed Abu AlSaud SM' },
    contactLabel: { en: 'Official Contact', ar: 'التواصل الرسمي' },
    proprietaryTitle: { en: 'Proprietary & Protected Platform', ar: 'منصة محمية ومملوكة بالكامل' },
    proprietaryBody: {
      en: 'Scan Link SM is proprietary software developed and owned exclusively by Mohamed Abu AlSaud SM. All analysis engines, backend services, visual identities, and telemetry systems are protected intellectual property.',
      ar: 'منصة Scan Link SM هي برمجية أمن سيبراني خاصة ومملوكة حصرياً للمطور Mohamed Abu AlSaud SM. جميع محركات التحليل والخدمات الخلفية والواجهات محمية بحقوق الملكية الفكرية.',
    },
    proprietaryBadge: {
      en: 'Proprietary Security Platform · All Rights Reserved',
      ar: 'منصة أمنية خاصة محمية · جميع الحقوق محفوظة',
    },
  },
  errors: {
    backHome: { en: 'Back to Home', ar: 'العودة إلى الرئيسية' },
    retry: { en: 'Try Again', ar: 'إعادة المحاولة' },
    401: {
      title: { en: 'Sign-In Required', ar: 'يلزم التحقق للمتابعة' },
      desc: {
        en: 'You need valid authorization to access this protected resource. Please return to the home page and start a standard scan.',
        ar: 'تحتاج إلى صلاحية دخول صالحة للوصول إلى هذه الصفحة. يمكنك العودة إلى الرئيسية ومتابعة الفحص بشكل طبيعي.',
      },
    },
    403: {
      title: { en: 'Access Restricted', ar: 'الوصول مقيّد' },
      desc: {
        en: 'For platform and data security reasons, this internal path or resource is not publicly accessible.',
        ar: 'لحماية المنصة وسلامة البيانات، هذا المسار أو المورد الداخلي غير متاح للوصول العام.',
      },
    },
    404: {
      title: { en: 'Page Not Found', ar: 'الصفحة غير موجودة' },
      desc: {
        en: 'The page or link you are looking for could not be found or may have been moved. Check the address or return home.',
        ar: 'الصفحة أو المسار الذي تبحث عنه غير موجود أو ربما تم نقله. تأكد من صحة العنوان أو عد إلى الصفحة الرئيسية.',
      },
    },
    429: {
      title: { en: 'Too Many Requests', ar: 'طلبات متكررة خلال وقت قصير' },
      desc: {
        en: 'You have reached the temporary scan rate limit to keep the service stable for everyone. Please wait a moment and try again.',
        ar: 'لقد تجاوزت الحد المؤقت لعدد الطلبات المتتالية للحفاظ على استقرار الخدمة. انتظر لحظة ثم أعد المحاولة.',
      },
    },
    500: {
      title: { en: 'Temporary Processing Issue', ar: 'حدث خلل مؤقت في المعالجة' },
      desc: {
        en: 'We ran into an unexpected technical issue while preparing this page. Our service stays protected—please try again shortly.',
        ar: 'واجهنا مشكلة فنية مؤقتة أثناء معالجة طلبك. يرجى المحاولة مرة أخرى بعد قليل أو العودة إلى الرئيسية.',
      },
    },
    502: {
      title: { en: 'Upstream Gateway Unavailable', ar: 'تعذر الاتصال بالبوابة الوسيطة' },
      desc: {
        en: 'An upstream inspection service did not respond in time. Please retry your request in a few seconds.',
        ar: 'لم تستجب إحدى بوابات الفحص بالسرعة المطلوبة. يرجى إعادة المحاولة بعد بضع ثوانٍ.',
      },
    },
    503: {
      title: { en: 'Service Temporarily Busy', ar: 'الخدمة مشغولة مؤقتاً' },
      desc: {
        en: 'Scan Link SM is currently experiencing heavy load or maintenance. Please try again in a moment.',
        ar: 'المنصة قيد ضغط مرتفع أو تحديث مؤقت حالياً. يرجى المحاولة مرة أخرى بعد قليل.',
      },
    },
  },
  consent: {
    title: { en: 'Privacy & Local Storage Controls', ar: 'إعدادات الخصوصية والتخزين المحلي' },
    body: {
      en: 'Necessary storage remembers your theme and language preferences. Optional local storage saves your scan history inside this browser. No third-party tracking cookies or external analytics are enabled.',
      ar: 'يُستخدم التخزين الضروري لحفظ المظهر واللغة فقط. ويُستخدم التخزين الاختياري لحفظ سجل الفحوصات محلياً في متصفحك دون أي تتبع أو تحليلات خارجية.',
    },
    acceptHistory: { en: 'Enable Optional History Storage', ar: 'تفعيل حفظ السجل الاختياري' },
    essentialOnly: { en: 'Necessary Only', ar: 'الضروري فقط' },
    manageSettings: { en: 'Privacy Settings', ar: 'إعدادات الخصوصية' },
  },
  footer: {
    rights: {
      en: `Scan Link SM © ${CURRENT_YEAR}`,
      ar: `Scan Link SM © ${CURRENT_YEAR}`,
    },
    ownerLine: {
      en: 'Owned & Developed by Mohamed Abu AlSaud SM',
      ar: 'المالك والمطور: Mohamed Abu AlSaud SM',
    },
    contactLine: {
      en: 'Official Contact: @A_Y_TR',
      ar: 'التواصل الرسمي: @A_Y_TR',
    },
    proprietaryTag: {
      en: 'Advanced URL & Website Security Analysis Platform · All Rights Reserved',
      ar: 'منصة متقدمة لفحص الروابط والمواقع وتحليل المؤشرات الأمنية · جميع الحقوق محفوظة',
    },
    disclaimer: {
      en: 'Automated telemetry assists security decisions but does not guarantee absolute safety against zero-day threats.',
      ar: 'النتائج استخباراتية مساعدة لاتخاذ القرار الأمني ولا تضمن الأمان المطلق ضد التهديدات المستجدة.',
    },
  },
} as const;

export function tStatus(status: CheckStatus | string | undefined, lang: Language = 'en'): string {
  const map: Record<string, { en: string; ar: string }> = {
    pass: { en: 'Pass', ar: 'سليم' },
    warning: { en: 'Warning', ar: 'تحذير' },
    failed: { en: 'Failed', ar: 'فشل' },
    unknown: { en: 'Unknown', ar: 'غير معروف' },
  };
  const targetLang = lang === 'ar' ? 'ar' : 'en';
  const key = status ? String(status).toLowerCase() : 'unknown';
  const item = map[key] || map.unknown;
  return item[targetLang] || item.en || String(status || 'Unknown');
}

export function tSeverity(sev: RiskSeverity | string | undefined, lang: Language = 'en'): string {
  const legacyMap: Record<string, RiskSeverity> = {
    none: 'informational',
    guarded: 'low',
    moderate: 'medium',
  };
  const rawKey = sev ? String(sev).toLowerCase() : 'unknown';
  const key = legacyMap[rawKey] || rawKey;
  const map: Record<string, { en: string; ar: string }> = {
    critical: { en: 'Critical', ar: 'حرج' },
    high: { en: 'High', ar: 'مرتفع' },
    medium: { en: 'Medium', ar: 'متوسط' },
    low: { en: 'Low', ar: 'منخفض' },
    informational: { en: 'Informational', ar: 'معلوماتي' },
    unknown: { en: 'Unknown', ar: 'غير معروف' },
  };
  const targetLang = lang === 'ar' ? 'ar' : 'en';
  const item = map[key] || map.unknown;
  return item[targetLang] || item.en || String(sev || 'Unknown');
}

export function tClassification(cls: RiskClassification | string | undefined, lang: Language = 'en'): string {
  const legacyMap: Record<string, RiskClassification> = {
    'Critical Risk': 'CRITICAL',
    'High Risk': 'HIGH',
    'Medium Risk': 'MEDIUM',
    'Moderate Risk': 'MEDIUM',
    Guarded: 'LOW',
    'Low Risk': 'LOW',
    INFORMATIONAL: 'NO_KNOWN_THREATS',
  };
  const upper = cls ? String(cls).toUpperCase() : '';
  const key = (cls && (legacyMap[cls as string] || legacyMap[upper] || upper)) as RiskClassification;
  const map: Record<string, { en: string; ar: string }> = {
    CRITICAL: { en: 'CRITICAL RISK', ar: 'خطورة حرجة (CRITICAL)' },
    HIGH: { en: 'HIGH RISK', ar: 'خطورة مرتفعة (HIGH)' },
    MEDIUM: { en: 'MEDIUM RISK', ar: 'خطورة متوسطة (MEDIUM)' },
    LOW: { en: 'LOW RISK', ar: 'خطورة منخفضة (LOW)' },
    NO_KNOWN_THREATS: { en: 'NO KNOWN THREATS', ar: 'لا توجد تهديدات معروفة' },
    OFFICIAL_DOMAIN_VERIFIED: { en: 'OFFICIAL DOMAIN VERIFIED', ar: 'نطاق رسمي موثق' },
    SAFE_INDICATORS: { en: 'NO KNOWN THREATS', ar: 'لا توجد تهديدات معروفة' },
    INFORMATIONAL: { en: 'NO KNOWN THREATS', ar: 'لا توجد تهديدات معروفة' },
    UNKNOWN: { en: 'INSUFFICIENT EVIDENCE', ar: 'أدلة غير كافية' },
    INCONCLUSIVE: { en: 'INSUFFICIENT EVIDENCE', ar: 'أدلة غير كافية' },
  };
  const targetLang = lang === 'ar' ? 'ar' : 'en';
  const item = map[key] || map.UNKNOWN;
  if (!item) return targetLang === 'ar' ? 'أدلة غير كافية' : 'INSUFFICIENT EVIDENCE';
  return item[targetLang] || item.en || String(cls || 'INSUFFICIENT EVIDENCE');
}

export function tVerdict(verdict: FinalVerdict | string | undefined, lang: Language = 'en'): string {
  const map: Record<string, { en: string; ar: string }> = {
    'Critical Risk': { en: 'Critical Risk', ar: 'خطورة حرجة' },
    Critical: { en: 'Critical Risk', ar: 'خطورة حرجة' },
    'Malicious Indicators Detected': { en: 'Critical Risk', ar: 'خطورة حرجة — مؤشرات خبيثة' },
    'High Risk': { en: 'High Risk', ar: 'خطورة مرتفعة' },
    'Medium Risk': { en: 'Medium Risk', ar: 'خطورة متوسطة' },
    Suspicious: { en: 'Medium Risk', ar: 'خطورة متوسطة (مشبوه)' },
    'Low Risk': { en: 'Low Risk', ar: 'خطورة منخفضة' },
    'Official Domain Verified': { en: 'Official Domain Verified', ar: 'نطاق رسمي موثق' },
    'No Known Threats': { en: 'No Known Threats', ar: 'لا توجد تهديدات معروفة' },
    'Safe Indicators Found': { en: 'No Known Threats', ar: 'لا توجد تهديدات معروفة' },
    'No Known Threats Detected': { en: 'No Known Threats', ar: 'لا توجد تهديدات معروفة' },
    'Insufficient Evidence': { en: 'Insufficient Evidence', ar: 'أدلة غير كافية' },
    Inconclusive: { en: 'Insufficient Evidence', ar: 'أدلة غير كافية' },
    'Incomplete Analysis': { en: 'Insufficient Evidence', ar: 'أدلة غير كافية' },
  };
  const targetLang = lang === 'ar' ? 'ar' : 'en';
  const key = verdict ? String(verdict) : 'Insufficient Evidence';
  const item = map[key] || map['Insufficient Evidence'];
  return item[targetLang] || item.en || key;
}

export function tOperationalState(state: ProviderOperationalState | string | undefined, lang: Language = 'en'): string {
  const legacyMap: Record<string, ProviderOperationalState> = {
    unconfigured: 'auth_required',
    error: 'unavailable',
  };
  const rawKey = state ? String(state).toLowerCase() : 'unavailable';
  const key = legacyMap[rawKey] || rawKey;
  const map: Record<string, { en: string; ar: string }> = {
    active: { en: 'Active', ar: 'نشط' },
    configured: { en: 'Configured', ar: 'مهيأ' },
    disabled: { en: 'Disabled', ar: 'معطل' },
    rate_limited: { en: 'Rate Limited', ar: 'محدود المعدل' },
    unavailable: { en: 'Unavailable', ar: 'غير متاح' },
    auth_required: { en: 'Authentication Required', ar: 'يتطلب مفتاح توثيق' },
  };
  const targetLang = lang === 'ar' ? 'ar' : 'en';
  const item = map[key] || map.unavailable;
  return item[targetLang] || item.en || String(state || 'Unavailable');
}

export function tCookieCategory(cat: CookieCategory | string | undefined, lang: Language = 'en'): string {
  const map: Record<string, { en: string; ar: string }> = {
    essential_necessary: { en: 'ESSENTIAL / NECESSARY', ar: 'ضروري للتشغيل' },
    functional_preference: { en: 'FUNCTIONAL / PREFERENCE', ar: 'وظيفي / تفضيلات' },
    security_cookie: { en: 'SECURITY / SESSION', ar: 'أمان / جلسة' },
    analytics: { en: 'ANALYTICS', ar: 'تحليلات وقياس' },
    advertising: { en: 'ADVERTISING', ar: 'إعلانات وتخصيص' },
    third_party: { en: 'THIRD-PARTY', ar: 'طرف ثالث' },
    suspicious: { en: 'SUSPICIOUS', ar: 'سلوك مشبوه' },
    malicious: { en: 'MALICIOUS', ar: 'سلوك خبيث' },
  };
  const targetLang = lang === 'ar' ? 'ar' : 'en';
  const item = (cat && map[cat]) || map.essential_necessary;
  return item[targetLang];
}

export function tAdIntelState(state: AdvertisingIntelligenceState | string | undefined, lang: Language = 'en'): string {
  const map: Record<string, { en: string; ar: string }> = {
    legitimate_advertising: { en: 'Legitimate Advertising', ar: 'إعلانات مشروعة' },
    declared_analytics: { en: 'Declared Analytics', ar: 'تحليلات معلنة' },
    consent_dependent_tracking: { en: 'Consent-Dependent Tracking', ar: 'تتبع خاضع للموافقة' },
    undeclared_tracking: { en: 'Undeclared Tracking (Privacy Notice)', ar: 'تتبع غير معلن (ملاحظة خصوصية)' },
    suspicious_advertising: { en: 'Suspicious Advertising', ar: 'إعلانات مشبوهة' },
    malicious_advertising: { en: 'Malicious Advertising / Malvertising', ar: 'إعلانات خبيثة / برمجيات دعائية' },
    no_advertising_detected: { en: 'No Advertising Detected', ar: 'لم تُرصد شبكات إعلانية' },
    unknown_incomplete: { en: 'Unknown / Incomplete', ar: 'غير مكتمل / غير معروف' },
  };
  const targetLang = lang === 'ar' ? 'ar' : 'en';
  const item = (state && map[state]) || map.unknown_incomplete;
  return item[targetLang];
}

export function tFileDownloadCategory(cat: FileDownloadCategory | string | undefined, lang: Language = 'en'): string {
  const map: Record<string, { en: string; ar: string }> = {
    user_initiated_download: { en: 'User-Initiated Download', ar: 'تحميل يبدأه المستخدم' },
    automatic_download: { en: 'Automatic / Drive-By Download', ar: 'تنزيل تلقائي قسري' },
    deceptive_download: { en: 'Deceptive Download', ar: 'تحميل مموه / خداعي' },
    executable: { en: 'Executable Binary', ar: 'ملف تنفيذي' },
    archive: { en: 'Archive Package', ar: 'ملف مضغوط' },
    script: { en: 'Script Payload', ar: 'ملف نصي برمجي' },
    verified_safe_resource: { en: 'Standard Static Resource', ar: 'مورد قياسي سليم' },
    unknown_file: { en: 'Unclassified File', ar: 'ملف غير مصنف' },
  };
  const targetLang = lang === 'ar' ? 'ar' : 'en';
  const item = (cat && map[cat]) || map.unknown_file;
  return item[targetLang];
}

export function tXssStatus(
  status: 'safe' | 'potential_weakness' | 'high_risk' | 'unavailable' | string | undefined,
  lang: Language = 'en'
): string {
  const map: Record<string, { en: string; ar: string }> = {
    safe: { en: 'Safe (0 XSS Detected)', ar: 'سليم (لا توجد ثغرات XSS)' },
    potential_weakness: { en: 'Potential Weakness', ar: 'ضعف محتمل تجاه XSS' },
    high_risk: { en: 'High XSS Risk', ar: 'مخاطر XSS مرتفعة' },
    unavailable: { en: 'Inspection Unavailable', ar: 'تعذر الفحص' },
  };
  const targetLang = lang === 'ar' ? 'ar' : 'en';
  const item = (status && map[status]) || map.unavailable;
  return item[targetLang];
}
