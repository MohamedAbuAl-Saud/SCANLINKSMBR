import type {
  BilingualText,
  CheckFinding,
  DomainIntelData,
  LevelBExecutionData,
  PlantedBackdoorItem,
  RedirectHop,
  StaticDataFlowTaintItem,
  ThreatProviderResult,
  TlsInspectionData,
} from '../types.ts';
import type { DomainAuthenticityAssessment } from './officialDomainRegistry.ts';

export interface CorrelationEngineContext {
  domainAuthenticity?: DomainAuthenticityAssessment;
  tlsData?: TlsInspectionData;
  dnsData?: DomainIntelData;
  redirects?: RedirectHop[];
  finalUrl?: string;
  levelB?: LevelBExecutionData;
  urlDecodedSecretsCount?: number;
  dataFlowTaints?: StaticDataFlowTaintItem[];
  plantedBackdoors?: PlantedBackdoorItem[];
}

export interface ScoreLedgerEntry {
  id: string;
  ruleId?: string;
  label: BilingualText;
  category: string;
  delta: number;
  evidence?: string;
  explanation?: BilingualText;
}

export interface CorrelationResult {
  riskScore: number;
  hasConfirmedSevereEvidence: boolean;
  hasPermissionEscalation: boolean;
  hasCovertSurveillanceTrap: boolean;
  hasConfirmedStaticAstExfil: boolean;
  hasDecodedUrlSecrets: boolean;
  hasPlantedBackdoor: boolean;
  hasLevelBHighRiskRuntime: boolean;
  hasBgExfilFailed: boolean;
  hasMaliciousCookieFailed: boolean;
  hasDomainDeceptionFailed: boolean;
  hasBrandImpersonation: boolean;
  hasBrandSimilarityOnly: boolean;
  hasCredentialRisk: boolean;
  hasFakeUpdateAlert: boolean;
  hasExplicitPhishingLure: boolean;
  hasCrossOriginForm: boolean;
  hasExternalFlag: boolean;
  hasExternalSuspicious: boolean;
  hasXssFailed: boolean;
  isPaasHosted: boolean;
  correlationNotes: BilingualText[];
  scoreBreakdown: ScoreLedgerEntry[];
}

export function correlateFindingsAndCalibrateScore(params: {
  findings: CheckFinding[];
  providers: ThreatProviderResult[];
  strongRiskScore: number;
  weakSignalScore: number;
  weakSignalContribution: number;
  failedChecks: number;
  baseScoreBreakdown: ScoreLedgerEntry[];
  context?: CorrelationEngineContext;
}): CorrelationResult {
  const {
    findings,
    strongRiskScore,
    weakSignalContribution,
    failedChecks,
    baseScoreBreakdown,
    context,
  } = params;

  const scoreBreakdown: ScoreLedgerEntry[] = [...baseScoreBreakdown];
  let rawScore = Math.round(strongRiskScore) + Math.round(weakSignalContribution);

  const byId = new Map(findings.map((f) => [f.id, f]));
  const homographFinding = byId.get('deception-homograph-confusables');
  const subdomainDeceptionFinding = byId.get('deception-subdomain-identity-mismatch');
  const openRedirectFinding = byId.get('deception-open-redirect-relays');
  const brandFinding = byId.get('brand-impersonation');

  const hasDomainDeceptionFailed =
    homographFinding?.status === 'failed' ||
    subdomainDeceptionFinding?.status === 'failed' ||
    openRedirectFinding?.status === 'failed';
  const hasBrandImpersonation = brandFinding?.status === 'failed';
  const hasBrandSimilarityOnly =
    Boolean(homographFinding?.evidence?.includes('SimilarityOnly: true')) ||
    Boolean(brandFinding?.evidence?.includes('SimilarityOnly: true'));

  // =========================================================================
  // 1. CENTRALIZED CROSS-MODULE DEDUPLICATION (PREVENTS DOUBLE PENALTIES)
  // =========================================================================
  if (
    hasBrandImpersonation &&
    (homographFinding?.status === 'failed' || subdomainDeceptionFinding?.status === 'failed')
  ) {
    const deceptionDomainWeight = Math.max(
      homographFinding?.status === 'failed' ? homographFinding.weight : 0,
      subdomainDeceptionFinding?.status === 'failed' ? subdomainDeceptionFinding.weight : 0
    );
    const overlapDeduction = Math.round(Math.min(brandFinding?.weight || 0, deceptionDomainWeight) * 0.6);
    rawScore = Math.max(0, rawScore - overlapDeduction);
    if (overlapDeduction > 0) {
      scoreBreakdown.push({
        id: 'dedup-brand-deception',
        ruleId: 'DEDUP_BRAND_DECEPTION',
        label: {
          en: 'Overlap Deduplication (Brand & Domain Deception)',
          ar: 'إزالة التكرار بين خداع النطاق وانتحال العلامة',
        },
        category: 'calibration',
        delta: -overlapDeduction,
      });
    }
  } else if (
    hasBrandSimilarityOnly &&
    homographFinding?.status === 'warning' &&
    brandFinding?.status === 'warning'
  ) {
    const overlapDeduction = Math.round(Math.min(brandFinding.weight || 0, homographFinding.weight || 0) * 0.75);
    rawScore = Math.max(0, rawScore - overlapDeduction);
    if (overlapDeduction > 0) {
      scoreBreakdown.push({
        id: 'dedup-similarity-only',
        ruleId: 'DEDUP_SIMILARITY_ONLY',
        label: {
          en: 'Overlap Deduplication (Similarity Only)',
          ar: 'إزالة التكرار لمؤشر التشابه غير المؤكد',
        },
        category: 'calibration',
        delta: -overlapDeduction,
      });
    }
  }

  const jsStaticFinding = byId.get('js-static-analysis');
  const sourceJsFinding = byId.get('source-js-behavior');
  const sourceHtmlFinding = byId.get('source-html-structure');
  const credHarvFinding = byId.get('phishing-credential-harvesting');

  if (jsStaticFinding?.status === 'failed' && sourceJsFinding?.status === 'failed') {
    const overlapJs = Math.round(Math.min(jsStaticFinding.weight || 0, sourceJsFinding.weight || 0) * 0.85);
    if (overlapJs > 0) {
      rawScore = Math.max(0, rawScore - overlapJs);
      scoreBreakdown.push({
        id: 'dedup-js-overlap',
        ruleId: 'DEDUP_JS_OVERLAP',
        label: {
          en: 'Overlap Deduplication (Static JS & Source Forensics)',
          ar: 'منع التكرار بين فحص JS الساكن وتحليل السورس',
        },
        category: 'calibration',
        delta: -overlapJs,
      });
    }
  }

  if (
    brandFinding?.status === 'failed' &&
    sourceHtmlFinding?.status === 'failed' &&
    (sourceHtmlFinding.evidence || '').includes('TitleMismatch: true')
  ) {
    const overlapBrand = Math.round(Math.min(brandFinding.weight || 0, sourceHtmlFinding.weight || 0) * 0.75);
    if (overlapBrand > 0) {
      rawScore = Math.max(0, rawScore - overlapBrand);
      scoreBreakdown.push({
        id: 'dedup-title-brand-overlap',
        ruleId: 'DEDUP_TITLE_BRAND',
        label: {
          en: 'Overlap Deduplication (Title & Brand Mismatch)',
          ar: 'منع التكرار بين انتحال العلامة وتناقض العنوان',
        },
        category: 'calibration',
        delta: -overlapBrand,
      });
    }
  }

  if (
    credHarvFinding?.status === 'failed' &&
    sourceHtmlFinding?.status === 'failed' &&
    (sourceHtmlFinding.evidence || '').includes('CrossOriginFormaction: true')
  ) {
    const overlapForm = Math.round(Math.min(credHarvFinding.weight || 0, sourceHtmlFinding.weight || 0) * 0.65);
    if (overlapForm > 0) {
      rawScore = Math.max(0, rawScore - overlapForm);
      scoreBreakdown.push({
        id: 'dedup-form-overlap',
        ruleId: 'DEDUP_FORM_OVERLAP',
        label: {
          en: 'Overlap Deduplication (External Form Exfiltration)',
          ar: 'منع التكرار لمؤشر إرسال النموذج لنطاق خارجي',
        },
        category: 'calibration',
        delta: -overlapForm,
      });
    }
  }

  const bgExfilDupFinding = byId.get('source-background-exfiltration');
  const cookieDupFinding = byId.get('source-cookie-audit');
  if (bgExfilDupFinding?.status === 'failed' && cookieDupFinding?.status === 'failed') {
    const overlapCookie = Math.round(Math.min(bgExfilDupFinding.weight || 0, cookieDupFinding.weight || 0) * 0.7);
    if (overlapCookie > 0) {
      rawScore = Math.max(0, rawScore - overlapCookie);
      scoreBreakdown.push({
        id: 'dedup-cookie-exfil-overlap',
        ruleId: 'DEDUP_COOKIE_EXFIL',
        label: {
          en: 'Overlap Deduplication (Cookie & Background Exfiltration)',
          ar: 'منع التكرار بين سرقة الكوكيز والتسريب بالخلفية',
        },
        category: 'calibration',
        delta: -overlapCookie,
      });
    }
  }

  const astExfilFinding = byId.get('source-ast-dataflow-exfil');
  if (bgExfilDupFinding?.status === 'failed' && astExfilFinding?.status === 'failed') {
    const overlapAst = Math.round(Math.min(bgExfilDupFinding.weight || 0, astExfilFinding.weight || 0) * 0.5);
    if (overlapAst > 0) {
      rawScore = Math.max(0, rawScore - overlapAst);
      scoreBreakdown.push({
        id: 'dedup-ast-bg-overlap',
        ruleId: 'DEDUP_AST_BG_EXFIL',
        label: {
          en: 'Overlap Deduplication (AST Taint & Background Exfiltration)',
          ar: 'منع التكرار بين تدفق AST الساكن والتسريب بالخلفية',
        },
        category: 'calibration',
        delta: -overlapAst,
      });
    }
  }

  const contentMalAds = byId.get('content-malicious-ads');
  const sourceAdAudit = byId.get('source-advertising-audit');
  if (contentMalAds && sourceAdAudit && contentMalAds.weight > 0 && sourceAdAudit.weight > 0) {
    const overlapAds = Math.round(Math.min(contentMalAds.weight || 0, sourceAdAudit.weight || 0) * 0.8);
    if (overlapAds > 0) {
      rawScore = Math.max(0, rawScore - overlapAds);
      scoreBreakdown.push({
        id: 'dedup-malvertising-overlap',
        ruleId: 'DEDUP_MALVERTISING',
        label: {
          en: 'Overlap Deduplication (Malvertising & Ad Intelligence)',
          ar: 'منع التكرار بين مؤشرات الإعلانات الخبيثة',
        },
        category: 'calibration',
        delta: -overlapAds,
      });
    }
  }

  const xssFinding = byId.get('xss-reflection-dom-audit');
  if (
    xssFinding?.status === 'failed' &&
    (jsStaticFinding?.status === 'failed' || sourceJsFinding?.status === 'failed')
  ) {
    const jsOverlapTarget = Math.max(
      jsStaticFinding?.status === 'failed' ? jsStaticFinding.weight : 0,
      sourceJsFinding?.status === 'failed' ? sourceJsFinding.weight : 0
    );
    const overlapXssJs = Math.round(Math.min(xssFinding.weight || 0, jsOverlapTarget) * 0.45);
    if (overlapXssJs > 0) {
      rawScore = Math.max(0, rawScore - overlapXssJs);
      scoreBreakdown.push({
        id: 'dedup-xss-js-overlap',
        ruleId: 'DEDUP_XSS_JS',
        label: {
          en: 'Overlap Deduplication (DOM XSS & JS Behavioral Audit)',
          ar: 'منع التكرار بين ثغرات DOM XSS وتحليل JavaScript',
        },
        category: 'calibration',
        delta: -overlapXssJs,
      });
    }
  }

  // =========================================================================
  // 2. DETERMINISTIC MULTI-SIGNAL CORRELATION RULES
  // =========================================================================
  const correlationNotes: BilingualText[] = [];
  let minScoreFloor = 0;

  const hasExternalFlag = findings.some(
    (f) => f.section === 'external_threat_intel' && f.status === 'failed'
  );
  const hasExternalSuspicious = findings.some(
    (f) => f.section === 'external_threat_intel' && f.status === 'warning'
  );
  const credFinding = credHarvFinding;
  const socialFinding = byId.get('phishing-social-engineering');
  const structFinding = byId.get('content-structure');
  const paasFinding = byId.get('url-subdomain-paas');
  const lexicalFinding = byId.get('url-lexical-extensions');
  const redirectFinding = byId.get('redirect-chain-analysis');
  const fileDirectFinding = byId.get('file-direct-download');
  const fileLinkedFinding = byId.get('file-linked-downloads');
  const tlsStrengthFinding = byId.get('tls-cipher-strength') || byId.get('tls-protocol-cipher');
  const urlDecodedSecretsFinding = byId.get('url-decoded-credentials');
  const plantedBackdoorFinding = byId.get('source-planted-backdoors');

  const isOfficialEntityVerified = Boolean(
    context?.domainAuthenticity &&
      (context.domainAuthenticity.status === 'official_verified' ||
        context.domainAuthenticity.status === 'official_subdomain') &&
      context.domainAuthenticity.corroborated &&
      !context.domainAuthenticity.conflictDetected
  );

  const hasCredentialRisk = credFinding?.status === 'failed';
  const hasUnwrappedPassword =
    Boolean(credFinding?.evidence.includes('unwrapped in <div>:')) &&
    !/unwrapped in <div>:\s*0\b/.test(credFinding?.evidence || '');
  const hasAnyPasswordInput =
    hasUnwrappedPassword ||
    (Boolean(credFinding?.evidence) && !/Password fields:\s*0\b/.test(credFinding?.evidence || ''));
  const hasCrossOriginForm =
    Boolean(credFinding?.evidence) && !/Cross-origin actions:\s*\[none\]/.test(credFinding?.evidence || '');
  const hasFakeUpdateAlert =
    /Fake software update|system security warning/i.test(socialFinding?.evidence || '');
  const hasExplicitPhishingLure = socialFinding?.status === 'failed';
  const hasPhishingPageArtifact =
    /Explicit social-engineering \/ phishing page markers/i.test(socialFinding?.evidence || '');
  const hasMissingTitleCreds =
    structFinding?.status === 'warning' && (structFinding?.evidence || '').includes('Title: NONE');
  const hasPhishingLexical =
    lexicalFinding?.status === 'warning' || lexicalFinding?.status === 'failed';
  const isPaasHosted =
    Boolean(context?.dnsData?.isMultiTenantPaas) ||
    (Boolean(paasFinding?.evidence) && !/Shared PaaS:\s*No/i.test(paasFinding?.evidence || ''));
  const isYoungDomain = byId.get('domain-age')?.status === 'failed';
  const hasHttpsDowngrade = (redirectFinding?.evidence || '').includes('HTTPS->HTTP');
  const hasTlsInvalid =
    byId.get('tls-chain-trust')?.status === 'failed' ||
    byId.get('tls-availability')?.status === 'failed' ||
    tlsStrengthFinding?.status === 'failed';
  const hasDangerousFile =
    fileDirectFinding?.status === 'failed' || fileLinkedFinding?.status === 'failed';
  const hasXssFailed = xssFinding?.status === 'failed';
  const hasDecodedUrlSecrets =
    urlDecodedSecretsFinding?.status === 'failed' || (context?.urlDecodedSecretsCount ?? 0) > 0;
  const hasConfirmedStaticAstExfil = astExfilFinding?.status === 'failed';
  const hasPlantedBackdoor =
    plantedBackdoorFinding?.status === 'failed' ||
    Boolean(context?.plantedBackdoors && context.plantedBackdoors.some((b) => b.severity === 'critical' || b.severity === 'high'));

  // Rule 1: Confirmed external threat-intelligence hit
  if (hasExternalFlag) {
    rawScore += 25;
    minScoreFloor = Math.max(minScoreFloor, 84);
    scoreBreakdown.push({
      id: 'corr-threat-intel-hit',
      ruleId: 'THREAT_INTEL_CONFIRMED',
      label: { en: 'Correlation: External Threat Feed Hit', ar: 'ارتباط: بلاغ مؤكد من استخبارات التهديدات' },
      category: 'correlation',
      delta: 25,
    });
    correlationNotes.push({
      en: 'External Threat Feed Hit: One or more active threat-intelligence providers flagged this exact URL or unverified infrastructure, elevating risk to Critical.',
      ar: 'بلاغ استخبارات تهديدات: أبلغ مزود أو أكثر عن خطورة هذا الرابط أو النطاق أو عنوان IP، مما يرفع التصنيف إلى حرج.',
    });
  } else if (hasExternalSuspicious) {
    rawScore += 6;
    scoreBreakdown.push({
      id: 'corr-threat-intel-suspicious',
      ruleId: 'THREAT_INTEL_SUSPICIOUS',
      label: { en: 'Correlation: Suspicious Threat Feed Note', ar: 'ارتباط: ملاحظة اشتباه في مصادر التهديد' },
      category: 'correlation',
      delta: 6,
    });
  }

  // Rule 1b: Standalone subdomain spoofing / authority @ masking structural deception
  if (
    subdomainDeceptionFinding?.status === 'failed' &&
    /SubdomainSpoofing:\s*true|Authority@:\s*true/.test(subdomainDeceptionFinding.evidence || '') &&
    context?.domainAuthenticity?.status !== 'official_verified'
  ) {
    minScoreFloor = Math.max(minScoreFloor, 54);
  }

  // Rule 2: Domain deception / homograph / confirmed open redirect + credential or social-engineering signals
  const hasDeceptionExploitCombo =
    hasDomainDeceptionFailed &&
    (hasCredentialRisk ||
      hasExplicitPhishingLure ||
      hasBrandImpersonation ||
      isYoungDomain ||
      (isPaasHosted && hasAnyPasswordInput) ||
      (hasAnyPasswordInput && !isOfficialEntityVerified));

  if (hasDeceptionExploitCombo) {
    rawScore += 20;
    minScoreFloor = Math.max(minScoreFloor, hasCredentialRisk || hasBrandImpersonation ? 82 : 70);
    scoreBreakdown.push({
      id: 'corr-deception-exploit-combo',
      ruleId: 'DECEPTION_EXPLOIT_COMBO',
      label: { en: 'Correlation: Deceptive Domain + Exploitation Signal', ar: 'ارتباط: تمويه النطاق مع مؤشر استغلال' },
      category: 'correlation',
      delta: 20,
    });
    correlationNotes.push({
      en: 'Deceptive Domain Identity + Exploitation Signal: Visual spoofing, homoglyphs, subdomain masking, or open redirect co-occurs with credential or phishing lures.',
      ar: 'تطابق تمويه الهوية مع مؤشرات الاستغلال: تمويه النطاق أو الأحرف المتشابهة أو التوجيه المفتوح يترافق مع استدراج بيانات أو علامات تصيد.',
    });
  }

  // Rule 3: Unwrapped password input (outside <form>) ONLY when paired with genuine phishing lures/missing-title/external form
  if (
    hasUnwrappedPassword &&
    credFinding?.status === 'failed' &&
    (hasFakeUpdateAlert || hasExplicitPhishingLure || hasMissingTitleCreds || hasPhishingLexical || hasCrossOriginForm)
  ) {
    rawScore += 24;
    minScoreFloor = Math.max(minScoreFloor, 74);
    scoreBreakdown.push({
      id: 'corr-unwrapped-password-phish',
      ruleId: 'UNWRAPPED_PASSWORD_LURE',
      label: { en: 'Correlation: Unwrapped Password + Lure/External Form', ar: 'ارتباط: حقل كلمة مرور خارج نموذج مع مؤشر تصيد' },
      category: 'correlation',
      delta: 24,
    });
    correlationNotes.push({
      en: 'Correlated Phishing Pattern: Password input outside a standard <form> co-occurs with deceptive lures, missing <title>, or phishing indicators.',
      ar: 'ترابط مؤشرات التصيد: وجود حقل كلمة مرور خارج نموذج <form> قياسي بالتزامن مع مؤشرات خداع أو غياب <title> أو روابط تصيد.',
    });
  }

  // Rule 4: Password or sensitive credential collection + fake alert / social engineering / cross-origin submission
  if (
    (hasCredentialRisk || hasCrossOriginForm) &&
    (hasFakeUpdateAlert || hasExplicitPhishingLure || hasCrossOriginForm || hasBrandImpersonation)
  ) {
    const comboCount = [
      hasFakeUpdateAlert,
      hasExplicitPhishingLure,
      hasCrossOriginForm,
      hasBrandImpersonation,
      hasMissingTitleCreds,
    ].filter(Boolean).length;

    const delta = 18 + comboCount * 5;
    rawScore += delta;
    minScoreFloor = Math.max(minScoreFloor, comboCount >= 2 ? 82 : 68);
    scoreBreakdown.push({
      id: 'corr-credential-harvesting',
      ruleId: 'CREDENTIAL_HARVESTING_COMBO',
      label: { en: 'Correlation: Credential Harvesting Pattern', ar: 'ارتباط: نمط حصد بيانات الاعتماد' },
      category: 'correlation',
      delta,
    });
    correlationNotes.push({
      en: 'Credential Harvesting Correlation: Login or sensitive inputs appear alongside deceptive lures, fake alerts, impersonation, or unverified third-party endpoints.',
      ar: 'ارتباط حصد بيانات الاعتماد: حقول كلمات المرور مقترنة بعبارات تضليل أو تحذيرات مزيفة أو انتحال أو إرسال لطرف ثالث غير موثق.',
    });
  }

  // Rule 5: Explicit phishing artifact / lure on PaaS or phishing-lexical URL
  if (hasPhishingPageArtifact || (socialFinding?.status === 'failed' && (isPaasHosted || hasPhishingLexical))) {
    rawScore += 26;
    minScoreFloor = Math.max(minScoreFloor, 76);
    scoreBreakdown.push({
      id: 'corr-phishing-lure-infra',
      ruleId: 'PHISHING_LURE_INFRA',
      label: { en: 'Correlation: Phishing Lure & Hosting Context', ar: 'ارتباط: محتوى تصيد مع بنية استضافة مشبوهة' },
      category: 'correlation',
      delta: 26,
    });
    correlationNotes.push({
      en: 'Phishing Lure & Infrastructure Correlation: Explicit social-engineering content detected alongside shared PaaS hosting or phishing path indicators.',
      ar: 'ارتباط محتوى التصيد بالبنية المستضيفة: تم رصد نصوص خداع وتصيد صريحة على استضافة تشاركية أو مسار رابط مشبوه.',
    });
  }

  // Rule 6: Confirmed brand impersonation + newly registered domain or PaaS hosting
  if (hasBrandImpersonation && (isYoungDomain || isPaasHosted || hasPhishingLexical)) {
    rawScore += 16;
    minScoreFloor = Math.max(minScoreFloor, 74);
    scoreBreakdown.push({
      id: 'corr-brand-impersonation-infra',
      ruleId: 'BRAND_IMPERSONATION_INFRA',
      label: { en: 'Correlation: Brand Impersonation + Unverified Host', ar: 'ارتباط: انتحال علامة على نطاق غير موثق' },
      category: 'correlation',
      delta: 16,
    });
    correlationNotes.push({
      en: 'Impersonation Infrastructure Correlation: Brand impersonation detected on an unverified young domain or shared multi-tenant PaaS subdomain.',
      ar: 'انتحال هوية مع بنية استضافة غير موثقة: انتحال علامة تجارية معروفة على نطاق حديث أو استضافة تشاركية.',
    });
  }

  // Rule 7: Credential form over downgraded HTTP or invalid TLS
  if ((hasAnyPasswordInput || hasCredentialRisk) && (hasHttpsDowngrade || hasTlsInvalid)) {
    rawScore += 14;
    minScoreFloor = Math.max(minScoreFloor, 64);
    scoreBreakdown.push({
      id: 'corr-insecure-credential-transport',
      ruleId: 'INSECURE_CREDENTIAL_TRANSPORT',
      label: { en: 'Correlation: Insecure Credential Transport', ar: 'ارتباط: نقل غير آمن لبيانات الدخول' },
      category: 'correlation',
      delta: 14,
    });
    correlationNotes.push({
      en: 'Insecure Credential Transport: Login fields detected where HTTPS was downgraded or TLS validation failed.',
      ar: 'نقل غير آمن لبيانات الدخول: حقول تسجيل دخول على اتصال تم تخفيضه أو بشهادة غير صالحة.',
    });
  }

  // Rule 8: Smart File Download & Drive-By Risk Correlation
  const hasMimeMasqueradeOrDeceptiveFile = Boolean(
    fileDirectFinding?.status === 'failed' ||
      fileDirectFinding?.result?.en?.includes('MIME/Extension mismatch') ||
      fileDirectFinding?.evidence?.includes('Deceptive: true') ||
      fileDirectFinding?.evidence?.includes('double extension') ||
      fileLinkedFinding?.evidence?.includes('double extension')
  );

  const isCleanOrOfficialSite =
    isOfficialEntityVerified ||
    (!hasExplicitPhishingLure &&
      !hasFakeUpdateAlert &&
      !hasCredentialRisk &&
      !hasDomainDeceptionFailed &&
      !hasExternalFlag);

  if (hasMimeMasqueradeOrDeceptiveFile) {
    rawScore += 18;
    minScoreFloor = Math.max(minScoreFloor, 68);
    scoreBreakdown.push({
      id: 'corr-deceptive-file',
      ruleId: 'DECEPTIVE_FILE_DOWNLOAD',
      label: { en: 'Correlation: Deceptive File / MIME Mismatch', ar: 'ارتباط: ملف مموه أو تضارب نوع MIME' },
      category: 'correlation',
      delta: 18,
    });
    correlationNotes.push({
      en: 'Deceptive / Masqueraded File Download: Mismatched signature or dangerous double extension detected.',
      ar: 'تنزيل ملف مموه أو مضلل: تم رصد تلاعب بامتداد الملف أو تضارب في توقيع البايتات السحرية الثنائية.',
    });
  } else if (hasDangerousFile && !isCleanOrOfficialSite) {
    rawScore += 12;
    minScoreFloor = Math.max(minScoreFloor, 56);
    scoreBreakdown.push({
      id: 'corr-suspicious-file-context',
      ruleId: 'HIGH_RISK_FILE_CONTEXT',
      label: { en: 'Correlation: High-Risk File in Suspicious Context', ar: 'ارتباط: تنزيل ملف خطر في سياق مشبوه' },
      category: 'correlation',
      delta: 12,
    });
    correlationNotes.push({
      en: 'High-Risk File Download in Suspicious Context: Executable or archive download detected alongside suspicious content or lures.',
      ar: 'تنزيل ملفات في سياق مشبوه: رصد تنزيل ملفات بالتزامن مع مؤشرات خطورة أو استدراج في محتوى الموقع.',
    });
  } else if ((fileDirectFinding || fileLinkedFinding) && isCleanOrOfficialSite) {
    correlationNotes.push({
      en: 'User-Initiated Software / Document Download: Download links detected on clean/official domain via user action without automatic triggers or deception.',
      ar: 'تنزيل برمجيات أو وثائق عبر روابط اختيارية: رُصدت روابط تنزيل ضمن محتوى نظيف أو نطاق موثق دون تنزيل تلقائي قسري أو تضليل.',
    });
  }

  // Rule 9: Multi-tenant PaaS + password field notice (only escalate when combined with real phishing/suspicion signals)
  if (
    isPaasHosted &&
    hasAnyPasswordInput &&
    (hasCredentialRisk || hasUnwrappedPassword || hasFakeUpdateAlert || hasExplicitPhishingLure || hasBrandImpersonation || hasPhishingLexical)
  ) {
    minScoreFloor = Math.max(minScoreFloor, 60);
    correlationNotes.push({
      en: 'Shared Multi-Tenant PaaS Warning: Underlying platform domain age and wildcard TLS belong to the hosting provider, not this risky credential page.',
      ar: 'تنبيه استضافة تشاركية: عمر النطاق الأساسي وشهادة TLS التلقائية تعود لمزود الاستضافة وليس لموثوقية صفحة تسجيل الدخول المشبوهة.',
    });
  } else if (isPaasHosted && hasAnyPasswordInput) {
    correlationNotes.push({
      en: 'Contextual Note (Multi-Tenant PaaS Form): This page is hosted on shared PaaS infrastructure and includes a standard login form without phishing lures or domain deception.',
      ar: 'ملاحظة سياقية (استضافة تشاركية): هذه الصفحة مستضافة على منصة تشاركية وتحتوي على نموذج دخول قياسي دون علامات تصيد أو خداع.',
    });
  }

  // Rule 10: Drive-by auto-download or confirmed malvertising
  const autoDownloadFinding = byId.get('content-auto-download');
  const malAdsFinding = byId.get('content-malicious-ads');
  const permFinding = byId.get('content-permissions-audit');
  if (autoDownloadFinding?.status === 'failed') {
    rawScore += 18;
    minScoreFloor = Math.max(minScoreFloor, 72);
    scoreBreakdown.push({
      id: 'corr-autodownload',
      ruleId: 'DRIVE_BY_AUTODOWNLOAD',
      label: { en: 'Correlation: Drive-By Download', ar: 'ارتباط: تنزيل تلقائي أو تهريب ملفات' },
      category: 'correlation',
      delta: 18,
    });
    correlationNotes.push({
      en: 'Drive-By Download / HTML Smuggling Signal: Page triggers automatic file downloads or assembles payloads client-side without explicit user consent.',
      ar: 'محفز تنزيل تلقائي أو تهريب ملفات: تحتوي الصفحة على آلية لبدء تنزيل ملف تلقائياً أو بناء حمولات عبر المتصفح.',
    });
  }
  if (malAdsFinding?.status === 'failed' || (malAdsFinding?.status === 'warning' && permFinding?.status === 'failed')) {
    rawScore += 12;
    minScoreFloor = Math.max(minScoreFloor, 56);
    scoreBreakdown.push({
      id: 'corr-malads',
      ruleId: 'MALVERTISING_PERMISSIONS',
      label: { en: 'Correlation: Malvertising & Permissions', ar: 'ارتباط: إعلانات خبيثة وأذونات' },
      category: 'correlation',
      delta: 12,
    });
    correlationNotes.push({
      en: 'Malvertising / Intrusive Permission Correlation: Deceptive ad/popunder triggers co-occur with aggressive browser permission requests.',
      ar: 'ارتباط الإعلانات الخبيثة والأذونات: تزامن مؤشرات الإعلانات المنبثقة/خطف النقرات مع طلب أذونات متصفح حساسة.',
    });
  }

  // Rule 11: Deep Source / HTML / JavaScript Behavioral Exploitation Correlation
  const jsBehaviorFinding = byId.get('source-js-behavior');
  const htmlStructFinding = byId.get('source-html-structure');
  if (
    jsBehaviorFinding?.status === 'failed' &&
    (hasAnyPasswordInput || htmlStructFinding?.status === 'failed' || hasBrandImpersonation || hasCredentialRisk)
  ) {
    rawScore += 18;
    minScoreFloor = Math.max(minScoreFloor, 68);
    scoreBreakdown.push({
      id: 'corr-js-source-exploit',
      ruleId: 'JS_HTML_EXPLOIT_COMBO',
      label: { en: 'Correlation: Active JS & HTML Exploitation', ar: 'ارتباط: استغلال نشط في كود JavaScript و HTML' },
      category: 'correlation',
      delta: 18,
    });
    correlationNotes.push({
      en: 'Source & JavaScript Threat Correlation: Malicious JS behavior (form rewriting, encoded unpacking, or exfiltration hooks) co-occurs with credential inputs or deceptive HTML structure.',
      ar: 'ارتباط سورس الموقع و JavaScript: تزامن سلوك خطير في أكواد JavaScript مع حقول إدخال أو تلاعب في بنية HTML.',
    });
  }

  // Rule 12: Intrusive On-Entry Browser Permissions & Stated-Usage Mismatch Escalation -> HIGH RISK
  const hasPermissionEscalation = Boolean(
    permFinding?.status === 'failed' &&
      (/EscalateHigh:\s*true/i.test(permFinding.evidence || '') ||
        /OnEntry:\s*true/i.test(permFinding.evidence || '') ||
        /DECEPTIVE_INTERACTION_TRIGGER|STATIC_AUTO_TRIGGER_ON_LOAD/i.test(permFinding.evidence || '') ||
        /UsageConsistent:\s*false/i.test(permFinding.evidence || ''))
  );
  if (hasPermissionEscalation) {
    rawScore += 28;
    minScoreFloor = Math.max(minScoreFloor, 72);
    scoreBreakdown.push({
      id: 'corr-on-entry-permissions',
      ruleId: 'PERMISSION_ESCALATION',
      label: {
        en: 'Escalation: On-Entry / Deceptive Browser Permissions',
        ar: 'رفع الخطورة: طلب أذونات متصفح عند الدخول أو عبر زر مضلل',
      },
      category: 'correlation',
      delta: 28,
    });
    correlationNotes.push({
      en: 'High-Risk Permission Escalation: Website requests intrusive browser permissions automatically upon entry, via deceptive lure actions, or without matching stated usage.',
      ar: 'رفع مستوى الفحص لخطورة مرتفعة: يطلب الموقع أذونات متصفح حساسة بمجرد الدخول أو عبر أزرار خادعة دون تطابق مع الوظيفة المعلنة.',
    });
  }

  // Rule 13: Background JS Data Collection + External Service Transmission & Encrypted/Encoded URL Correlation
  const bgExfilFinding = byId.get('source-background-exfiltration');
  const cookieAuditFinding = byId.get('source-cookie-audit');
  const urlEncodingFinding = byId.get('url-encoding-obfuscation');
  const hasBgExfilFailed = bgExfilFinding?.status === 'failed';
  const hasMaliciousCookieFailed = cookieAuditFinding?.status === 'failed';
  const hasUrlEncryptionAnomaly = urlEncodingFinding?.status === 'failed' || urlEncodingFinding?.status === 'warning';

  if (hasBgExfilFailed) {
    const corrDelta = hasUrlEncryptionAnomaly ? 22 : 16;
    rawScore += corrDelta;
    minScoreFloor = Math.max(minScoreFloor, hasUrlEncryptionAnomaly || hasAnyPasswordInput ? 76 : 70);
    scoreBreakdown.push({
      id: 'corr-bg-js-exfiltration',
      ruleId: hasUrlEncryptionAnomaly ? 'ENCRYPTED_URL_EXFIL' : 'CONFIRMED_BG_EXFIL',
      label: {
        en: hasUrlEncryptionAnomaly
          ? 'Correlation: Encrypted/Encoded URL + Harmful Background Exfiltration'
          : 'Escalation: Confirmed Harmful Background Data Exfiltration',
        ar: hasUrlEncryptionAnomaly
          ? 'ارتباط: رابط/مسار مشفر مع تسريب بيانات ضار بالخلفية'
          : 'تصعيد: تأكيد إرسال بيانات حساسة وضارة لخادم خارجي بالخلفية',
      },
      category: 'correlation',
      delta: corrDelta,
    });
    correlationNotes.push({
      en: hasUrlEncryptionAnomaly
        ? 'Encrypted URL + Harmful Background Exfiltration: URL or path segments are encrypted/encoded while scripts harvest sensitive credentials, auth cookies, or keystrokes in the background and transmit them externally.'
        : 'Harmful Background Data Exfiltration: Payload inspection confirmed JavaScript collects sensitive credentials, tokens, cookies, or keystrokes and transmits them to an unverified or obfuscated external server.',
      ar: hasUrlEncryptionAnomaly
        ? 'تطابق تشفير الرابط مع تسريب بيانات ضار: يحتوي الرابط أو مساراته على مقاطع مشفرة بالتزامن مع إرسال بيانات حساسة (كوكيز جلسة أو كلمات مرور أو ضغطات مفاتيح) لخدمة خارجية.'
        : 'تأكيد إرسال بيانات ضارة بالخلفية: تحقق المحلل من نوع البيانات المرسلة عبر JavaScript وتبين أنها بيانات حساسة تُرسل لخادم خارجي غير موثوق أو مموه.',
    });
  } else if (hasMaliciousCookieFailed) {
    rawScore += 14;
    minScoreFloor = Math.max(minScoreFloor, 68);
    scoreBreakdown.push({
      id: 'corr-malicious-cookie-abuse',
      ruleId: 'MALICIOUS_COOKIE_ABUSE',
      label: {
        en: 'Escalation: Malicious Cookie Abuse / Hidden Stuffing',
        ar: 'تصعيد: سلوك كوكيز خبيث أو حشو إعلانات مخفي',
      },
      category: 'correlation',
      delta: 14,
    });
    correlationNotes.push({
      en: 'Malicious Cookie Behavior Detected: Page exhibits cookie theft, obfuscated cookie injection, insecure cross-site cookie scoping, or hidden ad/affiliate cookie-stuffing.',
      ar: 'سلوك كوكيز ضار: تم رصد حقن كوكيز مموه أو سرقة كوكيز أو حشو إعلانات خفي.',
    });
  } else if (
    urlEncodingFinding?.status === 'failed' &&
    (hasAnyPasswordInput || hasExplicitPhishingLure || jsBehaviorFinding?.status === 'failed')
  ) {
    rawScore += 14;
    minScoreFloor = Math.max(minScoreFloor, 68);
    scoreBreakdown.push({
      id: 'corr-encrypted-url-exploit',
      ruleId: 'ENCRYPTED_URL_EXPLOIT',
      label: {
        en: 'Correlation: Encrypted/Encoded URL + Credential/Script Risk',
        ar: 'ارتباط: مسار/رابط مشفر مع مخاطر نموذج أو سكربت',
      },
      category: 'correlation',
      delta: 14,
    });
    correlationNotes.push({
      en: 'Obfuscated URL & Path Exploitation: Encrypted or multi-encoded URL paths appear alongside credential collection or suspicious runtime scripts.',
      ar: 'استغلال الروابط والمسارات المشفرة: تترافق المسارات المشفرة أو المرمزة في الرابط مع حقول دخول أو سكربتات مشبوهة.',
    });
  }

  // Rule 14: Verified Target XSS Vulnerability Correlation (Unescaped Reflection / DOM XSS + Weak/Missing CSP)
  if (hasXssFailed) {
    const cspWeakOrMissing = Boolean(
      byId.get('source-csp-missing') ||
        /CSP:\s*(?:missing|weak)/i.test(xssFinding?.evidence || '')
    );
    const xssCorr = cspWeakOrMissing ? 14 : 8;
    rawScore += xssCorr;
    minScoreFloor = Math.max(minScoreFloor, hasAnyPasswordInput || cspWeakOrMissing ? 56 : 44);
    scoreBreakdown.push({
      id: 'corr-xss-vulnerability',
      ruleId: 'XSS_VULNERABILITY_CORR',
      label: {
        en: cspWeakOrMissing
          ? 'Correlation: Unescaped/DOM XSS + Missing or Weak CSP'
          : 'Escalation: Verified Target XSS Risk',
        ar: cspWeakOrMissing
          ? 'ارتباط: ثغرة XSS مع غياب أو ضعف سياسة CSP'
          : 'تصعيد: مؤشر ثغرة XSS في الصفحة المستهدفة',
      },
      category: 'correlation',
      delta: xssCorr,
    });
    correlationNotes.push({
      en: 'Target XSS Risk Correlation: Unescaped parameter reflection or tainted DOM sink detected passively in target HTML/JS.',
      ar: 'مؤشر ثغرة XSS: رصد الفحص السلبي انعكاس مدخلات غير معقّمة أو تدفق DOM ملوث في الصفحة المستهدفة.',
    });
  }

  // Rule 15: Covert Surveillance / Hardware Capture + External Exfiltration Trap (even without Level B!)
  const levelB = context?.levelB;
  const levelBExecuted = levelB?.status === 'executed';
  const levelBHighRiskReqs = levelBExecuted
    ? levelB.networkRequests.filter(
        (r) => r.channelCategory === 'HIGH_RISK_EXFILTRATION_CHANNEL' || r.channelCategory === 'WEBHOOK_OR_BOT_SINK'
      )
    : [];
  const levelBIpProfilingReqs = levelBExecuted
    ? levelB.networkRequests.filter((r) => r.channelCategory === 'IP_AND_DEVICE_PROFILING')
    : [];
  const levelBUnverifiedSinkReqs = levelBExecuted
    ? levelB.networkRequests.filter((r) => r.channelCategory === 'UNVERIFIED_EXTERNAL' && r.isSensitiveSink)
    : [];
  const levelBPermEvents = levelBExecuted
    ? levelB.permissionEvents.filter((e) => ['camera', 'microphone', 'geolocation', 'clipboard'].includes(e.kind))
    : [];
  const hasLevelBHighRiskRuntime = Boolean(
    levelBExecuted &&
      (levelBHighRiskReqs.length > 0 || (levelBPermEvents.length > 0 && (levelBIpProfilingReqs.length > 0 || levelBUnverifiedSinkReqs.length > 0)))
  );

  const staticTaints = context?.dataFlowTaints || [];
  const hasSensitiveDeviceTaint = staticTaints.some(
    (t) =>
      ['camera_mic', 'geolocation', 'clipboard', 'ip_profiling'].includes(t.sourceKind) ||
      t.triggerContext === 'DECEPTIVE_INTERACTION_TRIGGER' ||
      t.triggerContext === 'STATIC_AUTO_TRIGGER_ON_LOAD'
  );
  const hasSurveillanceSourceSignal = Boolean(
    permFinding?.status === 'failed' ||
      hasSensitiveDeviceTaint ||
      levelBPermEvents.length > 0
  );
  const hasSurveillanceSinkSignal = Boolean(
    hasConfirmedStaticAstExfil ||
      hasBgExfilFailed ||
      hasDecodedUrlSecrets ||
      hasPlantedBackdoor ||
      hasLevelBHighRiskRuntime ||
      /HIGH_RISK_EXFILTRATION_CHANNEL|WEBHOOK_OR_BOT_SINK|telegram|webhook/i.test(
        `${bgExfilFinding?.evidence || ''} ${astExfilFinding?.evidence || ''} ${urlDecodedSecretsFinding?.evidence || ''}`
      )
  );
  const hasCovertSurveillanceTrap = hasSurveillanceSourceSignal && hasSurveillanceSinkSignal;

  if (hasCovertSurveillanceTrap) {
    rawScore += 24;
    minScoreFloor = Math.max(minScoreFloor, 82);
    scoreBreakdown.push({
      id: 'corr-covert-surveillance-trap',
      ruleId: 'COVERT_SURVEILLANCE_OR_CAPTURE_TRAP',
      label: {
        en: 'Correlation: Covert Surveillance / Capture Trap + External Exfiltration',
        ar: 'ارتباط: فخ تجسس/التقاط كاميرا أو موقع مع قناة تسريب خارجية',
      },
      category: 'correlation',
      delta: 24,
      evidence: `Perm=${permFinding?.status || 'none'}; ASTExfil=${hasConfirmedStaticAstExfil}; DecodedURLSecrets=${hasDecodedUrlSecrets}; LevelBHighRisk=${levelBHighRiskReqs.length}`,
      explanation: {
        en: 'Sensitive device capture APIs (camera, microphone, geolocation, clipboard, or IP profiling) are paired with deceptive/automatic triggers and external bot/webhook exfiltration or encoded attacker credentials.',
        ar: 'تقترن واجهات التقاط بيانات الجهاز الحساسة (الكاميرا، الميكروفون، الموقع، الحافظة، أو تحديد IP) بمحفزات خادعة/تلقائية وقنوات تسريب أو مفاتيح بوت مرمزة.',
      },
    });
    correlationNotes.push({
      en: 'COVERT_SURVEILLANCE_OR_CAPTURE_TRAP: Static/runtime evidence links sensitive media, geolocation, or device capture to automated external bot/webhook exfiltration or decoded URL parameters.',
      ar: 'فخ تجسس والتقاط بيانات (COVERT_SURVEILLANCE_OR_CAPTURE_TRAP): يربط التحليل بين محاولات الوصول للكاميرا/الميكروفون/الموقع وقنوات التسريب الخارجية أو معرفات البوت المفكوكة في الرابط.',
    });
  }

  // Rule 16: Decoded URL Bot/Chat Secrets + Planted Backdoors / AST Exfil
  if (hasDecodedUrlSecrets && (hasPlantedBackdoor || hasConfirmedStaticAstExfil || hasBgExfilFailed)) {
    rawScore += 18;
    minScoreFloor = Math.max(minScoreFloor, 80);
    scoreBreakdown.push({
      id: 'corr-decoded-url-backdoor-exfil',
      ruleId: 'DECODED_URL_SECRETS_EXFIL',
      label: {
        en: 'Correlation: Decoded URL Bot Credentials + Exfiltration / Backdoor',
        ar: 'ارتباط: مفاتيح بوت مفكوكة في الرابط مع تسريب أو باب خلفي',
      },
      category: 'correlation',
      delta: 18,
    });
    correlationNotes.push({
      en: 'Decoded URL Secrets + Exfiltration Chain: Base64/encoded URL parameters expose bot credentials or chat IDs corroborated by page script exfiltration or backdoor logic.',
      ar: 'مفاتيح مسربة في الرابط مع آلية إرسال: يكشف فك تشفير معاملات الرابط عن معرفات بوت أو قنوات تحكم تتطابق مع سكربتات الإرسال بالصفحة.',
    });
  } else if (hasConfirmedStaticAstExfil && !hasBgExfilFailed) {
    minScoreFloor = Math.max(minScoreFloor, hasPlantedBackdoor || hasPermissionEscalation ? 76 : 68);
  }

  // Rule 17: Level B External Cloud Browser Runtime Telemetry (ONLY when actually executed)
  if (levelBExecuted) {
    if (hasLevelBHighRiskRuntime) {
      rawScore += 22;
      minScoreFloor = Math.max(minScoreFloor, levelBHighRiskReqs.length > 0 ? 80 : 72);
      scoreBreakdown.push({
        id: 'corr-level-b-runtime-threat',
        ruleId: 'LEVEL_B_DYNAMIC_THREAT',
        label: {
          en: 'Level B Dynamic Runtime: High-Risk Exfiltration / Permission Abuse',
          ar: 'رصد Level B الحي: قناة تسريب عالية الخطورة أو استغلال صلاحيات',
        },
        category: 'correlation',
        delta: 22,
        evidence: `HighRiskNet=${levelBHighRiskReqs.length}, RuntimePerms=${levelBPermEvents.length}`,
      });
      correlationNotes.push({
        en: `Level B Runtime Confirmation: Live cloud browser execution captured ${levelBHighRiskReqs.length} high-risk bot/webhook channel(s) and ${levelBPermEvents.length} runtime permission request(s).`,
        ar: `تأكيد التشغيل الحي (Level B): رصد المتصفح السحابي ${levelBHighRiskReqs.length} قناة تسريب/بوت خطيرة و${levelBPermEvents.length} محاولة لطلب صلاحيات حساسة.`,
      });
    } else if (levelBIpProfilingReqs.length > 0 || levelBPermEvents.length > 0) {
      rawScore += 10;
      scoreBreakdown.push({
        id: 'corr-level-b-runtime-observation',
        ruleId: 'LEVEL_B_DYNAMIC_OBSERVATION',
        label: {
          en: 'Level B Dynamic Runtime: IP Profiling or Runtime Permission Attempt',
          ar: 'رصد Level B الحي: استعلام تحديد IP أو محاولة طلب صلاحية',
        },
        category: 'correlation',
        delta: 10,
      });
      correlationNotes.push({
        en: `Level B Runtime Observation: Live session observed ${levelBIpProfilingReqs.length} IP/profiling call(s) and ${levelBPermEvents.length} permission event(s).`,
        ar: `ملاحظة التشغيل الحي (Level B): رُصدت ${levelBIpProfilingReqs.length} طلبات استعلام IP و${levelBPermEvents.length} أحداث صلاحيات أثناء التنفيذ.`,
      });
    }
  }

  // =========================================================================
  // 3. STRICT CONFIRMED SEVERE EVIDENCE GATE FOR HIGH (70+) & POSTURE BALANCING
  // =========================================================================
  const hasBaseTagHijack = byId.get('source-base-tag-hijack')?.status === 'failed';
  const hasConfirmedSevereEvidence = Boolean(
    hasExternalFlag ||
      hasBgExfilFailed ||
      hasConfirmedStaticAstExfil ||
      hasCovertSurveillanceTrap ||
      hasLevelBHighRiskRuntime ||
      (hasDecodedUrlSecrets && (hasPlantedBackdoor || hasPermissionEscalation || hasAnyPasswordInput)) ||
      hasMaliciousCookieFailed ||
      autoDownloadFinding?.status === 'failed' ||
      hasMimeMasqueradeOrDeceptiveFile ||
      hasBrandImpersonation ||
      hasExplicitPhishingLure ||
      hasPermissionEscalation ||
      hasBaseTagHijack ||
      hasDeceptionExploitCombo ||
      (hasCredentialRisk &&
        (hasFakeUpdateAlert || hasExplicitPhishingLure || hasCrossOriginForm || hasBrandImpersonation || hasUnwrappedPassword)) ||
      (jsBehaviorFinding?.status === 'failed' &&
        (hasAnyPasswordInput || htmlStructFinding?.status === 'failed' || hasBrandImpersonation || hasCredentialRisk)) ||
      (hasXssFailed && hasAnyPasswordInput && !isOfficialEntityVerified)
  );

  // Balanced Defensive Posture Calibration:
  // Valid HTTPS + CSP present + 0 suspicious redirects + 0 confirmed severe threats gently stabilizes minor weak signals
  const tlsValid = Boolean(
    context?.tlsData?.httpsAvailable &&
      context.tlsData.authorized &&
      !context.tlsData.expired &&
      context.tlsData.domainMatches !== false
  );
  const cspPresent =
    !byId.has('source-csp-missing') &&
    (!xssFinding || /CSP:\s*strict/i.test(xssFinding.evidence || ''));
  const zeroSuspiciousRedirects =
    !redirectFinding || redirectFinding.status === 'pass';

  if (!hasConfirmedSevereEvidence && rawScore > 0 && tlsValid && cspPresent && zeroSuspiciousRedirects) {
    const postureDiscount = Math.min(6, Math.max(1, Math.round(rawScore * 0.15)));
    rawScore = Math.max(0, rawScore - postureDiscount);
    scoreBreakdown.push({
      id: 'posture-defensive-balance',
      ruleId: 'DEFENSIVE_POSTURE_BALANCE',
      label: {
        en: 'Defensive Posture Calibration (Valid HTTPS + CSP + Clean Redirects)',
        ar: 'معايرة التحصين الدفاعي (HTTPS صالح + CSP + تحويلات سليمة)',
      },
      category: 'calibration',
      delta: -postureDiscount,
    });
  }

  const hasRealDangerBasis =
    failedChecks > 0 ||
    strongRiskScore > 0 ||
    hasExternalFlag ||
    hasExternalSuspicious ||
    minScoreFloor > 0 ||
    hasLevelBHighRiskRuntime;

  const preFloorScore = Math.min(100, Math.round(rawScore));
  let computedScore = Math.min(100, Math.max(minScoreFloor, preFloorScore));

  // If rawScore exceeded 100 before cap, record cap calibration so scoreBreakdown sums cleanly to computedScore
  const ledgerPreCapSum = scoreBreakdown.reduce((acc, item) => acc + item.delta, 0);
  if (computedScore > preFloorScore && hasRealDangerBasis) {
    scoreBreakdown.push({
      id: 'corr-floor',
      ruleId: 'CORRELATION_FLOOR',
      label: {
        en: 'Multi-Signal Correlation Floor Adjustment',
        ar: 'تعديل الحد الأدنى لترابط الأدلة المتعددة',
      },
      category: 'correlation',
      delta: computedScore - ledgerPreCapSum,
    });
  } else if (ledgerPreCapSum !== computedScore) {
    scoreBreakdown.push({
      id: 'score-ceiling-cap',
      ruleId: 'SCORE_CEILING_CAP',
      label: {
        en: 'Score Scale Normalization (0–100 Range)',
        ar: 'تطبيع سقف النقاط ضمن نطاق 0–100',
      },
      category: 'calibration',
      delta: computedScore - ledgerPreCapSum,
    });
  }

  let riskScore = hasRealDangerBasis ? computedScore : Math.min(15, computedScore);
  if (!hasRealDangerBasis && computedScore > 15) {
    scoreBreakdown.push({
      id: 'no-danger-cap',
      ruleId: 'NO_DANGER_BASIS_CAP',
      label: {
        en: 'Benign Signal Cap (No Confirmed Risk Basis)',
        ar: 'سقف الإشارات الثانوية عند غياب أساس خطورة',
      },
      category: 'calibration',
      delta: riskScore - computedScore,
    });
  }

  // Strict HIGH (70+) Gate: preliminary/weak/unconfirmed signals CANNOT reach HIGH (70+) or CRITICAL
  if (!hasConfirmedSevereEvidence && riskScore > 64) {
    const clampDelta = riskScore - 64;
    riskScore = 64;
    scoreBreakdown.push({
      id: 'high-gate-clamp',
      ruleId: 'CONFIRMED_EVIDENCE_HIGH_GATE',
      label: {
        en: 'Confirmed-Evidence Gate (Preliminary Signals Capped Below High Risk)',
        ar: 'حاجز الأدلة المؤكدة (منع تصعيد المؤشرات الأولية لخطورة مرتفعة)',
      },
      category: 'calibration',
      delta: -clampDelta,
    });
  }

  return {
    riskScore,
    hasConfirmedSevereEvidence,
    hasPermissionEscalation,
    hasCovertSurveillanceTrap,
    hasConfirmedStaticAstExfil,
    hasDecodedUrlSecrets,
    hasPlantedBackdoor,
    hasLevelBHighRiskRuntime,
    hasBgExfilFailed,
    hasMaliciousCookieFailed,
    hasDomainDeceptionFailed,
    hasBrandImpersonation,
    hasBrandSimilarityOnly,
    hasCredentialRisk,
    hasFakeUpdateAlert,
    hasExplicitPhishingLure,
    hasCrossOriginForm,
    hasExternalFlag,
    hasExternalSuspicious,
    hasXssFailed,
    isPaasHosted,
    correlationNotes,
    scoreBreakdown,
  };
}

export const CorrelationEngine = {
  correlateFindingsAndCalibrateScore,
};
