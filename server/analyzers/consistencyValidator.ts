import type { CheckFinding, CheckStatus, RiskClassification, ScanReport } from '../types.ts';

/**
 * Global Bi-Directional Consistency Validator & Normalizer
 *
 * Ensures that all sections, findings, risk scores, classifications, evidence buckets,
 * Cookie Intelligence, Advertising Intelligence, AST Data-Flow, and Level B telemetry
 * never contradict each other in the final ScanReport.
 */
export function validateAndNormalizeReportConsistency(report: ScanReport): ScanReport {
  const sourceIntel = report.sourceIntel;
  const cookieAudit = sourceIntel?.cookieAudit;
  const adIntel = sourceIntel?.advertisingIntel;
  const txs = sourceIntel?.externalDataTransmissions || [];
  const dataFlowTaints = sourceIntel?.dataFlowTaints || [];
  const findings: CheckFinding[] = report.findings.map((f) => ({ ...f }));

  const harmfulTxs = txs.filter((t) => t.isHarmful);
  const externalTxs = txs.filter((t) => t.isThirdParty);
  const confirmedAstExfil = dataFlowTaints.some((t) => t.confirmedStaticFlow);
  const hasLevelBHighRisk = Boolean(
    report.levelB?.status === 'executed' &&
      report.levelB.networkRequests.some(
        (r) => r.channelCategory === 'HIGH_RISK_EXFILTRATION_CHANNEL' || r.channelCategory === 'WEBHOOK_OR_BOT_SINK'
      )
  );
  const hasAnyConfirmedExfil = harmfulTxs.length > 0 || confirmedAstExfil || hasLevelBHighRisk;

  // 1. Cookie Invariant: When malicious cookie behavior is NOT proven, never report failed/malicious count
  if (cookieAudit && !cookieAudit.hasMaliciousCookieBehavior) {
    if (cookieAudit.maliciousCookieCount > 0) {
      cookieAudit.maliciousCookieCount = 0;
    }
    const cookieFinding = findings.find((f) => f.id === 'source-cookie-audit');
    if (cookieFinding && cookieFinding.status === 'failed') {
      cookieFinding.status = cookieAudit.consentVerification?.privacyViolationDetected ? 'warning' : 'pass';
      cookieFinding.severity = cookieAudit.consentVerification?.privacyViolationDetected ? 'low' : 'informational';
      cookieFinding.weight = 0;
      cookieFinding.riskImpact = 'none';
    }
  }

  // 2. External Data Transmission Invariant: No harmful exfiltration (neither JS tx, AST taint, nor Level B) -> no false exfiltration claim
  if (!hasAnyConfirmedExfil) {
    const bgFinding = findings.find((f) => f.id === 'source-background-exfiltration');
    if (bgFinding && bgFinding.status === 'failed') {
      const hasUnverified = externalTxs.some((t) => t.harmClassification === 'unverified_external');
      bgFinding.status = hasUnverified ? 'warning' : 'pass';
      bgFinding.severity = hasUnverified ? 'medium' : 'informational';
      bgFinding.weight = hasUnverified ? 12 : 0;
      bgFinding.riskImpact = hasUnverified ? 'medium' : 'none';
      bgFinding.result = hasUnverified
        ? {
            en: `${externalTxs.length} unverified external outbound request(s) detected (cannot assume benign)`,
            ar: `رصد ${externalTxs.length} طلب إرسال خارجي غير موثوق (لا يُفترض سلامته)`,
          }
        : {
            en: externalTxs.length > 0
              ? `${externalTxs.length} outbound JS request(s) verified benign/functional — 0 sensitive exfiltration`
              : 'No external background data transmission detected',
            ar: externalTxs.length > 0
              ? `رصد ${externalTxs.length} طلب JS خارجي سليم/وظيفي — لا يوجد تسريب بيانات حساسة`
              : 'لم يتم رصد أي إرسال بيانات للخارج بالخلفية',
          };
    }
  }

  // 3. Advertising Intelligence Invariant: Undeclared tracking without malvertising is Privacy Violation (0 risk penalty, not Malicious)
  if (adIntel) {
    if (adIntel.status === 'undeclared_tracking') {
      const adFinding = findings.find((f) => f.id === 'source-advertising-audit');
      if (adFinding && adFinding.status === 'failed') {
        adFinding.status = 'warning';
        adFinding.severity = 'low';
        adFinding.weight = 0;
        adFinding.riskImpact = 'none';
      }
    }
    if (adIntel.status === 'no_advertising_detected' && cookieAudit && cookieAudit.adCookieCount === 0) {
      cookieAudit.setsAdvertisingCookies = false;
      const adFinding = findings.find((f) => f.id === 'source-advertising-audit');
      if (adFinding && adFinding.status !== 'pass') {
        adFinding.status = 'pass';
        adFinding.severity = 'informational';
        adFinding.weight = 0;
        adFinding.riskImpact = 'none';
      }
    }
  }

  // 3b. XSS Assessment Invariant: Safe XSS audit has 0 risk weight
  if (report.xssAssessment) {
    const xssFinding = findings.find((f) => f.id === 'xss-reflection-dom-audit');
    if (report.xssAssessment.status === 'safe' && xssFinding && xssFinding.status !== 'pass') {
      xssFinding.status = 'pass';
      xssFinding.severity = 'informational';
      xssFinding.weight = 0;
      xssFinding.riskImpact = 'none';
    }
  }

  // 4. Forward & Backward Contradiction Scrubbing
  const noExternalTx = externalTxs.length === 0 && !confirmedAstExfil && !hasLevelBHighRisk;
  const noHarmfulTx = !hasAnyConfirmedExfil;

  const isContradictoryExfilNote = (textEn: string) =>
    noHarmfulTx && /Harmful Background Data Exfiltration|Encrypted URL \+ Harmful Background Exfiltration|transmits credentials.*externally/i.test(textEn);

  const isContradictoryExternalTxNote = (textEn: string) =>
    noExternalTx && /outbound transmission.*external|sends data externally/i.test(textEn) && !/No external/i.test(textEn);

  const hasAstExfilFailed = findings.some((f) => f.id === 'source-ast-dataflow-exfil' && f.status === 'failed');
  const hasBackdoorFailed = findings.some((f) => f.id === 'source-planted-backdoors' && f.status === 'failed');
  const hasUrlSecretsFailed = findings.some((f) => f.id === 'url-decoded-credentials' && f.status === 'failed');

  const isHighOrCritical =
    report.riskScore >= 70 ||
    report.classification === 'HIGH' ||
    report.classification === 'CRITICAL' ||
    harmfulTxs.length > 0 ||
    hasAstExfilFailed ||
    hasLevelBHighRisk ||
    (hasBackdoorFailed && hasUrlSecretsFailed);

  const isContradictoryCleanClaimOnHighRisk = (textEn: string) =>
    isHighOrCritical &&
    (/\ball\s+(?:\d+\s+)?(?:completed\s+)?(?:deterministic\s+)?checks?\s+passed\b/i.test(textEn) ||
      (/\bbenign\b/i.test(textEn) && !/cannot\s+(?:assume|confirm)\s+benign|not\s+benign|never\s+benign/i.test(textEn)) ||
      /no malicious content or credential traps observed/i.test(textEn) ||
      /benign\/harmless payload telemetry verified/i.test(textEn) ||
      (hasAnyConfirmedExfil && /\bHarmful:\s*0\b/i.test(textEn)));

  const filterNote = (n: { en: string; ar: string }) =>
    !isContradictoryExfilNote(n.en) &&
    !isContradictoryExternalTxNote(n.en) &&
    !isContradictoryCleanClaimOnHighRisk(n.en);

  const correlationNotes = report.correlationNotes.filter(filterNote);
  let topReasons = (report.topReasons || []).filter(filterNote);
  const existingBuckets = report.evidenceBuckets || {
    confirmed: [],
    suspicious: [],
    inconclusive: [],
    conflicting: [],
  };
  let confirmedBucket = existingBuckets.confirmed.filter(filterNote);
  const suspiciousBucket = existingBuckets.suspicious.filter(filterNote);

  // 5. Recalculate invariant check totals and validate Risk Score / Classification consistency
  const passedChecks = findings.filter((f) => f.status === 'pass').length;
  const warningChecks = findings.filter((f) => f.status === 'warning').length;
  const failedChecks = findings.filter((f) => f.status === 'failed').length;
  const incompleteChecks = findings.filter((f) => f.status === 'unknown').length;
  const criticalFindings = findings.filter(
    (f) => f.severity === 'critical' || (f.status === 'failed' && f.severity === 'high')
  ).length;

  const flaggedProviders = report.threatProviders.filter((p) => p.status === 'flagged').length;
  const hasActivePositiveRisk =
    failedChecks > 0 ||
    flaggedProviders > 0 ||
    hasLevelBHighRisk ||
    findings.some((f) => f.status === 'warning' && f.weight > 0);

  let riskScore = report.riskScore;
  let classification: RiskClassification = report.classification;
  let verdict = report.verdict;
  let scoreBreakdown = report.scoreBreakdown ? report.scoreBreakdown.map((s) => ({ ...s })) : undefined;

  if (!hasActivePositiveRisk && classification !== 'UNKNOWN') {
    riskScore = 0;
    const isOfficial =
      report.domainAuthenticity &&
      (report.domainAuthenticity.status === 'official_verified' ||
        report.domainAuthenticity.status === 'official_subdomain') &&
      report.domainAuthenticity.corroborated &&
      !report.domainAuthenticity.conflictDetected;
    classification = isOfficial ? 'OFFICIAL_DOMAIN_VERIFIED' : 'NO_KNOWN_THREATS';
    verdict = isOfficial ? 'Official Domain Verified' : 'No Known Threats';
    scoreBreakdown = [];
  }

  // Monotonic clamp check between classification & riskScore
  if (classification === 'OFFICIAL_DOMAIN_VERIFIED' || classification === 'NO_KNOWN_THREATS') {
    riskScore = Math.min(riskScore, 11);
  } else if (classification === 'LOW' && riskScore > 50) {
    classification = 'MEDIUM';
    verdict = 'Medium Risk';
  } else if (classification === 'MEDIUM' && riskScore <= 50 && failedChecks === 0 && !hasLevelBHighRisk) {
    classification = 'LOW';
    verdict = 'Low Risk';
  } else if (riskScore >= 70 && (classification === 'LOW' || classification === 'MEDIUM')) {
    classification = riskScore >= 82 ? 'CRITICAL' : 'HIGH';
    verdict = riskScore >= 82 ? 'Critical Risk' : 'High Risk';
  }

  // Keep scoreBreakdown delta sum strictly synchronized with riskScore when scoreBreakdown exists
  if (scoreBreakdown && scoreBreakdown.length > 0) {
    const ledgerSum = scoreBreakdown.reduce((acc, item) => acc + item.delta, 0);
    if (ledgerSum !== riskScore) {
      scoreBreakdown.push({
        id: 'consistency-balance',
        ruleId: 'CONSISTENCY_LEDGER_BALANCE',
        label: {
          en: 'Consistency Calibration Balance',
          ar: 'موازنة الاتساق النهائية للنقاط',
        },
        category: 'calibration',
        delta: riskScore - ledgerSum,
      });
    }
  }

  // Rebuild topReasons / confirmedBucket from actual failed findings if high-risk scrubbing emptied them
  if (topReasons.length === 0) {
    const sortedFailed = [...findings]
      .filter((f) => f.status === 'failed')
      .sort((a, b) => b.weight - a.weight);
    if (sortedFailed.length > 0) {
      topReasons = sortedFailed.slice(0, 4).map((f) => ({
        en: `${f.test.en}: ${f.result.en}`,
        ar: `${f.test.ar}: ${f.result.ar}`,
      }));
    } else {
      topReasons = [
        {
          en: `${passedChecks} deterministic check(s) completed cleanly with ${report.summaryStats.availableProviders}/${report.summaryStats.totalProviders} active threat feeds reporting 0 hits.`,
          ar: `اكتمل ${passedChecks} فحصاً حتمياً بنجاح مع استجابة ${report.summaryStats.availableProviders}/${report.summaryStats.totalProviders} من مزودي التهديدات دون بلاغات.`,
        },
      ];
    }
  }

  if (confirmedBucket.length === 0) {
    const failedConfirmed = findings
      .filter((f) => f.status === 'failed')
      .slice(0, 6)
      .map((f) => ({ en: `${f.test.en}: ${f.result.en}`, ar: `${f.test.ar}: ${f.result.ar}` }));
    confirmedBucket = failedConfirmed.length > 0 ? failedConfirmed : [topReasons[0]];
  }

  // Ensure separatedAssessments.websiteSecurity never claims "No malicious content" when severe web threats exist
  let separatedAssessments = report.separatedAssessments;
  if (separatedAssessments && isHighOrCritical && separatedAssessments.websiteSecurity.status !== 'failed') {
    separatedAssessments = {
      ...separatedAssessments,
      websiteSecurity: {
        ...separatedAssessments.websiteSecurity,
        status: 'failed',
        verdict: {
          en: 'Active security threats, exfiltration chains, or backdoors detected',
          ar: 'تم رصد تهديدات أمنية نشطة أو سلاسل تسريب أو أبواب خلفية',
        },
      },
    };
  }

  // Synchronize technical sections counts with normalized findings
  const sections = report.sections.map((sec) => {
    const secFindings = findings.filter((f) => f.section === sec.id);
    if (secFindings.length === 0) return sec;
    const secFailed = secFindings.filter((f) => f.status === 'failed').length;
    const secWarn = secFindings.filter((f) => f.status === 'warning').length;
    const secPassed = secFindings.filter((f) => f.status === 'pass').length;
    const secUnknown = secFindings.filter((f) => f.status === 'unknown').length;
    const nextStatus: CheckStatus =
      secFailed > 0
        ? 'failed'
        : secWarn > 0
          ? 'warning'
          : secUnknown === secFindings.length
            ? 'unknown'
            : 'pass';
    const scrubbedSummary =
      isHighOrCritical && sec.id === 'source_intelligence' && /\bHarmful:\s*0\b/i.test(sec.summary.en)
        ? {
            en: 'Confirmed security threats, exfiltration flows, or suspicious hooks detected in source analysis.',
            ar: 'تم رصد تهديدات أمنية أو سلاسل تسريب بيانات أو خطافات مشبوهة في تحليل الشيفرة.',
          }
        : sec.summary;
    return {
      ...sec,
      status: nextStatus,
      summary: scrubbedSummary,
      findingsCount: secFindings.length,
      passedCount: secPassed,
      warningCount: secWarn,
      failedCount: secFailed,
      unknownCount: secUnknown,
    };
  });

  return {
    ...report,
    riskScore,
    classification,
    verdict,
    scoreBreakdown,
    separatedAssessments,
    sections,
    findings,
    correlationNotes,
    topReasons,
    evidenceBuckets: {
      confirmed: confirmedBucket,
      suspicious: suspiciousBucket,
      inconclusive: existingBuckets.inconclusive,
      conflicting: existingBuckets.conflicting,
    },
    summaryStats: {
      ...report.summaryStats,
      totalChecks: findings.length,
      passedChecks,
      warningChecks,
      failedChecks,
      criticalFindings,
      incompleteChecks,
    },
  };
}
