export type CheckStatus = 'pass' | 'warning' | 'failed' | 'unknown';
export type RiskSeverity = 'critical' | 'high' | 'medium' | 'low' | 'informational' | 'unknown';
export type RiskClassification =
  | 'CRITICAL'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW'
  | 'NO_KNOWN_THREATS'
  | 'OFFICIAL_DOMAIN_VERIFIED'
  | 'SAFE_INDICATORS'
  | 'UNKNOWN';

export type TechnicalSectionId =
  | 'url_intelligence'
  | 'domain_deception'
  | 'redirect_analysis'
  | 'domain_intelligence'
  | 'dns_analysis'
  | 'ssl_tls_analysis'
  | 'website_content'
  | 'source_intelligence'
  | 'page_discovery'
  | 'phishing_detection'
  | 'brand_impersonation'
  | 'javascript_analysis'
  | 'supply_chain_analysis'
  | 'file_download_analysis'
  | 'xss_security'
  | 'external_threat_intel'
  | 'screenshot_evidence';

export interface BilingualText {
  en: string;
  ar: string;
}

export interface FindingForensicDetail {
  whereDetected: BilingualText;
  whyRisky: BilingualText;
  howExploited: BilingualText;
  userImpact: BilingualText;
  notProvenAlone: BilingualText;
}

export interface CheckFinding {
  id: string;
  section: TechnicalSectionId;
  test: BilingualText;
  result: BilingualText;
  status: CheckStatus;
  severity: RiskSeverity;
  weight: number;
  evidence: string;
  relatedUrl?: string;
  pageFoundOn?: string;
  sourceCodeEvidence?: string;
  httpEvidence?: string;
  threatIntelEvidence?: string;
  explanation: BilingualText;
  recommendedAction: BilingualText;
  forensic?: FindingForensicDetail;
  source: string;
  timestamp: string;
  lastUpdated?: string;
  confidence: number; // 0-100
  reliabilityLabel?: 'High' | 'Medium' | 'Low';
  riskImpact?: 'none' | 'low' | 'medium' | 'high' | 'critical';
  errorState?: string;
  dataClassification?: string;
  destination?: string;
  consentContext?: string;
}

export interface RedirectHop {
  step: number;
  url: string;
  sourceUrl?: string;
  destinationUrl?: string;
  redirectType?: 'initial' | 'http_3xx' | 'meta_refresh' | 'js_static' | 'loop_or_blocked';
  hostname: string;
  protocol: string;
  statusCode: number | null;
  locationHeader?: string;
  resolvedIp?: string;
  crossDomain: boolean;
  isSameOrganization?: boolean;
  relationshipType?: string;
  relationshipDetail?: string;
  downgradedToHttp: boolean;
  latencyMs: number;
  blockedReason?: string;
}

export interface DomainDeceptionData {
  submittedHost: string;
  finalHost: string;
  originalDomain: string;
  normalizedDomain: string;
  apparentUserDomain: string;
  publicSuffix: string;
  eTldPlusOne: string;
  registrableDomain: string;
  asciiDomain: string;
  unicodeDomain: string;
  isPunycode: boolean;
  mixedScripts: boolean;
  bidiControlsDetected: boolean;
  bidiChars: { char: string; codePoint: string; name: string }[];
  zeroWidthDetected: boolean;
  zeroWidthCount: number;
  fragmentDeception: boolean;
  fragmentEvidence?: string;
  confusableDetected: boolean;
  confusableSkeleton?: string;
  confusableLookalikeDomain?: string;
  confusableCharacters: { char: string; codePoint: string; lookalikeAscii: string; script: string }[];
  subdomainSpoofing: boolean;
  spoofedTargetDomain?: string;
  authorityMasking: boolean;
  visibleVsRealMismatches: { visibleText: string; actualHost: string; actualUrl: string }[];
  embeddedRedirectUrls: { param: string; targetUrl: string; targetHost: string }[];
  openRedirectConfirmed: boolean;
  openRedirectEvidence?: string;
  typosquatTarget?: {
    brand: string;
    officialDomain: string;
    distance: number;
    technique: string;
  };
  typosquatDiff?: {
    technique: 'substitution' | 'insertion' | 'omission' | 'repetition' | 'digraph' | 'homoglyph' | 'compound_lookalike';
    targetDomain: string;
    similarityScore: number;
    differenceSummary: BilingualText;
  };
  similarityOnly?: boolean;
  brandSimilarityMatches?: {
    brand: string;
    officialDomain: string;
    similarityType: 'compound_brand_name' | 'leetspeak_lookalike' | 'typosquat' | 'subdomain_spoof' | 'homoglyph';
    matchedToken: string;
    evidence: string;
  }[];
}

export interface DomainIntelData {
  domain: string;
  registrableDomain: string;
  isMultiTenantPaas: boolean;
  paasProvider?: string;
  registrationDate?: string;
  expirationDate?: string;
  lastUpdatedDate?: string;
  domainAgeDays?: number;
  domainAgeYears?: number;
  registrar?: string;
  registry?: string;
  nameservers: string[];
  statuses: string[];
  privacyProtected: boolean | null;
  ownerSummary: BilingualText;
  dnsRecords: {
    a: string[];
    aaaa: string[];
    mx: string[];
    ns: string[];
    txt: string[];
    cname: string[];
    caa?: string[];
    soa?: string;
    ptr: string[];
    dnssecValidated: boolean | null;
    dnsProvider?: string;
    cdnOrProxyProvider?: string;
    minTtlSeconds?: number;
    fastFluxSuspected?: boolean;
    hasSpf: boolean;
    hasDmarc: boolean;
    dohVerified?: boolean;
  };
  ipAddress?: string;
  asn?: string;
  networkName?: string;
  country?: string;
  rdapSource?: string;
  whoisSource?: string;
  ipIntel?: {
    ip: string;
    city?: string;
    region?: string;
    country?: string;
    countryCode?: string;
    isp?: string;
    org?: string;
    asn?: string;
    reversePtr?: string[];
    isHostingOrProxy?: boolean;
    openPorts?: number[];
    vulns?: string[];
    cpes?: string[];
    tags?: string[];
    hostnames?: string[];
    source?: string;
  };
  subdomainAnalysis?: {
    subdomainPrefix: string;
    subdomainLevels: number;
    sensitiveRoleTokens: string[];
    cnameTargets: string[];
    externalCnameDelegation: boolean;
    externalCnameRelationship?: string;
    assessment: BilingualText;
  };
}

export interface TlsInspectionData {
  httpsAvailable: boolean;
  authorized: boolean;
  authorizationError?: string;
  protocol?: string;
  cipher?: string;
  keyBits?: number;
  sigAlg?: string;
  weakProtocolOrCipher?: boolean;
  weakCipherReasons?: string[];
  chainLength?: number;
  subjectCN?: string;
  issuer?: string;
  validFrom?: string;
  validTo?: string;
  daysRemaining?: number;
  expired?: boolean;
  domainMatches?: boolean;
  sanList: string[];
  sha256Fingerprint?: string;
  ctLogCount?: number;
  ctSource?: string;
  isSharedMultiTenantCert?: boolean;
  sharedWildcardSanNote?: string;
}

export interface ContentInspectionData {
  httpStatus?: number;
  contentType?: string;
  htmlSizeBytes: number;
  pageTitle?: string;
  metaDescription?: string;
  visibleWordCount: number;
  formCount: number;
  passwordInputCount: number;
  unwrappedPasswordInputCount: number;
  usernameInputCount: number;
  sensitiveInputHints: string[];
  crossOriginFormActions: string[];
  externalLinkCount: number;
  externalResourceDomains: string[];
  externalScriptDomains: string[];
  iframeCount: number;
  hiddenElementCount: number;
  inlineScriptCount: number;
  externalScriptCount: number;
  popupIndicators: string[];
  autoRedirectIndicators: string[];
  jsIndicators: string[];
  notificationApiDetected: boolean;
  requestedPermissions?: string[];
  autoDownloadTriggers?: string[];
  maliciousAdIndicators?: string[];
  fakeAlertIndicators: string[];
  phishingKeywordsMatched: string[];
  contentReadStatus?: 'full' | 'truncated' | 'blocked_by_site' | 'non_html' | 'unreachable';
  blockedReason?: string;
  headings?: string[];
  buttonLabels?: string[];
  internalLinkCount?: number;
  logoAltTexts?: string[];
  waitingOrInterstitialDetected?: boolean;
  oauthWidgetsDetected?: string[];
  fakeSupportIndicators?: string[];
  personalFinanceFields?: string[];
  claimedPurpose?: BilingualText;
  permissionAudit?: {
    permissions: {
      id: string;
      label: BilingualText;
      api: string;
      triggeredOnEntry: boolean;
      triggerContext: BilingualText;
      consistentWithSitePurpose: boolean;
      reason: BilingualText;
    }[];
    triggeredOnEntry: boolean;
    entryTriggerEvidence: string[];
    statedPurposeSummary: BilingualText;
    statedUsageConsistent: boolean;
    usageVerificationVerdict: BilingualText;
    riskEscalatedToHigh: boolean;
  };
  suspectedBrand?: {
    brand: string;
    officialDomain: string;
    confidence: number;
    evidence: string[];
    similarityOnly?: boolean;
  };
}

export interface SuspiciousCodeSignal {
  id: string;
  indicator: string;
  category:
    | 'obfuscation'
    | 'dynamic_eval'
    | 'dom_injection'
    | 'redirect'
    | 'exfiltration'
    | 'fingerprinting'
    | 'clipboard'
    | 'popup'
    | 'download_trigger';
  codeExcerpt: string;
  contextAssessment: BilingualText;
  benignContextPossible: boolean;
  riskLevel: RiskSeverity;
}

export interface DiscoveredSubdomainInfo {
  host: string;
  sources: string[];
  role: 'auth' | 'api' | 'cdn_static' | 'mail' | 'admin' | 'general';
  suspiciousRole?: boolean;
  resolvedIps?: string[];
  cnameChain?: string[];
}

export interface UrlEncryptionSegment {
  location: 'path_segment' | 'query_param' | 'fragment' | 'full_url';
  keyOrSegmentIndex: string;
  technique:
    | 'base64'
    | 'base64url_token'
    | 'hex_encoded'
    | 'double_percent_encoding'
    | 'heavy_percent_encoding'
    | 'unicode_escape'
    | 'high_entropy_cipher';
  rawSample: string;
  decodedPreview?: string;
  entropy?: number;
  containsSensitiveOrUrl?: boolean;
  note: BilingualText;
}

export interface UrlDecodedSecretItem {
  param: string;
  kind: 'telegram_bot_token' | 'chat_id' | 'api_secret';
  redactedPreview: string;
  hasBotToken: boolean;
  hasChatId: boolean;
  note: BilingualText;
}

export interface UrlEncryptionTelemetry {
  hasEncryptedOrEncodedParts: boolean;
  encodedPathSegmentCount: number;
  encodedQueryParamCount: number;
  doublePercentEncoded: boolean;
  totalPercentEncodedChars: number;
  segments: UrlEncryptionSegment[];
  decodedSecretsDetected?: UrlDecodedSecretItem[];
  summary: BilingualText;
}

export interface BackgroundDataCollectionItem {
  id: string;
  category:
    | 'cookies_storage'
    | 'credentials_inputs'
    | 'browser_fingerprinting'
    | 'keystrokes_clipboard'
    | 'device_network_webrtc'
    | 'background_polling';
  title: BilingualText;
  apisUsed: string[];
  triggers: string[];
  excerpt: string;
  riskLevel: RiskSeverity;
  detail: BilingualText;
  sourceScript?: string;
  sourceFunction?: string;
  pipelineStage?: string;
  transmittedExternally?: boolean;
  destinationHost?: string;
  consentState?: 'pre_consent' | 'post_consent' | 'not_required' | 'unknown';
  purpose?: BilingualText;
}

export type TransmittedDataType =
  | 'credentials'
  | 'session_tokens'
  | 'cookies'
  | 'financial_pii'
  | 'keystrokes_clipboard'
  | 'device_fingerprint'
  | 'analytics_metrics'
  | 'error_telemetry'
  | 'functional_state'
  | 'unknown'
  | 'personal_pii'
  | 'api_keys'
  | 'form_inputs'
  | 'geolocation'
  | 'storage_data'
  | 'system_telemetry';

export type LevelBNetworkChannelCategory =
  | 'HIGH_RISK_EXFILTRATION_CHANNEL'
  | 'IP_AND_DEVICE_PROFILING'
  | 'WEBHOOK_OR_BOT_SINK'
  | 'UNVERIFIED_EXTERNAL'
  | 'FIRST_PARTY_OR_KNOWN';

export interface ExternalDataTransmissionItem {
  destinationUrl: string;
  destinationHost: string;
  method:
    | 'fetch'
    | 'xhr'
    | 'sendBeacon'
    | 'websocket'
    | 'eventsource'
    | 'dynamic_beacon'
    | 'form_action';
  obfuscatedUrl: boolean;
  decodedFrom?: string;
  isThirdParty: boolean;
  relationshipStatus:
    | 'external_unknown'
    | 'authorized_provider'
    | 'same_organization'
    | 'suspicious_lookalike';
  pairedWithBackgroundCollection: boolean;
  transmittedDataTypes: TransmittedDataType[];
  payloadEvidence?: string;
  harmClassification: 'malicious_harmful' | 'suspicious_tracking' | 'unverified_external' | 'benign_functional';
  channelCategory?: LevelBNetworkChannelCategory;
  isHarmful: boolean;
  harmAssessment: BilingualText;
  excerpt: string;
  detail: BilingualText;
  endpointPath?: string;
  httpMethod?: string;
  contentType?: string;
  payloadSizeBytes?: number;
  sanitizedPayloadPreview?: string;
  isEncryptedInTransit?: boolean;
  sourceScript?: string;
  sourceFunction?: string;
  trigger?: string;
  frequency?: 'once' | 'on_event' | 'periodic' | 'on_exit' | 'unknown';
  consentState?: 'pre_consent' | 'post_consent' | 'not_required' | 'unknown';
  purpose?: BilingualText;
  payloadClassification?: string;
  reliability?: 'High' | 'Medium' | 'Low';
  destinationRole?:
    | 'cdn'
    | 'analytics'
    | 'auth_provider'
    | 'ad_network'
    | 'payment_gateway'
    | 'api_backend'
    | 'unverified_third_party';
}

export type CookieCategory =
  | 'essential_necessary'
  | 'functional_preference'
  | 'security_cookie'
  | 'analytics'
  | 'advertising'
  | 'third_party'
  | 'suspicious'
  | 'malicious';

export type CookieAstOperation =
  | 'read'
  | 'parse'
  | 'validate'
  | 'filter'
  | 'encode'
  | 'decode'
  | 'store'
  | 'transmit'
  | 'theft';

export interface CookieAuditItem {
  name: string;
  source: 'http_set_cookie' | 'js_cookie_write' | 'js_cookie_read';
  category: CookieCategory;
  isThirdPartyOrAdNetwork: boolean;
  isMaliciousOrHarmful: boolean;
  isDeclaredOrConsented?: boolean;
  isEssentialForSite?: boolean;
  securityFlags?: {
    httpOnly: boolean;
    secure: boolean;
    sameSite?: string;
  };
  domainOrVendor?: string;
  excerpt?: string;
  detail: BilingualText;
  sanitizedValuePreview?: string;
  domain?: string;
  path?: string;
  expires?: string;
  maxAge?: number;
  persistence?: 'session' | 'persistent';
  party?: 'first_party' | 'third_party';
  purposeAssessment?: BilingualText;
  preConsentObserved?: boolean;
  postConsentRequired?: boolean;
  hasTrackingIdentifiers?: boolean;
  transmittedExternally?: boolean;
  externalDestinationHost?: string;
  astOperations?: CookieAstOperation[];
}

export interface CookieConsentVerification {
  hasConsentMechanism: boolean;
  mechanismType: 'banner' | 'modal_dialog' | 'explicit_notice' | 'cookie_flag' | 'none';
  explainsPurpose: boolean;
  hasRejectOrManageOption: boolean;
  requiresConsent: boolean;
  preConsentCookiesCount: number;
  postConsentOptionalCount: number;
  preConsentTrackingViolations: number;
  preConsentEssentialOnly: boolean;
  privacyViolationDetected: boolean;
  postRejectBehavior: 'compliant_blocked' | 'continues_tracking' | 'not_observable_statically' | 'not_applicable';
  behavioralCompliance: 'compliant' | 'pre_consent_essential_only' | 'undeclared_tracking_pre_consent' | 'unknown';
  details: BilingualText;
}

export interface CookieAuditSummary {
  totalCookiesInspected: number;
  httpSetCookieCount: number;
  jsCookieWriteCount: number;
  jsCookieReadCount: number;
  setsAdvertisingCookies: boolean;
  hasMaliciousCookieBehavior: boolean;
  hasConsentNoticeOrBanner: boolean;
  consentNoticeDetails?: BilingualText;
  consentVerification?: CookieConsentVerification;
  essentialFunctionalCount: number;
  securityCookieCount?: number;
  analyticsCookieCount?: number;
  adCookieCount: number;
  thirdPartyCookieCount?: number;
  suspiciousCookieCount?: number;
  maliciousCookieCount: number;
  categoryCounts?: Record<CookieCategory, number>;
  cookieStuffingSignals: string[];
  cookiesDetected: CookieAuditItem[];
  summary: BilingualText;
}

export type AdvertisingIntelligenceState =
  | 'legitimate_advertising'
  | 'declared_analytics'
  | 'consent_dependent_tracking'
  | 'undeclared_tracking'
  | 'suspicious_advertising'
  | 'malicious_advertising'
  | 'no_advertising_detected'
  | 'unknown_incomplete';

export interface AdvertisingIntelligenceSummary {
  status: AdvertisingIntelligenceState;
  label: BilingualText;
  adNetworksDetected: string[];
  analyticsPlatformsDetected: string[];
  firstPartyResponsibilityNote: BilingualText;
  thirdPartyAdResponsibilityNote?: BilingualText;
  malvertisingIndicators: string[];
  privacyViolations: string[];
  summary: BilingualText;
}

export interface WorkerDetectionInfo {
  hasServiceWorker: boolean;
  hasWebWorker: boolean;
  serviceWorkerUrls: string[];
  webWorkerUrls: string[];
  isMaliciousOrSuspicious: boolean;
  summary: BilingualText;
}

export interface MalvertisingSignalsInfo {
  popunderDetected: boolean;
  forcedRedirectDetected: boolean;
  fakeDownloadDetected: boolean;
  notificationAbuseDetected: boolean;
  cryptominerDetected: boolean;
  hiddenIframesCount: number;
  adNetworksDetected: string[];
  details: BilingualText[];
}

export interface SourceIntelligenceData {
  canonicalUrl?: string;
  ogTags: Record<string, string>;
  jsonLdCount: number;
  jsonLdTypes: string[];
  baseTagHref?: string;
  baseTagHijack: boolean;
  metaRefresh?: string;
  securityHeaders: {
    csp?: string;
    hsts?: string;
    xFrameOptions?: string;
    xContentTypeOptions?: string;
    referrerPolicy?: string;
    permissionsPolicy?: string;
  };
  externalJsFiles: string[];
  externalCssFiles: string[];
  inlineJsCount: number;
  inlineCssCount: number;
  iframeSources: string[];
  embeddedResources: { tag: string; src: string }[];
  hiddenInputs: { name?: string; type: string; valuePreview?: string }[];
  suspiciousAttributes: { attribute: string; tag: string; snippet: string }[];
  suspiciousCodeSignals: SuspiciousCodeSignal[];
  lureExcerpts: { label: string; excerpt: string }[];
  externalCssUrls?: string[];
  cssExternalDomains?: string[];
  storageAndCookieAccess?: string[];
  formExfiltrationHooks?: string[];
  isMinifiedBundlePresent?: boolean;
  obfuscationVsMinifiedNote?: BilingualText;
  titleContentMismatch?: boolean;
  titleMismatchDetail?: BilingualText;
  discoveredSubdomains?: DiscoveredSubdomainInfo[];
  brandLookalikeLinks?: {
    url: string;
    host: string;
    targetBrand: string;
    officialDomain: string;
    evidence: string;
  }[];
  jsDomMutationPayloads?: string[];
  dynamicContentAfterJsLikely?: boolean;
  staticVsRenderedNote?: BilingualText;
  externalJsInspectedCount?: number;
  jsBehaviorSummary?: {
    dynamicFormActionRewrite: boolean;
    passwordFieldDomHooks: boolean;
    walletDrainerPattern: boolean;
    antiDebugTraps: boolean;
    hiddenOverlayIframes: number;
    obfuscationMarkerCount: number;
  };
  backgroundDataCollection?: BackgroundDataCollectionItem[];
  externalDataTransmissions?: ExternalDataTransmissionItem[];
  dataFlowTaints?: StaticDataFlowTaintItem[];
  plantedBackdoors?: PlantedBackdoorItem[];
  cookieAudit?: CookieAuditSummary;
  advertisingIntel?: AdvertisingIntelligenceSummary;
  workersDetected?: WorkerDetectionInfo;
  malvertisingSignals?: MalvertisingSignalsInfo;
}

export interface StaticDataFlowTaintItem {
  id: string;
  source: string;
  sourceKind:
    | 'camera_mic'
    | 'geolocation'
    | 'clipboard'
    | 'ip_profiling'
    | 'url_params'
    | 'credentials_form'
    | 'storage_cookies';
  sink: string;
  sinkChannel: LevelBNetworkChannelCategory;
  triggerContext: 'STATIC_AUTO_TRIGGER_ON_LOAD' | 'DECEPTIVE_INTERACTION_TRIGGER' | 'user_click' | 'unknown';
  confirmedStaticFlow: boolean;
  detail: BilingualText;
  excerpt: string;
}

export interface PlantedBackdoorItem {
  id: string;
  kind:
    | 'hardcoded_bot_token'
    | 'hardcoded_api_secret'
    | 'hidden_control_param'
    | 'unsafe_postmessage_wildcard'
    | 'unvalidated_message_listener'
    | 'suspicious_backdoor_hook';
  severity: RiskSeverity;
  evidence: string;
  detail: BilingualText;
}

export interface FormSecurityDetail {
  pageUrl: string;
  formIndex: number;
  idOrName?: string;
  action: string;
  resolvedActionHost?: string;
  method: string;
  usesHttps: boolean;
  isCrossOrigin: boolean;
  originMismatch: boolean;
  inputTypes: string[];
  passwordCount: number;
  emailCount: number;
  otpCount: number;
  pinCount: number;
  cardCount: number;
  hiddenCount: number;
  invisibleCount: number;
  unusualAttributes: string[];
  jsHandlers: string[];
  riskLevel: RiskSeverity;
  reason: BilingualText;
}

export interface DiscoveredPageResult {
  url: string;
  title?: string;
  pageType:
    | 'login'
    | 'signup'
    | 'verification'
    | 'password_reset'
    | 'payment'
    | 'checkout'
    | 'wallet'
    | 'banking'
    | 'admin'
    | 'download'
    | 'support'
    | 'security'
    | 'general';
  discoverySource: 'internal_link' | 'nav_menu' | 'footer' | 'canonical' | 'sitemap' | 'robots';
  status: 'inspected' | 'skipped' | 'blocked_ssrf' | 'error';
  statusCode?: number;
  severity: RiskSeverity;
  indicators: string[];
  reason: BilingualText;
  formCount: number;
  passwordInputCount: number;
  crossOriginForms: number;
  lureCount: number;
}

export interface PageDiscoverySummary {
  robotsTxtChecked: boolean;
  sitemapChecked: boolean;
  totalDiscovered: number;
  inspectedCount: number;
  skippedCount: number;
  pages: DiscoveredPageResult[];
}

export interface SupplyChainResourceSummary {
  totalExternalDomains: number;
  scripts: { url: string; host: string; isThirdParty: boolean; isCdn: boolean }[];
  stylesheets: { url: string; host: string; isThirdParty: boolean; isCdn: boolean }[];
  iframes: { url: string; host: string; isThirdParty: boolean }[];
  fonts: string[];
  imagesCount: number;
  externalImagesCount: number;
  apiEndpoints: string[];
  trackingServices: { name: string; host: string }[];
  cdnDomains: string[];
  externalForms: string[];
  outdatedLibraries: { library: string; detectedVersion: string; sourceUrl: string; advisory: string }[];
}

export interface VisualIdentityComparison {
  attempted: boolean;
  screenshotAvailable: boolean;
  suspectedBrand?: string;
  officialDomain?: string;
  brandMismatch: boolean;
  titleMatchesBrandOutsideOfficial: boolean;
  faviconDetected: boolean;
  similarityAssessment: BilingualText;
  limitationNote: BilingualText;
}

export type FileDownloadCategory =
  | 'user_initiated_download'
  | 'automatic_download'
  | 'deceptive_download'
  | 'executable'
  | 'archive'
  | 'script'
  | 'verified_safe_resource'
  | 'unknown_file';

export interface FileDownloadItem {
  url: string;
  filename: string;
  extension: string;
  declaredMime?: string;
  detectedSignature?: string;
  sizeBytes?: number;
  sha256?: string;
  mimeMismatch: boolean;
  suspiciousNaming: boolean;
  downloadCategory?: FileDownloadCategory;
  analysisState: 'header_inspected' | 'not_fully_analyzed' | 'blocked_size_limit';
  riskFlag: RiskSeverity;
  notes: BilingualText;
}

export type ProviderOperationalState =
  | 'active'
  | 'configured'
  | 'disabled'
  | 'rate_limited'
  | 'unavailable'
  | 'auth_required';

export interface ThreatProviderResult {
  providerId: string;
  providerName: string;
  category: string;
  enabled: boolean;
  configured: boolean;
  operationalState: ProviderOperationalState;
  status:
    | 'clean'
    | 'flagged'
    | 'suspicious'
    | 'unknown'
    | 'unavailable'
    | 'auth_required'
    | 'error'
    | 'rate_limited'
    | 'disabled';
  verdictDetail: BilingualText;
  engineStats?: {
    malicious: number;
    suspicious: number;
    harmless: number;
    undetected: number;
  };
  inspectedTargets?: string[];
  matchScope?: 'exact_url' | 'hostname' | 'registrable_domain' | 'ip_address' | 'none';
  dataSource?: string;
  lastAnalyzedAt?: string;
  latencyMs?: number;
  lastSuccessfulLookup?: string;
  cached?: boolean;
  referenceUrl?: string;
  requiresKey: boolean;
  envVarName?: string;
}

export interface ScreenshotResult {
  status: 'captured' | 'unavailable' | 'blocked_private_url' | 'failed';
  method: 'screenshotneo' | 'none';
  viewport: 'desktop' | 'mobile' | 'full_page';
  capturedAt?: string;
  finalDestinationUrl: string;
  imageDataUrl?: string;
  mobileImageDataUrl?: string;
  fullPageAvailable: boolean;
  reason?: BilingualText;
}

export interface TechnicalSectionSummary {
  id: TechnicalSectionId;
  title: BilingualText;
  status: CheckStatus;
  severity: RiskSeverity;
  summary: BilingualText;
  findingsCount: number;
  passedCount: number;
  warningCount: number;
  failedCount: number;
  unknownCount: number;
}

export type FinalVerdict =
  | 'Critical Risk'
  | 'Critical'
  | 'Malicious Indicators Detected'
  | 'High Risk'
  | 'Medium Risk'
  | 'Suspicious'
  | 'Low Risk'
  | 'No Known Threats'
  | 'Official Domain Verified'
  | 'Safe Indicators Found'
  | 'No Known Threats Detected'
  | 'Insufficient Evidence'
  | 'Inconclusive'
  | 'Incomplete Analysis';

export interface SeparatedPillarAssessment {
  id: 'domain_authenticity' | 'threat_intelligence' | 'website_security' | 'ssl_tls_status' | 'redirect_analysis';
  title: BilingualText;
  status: CheckStatus;
  verdict: BilingualText;
  detail: BilingualText;
  caveat?: BilingualText;
}

export interface DomainHostingMetadata {
  isSharedPaas: boolean;
  hostingProvider?: string;
  customDomainOwnership: 'verified' | 'unverified';
  websiteIdentity: BilingualText;
}

export interface XssIndicatorItem {
  id: string;
  type:
    | 'reflected_param'
    | 'dom_sink'
    | 'weak_csp'
    | 'missing_csp'
    | 'cookie_httponly'
    | 'unsafe_postmessage'
    | 'decoded_param_sink';
  severity: RiskSeverity;
  parameterOrSink: string;
  context: string;
  detail: BilingualText;
  excerpt?: string;
}

export interface XssAssessmentData {
  status: 'safe' | 'potential_weakness' | 'high_risk' | 'unavailable';
  label: BilingualText;
  summary: BilingualText;
  reflectedParamsCount: number;
  domSinkCount: number;
  cspStatus: 'strict' | 'weak' | 'missing';
  httpOnlySessionCookiesMissing: boolean;
  indicators: XssIndicatorItem[];
  remediationGuidance: BilingualText[];
}

export interface ScanReportDomainAuthenticity {
  status:
    | 'official_verified'
    | 'official_subdomain'
    | 'authorized_third_party'
    | 'partner_or_provider'
    | 'brand_lookalike'
    | 'unknown_unverified';
  label: BilingualText;
  registrableDomain: string;
  subdomain: string;
  publicSuffix: string;
  parentCompany?: string;
  officialProduct?: string;
  relationshipLabel?: BilingualText;
  corroborated: boolean;
  corroborationSources: {
    source: string;
    signal: string;
    verified: boolean;
    timestamp?: string;
  }[];
  registrySources: string[];
  disclaimer: BilingualText;
  conflictDetected: boolean;
  conflictDetail?: BilingualText;
  hostingMetadata?: DomainHostingMetadata;
}

export interface ScanReport {
  scanId: string;
  submittedUrl: string;
  normalizedUrl: string;
  finalDestinationUrl: string;
  pageTitle?: string;
  siteFaviconDataUrl?: string;
  siteFaviconSourceUrl?: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  status: 'completed' | 'partial' | 'failed';
  riskScore: number; // 0-100
  classification: RiskClassification;
  verdict: FinalVerdict;
  confidenceScore: number; // 0-100
  confidenceLabel: 'High' | 'Medium' | 'Low';
  inspectionCoveragePercent?: number;
  recommendation: BilingualText;
  topReasons: BilingualText[];
  correlationNotes: BilingualText[];
  conflictNotes?: BilingualText[];
  scoreBreakdown?: {
    id: string;
    ruleId?: string;
    label: BilingualText;
    category: string;
    delta: number;
    evidence?: string;
    explanation?: BilingualText;
  }[];
  evidenceBuckets?: {
    confirmed: BilingualText[];
    suspicious: BilingualText[];
    inconclusive: BilingualText[];
    conflicting: BilingualText[];
  };
  websiteIntelligenceReport?: {
    itemKey: string;
    title: BilingualText;
    status: 'inspected' | 'not_present' | 'unavailable';
    summary: BilingualText;
    detail?: string;
  }[];
  domainAuthenticity?: ScanReportDomainAuthenticity;
  separatedAssessments?: {
    domainAuthenticity: SeparatedPillarAssessment;
    threatIntelligence: SeparatedPillarAssessment;
    websiteSecurity: SeparatedPillarAssessment;
    sslTlsStatus: SeparatedPillarAssessment;
    redirectAnalysis: SeparatedPillarAssessment;
  };
  summaryStats: {
    totalChecks: number;
    passedChecks: number;
    warningChecks: number;
    failedChecks: number;
    criticalFindings: number;
    incompleteChecks: number;
    availableProviders: number;
    totalProviders: number;
  };
  sections: TechnicalSectionSummary[];
  findings: CheckFinding[];
  redirects: RedirectHop[];
  domainDeception?: DomainDeceptionData;
  urlEncryptionIntel?: UrlEncryptionTelemetry;
  domainIntel?: DomainIntelData;
  tlsIntel?: TlsInspectionData;
  contentIntel?: ContentInspectionData;
  sourceIntel?: SourceIntelligenceData;
  pageDiscovery?: PageDiscoverySummary;
  formSecurityDetails?: FormSecurityDetail[];
  supplyChain?: SupplyChainResourceSummary;
  visualIdentity?: VisualIdentityComparison;
  fileAnalysis: {
    isDirectDownload: boolean;
    directFile?: FileDownloadItem;
    discoveredDownloads: FileDownloadItem[];
    dynamicAnalysisPerformed: boolean;
    sandboxNote: BilingualText;
  };
  xssAssessment?: XssAssessmentData;
  threatProviders: ThreatProviderResult[];
  screenshot: ScreenshotResult;
  sandboxCapabilities: {
    ssrfGuardActive: boolean;
    isolatedBrowserWorker: boolean;
    screenshotFallbackConfigured: boolean;
    dynamicFileSandbox: boolean;
    inspectionMode: 'controlled_server_fetch' | 'isolated_worker';
    disclosure: BilingualText;
  };
  analysisLevels?: {
    levelAStatic: {
      performed: boolean;
      status: 'complete' | 'partial' | 'blocked_by_site' | 'unavailable';
      coverageItems: string[];
      summary: BilingualText;
    };
    levelBIsolatedBrowser: {
      performed: boolean;
      available: boolean;
      sandboxMode: 'unavailable' | 'isolated_worker' | 'external_cloud_browser';
      dynamicDomDivergenceLikely: boolean;
      reason: BilingualText;
    };
  };
  levelB?: LevelBExecutionData;
}

export type LevelBExecutionStatus =
  | 'executed'
  | 'unavailable'
  | 'failed'
  | 'blocked_by_ssrf'
  | 'disabled';

export interface LevelBNetworkRequestItem {
  url: string;
  domain: string;
  path: string;
  method: string;
  resourceType?: string;
  channelCategory: LevelBNetworkChannelCategory;
  isSensitiveSink: boolean;
  isThirdParty: boolean;
  statusCode?: number;
  note: BilingualText;
}

export interface LevelBPermissionEventItem {
  kind:
    | 'camera'
    | 'microphone'
    | 'geolocation'
    | 'clipboard'
    | 'notifications'
    | 'auto_timer'
    | 'lure_interaction'
    | 'other';
  api: string;
  trigger: 'on_load' | 'timer' | 'user_click' | 'unknown';
  outcome: 'attempted' | 'granted' | 'blocked' | 'observed' | 'not_triggered';
  detail: BilingualText;
}

export interface LevelBExecutionData {
  status: LevelBExecutionStatus;
  executionMode: 'external_cloud_browser' | 'unavailable';
  providerLabel: BilingualText;
  executedAt?: string;
  durationMs?: number;
  finalUrl?: string;
  redirects: { step: number; url: string; statusCode?: number; note?: string }[];
  screenshot: {
    captured: boolean;
    dataUrl?: string;
    viewport: 'desktop' | 'mobile' | 'full_page';
    width?: number;
    height?: number;
    capturedAt?: string;
    missingReason?: BilingualText;
  };
  networkRequests: LevelBNetworkRequestItem[];
  permissionEvents: LevelBPermissionEventItem[];
  domSummary?: {
    title?: string;
    dynamicFormCount: number;
    sensitiveInputCount: number;
    dynamicIframeCount: number;
    dynamicScriptCount: number;
    wordCount: number;
    notableElements: string[];
  };
  confidenceImpact: number;
  coverageImpact: number;
  errorReason?: BilingualText;
  executiveSummary: BilingualText;
}

export type ScanStageId =
  | 'url_validation'
  | 'dns_resolution'
  | 'redirect_tracer'
  | 'domain_rdap'
  | 'tls_inspection'
  | 'content_phishing'
  | 'source_intelligence'
  | 'page_discovery'
  | 'threat_intel'
  | 'level_b_cloud_browser'
  | 'screenshot_capture'
  | 'risk_scoring'
  | 'report_generation';

export interface ScanStageProgress {
  id: ScanStageId;
  label: BilingualText;
  status: 'pending' | 'running' | 'completed' | 'warning' | 'failed' | 'unavailable';
  detail?: BilingualText;
  durationMs?: number;
}

export interface ScanJobState {
  scanId: string;
  submittedUrl: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  progressPercent: number;
  startedAt: string;
  completedAt?: string;
  stages: ScanStageProgress[];
  report?: ScanReport;
  error?: BilingualText;
}
