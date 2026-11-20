import { useCallback, useEffect, useRef, useState } from 'react';
import type {
  AppPage,
  ErrorStatusCode,
  Language,
  ProviderDescriptor,
  SavedHistoryEntry,
  ScanJobState,
  ScanReport,
  ScreenshotViewport,
  ThemeMode,
} from './types/scan';
import { Navbar } from './components/Navbar';
import { ScannerHero } from './components/ScannerHero';
import { ScanProgressView } from './components/ScanProgressView';
import { SecurityReportView } from './components/SecurityReportView';
import { ProvidersView } from './components/ProvidersView';
import { HistoryView } from './components/HistoryView';
import { AboutView } from './components/AboutView';
import { PrivacyView } from './components/PrivacyView';
import { TermsView } from './components/TermsView';
import { ErrorView } from './components/ErrorView';
import { ConsentBanner } from './components/ConsentBanner';
import { Footer } from './components/Footer';
import {
  safeImageDataUrl,
  sanitizePlainText,
  sanitizeSavedReport,
  sanitizeUrlParamForScan,
} from './utils/sanitize';

async function safeJsonResponse(response: Response) {
  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) {
    await response.text();
    throw new Error(
      `Expected JSON response but received ${contentType || 'unknown content type'} (HTTP ${response.status}).`
    );
  }
  const data = await response.json();
  if (!response.ok) {
    const err = new Error(data?.error || data?.message || `HTTP error ${response.status}`) as Error & {
      status?: number;
    };
    err.status = response.status;
    throw err;
  }
  return data;
}

const THEME_KEY = 'scanlink_theme';
const LANG_KEY = 'scanlink_lang';
const CONSENT_KEY = 'scanlink_history_consent';
const HISTORY_KEY = 'scanlink_scan_history';
const DISABLED_PROVIDERS_KEY = 'scanlink_disabled_providers';

function loadInitialDisabledProviders(): string[] {
  try {
    const raw = localStorage.getItem(DISABLED_PROVIDERS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === 'string') : [];
  } catch {
    return [];
  }
}

const PAGE_TO_PATH: Record<Exclude<AppPage, 'error'>, string> = {
  home: '/',
  scanner: '/scanner',
  providers: '/providers',
  history: '/history',
  about: '/about',
  privacy: '/privacy',
  terms: '/terms',
};

const VALID_ERROR_CODES = new Set<number>([401, 403, 404, 429, 500, 502, 503]);

function resolveRouteFromPathname(
  pathname: string,
  checkServerErrorMeta = false
): { page: AppPage; errorCode: ErrorStatusCode } {
  if (checkServerErrorMeta && typeof document !== 'undefined') {
    const metaCodeRaw = document.querySelector('meta[name="scanlink-error-code"]')?.getAttribute('content');
    const metaCode = metaCodeRaw ? Number(metaCodeRaw) : NaN;
    if (VALID_ERROR_CODES.has(metaCode)) {
      return { page: 'error', errorCode: metaCode as ErrorStatusCode };
    }
  }
  const clean = pathname === '/' ? '/' : pathname.replace(/\/+$/, '');
  if (clean === '/') return { page: 'home', errorCode: 404 };
  if (clean === '/scanner') return { page: 'scanner', errorCode: 404 };
  if (clean === '/providers') return { page: 'providers', errorCode: 404 };
  if (clean === '/history') return { page: 'history', errorCode: 404 };
  if (clean === '/about') return { page: 'about', errorCode: 404 };
  if (clean === '/privacy') return { page: 'privacy', errorCode: 404 };
  if (clean === '/terms') return { page: 'terms', errorCode: 404 };

  const errMatch = clean.match(/^\/error\/(\d{3})$/);
  if (errMatch && VALID_ERROR_CODES.has(Number(errMatch[1]))) {
    return { page: 'error', errorCode: Number(errMatch[1]) as ErrorStatusCode };
  }
  return { page: 'error', errorCode: 404 };
}

const SEO_METADATA: Record<
  AppPage,
  {
    title: { en: string; ar: string };
    description: { en: string; ar: string };
    robots: string;
  }
> = {
  home: {
    title: {
      en: 'Scan Link SM — Website & URL Threat Intelligence Platform',
      ar: 'Scan Link SM — منصة فحص الروابط والمواقع وتحليل التهديدات',
    },
    description: {
      en: 'Analyze suspicious links, verify official domains, trace hidden redirects, inspect SSL/TLS certificates, and check real-time threat intelligence feeds.',
      ar: 'افحص الروابط المشبوهة، وتحقق من النطاقات الرسمية، وتتبع إعادة التوجيه، وافحص شهادات TLS واستخبارات التهديدات المباشرة.',
    },
    robots: 'index, follow',
  },
  scanner: {
    title: {
      en: 'URL Security Scanner — Scan Link SM',
      ar: 'فاحص الروابط الأمني — Scan Link SM',
    },
    description: {
      en: 'Live deterministic multi-layer security inspection workspace for URLs and websites.',
      ar: 'بيئة الفحص الأمني المباشر للروابط والمواقع عبر Scan Link SM.',
    },
    robots: 'noindex, nofollow',
  },
  providers: {
    title: {
      en: 'Threat Intelligence Providers & Network Map — Scan Link SM',
      ar: 'مزودي البيانات وخريطة الشبكة التفاعلية — Scan Link SM',
    },
    description: {
      en: 'Explore active security feeds including VirusTotal, URLhaus, OpenPhish, PhishStats, Cloudflare Security DNS, AlienVault OTX, Shodan InternetDB, and RDAP.',
      ar: 'استعرض مزودي البيانات وخريطة الشبكة التفاعلية وطبقات الفحص الأمني في منصة Scan Link SM.',
    },
    robots: 'index, follow',
  },
  history: {
    title: {
      en: 'Local Scan History — Scan Link SM',
      ar: 'سجل الفحوصات المحلي — Scan Link SM',
    },
    description: {
      en: 'Browser-local scan archive for consented inspection reports.',
      ar: 'أرشيف سجل الفحوصات المحفوظ محلياً في متصفحك فقط.',
    },
    robots: 'noindex, nofollow',
  },
  about: {
    title: {
      en: 'About Scan Link SM — Owned & Developed by Mohamed Abu AlSaud SM',
      ar: 'عن منصة Scan Link SM — المالك والمطور Mohamed Abu AlSaud SM',
    },
    description: {
      en: 'Learn how Scan Link SM delivers transparent, deterministic URL and website threat analysis by Mohamed Abu AlSaud SM (@A_Y_TR).',
      ar: 'تعرف على منصة Scan Link SM المتخصصة في فحص الروابط والمواقع وتحليل المؤشرات الأمنية، تطوير Mohamed Abu AlSaud SM (@A_Y_TR).',
    },
    robots: 'index, follow',
  },
  privacy: {
    title: {
      en: 'Privacy Policy — Scan Link SM',
      ar: 'سياسة الخصوصية — Scan Link SM',
    },
    description: {
      en: 'Privacy standards, local storage controls, and backend key isolation for Scan Link SM.',
      ar: 'سياسة الخصوصية وضوابط التخزين المحلي وعزل المفاتيح على الخادم في Scan Link SM.',
    },
    robots: 'index, follow',
  },
  terms: {
    title: {
      en: 'Terms of Use — Scan Link SM',
      ar: 'شروط الاستخدام — Scan Link SM',
    },
    description: {
      en: 'Terms of authorized security inspection and platform usage guidelines for Scan Link SM.',
      ar: 'شروط الاستخدام المصرح به والضوابط القانونية لمنصة Scan Link SM.',
    },
    robots: 'index, follow',
  },
  error: {
    title: {
      en: 'Status Notice — Scan Link SM',
      ar: 'تنبيه حالة الصفحة — Scan Link SM',
    },
    description: {
      en: 'Requested route or service status notice on Scan Link SM.',
      ar: 'صفحة تنبيه حالة المسار أو الخدمة على منصة Scan Link SM.',
    },
    robots: 'noindex, nofollow',
  },
};

function readCookie(name: string): string | null {
  try {
    const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
    return match ? decodeURIComponent(match[1]) : null;
  } catch {
    return null;
  }
}

function writeCookie(name: string, value: string): void {
  try {
    document.cookie = `${name}=${encodeURIComponent(value)}; path=/; max-age=31536000; SameSite=Lax`;
  } catch {
    // ignore
  }
}

function getInitialTheme(): ThemeMode {
  try {
    const saved = readCookie(THEME_KEY) || localStorage.getItem(THEME_KEY);
    if (saved === 'dark' || saved === 'light') return saved;
  } catch {
    // ignore
  }
  return 'light';
}

function getInitialLang(): Language {
  try {
    const saved = readCookie(LANG_KEY) || localStorage.getItem(LANG_KEY);
    if (saved === 'ar' || saved === 'en') return saved;
  } catch {
    // ignore
  }
  return 'en';
}

function getInitialConsent(): 'granted' | 'denied' | 'unset' {
  try {
    const val = localStorage.getItem(CONSENT_KEY);
    if (val === 'granted' || val === 'denied') return val;
  } catch {
    // ignore
  }
  return 'unset';
}

function normalizeLegacyClassification(raw: string | undefined): ScanReport['classification'] {
  const legacyMap: Record<string, ScanReport['classification']> = {
    'Critical Risk': 'CRITICAL',
    'High Risk': 'HIGH',
    'Medium Risk': 'MEDIUM',
    'Moderate Risk': 'MEDIUM',
    Guarded: 'LOW',
    'Low Risk': 'LOW',
    CRITICAL: 'CRITICAL',
    HIGH: 'HIGH',
    MEDIUM: 'MEDIUM',
    LOW: 'LOW',
    NO_KNOWN_THREATS: 'NO_KNOWN_THREATS',
    'No Known Threats': 'NO_KNOWN_THREATS',
    OFFICIAL_DOMAIN_VERIFIED: 'OFFICIAL_DOMAIN_VERIFIED',
    'Official Domain Verified': 'OFFICIAL_DOMAIN_VERIFIED',
    INFORMATIONAL: 'NO_KNOWN_THREATS',
    SAFE_INDICATORS: 'NO_KNOWN_THREATS',
    'Insufficient Evidence': 'UNKNOWN',
    UNKNOWN: 'UNKNOWN',
  };
  return (raw && legacyMap[raw]) || 'UNKNOWN';
}

function normalizeLegacySeverity(raw: string | undefined): ScanReport['findings'][number]['severity'] {
  const legacyMap: Record<string, ScanReport['findings'][number]['severity']> = {
    none: 'informational',
    guarded: 'low',
    moderate: 'medium',
    critical: 'critical',
    high: 'high',
    medium: 'medium',
    low: 'low',
    informational: 'informational',
    unknown: 'unknown',
  };
  return (raw && legacyMap[raw]) || 'unknown';
}

function normalizeSavedEntry(entry: any): SavedHistoryEntry | null {
  if (!entry || typeof entry !== 'object' || !entry.report || !entry.scanId) return null;
  const r = entry.report;
  const providers = Array.isArray(r.threatProviders) ? r.threatProviders : [];
  const findings = Array.isArray(r.findings)
    ? r.findings.map((f: any) => ({
        ...f,
        severity: normalizeLegacySeverity(f.severity || f.risk),
        recommendedAction: f.recommendedAction || {
          en: 'Review the finding details and technical evidence carefully.',
          ar: 'راجع تفاصيل الفحص والأدلة التقنية بعناية.',
        },
      }))
    : [];

  const normalizedReport: ScanReport = {
    ...r,
    classification: normalizeLegacyClassification(r.classification),
    topReasons: Array.isArray(r.topReasons) ? r.topReasons : [],
    correlationNotes: Array.isArray(r.correlationNotes) ? r.correlationNotes : [],
    findings,
    summaryStats: {
      totalChecks: r.summaryStats?.totalChecks ?? findings.length,
      passedChecks: r.summaryStats?.passedChecks ?? 0,
      warningChecks: r.summaryStats?.warningChecks ?? 0,
      failedChecks: r.summaryStats?.failedChecks ?? 0,
      criticalFindings: r.summaryStats?.criticalFindings ?? 0,
      incompleteChecks: r.summaryStats?.incompleteChecks ?? 0,
      availableProviders:
        r.summaryStats?.availableProviders ??
        providers.filter((p: any) => p.status === 'clean' || p.status === 'flagged').length,
      totalProviders: r.summaryStats?.totalProviders ?? providers.length,
    },
    threatProviders: providers.map((p: any) => ({
      ...p,
      operationalState:
        p.operationalState ||
        (p.status === 'clean' || p.status === 'flagged'
          ? 'active'
          : p.status === 'unconfigured'
            ? 'auth_required'
            : 'unavailable'),
    })),
    sandboxCapabilities: r.sandboxCapabilities || {
      fullJsExecution: false,
      binaryExecution: false,
      disclosure: {
        en: 'Static HTML, DOM, redirect, DNS, TLS, and threat-feed inspection only. No scanned JavaScript or binaries are executed.',
        ar: 'فحص ساكن للبنية والشبكة والشهادات دون تنفيذ أكواد جافاسكربت أو تشغيل ملفات.',
      },
    },
    fileAnalysis: r.fileAnalysis || {
      isDirectDownload: false,
      discoveredDownloads: [],
      sandboxNote: {
        en: 'Static signature inspection only; no files executed.',
        ar: 'فحص توقيع ساكن فقط دون تشغيل أي ملفات.',
      },
    },
    recommendation: r.recommendation || {
      en: 'Review the report findings before interacting with this URL.',
      ar: 'راجع نتائج الفحص قبل التعامل مع هذا الرابط.',
    },
    sections: Array.isArray(r.sections) ? r.sections : [],
    redirects: Array.isArray(r.redirects) ? r.redirects : [],
    screenshot: {
      ...r.screenshot,
      viewport: r.screenshot?.viewport || 'desktop',
      finalDestinationUrl: r.screenshot?.finalDestinationUrl || r.finalDestinationUrl,
    },
  };

  const safeReport = sanitizeSavedReport(normalizedReport);

  return {
    ...entry,
    submittedUrl: sanitizePlainText(entry.submittedUrl || safeReport.submittedUrl),
    finalDestinationUrl: sanitizePlainText(entry.finalDestinationUrl || safeReport.finalDestinationUrl),
    classification: normalizeLegacyClassification(entry.classification || safeReport.classification),
    siteFaviconDataUrl: safeImageDataUrl(entry.siteFaviconDataUrl || safeReport.siteFaviconDataUrl),
    report: safeReport,
  };
}

function loadSavedHistorySafe(): { entries: SavedHistoryEntry[]; error: string | null } {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    if (!raw) return { entries: [], error: null };
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return { entries: [], error: 'Saved browser history format was unrecognized.' };
    }
    return {
      entries: parsed
        .map(normalizeSavedEntry)
        .filter((item): item is SavedHistoryEntry => item !== null),
      error: null,
    };
  } catch {
    return { entries: [], error: 'Unable to read local browser storage.' };
  }
}

export default function App() {
  const initialRoute = resolveRouteFromPathname(window.location.pathname, true);

  const [theme, setTheme] = useState<ThemeMode>(getInitialTheme);
  const [lang, setLang] = useState<Language>(getInitialLang);
  const [page, setPage] = useState<AppPage>(initialRoute.page);
  const [errorCode, setErrorCode] = useState<ErrorStatusCode>(initialRoute.errorCode);
  const [consentState, setConsentState] = useState<'granted' | 'denied' | 'unset'>(getInitialConsent);
  const [showConsentModal, setShowConsentModal] = useState(false);

  const [providers, setProviders] = useState<ProviderDescriptor[]>([]);
  const [disabledProviders, setDisabledProviders] = useState<string[]>(loadInitialDisabledProviders);
  const [activeJob, setActiveJob] = useState<ScanJobState | null>(null);
  const [activeReport, setActiveReport] = useState<ScanReport | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);

  const [history, setHistory] = useState<SavedHistoryEntry[]>(() =>
    getInitialConsent() === 'granted' ? loadSavedHistorySafe().entries : []
  );
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyStorageError, setHistoryStorageError] = useState<string | null>(() =>
    getInitialConsent() === 'granted' ? loadSavedHistorySafe().error : null
  );

  const eventSourceRef = useRef<EventSource | null>(null);

  const navigateTo = useCallback((nextPage: AppPage, code: ErrorStatusCode = 404) => {
    if (nextPage === 'error') {
      setErrorCode(code);
      setPage('error');
      const targetPath = `/error/${code}`;
      if (window.location.pathname !== targetPath) {
        window.history.pushState({ page: 'error', code }, '', targetPath);
      }
      window.scrollTo({ top: 0, behavior: 'smooth' });
      return;
    }

    if (nextPage === 'home') {
      setActiveJob(null);
      setActiveReport(null);
      setScanError(null);
    }
    setPage(nextPage);
    const targetPath = PAGE_TO_PATH[nextPage] || '/';
    if (window.location.pathname !== targetPath) {
      window.history.pushState({ page: nextPage }, '', targetPath);
    }
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }, []);

  useEffect(() => {
    const onPopState = () => {
      const resolved = resolveRouteFromPathname(window.location.pathname);
      setPage(resolved.page);
      setErrorCode(resolved.errorCode);
    };
    window.addEventListener('popstate', onPopState);
    return () => window.removeEventListener('popstate', onPopState);
  }, []);

  // Dynamic SEO Head Tags Synchronization (title, description, robots, canonical, OG/Twitter)
  useEffect(() => {
    const seo = SEO_METADATA[page] || SEO_METADATA.home;
    const titleStr = page === 'error' ? `HTTP ${errorCode} — ${seo.title[lang]}` : seo.title[lang];
    const descStr = seo.description[lang];
    document.title = titleStr;

    const setMeta = (selector: string, attr: 'name' | 'property', key: string, content: string) => {
      let el = document.querySelector(selector) as HTMLMetaElement | null;
      if (!el) {
        el = document.createElement('meta');
        el.setAttribute(attr, key);
        document.head.appendChild(el);
      }
      el.setAttribute('content', content);
    };

    setMeta('meta[name="description"]', 'name', 'description', descStr);
    setMeta('meta[name="robots"]', 'name', 'robots', seo.robots);
    setMeta('meta[property="og:title"]', 'property', 'og:title', titleStr);
    setMeta('meta[property="og:description"]', 'property', 'og:description', descStr);
    setMeta('meta[name="twitter:title"]', 'name', 'twitter:title', titleStr);
    setMeta('meta[name="twitter:description"]', 'name', 'twitter:description', descStr);

    const canonical = document.getElementById('canonical-link') as HTMLLinkElement | null;
    if (canonical && page !== 'error') {
      canonical.href = `${window.location.origin}${PAGE_TO_PATH[page]}`;
    }
  }, [page, errorCode, lang]);

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark');
    const metaTheme = document.querySelector('meta[name="theme-color"]');
    if (metaTheme) metaTheme.setAttribute('content', theme === 'dark' ? '#000000' : '#FFFFFF');
    writeCookie(THEME_KEY, theme);
    try {
      localStorage.setItem(THEME_KEY, theme);
    } catch {
      // ignore
    }
  }, [theme]);

  useEffect(() => {
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
    writeCookie(LANG_KEY, lang);
    try {
      localStorage.setItem(LANG_KEY, lang);
    } catch {
      // ignore
    }
  }, [lang]);

  const fetchProviders = useCallback(() => {
    fetch('/api/providers')
      .then(async (res) => {
        const data = await safeJsonResponse(res);
        if (data?.providers && Array.isArray(data.providers)) {
          setProviders(data.providers);
        }
      })
      .catch(() => {
        // Non-blocking
      });
  }, []);

  useEffect(() => {
    fetchProviders();
  }, [fetchProviders]);

  useEffect(() => {
    if (consentState !== 'unset' || page === 'error') return;
    const timer = setTimeout(() => setShowConsentModal(true), 1200);
    return () => clearTimeout(timer);
  }, [consentState, page]);

  useEffect(() => {
    try {
      localStorage.setItem(DISABLED_PROVIDERS_KEY, JSON.stringify(disabledProviders));
    } catch {
      // ignore
    }
  }, [disabledProviders]);

  const toggleProvider = useCallback((id: string) => {
    setDisabledProviders((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  }, []);

  const setAllDisabledProviders = useCallback((ids: string[]) => {
    setDisabledProviders(Array.from(new Set(ids)));
  }, []);

  const saveReportToHistory = useCallback(
    (report: ScanReport) => {
      if (consentState !== 'granted') return;
      const entry: SavedHistoryEntry = {
        scanId: report.scanId,
        submittedUrl: report.submittedUrl,
        finalDestinationUrl: report.finalDestinationUrl,
        completedAt: report.completedAt,
        riskScore: report.riskScore,
        classification: report.classification,
        verdict: report.verdict,
        screenshotAvailable: report.screenshot.status === 'captured',
        siteFaviconDataUrl: report.siteFaviconDataUrl,
        status: report.status,
        report,
      };
      setHistory((prev) => {
        const next = [entry, ...prev.filter((h) => h.scanId !== report.scanId)].slice(0, 30);
        try {
          localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
          setHistoryStorageError(null);
        } catch {
          setHistoryStorageError('Local storage quota exceeded while saving scan history.');
        }
        return next;
      });
    },
    [consentState]
  );

  const cleanupStream = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
  };

  useEffect(() => () => cleanupStream(), []);

  const pollUntilDone = async (scanId: string) => {
    for (let i = 0; i < 30; i++) {
      try {
        const res = await fetch(`/api/scans/${encodeURIComponent(scanId)}`);
        const job: ScanJobState = await safeJsonResponse(res);
        setActiveJob(job);
        if (job.status === 'completed' && job.report) {
          setActiveReport(job.report);
          saveReportToHistory(job.report);
          fetchProviders();
          break;
        }
        if (job.status === 'failed') break;
      } catch {
        break;
      }
      await new Promise((r) => setTimeout(r, 800));
    }
  };

  const handleStartScan = async (options: {
    url: string;
    viewport: ScreenshotViewport;
    disabledProviders: string[];
  }) => {
    cleanupStream();
    setScanError(null);
    setActiveReport(null);
    navigateTo('scanner');

    try {
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(options),
      });
      const json = await safeJsonResponse(res);

      const initialJob: ScanJobState = {
        scanId: json.scanId,
        submittedUrl: options.url,
        status: json.status,
        progressPercent: json.progressPercent ?? 0,
        startedAt: new Date().toISOString(),
        stages: json.stages ?? [],
      };
      setActiveJob(initialJob);

      const es = new EventSource(`/api/scans/${encodeURIComponent(json.scanId)}/stream`);
      eventSourceRef.current = es;

      es.onmessage = (ev) => {
        try {
          const updated: ScanJobState = JSON.parse(ev.data);
          setActiveJob(updated);
          if (updated.status === 'completed' && updated.report) {
            const safeRep = sanitizeSavedReport(updated.report);
            setActiveReport(safeRep);
            saveReportToHistory(safeRep);
            fetchProviders();
            es.close();
            eventSourceRef.current = null;
          } else if (updated.status === 'failed') {
            es.close();
            eventSourceRef.current = null;
          }
        } catch {
          // ignore
        }
      };

      es.onerror = () => {
        es.close();
        eventSourceRef.current = null;
        void pollUntilDone(json.scanId);
      };
    } catch (err) {
      const httpStatus = (err as Error & { status?: number })?.status;
      if (httpStatus === 429) {
        navigateTo('error', 429);
        return;
      }
      setScanError((err as Error).message || 'Network failure starting scan.');
    }
  };

  // Auto-scan when ?url= is passed in query parameters (e.g. from PDF report or shared links)
  const autoScanTriggeredRef = useRef(false);
  useEffect(() => {
    if (autoScanTriggeredRef.current) return;
    try {
      const searchParams = new URLSearchParams(window.location.search);
      const urlParam = sanitizeUrlParamForScan(searchParams.get('url'));
      if (urlParam) {
        autoScanTriggeredRef.current = true;
        void handleStartScan({
          url: urlParam,
          viewport: 'desktop',
          disabledProviders,
        });
      }
    } catch {
      // ignore
    }
  }, [disabledProviders]);

  const handleResetScanner = () => {
    cleanupStream();
    setActiveJob(null);
    setActiveReport(null);
    setScanError(null);
    navigateTo('scanner');
  };

  const handleAcceptHistoryConsent = () => {
    setConsentState('granted');
    setShowConsentModal(false);
    setHistoryLoading(true);
    try {
      localStorage.setItem(CONSENT_KEY, 'granted');
      const loaded = loadSavedHistorySafe();
      setHistory(loaded.entries);
      setHistoryStorageError(loaded.error);
      if (activeReport) {
        saveReportToHistory(activeReport);
      }
    } catch {
      // ignore
    } finally {
      setHistoryLoading(false);
    }
  };

  const handleEssentialOnlyConsent = () => {
    setConsentState('denied');
    setShowConsentModal(false);
    setHistory([]);
    setHistoryStorageError(null);
    try {
      localStorage.setItem(CONSENT_KEY, 'denied');
      localStorage.removeItem(HISTORY_KEY);
    } catch {
      // ignore
    }
  };

  const handleDeleteHistoryEntry = (scanId: string) => {
    setHistory((prev) => {
      const next = prev.filter((item) => item.scanId !== scanId);
      try {
        localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
      } catch {
        // ignore
      }
      return next;
    });
  };

  const handleClearHistory = () => {
    setHistory([]);
    setHistoryStorageError(null);
    try {
      localStorage.removeItem(HISTORY_KEY);
    } catch {
      // ignore
    }
  };

  const isScanning = Boolean(activeJob && (activeJob.status === 'queued' || activeJob.status === 'running'));

  return (
    <div className="flex min-h-screen flex-col bg-white text-zinc-900 dark:bg-black dark:text-white transition-colors duration-200">
      <Navbar
        currentPage={page}
        onNavigate={(nextPage) => navigateTo(nextPage)}
        lang={lang}
        onToggleLang={() => setLang((l) => (l === 'en' ? 'ar' : 'en'))}
        theme={theme}
        onToggleTheme={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
      />

      <main className="flex-1">
        {(page === 'home' || page === 'scanner') && (
          <>
            {!activeJob && !activeReport ? (
              <ScannerHero
                lang={lang}
                isScanning={isScanning}
                providers={providers}
                disabledProviders={disabledProviders}
                onToggleProvider={toggleProvider}
                recentHistory={history}
                onOpenReport={(report) => {
                  setActiveJob(null);
                  setActiveReport(report);
                  navigateTo('scanner');
                }}
                onStartScan={handleStartScan}
                showLandingSections={page === 'home'}
              />
            ) : null}

            {scanError && (
              <div className="mx-auto mt-6 max-w-3xl px-4">
                <div
                  role="alert"
                  className="rounded-xl border border-red-500/40 bg-red-500/10 p-4 text-sm text-red-700 dark:text-red-300"
                >
                  {scanError}
                </div>
              </div>
            )}

            {activeJob && !activeReport && (
              <ScanProgressView job={activeJob} lang={lang} onReset={handleResetScanner} />
            )}

            {activeReport && (
              <SecurityReportView
                report={activeReport}
                lang={lang}
                onRescan={(url) =>
                  handleStartScan({
                    url,
                    viewport: activeReport.screenshot.viewport || 'desktop',
                    disabledProviders,
                  })
                }
                onNewScan={handleResetScanner}
              />
            )}
          </>
        )}

        {page === 'providers' && (
          <ProvidersView
            lang={lang}
            providers={providers}
            disabledProviders={disabledProviders}
            onToggleProvider={toggleProvider}
            onSetDisabledProviders={setAllDisabledProviders}
            onRefresh={fetchProviders}
            onOpenScanner={() => navigateTo('scanner')}
          />
        )}

        {page === 'history' && (
          <HistoryView
            history={history}
            isLoading={historyLoading}
            storageError={historyStorageError}
            consentGranted={consentState === 'granted'}
            lang={lang}
            onEnableConsent={handleAcceptHistoryConsent}
            onOpenReport={(report) => {
              setActiveJob(null);
              setActiveReport(report);
              navigateTo('scanner');
            }}
            onDeleteEntry={handleDeleteHistoryEntry}
            onClearAll={handleClearHistory}
            onGoToScanner={handleResetScanner}
            onGoHome={() => navigateTo('home')}
          />
        )}

        {page === 'about' && (
          <AboutView lang={lang} providers={providers} onNavigate={(nextPage) => navigateTo(nextPage)} />
        )}
        {page === 'privacy' && <PrivacyView lang={lang} />}
        {page === 'terms' && <TermsView lang={lang} />}
        {page === 'error' && (
          <ErrorView
            statusCode={errorCode}
            lang={lang}
            onGoHome={() => navigateTo('home')}
            onRetry={() => navigateTo('home')}
          />
        )}
      </main>

      <Footer
        lang={lang}
        onNavigate={(nextPage) => navigateTo(nextPage)}
        onOpenPrivacy={() => setShowConsentModal(true)}
      />

      <ConsentBanner
        visible={showConsentModal}
        lang={lang}
        onAcceptHistory={handleAcceptHistoryConsent}
        onEssentialOnly={handleEssentialOnlyConsent}
      />
    </div>
  );
}
