import { useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowDownUp,
  Camera,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Cookie,
  Cpu,
  Database,
  Download,
  ExternalLink,
  FileText,
  GitBranch,
  Globe,
  HelpCircle,
  Info,
  Layers,
  Lock,
  Maximize2,
  Megaphone,
  Radio,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  X,
  XCircle,
} from 'lucide-react';
import type {
  CheckFinding,
  CheckStatus,
  Language,
  RiskClassification,
  RiskSeverity,
  ScanReport,
  TechnicalSectionId,
  TransmittedDataType,
} from '../types/scan';
import {
  tAdIntelState,
  tClassification,
  tCookieCategory,
  tFileDownloadCategory,
  tOperationalState,
  tSeverity,
  tStatus,
  tVerdict,
  tXssStatus,
  UI_COPY,
} from '../i18n/translations';
import { ReportCharts } from './ReportCharts';
import { CyberMascot } from './CyberMascot';
import { CyberSticker } from './CyberStickers';
import { SourceCodeForensicsVisual, SubdomainDnsTopologyVisual } from './CyberIllustrations';
import { downloadScanReportPdf } from '../utils/pdfReportExporter';
import { safeExternalHref, safeImageDataUrl, sanitizeUrlParamForScan } from '../utils/sanitize';
import { LevelBScanBox } from './LevelBScanBox';

interface SecurityReportViewProps {
  report: ScanReport;
  lang: Language;
  onRescan: (url: string) => void;
  onNewScan: () => void;
}

function StatusLabel({ status, lang }: { status: CheckStatus; lang: Language }) {
  if (status === 'pass') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#16A34A]">
        <CheckCircle2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
        <span>{tStatus(status, lang)}</span>
      </span>
    );
  }
  if (status === 'warning') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#F59E0B]">
        <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
        <span>{tStatus(status, lang)}</span>
      </span>
    );
  }
  if (status === 'failed') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#EF233C]">
        <XCircle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
        <span>{tStatus(status, lang)}</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-zinc-500 dark:text-zinc-400">
      <HelpCircle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
      <span>{tStatus(status, lang)}</span>
    </span>
  );
}

const SEVERITY_ORDER: Record<RiskSeverity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  unknown: 1,
  informational: 0,
};

function classificationPalette(cls: RiskClassification): {
  stroke: string;
  textClass: string;
  glow: string;
  badgeBg: string;
} {
  switch (cls) {
    case 'CRITICAL':
      return {
        stroke: '#EF233C',
        textClass: 'text-[#EF233C]',
        glow: 'rgba(239, 35, 60, 0.42)',
        badgeBg: 'bg-[#EF233C]/12 border-[#EF233C]/40 text-[#EF233C]',
      };
    case 'HIGH':
      return {
        stroke: '#FF263F',
        textClass: 'text-[#FF263F]',
        glow: 'rgba(255, 38, 63, 0.38)',
        badgeBg: 'bg-[#FF263F]/12 border-[#FF263F]/40 text-[#FF263F]',
      };
    case 'MEDIUM':
      return {
        stroke: '#F59E0B',
        textClass: 'text-[#F59E0B]',
        glow: 'rgba(245, 158, 11, 0.35)',
        badgeBg: 'bg-[#F59E0B]/12 border-[#F59E0B]/40 text-[#F59E0B]',
      };
    case 'LOW':
      return {
        stroke: '#EAB308',
        textClass: 'text-amber-500',
        glow: 'rgba(234, 179, 8, 0.32)',
        badgeBg: 'bg-amber-500/12 border-amber-500/40 text-amber-500',
      };
    case 'UNKNOWN':
      return {
        stroke: '#71717A',
        textClass: 'text-zinc-500 dark:text-zinc-400',
        glow: 'rgba(113, 113, 122, 0.25)',
        badgeBg: 'bg-zinc-500/12 border-zinc-400/40 text-zinc-500 dark:text-zinc-400',
      };
    case 'OFFICIAL_DOMAIN_VERIFIED':
      return {
        stroke: '#0EA5E9',
        textClass: 'text-[#0284C7] dark:text-[#38BDF8]',
        glow: 'rgba(14, 165, 233, 0.36)',
        badgeBg: 'bg-sky-500/12 border-sky-500/40 text-[#0284C7] dark:text-[#38BDF8]',
      };
    case 'NO_KNOWN_THREATS':
    case 'SAFE_INDICATORS':
    default:
      return {
        stroke: '#16A34A',
        textClass: 'text-[#16A34A]',
        glow: 'rgba(22, 163, 74, 0.35)',
        badgeBg: 'bg-[#16A34A]/12 border-[#16A34A]/40 text-[#16A34A]',
      };
  }
}

function CircularRiskGauge({
  score,
  classification,
  lang,
}: {
  score: number;
  classification: RiskClassification;
  lang: Language;
}) {
  const palette = classificationPalette(classification);
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  const radius = 56;
  const circumference = 2 * Math.PI * radius;
  const isCleanZero =
    clamped === 0 &&
    (classification === 'OFFICIAL_DOMAIN_VERIFIED' ||
      classification === 'NO_KNOWN_THREATS' ||
      classification === 'SAFE_INDICATORS' ||
      (classification as string) === 'INFORMATIONAL');
  const fillFraction = isCleanZero ? 1 : Math.max(0.05, clamped / 100);
  const dashOffset = circumference * (1 - fillFraction);

  // 36 radial precision degree ticks
  const ticks = Array.from({ length: 36 }, (_, i) => i * 10);

  return (
    <div className="relative flex h-36 w-36 shrink-0 items-center justify-center rounded-full bg-[#F7F7F7] dark:bg-black">
      <svg
        viewBox="0 0 160 160"
        className="h-full w-full"
        role="img"
        aria-label={`${lang === 'ar' ? 'مؤشر الخطورة' : 'Risk Score'}: ${clamped}/100`}
      >
        {/* Subtle outer hairline halo colored by risk classification */}
        <circle
          cx="80"
          cy="80"
          r="75"
          fill="none"
          stroke={palette.stroke}
          strokeOpacity="0.24"
          strokeWidth="1.25"
        />

        {/* Precision laboratory radial degree ticks */}
        <g transform="translate(80 80)">
          {ticks.map((deg) => (
            <line
              key={deg}
              x1="0"
              y1="-70"
              x2="0"
              y2={deg % 30 === 0 ? '-65' : '-67.5'}
              transform={`rotate(${deg})`}
              stroke={palette.stroke}
              strokeOpacity={deg % 30 === 0 ? 0.55 : 0.25}
              strokeWidth={deg % 30 === 0 ? 1.5 : 1}
              strokeLinecap="round"
            />
          ))}
        </g>

        {/* Track circle */}
        <circle
          cx="80"
          cy="80"
          r={radius}
          fill="none"
          stroke="currentColor"
          strokeWidth="10"
          className="text-zinc-200 dark:text-[#1B1B1B]"
        />

        {/* Active color-coded progress arc */}
        <circle
          cx="80"
          cy="80"
          r={radius}
          fill="none"
          stroke={palette.stroke}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          transform="rotate(-90 80 80)"
          style={{
            filter: `drop-shadow(0 0 6px ${palette.glow})`,
            transition: 'stroke-dashoffset 500ms cubic-bezier(0.16, 1, 0.3, 1)',
          }}
        />
      </svg>

      {/* Centered Score & Unit */}
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center text-center">
        <span className={`font-mono text-3xl font-extrabold leading-none tabular-nums ${palette.textClass}`}>
          {clamped}
        </span>
        <span className="mt-1 font-mono text-[11px] font-semibold text-zinc-500 dark:text-zinc-400 tabular-nums">
          / 100
        </span>
      </div>
    </div>
  );
}

export function SecurityReportView({
  report,
  lang,
  onRescan,
  onNewScan,
}: SecurityReportViewProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<CheckStatus | 'all'>('all');
  const [sectionFilter, setSectionFilter] = useState<TechnicalSectionId | 'all'>('all');
  const [sortBy, setSortBy] = useState<'severity' | 'status' | 'test'>('severity');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [expandedFindingIds, setExpandedFindingIds] = useState<Record<string, boolean>>({});
  const [zoomOpen, setZoomOpen] = useState(false);
  const [pdfExporting, setPdfExporting] = useState(false);
  const [customFileUrl, setCustomFileUrl] = useState('');

  const safeScreenshotSrc = safeImageDataUrl(report.screenshot.imageDataUrl);
  const safeFaviconSrc = safeImageDataUrl(report.siteFaviconDataUrl);

  const handleFetchCustomFile = (e: React.FormEvent) => {
    e.preventDefault();
    const cleaned = sanitizeUrlParamForScan(customFileUrl);
    if (!cleaned) return;
    let target = cleaned;
    if (!/^https?:\/\//i.test(target)) {
      try {
        const base = new URL(report.finalDestinationUrl || report.submittedUrl);
        target = new URL(target, base.origin).toString();
      } catch {
        target = `https://${target}`;
      }
    }
    const safeTarget = safeExternalHref(target);
    if (safeTarget) {
      onRescan(safeTarget);
    }
  };

  const toggleFinding = (id: string) => {
    setExpandedFindingIds((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleSort = (col: 'severity' | 'status' | 'test') => {
    if (sortBy === col) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortBy(col);
      setSortDir(col === 'test' ? 'asc' : 'desc');
    }
  };

  const filteredFindings = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    const list = (report.findings ?? []).filter((f) => {
      if (statusFilter !== 'all' && f.status !== statusFilter) return false;
      if (sectionFilter !== 'all' && f.section !== sectionFilter) return false;
      if (!q) return true;
      return (
        (f.test?.[lang] ?? '').toLowerCase().includes(q) ||
        (f.result?.[lang] ?? '').toLowerCase().includes(q) ||
        (f.evidence ?? '').toLowerCase().includes(q) ||
        (f.source ?? '').toLowerCase().includes(q)
      );
    });

    list.sort((a, b) => {
      let cmp = 0;
      if (sortBy === 'severity') {
        cmp = (SEVERITY_ORDER[a.severity] ?? 1) - (SEVERITY_ORDER[b.severity] ?? 1);
      } else if (sortBy === 'status') {
        cmp = (a.status ?? '').localeCompare(b.status ?? '');
      } else {
        cmp = (a.test?.[lang] ?? '').localeCompare(b.test?.[lang] ?? '');
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });
    return list;
  }, [report.findings, searchQuery, statusFilter, sectionFilter, sortBy, sortDir, lang]);

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan-link-sm-${report.scanId.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportPdf = async () => {
    if (pdfExporting) return;
    setPdfExporting(true);
    try {
      await downloadScanReportPdf(report, lang);
    } finally {
      setPdfExporting(false);
    }
  };

  const scorePalette = classificationPalette(report.classification);
  const resolvedTitle = report.pageTitle || report.contentIntel?.pageTitle;
  const targetDomain = (() => {
    try {
      return new URL(report.finalDestinationUrl || report.submittedUrl).hostname;
    } catch {
      return report.submittedUrl;
    }
  })();

  return (
    <section className="mx-auto max-w-7xl space-y-7 px-4 py-9 sm:px-6 lg:px-8">
      {/* Top Action Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="text-xs font-bold tracking-wider text-[#FF263F]">
            {UI_COPY.report.title[lang]}
          </p>
          <p dir="ltr" className="mt-1 font-mono text-xs text-zinc-500 dark:text-zinc-400 tabular-nums">
            ID: {report.scanId} · {(report.durationMs / 1000).toFixed(2)}s ·{' '}
            {new Date(report.completedAt).toLocaleString(lang === 'ar' ? 'ar-EG' : 'en-US')}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => onRescan(report.submittedUrl)}
            className="inline-flex h-10 items-center gap-2 rounded-lg border border-[#E5E7EB] bg-white px-3.5 text-xs font-semibold text-zinc-800 hover:border-[#FF263F] hover:text-[#FF263F] dark:border-[#202020] dark:bg-[#0D0D0D] dark:text-zinc-200 transition-colors"
          >
            <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
            <span>{UI_COPY.report.rescan[lang]}</span>
          </button>
          <button
            type="button"
            onClick={handleExportJson}
            className="inline-flex h-10 items-center gap-2 rounded-lg border border-[#E5E7EB] bg-white px-3.5 text-xs font-semibold text-zinc-800 hover:border-[#FF263F] hover:text-[#FF263F] dark:border-[#202020] dark:bg-[#0D0D0D] dark:text-zinc-200 transition-colors"
          >
            <Download className="h-3.5 w-3.5" aria-hidden="true" />
            <span>{UI_COPY.report.exportJson[lang]}</span>
          </button>
          <button
            type="button"
            onClick={handleExportPdf}
            disabled={pdfExporting}
            className="inline-flex h-10 items-center gap-2 rounded-lg border border-[#E5E7EB] bg-white px-3.5 text-xs font-semibold text-zinc-800 hover:border-[#FF263F] hover:text-[#FF263F] disabled:opacity-60 dark:border-[#202020] dark:bg-[#0D0D0D] dark:text-zinc-200 transition-colors"
          >
            <FileText className="h-3.5 w-3.5 text-[#FF263F]" aria-hidden="true" />
            <span>{pdfExporting ? UI_COPY.report.exportingPdf[lang] : UI_COPY.report.exportPdf[lang]}</span>
          </button>
          <button
            type="button"
            onClick={onNewScan}
            className="inline-flex h-10 items-center gap-2 rounded-lg bg-[#FF263F] px-4 text-xs font-bold text-white hover:bg-[#E01E35] transition-colors"
          >
            <span>{UI_COPY.report.newScan[lang]}</span>
          </button>
        </div>
      </div>

      {/* =====================================================================
          SECTION 1 (TOP PRIORITY): WEBSITE SCREENSHOT + CORE VERDICT SUMMARY
          ===================================================================== */}
      <div className="rounded-2xl border border-[#E5E7EB] bg-white p-5 shadow-sm dark:border-[#202020] dark:bg-[#0D0D0D] sm:p-7 sm-red-glow">
        <div className="grid grid-cols-1 gap-7 lg:grid-cols-12">
          {/* Left / First Column: Prominent Website Screenshot & Capture Metadata */}
          <div className="lg:col-span-5 flex flex-col justify-between rounded-xl border border-[#E5E7EB] bg-[#F7F7F7] p-4 dark:border-[#202020] dark:bg-black">
            <div>
              <div className="flex items-center justify-between gap-2">
                <h2 className="font-display text-sm font-bold text-zinc-950 dark:text-white flex items-center gap-2">
                  <Camera className="h-4 w-4 text-[#FF263F]" aria-hidden="true" />
                  <span>{UI_COPY.report.screenshotSection[lang]}</span>
                </h2>
                {safeScreenshotSrc && (
                  <button
                    type="button"
                    onClick={() => setZoomOpen(true)}
                    className="inline-flex items-center gap-1 text-xs font-semibold text-[#FF263F] hover:underline"
                  >
                    <Maximize2 className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>{UI_COPY.report.zoomScreenshot[lang]}</span>
                  </button>
                )}
              </div>

              {report.screenshot.status === 'captured' && safeScreenshotSrc ? (
                <button
                  type="button"
                  onClick={() => setZoomOpen(true)}
                  className="mt-3 block w-full overflow-hidden rounded-lg border border-[#E5E7EB] bg-white dark:border-[#202020] dark:bg-[#080808]"
                >
                  <img
                    src={safeScreenshotSrc}
                    alt={`Screenshot of ${report.finalDestinationUrl}`}
                    referrerPolicy="no-referrer"
                    className="max-h-64 w-full object-cover object-top"
                  />
                </button>
              ) : (
                <div className="mt-3 flex min-h-[190px] flex-col items-center justify-center rounded-lg border border-dashed border-zinc-300 bg-white p-5 text-center dark:border-[#262626] dark:bg-[#080808]">
                  <Camera className="h-8 w-8 text-zinc-400" aria-hidden="true" />
                  <p className="mt-2.5 text-xs font-bold text-zinc-900 dark:text-zinc-100">
                    {lang === 'en' ? 'Visual Preview Unavailable' : 'المعاينة البصرية غير متاحة'}
                  </p>
                  <p className="mt-1.5 text-xs leading-relaxed text-zinc-500 dark:text-zinc-400">
                    {report.screenshot.reason?.[lang]}
                  </p>
                </div>
              )}
            </div>

            <dl className="mt-3 grid grid-cols-3 gap-2 border-t border-[#E5E7EB] pt-3 text-[11px] dark:border-[#202020]">
              <div>
                <dt className="text-zinc-500">{UI_COPY.report.screenshotStatus[lang]}</dt>
                <dd className="font-mono font-semibold text-zinc-900 dark:text-white">
                  {report.screenshot.status}
                </dd>
              </div>
              <div>
                <dt className="text-zinc-500">{UI_COPY.report.captureMethod[lang]}</dt>
                <dd className="font-mono font-semibold text-zinc-900 dark:text-white">
                  {report.screenshot.method}
                </dd>
              </div>
              <div>
                <dt className="text-zinc-500">{UI_COPY.report.viewport[lang]}</dt>
                <dd className="font-mono font-semibold text-zinc-900 dark:text-white">
                  {report.screenshot.viewport}
                </dd>
              </div>
            </dl>
          </div>

          {/* Right / Second Column: Circular Risk Gauge, Site Icon Identity, Classification, Verdict & URLs */}
          <div className="lg:col-span-7 flex flex-col justify-between space-y-5">
            {/* Target Site Identity Header with Real Scanned Website Favicon */}
            <div className="flex min-w-0 flex-wrap items-center gap-3 overflow-hidden rounded-xl border border-[#E5E7EB] bg-[#F7F7F7] px-3.5 py-2.5 dark:border-[#202020] dark:bg-black">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center overflow-hidden rounded-full border border-[#E5E7EB] bg-white dark:border-[#242424] dark:bg-[#0D0D0D]">
                {safeFaviconSrc ? (
                  <img
                    src={safeFaviconSrc}
                    alt={resolvedTitle || targetDomain}
                    referrerPolicy="no-referrer"
                    className="h-6 w-6 rounded-full object-contain"
                  />
                ) : (
                  <Globe className="h-5 w-5 text-zinc-400" aria-hidden="true" />
                )}
              </div>
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-bold text-zinc-950 dark:text-white">
                  {resolvedTitle || targetDomain}
                </p>
                <p dir="ltr" className="truncate font-mono text-[11px] text-zinc-500 dark:text-zinc-400">
                  {targetDomain}
                </p>
              </div>
              <span className={`max-w-full break-words text-xs font-extrabold tracking-wide ${scorePalette.textClass}`}>
                {tClassification(report.classification, lang)}
              </span>
            </div>

            <div className="flex flex-col gap-5 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-5">
                <CircularRiskGauge
                  score={report.riskScore}
                  classification={report.classification}
                  lang={lang}
                />

                <div className="space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-medium text-zinc-500 dark:text-zinc-400">
                      {UI_COPY.report.classification[lang]}:
                    </span>
                    <span className={`font-display text-xl font-extrabold tracking-tight ${scorePalette.textClass}`}>
                      {tClassification(report.classification, lang)}
                    </span>
                  </div>
                  <div>
                    <span className="text-xs font-medium text-zinc-500 dark:text-zinc-400">
                      {UI_COPY.report.verdict[lang]}:{' '}
                    </span>
                    <span className="text-base font-bold text-zinc-950 dark:text-white">
                      {tVerdict(report.verdict, lang)}
                    </span>
                  </div>
                  <div className="flex flex-wrap items-center gap-3 pt-1">
                    <span className="text-xs text-zinc-500 dark:text-zinc-400">
                      {UI_COPY.report.confidence[lang]}:
                    </span>
                    <span className="font-mono text-xs font-bold text-zinc-900 dark:text-white tabular-nums">
                      {report.confidenceScore}% ({report.confidenceLabel})
                    </span>
                    <div className="h-1.5 w-24 overflow-hidden rounded-full bg-zinc-200 dark:bg-[#202020]">
                      <div
                        className="h-full transition-all duration-300"
                        style={{
                          width: `${report.confidenceScore}%`,
                          backgroundColor: scorePalette.stroke,
                        }}
                      />
                    </div>
                    {report.inspectionCoveragePercent !== undefined && (
                      <span className="font-mono text-xs text-zinc-600 dark:text-zinc-400 tabular-nums">
                        · {UI_COPY.report.inspectionCoverage[lang]}: {report.inspectionCoveragePercent}%
                      </span>
                    )}
                  </div>
                </div>
              </div>

              {/* Animated WhatsApp-Sticker Style Mascot Reacting to Verdict */}
              <div className="hidden sm:flex shrink-0 items-center justify-center ps-2">
                <CyberMascot
                  state={
                    report.classification === 'CRITICAL' || report.classification === 'HIGH' || report.riskScore >= 50
                      ? 'threat'
                      : report.classification === 'OFFICIAL_DOMAIN_VERIFIED' ||
                          report.classification === 'NO_KNOWN_THREATS' ||
                          report.classification === 'SAFE_INDICATORS' ||
                          report.riskScore <= 15
                        ? 'success'
                        : 'idle'
                  }
                  size={120}
                />
              </div>
            </div>

            {/* Recommendation with Cybersecurity Shield Sticker */}
            <div className="flex items-start gap-3 rounded-xl border border-[#E5E7EB] bg-[#F7F7F7] p-4 dark:border-[#202020] dark:bg-black">
              <div className="shrink-0 mt-0.5">
                <CyberSticker
                  type={
                    report.classification === 'CRITICAL' || report.classification === 'HIGH'
                      ? 'threat'
                      : report.classification === 'OFFICIAL_DOMAIN_VERIFIED' ||
                          report.classification === 'NO_KNOWN_THREATS' ||
                          report.classification === 'SAFE_INDICATORS'
                        ? 'shield'
                        : 'scanner'
                  }
                  size={32}
                />
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-xs font-semibold text-[#FF263F]">
                  {UI_COPY.report.recommendation[lang]}
                </p>
                <p className="mt-1 text-sm font-medium leading-relaxed text-zinc-900 dark:text-zinc-100">
                  {report.recommendation?.[lang] || ''}
                </p>
              </div>
            </div>

            {/* Top Reasons Driving This Score */}
            {report.topReasons && report.topReasons.length > 0 && (
              <div className="rounded-xl border border-[#E5E7EB] bg-[#F7F7F7] p-4 dark:border-[#202020] dark:bg-black">
                <p className="text-xs font-semibold text-zinc-900 dark:text-white">
                  {UI_COPY.report.topReasonsHeading[lang]}
                </p>
                <ul className="mt-2 space-y-1.5 text-xs leading-relaxed text-zinc-700 dark:text-zinc-300">
                  {report.topReasons.map((reason, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <span className="font-mono text-[11px] font-bold text-[#FF263F] tabular-nums">
                        {idx + 1}.
                      </span>
                      <span>{reason[lang]}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {/* Website Title + Submitted URL + Final Destination */}
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <div className="min-w-0 overflow-hidden rounded-xl border border-[#E5E7EB] bg-[#F7F7F7] p-3 dark:border-[#202020] dark:bg-black">
                <p className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
                  {UI_COPY.report.pageTitle[lang]}
                </p>
                <div className="mt-1 flex items-center gap-1.5 min-w-0">
                  {safeFaviconSrc && (
                    <img
                      src={safeFaviconSrc}
                      alt=""
                      referrerPolicy="no-referrer"
                      className="h-3.5 w-3.5 shrink-0 rounded-full object-contain"
                    />
                  )}
                  <p className="min-w-0 truncate text-xs font-semibold text-zinc-900 dark:text-white">
                    {resolvedTitle || UI_COPY.report.noPageTitle[lang]}
                  </p>
                </div>
              </div>
              <div className="min-w-0 overflow-hidden rounded-xl border border-[#E5E7EB] bg-[#F7F7F7] p-3 dark:border-[#202020] dark:bg-black">
                <p className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
                  {UI_COPY.report.submittedUrl[lang]}
                </p>
                <p dir="ltr" className="mt-1 break-all font-mono text-[11px] text-zinc-900 dark:text-zinc-100">
                  {report.submittedUrl}
                </p>
              </div>
              <div className="min-w-0 overflow-hidden rounded-xl border border-[#E5E7EB] bg-[#F7F7F7] p-3 dark:border-[#202020] dark:bg-black">
                <p className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
                  {UI_COPY.report.finalUrl[lang]}
                </p>
                <p dir="ltr" className="mt-1 break-all font-mono text-[11px] text-zinc-900 dark:text-zinc-100">
                  {report.finalDestinationUrl}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Correlation Explanations (when multi-signal rules fired) */}
        {report.correlationNotes && report.correlationNotes.length > 0 && (
          <div className="mt-6 rounded-xl border border-[#FF263F]/35 bg-[#FF263F]/[0.06] p-4">
            <div className="flex items-center gap-2 text-xs font-bold text-[#FF263F]">
              <GitBranch className="h-4 w-4 shrink-0" aria-hidden="true" />
              <span>{UI_COPY.report.correlationHeading[lang]}</span>
            </div>
            <ul className="mt-2 space-y-1.5 text-xs leading-relaxed text-zinc-800 dark:text-zinc-200">
              {report.correlationNotes.map((note, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-[#FF263F]" aria-hidden="true" />
                  <span>{note[lang]}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Conflicting Evidence Disclosure */}
        {report.conflictNotes && report.conflictNotes.length > 0 && (
          <div className="mt-4 rounded-xl border border-[#F59E0B]/40 bg-[#F59E0B]/[0.07] p-4">
            <div className="flex items-center gap-2 text-xs font-bold text-[#D97706] dark:text-[#FBBF24]">
              <AlertTriangle className="h-4 w-4 shrink-0" aria-hidden="true" />
              <span>{UI_COPY.report.conflictHeading[lang]}</span>
            </div>
            <ul className="mt-2 space-y-1.5 text-xs leading-relaxed text-zinc-800 dark:text-zinc-200">
              {report.conflictNotes.map((note, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-[#F59E0B]" aria-hidden="true" />
                  <span>{note[lang]}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* Official Domain & Page Authenticity Verification (Full Domain + Page + Transport + Feeds) */}
      {report.domainAuthenticity && (
        <div
          className={`overflow-hidden rounded-2xl border p-5 sm:p-6 ${
            report.domainAuthenticity.conflictDetected
              ? 'border-[#F59E0B]/45 bg-[#F59E0B]/[0.06]'
              : report.domainAuthenticity.status === 'official_verified' ||
                  report.domainAuthenticity.status === 'official_subdomain'
                ? 'border-sky-500/35 bg-sky-500/[0.04] dark:bg-sky-950/15'
                : 'border-[#E5E7EB] bg-white dark:border-[#202020] dark:bg-[#0D0D0D]'
          }`}
        >
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="flex min-w-0 flex-1 items-start gap-2.5">
              <ShieldCheck
                className={`mt-0.5 h-5 w-5 shrink-0 ${
                  report.domainAuthenticity.status === 'official_verified' ||
                  report.domainAuthenticity.status === 'official_subdomain'
                    ? 'text-[#0284C7] dark:text-[#38BDF8]'
                    : report.domainAuthenticity.status === 'brand_lookalike'
                      ? 'text-[#F59E0B]'
                      : 'text-zinc-500'
                }`}
                aria-hidden="true"
              />
              <div className="min-w-0 flex-1">
                <h2 className="font-display break-words text-sm font-bold text-zinc-950 dark:text-white">
                  {UI_COPY.report.domainAuthHeading[lang]}
                </h2>
                <p className="mt-0.5 break-words text-xs font-semibold text-zinc-700 dark:text-zinc-300">
                  {report.domainAuthenticity.label[lang]}
                </p>
              </div>
            </div>

            {report.domainAuthenticity.parentCompany && (
              <div className="min-w-0 max-w-full text-xs font-semibold text-[#0284C7] dark:text-[#38BDF8] break-words">
                {report.domainAuthenticity.parentCompany}
                {report.domainAuthenticity.officialProduct
                  ? ` · ${report.domainAuthenticity.officialProduct}`
                  : ''}
              </div>
            )}
          </div>

          <dl className="mt-4 grid grid-cols-1 gap-4 border-t border-zinc-200/70 pt-4 text-xs dark:border-[#202020] sm:grid-cols-2 lg:grid-cols-4">
            <div className="min-w-0">
              <dt className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
                {lang === 'en' ? 'PSL Registrable Domain (eTLD+1)' : 'النطاق الأساسي (PSL eTLD+1)'}
              </dt>
              <dd dir="ltr" className="mt-1 break-all font-mono font-semibold text-zinc-900 dark:text-white">
                {report.domainAuthenticity.registrableDomain}
              </dd>
            </div>
            <div className="min-w-0">
              <dt className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
                {lang === 'en' ? 'Subdomain & Public Suffix' : 'النطاق الفرعي واللاحقة العامة'}
              </dt>
              <dd dir="ltr" className="mt-1 break-all font-mono text-zinc-900 dark:text-white">
                {report.domainAuthenticity.subdomain || '(apex)'} · .{report.domainAuthenticity.publicSuffix || '—'}
              </dd>
            </div>
            <div className="min-w-0">
              <dt className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
                {lang === 'en' ? 'Corroboration Sources' : 'مصادر التحقق المتقاطع'}
              </dt>
              <dd dir="ltr" className="mt-1 break-words font-mono text-zinc-800 dark:text-zinc-200">
                {report.domainAuthenticity.corroborationSources
                  .filter((c) => c.verified)
                  .map((c) => c.source)
                  .join(', ') || (lang === 'en' ? 'Registry / Structural only' : 'السجل / البنية فقط')}
              </dd>
            </div>
            <div className="min-w-0">
              <dt className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
                {lang === 'en' ? 'Ownership Registries' : 'سجلات الملكية المرجعية'}
              </dt>
              <dd dir="ltr" className="mt-1 break-words font-mono text-[11px] text-zinc-700 dark:text-zinc-300">
                {report.domainAuthenticity.registrySources.join(', ') || 'PSL / RDAP / TLS'}
              </dd>
            </div>
          </dl>

          {report.domainAuthenticity.hostingMetadata?.isSharedPaas && (
            <dl className="mt-4 grid grid-cols-1 gap-4 border-t border-zinc-200/70 pt-4 text-xs dark:border-[#202020] sm:grid-cols-3">
              <div className="min-w-0 rounded-lg border border-sky-500/25 bg-sky-500/[0.04] p-3">
                <dt className="flex items-center gap-1.5 text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
                  <Server className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" aria-hidden="true" />
                  <span>{lang === 'en' ? 'Shared PaaS / Hosting Provider' : 'مزود الاستضافة المشتركة (PaaS)'}</span>
                </dt>
                <dd dir="ltr" className="mt-1 font-mono font-bold text-zinc-900 dark:text-white">
                  {report.domainAuthenticity.hostingMetadata.hostingProvider || 'Shared PaaS'}
                </dd>
              </div>
              <div className="min-w-0 rounded-lg border border-zinc-200/80 bg-white/70 p-3 dark:border-[#242424] dark:bg-black/60">
                <dt className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
                  {lang === 'en' ? 'Custom Domain Ownership' : 'ملكية النطاق المخصص'}
                </dt>
                <dd className="mt-1 font-semibold text-zinc-900 dark:text-white">
                  {report.domainAuthenticity.hostingMetadata.customDomainOwnership === 'verified'
                    ? lang === 'en'
                      ? 'Verified Ownership'
                      : 'ملكية موثقة'
                    : lang === 'en'
                      ? 'Unverified (PaaS Subdomain — Informational)'
                      : 'غير موثقة (نطاق فرعي مشترك — معلوماتي)'}
                </dd>
              </div>
              <div className="min-w-0 rounded-lg border border-zinc-200/80 bg-white/70 p-3 dark:border-[#242424] dark:bg-black/60">
                <dt className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
                  {lang === 'en' ? 'Website Identity' : 'تصنيف هوية الموقع'}
                </dt>
                <dd className="mt-1 font-semibold text-zinc-900 dark:text-white">
                  {report.domainAuthenticity.hostingMetadata.websiteIdentity[lang]}
                </dd>
              </div>
            </dl>
          )}

          {/* Complete Page, Transport & Threat-Feed Verification Matrix inside the same box */}
          <dl className="mt-4 grid grid-cols-1 gap-4 border-t border-zinc-200/70 pt-4 text-xs dark:border-[#202020] sm:grid-cols-2 lg:grid-cols-4">
            <div className="min-w-0">
              <dt className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
                {lang === 'en' ? 'Inspected Page & Content' : 'فحص الصفحة والمحتوى'}
              </dt>
              <dd className="mt-1 break-words font-semibold text-zinc-900 dark:text-white">
                {report.separatedAssessments?.websiteSecurity.verdict[lang] ||
                  (resolvedTitle
                    ? resolvedTitle
                    : lang === 'en'
                      ? 'Static HTML & DOM verified'
                      : 'تم فحص بنية الصفحة الساكنة')}
              </dd>
            </div>
            <div className="min-w-0">
              <dt className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
                {lang === 'en' ? 'SSL/TLS Certificate & Hops' : 'شهادة التشفير وسلسلة التوجيه'}
              </dt>
              <dd dir="ltr" className="mt-1 break-words font-mono text-zinc-900 dark:text-white">
                {report.tlsIntel?.authorized
                  ? `${report.tlsIntel.protocol || 'TLS'} · Trusted`
                  : lang === 'en'
                    ? 'TLS Unverified'
                    : 'شهادة غير موثقة'}{' '}
                · {report.redirects.length} {lang === 'en' ? 'hop(s)' : 'قفزة'}
              </dd>
            </div>
            <div className="min-w-0">
              <dt className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
                {lang === 'en' ? 'Final Destination Host' : 'نطاق الوجهة النهائية'}
              </dt>
              <dd dir="ltr" className="mt-1 break-all font-mono text-zinc-900 dark:text-white">
                {targetDomain}
              </dd>
            </div>
            <div className="min-w-0">
              <dt className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
                {lang === 'en' ? 'Threat Feeds Consensus' : 'إجماع مزودي التهديدات'}
              </dt>
              <dd className="mt-1 break-words font-semibold text-zinc-900 dark:text-white">
                {report.separatedAssessments?.threatIntelligence.verdict[lang] ||
                  `${report.summaryStats.availableProviders ?? 0}/${report.summaryStats.totalProviders ?? report.threatProviders.length}`}
              </dd>
            </div>
          </dl>

          <div className="mt-4 flex items-start gap-2 rounded-lg border border-zinc-200/80 bg-white/70 p-3 text-xs leading-relaxed text-zinc-700 dark:border-[#242424] dark:bg-black/60 dark:text-zinc-300">
            <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-sky-500" aria-hidden="true" />
            <p className="min-w-0 flex-1 break-words">{report.domainAuthenticity.disclaimer[lang]}</p>
          </div>
        </div>
      )}

      {/* Five Separated Assessments (Domain Authenticity vs Threat Intel vs Website Security vs SSL/TLS vs Redirects) */}
      {report.separatedAssessments && (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Layers className="h-4 w-4 text-[#FF263F]" aria-hidden="true" />
            <h2 className="font-display text-base font-bold text-zinc-950 dark:text-white">
              {UI_COPY.report.separatedPillarsHeading[lang]}
            </h2>
          </div>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-5">
            {[
              report.separatedAssessments.domainAuthenticity,
              report.separatedAssessments.threatIntelligence,
              report.separatedAssessments.websiteSecurity,
              report.separatedAssessments.sslTlsStatus,
              report.separatedAssessments.redirectAnalysis,
            ].map((pillar) => (
              <div
                key={pillar.id}
                className="flex flex-col justify-between rounded-xl border border-[#E5E7EB] bg-white p-4 dark:border-[#202020] dark:bg-[#0D0D0D]"
              >
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <h3 className="text-xs font-bold text-zinc-950 dark:text-white">
                      {pillar.title[lang]}
                    </h3>
                    <StatusLabel status={pillar.status} lang={lang} />
                  </div>
                  <p className="mt-2 text-xs font-semibold text-zinc-900 dark:text-zinc-100">
                    {pillar.verdict[lang]}
                  </p>
                  <p className="mt-1 text-[11px] leading-relaxed text-zinc-600 dark:text-zinc-400">
                    {pillar.detail[lang]}
                  </p>
                </div>
                {pillar.caveat && (
                  <p className="mt-2.5 border-t border-[#E5E7EB] pt-2 text-[10px] leading-relaxed text-zinc-500 dark:border-[#202020] dark:text-zinc-400">
                    {pillar.caveat[lang]}
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Deterministic Score Breakdown & Evidence Matrix */}
      {(report.scoreBreakdown?.length || report.evidenceBuckets) && (
        <div className="rounded-xl border border-[#E5E7EB] bg-white p-5 dark:border-[#202020] dark:bg-[#0D0D0D]">
          <h2 className="font-display text-base font-bold text-zinc-950 dark:text-white">
            {UI_COPY.report.scoreBreakdownHeading[lang]}
          </h2>
          <div className="mt-4 grid grid-cols-1 gap-5 lg:grid-cols-12">
            {report.scoreBreakdown && report.scoreBreakdown.length > 0 && (
              <div className="lg:col-span-5 rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-4 dark:border-[#202020] dark:bg-black">
                <p className="text-xs font-bold text-zinc-900 dark:text-zinc-100">
                  {lang === 'en' ? 'Risk Score Delta Ledger' : 'سجل تفصيل نقاط المخاطر'}
                </p>
                <ul className="mt-3 space-y-2 text-xs">
                  {report.scoreBreakdown.map((item) => (
                    <li
                      key={item.id}
                      className="flex items-start justify-between gap-3 border-b border-[#E5E7EB] pb-1.5 last:border-b-0 dark:border-[#202020]"
                    >
                      <span className="text-zinc-700 dark:text-zinc-300">{item.label[lang]}</span>
                      <span
                        dir="ltr"
                        className={`shrink-0 font-mono font-bold tabular-nums ${
                          item.delta < 0
                            ? 'text-[#16A34A]'
                            : item.delta >= 18
                              ? 'text-[#EF233C]'
                              : 'text-[#D97706]'
                        }`}
                      >
                        {item.delta >= 0 ? `+${item.delta}` : item.delta}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {report.evidenceBuckets && (
              <div
                className={`${
                  report.scoreBreakdown && report.scoreBreakdown.length > 0 ? 'lg:col-span-7' : 'lg:col-span-12'
                } grid grid-cols-1 gap-3 sm:grid-cols-2`}
              >
                {[
                  {
                    key: 'confirmed',
                    title: lang === 'en' ? 'Confirmed Evidence' : 'أدلة مؤكدة',
                    items: report.evidenceBuckets.confirmed,
                    accent: 'text-zinc-950 dark:text-white',
                  },
                  {
                    key: 'suspicious',
                    title: lang === 'en' ? 'Suspicious Indicators' : 'مؤشرات اشتباه',
                    items: report.evidenceBuckets.suspicious,
                    accent: 'text-[#D97706] dark:text-[#FBBF24]',
                  },
                  {
                    key: 'inconclusive',
                    title: lang === 'en' ? 'Inconclusive / Incomplete' : 'غير مكتمل أو غير حاسم',
                    items: report.evidenceBuckets.inconclusive,
                    accent: 'text-zinc-600 dark:text-zinc-400',
                  },
                  {
                    key: 'conflicting',
                    title: lang === 'en' ? 'Conflicting Evidence' : 'أدلة متضاربة',
                    items: report.evidenceBuckets.conflicting,
                    accent: 'text-[#EF233C]',
                  },
                ].map((bucket) => (
                  <div
                    key={bucket.key}
                    className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-3.5 dark:border-[#202020] dark:bg-black"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <p className={`text-xs font-bold ${bucket.accent}`}>{bucket.title}</p>
                      <span className="font-mono text-[11px] text-zinc-500 tabular-nums">
                        {bucket.items.length}
                      </span>
                    </div>
                    {bucket.items.length === 0 ? (
                      <p className="mt-2 text-[11px] text-zinc-500 dark:text-zinc-400">
                        {lang === 'en' ? 'None recorded.' : 'لا يوجد.'}
                      </p>
                    ) : (
                      <ul className="mt-2 space-y-1 text-[11px] leading-relaxed text-zinc-700 dark:text-zinc-300">
                        {bucket.items.slice(0, 4).map((entry, idx) => (
                          <li key={idx}>· {entry[lang]}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Structured 12-Item SM Website Intelligence Report */}
      {report.websiteIntelligenceReport && report.websiteIntelligenceReport.length > 0 && (
        <div className="rounded-xl border border-[#E5E7EB] bg-white p-5 dark:border-[#202020] dark:bg-[#0D0D0D]">
          <h2 className="font-display text-base font-bold text-zinc-950 dark:text-white">
            {UI_COPY.report.websiteIntelReportHeading[lang]}
          </h2>
          <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-3">
            {report.websiteIntelligenceReport.map((item) => {
              const statusLabel =
                item.status === 'inspected'
                  ? lang === 'en'
                    ? 'Inspected'
                    : 'تم الفحص'
                  : item.status === 'not_present'
                    ? lang === 'en'
                      ? 'Not Present'
                      : 'غير موجود'
                    : lang === 'en'
                      ? 'Unavailable'
                      : 'تعذر الفحص';
              return (
                <div
                  key={item.itemKey}
                  className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-3.5 dark:border-[#202020] dark:bg-black"
                >
                  <div className="flex items-center justify-between gap-2">
                    <h3 className="text-xs font-bold text-zinc-950 dark:text-white">
                      {item.title[lang]}
                    </h3>
                    <span
                      className={`shrink-0 font-mono text-[10px] font-semibold ${
                        item.status === 'inspected'
                          ? 'text-[#16A34A]'
                          : item.status === 'not_present'
                            ? 'text-zinc-500'
                            : 'text-[#D97706]'
                      }`}
                    >
                      {statusLabel}
                    </span>
                  </div>
                  <p className="mt-1.5 text-xs leading-relaxed text-zinc-700 dark:text-zinc-300">
                    {item.summary[lang]}
                  </p>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Inspection Capability Levels: Level A (Static Analysis) vs Level B (Isolated Browser) */}
      {report.analysisLevels && (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <div className="rounded-xl border border-[#E5E7EB] bg-white p-4 dark:border-[#202020] dark:bg-[#0D0D0D]">
            <div className="flex items-center justify-between gap-2">
              <h3 className="font-display text-xs font-bold uppercase tracking-wider text-zinc-950 dark:text-white">
                {lang === 'en' ? 'Level A · Static Source & DOM Analysis' : 'المستوى A · التحليل الساكن للمصدر وDOM'}
              </h3>
              <span
                className={`font-mono text-[11px] font-bold ${
                  report.analysisLevels.levelAStatic.status === 'complete'
                    ? 'text-[#16A34A]'
                    : report.analysisLevels.levelAStatic.status === 'partial'
                      ? 'text-[#0284C7]'
                      : 'text-[#D97706]'
                }`}
              >
                {report.analysisLevels.levelAStatic.status === 'complete'
                  ? lang === 'en'
                    ? 'Complete'
                    : 'مكتمل'
                  : report.analysisLevels.levelAStatic.status === 'partial'
                    ? lang === 'en'
                      ? 'Partial (JS Dynamic)'
                      : 'جزئي (محتوى متغير بـ JS)'
                    : report.analysisLevels.levelAStatic.status === 'blocked_by_site'
                      ? lang === 'en'
                        ? 'Blocked by Site'
                        : 'محجوب من الموقع'
                      : lang === 'en'
                        ? 'Unavailable'
                        : 'تعذر الفحص'}
              </span>
            </div>
            <p className="mt-2 text-xs leading-relaxed text-zinc-700 dark:text-zinc-300">
              {report.analysisLevels.levelAStatic.summary[lang]}
            </p>
            {report.analysisLevels.levelAStatic.coverageItems.length > 0 && (
              <p className="mt-2 font-mono text-[10px] leading-relaxed text-zinc-500 dark:text-zinc-400">
                {report.analysisLevels.levelAStatic.coverageItems.join(' · ')}
              </p>
            )}
          </div>

          <div className="rounded-xl border border-[#E5E7EB] bg-white p-4 dark:border-[#202020] dark:bg-[#0D0D0D]">
            <div className="flex items-center justify-between gap-2">
              <h3 className="font-display text-xs font-bold uppercase tracking-wider text-zinc-950 dark:text-white">
                {lang === 'en' ? 'Level B · Isolated Cloud Browser Execution' : 'المستوى B · التنفيذ المعزول في متصفح سحابي'}
              </h3>
              <span
                className={`font-mono text-[11px] font-bold ${
                  report.analysisLevels.levelBIsolatedBrowser.performed ? 'text-[#16A34A]' : 'text-[#D97706]'
                }`}
              >
                {report.analysisLevels.levelBIsolatedBrowser.performed
                  ? lang === 'en'
                    ? 'Executed (External Cloud)'
                    : 'نشط (متصفح سحابي خارجي)'
                  : lang === 'en'
                    ? 'Not Executed (Static Only)'
                    : 'غير منفّذ (ساكن فقط)'}
              </span>
            </div>
            <p className="mt-2 text-xs leading-relaxed text-zinc-700 dark:text-zinc-300">
              {report.analysisLevels.levelBIsolatedBrowser.reason[lang]}
            </p>
            {report.analysisLevels.levelBIsolatedBrowser.dynamicDomDivergenceLikely && (
              <p className="mt-2 font-mono text-[11px] font-semibold text-[#D97706]">
                {lang === 'en'
                  ? 'Notice: Static source shows post-load JS DOM updates / SPA shell.'
                  : 'تنبيه: يُرجَّح تغيّر DOM بعد تشغيل JavaScript (تطبيق SPA أو حقن ديناميكي).'}
              </p>
            )}
          </div>
        </div>
      )}

      {/* Standalone Level B Runtime Box (LevelBScanBox) */}
      <LevelBScanBox
        levelB={report.levelB}
        analysisLevelB={report.analysisLevels?.levelBIsolatedBrowser}
        lang={lang}
      />

      {/* Sandbox Isolation Honest Disclosure */}
      <div className="flex items-start gap-3 rounded-xl border border-[#E5E7EB] bg-[#F7F7F7] p-4 text-xs leading-relaxed text-zinc-700 dark:border-[#202020] dark:bg-[#080808] dark:text-zinc-300">
        <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-[#FF263F]" aria-hidden="true" />
        <div>
          <p className="font-semibold text-zinc-950 dark:text-white">
            {UI_COPY.report.sandboxNoticeTitle[lang]}
          </p>
          <p className="mt-1">{report.sandboxCapabilities?.disclosure?.[lang] || ''}</p>
        </div>
      </div>

      {/* Statistics Overview Cards (including Available Threat Providers) */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-7">
        {[
          { label: UI_COPY.report.stats.total[lang], value: `${report.summaryStats.totalChecks}`, cls: 'text-zinc-950 dark:text-white' },
          { label: UI_COPY.report.stats.passed[lang], value: `${report.summaryStats.passedChecks}`, cls: 'text-[#16A34A]' },
          { label: UI_COPY.report.stats.warning[lang], value: `${report.summaryStats.warningChecks}`, cls: 'text-[#F59E0B]' },
          { label: UI_COPY.report.stats.failed[lang], value: `${report.summaryStats.failedChecks}`, cls: 'text-[#EF233C]' },
          { label: UI_COPY.report.stats.critical[lang], value: `${report.summaryStats.criticalFindings}`, cls: 'text-[#FF263F]' },
          {
            label: UI_COPY.report.stats.providers[lang],
            value: `${
              report.summaryStats.availableProviders ??
              report.threatProviders.filter((p) => p.status === 'clean' || p.status === 'flagged').length
            }/${report.summaryStats.totalProviders ?? report.threatProviders.length}`,
            cls: 'text-zinc-950 dark:text-white',
          },
          { label: UI_COPY.report.stats.incomplete[lang], value: `${report.summaryStats.incompleteChecks}`, cls: 'text-zinc-500 dark:text-zinc-400' },
        ].map((stat) => (
          <div
            key={stat.label}
            className="rounded-xl border border-[#E5E7EB] bg-white p-4 dark:border-[#202020] dark:bg-[#0D0D0D]"
          >
            <p className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">{stat.label}</p>
            <p className={`mt-1 font-mono text-2xl font-bold tabular-nums ${stat.cls}`}>
              {stat.value}
            </p>
          </div>
        ))}
      </div>

      {/* Interactive Analytics */}
      <ReportCharts
        report={report}
        lang={lang}
        onSelectStatusFilter={(st) => {
          setStatusFilter(st);
          document.getElementById('findings-table')?.scrollIntoView({ behavior: 'smooth' });
        }}
        onSelectSectionFilter={(sec) => {
          setSectionFilter(sec);
          document.getElementById('findings-table')?.scrollIntoView({ behavior: 'smooth' });
        }}
      />

      {/* 12 Technical Modules Summary Grid */}
      <div className="space-y-4">
        <h2 className="font-display text-xl font-bold text-zinc-950 dark:text-white">
          {UI_COPY.report.sectionsHeading[lang]}
        </h2>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {report.sections.map((sec) => (
            <button
              key={sec.id}
              type="button"
              onClick={() => {
                setSectionFilter(sec.id);
                document.getElementById('findings-table')?.scrollIntoView({ behavior: 'smooth' });
              }}
              className="rounded-xl border border-[#E5E7EB] bg-white p-4 text-start hover:border-[#FF263F]/60 dark:border-[#202020] dark:bg-[#0D0D0D] transition-colors"
            >
              <div className="flex items-center justify-between gap-2">
                <h3 className="font-display text-sm font-bold text-zinc-950 dark:text-white">
                  {sec.title[lang]}
                </h3>
                <StatusLabel status={sec.status} lang={lang} />
              </div>
              <p className="mt-2 text-xs leading-relaxed text-zinc-600 dark:text-zinc-400">
                {sec.summary[lang]}
              </p>
            </button>
          ))}
        </div>

        {/* Deep Telemetry Cards */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2 pt-2">
          {/* Domain Deception & Identity Analysis */}
          {report.domainDeception && (
            <div className="lg:col-span-2 rounded-xl border border-[#E5E7EB] bg-white p-5 dark:border-[#202020] dark:bg-[#0D0D0D]">
              <h3 className="font-display text-sm font-bold text-zinc-950 dark:text-white">
                {UI_COPY.report.deceptionDetails[lang]}
              </h3>
              <dl className="mt-3 grid grid-cols-1 gap-3 text-xs sm:grid-cols-3 lg:grid-cols-4">
                <div>
                  <dt className="text-zinc-500">{lang === 'en' ? 'Unicode / ASCII Form' : 'النطاق المفكك / ASCII'}</dt>
                  <dd dir="ltr" className="font-mono font-semibold text-zinc-900 dark:text-white break-all">
                    {report.domainDeception.unicodeDomain}
                    {report.domainDeception.isPunycode ? ` (${report.domainDeception.asciiDomain})` : ''}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">{lang === 'en' ? 'Punycode / Mixed Scripts' : 'Punycode / خلط الأبجديات'}</dt>
                  <dd className={`font-semibold ${report.domainDeception.mixedScripts ? 'text-[#EF233C]' : 'text-zinc-900 dark:text-white'}`}>
                    {report.domainDeception.isPunycode ? 'Punycode (xn--)' : lang === 'en' ? 'Standard ASCII' : 'ASCII قياسي'}
                    {report.domainDeception.mixedScripts
                      ? lang === 'en'
                        ? ' · Mixed Scripts Alert'
                        : ' · تنبيه خلط أحرف'
                      : ''}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">{lang === 'en' ? 'Subdomain / @ Masking' : 'انتحال فرعي / تمويه @'}</dt>
                  <dd className={`font-semibold ${report.domainDeception.subdomainSpoofing || report.domainDeception.authorityMasking ? 'text-[#EF233C]' : 'text-zinc-900 dark:text-white'}`}>
                    {report.domainDeception.authorityMasking
                      ? lang === 'en'
                        ? '@ Authority Masking'
                        : 'تمويه بالرمز @'
                      : report.domainDeception.subdomainSpoofing
                        ? `${lang === 'en' ? 'Spoofing' : 'انتحال'}: ${report.domainDeception.spoofedTargetDomain}`
                        : lang === 'en'
                          ? 'None Detected'
                          : 'لا يوجد'}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">{lang === 'en' ? 'Open Redirect Proof' : 'تأكيد التوجيه المفتوح'}</dt>
                  <dd className={`font-semibold ${report.domainDeception.openRedirectConfirmed ? 'text-[#EF233C]' : 'text-zinc-900 dark:text-white'}`}>
                    {report.domainDeception.openRedirectConfirmed
                      ? lang === 'en'
                        ? 'Confirmed Cross-Domain Relay'
                        : 'توجيه مفتوح مؤكد عبر المعاملات'
                      : report.domainDeception.embeddedRedirectUrls.length > 0
                        ? `${report.domainDeception.embeddedRedirectUrls.length} ${lang === 'en' ? 'Embedded Param(s)' : 'معامل مضمن'}`
                        : lang === 'en'
                          ? 'None'
                          : 'لا يوجد'}
                  </dd>
                </div>
              </dl>

              {report.domainDeception.confusableCharacters.length > 0 && (
                <div className="mt-3 rounded-lg border border-[#EF233C]/35 bg-[#EF233C]/[0.06] p-3 text-xs">
                  <p className="font-bold text-[#EF233C]">
                    {lang === 'en'
                      ? `Confusable Skeleton: "${report.domainDeception.confusableSkeleton}"`
                      : `الهيكل البصري المشابه: "${report.domainDeception.confusableSkeleton}"`}
                  </p>
                  <p dir="ltr" className="mt-1 font-mono text-[11px] text-zinc-800 dark:text-zinc-200">
                    {report.domainDeception.confusableCharacters
                      .map((c) => `${c.char} (${c.codePoint} / ${c.script} -> '${c.lookalikeAscii}')`)
                      .join(' · ')}
                  </p>
                </div>
              )}

              {report.domainDeception.typosquatTarget && (
                <p
                  className={`mt-3 text-xs font-semibold ${
                    report.domainDeception.similarityOnly ? 'text-[#D97706] dark:text-[#FBBF24]' : 'text-[#EF233C]'
                  }`}
                >
                  {report.domainDeception.similarityOnly
                    ? lang === 'en'
                      ? `Domain name similarity to a known brand detected; impersonation has not been proven ("${report.domainDeception.typosquatTarget.brand}" / ${report.domainDeception.typosquatTarget.officialDomain}).`
                      : `تم اكتشاف تشابه في اسم النطاق مع علامة تجارية معروفة، ولم يتم إثبات الانتحال ("${report.domainDeception.typosquatTarget.brand}" / ${report.domainDeception.typosquatTarget.officialDomain}).`
                    : lang === 'en'
                      ? `Lookalike / Typosquatting: "${report.domainDeception.typosquatTarget.brand}" (${report.domainDeception.typosquatTarget.officialDomain}) — ${report.domainDeception.typosquatTarget.technique} (distance ${report.domainDeception.typosquatTarget.distance})`
                      : `تشابه نطاق انتحالي مع "${report.domainDeception.typosquatTarget.brand}" (${report.domainDeception.typosquatTarget.officialDomain}) — ${report.domainDeception.typosquatTarget.technique}`}
                </p>
              )}

              {report.domainDeception.visibleVsRealMismatches.length > 0 && (
                <div className="mt-3 border-t border-[#E5E7EB] pt-3 text-xs dark:border-[#202020]">
                  <p className="font-semibold text-[#EF233C]">
                    {lang === 'en'
                      ? 'Visible Anchor Text vs Actual Destination Mismatches:'
                      : 'اختلاف النص الظاهر للروابط عن وجهتها الفعلية:'}
                  </p>
                  <ul className="mt-1.5 space-y-1 font-mono text-[11px] text-zinc-700 dark:text-zinc-300" dir="ltr">
                    {report.domainDeception.visibleVsRealMismatches.map((m, i) => (
                      <li key={i}>
                        "{m.visibleText}" -&gt; {m.actualHost}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* Redirect Chain */}
          <div className="rounded-xl border border-[#E5E7EB] bg-white p-5 dark:border-[#202020] dark:bg-[#0D0D0D]">
            <h3 className="font-display text-sm font-bold text-zinc-950 dark:text-white">
              {UI_COPY.report.redirectChain[lang]}
            </h3>
            <div className="mt-3 space-y-2">
              {report.redirects.map((hop) => (
                <div
                  key={hop.step}
                  className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-3 text-xs dark:border-[#202020] dark:bg-black"
                >
                  <div className="flex items-center justify-between gap-2 font-mono">
                    <span className="font-bold text-[#FF263F]">
                      Hop #{hop.step} · HTTP {hop.statusCode ?? 'ERR'}
                    </span>
                    <span className="text-zinc-500 tabular-nums">
                      {hop.resolvedIp ? `${hop.resolvedIp} · ` : ''}
                      {hop.latencyMs}ms
                    </span>
                  </div>
                  <p dir="ltr" className="mt-1 break-all font-mono text-zinc-900 dark:text-zinc-200">
                    {hop.url}
                  </p>
                  {hop.isSameOrganization && hop.step > 1 && (
                    <p className="mt-1 font-medium text-[#0284C7] dark:text-[#38BDF8]">
                      {hop.relationshipDetail ||
                        (lang === 'en'
                          ? 'Same-organization / authorized service redirect'
                          : 'إعادة توجيه ضمن نفس الشركة أو خدمة مصرح بها')}
                    </p>
                  )}
                  {hop.downgradedToHttp && (
                    <p className="mt-1 font-semibold text-[#EF233C]">
                      {lang === 'en' ? 'HTTPS downgraded to unencrypted HTTP!' : 'تم خفض تشفير HTTPS إلى HTTP غير مشفر!'}
                    </p>
                  )}
                  {hop.blockedReason && (
                    <p className="mt-1 text-[#EF233C] font-medium">{hop.blockedReason}</p>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Domain & DNS Telemetry */}
          {report.domainIntel && (
            <div className="rounded-xl border border-[#E5E7EB] bg-white p-5 dark:border-[#202020] dark:bg-[#0D0D0D]">
              <h3 className="font-display text-sm font-bold text-zinc-950 dark:text-white">
                {UI_COPY.report.domainDetails[lang]}
              </h3>
              <dl className="mt-3 grid grid-cols-1 gap-2.5 text-xs sm:grid-cols-2">
                <div>
                  <dt className="text-zinc-500">{lang === 'en' ? 'Registrable Domain' : 'النطاق المسجل'}</dt>
                  <dd dir="ltr" className="font-mono font-semibold text-zinc-900 dark:text-white">
                    {report.domainIntel.registrableDomain}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">{lang === 'en' ? 'Registrar / Registry' : 'المسجل / السجل'}</dt>
                  <dd className="font-medium text-zinc-900 dark:text-white">
                    {report.domainIntel.registrar || (lang === 'en' ? 'Unavailable' : 'غير متوفر')}
                    {report.domainIntel.registry ? ` (${report.domainIntel.registry})` : ''}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">{lang === 'en' ? 'Domain Age' : 'عمر النطاق'}</dt>
                  <dd className="font-mono font-semibold text-zinc-900 dark:text-white tabular-nums">
                    {report.domainIntel.domainAgeDays !== undefined
                      ? `${report.domainIntel.domainAgeDays}d${report.domainIntel.domainAgeYears !== undefined ? ` (${report.domainIntel.domainAgeYears}y)` : ''}`
                      : lang === 'en'
                        ? 'Unavailable'
                        : 'غير متوفر'}
                    {report.domainIntel.isMultiTenantPaas && report.domainIntel.paasProvider
                      ? ` (${report.domainIntel.paasProvider})`
                      : ''}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">{lang === 'en' ? 'Primary IP / ASN / Network' : 'عنوان IP / الشبكة'}</dt>
                  <dd dir="ltr" className="font-mono text-zinc-900 dark:text-white">
                    {report.domainIntel.ipAddress || '—'}
                    {report.domainIntel.asn ? ` · ${report.domainIntel.asn}` : ''}
                    {report.domainIntel.country ? ` (${report.domainIntel.country})` : ''}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">{lang === 'en' ? 'DNS Provider & DNSSEC' : 'مزود DNS و DNSSEC'}</dt>
                  <dd dir="ltr" className="font-mono text-zinc-900 dark:text-white">
                    {report.domainIntel.dnsRecords.dnsProvider || 'Standard'} · DNSSEC:{' '}
                    {report.domainIntel.dnsRecords.dnssecValidated === true
                      ? 'Validated'
                      : report.domainIntel.dnsRecords.dnssecValidated === false
                        ? 'Unsigned'
                        : 'Unknown'}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">{lang === 'en' ? 'CDN / Proxy & TTL' : 'شبكة CDN وزمن TTL'}</dt>
                  <dd dir="ltr" className="font-mono text-zinc-900 dark:text-white tabular-nums">
                    {report.domainIntel.dnsRecords.cdnOrProxyProvider || 'Direct'}
                    {report.domainIntel.dnsRecords.minTtlSeconds ? ` · MinTTL ${report.domainIntel.dnsRecords.minTtlSeconds}s` : ''}
                    {report.domainIntel.dnsRecords.fastFluxSuspected ? ' · FastFlux!' : ''}
                  </dd>
                </div>
                <div className="sm:col-span-2">
                  <dt className="text-zinc-500">{lang === 'en' ? 'Owner / WHOIS Privacy' : 'المالك / خصوصية التسجيل'}</dt>
                  <dd className="font-medium text-zinc-900 dark:text-white">
                    {report.domainIntel.ownerSummary[lang]}
                  </dd>
                </div>
                <div className="sm:col-span-2">
                  <dt className="text-zinc-500">{lang === 'en' ? 'DNS Records (A / CAA / PTR / SOA / SPF / DMARC / DoH)' : 'سجلات DNS الكاملة (بما فيها CAA)'}</dt>
                  <dd dir="ltr" className="font-mono text-[11px] text-zinc-700 dark:text-zinc-300 break-words">
                    A: {report.domainIntel.dnsRecords.a.join(', ') || 'None'} · CNAME:{' '}
                    {report.domainIntel.dnsRecords.cname?.join(', ') || 'None'} · CAA:{' '}
                    {report.domainIntel.dnsRecords.caa?.join(', ') || 'None'} · PTR:{' '}
                    {report.domainIntel.dnsRecords.ptr?.join(', ') || 'None'} · SOA:{' '}
                    {report.domainIntel.dnsRecords.soa || 'N/A'} · SPF:{' '}
                    {report.domainIntel.dnsRecords.hasSpf ? 'Yes' : 'No'} · DMARC:{' '}
                    {report.domainIntel.dnsRecords.hasDmarc ? 'Yes' : 'No'} · DoH:{' '}
                    {report.domainIntel.dnsRecords.dohVerified ? 'Verified' : 'OS Only'}
                  </dd>
                </div>
                {report.domainIntel.subdomainAnalysis && (
                  <div className="sm:col-span-2 rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-3 dark:border-[#202020] dark:bg-black">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="font-semibold text-zinc-950 dark:text-white">
                        {lang === 'en' ? 'Subdomain & CNAME Delegation Audit' : 'تدقيق النطاقات الفرعية وتفويض CNAME'}
                      </span>
                      <span dir="ltr" className="font-mono text-[11px] text-zinc-500 tabular-nums">
                        {report.domainIntel.subdomainAnalysis.subdomainPrefix || '(apex)'} ·{' '}
                        {report.domainIntel.subdomainAnalysis.subdomainLevels}{' '}
                        {lang === 'en' ? 'level(s)' : 'مستوى'}
                      </span>
                    </div>
                    <p className="mt-1.5 text-xs leading-relaxed text-zinc-700 dark:text-zinc-300">
                      {report.domainIntel.subdomainAnalysis.assessment[lang]}
                    </p>
                    {report.domainIntel.subdomainAnalysis.sensitiveRoleTokens.length > 0 && (
                      <p dir="ltr" className="mt-1 font-mono text-[11px] text-[#D97706] dark:text-[#FBBF24]">
                        Role Tokens: {report.domainIntel.subdomainAnalysis.sensitiveRoleTokens.join(', ')}
                      </p>
                    )}
                    {report.domainIntel.subdomainAnalysis.externalCnameDelegation && (
                      <p className="mt-1 text-[11px] font-medium text-[#0284C7] dark:text-[#38BDF8]">
                        CNAME → {report.domainIntel.subdomainAnalysis.cnameTargets.join(', ')}{' '}
                        {report.domainIntel.subdomainAnalysis.externalCnameRelationship
                          ? `(${report.domainIntel.subdomainAnalysis.externalCnameRelationship})`
                          : ''}
                      </p>
                    )}
                  </div>
                )}
              </dl>
            </div>
          )}

          {/* SSL/TLS Telemetry */}
          {report.tlsIntel && (
            <div className="rounded-xl border border-[#E5E7EB] bg-white p-5 dark:border-[#202020] dark:bg-[#0D0D0D]">
              <h3 className="font-display text-sm font-bold text-zinc-950 dark:text-white">
                {UI_COPY.report.tlsDetails[lang]}
              </h3>
              <dl className="mt-3 grid grid-cols-1 gap-2.5 text-xs sm:grid-cols-2">
                <div>
                  <dt className="text-zinc-500">{lang === 'en' ? 'Protocol, Cipher & Strength' : 'البروتوكول والتشفير وقوة المفتاح'}</dt>
                  <dd dir="ltr" className={`font-mono font-semibold ${report.tlsIntel.weakProtocolOrCipher ? 'text-[#EF233C]' : 'text-zinc-900 dark:text-white'}`}>
                    {report.tlsIntel.protocol || 'None'} · {report.tlsIntel.cipher || 'N/A'}
                    {report.tlsIntel.keyBits ? ` · ${report.tlsIntel.keyBits}b` : ''}
                    {report.tlsIntel.sigAlg ? ` · ${report.tlsIntel.sigAlg}` : ''}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">{lang === 'en' ? 'Chain Trusted & Depth' : 'موثوقية السلسلة وعمقها'}</dt>
                  <dd className="font-semibold text-zinc-900 dark:text-white">
                    {report.tlsIntel.authorized ? 'Yes' : `No (${report.tlsIntel.authorizationError || 'Untrusted'})`}
                    {report.tlsIntel.chainLength ? ` · Chain depth ${report.tlsIntel.chainLength}` : ''}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">{lang === 'en' ? 'Issuer' : 'الجهة المصدرة'}</dt>
                  <dd className="font-medium text-zinc-900 dark:text-white">
                    {report.tlsIntel.issuer || 'N/A'}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">{lang === 'en' ? 'Expires / CT Logs' : 'الانتهاء / سجلات الشفافية'}</dt>
                  <dd dir="ltr" className="font-mono text-zinc-900 dark:text-white tabular-nums">
                    {report.tlsIntel.validTo?.slice(0, 10) || 'N/A'} · CT: {report.tlsIntel.ctLogCount ?? 'N/A'}
                  </dd>
                </div>
                <div className="sm:col-span-2">
                  <dt className="text-zinc-500">SANs ({report.tlsIntel.sanList.length})</dt>
                  <dd dir="ltr" className="max-h-16 overflow-y-auto font-mono text-[11px] text-zinc-600 dark:text-zinc-400">
                    {report.tlsIntel.sanList.join(', ') || 'None'}
                  </dd>
                </div>
              </dl>
            </div>
          )}

          {/* Content, JS & Brand Impersonation Telemetry */}
          {report.contentIntel && (
            <div className="rounded-xl border border-[#E5E7EB] bg-white p-5 dark:border-[#202020] dark:bg-[#0D0D0D]">
              <h3 className="font-display text-sm font-bold text-zinc-950 dark:text-white">
                {UI_COPY.report.contentDetails[lang]}
              </h3>
              <dl className="mt-3 grid grid-cols-1 gap-2.5 text-xs sm:grid-cols-2">
                <div className="sm:col-span-2">
                  <dt className="text-zinc-500">{lang === 'en' ? 'Page Title' : 'عنوان الصفحة'}</dt>
                  <dd className="font-medium text-zinc-900 dark:text-white">
                    {report.contentIntel.pageTitle || (lang === 'en' ? 'Empty / Missing <title>' : 'فارغ / مفقود')}
                  </dd>
                </div>
                {report.contentIntel.claimedPurpose && (
                  <div className="sm:col-span-2">
                    <dt className="text-zinc-500">{lang === 'en' ? 'Claimed Website Function' : 'الوظيفة المُدّعاة للموقع'}</dt>
                    <dd className="font-medium text-zinc-900 dark:text-white">
                      {report.contentIntel.claimedPurpose[lang]}
                      {report.contentIntel.contentReadStatus === 'blocked_by_site' && report.contentIntel.blockedReason
                        ? ` (${report.contentIntel.blockedReason})`
                        : ''}
                    </dd>
                  </div>
                )}
                <div>
                  <dt className="text-zinc-500">{lang === 'en' ? 'Forms / Password Fields' : 'النماذج / حقول كلمة المرور'}</dt>
                  <dd className="font-mono font-semibold text-zinc-900 dark:text-white tabular-nums">
                    {report.contentIntel.formCount} / {report.contentIntel.passwordInputCount}
                    {report.contentIntel.unwrappedPasswordInputCount > 0 && (
                      <span className="ms-1 text-[#EF233C]">
                        ({report.contentIntel.unwrappedPasswordInputCount} unwrapped)
                      </span>
                    )}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">{lang === 'en' ? 'Scripts (Inline / External)' : 'السكربتات (داخلي / خارجي)'}</dt>
                  <dd className="font-mono font-semibold text-zinc-900 dark:text-white tabular-nums">
                    {report.contentIntel.inlineScriptCount} / {report.contentIntel.externalScriptCount}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">{lang === 'en' ? 'Iframes / Hidden Nodes' : 'الإطارات / العناصر المخفية'}</dt>
                  <dd className="font-mono text-zinc-900 dark:text-white tabular-nums">
                    {report.contentIntel.iframeCount} / {report.contentIntel.hiddenElementCount}
                  </dd>
                </div>
                <div>
                  <dt className="text-zinc-500">{lang === 'en' ? 'Popups / Auto-Redirects / Lures' : 'النوافذ / التحويل التلقائي / الخداع'}</dt>
                  <dd className="font-mono text-zinc-900 dark:text-white tabular-nums">
                    {(report.contentIntel.popupIndicators?.length || 0)} / {(report.contentIntel.autoRedirectIndicators?.length || 0)} / {report.contentIntel.fakeAlertIndicators.length + report.contentIntel.phishingKeywordsMatched.length}
                  </dd>
                </div>
                {report.contentIntel.oauthWidgetsDetected && report.contentIntel.oauthWidgetsDetected.length > 0 && (
                  <div className="sm:col-span-2">
                    <dt className="text-zinc-500">
                      {lang === 'en' ? 'Standard Third-Party OAuth Widgets' : 'أزرار تسجيل الدخول الخارجية المعتادة (OAuth)'}
                    </dt>
                    <dd className="text-[11px] font-medium text-[#16A34A]">
                      {report.contentIntel.oauthWidgetsDetected.join(', ')} ·{' '}
                      {lang === 'en'
                        ? 'Recognized standard sign-in widget (not treated as brand impersonation)'
                        : 'خيار تسجيل دخول معتاد لا يُحتسب انتحالاً للعلامة التجارية'}
                    </dd>
                  </div>
                )}
                {((report.contentIntel.personalFinanceFields && report.contentIntel.personalFinanceFields.length > 0) ||
                  (report.contentIntel.fakeSupportIndicators && report.contentIntel.fakeSupportIndicators.length > 0)) && (
                  <div className="sm:col-span-2">
                    <dt className="text-zinc-500">
                      {lang === 'en' ? 'Sensitive Input / Fake Support Signals' : 'حقول البيانات الحساسة / مؤشرات الدعم المزيف'}
                    </dt>
                    <dd className="font-mono text-[11px] text-[#EF233C]">
                      {[
                        ...(report.contentIntel.personalFinanceFields || []),
                        ...(report.contentIntel.fakeSupportIndicators || []),
                      ].join(' · ')}
                    </dd>
                  </div>
                )}
                {report.contentIntel.externalScriptDomains && report.contentIntel.externalScriptDomains.length > 0 && (
                  <div className="sm:col-span-2">
                    <dt className="text-zinc-500">{lang === 'en' ? 'External Script Hosts' : 'نطاقات السكربتات الخارجية'}</dt>
                    <dd dir="ltr" className="truncate font-mono text-[11px] text-zinc-600 dark:text-zinc-400">
                      {report.contentIntel.externalScriptDomains.join(', ')}
                    </dd>
                  </div>
                )}
                {report.contentIntel.permissionAudit && (
                  <div
                    className={`sm:col-span-2 rounded-xl border p-3.5 ${
                      report.contentIntel.permissionAudit.riskEscalatedToHigh
                        ? 'border-red-500/45 bg-red-500/[0.06] text-zinc-900 dark:text-zinc-100'
                        : 'border-emerald-500/35 bg-emerald-500/[0.05] text-zinc-900 dark:text-zinc-100'
                    }`}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="text-xs font-bold">
                        {lang === 'ar'
                          ? 'فحص أذونات المتصفح عند الدخول ومطابقة الاستخدام المعلن'
                          : 'On-Entry Browser Permissions & Stated Usage Audit'}
                      </span>
                      <span
                        className={`font-mono text-[11px] font-bold ${
                          report.contentIntel.permissionAudit.riskEscalatedToHigh
                            ? 'text-[#EF233C]'
                            : 'text-[#16A34A]'
                        }`}
                      >
                        {report.contentIntel.permissionAudit.riskEscalatedToHigh
                          ? lang === 'ar'
                            ? 'تصعيد خطورة مرتفعة (HIGH RISK)'
                            : 'ESCALATED: HIGH RISK'
                          : report.contentIntel.permissionAudit.permissions.length > 0
                            ? lang === 'ar'
                              ? 'استخدام مطابق ومبرر'
                              : 'CONSISTENT USAGE'
                            : lang === 'ar'
                              ? 'لا تطلب أذونات حساسة'
                              : 'NO PROMPTS'}
                      </span>
                    </div>

                    <p className="mt-1.5 text-xs leading-relaxed text-zinc-700 dark:text-zinc-300">
                      {report.contentIntel.permissionAudit.usageVerificationVerdict[lang]}
                    </p>

                    {report.contentIntel.permissionAudit.permissions.length > 0 && (
                      <div className="mt-3 space-y-2">
                        {report.contentIntel.permissionAudit.permissions.map((perm) => (
                          <div
                            key={perm.id}
                            className="rounded-lg border border-[#E5E7EB] bg-white/90 p-2.5 text-[11px] dark:border-[#242424] dark:bg-black/80"
                          >
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <span className="font-bold text-zinc-950 dark:text-white">
                                {perm.label[lang]}
                              </span>
                              <span
                                className={`font-mono text-[10px] font-bold ${
                                  perm.triggeredOnEntry || !perm.consistentWithSitePurpose
                                    ? 'text-[#EF233C]'
                                    : 'text-[#16A34A]'
                                }`}
                              >
                                {perm.triggeredOnEntry
                                  ? lang === 'ar'
                                    ? 'تلقائي فور الدخول'
                                    : 'AUTO ON ENTRY'
                                  : lang === 'ar'
                                    ? 'عند تفاعل المستخدم'
                                    : 'USER ACTION'}{' '}
                                ·{' '}
                                {perm.consistentWithSitePurpose
                                  ? lang === 'ar'
                                    ? 'الاستخدام المعلن صحيح'
                                    : 'USAGE MATCHES'
                                  : lang === 'ar'
                                    ? 'الاستخدام المعلن غير صحيح'
                                    : 'USAGE MISMATCH'}
                              </span>
                            </div>
                            <p dir="ltr" className="mt-0.5 font-mono text-[10px] text-zinc-500 dark:text-zinc-400">
                              API: {perm.api}
                            </p>
                            <p className="mt-1 text-zinc-700 dark:text-zinc-300">{perm.reason[lang]}</p>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                {report.contentIntel.suspectedBrand && (
                  <div
                    className={`sm:col-span-2 rounded-lg border p-2.5 ${
                      report.contentIntel.suspectedBrand.similarityOnly
                        ? 'border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-300'
                        : 'border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300'
                    }`}
                  >
                    {report.contentIntel.suspectedBrand.similarityOnly ? (
                      <p className="text-xs font-semibold">
                        {lang === 'en'
                          ? `Domain name similarity to ${report.contentIntel.suspectedBrand.brand} (${report.contentIntel.suspectedBrand.officialDomain}) detected; impersonation has not been proven.`
                          : `تم اكتشاف تشابه في اسم النطاق مع علامة تجارية معروفة، ولم يتم إثبات الانتحال (${report.contentIntel.suspectedBrand.brand} — ${report.contentIntel.suspectedBrand.officialDomain}).`}
                      </p>
                    ) : (
                      <>
                        <span className="font-bold">
                          {report.contentIntel.suspectedBrand.brand} ({report.contentIntel.suspectedBrand.confidence}%)
                        </span>
                        <span className="ms-2 font-mono text-[11px]">
                          Official: {report.contentIntel.suspectedBrand.officialDomain}
                        </span>
                      </>
                    )}
                  </div>
                )}
              </dl>
            </div>
          )}

          {/* File & Download Analysis */}
          <div className="lg:col-span-2 rounded-xl border border-[#E5E7EB] bg-white p-5 dark:border-[#202020] dark:bg-[#0D0D0D] space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-100 pb-3 dark:border-zinc-800">
              <div className="flex items-center gap-2.5">
                <CyberSticker type="radar" size={32} interactive={false} />
                <div>
                  <h3 className="font-display text-sm font-bold text-zinc-950 dark:text-white">
                    {lang === 'ar' ? 'فحص الملفات المرصودة وروابط التنزيل (File & Payload Inspection)' : 'File & Download Payload Inspection'}
                  </h3>
                  <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
                    {report.fileAnalysis.sandboxNote[lang]}
                  </p>
                </div>
              </div>
              <span className="inline-flex items-center gap-1.5 rounded-md border border-zinc-200 bg-zinc-50 px-2.5 py-1 text-[11px] font-semibold text-zinc-700 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
                <ShieldCheck className="h-3 w-3 text-emerald-600 dark:text-emerald-400" />
                <span>{lang === 'ar' ? 'فحص البصمة والتوقيع الثنائي' : 'Header & Magic Signature Verified'}</span>
              </span>
            </div>

            {report.fileAnalysis.directFile ? (
              <div className="space-y-4">
                <dl className="grid grid-cols-1 gap-3 text-xs sm:grid-cols-4">
                  <div className="rounded-lg border border-zinc-200 bg-zinc-50/70 p-3 dark:border-zinc-800 dark:bg-zinc-900/50">
                    <dt className="text-zinc-500">{lang === 'en' ? 'Filename & Extension' : 'اسم الملف والامتداد'}</dt>
                    <dd dir="ltr" className="mt-1 font-mono font-semibold text-zinc-900 dark:text-white">
                      {report.fileAnalysis.directFile.filename} ({report.fileAnalysis.directFile.extension})
                    </dd>
                  </div>
                  <div className="rounded-lg border border-zinc-200 bg-zinc-50/70 p-3 dark:border-zinc-800 dark:bg-zinc-900/50">
                    <dt className="text-zinc-500">{lang === 'en' ? 'Download Category' : 'تصنيف التحميل'}</dt>
                    <dd className="mt-1 font-semibold text-zinc-900 dark:text-white">
                      {tFileDownloadCategory(report.fileAnalysis.directFile.downloadCategory, lang)}
                    </dd>
                  </div>
                  <div className="rounded-lg border border-zinc-200 bg-zinc-50/70 p-3 dark:border-zinc-800 dark:bg-zinc-900/50">
                    <dt className="text-zinc-500">{lang === 'en' ? 'Detected Signature' : 'التوقيع الثنائي المكتشف'}</dt>
                    <dd dir="ltr" className="mt-1 font-mono text-zinc-900 dark:text-white">
                      {report.fileAnalysis.directFile.detectedSignature || 'N/A'}
                    </dd>
                  </div>
                  <div className="rounded-lg border border-zinc-200 bg-zinc-50/70 p-3 dark:border-zinc-800 dark:bg-zinc-900/50">
                    <dt className="text-zinc-500">SHA-256 Hash</dt>
                    <dd dir="ltr" className="mt-1 break-all font-mono text-[11px] text-zinc-700 dark:text-zinc-300">
                      {report.fileAnalysis.directFile.sha256 || '—'}
                    </dd>
                  </div>
                </dl>

                {/* Interactive Action Box: Live Scan in Platform, Download for Sandbox, & External Threat References */}
                <div
                  className={`rounded-lg border p-4 ${
                    report.fileAnalysis.directFile.riskFlag === 'high' ||
                    report.fileAnalysis.directFile.riskFlag === 'critical'
                      ? 'border-red-200 bg-red-50/40 dark:border-red-950/60 dark:bg-red-950/20'
                      : 'border-zinc-200 bg-zinc-50/60 dark:border-zinc-800 dark:bg-zinc-900/40'
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <h4
                        className={`text-xs font-bold ${
                          report.fileAnalysis.directFile.riskFlag === 'high' ||
                          report.fileAnalysis.directFile.riskFlag === 'critical'
                            ? 'text-red-900 dark:text-red-300'
                            : 'text-zinc-900 dark:text-zinc-100'
                        }`}
                      >
                        {lang === 'ar' ? 'فحص وتتبع رابط هذا الملف مباشرة في Scan Link SM' : 'Inspect & Track this Payload URL in Scan Link SM'}
                      </h4>
                      <p
                        className={`mt-0.5 text-[11px] ${
                          report.fileAnalysis.directFile.riskFlag === 'high' ||
                          report.fileAnalysis.directFile.riskFlag === 'critical'
                            ? 'text-red-700 dark:text-red-400'
                            : 'text-zinc-600 dark:text-zinc-400'
                        }`}
                      >
                        {lang === 'ar'
                          ? 'يمكنك فحص رابط هذا الملف مباشرة للكشف عن مسارات التحويل وسلوك السورس والتهديدات'
                          : 'Launch a direct deterministic scan of this file download URL to inspect redirect hops and telemetry'}
                      </p>
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        type="button"
                        onClick={() => onRescan(report.fileAnalysis.directFile!.url)}
                        className="inline-flex items-center gap-1.5 rounded-lg bg-red-600 px-3 py-1.5 text-xs font-bold text-white shadow-sm hover:bg-red-700 transition"
                      >
                        <RefreshCw className="h-3.5 w-3.5" />
                        <span>{lang === 'ar' ? 'فحص الملف الآن بالمنصة' : 'Scan File URL Now'}</span>
                      </button>

                      {safeExternalHref(report.fileAnalysis.directFile.url) && (
                        <a
                          href={safeExternalHref(report.fileAnalysis.directFile.url)}
                          download={report.fileAnalysis.directFile.filename}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1.5 rounded-lg border border-zinc-300 bg-white px-3 py-1.5 text-xs font-semibold text-zinc-800 shadow-sm hover:bg-zinc-50 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-200 transition"
                        >
                          <Download className="h-3.5 w-3.5" />
                          <span>{lang === 'ar' ? 'تنزيل للفحص المعزول' : 'Download for Sandbox'}</span>
                        </a>
                      )}
                    </div>
                  </div>

                  {/* Multi-Engine External Intelligence References */}
                  <div className="mt-3.5 border-t border-red-200/70 pt-3 dark:border-red-900/50">
                    <span className="text-[11px] font-bold text-zinc-700 dark:text-zinc-300">
                      {lang === 'ar' ? 'مراجع فحص نوع الملف وقواعد التهديدات الدولية:' : 'Multi-Engine Threat Verification References:'}
                    </span>
                    <div className="mt-2 flex flex-wrap gap-2 text-xs">
                      <a
                        href={`https://www.virustotal.com/gui/search/${encodeURIComponent(report.fileAnalysis.directFile.sha256 || report.fileAnalysis.directFile.filename)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 rounded-md border border-zinc-300 bg-white px-2.5 py-1 text-[11px] font-medium text-zinc-800 hover:text-red-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-200"
                      >
                        <ExternalLink className="h-3 w-3" />
                        <span>VirusTotal Hash Lookup</span>
                      </a>
                      <a
                        href={`https://www.hybrid-analysis.com/search?query=${encodeURIComponent(report.fileAnalysis.directFile.sha256 || report.fileAnalysis.directFile.filename)}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 rounded-md border border-zinc-300 bg-white px-2.5 py-1 text-[11px] font-medium text-zinc-800 hover:text-red-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-200"
                      >
                        <ExternalLink className="h-3 w-3" />
                        <span>Hybrid Analysis Sandbox</span>
                      </a>
                    </div>
                  </div>
                </div>
              </div>
            ) : report.fileAnalysis.discoveredDownloads.length > 0 ? (
              <div className="space-y-3">
                <p className="text-xs font-semibold text-zinc-700 dark:text-zinc-300">
                  {lang === 'ar'
                    ? `تم رصد ${report.fileAnalysis.discoveredDownloads.length} رابط تنزيل بصفحة الموقع:`
                    : `Discovered ${report.fileAnalysis.discoveredDownloads.length} download resource links in page DOM:`}
                </p>
                <div className="divide-y divide-zinc-100 rounded-lg border border-zinc-200 dark:divide-zinc-800 dark:border-zinc-800">
                  {report.fileAnalysis.discoveredDownloads.slice(0, 6).map((d) => (
                    <div key={d.url} className="flex flex-wrap items-center justify-between gap-2 p-3 text-xs">
                      <div className="min-w-0 flex-1">
                        <div dir="ltr" className="flex flex-wrap items-center gap-2 font-mono font-semibold text-zinc-900 dark:text-white">
                          <span className="truncate">{d.filename}</span>
                          <span className="text-zinc-500">({d.extension})</span>
                          {d.downloadCategory && (
                            <span className="rounded border border-zinc-200 bg-zinc-100 px-1.5 py-0.5 font-sans text-[10px] font-semibold text-zinc-700 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
                              {tFileDownloadCategory(d.downloadCategory, lang)}
                            </span>
                          )}
                        </div>
                        <div dir="ltr" className="truncate font-mono text-[11px] text-zinc-500">
                          {d.url}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => onRescan(d.url)}
                          className="inline-flex items-center gap-1 rounded-md bg-red-600 px-2.5 py-1 text-[11px] font-bold text-white hover:bg-red-700 transition"
                        >
                          <RefreshCw className="h-3 w-3" />
                          <span>{lang === 'ar' ? 'فحص هذا الملف' : 'Scan File'}</span>
                        </button>
                        {safeExternalHref(d.url) && (
                          <a
                            href={safeExternalHref(d.url)}
                            download={d.filename}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 rounded-md border border-zinc-300 bg-white px-2 py-1 text-[11px] font-medium text-zinc-700 hover:bg-zinc-50 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-200"
                          >
                            <Download className="h-3 w-3" />
                          </a>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">
                {lang === 'en'
                  ? 'No direct binary download or executable download links found on inspected page.'
                  : 'لم يتم رصد تنزيل مباشر لملفات أو روابط برامج تنفيذية في الصفحة المفحوصة.'}
              </p>
            )}

            {/* Interactive Custom File Fetch & Deep Inspection Box */}
            <div className="mt-4 rounded-xl border border-dashed border-red-200 bg-red-50/40 p-4 dark:border-red-900/40 dark:bg-red-950/20">
              <div className="flex flex-col gap-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Search className="h-4 w-4 text-red-600 dark:text-red-400" />
                    <span className="text-xs font-bold text-zinc-900 dark:text-white">
                      {lang === 'ar'
                        ? 'خانة جلب وفحص ملف محدد من الموقع (تحليل فوري وحي)'
                        : 'Inspect & Fetch Custom File from Target (Live Analysis)'}
                    </span>
                  </div>
                  <span className="rounded bg-red-100 px-2 py-0.5 text-[10px] font-bold text-red-700 dark:bg-red-900/50 dark:text-red-300">
                    {lang === 'ar' ? 'فحص حي بالمنصة' : 'Live Platform Scan'}
                  </span>
                </div>

                <p className="text-[11.5px] text-zinc-600 dark:text-zinc-300">
                  {lang === 'ar'
                    ? 'أدخل مسار أو رابط أي ملف داخل هذا النطاق (مثل /setup.exe أو /app.zip أو رابط مباشر) ليقوم المحرك بجلبه وفحصه أمنياً وكشف أي مخاطر تنفيذية أمامك مباشرة:'
                    : 'Enter the path or URL of any file on this domain (e.g. /setup.exe, /app.zip or direct link) to fetch and analyze it live in front of you:'}
                </p>

                <form onSubmit={handleFetchCustomFile} className="flex flex-wrap items-center gap-2">
                  <input
                    type="text"
                    value={customFileUrl}
                    onChange={(e) => setCustomFileUrl(e.target.value)}
                    dir="ltr"
                    placeholder="e.g. /downloads/update.exe or https://..."
                    className="min-w-[260px] flex-1 rounded-lg border border-zinc-300 bg-white px-3 py-1.5 font-mono text-xs text-zinc-900 shadow-sm focus:border-red-500 focus:outline-none focus:ring-1 focus:ring-red-500 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100"
                  />
                  <button
                    type="submit"
                    disabled={!customFileUrl.trim()}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-red-600 px-3.5 py-1.5 text-xs font-bold text-white shadow-sm hover:bg-red-700 disabled:opacity-50 transition"
                  >
                    <RefreshCw className="h-3.5 w-3.5" />
                    <span>{lang === 'ar' ? 'جلب وفحص فوري للملف' : 'Fetch & Scan File'}</span>
                  </button>
                </form>

                {/* External Multi-Engine Threat Intelligence Lookup References */}
                <div className="mt-1 border-t border-red-200/60 pt-2.5 dark:border-red-900/40">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-[11px] font-semibold text-zinc-600 dark:text-zinc-300">
                      {lang === 'ar'
                        ? 'مراجع خارجية لفحص نوع وحمولة الملفات وقواعد التهديدات الدولية:'
                        : 'External Multi-Engine Intelligence & Sandbox References:'}
                    </span>
                    <div className="flex flex-wrap items-center gap-1.5">
                      <a
                        href={
                          report.fileAnalysis?.directFile?.sha256
                            ? `https://www.virustotal.com/gui/file/${report.fileAnalysis.directFile.sha256}`
                            : `https://www.virustotal.com/gui/domain/${encodeURIComponent(report.domainIntel?.registrableDomain || report.submittedUrl)}`
                        }
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 rounded border border-zinc-300 bg-white px-2 py-0.5 text-[10.5px] font-medium text-zinc-700 hover:text-red-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
                      >
                        <ExternalLink className="h-2.5 w-2.5" />
                        <span>VirusTotal</span>
                      </a>
                      <a
                        href="https://www.hybrid-analysis.com/"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 rounded border border-zinc-300 bg-white px-2 py-0.5 text-[10.5px] font-medium text-zinc-700 hover:text-red-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
                      >
                        <ExternalLink className="h-2.5 w-2.5" />
                        <span>Hybrid Analysis</span>
                      </a>
                      <a
                        href="https://metadefender.opswat.com/"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 rounded border border-zinc-300 bg-white px-2 py-0.5 text-[10.5px] font-medium text-zinc-700 hover:text-red-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
                      >
                        <ExternalLink className="h-2.5 w-2.5" />
                        <span>OPSWAT MetaDefender</span>
                      </a>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Deep HTML & JS Behavioral Source Forensics */}
          {report.sourceIntel && (
            <div className="rounded-xl border border-[#E5E7EB] bg-white p-5 dark:border-[#202020] dark:bg-[#0D0D0D] space-y-4">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2.5">
                  <CyberSticker type="source_code" size={34} interactive={false} />
                  <div>
                    <h3 className="font-display text-sm font-bold text-zinc-950 dark:text-white">
                      {lang === 'en'
                        ? 'HTML Source & JavaScript Behavioral Forensics'
                        : 'تحليل سورس HTML وسلوك JavaScript بالذاكرة'}
                    </h3>
                    <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
                      {lang === 'en'
                        ? `Static non-executing AST/pattern telemetry across DOM, scripts & headers · ${report.sourceIntel.externalJsInspectedCount ?? 0} fetched external JS`
                        : `قراءة ساكنة للشفرة المصدرية دون تنفيذ (${report.sourceIntel.externalJsInspectedCount ?? 0} ملف JS خارجي تم فحصه)`}
                    </p>
                  </div>
                </div>
              </div>

              <SourceCodeForensicsVisual lang={lang} />

              <dl className="grid grid-cols-2 gap-2.5 text-xs">
                <div className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-2.5 dark:border-[#202020] dark:bg-black">
                  <dt className="text-[11px] text-zinc-500">
                    {lang === 'en' ? 'Form Action Hijack' : 'تغيير وجهة النموذج ديناميكياً'}
                  </dt>
                  <dd className={`mt-0.5 font-mono font-bold ${report.sourceIntel.jsBehaviorSummary?.dynamicFormActionRewrite ? 'text-[#EF233C]' : 'text-[#16A34A]'}`}>
                    {report.sourceIntel.jsBehaviorSummary?.dynamicFormActionRewrite
                      ? lang === 'en' ? 'DETECTED' : 'مرصود'
                      : lang === 'en' ? 'Clean' : 'سليم'}
                  </dd>
                </div>
                <div className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-2.5 dark:border-[#202020] dark:bg-black">
                  <dt className="text-[11px] text-zinc-500">
                    {lang === 'en' ? 'Password DOM Hooks' : 'التقاط حقول كلمات المرور'}
                  </dt>
                  <dd className={`mt-0.5 font-mono font-bold ${report.sourceIntel.jsBehaviorSummary?.passwordFieldDomHooks ? 'text-[#EF233C]' : 'text-[#16A34A]'}`}>
                    {report.sourceIntel.jsBehaviorSummary?.passwordFieldDomHooks
                      ? lang === 'en' ? 'DETECTED' : 'مرصود'
                      : lang === 'en' ? 'Clean' : 'سليم'}
                  </dd>
                </div>
                <div className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-2.5 dark:border-[#202020] dark:bg-black">
                  <dt className="text-[11px] text-zinc-500">
                    {lang === 'en' ? 'Crypto/Clipboard Drainer' : 'سحب محافظ / حافظة النسخ'}
                  </dt>
                  <dd className={`mt-0.5 font-mono font-bold ${report.sourceIntel.jsBehaviorSummary?.walletDrainerPattern ? 'text-[#EF233C]' : 'text-[#16A34A]'}`}>
                    {report.sourceIntel.jsBehaviorSummary?.walletDrainerPattern
                      ? lang === 'en' ? 'DETECTED' : 'مرصود'
                      : lang === 'en' ? 'None' : 'لا يوجد'}
                  </dd>
                </div>
                <div className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-2.5 dark:border-[#202020] dark:bg-black">
                  <dt className="text-[11px] text-zinc-500">
                    {lang === 'en' ? 'Hidden Overlay Iframes / Traps' : 'إطارات مخفية / مصائد الفحص'}
                  </dt>
                  <dd className="mt-0.5 font-mono font-bold text-zinc-900 dark:text-white tabular-nums">
                    {report.sourceIntel.jsBehaviorSummary?.hiddenOverlayIframes ?? 0} ·{' '}
                    {report.sourceIntel.jsBehaviorSummary?.antiDebugTraps
                      ? lang === 'en' ? 'Anti-Debug Active' : 'منع فحص نشط'
                      : lang === 'en' ? 'No Anti-Debug' : 'بدون تعطيل'}
                  </dd>
                </div>
              </dl>

              {report.sourceIntel.obfuscationVsMinifiedNote && (
                <p className="text-xs leading-relaxed text-zinc-600 dark:text-zinc-400">
                  {report.sourceIntel.obfuscationVsMinifiedNote[lang]}
                </p>
              )}

              {report.sourceIntel.staticVsRenderedNote && (
                <p className="text-xs leading-relaxed text-[#D97706]">
                  {report.sourceIntel.staticVsRenderedNote[lang]}
                </p>
              )}

              {report.sourceIntel.brandLookalikeLinks && report.sourceIntel.brandLookalikeLinks.length > 0 && (
                <div className="space-y-1.5 border-t border-[#E5E7EB] pt-3 dark:border-[#202020]">
                  <p className="text-xs font-bold text-[#EF233C]">
                    {lang === 'en'
                      ? 'Outbound Lookalike Brand Links Detected:'
                      : 'روابط خارجية مشابهة لعلامات تجارية معروفة:'}
                  </p>
                  {report.sourceIntel.brandLookalikeLinks.slice(0, 4).map((lk, idx) => (
                    <div
                      key={`${lk.host}-${idx}`}
                      className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-2 text-[11px] dark:border-[#202020] dark:bg-black"
                    >
                      <span dir="ltr" className="font-mono font-semibold text-zinc-950 dark:text-white">
                        {lk.host}
                      </span>{' '}
                      <span className="text-zinc-600 dark:text-zinc-400">
                        → {lk.targetBrand} ({lk.officialDomain}) · {lk.evidence}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {report.sourceIntel.jsDomMutationPayloads && report.sourceIntel.jsDomMutationPayloads.length > 0 && (
                <div className="space-y-1 border-t border-[#E5E7EB] pt-3 dark:border-[#202020]">
                  <p className="text-xs font-bold text-zinc-900 dark:text-white">
                    {lang === 'en'
                      ? 'Post-Load JS DOM Injection / Mutation Signatures:'
                      : 'مؤشرات تعديل وحقن DOM بعد تشغيل JavaScript:'}
                  </p>
                  <p dir="ltr" className="font-mono text-[11px] text-[#D97706]">
                    {report.sourceIntel.jsDomMutationPayloads.join(' · ')}
                  </p>
                </div>
              )}

              {report.sourceIntel.suspiciousCodeSignals.length > 0 && (
                <div className="space-y-2 border-t border-[#E5E7EB] pt-3 dark:border-[#202020]">
                  <p className="text-xs font-bold text-zinc-900 dark:text-white">
                    {lang === 'en' ? 'Code Pattern Signals Observed:' : 'إشارات الشيفرة المرصودة:'}
                  </p>
                  {report.sourceIntel.suspiciousCodeSignals.slice(0, 4).map((sig) => (
                    <div
                      key={sig.id}
                      className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-2.5 text-xs dark:border-[#202020] dark:bg-black"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span
                          className={`font-mono font-semibold ${
                            sig.riskLevel === 'critical' || sig.riskLevel === 'high'
                              ? 'text-[#EF233C]'
                              : sig.riskLevel === 'medium'
                                ? 'text-[#D97706]'
                                : 'text-zinc-800 dark:text-zinc-200'
                          }`}
                        >
                          {sig.indicator}
                        </span>
                        <span className="font-mono text-[10px] text-zinc-500 uppercase">{sig.category}</span>
                      </div>
                      <p className="mt-1 text-[11px] text-zinc-700 dark:text-zinc-300">
                        {sig.contextAssessment[lang]}
                      </p>
                    </div>
                  ))}
                </div>
              )}
              {report.sourceIntel.dataFlowTaints && report.sourceIntel.dataFlowTaints.length > 0 && (
                <div className="space-y-2 border-t border-[#E5E7EB] pt-3 dark:border-[#202020]">
                  <p className="text-xs font-bold text-[#EF233C]">
                    {lang === 'en'
                      ? `AST Static Taint & Surveillance Exfiltration Flows (${report.sourceIntel.dataFlowTaints.length})`
                      : `مسارات تدفق البيانات والتسريب بالتحليل الثابت AST (${report.sourceIntel.dataFlowTaints.length})`}
                  </p>
                  {report.sourceIntel.dataFlowTaints.slice(0, 6).map((tf) => (
                    <div
                      key={tf.id}
                      className="rounded-lg border border-[#EF233C]/35 bg-[#EF233C]/[0.04] p-2.5 text-xs dark:bg-[#140709]"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span dir="ltr" className="font-mono text-[11px] font-bold text-[#EF233C]">
                          {tf.source} → {tf.sink}
                        </span>
                        <span dir="ltr" className="font-mono text-[10px] font-semibold text-zinc-600 dark:text-zinc-300">
                          {tf.triggerContext} · {tf.sinkChannel}
                        </span>
                      </div>
                      <p className="mt-1 text-[11px] text-zinc-700 dark:text-zinc-300">{tf.detail[lang]}</p>
                      {tf.excerpt && (
                        <p dir="ltr" className="mt-1 truncate font-mono text-[10px] text-zinc-500">
                          {tf.excerpt}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {report.sourceIntel.plantedBackdoors && report.sourceIntel.plantedBackdoors.length > 0 && (
                <div className="space-y-2 border-t border-[#E5E7EB] pt-3 dark:border-[#202020]">
                  <p className="text-xs font-bold text-[#EF233C]">
                    {lang === 'en'
                      ? `Planted Backdoor & Control Hook Indicators (${report.sourceIntel.plantedBackdoors.length})`
                      : `مؤشرات الأبواب الخلفية أو الثغرات المزروعة (${report.sourceIntel.plantedBackdoors.length})`}
                  </p>
                  {report.sourceIntel.plantedBackdoors.slice(0, 6).map((bd) => (
                    <div
                      key={bd.id}
                      className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-2.5 text-xs dark:border-[#202020] dark:bg-black"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span dir="ltr" className="font-mono text-[11px] font-bold text-[#EF233C]">
                          {bd.kind}
                        </span>
                        <span className="font-mono text-[10px] font-semibold uppercase text-zinc-500">
                          {tSeverity(bd.severity, lang)}
                        </span>
                      </div>
                      <p className="mt-1 text-[11px] text-zinc-700 dark:text-zinc-300">{bd.detail[lang]}</p>
                      <p dir="ltr" className="mt-1 truncate font-mono text-[10px] text-zinc-500">
                        {bd.evidence}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Encrypted / Encoded URL & Path Segment Forensics */}
          {report.urlEncryptionIntel && (
            <div
              className={`lg:col-span-2 rounded-xl border p-5 space-y-4 ${
                report.urlEncryptionIntel.hasEncryptedOrEncodedParts
                  ? 'border-amber-500/45 bg-amber-500/[0.04] dark:border-amber-500/35 dark:bg-[#0D0D0D]'
                  : 'border-[#E5E7EB] bg-white dark:border-[#202020] dark:bg-[#0D0D0D]'
              }`}
            >
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-200/70 pb-3 dark:border-[#202020]">
                <div className="flex items-center gap-2.5">
                  <Lock
                    className={`h-4 w-4 shrink-0 ${
                      report.urlEncryptionIntel.hasEncryptedOrEncodedParts ? 'text-[#D97706]' : 'text-[#16A34A]'
                    }`}
                    aria-hidden="true"
                  />
                  <div>
                    <h3 className="font-display text-sm font-bold text-zinc-950 dark:text-white">
                      {lang === 'ar'
                        ? 'فحص تشفير الرابط والمسارات المشفرة والترميز المخفي'
                        : 'Encrypted URL, Encoded Paths & Payload Inspection'}
                    </h3>
                    <p className="text-[11px] text-zinc-600 dark:text-zinc-400">
                      {report.urlEncryptionIntel.summary[lang]}
                    </p>
                  </div>
                </div>
                <div dir="ltr" className="flex flex-wrap items-center gap-3 font-mono text-[11px] text-zinc-700 dark:text-zinc-300 tabular-nums">
                  <span>Paths: {report.urlEncryptionIntel.encodedPathSegmentCount}</span>
                  <span>Params: {report.urlEncryptionIntel.encodedQueryParamCount}</span>
                  <span>Double%25: {report.urlEncryptionIntel.doublePercentEncoded ? 'YES' : 'No'}</span>
                </div>
              </div>

              {report.urlEncryptionIntel.segments.length > 0 ? (
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                  {report.urlEncryptionIntel.segments.map((seg, idx) => (
                    <div
                      key={`${seg.location}-${seg.keyOrSegmentIndex}-${idx}`}
                      className="rounded-lg border border-[#E5E7EB] bg-white p-3.5 text-xs dark:border-[#242424] dark:bg-black space-y-2"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span
                          className={`font-mono text-[11px] font-bold ${
                            seg.containsSensitiveOrUrl ? 'text-[#EF233C]' : 'text-zinc-800 dark:text-zinc-200'
                          }`}
                        >
                          {seg.location === 'path_segment'
                            ? lang === 'ar'
                              ? `مسار (${seg.keyOrSegmentIndex})`
                              : `Path Segment ${seg.keyOrSegmentIndex}`
                            : seg.location === 'fragment'
                              ? lang === 'ar'
                                ? 'جزء الرابط (#Fragment)'
                                : 'URL #Fragment'
                              : lang === 'ar'
                                ? `معامل (${seg.keyOrSegmentIndex})`
                                : `Query Param (${seg.keyOrSegmentIndex})`}
                        </span>
                        <span dir="ltr" className="rounded border border-zinc-200 bg-zinc-50 px-2 py-0.5 font-mono text-[10px] font-bold uppercase text-zinc-700 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300">
                          {seg.technique.replace(/_/g, ' ')}
                          {seg.entropy !== undefined ? ` · ${seg.entropy}b` : ''}
                        </span>
                      </div>

                      <div className="space-y-1">
                        <p className="text-[10px] font-semibold text-zinc-500">
                          {lang === 'ar' ? 'القيمة المشفرة / المرمزة المرصودة:' : 'Raw Encoded / Encrypted Segment:'}
                        </p>
                        <p dir="ltr" className="break-all rounded bg-[#F7F7F7] px-2 py-1 font-mono text-[11px] text-zinc-900 dark:bg-[#111111] dark:text-zinc-200">
                          {seg.rawSample}
                        </p>
                      </div>

                      {seg.decodedPreview && (
                        <div className="space-y-1">
                          <p className="text-[10px] font-semibold text-[#16A34A]">
                            {lang === 'ar' ? 'المحتوى بعد فك التشفير/الترميز:' : 'Decoded Plaintext Preview:'}
                          </p>
                          <p dir="ltr" className="break-all rounded border border-emerald-500/30 bg-emerald-500/[0.06] px-2 py-1 font-mono text-[11px] font-semibold text-emerald-800 dark:text-emerald-300">
                            {seg.decodedPreview}
                          </p>
                        </div>
                      )}

                      <p className="text-[11px] leading-relaxed text-zinc-600 dark:text-zinc-400">
                        {seg.note[lang]}
                      </p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-zinc-600 dark:text-zinc-400">
                  {lang === 'ar'
                    ? 'جميع مسارات الرابط ومعاملاته مقروءة ولا توجد مقاطع مشفرة أو ترميز خبيث.'
                    : 'All URL path segments and query parameters are transparent with no encrypted/obfuscated components.'}
                </p>
              )}

              {report.urlEncryptionIntel.decodedSecretsDetected &&
                report.urlEncryptionIntel.decodedSecretsDetected.length > 0 && (
                  <div className="space-y-2 border-t border-[#E5E7EB] pt-3 dark:border-[#202020]">
                    <p className="text-xs font-bold text-[#EF233C]">
                      {lang === 'ar'
                        ? `مفاتيح أو معرفات مسربة مفكوكة من الرابط (${report.urlEncryptionIntel.decodedSecretsDetected.length})`
                        : `Decoded Embedded Credentials / Bot Secrets in URL (${report.urlEncryptionIntel.decodedSecretsDetected.length})`}
                    </p>
                    <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                      {report.urlEncryptionIntel.decodedSecretsDetected.map((sec, sIdx) => (
                        <div
                          key={`${sec.param}-${sec.kind}-${sIdx}`}
                          className="rounded-lg border border-[#EF233C]/35 bg-[#EF233C]/[0.04] p-2.5 text-xs dark:bg-[#140709]"
                        >
                          <div className="flex items-center justify-between gap-2 font-mono text-[11px]">
                            <span className="font-bold text-[#EF233C]">
                              ?{sec.param} · {sec.kind}
                            </span>
                            <span className="text-zinc-500">{sec.redactedPreview}</span>
                          </div>
                          <p className="mt-1 text-[11px] text-zinc-700 dark:text-zinc-300">{sec.note[lang]}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
            </div>
          )}

          {/* Target Passive XSS & DOM Sink Security Assessment */}
          {report.xssAssessment && (
            <div
              className={`lg:col-span-2 rounded-xl border p-5 space-y-4 ${
                report.xssAssessment.status === 'high_risk'
                  ? 'border-[#EF233C]/45 bg-[#EF233C]/[0.04] dark:bg-[#0D0D0D]'
                  : report.xssAssessment.status === 'potential_weakness'
                    ? 'border-amber-500/45 bg-amber-500/[0.04] dark:border-amber-500/35 dark:bg-[#0D0D0D]'
                    : 'border-[#E5E7EB] bg-white dark:border-[#202020] dark:bg-[#0D0D0D]'
              }`}
            >
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-200/70 pb-3 dark:border-[#202020]">
                <div className="flex items-center gap-2.5">
                  <ShieldCheck
                    className={`h-4 w-4 shrink-0 ${
                      report.xssAssessment.status === 'high_risk'
                        ? 'text-[#FF263F]'
                        : report.xssAssessment.status === 'potential_weakness'
                          ? 'text-[#D97706]'
                          : report.xssAssessment.status === 'safe'
                            ? 'text-[#16A34A]'
                            : 'text-zinc-500'
                    }`}
                    aria-hidden="true"
                  />
                  <div>
                    <h3 className="font-display text-sm font-bold text-zinc-950 dark:text-white">
                      {lang === 'ar'
                        ? 'فحص ثغرات XSS وسلامة DOM (فحص سلبي غير تخريبي)'
                        : 'Target XSS & DOM Sink Security Assessment (Passive Audit)'}
                    </h3>
                    <p className="text-[11px] text-zinc-600 dark:text-zinc-400">
                      {report.xssAssessment.summary[lang]}
                    </p>
                  </div>
                </div>
                <span
                  className={`rounded-md border px-2.5 py-1 text-[11px] font-bold ${
                    report.xssAssessment.status === 'high_risk'
                      ? 'border-[#EF233C]/40 bg-[#EF233C]/10 text-[#EF233C]'
                      : report.xssAssessment.status === 'potential_weakness'
                        ? 'border-amber-500/40 bg-amber-500/10 text-[#D97706]'
                        : report.xssAssessment.status === 'safe'
                          ? 'border-emerald-500/35 bg-emerald-500/10 text-[#16A34A]'
                          : 'border-zinc-300 bg-zinc-100 text-zinc-700 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300'
                  }`}
                >
                  {tXssStatus(report.xssAssessment.status, lang)}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <div className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-3 dark:border-[#202020] dark:bg-black">
                  <p className="text-[11px] text-zinc-500">{lang === 'ar' ? 'معاملات منعكسة غير معقّمة' : 'Unescaped Reflections'}</p>
                  <p className="mt-1 font-mono text-base font-bold text-zinc-950 dark:text-white tabular-nums">
                    {report.xssAssessment.reflectedParamsCount}
                  </p>
                </div>
                <div className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-3 dark:border-[#202020] dark:bg-black">
                  <p className="text-[11px] text-zinc-500">{lang === 'ar' ? 'منافذ DOM XSS الخطرة' : 'DOM XSS Sinks'}</p>
                  <p className="mt-1 font-mono text-base font-bold text-zinc-950 dark:text-white tabular-nums">
                    {report.xssAssessment.domSinkCount}
                  </p>
                </div>
                <div className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-3 dark:border-[#202020] dark:bg-black">
                  <p className="text-[11px] text-zinc-500">{lang === 'ar' ? 'سياسة CSP' : 'CSP Posture'}</p>
                  <p className="mt-1 font-mono text-sm font-bold uppercase text-zinc-950 dark:text-white">
                    {report.xssAssessment.cspStatus}
                  </p>
                </div>
                <div className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-3 dark:border-[#202020] dark:bg-black">
                  <p className="text-[11px] text-zinc-500">{lang === 'ar' ? 'كوكيز جلسة بدون HttpOnly' : 'Session Missing HttpOnly'}</p>
                  <p className="mt-1 font-mono text-sm font-bold text-zinc-950 dark:text-white">
                    {report.xssAssessment.httpOnlySessionCookiesMissing
                      ? lang === 'ar' ? 'نعم' : 'Yes'
                      : lang === 'ar' ? 'لا' : 'No'}
                  </p>
                </div>
              </div>

              {report.xssAssessment.indicators.length > 0 && (
                <div className="grid grid-cols-1 gap-2.5 md:grid-cols-2">
                  {report.xssAssessment.indicators.slice(0, 6).map((ind) => (
                    <div
                      key={ind.id}
                      className="rounded-lg border border-[#E5E7EB] bg-white p-3 text-xs dark:border-[#242424] dark:bg-black space-y-1.5"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span dir="ltr" className="font-mono text-[11px] font-bold text-zinc-900 dark:text-white">
                          {ind.parameterOrSink}
                        </span>
                        <span className="rounded border border-zinc-200 bg-zinc-50 px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase text-zinc-700 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300">
                          {tSeverity(ind.severity, lang)}
                        </span>
                      </div>
                      <p dir="ltr" className="font-mono text-[10.5px] text-zinc-500">
                        {ind.context}
                      </p>
                      <p className="text-[11px] leading-relaxed text-zinc-700 dark:text-zinc-300">
                        {ind.detail[lang]}
                      </p>
                      {ind.excerpt && (
                        <code dir="ltr" className="block break-all rounded bg-[#F7F7F7] px-2 py-1 font-mono text-[10.5px] text-zinc-800 dark:bg-[#111111] dark:text-zinc-200">
                          {ind.excerpt}
                        </code>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {report.xssAssessment.remediationGuidance.length > 0 && (
                <div className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-3 dark:border-[#202020] dark:bg-black space-y-1.5">
                  <p className="text-[11px] font-bold text-zinc-800 dark:text-zinc-200">
                    {lang === 'ar' ? 'إرشادات التحصين والوقاية من XSS:' : 'XSS Hardening & Remediation Guidance:'}
                  </p>
                  <ul className="space-y-1 text-[11px] text-zinc-600 dark:text-zinc-400">
                    {report.xssAssessment.remediationGuidance.map((guide, idx) => (
                      <li key={idx}>• {guide[lang]}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* Background JavaScript Data Collection & External Service Data Transmission */}
          {report.sourceIntel && (
            <div
              className={`lg:col-span-2 rounded-xl border p-5 space-y-5 ${
                report.sourceIntel.externalDataTransmissions?.some((t) => t.isHarmful)
                  ? 'border-[#EF233C]/45 bg-[#EF233C]/[0.04] dark:bg-[#0D0D0D]'
                  : 'border-[#E5E7EB] bg-white dark:border-[#202020] dark:bg-[#0D0D0D]'
              }`}
            >
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-200/70 pb-3 dark:border-[#202020]">
                <div className="flex items-center gap-2.5">
                  <Radio
                    className={`h-4 w-4 shrink-0 ${
                      report.sourceIntel.externalDataTransmissions?.some((t) => t.isHarmful)
                        ? 'text-[#FF263F]'
                        : report.sourceIntel.externalDataTransmissions?.some((t) => t.harmClassification === 'suspicious_tracking')
                          ? 'text-[#D97706]'
                          : 'text-[#16A34A]'
                    }`}
                    aria-hidden="true"
                  />
                  <div>
                    <h3 className="font-display text-sm font-bold text-zinc-950 dark:text-white">
                      {lang === 'ar'
                        ? 'تحليل جمع البيانات بالخلفية (JavaScript) ونوع البيانات المرسلة ومدى خطورتها'
                        : 'Background JS Data Collection, Payload Type & Harmfulness Audit'}
                    </h3>
                    <p className="text-[11px] text-zinc-600 dark:text-zinc-400">
                      {lang === 'ar'
                        ? 'تحديد نوع البيانات التي تُجمع وتُرسل لخدمات خارجية وتصنيفها: هل هي خبيثة وتضر أم إحصائيات غير ضارة'
                        : 'Classifies exact data types transmitted to external servers and verifies whether each transmission is malicious/harmful or benign'}
                    </p>
                  </div>
                </div>
                <div dir="ltr" className="flex items-center gap-3 font-mono text-[11px] font-semibold text-zinc-700 dark:text-zinc-300 tabular-nums">
                  <span>Collectors: {report.sourceIntel.backgroundDataCollection?.length ?? 0}</span>
                  <span>Endpoints: {report.sourceIntel.externalDataTransmissions?.length ?? 0}</span>
                  <span>
                    Harmful: {report.sourceIntel.externalDataTransmissions?.filter((t) => t.isHarmful).length ?? 0}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
                {/* Column A: Background JS Collectors */}
                <div className="space-y-3">
                  <div className="flex items-center gap-2 text-xs font-bold text-zinc-950 dark:text-white">
                    <Database
                      className={`h-3.5 w-3.5 ${
                        report.sourceIntel.backgroundDataCollection?.some(
                          (c) => c.riskLevel === 'high' || c.riskLevel === 'critical'
                        )
                          ? 'text-[#EF233C]'
                          : report.sourceIntel.backgroundDataCollection?.some((c) => c.transmittedExternally)
                            ? 'text-[#D97706]'
                            : 'text-[#16A34A]'
                      }`}
                      aria-hidden="true"
                    />
                    <span>
                      {lang === 'ar'
                        ? 'البيانات التي يتم جمعها في الخلفية عبر JavaScript'
                        : 'Background Data Collected by JavaScript'}
                    </span>
                  </div>

                  {report.sourceIntel.backgroundDataCollection && report.sourceIntel.backgroundDataCollection.length > 0 ? (
                    <div className="space-y-2.5">
                      {report.sourceIntel.backgroundDataCollection.map((col) => (
                        <div
                          key={col.id}
                          className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-3 text-xs dark:border-[#202020] dark:bg-black space-y-1.5"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <span className="font-bold text-zinc-950 dark:text-white">{col.title[lang]}</span>
                            <span
                              className={`font-mono text-[10px] font-bold uppercase ${
                                col.riskLevel === 'high' || col.riskLevel === 'critical'
                                  ? 'text-[#EF233C]'
                                  : col.riskLevel === 'medium' || col.riskLevel === 'low'
                                    ? 'text-[#D97706]'
                                    : 'text-[#16A34A]'
                              }`}
                            >
                              {tSeverity(col.riskLevel, lang)}
                            </span>
                          </div>
                          <p className="text-[11px] leading-relaxed text-zinc-700 dark:text-zinc-300">
                            {col.detail[lang]}
                          </p>
                          <p dir="ltr" className="font-mono text-[10px] text-zinc-600 dark:text-zinc-400">
                            APIs: {col.apisUsed.join(', ')} · Triggers: {col.triggers.join(', ')}
                            {col.consentState ? ` · Consent: ${col.consentState}` : ''}
                          </p>
                          {(col.sourceScript || col.sourceFunction || col.pipelineStage || col.destinationHost) && (
                            <p dir="ltr" className="font-mono text-[10px] text-zinc-500">
                              {col.sourceScript ? `Script: ${col.sourceScript}` : ''}
                              {col.sourceFunction ? ` · Fn: ${col.sourceFunction}` : ''}
                              {col.pipelineStage ? ` · Stage: ${col.pipelineStage}` : ''}
                              {col.transmittedExternally !== undefined
                                ? ` · External: ${col.transmittedExternally ? col.destinationHost || 'Yes' : 'Local Only'}`
                                : ''}
                            </p>
                          )}
                          {col.excerpt && (
                            <pre dir="ltr" className="overflow-x-auto rounded border border-zinc-200/80 bg-white px-2 py-1 font-mono text-[10px] text-zinc-800 dark:border-[#242424] dark:bg-[#080808] dark:text-zinc-300">
                              {col.excerpt}
                            </pre>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-3.5 text-xs text-zinc-600 dark:border-[#202020] dark:bg-black dark:text-zinc-400">
                      {lang === 'ar'
                        ? 'لم يتم رصد جمع بيانات خفي (كوكيز، حافظة، بصمة جهاز، أو تسجيل مفاتيح) في أكواد JavaScript المفحوصة.'
                        : 'No silent cookie, storage, keystroke, or fingerprint harvesting patterns detected in inspected JavaScript.'}
                    </div>
                  )}
                </div>

                {/* Column B: External Service Transmission Targets & Data Harmfulness Verdict */}
                <div className="space-y-3">
                  <div className="flex items-center gap-2 text-xs font-bold text-zinc-950 dark:text-white">
                    <ExternalLink
                      className={`h-3.5 w-3.5 ${
                        report.sourceIntel.externalDataTransmissions?.some((t) => t.isHarmful)
                          ? 'text-[#EF233C]'
                          : report.sourceIntel.externalDataTransmissions?.some(
                                (t) => t.harmClassification === 'suspicious_tracking'
                              )
                            ? 'text-[#D97706]'
                            : 'text-[#16A34A]'
                      }`}
                      aria-hidden="true"
                    />
                    <span>
                      {lang === 'ar'
                        ? 'الوجهات الخارجية المستلمة ونوع البيانات وتقييم الضرر'
                        : 'Outbound Endpoints, Transmitted Data Type & Harm Verdict'}
                    </span>
                  </div>

                  {report.sourceIntel.externalDataTransmissions && report.sourceIntel.externalDataTransmissions.length > 0 ? (
                    <div className="space-y-2.5 max-h-[28rem] overflow-y-auto pe-1">
                      {report.sourceIntel.externalDataTransmissions.map((tx, idx) => {
                        const dataTypeLabels: Record<TransmittedDataType, { en: string; ar: string }> = {
                          credentials: { en: 'Passwords / Credentials', ar: 'كلمات مرور / دخول' },
                          session_tokens: { en: 'Auth / Session Tokens', ar: 'رموز الجلسة والمصادقة' },
                          cookies: { en: 'Browser Cookies', ar: 'ملفات الكوكيز' },
                          financial_pii: { en: 'Financial / OTP / Card', ar: 'بيانات مالية / OTP' },
                          keystrokes_clipboard: { en: 'Keystrokes / Clipboard', ar: 'ضغطات المفاتيح / الحافظة' },
                          device_fingerprint: { en: 'Device Fingerprint', ar: 'بصمة الجهاز' },
                          analytics_metrics: { en: 'Analytics / UI Metrics', ar: 'إحصائيات التصفح' },
                          error_telemetry: { en: 'Error / Perf Telemetry', ar: 'تقارير الأخطاء والأداء' },
                          functional_state: { en: 'Functional App Data', ar: 'بيانات تشغيلية عادية' },
                          personal_pii: { en: 'Personal PII', ar: 'بيانات شخصية' },
                          api_keys: { en: 'API Keys / Secrets', ar: 'مفاتيح برمجية' },
                          form_inputs: { en: 'Form Inputs', ar: 'مدخلات نماذج' },
                          geolocation: { en: 'Geolocation', ar: 'الموقع الجغرافي' },
                          storage_data: { en: 'Web Storage Data', ar: 'بيانات التخزين المحلي' },
                          system_telemetry: { en: 'System Telemetry', ar: 'قياس بيئة المتصفح' },
                          unknown: { en: 'Unclassified Payload', ar: 'بيانات غير محددة' },
                        };

                        return (
                          <div
                            key={`${tx.method}-${tx.destinationUrl}-${idx}`}
                            className={`rounded-lg border p-3 text-xs space-y-2 ${
                              tx.isHarmful
                                ? 'border-[#EF233C]/45 bg-[#EF233C]/[0.05] dark:bg-[#140709]'
                                : tx.harmClassification === 'suspicious_tracking'
                                  ? 'border-amber-500/40 bg-amber-500/[0.04] dark:bg-black'
                                  : 'border-[#E5E7EB] bg-[#F7F7F7] dark:border-[#202020] dark:bg-black'
                            }`}
                          >
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <span dir="ltr" className="font-mono text-[11px] font-bold text-zinc-950 dark:text-white">
                                {tx.destinationHost}
                              </span>
                              <div className="flex flex-wrap items-center gap-1.5 font-mono text-[10px] font-bold">
                                <span className="rounded border border-zinc-300 bg-white px-1.5 py-0.5 uppercase text-zinc-700 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300">
                                  {tx.method}
                                </span>
                                {tx.destinationRole && (
                                  <span className="rounded border border-zinc-300 bg-white px-1.5 py-0.5 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-300">
                                    {tx.destinationRole}
                                  </span>
                                )}
                                <span
                                  className={`rounded px-1.5 py-0.5 ${
                                    tx.harmClassification === 'malicious_harmful'
                                      ? 'bg-[#EF233C]/15 text-[#EF233C]'
                                      : tx.harmClassification === 'suspicious_tracking'
                                        ? 'bg-amber-500/15 text-[#D97706] dark:text-[#FBBF24]'
                                        : tx.harmClassification === 'unverified_external'
                                          ? 'bg-sky-500/15 text-sky-700 dark:text-sky-300'
                                          : 'bg-emerald-500/15 text-[#16A34A]'
                                  }`}
                                >
                                  {tx.harmClassification === 'malicious_harmful'
                                    ? lang === 'ar'
                                      ? 'خبيثة وتضر (ضار)'
                                      : 'MALICIOUS / HARMFUL'
                                    : tx.harmClassification === 'suspicious_tracking'
                                      ? lang === 'ar'
                                        ? 'تتبع / انتهاك خصوصية'
                                        : 'TRACKING / PRIVACY'
                                      : tx.harmClassification === 'unverified_external'
                                        ? lang === 'ar'
                                          ? 'إرسال خارجي غير موثوق'
                                          : 'UNVERIFIED EXTERNAL'
                                        : lang === 'ar'
                                          ? 'سليمة وغير ضارة'
                                          : 'BENIGN / HARMLESS'}
                                </span>
                              </div>
                            </div>

                            <p
                              dir="ltr"
                              className={`break-all rounded bg-white px-2 py-1 font-mono text-[11px] dark:bg-[#080808] ${
                                tx.isHarmful || tx.harmClassification === 'malicious_harmful'
                                  ? 'text-[#EF233C]'
                                  : tx.harmClassification === 'suspicious_tracking'
                                    ? 'text-[#D97706] dark:text-[#FBBF24]'
                                    : tx.harmClassification === 'unverified_external'
                                      ? 'text-sky-700 dark:text-sky-300'
                                      : 'text-zinc-800 dark:text-zinc-200'
                              }`}
                            >
                              {tx.destinationUrl}
                            </p>

                            {tx.transmittedDataTypes && tx.transmittedDataTypes.length > 0 && (
                              <div className="flex flex-wrap items-center gap-1.5">
                                <span className="text-[10px] font-bold text-zinc-500">
                                  {lang === 'ar' ? 'نوع البيانات المرسلة:' : 'Data Type:'}
                                </span>
                                {tx.transmittedDataTypes.map((dt) => (
                                  <span
                                    key={dt}
                                    className="rounded border border-zinc-200 bg-white px-1.5 py-0.5 text-[10px] font-semibold text-zinc-800 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-200"
                                  >
                                    {dataTypeLabels[dt]?.[lang] || dt}
                                  </span>
                                ))}
                              </div>
                            )}

                            {tx.harmAssessment && (
                              <p
                                className={`text-[11px] font-medium leading-relaxed ${
                                  tx.isHarmful
                                    ? 'text-[#EF233C]'
                                    : tx.harmClassification === 'suspicious_tracking'
                                      ? 'text-[#D97706] dark:text-[#FBBF24]'
                                      : tx.harmClassification === 'unverified_external'
                                        ? 'text-sky-700 dark:text-sky-300'
                                        : 'text-emerald-700 dark:text-emerald-400'
                                }`}
                              >
                                {tx.harmAssessment[lang]}
                              </p>
                            )}

                            <p className="text-[11px] leading-relaxed text-zinc-700 dark:text-zinc-300">
                              {tx.detail[lang]}
                            </p>

                            {(tx.sourceScript || tx.sourceFunction || tx.trigger || tx.frequency || tx.consentState || tx.reliability) && (
                              <div dir="ltr" className="flex flex-wrap items-center gap-2 font-mono text-[10px] text-zinc-500">
                                {tx.sourceScript && <span>Script: {tx.sourceScript}</span>}
                                {tx.sourceFunction && <span>· Fn: {tx.sourceFunction}</span>}
                                {tx.trigger && <span>· Trigger: {tx.trigger}</span>}
                                {tx.frequency && <span>· Freq: {tx.frequency}</span>}
                                {tx.consentState && <span>· Consent: {tx.consentState}</span>}
                                {tx.reliability && <span>· Conf: {tx.reliability}</span>}
                              </div>
                            )}

                            {tx.purpose && (
                              <p className="text-[10.5px] text-zinc-600 dark:text-zinc-400">
                                <span className="font-semibold">{lang === 'ar' ? 'الغرض المرجح: ' : 'Likely Purpose: '}</span>
                                {tx.purpose[lang]}
                              </p>
                            )}

                            {(tx.obfuscatedUrl || tx.pairedWithBackgroundCollection) && (
                              <div className="flex flex-wrap gap-2 pt-0.5 font-mono text-[10px] font-semibold">
                                {tx.obfuscatedUrl && (
                                  <span className="text-[#D97706] dark:text-[#FBBF24]">
                                    {lang === 'ar'
                                      ? `رابط مموه داخل JS (${tx.decodedFrom || 'encoded'})`
                                      : `Obfuscated in JS (${tx.decodedFrom || 'encoded'})`}
                                  </span>
                                )}
                                {tx.pairedWithBackgroundCollection && tx.isThirdParty && (
                                  <span className="text-[#EF233C]">
                                    {lang === 'ar'
                                      ? '· مقترن بجمع بيانات في الخلفية'
                                      : '· Paired with background data collection'}
                                  </span>
                                )}
                              </div>
                            )}

                            {(tx.payloadEvidence || tx.excerpt) && (
                              <p dir="ltr" className="truncate font-mono text-[10px] text-zinc-500">
                                Payload/Code: {tx.payloadEvidence || tx.excerpt}
                              </p>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <div className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-3.5 text-xs text-zinc-600 dark:border-[#202020] dark:bg-black dark:text-zinc-400">
                      {lang === 'ar'
                        ? 'لم تُرصد استدعاءات إرسال صامتة إلى خدمات خارجية (fetch / XHR / sendBeacon / WebSocket) في أكواد الصفحة.'
                        : 'No outbound background transmission calls (fetch / XHR / sendBeacon / WebSocket) detected in inspected scripts.'}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Cookie Security, Consent Transparency & 8-Category Classification Audit */}
          {report.sourceIntel?.cookieAudit && (
            <div
              className={`lg:col-span-2 rounded-xl border p-5 space-y-4 ${
                report.sourceIntel.cookieAudit.hasMaliciousCookieBehavior
                  ? 'border-[#EF233C]/45 bg-[#EF233C]/[0.04] dark:bg-[#0D0D0D]'
                  : report.sourceIntel.cookieAudit.consentVerification?.privacyViolationDetected ||
                      report.sourceIntel.cookieAudit.setsAdvertisingCookies
                    ? 'border-amber-500/40 bg-amber-500/[0.03] dark:bg-[#0D0D0D]'
                    : 'border-[#E5E7EB] bg-white dark:border-[#202020] dark:bg-[#0D0D0D]'
              }`}
            >
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-200/70 pb-3 dark:border-[#202020]">
                <div className="flex items-center gap-2.5">
                  <Cookie
                    className={`h-4 w-4 shrink-0 ${
                      report.sourceIntel.cookieAudit.hasMaliciousCookieBehavior
                        ? 'text-[#EF233C]'
                        : report.sourceIntel.cookieAudit.consentVerification?.privacyViolationDetected ||
                            report.sourceIntel.cookieAudit.setsAdvertisingCookies
                          ? 'text-[#D97706]'
                          : 'text-[#16A34A]'
                    }`}
                    aria-hidden="true"
                  />
                  <div>
                    <h3 className="font-display text-sm font-bold text-zinc-950 dark:text-white">
                      {lang === 'ar'
                        ? 'فحص ملفات تعريف الارتباط (Cookies): التصنيف الثماني، الموافقة، والسلوك الحقيقي'
                        : 'Cookie Intelligence Audit: 8-Category Classification, Consent & AST Behavior'}
                    </h3>
                    <p className="text-[11px] text-zinc-600 dark:text-zinc-400">
                      {report.sourceIntel.cookieAudit.summary[lang]}
                    </p>
                  </div>
                </div>
                <div dir="ltr" className="flex flex-wrap items-center gap-3 font-mono text-[11px] font-semibold text-zinc-700 dark:text-zinc-300 tabular-nums">
                  <span>Total: {report.sourceIntel.cookieAudit.totalCookiesInspected}</span>
                  <span>Essential/Func: {report.sourceIntel.cookieAudit.essentialFunctionalCount}</span>
                  {(report.sourceIntel.cookieAudit.analyticsCookieCount ?? 0) > 0 && (
                    <span>Analytics: {report.sourceIntel.cookieAudit.analyticsCookieCount}</span>
                  )}
                  <span>Ads: {report.sourceIntel.cookieAudit.adCookieCount}</span>
                  <span className={report.sourceIntel.cookieAudit.hasMaliciousCookieBehavior ? 'text-[#EF233C]' : ''}>
                    Malicious: {report.sourceIntel.cookieAudit.maliciousCookieCount}
                  </span>
                </div>
              </div>

              {/* Privacy / Consent Violation Notice (never treated as Malicious Malware) */}
              {report.sourceIntel.cookieAudit.consentVerification?.privacyViolationDetected &&
                !report.sourceIntel.cookieAudit.hasMaliciousCookieBehavior && (
                  <div className="flex items-start gap-2.5 rounded-lg border border-amber-500/40 bg-amber-500/[0.08] p-3 text-xs text-amber-900 dark:border-amber-500/35 dark:bg-amber-500/[0.12] dark:text-amber-200">
                    <AlertTriangle className="h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400 mt-0.5" />
                    <div>
                      <p className="font-bold">
                        {lang === 'ar'
                          ? 'ملاحظة خصوصية / امتثال موافقة (Privacy Violation — غير مصنف كبرمجية خبيثة)'
                          : 'Privacy / Consent Compliance Notice (Classified as Privacy Violation, NOT Malicious)'}
                      </p>
                      <p className="mt-0.5 text-[11px] leading-relaxed opacity-90">
                        {report.sourceIntel.cookieAudit.consentVerification.details[lang]}
                      </p>
                    </div>
                  </div>
                )}

              {/* User Consent & Transparency Banner */}
              {report.sourceIntel.cookieAudit.hasConsentNoticeOrBanner && (
                <div className="flex items-start gap-2.5 rounded-lg border border-emerald-500/30 bg-emerald-500/[0.08] p-3 text-xs text-emerald-800 dark:border-emerald-500/30 dark:bg-emerald-500/[0.12] dark:text-emerald-300">
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400 mt-0.5" />
                  <div>
                    <p className="font-bold">
                      {lang === 'ar'
                        ? 'طلب إذن وموافقة معلنة من المستخدم (مصرّح بها — بدون أي خصم من التقييم)'
                        : 'User Consent Requested & Declared (Authorized — Zero rating penalty)'}
                    </p>
                    <p className="mt-0.5 text-[11px] leading-relaxed opacity-90">
                      {report.sourceIntel.cookieAudit.consentNoticeDetails?.[lang] ||
                        (lang === 'ar'
                          ? 'يعلن الموقع بوضوح عن ملفات تعريف الارتباط التشغيلية اللازمة لعمله ويطلب موافقة المستخدم؛ ولا تُحسب هذه الكوكيز المشروعة ضمن تقييم المخاطر.'
                          : 'The website transparently declares necessary functional cookies and requests user consent; these authorized cookies are not penalized in the risk assessment.')}
                    </p>
                  </div>
                </div>
              )}

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <div className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-3 text-xs dark:border-[#202020] dark:bg-black">
                  <p className="text-[11px] text-zinc-500">
                    {lang === 'ar' ? 'آلية الموافقة والرفض' : 'Consent & Reject Controls'}
                  </p>
                  <p
                    className={`mt-1 font-bold ${
                      report.sourceIntel.cookieAudit.hasConsentNoticeOrBanner
                        ? 'text-[#16A34A]'
                        : 'text-zinc-600 dark:text-zinc-400'
                    }`}
                  >
                    {report.sourceIntel.cookieAudit.hasConsentNoticeOrBanner
                      ? lang === 'ar'
                        ? `نعم${report.sourceIntel.cookieAudit.consentVerification?.hasRejectOrManageOption ? ' (يتيح الرفض/الإدارة)' : ''}`
                        : `Declared${report.sourceIntel.cookieAudit.consentVerification?.hasRejectOrManageOption ? ' (Reject/Manage UI)' : ''}`
                      : lang === 'ar'
                        ? 'تشغيلية تلقائية فقط'
                        : 'Essential only (no banner)'}
                  </p>
                </div>

                <div className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-3 text-xs dark:border-[#202020] dark:bg-black">
                  <p className="text-[11px] text-zinc-500">
                    {lang === 'ar' ? 'الامتثال السلوكي قبل الموافقة' : 'Pre-Consent Behavior'}
                  </p>
                  <p
                    className={`mt-1 font-bold ${
                      report.sourceIntel.cookieAudit.consentVerification?.behavioralCompliance === 'undeclared_tracking_pre_consent'
                        ? 'text-[#D97706] dark:text-[#FBBF24]'
                        : 'text-[#16A34A]'
                    }`}
                  >
                    {report.sourceIntel.cookieAudit.consentVerification?.behavioralCompliance === 'undeclared_tracking_pre_consent'
                      ? lang === 'ar'
                        ? 'تتبع قبل الموافقة (انتهاك خصوصية)'
                        : 'Tracking pre-consent (Privacy)'
                      : report.sourceIntel.cookieAudit.consentVerification?.behavioralCompliance === 'compliant'
                        ? lang === 'ar'
                          ? 'متوافق ومنضبط'
                          : 'Consent compliant'
                        : lang === 'ar'
                          ? 'ضرورية للتشغيل فقط'
                          : 'Essential cookies only'}
                  </p>
                </div>

                <div className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-3 text-xs dark:border-[#202020] dark:bg-black">
                  <p className="text-[11px] text-zinc-500">
                    {lang === 'ar' ? 'كوكيز الإعلانات والتحليلات' : 'Ads & Analytics Cookies'}
                  </p>
                  <p
                    className={`mt-1 font-bold ${
                      report.sourceIntel.cookieAudit.setsAdvertisingCookies ? 'text-[#D97706] dark:text-[#FBBF24]' : 'text-[#16A34A]'
                    }`}
                  >
                    {report.sourceIntel.cookieAudit.setsAdvertisingCookies
                      ? lang === 'ar'
                        ? `${report.sourceIntel.cookieAudit.adCookieCount} إعلاني · ${report.sourceIntel.cookieAudit.analyticsCookieCount ?? 0} تحليلي`
                        : `${report.sourceIntel.cookieAudit.adCookieCount} ad · ${report.sourceIntel.cookieAudit.analyticsCookieCount ?? 0} analytics`
                      : (report.sourceIntel.cookieAudit.analyticsCookieCount ?? 0) > 0
                        ? lang === 'ar'
                          ? `تحليلات فقط (${report.sourceIntel.cookieAudit.analyticsCookieCount})`
                          : `Analytics only (${report.sourceIntel.cookieAudit.analyticsCookieCount})`
                        : lang === 'ar'
                          ? 'كوكيز تشغيلية فقط'
                          : 'Essential/functional only'}
                  </p>
                </div>

                <div className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-3 text-xs dark:border-[#202020] dark:bg-black">
                  <p className="text-[11px] text-zinc-500">
                    {lang === 'ar' ? 'هل يوجد استغلال خبيث أو سرقة؟' : 'Confirmed Cookie Theft / Abuse?'}
                  </p>
                  <p
                    className={`mt-1 font-bold ${
                      report.sourceIntel.cookieAudit.hasMaliciousCookieBehavior ? 'text-[#EF233C]' : 'text-[#16A34A]'
                    }`}
                  >
                    {report.sourceIntel.cookieAudit.hasMaliciousCookieBehavior
                      ? lang === 'ar'
                        ? `نعم — ${report.sourceIntel.cookieAudit.maliciousCookieCount} سلوك ضار`
                        : `Yes — ${report.sourceIntel.cookieAudit.maliciousCookieCount} malicious item(s)`
                      : lang === 'ar'
                        ? 'لا — آمن بدون سرقة أو حقن'
                        : 'No theft or stuffing detected'}
                  </p>
                </div>
              </div>

              {report.sourceIntel.cookieAudit.cookiesDetected.length > 0 && (
                <div className="grid grid-cols-1 gap-2.5 md:grid-cols-2 max-h-80 overflow-y-auto pe-1">
                  {report.sourceIntel.cookieAudit.cookiesDetected.map((ck, idx) => {
                    const isAdOrWarn =
                      ck.category === 'advertising' ||
                      ck.category === 'suspicious' ||
                      ck.category === 'third_party';
                    const isAnalyticsOrSec =
                      ck.category === 'analytics' || ck.category === 'security_cookie';

                    return (
                      <div
                        key={`${ck.source}-${ck.name}-${idx}`}
                        className={`rounded-lg border p-3 text-xs space-y-1.5 ${
                          ck.isMaliciousOrHarmful || ck.category === 'malicious'
                            ? 'border-[#EF233C]/45 bg-[#EF233C]/[0.05] dark:bg-[#140709]'
                            : isAdOrWarn
                              ? 'border-amber-500/35 bg-amber-500/[0.04] dark:bg-black'
                              : 'border-[#E5E7EB] bg-[#F7F7F7] dark:border-[#202020] dark:bg-black'
                        }`}
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex flex-wrap items-center gap-1.5">
                            <span dir="ltr" className="font-mono font-bold text-zinc-950 dark:text-white">
                              {ck.name}
                            </span>
                            {ck.isEssentialForSite && (
                              <span className="rounded bg-emerald-500/10 px-1 py-0.5 text-[9px] font-semibold text-emerald-700 dark:text-emerald-400">
                                {lang === 'ar' ? 'ضروري' : 'Necessary'}
                              </span>
                            )}
                            {ck.party && (
                              <span className="rounded bg-zinc-200/70 px-1 py-0.5 font-mono text-[9px] text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
                                {ck.party === 'third_party' ? '3P' : '1P'}
                              </span>
                            )}
                            {ck.persistence && (
                              <span className="rounded bg-zinc-200/70 px-1 py-0.5 font-mono text-[9px] text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300">
                                {ck.persistence}
                              </span>
                            )}
                          </div>
                          <span
                            className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-bold uppercase ${
                              ck.isMaliciousOrHarmful || ck.category === 'malicious'
                                ? 'bg-[#EF233C]/15 text-[#EF233C]'
                                : isAdOrWarn
                                  ? 'bg-amber-500/15 text-[#D97706] dark:text-[#FBBF24]'
                                  : isAnalyticsOrSec
                                    ? 'bg-sky-500/15 text-[#0284C7] dark:text-[#38BDF8]'
                                    : 'bg-emerald-500/15 text-[#16A34A]'
                            }`}
                          >
                            {tCookieCategory(ck.category, lang)}
                          </span>
                        </div>

                        <div dir="ltr" className="flex flex-wrap items-center gap-2 font-mono text-[10px] text-zinc-500">
                          <span>
                            {ck.source === 'http_set_cookie'
                              ? 'HTTP Set-Cookie'
                              : ck.source === 'js_cookie_write'
                                ? 'JS Write'
                                : 'JS Read'}
                          </span>
                          {ck.domainOrVendor && <span>· {ck.domainOrVendor}</span>}
                          {ck.securityFlags && (
                            <span>
                              · HttpOnly:{ck.securityFlags.httpOnly ? 'Y' : 'N'} · Secure:{ck.securityFlags.secure ? 'Y' : 'N'}
                              {ck.securityFlags.sameSite ? ` · SameSite:${ck.securityFlags.sameSite}` : ''}
                            </span>
                          )}
                          {ck.astOperations && ck.astOperations.length > 0 && (
                            <span>· Ops: {ck.astOperations.join(', ')}</span>
                          )}
                        </div>

                        <p className="text-[11px] leading-relaxed text-zinc-700 dark:text-zinc-300">
                          {ck.detail[lang]}
                        </p>

                        {ck.excerpt && (
                          <p dir="ltr" className="truncate font-mono text-[10px] text-zinc-500">
                            {ck.excerpt}
                          </p>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* Advertising Intelligence, Malvertising & Background Workers */}
          {(report.sourceIntel?.advertisingIntel || report.sourceIntel?.workersDetected) && (
            <div className="lg:col-span-2 grid grid-cols-1 gap-5 lg:grid-cols-2">
              {report.sourceIntel.advertisingIntel && (
                <div
                  className={`rounded-xl border p-5 space-y-3 ${
                    report.sourceIntel.advertisingIntel.status === 'malicious_advertising'
                      ? 'border-[#EF233C]/45 bg-[#EF233C]/[0.04] dark:bg-[#0D0D0D]'
                      : report.sourceIntel.advertisingIntel.status === 'suspicious_advertising' ||
                          report.sourceIntel.advertisingIntel.status === 'undeclared_tracking'
                        ? 'border-amber-500/40 bg-amber-500/[0.03] dark:bg-[#0D0D0D]'
                        : 'border-[#E5E7EB] bg-white dark:border-[#202020] dark:bg-[#0D0D0D]'
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-200/70 pb-3 dark:border-[#202020]">
                    <div className="flex items-center gap-2">
                      <Megaphone
                        className={`h-4 w-4 shrink-0 ${
                          report.sourceIntel.advertisingIntel.status === 'malicious_advertising'
                            ? 'text-[#EF233C]'
                            : report.sourceIntel.advertisingIntel.status === 'suspicious_advertising' ||
                                report.sourceIntel.advertisingIntel.status === 'undeclared_tracking'
                              ? 'text-[#D97706]'
                              : 'text-[#16A34A]'
                        }`}
                        aria-hidden="true"
                      />
                      <h3 className="font-display text-sm font-bold text-zinc-950 dark:text-white">
                        {lang === 'ar'
                          ? 'تحليل الإعلانات والتتبع (Advertising Intelligence)'
                          : 'Advertising & Tracking Intelligence'}
                      </h3>
                    </div>
                    <span
                      className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold ${
                        report.sourceIntel.advertisingIntel.status === 'malicious_advertising'
                          ? 'bg-[#EF233C]/15 text-[#EF233C]'
                          : report.sourceIntel.advertisingIntel.status === 'suspicious_advertising' ||
                              report.sourceIntel.advertisingIntel.status === 'undeclared_tracking'
                            ? 'bg-amber-500/15 text-[#D97706] dark:text-[#FBBF24]'
                            : 'bg-emerald-500/15 text-[#16A34A]'
                      }`}
                    >
                      {tAdIntelState(report.sourceIntel.advertisingIntel.status, lang)}
                    </span>
                  </div>

                  <p className="text-xs leading-relaxed text-zinc-700 dark:text-zinc-300">
                    {report.sourceIntel.advertisingIntel.summary[lang]}
                  </p>

                  <div className="space-y-2 text-[11px]">
                    <div className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-2.5 dark:border-[#202020] dark:bg-black">
                      <span className="font-semibold text-zinc-900 dark:text-white">
                        {lang === 'ar' ? 'فصل مسؤولية الموقع الأول:' : 'First-Party vs Ad Network Separation:'}
                      </span>
                      <p className="mt-0.5 text-zinc-600 dark:text-zinc-400">
                        {report.sourceIntel.advertisingIntel.firstPartyResponsibilityNote[lang]}
                      </p>
                      {report.sourceIntel.advertisingIntel.thirdPartyAdResponsibilityNote && (
                        <p className="mt-1 text-zinc-600 dark:text-zinc-400">
                          {report.sourceIntel.advertisingIntel.thirdPartyAdResponsibilityNote[lang]}
                        </p>
                      )}
                    </div>

                    {(report.sourceIntel.advertisingIntel.adNetworksDetected.length > 0 ||
                      report.sourceIntel.advertisingIntel.analyticsPlatformsDetected.length > 0) && (
                      <div dir="ltr" className="flex flex-wrap gap-1.5 font-mono text-[10px]">
                        {report.sourceIntel.advertisingIntel.adNetworksDetected.map((n) => (
                          <span
                            key={`ad-${n}`}
                            className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-amber-800 dark:text-amber-300"
                          >
                            AdNet: {n}
                          </span>
                        ))}
                        {report.sourceIntel.advertisingIntel.analyticsPlatformsDetected.map((a) => (
                          <span
                            key={`an-${a}`}
                            className="rounded border border-sky-500/30 bg-sky-500/10 px-2 py-0.5 text-sky-800 dark:text-sky-300"
                          >
                            Analytics: {a}
                          </span>
                        ))}
                      </div>
                    )}

                    {report.sourceIntel.advertisingIntel.malvertisingIndicators.length > 0 && (
                      <p dir="ltr" className="font-mono text-[10.5px] font-semibold text-[#EF233C]">
                        Malvertising: {report.sourceIntel.advertisingIntel.malvertisingIndicators.join(' · ')}
                      </p>
                    )}

                    {report.sourceIntel.advertisingIntel.privacyViolations.length > 0 && (
                      <p dir="ltr" className="font-mono text-[10.5px] font-semibold text-[#D97706] dark:text-[#FBBF24]">
                        Privacy Notices: {report.sourceIntel.advertisingIntel.privacyViolations.join(' · ')}
                      </p>
                    )}
                  </div>
                </div>
              )}

              {report.sourceIntel.workersDetected && (
                <div
                  className={`rounded-xl border p-5 space-y-3 ${
                    report.sourceIntel.workersDetected.isMaliciousOrSuspicious
                      ? 'border-[#EF233C]/45 bg-[#EF233C]/[0.04] dark:bg-[#0D0D0D]'
                      : 'border-[#E5E7EB] bg-white dark:border-[#202020] dark:bg-[#0D0D0D]'
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-zinc-200/70 pb-3 dark:border-[#202020]">
                    <div className="flex items-center gap-2">
                      <Cpu
                        className={`h-4 w-4 shrink-0 ${
                          report.sourceIntel.workersDetected.isMaliciousOrSuspicious
                            ? 'text-[#EF233C]'
                            : 'text-[#16A34A]'
                        }`}
                        aria-hidden="true"
                      />
                      <h3 className="font-display text-sm font-bold text-zinc-950 dark:text-white">
                        {lang === 'ar'
                          ? 'فحص Service Workers و Web Workers'
                          : 'Background Service Workers & Web Workers'}
                      </h3>
                    </div>
                    <span
                      className={`font-mono text-[10px] font-bold ${
                        report.sourceIntel.workersDetected.isMaliciousOrSuspicious
                          ? 'text-[#EF233C]'
                          : 'text-[#16A34A]'
                      }`}
                    >
                      {report.sourceIntel.workersDetected.isMaliciousOrSuspicious
                        ? lang === 'ar' ? 'مرصود سلوك مشبوه' : 'SUSPICIOUS WORKER'
                        : report.sourceIntel.workersDetected.hasServiceWorker ||
                            report.sourceIntel.workersDetected.hasWebWorker
                          ? lang === 'ar' ? 'سليم / قياسي' : 'BENIGN / STANDARD'
                          : lang === 'ar' ? 'لا يوجد' : 'NONE'}
                    </span>
                  </div>

                  <p className="text-xs leading-relaxed text-zinc-700 dark:text-zinc-300">
                    {report.sourceIntel.workersDetected.summary[lang]}
                  </p>

                  {(report.sourceIntel.workersDetected.serviceWorkerUrls.length > 0 ||
                    report.sourceIntel.workersDetected.webWorkerUrls.length > 0) && (
                    <div dir="ltr" className="space-y-1.5 font-mono text-[10.5px] text-zinc-600 dark:text-zinc-400">
                      {report.sourceIntel.workersDetected.serviceWorkerUrls.map((u) => (
                        <div key={`sw-${u}`} className="truncate rounded bg-[#F7F7F7] px-2 py-1 dark:bg-black">
                          SW: {u}
                        </div>
                      ))}
                      {report.sourceIntel.workersDetected.webWorkerUrls.map((u) => (
                        <div key={`ww-${u}`} className="truncate rounded bg-[#F7F7F7] px-2 py-1 dark:bg-black">
                          WW: {u}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Discovered Subdomains & Live DNS Resolution */}
          {report.sourceIntel && (
            <div className="rounded-xl border border-[#E5E7EB] bg-white p-5 dark:border-[#202020] dark:bg-[#0D0D0D] space-y-4">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2.5">
                  <CyberSticker type="subdomain_tree" size={34} interactive={false} />
                  <div>
                    <h3 className="font-display text-sm font-bold text-zinc-950 dark:text-white">
                      {lang === 'en'
                        ? 'Discovered Site Subdomains & Live DNS'
                        : 'النطاقات الفرعية المكتشفة وحل DNS المباشر'}
                    </h3>
                    <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
                      {lang === 'en'
                        ? 'Same-brand hosts extracted from HTML, JS, CSS & verified against public DNS'
                        : 'نطاقات فرعية مستخرجة من السورس والروابط مع التحقق المباشر من IP و CNAME'}
                    </p>
                  </div>
                </div>
                <span className="font-mono text-xs font-bold text-[#FF263F] tabular-nums">
                  {report.sourceIntel.discoveredSubdomains?.length ?? 0}
                </span>
              </div>

              <SubdomainDnsTopologyVisual lang={lang} />

              {report.sourceIntel.discoveredSubdomains && report.sourceIntel.discoveredSubdomains.length > 0 ? (
                <div className="max-h-72 space-y-2 overflow-y-auto pe-1">
                  {report.sourceIntel.discoveredSubdomains.map((sub) => (
                    <div
                      key={sub.host}
                      className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-3 text-xs dark:border-[#202020] dark:bg-black"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span dir="ltr" className="break-all font-mono font-bold text-zinc-950 dark:text-white">
                          {sub.host}
                        </span>
                        <span
                          className={`font-mono text-[10px] font-bold uppercase ${
                            sub.suspiciousRole ? 'text-[#D97706]' : 'text-[#0284C7] dark:text-[#38BDF8]'
                          }`}
                        >
                          {sub.role.replace('_', ' ')}
                        </span>
                      </div>
                      <p dir="ltr" className="mt-1 font-mono text-[11px] text-zinc-600 dark:text-zinc-400">
                        Sources: {sub.sources.join(', ')}
                        {sub.resolvedIps && sub.resolvedIps.length > 0
                          ? ` · IPs: ${sub.resolvedIps.join(', ')}`
                          : ''}
                        {sub.cnameChain && sub.cnameChain.length > 0
                          ? ` · CNAME: ${sub.cnameChain.join(' -> ')}`
                          : ''}
                      </p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-zinc-500 dark:text-zinc-400">
                  {lang === 'en'
                    ? 'All extracted references remain strictly on the primary inspected hostname without auxiliary subdomains.'
                    : 'جميع الإشارات المستخرجة تقتصر على النطاق الأساسي نفسه دون نطاقات فرعية مساندة.'}
                </p>
              )}
            </div>
          )}
        </div>

        {/* External Threat Intelligence Feeds */}
        <div className="overflow-hidden rounded-xl border border-[#E5E7EB] bg-white p-5 dark:border-[#202020] dark:bg-[#0D0D0D]">
          <h3 className="font-display text-sm font-bold text-zinc-950 dark:text-white">
            {UI_COPY.report.threatFeeds[lang]}
          </h3>
          <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {report.threatProviders.map((prov) => (
              <div
                key={prov.providerId}
                className="min-w-0 overflow-hidden rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-3.5 dark:border-[#202020] dark:bg-black"
              >
                <div className="flex min-w-0 flex-wrap items-center justify-between gap-2">
                  <span className="min-w-0 break-words text-xs font-bold text-zinc-950 dark:text-white">
                    {prov.providerName}
                  </span>
                  <span
                    className={`shrink-0 font-mono text-[11px] font-semibold ${
                      prov.status === 'flagged'
                        ? 'text-[#EF233C]'
                        : prov.status === 'suspicious'
                          ? 'text-[#F59E0B]'
                          : prov.status === 'clean'
                            ? 'text-[#16A34A]'
                            : 'text-zinc-500 dark:text-zinc-400'
                    }`}
                  >
                    {tOperationalState(prov.operationalState, lang)} · {prov.status}
                  </span>
                </div>
                <p className="mt-1.5 break-words text-xs text-zinc-600 dark:text-zinc-400">
                  {prov.verdictDetail[lang]}
                </p>
                {prov.engineStats && (
                  <p dir="ltr" className="mt-1.5 break-words font-mono text-[11px] text-zinc-600 dark:text-zinc-400 tabular-nums">
                    Malicious: {prov.engineStats.malicious} · Suspicious: {prov.engineStats.suspicious} · Harmless: {prov.engineStats.harmless}
                  </p>
                )}
                {prov.inspectedTargets && prov.inspectedTargets.length > 0 && (
                  <p dir="ltr" className="mt-1 truncate font-mono text-[10px] text-zinc-500">
                    {prov.matchScope ? `Scope: ${prov.matchScope} · ` : ''}
                    {prov.inspectedTargets.join(' · ')}
                  </p>
                )}
                {safeExternalHref(prov.referenceUrl) && (
                  <a
                    href={safeExternalHref(prov.referenceUrl)}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="mt-2 inline-flex items-center gap-1 text-[11px] font-medium text-[#FF263F] hover:underline"
                  >
                    <span>{lang === 'en' ? 'View Provider Reference' : 'عرض المرجع لدى المزود'}</span>
                    <ExternalLink className="h-3 w-3" aria-hidden="true" />
                  </a>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Detailed Findings Table */}
      <div
        id="findings-table"
        className="rounded-xl border border-[#E5E7EB] bg-white dark:border-[#202020] dark:bg-[#0D0D0D]"
      >
        <div className="flex flex-col gap-3 border-b border-[#E5E7EB] p-5 dark:border-[#202020] lg:flex-row lg:items-center lg:justify-between">
          <h2 className="font-display text-lg font-bold text-zinc-950 dark:text-white">
            {UI_COPY.report.table.title[lang]} ({filteredFindings.length})
          </h2>

          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search
                className={`pointer-events-none absolute top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-400 ${
                  lang === 'ar' ? 'right-3' : 'left-3'
                }`}
                aria-hidden="true"
              />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder={UI_COPY.report.table.searchPlaceholder[lang]}
                className={`h-9 w-56 rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] text-xs text-zinc-900 focus:border-[#FF263F] focus:outline-none dark:border-[#202020] dark:bg-black dark:text-white ${
                  lang === 'ar' ? 'pr-8 pl-3' : 'pl-8 pr-3'
                }`}
              />
            </div>

            <select
              aria-label={UI_COPY.report.table.allStatuses[lang]}
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value as CheckStatus | 'all')}
              className="h-9 rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] px-2.5 text-xs text-zinc-800 dark:border-[#202020] dark:bg-black dark:text-zinc-200"
            >
              <option value="all">{UI_COPY.report.table.allStatuses[lang]}</option>
              <option value="failed">{tStatus('failed', lang)}</option>
              <option value="warning">{tStatus('warning', lang)}</option>
              <option value="pass">{tStatus('pass', lang)}</option>
              <option value="unknown">{tStatus('unknown', lang)}</option>
            </select>

            <select
              aria-label={UI_COPY.report.table.allSections[lang]}
              value={sectionFilter}
              onChange={(e) => setSectionFilter(e.target.value as TechnicalSectionId | 'all')}
              className="h-9 rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] px-2.5 text-xs text-zinc-800 dark:border-[#202020] dark:bg-black dark:text-zinc-200"
            >
              <option value="all">{UI_COPY.report.table.allSections[lang]}</option>
              {report.sections.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.title[lang]}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-start text-xs">
            <thead className="border-b border-[#E5E7EB] bg-[#F7F7F7] text-zinc-600 dark:border-[#202020] dark:bg-black dark:text-zinc-400">
              <tr>
                <th className="px-4 py-3 text-start">
                  <button
                    type="button"
                    onClick={() => handleSort('test')}
                    className="inline-flex items-center gap-1 font-semibold hover:text-[#FF263F]"
                  >
                    <span>{UI_COPY.report.table.colTest[lang]}</span>
                    <ArrowDownUp className="h-3 w-3" />
                  </button>
                </th>
                <th className="px-4 py-3 text-start font-semibold">
                  {UI_COPY.report.table.colResult[lang]}
                </th>
                <th className="px-4 py-3 text-start">
                  <button
                    type="button"
                    onClick={() => handleSort('status')}
                    className="inline-flex items-center gap-1 font-semibold hover:text-[#FF263F]"
                  >
                    <span>{UI_COPY.report.table.colStatus[lang]}</span>
                    <ArrowDownUp className="h-3 w-3" />
                  </button>
                </th>
                <th className="px-4 py-3 text-start">
                  <button
                    type="button"
                    onClick={() => handleSort('severity')}
                    className="inline-flex items-center gap-1 font-semibold hover:text-[#FF263F]"
                  >
                    <span>{UI_COPY.report.table.colSeverity[lang]}</span>
                    <ArrowDownUp className="h-3 w-3" />
                  </button>
                </th>
                <th className="px-4 py-3 text-start font-semibold">
                  {UI_COPY.report.table.colSource[lang]}
                </th>
                <th className="px-4 py-3 text-end font-semibold">
                  {UI_COPY.report.table.expandDetails[lang]}
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#E5E7EB] dark:divide-[#202020]">
              {filteredFindings.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-zinc-500">
                    {UI_COPY.report.table.noMatches[lang]}
                  </td>
                </tr>
              ) : (
                filteredFindings.map((f: CheckFinding) => {
                  const isOpen = Boolean(expandedFindingIds[f.id]);
                  return (
                    <FragmentRow
                      key={f.id}
                      finding={f}
                      lang={lang}
                      isOpen={isOpen}
                      onToggle={() => toggleFinding(f.id)}
                    />
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Screenshot Zoom Modal */}
      {zoomOpen && safeScreenshotSrc && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/90 p-4 backdrop-blur-sm"
        >
          <div className="relative max-h-[90vh] max-w-5xl overflow-auto rounded-2xl border border-[#202020] bg-[#0D0D0D] p-4">
            <div className="mb-3 flex items-center justify-between gap-4">
              <p dir="ltr" className="truncate font-mono text-xs text-zinc-300">
                {report.finalDestinationUrl}
              </p>
              <button
                type="button"
                onClick={() => setZoomOpen(false)}
                className="inline-flex items-center gap-1.5 rounded-lg bg-[#FF263F] px-3 py-1.5 text-xs font-bold text-white"
              >
                <X className="h-3.5 w-3.5" />
                <span>{UI_COPY.report.closeZoom[lang]}</span>
              </button>
            </div>
            <img
              src={safeScreenshotSrc}
              alt={`Zoomed preview of ${report.finalDestinationUrl}`}
              referrerPolicy="no-referrer"
              className="w-full rounded-lg"
            />
          </div>
        </div>
      )}
    </section>
  );
}

function FragmentRow({
  finding,
  lang,
  isOpen,
  onToggle,
}: {
  finding: CheckFinding;
  lang: Language;
  isOpen: boolean;
  onToggle: () => void;
}) {
  return (
    <>
      <tr className="hover:bg-[#F7F7F7] dark:hover:bg-white/[0.02]">
        <td className="px-4 py-3 font-semibold text-zinc-900 dark:text-white">
          {finding.test[lang]}
        </td>
        <td className="px-4 py-3 text-zinc-700 dark:text-zinc-300 max-w-xs">
          {finding.result[lang]}
        </td>
        <td className="px-4 py-3 whitespace-nowrap">
          <StatusLabel status={finding.status} lang={lang} />
        </td>
        <td className="px-4 py-3 whitespace-nowrap font-semibold text-zinc-700 dark:text-zinc-300">
          {tSeverity(finding.severity, lang)}
        </td>
        <td className="px-4 py-3 text-zinc-500 dark:text-zinc-400 whitespace-nowrap">
          {finding.source}
        </td>
        <td className="px-4 py-3 text-end">
          <button
            type="button"
            onClick={onToggle}
            aria-expanded={isOpen}
            className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs font-medium text-[#FF263F] hover:bg-[#FF263F]/10"
          >
            <span>{UI_COPY.report.table.expandDetails[lang]}</span>
            {isOpen ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
          </button>
        </td>
      </tr>
      {isOpen && (
        <tr className="bg-[#F7F7F7] dark:bg-black">
          <td colSpan={6} className="px-4 py-4 space-y-4">
            <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
              <div>
                <p className="text-[11px] font-semibold text-zinc-500">
                  {lang === 'en' ? 'Risk Explanation' : 'التفسير الفني للمخاطر'}
                </p>
                <p className="mt-1 text-xs leading-relaxed text-zinc-800 dark:text-zinc-200">
                  {finding.explanation[lang]}
                </p>
              </div>
              <div>
                <p className="text-[11px] font-semibold text-zinc-500">
                  {UI_COPY.report.table.recommendedAction[lang]}
                </p>
                <p className="mt-1 text-xs leading-relaxed font-medium text-zinc-900 dark:text-zinc-100">
                  {finding.recommendedAction?.[lang] ||
                    (lang === 'en'
                      ? 'Review technical evidence before trusting this URL.'
                      : 'راجع الدليل التقني قبل الوثوق بهذا الرابط.')}
                </p>
              </div>
              <div>
                <p className="text-[11px] font-semibold text-zinc-500">
                  {UI_COPY.report.table.colEvidence[lang]}
                </p>
                <p dir="ltr" className="mt-1 break-all font-mono text-[11px] text-zinc-700 dark:text-zinc-300">
                  {finding.evidence}
                </p>
                <p dir="ltr" className="mt-2 font-mono text-[11px] text-zinc-500 tabular-nums">
                  {finding.lastUpdated || finding.timestamp} · Confidence: {finding.confidence}% · Weight: +{finding.weight}
                  {finding.reliabilityLabel ? ` · Reliability: ${finding.reliabilityLabel}` : ''}
                  {finding.riskImpact ? ` · Impact: ${finding.riskImpact}` : ''}
                </p>
              </div>
            </div>

            {finding.forensic && (
              <div className="grid grid-cols-1 gap-4 border-t border-[#E5E7EB] pt-3 dark:border-[#202020] md:grid-cols-3 lg:grid-cols-5">
                <div>
                  <p className="text-[11px] font-semibold text-zinc-500">
                    {UI_COPY.report.table.whereDetected[lang]}
                  </p>
                  <p className="mt-1 text-xs leading-relaxed text-zinc-800 dark:text-zinc-200">
                    {finding.forensic.whereDetected[lang]}
                  </p>
                </div>
                <div>
                  <p className="text-[11px] font-semibold text-zinc-500">
                    {UI_COPY.report.table.whyRisky[lang]}
                  </p>
                  <p className="mt-1 text-xs leading-relaxed text-zinc-800 dark:text-zinc-200">
                    {finding.forensic.whyRisky[lang]}
                  </p>
                </div>
                <div>
                  <p className="text-[11px] font-semibold text-zinc-500">
                    {UI_COPY.report.table.howExploited[lang]}
                  </p>
                  <p className="mt-1 text-xs leading-relaxed text-zinc-800 dark:text-zinc-200">
                    {finding.forensic.howExploited[lang]}
                  </p>
                </div>
                <div>
                  <p className="text-[11px] font-semibold text-zinc-500">
                    {UI_COPY.report.table.userImpact[lang]}
                  </p>
                  <p className="mt-1 text-xs leading-relaxed text-zinc-800 dark:text-zinc-200">
                    {finding.forensic.userImpact[lang]}
                  </p>
                </div>
                <div>
                  <p className="text-[11px] font-semibold text-[#FF263F]">
                    {UI_COPY.report.table.notProvenAlone[lang]}
                  </p>
                  <p className="mt-1 text-xs leading-relaxed text-zinc-800 dark:text-zinc-200">
                    {finding.forensic.notProvenAlone[lang]}
                  </p>
                </div>
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  );
}
