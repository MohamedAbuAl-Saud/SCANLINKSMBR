import { useMemo, useState } from 'react';
import {
  Camera,
  CheckCircle2,
  ExternalLink,
  Globe,
  Maximize2,
  ShieldAlert,
  ShieldCheck,
  X,
  XCircle,
} from 'lucide-react';
import type {
  Language,
  LevelBExecutionData,
  LevelBNetworkChannelCategory,
  ScanReport,
} from '../types/scan';
import { safeExternalHref, safeImageDataUrl } from '../utils/sanitize';

interface LevelBScanBoxProps {
  levelB?: LevelBExecutionData;
  analysisLevelB?: NonNullable<ScanReport['analysisLevels']>['levelBIsolatedBrowser'];
  lang: Language;
}

type NetworkFilter = 'all' | 'sensitive' | 'third_party';

function formatChannelCategory(
  cat: LevelBNetworkChannelCategory,
  lang: Language
): { label: string; colorClass: string } {
  switch (cat) {
    case 'HIGH_RISK_EXFILTRATION_CHANNEL':
      return {
        label: lang === 'ar' ? 'قناة تسريب عالية الخطورة' : 'HIGH_RISK_EXFILTRATION_CHANNEL',
        colorClass: 'text-[#EF233C]',
      };
    case 'WEBHOOK_OR_BOT_SINK':
      return {
        label: lang === 'ar' ? 'نقطة Webhook أو بوت' : 'WEBHOOK_OR_BOT_SINK',
        colorClass: 'text-[#EF233C]',
      };
    case 'IP_AND_DEVICE_PROFILING':
      return {
        label: lang === 'ar' ? 'تتبع IP وبصمة الجهاز' : 'IP_AND_DEVICE_PROFILING',
        colorClass: 'text-[#D97706] dark:text-[#FBBF24]',
      };
    case 'UNVERIFIED_EXTERNAL':
      return {
        label: lang === 'ar' ? 'وجهة خارجية غير موثوقة' : 'UNVERIFIED_EXTERNAL',
        colorClass: 'text-sky-600 dark:text-sky-400',
      };
    case 'FIRST_PARTY_OR_KNOWN':
    default:
      return {
        label: lang === 'ar' ? 'نطاق أساسي / موثوق' : 'FIRST_PARTY_OR_KNOWN',
        colorClass: 'text-[#16A34A]',
      };
  }
}

function getPermissionLabel(kind: string, lang: Language): string {
  const labels: Record<string, { en: string; ar: string }> = {
    camera: { en: 'Camera', ar: 'الكاميرا' },
    microphone: { en: 'Microphone', ar: 'الميكروفون' },
    geolocation: { en: 'Geolocation', ar: 'الموقع الجغرافي' },
    clipboard: { en: 'Clipboard', ar: 'الحافظة' },
    notifications: { en: 'Notifications', ar: 'الإشعارات' },
    auto_timer: { en: 'Auto Timer', ar: 'مؤقت تلقائي' },
    lure_interaction: { en: 'Lure Trigger', ar: 'تفاعل مخادع' },
    other: { en: 'Other API', ar: 'واجهة أخرى' },
  };
  return labels[kind]?.[lang] || kind;
}

export function LevelBScanBox({ levelB, analysisLevelB, lang }: LevelBScanBoxProps) {
  const isAr = lang === 'ar';
  const [networkFilter, setNetworkFilter] = useState<NetworkFilter>('all');
  const [zoomOpen, setZoomOpen] = useState(false);

  const effectiveStatus = levelB?.status ?? (analysisLevelB?.performed ? 'executed' : 'unavailable');
  const isExecuted = effectiveStatus === 'executed';
  const safeScreenshot = safeImageDataUrl(levelB?.screenshot?.dataUrl);
  const safeFinalHref = safeExternalHref(levelB?.finalUrl);

  const statusMeta = useMemo(() => {
    switch (effectiveStatus) {
      case 'executed':
        return {
          text: isAr
            ? 'تم التنفيذ · خدمة متصفح خارجي سحابي'
            : 'Executed · External Cloud Browser Service',
          color: 'text-[#16A34A]',
          Icon: CheckCircle2,
        };
      case 'blocked_by_ssrf':
        return {
          text: isAr
            ? 'محظور أمنياً · حارس SSRF'
            : 'Blocked · SSRF Network Isolation',
          color: 'text-[#EF233C]',
          Icon: ShieldAlert,
        };
      case 'failed':
        return {
          text: isAr
            ? 'تعذّر التنفيذ (فشل الاتصال الخارجي)'
            : 'Failed (Remote Execution Error)',
          color: 'text-[#D97706] dark:text-[#FBBF24]',
          Icon: XCircle,
        };
      case 'disabled':
        return {
          text: isAr ? 'معطّل في إعدادات الجلسة' : 'Disabled in Session Settings',
          color: 'text-zinc-500 dark:text-zinc-400',
          Icon: XCircle,
        };
      case 'unavailable':
      default:
        return {
          text: isAr
            ? 'غير منفّذ · غير متاح (Not Executed)'
            : 'Not Executed · Unavailable',
          color: 'text-[#D97706] dark:text-[#FBBF24]',
          Icon: ShieldAlert,
        };
    }
  }, [effectiveStatus, isAr]);

  const requests = levelB?.networkRequests ?? [];
  const filteredRequests = useMemo(() => {
    if (networkFilter === 'sensitive') {
      return requests.filter(
        (r) =>
          r.isSensitiveSink ||
          r.channelCategory === 'HIGH_RISK_EXFILTRATION_CHANNEL' ||
          r.channelCategory === 'WEBHOOK_OR_BOT_SINK' ||
          r.channelCategory === 'IP_AND_DEVICE_PROFILING'
      );
    }
    if (networkFilter === 'third_party') {
      return requests.filter((r) => r.isThirdParty);
    }
    return requests;
  }, [requests, networkFilter]);

  const permissionEvents = levelB?.permissionEvents ?? [];
  const redirects = levelB?.redirects ?? [];
  const domSummary = levelB?.domSummary;
  const sensitiveRequestCount = requests.filter(
    (r) =>
      r.isSensitiveSink ||
      r.channelCategory === 'HIGH_RISK_EXFILTRATION_CHANNEL' ||
      r.channelCategory === 'WEBHOOK_OR_BOT_SINK'
  ).length;

  const StatusIcon = statusMeta.Icon;

  return (
    <div
      id="level-b-scan-box"
      className="rounded-2xl border border-[#E5E7EB] bg-white p-5 sm:p-6 dark:border-[#202020] dark:bg-[#0D0D0D]"
    >
      {/* Top Header & Operational Status */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <Globe className="h-4 w-4 shrink-0 text-[#FF263F]" aria-hidden="true" />
            <h2 className="font-display text-base font-bold text-zinc-950 dark:text-white">
              {isAr
                ? 'صندوق فحص Level B — التحليل الديناميكي المعزول (Scan B)'
                : 'Level B Scan Box — Isolated Runtime Browser Execution'}
            </h2>
          </div>
          <p className="mt-1 text-xs leading-relaxed text-zinc-600 dark:text-zinc-400">
            {levelB?.executiveSummary?.[lang] ||
              analysisLevelB?.reason?.[lang] ||
              (isAr
                ? 'فحص وقت التشغيل عبر خدمة متصفح خارجي سحابي مضبوطة في بيئة الخادم (.env) فقط دون أي تثبيت محلي.'
                : 'Runtime execution telemetry via server-configured External Cloud Browser Service (.env only, zero local browser footprint).')}
          </p>
        </div>

        <div className={`inline-flex shrink-0 items-center gap-1.5 font-mono text-xs font-bold ${statusMeta.color}`}>
          <StatusIcon className="h-4 w-4 shrink-0" aria-hidden="true" />
          <span>{statusMeta.text}</span>
        </div>
      </div>

      {/* Metadata Strip (Flat Key-Value Row, Single Elevation) */}
      <dl className="mt-5 grid grid-cols-2 gap-4 border-t border-[#E5E7EB] pt-4 text-xs dark:border-[#202020] sm:grid-cols-3 lg:grid-cols-6">
        <div className="min-w-0">
          <dt className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
            {isAr ? 'المزود / الوضع' : 'Provider & Mode'}
          </dt>
          <dd className="mt-1 font-semibold text-zinc-950 dark:text-white">
            {levelB?.providerLabel?.[lang] ||
              (isAr ? 'خدمة متصفح خارجي سحابي' : 'External Cloud Browser Service')}
          </dd>
        </div>

        <div className="min-w-0">
          <dt className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
            {isAr ? 'المدة الزمنية' : 'Duration'}
          </dt>
          <dd dir="ltr" className="mt-1 font-mono font-bold text-zinc-950 dark:text-white tabular-nums">
            {levelB?.durationMs !== undefined ? `${levelB.durationMs} ms` : '—'}
          </dd>
        </div>

        <div className="min-w-0">
          <dt className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
            {isAr ? 'أثر الثقة والتغطية' : 'Confidence / Coverage'}
          </dt>
          <dd dir="ltr" className="mt-1 font-mono font-semibold tabular-nums text-zinc-950 dark:text-white">
            {isExecuted ? (
              <span className="text-[#16A34A]">
                +{Math.abs(levelB?.coverageImpact ?? 0)}% Coverage · 0 Risk Penalty
              </span>
            ) : (
              <span className="text-[#D97706] dark:text-[#FBBF24]">
                Conf {levelB?.confidenceImpact ?? -12}% · Cov {levelB?.coverageImpact ?? -15}% · Risk +0
              </span>
            )}
          </dd>
        </div>

        <div className="min-w-0">
          <dt className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
            {isAr ? 'الطلبات الشبكية' : 'Outbound Requests'}
          </dt>
          <dd dir="ltr" className="mt-1 font-mono font-bold text-zinc-950 dark:text-white tabular-nums">
            {requests.length}
            {sensitiveRequestCount > 0 ? (
              <span className="text-[#EF233C]"> · {sensitiveRequestCount} sensitive</span>
            ) : null}
          </dd>
        </div>

        <div className="min-w-0">
          <dt className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
            {isAr ? 'أحداث الصلاحيات' : 'Permission Events'}
          </dt>
          <dd dir="ltr" className="mt-1 font-mono font-bold text-zinc-950 dark:text-white tabular-nums">
            {permissionEvents.length}
          </dd>
        </div>

        <div className="min-w-0">
          <dt className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
            {isAr ? 'الرابط النهائي وقت التشغيل' : 'Runtime Final URL'}
          </dt>
          <dd dir="ltr" className="mt-1 truncate font-mono text-[11px] text-zinc-800 dark:text-zinc-200">
            {safeFinalHref ? (
              <a
                href={safeFinalHref}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 hover:text-[#FF263F] hover:underline"
              >
                <span className="truncate">{levelB?.finalUrl}</span>
                <ExternalLink className="h-3 w-3 shrink-0" aria-hidden="true" />
              </a>
            ) : (
              <span>{levelB?.finalUrl || '—'}</span>
            )}
          </dd>
        </div>
      </dl>

      {/* Honest Failure / Unavailability Notice when Level B did not execute */}
      {!isExecuted && (
        <div className="mt-5 border-t border-[#E5E7EB] pt-4 dark:border-[#202020]">
          <p className="text-xs font-bold text-[#D97706] dark:text-[#FBBF24]">
            {isAr
              ? 'سياسة الشفافية عند غياب Level B: لا توجد بيانات سلوك ديناميكي ملفّقة'
              : 'Transparent Non-Execution Disclosure: Zero Fabricated Runtime Telemetry'}
          </p>
          <p className="mt-1 text-xs leading-relaxed text-zinc-700 dark:text-zinc-300">
            {levelB?.errorReason?.[lang] ||
              analysisLevelB?.reason?.[lang] ||
              (isAr
                ? 'لم يُنفَّذ Level B لعدم توفر إعدادات الخدمة السحابية الخارجية في بيئة الخادم (.env). تم خصم الغياب من نسبة الثقة والتغطية فقط (+0 نقاط لدرجة المخاطر)، والاعتماد كلياً على أدلة التحليل الساكن Level A.'
                : 'Level B did not execute because external cloud browser configuration is absent in server .env. This absence reduces Confidence % and Coverage % only (zero Risk Score penalty), while threat classification relies solely on verified Level A static evidence.')}
          </p>
        </div>
      )}

      {/* Runtime Screenshot + Rendered DOM Summary */}
      <div className="mt-5 grid grid-cols-1 gap-6 border-t border-[#E5E7EB] pt-5 dark:border-[#202020] lg:grid-cols-12">
        {/* Screenshot Pane */}
        <div className="lg:col-span-6 space-y-2.5">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-xs font-bold text-zinc-950 dark:text-white">
              <Camera className="h-3.5 w-3.5 text-[#FF263F]" aria-hidden="true" />
              <span>
                {isAr ? 'لقطة الشاشة الملتقطة في Level B' : 'Level B Runtime Screenshot'}
              </span>
            </div>
            <span dir="ltr" className="font-mono text-[11px] text-zinc-500 dark:text-zinc-400 tabular-nums">
              {levelB?.screenshot?.viewport || 'desktop'}
              {levelB?.screenshot?.width && levelB?.screenshot?.height
                ? ` · ${levelB.screenshot.width}×${levelB.screenshot.height}`
                : ''}
            </span>
          </div>

          {safeScreenshot ? (
            <div className="relative overflow-hidden rounded-xl border border-[#E5E7EB] bg-[#F7F7F7] dark:border-[#202020] dark:bg-black">
              <img
                src={safeScreenshot}
                alt={
                  isAr
                    ? `لقطة شاشة Level B للرابط ${levelB?.finalUrl || ''}`
                    : `Level B runtime screenshot of ${levelB?.finalUrl || 'target page'}`
                }
                referrerPolicy="no-referrer"
                className="max-h-72 w-full object-cover object-top"
              />
              <button
                type="button"
                onClick={() => setZoomOpen(true)}
                className="absolute bottom-2.5 right-2.5 inline-flex items-center gap-1.5 rounded-lg border border-zinc-300/80 bg-white/95 px-2.5 py-1 text-[11px] font-semibold text-zinc-900 shadow-sm hover:border-[#FF263F] hover:text-[#FF263F] dark:border-zinc-700 dark:bg-zinc-950/90 dark:text-white transition-colors"
              >
                <Maximize2 className="h-3 w-3" aria-hidden="true" />
                <span>{isAr ? 'تكبير اللقطة' : 'Zoom Screenshot'}</span>
              </button>
            </div>
          ) : (
            <div className="flex min-h-[150px] flex-col items-center justify-center rounded-xl border border-dashed border-[#E5E7EB] bg-[#F7F7F7] p-5 text-center dark:border-[#202020] dark:bg-black">
              <Camera className="h-5 w-5 text-zinc-400" aria-hidden="true" />
              <p className="mt-2 text-xs font-semibold text-zinc-800 dark:text-zinc-200">
                {isAr ? 'لم يتم التقاط لقطة شاشة داخل Level B' : 'No Level B Runtime Screenshot Captured'}
              </p>
              <p className="mt-1 max-w-md text-[11px] leading-relaxed text-zinc-500 dark:text-zinc-400">
                {levelB?.screenshot?.missingReason?.[lang] ||
                  (isAr
                    ? 'تعذّر التقاط اللقطة أثناء تنفيذ Level B أو لم يتوفر اتصال الخدمة السحابية الخارجية.'
                    : 'Screenshot was not captured because Level B execution did not complete or returned no visual frame.')}
              </p>
            </div>
          )}
        </div>

        {/* Rendered DOM & Runtime Redirect Summary */}
        <div className="lg:col-span-6 space-y-4">
          <div className="flex items-center justify-between gap-2">
            <h3 className="text-xs font-bold text-zinc-950 dark:text-white">
              {isAr ? 'حالة DOM النهائي وإعادة التوجيه وقت التشغيل' : 'Rendered DOM & Runtime Redirect Telemetry'}
            </h3>
            <span dir="ltr" className="font-mono text-[11px] text-zinc-500 dark:text-zinc-400 tabular-nums">
              Redirects: {redirects.length}
            </span>
          </div>

          {domSummary ? (
            <div className="space-y-3 text-xs">
              {domSummary.title && (
                <p className="text-zinc-700 dark:text-zinc-300">
                  <span className="font-semibold text-zinc-500 dark:text-zinc-400">
                    {isAr ? 'عنوان الصفحة بعد التنفيذ: ' : 'Rendered Title: '}
                  </span>
                  <span className="font-semibold text-zinc-950 dark:text-white">{domSummary.title}</span>
                </p>
              )}

              <dl className="grid grid-cols-2 gap-x-4 gap-y-2 border-t border-[#E5E7EB] pt-3 font-mono text-[11px] tabular-nums dark:border-[#202020] sm:grid-cols-3">
                <div>
                  <dt className="font-sans text-zinc-500 dark:text-zinc-400">
                    {isAr ? 'نماذج DOM' : 'Dynamic Forms'}
                  </dt>
                  <dd className="font-bold text-zinc-950 dark:text-white">{domSummary.dynamicFormCount}</dd>
                </div>
                <div>
                  <dt className="font-sans text-zinc-500 dark:text-zinc-400">
                    {isAr ? 'حقول حساسة' : 'Sensitive Inputs'}
                  </dt>
                  <dd
                    className={`font-bold ${
                      domSummary.sensitiveInputCount > 0 ? 'text-[#EF233C]' : 'text-zinc-950 dark:text-white'
                    }`}
                  >
                    {domSummary.sensitiveInputCount}
                  </dd>
                </div>
                <div>
                  <dt className="font-sans text-zinc-500 dark:text-zinc-400">
                    {isAr ? 'إطارات Iframe' : 'Iframes'}
                  </dt>
                  <dd className="font-bold text-zinc-950 dark:text-white">{domSummary.dynamicIframeCount}</dd>
                </div>
                <div>
                  <dt className="font-sans text-zinc-500 dark:text-zinc-400">
                    {isAr ? 'سكربتات DOM' : 'Scripts'}
                  </dt>
                  <dd className="font-bold text-zinc-950 dark:text-white">{domSummary.dynamicScriptCount}</dd>
                </div>
                <div>
                  <dt className="font-sans text-zinc-500 dark:text-zinc-400">
                    {isAr ? 'عدد الكلمات' : 'Rendered Words'}
                  </dt>
                  <dd className="font-bold text-zinc-950 dark:text-white">{domSummary.wordCount}</dd>
                </div>
              </dl>

              {domSummary.notableElements.length > 0 && (
                <p className="text-[11px] leading-relaxed text-zinc-600 dark:text-zinc-400">
                  <span className="font-semibold text-zinc-800 dark:text-zinc-200">
                    {isAr ? 'عناصر بارزة: ' : 'Notable Elements: '}
                  </span>
                  {domSummary.notableElements.join(' · ')}
                </p>
              )}
            </div>
          ) : (
            <p className="text-xs text-zinc-500 dark:text-zinc-400">
              {isAr
                ? 'لم تُرصد لقطة DOM ديناميكية بسبب عدم تنفيذ Level B.'
                : 'No rendered DOM telemetry recorded (Level B did not execute).'}
            </p>
          )}

          {redirects.length > 0 && (
            <div className="border-t border-[#E5E7EB] pt-3 dark:border-[#202020]">
              <p className="text-[11px] font-bold text-zinc-700 dark:text-zinc-300">
                {isAr ? 'سلسلة التحويلات وقت التشغيل:' : 'Observed Runtime Redirects:'}
              </p>
              <ul className="mt-1.5 space-y-1 font-mono text-[11px] text-zinc-600 dark:text-zinc-400">
                {redirects.slice(0, 5).map((hop) => (
                  <li key={`${hop.step}-${hop.url}`} dir="ltr" className="truncate">
                    #{hop.step} {hop.statusCode ? `[${hop.statusCode}] ` : ''}
                    {hop.url}
                    {hop.note ? ` (${hop.note})` : ''}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>

      {/* Outbound Network Requests Observed During Runtime */}
      <div className="mt-5 border-t border-[#E5E7EB] pt-5 dark:border-[#202020]">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-xs font-bold text-zinc-950 dark:text-white">
              {isAr
                ? `الطلبات الشبكية الصادرة وقت التشغيل (${requests.length})`
                : `Runtime Outbound Network Requests (${requests.length})`}
            </h3>
            <p className="mt-0.5 text-[11px] text-zinc-500 dark:text-zinc-400">
              {isAr
                ? 'تصنيف الوجهات الشبكية إلى قنوات تسريب خطرة، بوتات/Webhooks، تتبع IP، أو نطاقات غير موثوقة.'
                : 'Classifies runtime destinations into exfiltration sinks, bot/webhook channels, IP profiling, or unverified external hosts.'}
            </p>
          </div>

          {requests.length > 0 && (
            <div className="inline-flex rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-0.5 dark:border-[#202020] dark:bg-black">
              {(
                [
                  { id: 'all' as const, en: `All (${requests.length})`, ar: `الكل (${requests.length})` },
                  {
                    id: 'sensitive' as const,
                    en: `Sensitive (${sensitiveRequestCount})`,
                    ar: `حساسة (${sensitiveRequestCount})`,
                  },
                  {
                    id: 'third_party' as const,
                    en: `Third-Party (${requests.filter((r) => r.isThirdParty).length})`,
                    ar: `طرف ثالث (${requests.filter((r) => r.isThirdParty).length})`,
                  },
                ] as const
              ).map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setNetworkFilter(tab.id)}
                  className={`rounded-md px-2.5 py-1 text-[11px] font-semibold transition-colors ${
                    networkFilter === tab.id
                      ? 'bg-white text-zinc-950 shadow-sm dark:bg-[#1A1A1A] dark:text-white'
                      : 'text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white'
                  }`}
                >
                  {isAr ? tab.ar : tab.en}
                </button>
              ))}
            </div>
          )}
        </div>

        {filteredRequests.length > 0 ? (
          <div className="mt-3 overflow-x-auto">
            <table className="w-full min-w-[680px] border-collapse text-start text-xs">
              <thead>
                <tr className="border-b border-[#E5E7EB] text-[11px] font-semibold text-zinc-500 dark:border-[#202020] dark:text-zinc-400">
                  <th className="py-2 pe-3 text-start">{isAr ? 'الطريقة' : 'Method'}</th>
                  <th className="py-2 px-3 text-start">{isAr ? 'النطاق' : 'Domain'}</th>
                  <th className="py-2 px-3 text-start">{isAr ? 'المسار (مُنقّح)' : 'Redacted Path'}</th>
                  <th className="py-2 px-3 text-start">{isAr ? 'النوع' : 'Type'}</th>
                  <th className="py-2 ps-3 text-start">{isAr ? 'تصنيف القناة' : 'Channel Category'}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E5E7EB] dark:divide-[#202020]">
                {filteredRequests.slice(0, 25).map((req, idx) => {
                  const cat = formatChannelCategory(req.channelCategory, lang);
                  return (
                    <tr key={`${req.method}-${req.domain}-${req.path}-${idx}`} className="align-top">
                      <td dir="ltr" className="py-2 pe-3 font-mono font-bold text-zinc-900 dark:text-white">
                        {req.method}
                      </td>
                      <td dir="ltr" className="py-2 px-3 font-mono font-semibold text-zinc-900 dark:text-zinc-100">
                        {req.domain}
                      </td>
                      <td dir="ltr" className="max-w-xs truncate py-2 px-3 font-mono text-[11px] text-zinc-600 dark:text-zinc-400">
                        {req.path || '/'}
                      </td>
                      <td dir="ltr" className="py-2 px-3 font-mono text-[11px] text-zinc-500 dark:text-zinc-400">
                        {req.resourceType || 'fetch'}
                        {req.statusCode ? ` · ${req.statusCode}` : ''}
                      </td>
                      <td className="py-2 ps-3">
                        <span className={`font-mono text-[11px] font-bold ${cat.colorClass}`}>
                          {cat.label}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="mt-2.5 text-xs text-zinc-500 dark:text-zinc-400">
            {isExecuted
              ? isAr
                ? 'لم تُرصد طلبات شبكية تطابق المرشح المحدد أثناء الجلسة.'
                : 'No runtime network requests matching the active filter were observed.'
              : isAr
                ? 'لم تُسجّل طلبات شبكية ديناميكية لعدم تنفيذ Level B.'
                : 'No dynamic network telemetry recorded (Level B unavailable).'}
          </p>
        )}
      </div>

      {/* Permission & Behavioral Runtime Events */}
      <div className="mt-5 border-t border-[#E5E7EB] pt-5 dark:border-[#202020]">
        <div className="flex items-center justify-between gap-2">
          <h3 className="text-xs font-bold text-zinc-950 dark:text-white">
            {isAr
              ? `محاولات الصلاحيات والأحداث السلوكية أثناء الجلسة (${permissionEvents.length})`
              : `Runtime Permission Attempts & Behavioral Events (${permissionEvents.length})`}
          </h3>
          <ShieldCheck className="h-3.5 w-3.5 text-zinc-400" aria-hidden="true" />
        </div>

        {permissionEvents.length > 0 ? (
          <div className="mt-3 divide-y divide-[#E5E7EB] dark:divide-[#202020]">
            {permissionEvents.slice(0, 12).map((ev, idx) => {
              const isHigh =
                ev.kind === 'camera' ||
                ev.kind === 'microphone' ||
                ev.kind === 'geolocation' ||
                ev.kind === 'clipboard' ||
                ev.trigger === 'on_load';
              return (
                <div key={`${ev.kind}-${ev.api}-${idx}`} className="py-2.5 text-xs">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-semibold text-zinc-950 dark:text-white">
                      {getPermissionLabel(ev.kind, lang)} ·{' '}
                      <span dir="ltr" className="font-mono text-[11px] text-zinc-600 dark:text-zinc-300">
                        {ev.api}
                      </span>
                    </span>
                    <span
                      dir="ltr"
                      className={`font-mono text-[11px] font-bold ${
                        isHigh ? 'text-[#EF233C]' : 'text-zinc-600 dark:text-zinc-300'
                      }`}
                    >
                      {ev.trigger} · {ev.outcome}
                    </span>
                  </div>
                  <p className="mt-1 text-[11px] leading-relaxed text-zinc-600 dark:text-zinc-400">
                    {ev.detail[lang]}
                  </p>
                </div>
              );
            })}
          </div>
        ) : (
          <p className="mt-2 text-xs text-zinc-500 dark:text-zinc-400">
            {isExecuted
              ? isAr
                ? 'لم تطلب الصفحة صلاحيات الكاميرا أو الميكروفون أو الموقع أو الحافظة أو الإشعارات أثناء الجلسة.'
                : 'No runtime camera, microphone, geolocation, clipboard, or notification permission prompts occurred.'
              : isAr
                ? 'لا توجد أحداث صلاحيات ديناميكية مرصودة في وقت التشغيل (راجع تدقيق أذونات Level A أدناه).'
                : 'No runtime permission telemetry captured (see Level A static permission audit in the report below).'}
          </p>
        )}
      </div>

      {/* Screenshot Zoom Modal */}
      {zoomOpen && safeScreenshot && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/90 p-4 backdrop-blur-sm"
        >
          <div className="relative max-h-[90vh] max-w-5xl overflow-auto rounded-2xl border border-[#202020] bg-[#0D0D0D] p-4">
            <div className="mb-3 flex items-center justify-between gap-4">
              <p dir="ltr" className="truncate font-mono text-xs text-zinc-300">
                Level B · {levelB?.finalUrl || ''}
              </p>
              <button
                type="button"
                onClick={() => setZoomOpen(false)}
                className="inline-flex items-center gap-1.5 rounded-lg bg-[#FF263F] px-3 py-1.5 text-xs font-bold text-white"
              >
                <X className="h-3.5 w-3.5" aria-hidden="true" />
                <span>{isAr ? 'إغلاق' : 'Close'}</span>
              </button>
            </div>
            <img
              src={safeScreenshot}
              alt={isAr ? 'معاينة مكبرة للقطة Level B' : 'Zoomed Level B runtime screenshot'}
              referrerPolicy="no-referrer"
              className="w-full rounded-lg"
            />
          </div>
        </div>
      )}
    </div>
  );
}
