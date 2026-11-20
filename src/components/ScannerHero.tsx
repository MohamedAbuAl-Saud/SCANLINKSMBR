import { useState, type FormEvent } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ClipboardPaste,
  ExternalLink,
  FileSearch,
  Globe,
  GlobeLock,
  Lock,
  Monitor,
  Radar,
  Search,
  ShieldAlert,
  SlidersHorizontal,
  Smartphone,
  X,
} from 'lucide-react';
import type {
  Language,
  ProviderDescriptor,
  SavedHistoryEntry,
  ScanReport,
  ScreenshotViewport,
} from '../types/scan';
import { tOperationalState, tVerdict, UI_COPY } from '../i18n/translations';
import { BrandMark } from './BrandMark';
import {
  BinaryInspectorVisual,
  SourceCodeForensicsVisual,
  SubdomainDnsTopologyVisual,
  ThreatIntelNetworkVisual,
} from './CyberIllustrations';
import { CyberHeroArtwork } from './CyberHeroArtwork';
import { CyberMascot } from './CyberMascot';
import { CyberSticker, type StickerType } from './CyberStickers';

interface ScannerHeroProps {
  lang: Language;
  isScanning: boolean;
  providers: ProviderDescriptor[];
  disabledProviders: string[];
  onToggleProvider: (id: string) => void;
  recentHistory: SavedHistoryEntry[];
  onOpenReport: (report: ScanReport) => void;
  onStartScan: (options: {
    url: string;
    viewport: ScreenshotViewport;
    disabledProviders: string[];
  }) => void;
  showLandingSections?: boolean;
}

function validateClientUrlSyntax(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed) return 'empty';
  if (/[\s\u0000-\u001f\u007f]/.test(trimmed)) return 'whitespace';
  const candidate = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed) ? trimmed : `https://${trimmed}`;
  try {
    const parsed = new URL(candidate);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return 'scheme';
    if (
      !parsed.hostname ||
      (!parsed.hostname.includes('.') && parsed.hostname !== 'localhost' && !parsed.hostname.includes(':'))
    ) {
      return 'host';
    }
    return null;
  } catch {
    return 'syntax';
  }
}

export function ScannerHero({
  lang,
  isScanning,
  providers,
  disabledProviders,
  onToggleProvider,
  recentHistory,
  onOpenReport,
  onStartScan,
  showLandingSections = true,
}: ScannerHeroProps) {
  const [urlInput, setUrlInput] = useState('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [showOptions, setShowOptions] = useState(false);
  const [viewport, setViewport] = useState<ScreenshotViewport>('desktop');

  const handlePaste = async () => {
    setErrorMsg(null);
    try {
      const text = await navigator.clipboard.readText();
      if (text) setUrlInput(text.trim());
    } catch {
      setErrorMsg(UI_COPY.hero.clipboardDenied[lang]);
    }
  };

  const handleClear = () => {
    setUrlInput('');
    setErrorMsg(null);
  };

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    const err = validateClientUrlSyntax(urlInput);
    if (err) {
      setErrorMsg(UI_COPY.hero.invalidUrl[lang]);
      return;
    }
    setErrorMsg(null);
    onStartScan({
      url: urlInput.trim(),
      viewport,
      disabledProviders,
    });
  };

  const capabilities = [
    {
      num: '01',
      icon: Radar,
      title: { en: 'URL Structure & Obfuscation', ar: 'استخبارات بنية الرابط والتمويه' },
      desc: {
        en: 'Inspects Punycode/IDN homographs, @ authority credentials, nested URL parameters, Base64 payloads, multi-tenant PaaS hosts, and shorteners.',
        ar: 'يفحص انتحال Punycode والتشابه البصري والتمويه بالرمز @ والمعاملات المشفرة والاستضافات التشاركية والروابط المختصرة.',
      },
    },
    {
      num: '02',
      icon: ArrowRight,
      title: { en: 'SSRF-Guarded Redirect Tracer', ar: 'تتبع إعادة التوجيه المحصن ضد SSRF' },
      desc: {
        en: 'Follows redirect chains hop-by-hop on the backend, flags HTTPS-to-HTTP downgrades and cross-domain bounces while blocking private networks.',
        ar: 'يتتبع قفزات التوجيه ويكتشف خفض HTTPS إلى HTTP والتنقل بين النطاقات مع حظر الشبكات الخاصة وlocalhost.',
      },
    },
    {
      num: '03',
      icon: GlobeLock,
      title: { en: 'RDAP, DoH & X.509 Inspection', ar: 'فحص RDAP و DoH وشهادات TLS' },
      desc: {
        en: 'Queries official IANA RDAP registries, OS DNS + Cloudflare DoH records, ASN metadata, live TLS chains, and Certificate Transparency logs.',
        ar: 'يستعلم سجلات RDAP الرسمية و DNS/DoH وبيانات الشبكة وشهادات التشفير الفعلية وسجلات الشفافية.',
      },
    },
    {
      num: '04',
      icon: ShieldAlert,
      title: { en: 'Credential, Lure & Brand Analysis', ar: 'كشف سرقة البيانات وانتحال العلامات' },
      desc: {
        en: 'Statically inspects DOM without running scripts to catch unwrapped password inputs, fake update lures, notification abuse, and brand impersonation.',
        ar: 'يحلل DOM دون تنفيذ أكواد الجافاسكربت لكشف حقول كلمات المرور المخادعة وتحذيرات التحديث الوهمية وانتحال العلامات.',
      },
    },
    {
      num: '05',
      icon: FileSearch,
      title: { en: 'In-Memory File Signature Check', ar: 'فحص التوقيع الثنائي للملفات بالذاكرة' },
      desc: {
        en: 'Computes SHA-256 and verifies magic bytes against declared MIME types without ever writing or executing downloaded binaries.',
        ar: 'يحسب بصمة SHA-256 ويطابق التوقيع الثنائي مع نوع الملف المعلن دون حفظ الملفات أو تشغيلها.',
      },
    },
    {
      num: '06',
      icon: Lock,
      title: { en: 'Threat Feeds & Deception Correlation', ar: 'استخبارات التهديدات وربط المؤشرات' },
      desc: {
        en: 'Combines VirusTotal v3, URLhaus, OpenPhish, PhishStats, Cloudflare Security DNS, AlienVault OTX, and URLScan.io with domain authenticity verification.',
        ar: 'يدمج VirusTotal و URLhaus و OpenPhish و PhishStats و Cloudflare Security DNS و OTX و URLScan.io مع التحقق الحقيقي من النطاقات.',
      },
    },
  ];

  const toggleableProviders = providers.filter((p) => p.toggleableInScan);

  return (
    <div>
      {/* Primary Scanner Workspace */}
      <section className="relative border-b border-[#E5E7EB] bg-white dark:border-[#202020] dark:bg-black">
        <div className="mx-auto max-w-5xl px-4 py-12 sm:px-6 sm:py-16 lg:px-8">
          <div className="flex flex-col items-center text-center">
            {/* 3D Animated Cybersecurity Mascot & Brand Mark */}
            <div className="mb-4 flex flex-col items-center">
              <CyberMascot state={isScanning ? 'scanning' : 'idle'} size={140} />
              <BrandMark className="mt-2 h-12 sm:h-14 w-auto max-w-[260px]" />
            </div>

            <h1
              className="font-display max-w-3xl text-balance font-extrabold tracking-tight text-zinc-950 dark:text-white"
              style={{ fontSize: 'clamp(2rem, 4vw, 3.3rem)', lineHeight: 1.12 }}
            >
              {UI_COPY.hero.headline[lang]}
            </h1>

            <p className="mt-4 max-w-2xl text-sm leading-relaxed text-zinc-600 dark:text-zinc-400 sm:text-base">
              {UI_COPY.hero.description[lang]}
            </p>

            {/* Primary URL Submission Form */}
            <form
              onSubmit={handleSubmit}
              className="mt-7 w-full max-w-3xl rounded-2xl border border-[#E5E7EB] bg-white/95 backdrop-blur-sm p-3 shadow-sm dark:border-[#202020] dark:bg-[#0D0D0D]/95 sm-red-glow"
            >
              <div className="flex flex-col gap-2.5 sm:flex-row sm:items-center">
                <div className="relative flex-1">
                  <Search
                    className={`pointer-events-none absolute top-1/2 -translate-y-1/2 h-5 w-5 text-zinc-400 ${
                      lang === 'ar' ? 'right-3.5' : 'left-3.5'
                    }`}
                    aria-hidden="true"
                  />
                  <input
                    type="text"
                    dir={urlInput ? 'ltr' : lang === 'ar' ? 'rtl' : 'ltr'}
                    value={urlInput}
                    onChange={(e) => {
                      setUrlInput(e.target.value);
                      if (errorMsg) setErrorMsg(null);
                    }}
                    placeholder={UI_COPY.hero.inputPlaceholder[lang]}
                    aria-label={UI_COPY.hero.inputPlaceholder[lang]}
                    disabled={isScanning}
                    className={`h-12 w-full rounded-xl border border-[#E5E7EB] bg-[#F7F7F7] font-mono text-sm text-zinc-950 placeholder:font-sans placeholder:text-zinc-400 focus:border-[#FF263F] focus:bg-white focus:outline-none focus:ring-2 focus:ring-[#FF263F]/20 dark:border-[#202020] dark:bg-black dark:text-white dark:placeholder:text-zinc-500 dark:focus:bg-[#080808] ${
                      lang === 'ar' ? 'pr-11 pl-10' : 'pl-11 pr-10'
                    }`}
                  />
                  {urlInput && !isScanning && (
                    <button
                      type="button"
                      onClick={handleClear}
                      aria-label={UI_COPY.hero.clear[lang]}
                      className={`absolute top-1/2 -translate-y-1/2 rounded-md p-1.5 text-zinc-400 hover:bg-zinc-200/70 hover:text-zinc-900 dark:hover:bg-white/10 dark:hover:text-white ${
                        lang === 'ar' ? 'left-2' : 'right-2'
                      }`}
                    >
                      <X className="h-4 w-4" />
                    </button>
                  )}
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    type="button"
                    onClick={handlePaste}
                    disabled={isScanning}
                    className="inline-flex h-12 items-center justify-center gap-1.5 rounded-xl border border-[#E5E7EB] bg-[#F7F7F7] px-3.5 text-xs font-semibold text-zinc-800 hover:border-[#FF263F]/50 hover:text-zinc-950 dark:border-[#202020] dark:bg-[#080808] dark:text-zinc-200 dark:hover:text-white transition-colors whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF263F]"
                  >
                    <ClipboardPaste className="h-4 w-4 text-[#FF263F]" aria-hidden="true" />
                    <span>{UI_COPY.hero.paste[lang]}</span>
                  </button>

                  <button
                    type="submit"
                    disabled={isScanning}
                    className="inline-flex h-12 flex-1 sm:flex-initial items-center justify-center gap-2 rounded-xl bg-[#FF263F] px-6 text-sm font-bold text-white hover:bg-[#E01E35] active:bg-[#B91C32] disabled:opacity-60 transition-colors whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF263F]"
                  >
                    <Radar className={`h-4 w-4 ${isScanning ? 'animate-spin' : ''}`} aria-hidden="true" />
                    <span>{isScanning ? UI_COPY.hero.scanning[lang] : UI_COPY.hero.scan[lang]}</span>
                  </button>
                </div>
              </div>

              {errorMsg && (
                <div
                  role="alert"
                  className="mt-3 flex items-center gap-2 rounded-lg border border-red-500/35 bg-red-500/10 px-3 py-2 text-start text-xs font-medium text-red-700 dark:text-red-300"
                >
                  <AlertTriangle className="h-4 w-4 shrink-0 text-[#EF233C]" aria-hidden="true" />
                  <span>{errorMsg}</span>
                </div>
              )}

              {/* Quick Samples & Options Toggle */}
              <div className="mt-3 flex flex-wrap items-center justify-between gap-3 border-t border-[#E5E7EB] pt-3 dark:border-[#202020] text-xs">
                <div className="flex flex-wrap items-center gap-2 text-zinc-500 dark:text-zinc-400">
                  <span>{UI_COPY.hero.examplesLabel[lang]}</span>
                  {['https://example.com', 'https://wikipedia.org'].map((sample) => (
                    <button
                      key={sample}
                      type="button"
                      dir="ltr"
                      onClick={() => {
                        setUrlInput(sample);
                        setErrorMsg(null);
                      }}
                      className="font-mono text-zinc-800 underline decoration-zinc-300 underline-offset-2 hover:text-[#FF263F] dark:text-zinc-200 dark:decoration-zinc-700 dark:hover:text-[#FF263F]"
                    >
                      {sample.replace('https://', '')}
                    </button>
                  ))}
                </div>

                <button
                  type="button"
                  onClick={() => setShowOptions((v) => !v)}
                  aria-expanded={showOptions}
                  className="inline-flex items-center gap-1.5 font-semibold text-zinc-700 hover:text-[#FF263F] dark:text-zinc-300 dark:hover:text-white transition-colors"
                >
                  <SlidersHorizontal className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>{UI_COPY.hero.optionsToggle[lang]}</span>
                </button>
              </div>

              {/* Scan Options: Screenshot Viewport & Provider Toggles */}
              {showOptions && (
                <div className="mt-3 border-t border-[#E5E7EB] pt-3 text-start dark:border-[#202020] space-y-3">
                  <div>
                    <p className="mb-1.5 text-xs font-semibold text-zinc-700 dark:text-zinc-300">
                      {UI_COPY.hero.viewportLabel[lang]}
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {(
                        [
                          { id: 'desktop', label: UI_COPY.hero.viewportDesktop[lang], icon: Monitor },
                          { id: 'mobile', label: UI_COPY.hero.viewportMobile[lang], icon: Smartphone },
                          { id: 'full_page', label: UI_COPY.hero.viewportFull[lang], icon: Monitor },
                        ] as const
                      ).map((vp) => {
                        const Icon = vp.icon;
                        const selected = viewport === vp.id;
                        return (
                          <button
                            key={vp.id}
                            type="button"
                            onClick={() => setViewport(vp.id)}
                            className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                              selected
                                ? 'border-[#FF263F] bg-[#FF263F]/10 text-zinc-950 dark:text-white'
                                : 'border-[#E5E7EB] bg-[#F7F7F7] text-zinc-600 dark:border-[#202020] dark:bg-black dark:text-zinc-400'
                            }`}
                          >
                            <Icon className="h-3.5 w-3.5 text-[#FF263F]" aria-hidden="true" />
                            <span>{vp.label}</span>
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  {toggleableProviders.length > 0 && (
                    <div>
                      <p className="mb-1.5 text-xs font-semibold text-zinc-700 dark:text-zinc-300">
                        {lang === 'en' ? 'Threat Intelligence Providers:' : 'مزودو استخبارات التهديدات:'}
                      </p>
                      <div className="flex flex-wrap gap-2">
                        {toggleableProviders.map((p) => {
                          const enabled = !disabledProviders.includes(p.id);
                          return (
                            <button
                              key={p.id}
                              type="button"
                              onClick={() => onToggleProvider(p.id)}
                              className={`rounded-lg border px-2.5 py-1 text-xs font-medium transition-colors ${
                                enabled
                                  ? 'border-[#FF263F]/50 bg-[#FF263F]/10 text-zinc-950 dark:text-white'
                                  : 'border-[#E5E7EB] bg-[#F7F7F7] text-zinc-400 dark:border-[#202020] dark:bg-black dark:text-zinc-500'
                              }`}
                            >
                              {p.name}
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </form>

            {/* Security Notice */}
            <div className="mt-4 flex max-w-2xl items-start gap-2.5 rounded-xl border border-amber-500/30 bg-amber-50/70 px-4 py-3 text-start text-xs leading-relaxed text-amber-950 dark:border-amber-500/25 dark:bg-amber-950/20 dark:text-amber-200/90">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" aria-hidden="true" />
              <p>{UI_COPY.hero.securityNotice[lang]}</p>
            </div>

            {/* Consented Recent Scans Strip */}
            {recentHistory.length > 0 && (
              <div className="mt-6 w-full max-w-3xl text-start">
                <p className="mb-2 text-xs font-semibold text-zinc-500 dark:text-zinc-400">
                  {UI_COPY.hero.recentScansLabel[lang]}
                </p>
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                  {recentHistory.slice(0, 3).map((item) => {
                    const faviconUrl = item.siteFaviconDataUrl || item.report?.siteFaviconDataUrl;
                    return (
                      <button
                        key={item.scanId}
                        type="button"
                        onClick={() => onOpenReport(item.report)}
                        className="flex items-center justify-between gap-2.5 rounded-xl border border-[#E5E7EB] bg-[#F7F7F7] px-3 py-2.5 text-start hover:border-[#FF263F]/60 dark:border-[#202020] dark:bg-[#0D0D0D] transition-colors"
                      >
                        <div className="flex min-w-0 items-center gap-2.5">
                          <div className="flex h-7 w-7 shrink-0 items-center justify-center overflow-hidden rounded-full border border-[#E5E7EB] bg-white dark:border-[#242424] dark:bg-black">
                            {faviconUrl ? (
                              <img
                                src={faviconUrl}
                                alt=""
                                referrerPolicy="no-referrer"
                                className="h-4 w-4 rounded-full object-contain"
                              />
                            ) : (
                              <Globe className="h-3.5 w-3.5 text-zinc-400" aria-hidden="true" />
                            )}
                          </div>
                          <div className="min-w-0">
                            <p dir="ltr" className="truncate font-mono text-xs font-semibold text-zinc-900 dark:text-white">
                              {item.submittedUrl}
                            </p>
                            <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
                              {tVerdict(item.verdict, lang)}
                            </p>
                          </div>
                        </div>
                        <div className="flex items-center gap-1 shrink-0 font-mono text-xs font-bold text-[#FF263F] tabular-nums">
                          <span>{item.riskScore}</span>
                          <ExternalLink className="h-3 w-3" aria-hidden="true" />
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </div>
      </section>

      {showLandingSections && (
        <>
          {/* Section 2: Deterministic Pipeline Visualization & 6 Core Pillars */}
          <section className="mx-auto max-w-7xl px-4 py-14 sm:px-6 lg:px-8">
            <div className="grid grid-cols-1 gap-8 lg:grid-cols-12 lg:items-center mb-10">
              <div className="lg:col-span-5">
                <h2 className="font-display text-2xl font-bold tracking-tight text-zinc-950 dark:text-white sm:text-3xl text-balance">
                  {UI_COPY.homeSections.labTitle[lang]}
                </h2>
                <p className="mt-3 text-sm leading-relaxed text-zinc-600 dark:text-zinc-400 sm:text-base">
                  {UI_COPY.homeSections.labSubtitle[lang]}
                </p>
              </div>
              <div className="lg:col-span-7">
                <CyberHeroArtwork isScanning={isScanning} />
              </div>
            </div>

            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
              {capabilities.map((cap, idx) => {
                const Icon = cap.icon;
                const capStickers: StickerType[] = [
                  'link',
                  'network',
                  'dns_globe',
                  'source_code',
                  'scanner',
                  'subdomain_tree',
                ];
                return (
                  <div
                    key={cap.num}
                    className="rounded-xl border border-[#E5E7EB] bg-white p-5 dark:border-[#202020] dark:bg-[#0D0D0D] transition-colors hover:border-[#FF263F]/50"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold text-[#FF263F] tabular-nums">
                        {cap.num}.
                      </span>
                      <div className="flex items-center gap-2">
                        <CyberSticker type={capStickers[idx % capStickers.length]} size={32} interactive={false} />
                        <Icon className="h-4 w-4 text-zinc-400" aria-hidden="true" />
                      </div>
                    </div>
                    <h3 className="font-display mt-3 text-base font-bold text-zinc-950 dark:text-white">
                      {cap.title[lang]}
                    </h3>
                    <p className="mt-1.5 text-xs leading-relaxed text-zinc-600 dark:text-zinc-400">
                      {cap.desc[lang]}
                    </p>
                  </div>
                );
              })}
            </div>

            <div className="mt-8 grid grid-cols-1 gap-6 lg:grid-cols-12 lg:items-stretch">
              <div className="lg:col-span-7">
                <ThreatIntelNetworkVisual lang={lang} />
              </div>
              <div className="lg:col-span-5">
                <BinaryInspectorVisual lang={lang} />
              </div>
            </div>

            <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-12 lg:items-stretch">
              <div className="lg:col-span-6">
                <SourceCodeForensicsVisual lang={lang} />
              </div>
              <div className="lg:col-span-6">
                <SubdomainDnsTopologyVisual lang={lang} />
              </div>
            </div>
          </section>

          {/* Section 3: Live Threat Intelligence Provider Matrix */}
          <section className="border-t border-[#E5E7EB] bg-[#F7F7F7] dark:border-[#202020] dark:bg-[#080808]">
            <div className="mx-auto max-w-7xl px-4 py-14 sm:px-6 lg:px-8">
              <div className="mb-8 max-w-2xl">
                <h2 className="font-display text-2xl font-bold tracking-tight text-zinc-950 dark:text-white sm:text-3xl">
                  {UI_COPY.homeSections.providersTitle[lang]}
                </h2>
                <p className="mt-2 text-sm leading-relaxed text-zinc-600 dark:text-zinc-400">
                  {UI_COPY.homeSections.providersSubtitle[lang]}
                </p>
              </div>

              <div className="overflow-hidden rounded-xl border border-[#E5E7EB] bg-white dark:border-[#202020] dark:bg-[#0D0D0D]">
                <table className="w-full text-start text-sm">
                  <thead className="border-b border-[#E5E7EB] bg-[#F7F7F7] text-xs font-semibold text-zinc-600 dark:border-[#202020] dark:bg-black dark:text-zinc-400">
                    <tr>
                      <th className="px-4 py-3 text-start">{lang === 'en' ? 'Provider / Engine' : 'المزود / المحرك'}</th>
                      <th className="px-4 py-3 text-start">{lang === 'en' ? 'Category' : 'التصنيف'}</th>
                      <th className="px-4 py-3 text-start">{lang === 'en' ? 'Operational State' : 'الحالة التشغيلية'}</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#E5E7EB] dark:divide-[#202020]">
                    {providers.map((p) => {
                      const isReady = p.operationalState === 'active' || p.operationalState === 'configured';
                      return (
                        <tr key={p.id} className="hover:bg-zinc-50 dark:hover:bg-white/[0.02]">
                          <td className="px-4 py-3 font-medium text-zinc-950 dark:text-white">
                            {p.name}
                          </td>
                          <td className="px-4 py-3 text-xs text-zinc-600 dark:text-zinc-400">
                            {p.category}
                          </td>
                          <td className="px-4 py-3 text-xs">
                            <span
                              className={`inline-flex items-center gap-1.5 font-semibold ${
                                isReady
                                  ? 'text-[#16A34A]'
                                  : p.operationalState === 'auth_required'
                                    ? 'text-[#F59E0B]'
                                    : 'text-zinc-500 dark:text-zinc-400'
                              }`}
                            >
                              {isReady ? (
                                <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
                              ) : (
                                <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
                              )}
                              <span>
                                {tOperationalState(p.operationalState, lang)}
                              </span>
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </section>
        </>
      )}
    </div>
  );
}
