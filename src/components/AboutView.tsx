import {
  ArrowUpRight,
  Award,
  CheckCircle2,
  Code2,
  Compass,
  Cpu,
  ExternalLink,
  FileText,
  Globe,
  History,
  Home,
  Info,
  Layers,
  Lock,
  Network,
  Radar,
  Scale,
  ScanSearch,
  Send,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
} from 'lucide-react';
import type { AppPage, Language, ProviderDescriptor } from '../types/scan';
import { tOperationalState, UI_COPY } from '../i18n/translations';
import { BrandMark } from './BrandMark';
import {
  BinaryInspectorVisual,
  DomainArchitectureVisual,
  HeroTelemetryIllustration,
  SourceCodeForensicsVisual,
  SubdomainDnsTopologyVisual,
  ThreatIntelNetworkVisual,
} from './CyberIllustrations';
import { CyberMascot } from './CyberMascot';
import { CyberSticker } from './CyberStickers';

interface AboutViewProps {
  lang: Language;
  providers: ProviderDescriptor[];
  onNavigate?: (page: Exclude<AppPage, 'error'>) => void;
}

export function AboutView({ lang, providers, onNavigate }: AboutViewProps) {
  const isAr = lang === 'ar';

  const differentiators = [
    {
      icon: Cpu,
      tag: '01 · ZERO-AI DETERMINISTIC',
      title: {
        en: 'Pure Rule-Weighted Evidence (No AI Guesswork)',
        ar: 'تحليل حتمي بالأدلة القواعدية (بدون تخمين الذكاء الاصطناعي)',
      },
      detail: {
        en: 'Every classification and risk score is computed deterministically from inspectable network, TLS, DOM, and threat-feed evidence—never probabilistic LLM opinions.',
        ar: 'كل تصنيف ودرجة خطورة يُحتسب حتمياً من أدلة الشبكة والشهادات وDOM واستخبارات التهديدات القابلة للتدقيق، دون أي تخمين عشوائي.',
      },
    },
    {
      icon: Globe,
      tag: '02 · OFFICIAL DOMAIN & RELATIONSHIPS',
      title: {
        en: 'Official Brand & Parent-Service Recognition',
        ar: 'التحقق الذكي من النطاقات الرسمية وعلاقات الخدمات',
      },
      detail: {
        en: 'Distinguishes verified eTLD+1 roots, corporate subsidiaries, and legitimate CDNs across Google, Meta, GitHub, Microsoft, and partners to eliminate false positives.',
        ar: 'يميّز بين النطاقات الرسمية والشركات الأم والشركاء المعتمدين مثل Google وMeta وGitHub وMicrosoft لمنع الإنذارات الكاذبة.',
      },
    },
    {
      icon: Network,
      tag: '03 · HOP-BY-HOP SSRF GUARD',
      title: {
        en: 'Pre- & Post-Redirect DNS Pinning Protection',
        ar: 'حماية SSRF وتثبيت DNS في كل قفزة توجيه',
      },
      detail: {
        en: 'Resolves and validates public IP ranges before every hop to block loopback, internal RFC1918 networks, link-local, and cloud metadata gateways.',
        ar: 'يفحص عناوين IP قبل وبعد كل قفزة إعادة توجيه لمنع الوصول للشبكات الداخلية أو بوابات البيانات السحابية.',
      },
    },
    {
      icon: ShieldCheck,
      tag: '04 · TRANSPARENT FEED HONESTY',
      title: {
        en: 'Never Counts Missing Data as "Safe"',
        ar: 'شفافية تامة: نقص المصادر لا يُحتسب أماناً',
      },
      detail: {
        en: 'If a feed is rate-limited, offline, or unauthenticated on the server, Scan Link SM marks the gap explicitly rather than inflating trust.',
        ar: 'إذا كان أحد المزودين متوقفاً أو يتطلب مفتاح توثيق، تعلن المنصة ذلك بوضوح ولا ترفع درجة الأمان بالخطأ.',
      },
    },
    {
      icon: ScanSearch,
      tag: '05 · IN-MEMORY NON-EXECUTION',
      title: {
        en: 'Static DOM & Magic-Byte RAM Inspection',
        ar: 'فحص ساكن بالذاكرة دون تشغيل سكربتات أو ملفات',
      },
      detail: {
        en: 'Inspects credential traps, redirect lures, SHA-256 hashes, and binary signatures strictly in memory without executing target JavaScript or payloads.',
        ar: 'يحلل حقول سرقة البيانات والتوقيع الثنائي وبصمة SHA-256 داخل الذاكرة فقط دون تشغيل أكواد أو حفظ ملفات.',
      },
    },
    {
      icon: Lock,
      tag: '06 · BACKEND KEY ISOLATION',
      title: {
        en: 'Server-Only Threat Feed Credentials',
        ar: 'عزل تام لمفاتيح الاستخبارات على الخادم',
      },
      detail: {
        en: 'All provider keys, rate-limit controls, and security headers remain strictly server-side and are never exposed in client bundles or responses.',
        ar: 'جميع مفاتيح المزودين وضوابط المعدل تُدار حصراً على الخادم الخلفي ولا تُرسل أبداً إلى المتصفح أو ملفات الواجهة.',
      },
    },
  ];

  const stack = [
    {
      name: 'Deterministic Correlation Engine',
      role: {
        en: 'Pure rule-weighted evidence scoring & multi-signal phishing correlation (Zero AI)',
        ar: 'محرك ارتباط قواعدي حتمي لاحتساب المخاطر وكشف التصيد (بدون ذكاء اصطناعي)',
      },
    },
    {
      name: 'Official Domain & Relationship Registry',
      role: {
        en: 'PSL eTLD+1 verification, corporate ownership records, and service relationship analysis',
        ar: 'التحقق من النطاقات الرسمية عبر PSL وبيانات الملكية وتحليل العلاقات بين الخدمات',
      },
    },
    {
      name: 'SSRF & DNS Pinning Guard',
      role: {
        en: 'Blocks private CIDRs, localhost, link-local, and cloud metadata IPs at every hop',
        ar: 'حظر الشبكات الداخلية وعناوين البيانات السحابية قبل وبعد كل قفزة توجيه',
      },
    },
    {
      name: 'Node TLS + IANA RDAP + DoH',
      role: {
        en: 'Direct X.509 handshake, registry RDAP lookup, and Cloudflare DoH verification',
        ar: 'فحص شهادات الخادم وبيانات التسجيل الرسمية والتحقق عبر DoH',
      },
    },
    {
      name: 'Static Cheerio DOM Inspector',
      role: {
        en: 'Analyzes credential fields, lures, scripts, and brand clones without executing JS',
        ar: 'تحليل DOM لكشف حقول السرقة وانتحال العلامات دون تنفيذ جافاسكربت',
      },
    },
    {
      name: 'In-Memory File Signature Check',
      role: {
        en: 'SHA-256 hashing and magic-byte vs MIME verification without writing binaries to disk',
        ar: 'فحص التوقيع الثنائي وبصمة SHA-256 في الذاكرة دون حفظ أو تشغيل الملفات',
      },
    },
    {
      name: 'External Cloud Browser Service (Level B)',
      role: {
        en: 'Optional server-configured isolated runtime execution capturing screenshots, outbound network calls, and permissions without local browser overhead',
        ar: 'تنفيذ معزول اختياري عبر خدمة متصفح خارجي سحابي مضبوطة بالخادم (.env) لالتقاط الشاشة ورصد الطلبات الشبكية والصلاحيات دون أعباء محلية',
      },
    },
  ];

  const siteRoutes: Array<{
    page: Exclude<AppPage, 'error'>;
    path: string;
    icon: typeof Home;
    group: 'core' | 'governance';
    title: { en: string; ar: string };
    summary: { en: string; ar: string };
  }> = [
    {
      page: 'home',
      path: '/',
      icon: Home,
      group: 'core',
      title: { en: 'Home & Quick URL Scanner', ar: 'الصفحة الرئيسية والفحص السريع' },
      summary: {
        en: 'Platform overview, instant URL input, viewport options, and recent local telemetry.',
        ar: 'الواجهة الرئيسية لإدخال الروابط مباشرة مع خيارات المعاينة وآخر الفحوصات المحلية.',
      },
    },
    {
      page: 'scanner',
      path: '/scanner',
      icon: Radar,
      group: 'core',
      title: { en: 'Live 16-Layer Scan Workspace', ar: 'مساحة الفحص المباشر من ١٦ طبقة' },
      summary: {
        en: 'Real-time SSE execution stages, forensic domain verification box, and structured reports.',
        ar: 'متابعة مراحل الفحص لحظياً عبر SSE وصندوق التحقق الرسمي والتقرير الجنائي المفصل.',
      },
    },
    {
      page: 'providers',
      path: '/providers',
      icon: Layers,
      group: 'core',
      title: { en: 'Live Providers & Layer Topology Map', ar: 'خريطة المزودين وطبقات الفحص المباشرة' },
      summary: {
        en: 'Interactive 4-layer architecture map, live server health telemetry, and per-feed controls.',
        ar: 'خريطة تفاعلية لطبقات الفحص الأربع وقوة المزودين وحالة الخادم اللحظية.',
      },
    },
    {
      page: 'history',
      path: '/history',
      icon: History,
      group: 'core',
      title: { en: 'Local Consented Scan Archive', ar: 'سجل الفحوصات المحلي' },
      summary: {
        en: 'Inspect, search, re-open, or purge previously saved reports stored strictly in your browser.',
        ar: 'استعراض التقارير السابقة والبحث فيها أو حذفها محلياً داخل متصفحك فقط.',
      },
    },
    {
      page: 'about',
      path: '/about',
      icon: Info,
      group: 'governance',
      title: { en: 'About Scan Link SM & Platform Advantages', ar: 'عن المنصة وما يميزها وخريطة الموقع' },
      summary: {
        en: 'Official developer identity, engineering differentiators, interactive site map, and feed status.',
        ar: 'الهوية الرسمية للمطور، ومزايا المنصة التنافسية، وخريطة التنقل الكاملة، وحالة المزودين.',
      },
    },
    {
      page: 'privacy',
      path: '/privacy',
      icon: Lock,
      group: 'governance',
      title: { en: 'Privacy & Storage Controls', ar: 'سياسة الخصوصية وضوابط التخزين' },
      summary: {
        en: 'Zero third-party tracking cookies, explicit local storage consent, and backend key isolation.',
        ar: 'تفاصيل عدم استخدام ملفات التتبع وموافقة التخزين المحلي وعزل مفاتيح الخادم.',
      },
    },
    {
      page: 'terms',
      path: '/terms',
      icon: Scale,
      group: 'governance',
      title: { en: 'Terms of Authorized Use', ar: 'شروط الاستخدام المصرح به' },
      summary: {
        en: 'Authorized inspection scope, proprietary rights of Mohamed Abu AlSaud SM, and usage boundaries.',
        ar: 'ضوابط الفحص المصرح به وحقوق الملكية الخاصة بالمطور وضمانات الاستخدام الآمن.',
      },
    },
  ];

  const coreRoutes = siteRoutes.filter((r) => r.group === 'core');
  const governanceRoutes = siteRoutes.filter((r) => r.group === 'governance');

  return (
    <section className="mx-auto max-w-6xl space-y-10 px-4 py-12 sm:px-6 lg:px-8">
      {/* Header */}
      <div className="grid grid-cols-1 gap-8 lg:grid-cols-12 lg:items-center">
        <div className="lg:col-span-5 space-y-4">
          <div className="flex items-center gap-3">
            <CyberMascot state="idle" size={72} />
            <BrandMark className="h-12 w-auto max-w-[230px]" />
          </div>
          <div>
            <h1 className="font-display text-3xl font-extrabold text-zinc-950 dark:text-white">
              {UI_COPY.about.title[lang]}
            </h1>
            <p className="mt-1 text-xs font-bold text-[#FF263F]">{UI_COPY.brand.tagline[lang]}</p>
          </div>
          <p className="text-sm leading-relaxed text-zinc-700 dark:text-zinc-300 sm:text-base">
            {UI_COPY.about.description[lang]}
          </p>
        </div>
        <div className="lg:col-span-7">
          <HeroTelemetryIllustration lang={lang} />
        </div>
      </div>

      {/* Principles, Proprietary Ownership & Developer Identity */}
      <div className="grid grid-cols-1 gap-5 md:grid-cols-3">
        <div className="rounded-xl border border-[#E5E7EB] bg-white p-6 dark:border-[#202020] dark:bg-[#0D0D0D]">
          <div className="flex items-center gap-2 text-[#FF263F]">
            <ShieldAlert className="h-5 w-5 shrink-0" aria-hidden="true" />
            <h2 className="font-display text-lg font-bold text-zinc-950 dark:text-white">
              {UI_COPY.about.missionTitle[lang]}
            </h2>
          </div>
          <p className="mt-3 text-sm leading-relaxed text-zinc-600 dark:text-zinc-400">
            {UI_COPY.about.missionBody[lang]}
          </p>
        </div>

        <div className="rounded-xl border border-[#E5E7EB] bg-white p-6 dark:border-[#202020] dark:bg-[#0D0D0D]">
          <div className="flex items-center gap-2 text-[#FF263F]">
            <Code2 className="h-5 w-5 shrink-0" aria-hidden="true" />
            <h2 className="font-display text-lg font-bold text-zinc-950 dark:text-white">
              {UI_COPY.about.proprietaryTitle[lang]}
            </h2>
          </div>
          <p className="mt-3 text-sm leading-relaxed text-zinc-600 dark:text-zinc-400">
            {UI_COPY.about.proprietaryBody[lang]}
          </p>
          <div className="mt-4 rounded-lg border border-zinc-200 bg-[#F7F7F7] px-3.5 py-2.5 text-xs font-mono text-zinc-600 dark:border-[#202020] dark:bg-black dark:text-zinc-400">
            {UI_COPY.about.proprietaryBadge[lang]}
          </div>
        </div>

        <div className="rounded-xl border border-[#E5E7EB] bg-white p-6 dark:border-[#202020] dark:bg-[#0D0D0D]">
          <div className="flex items-center gap-2 text-[#FF263F]">
            <UserCheck className="h-5 w-5 shrink-0" aria-hidden="true" />
            <h2 className="font-display text-lg font-bold text-zinc-950 dark:text-white">
              {UI_COPY.about.developerTitle[lang]}
            </h2>
          </div>

          <div className="mt-3 space-y-2">
            <p className="font-mono text-[11px] font-semibold text-[#FF263F]">
              {UI_COPY.about.developerTitle[lang]}
            </p>
            <p className="text-base font-bold text-zinc-950 dark:text-white">
              {UI_COPY.about.developerName[lang]}
            </p>
          </div>

          <p className="mt-3 text-xs text-zinc-500 dark:text-zinc-400">
            {UI_COPY.about.contactLabel[lang]}:{' '}
            <span dir="ltr" className="font-mono font-semibold text-[#FF263F]">
              @A_Y_TR
            </span>
          </p>
          <div className="mt-3 flex flex-wrap gap-3 text-xs">
            <a
              href={UI_COPY.brand.telegramUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] px-3.5 py-2 font-semibold text-zinc-900 hover:border-[#FF263F] hover:text-[#FF263F] dark:border-[#202020] dark:bg-black dark:text-zinc-200 transition-colors"
            >
              <Send className="h-3.5 w-3.5 text-[#FF263F]" aria-hidden="true" />
              <span dir="ltr">Telegram @A_Y_TR</span>
              <ExternalLink className="h-3 w-3 opacity-70" aria-hidden="true" />
            </a>
          </div>
        </div>
      </div>

      {/* What Distinguishes Scan Link SM */}
      <div className="rounded-xl border border-[#E5E7EB] bg-white p-6 dark:border-[#202020] dark:bg-[#0D0D0D]">
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12 lg:items-center">
          <div className="lg:col-span-5 space-y-3">
            <div className="flex items-center gap-2 text-[#FF263F]">
              <Award className="h-5 w-5 shrink-0" aria-hidden="true" />
              <span className="font-mono text-xs font-bold uppercase tracking-wider">
                {isAr ? 'مزايا المنصة التنافسية' : 'COMPETITIVE ADVANTAGES'}
              </span>
            </div>
            <h2 className="font-display text-2xl font-extrabold text-zinc-950 dark:text-white">
              {isAr ? 'ما يميز منصة Scan Link SM عن غيرها' : 'What Distinguishes Scan Link SM'}
            </h2>
            <p className="text-sm leading-relaxed text-zinc-600 dark:text-zinc-400">
              {isAr
                ? 'على عكس فاحصات الروابط التقليدية التي تعتمد على قائمة سوداء واحدة أو تحليلات غامضة، تجمع Scan Link SM بين التحقق الرسمي من ملكية النطاقات، وحماية SSRF متعددة القفزات، والفحص الساكن في الذاكرة ضمن محرك حتمي شفاف.'
                : 'Unlike basic single-lookup checkers or opaque heuristics, Scan Link SM pairs verified brand-relationship intelligence with hop-by-hop SSRF isolation and non-executing in-memory telemetry inside one transparent engine.'}
            </p>
          </div>
          <div className="lg:col-span-7">
            <DomainArchitectureVisual lang={lang} />
          </div>
        </div>

        <div className="mt-6 grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {differentiators.map((item, idx) => {
            const Icon = item.icon;
            const stickerTypes = ['shield', 'dns_globe', 'network', 'radar', 'source_code', 'vault_shield'] as const;
            return (
              <div
                key={item.tag}
                className="min-w-0 rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-4 dark:border-[#202020] dark:bg-black"
              >
                <div className="flex items-center justify-between gap-2">
                  <span dir="ltr" className="font-mono text-[11px] font-bold text-[#FF263F]">
                    {item.tag}
                  </span>
                  <div className="flex items-center gap-1.5">
                    <CyberSticker type={stickerTypes[idx % stickerTypes.length]} size={28} interactive={false} />
                    <Icon className="h-3.5 w-3.5 shrink-0 text-zinc-400" aria-hidden="true" />
                  </div>
                </div>
                <h3 className="mt-2 font-display text-sm font-bold text-zinc-950 dark:text-white">
                  {item.title[lang]}
                </h3>
                <p className="mt-1.5 text-xs leading-relaxed text-zinc-600 dark:text-zinc-400">
                  {item.detail[lang]}
                </p>
              </div>
            );
          })}
        </div>

        <div className="mt-6 grid grid-cols-1 gap-5 lg:grid-cols-2">
          <SourceCodeForensicsVisual lang={lang} />
          <SubdomainDnsTopologyVisual lang={lang} />
        </div>
      </div>

      {/* Interactive Site Map */}
      <div className="rounded-xl border border-[#E5E7EB] bg-white p-6 dark:border-[#202020] dark:bg-[#0D0D0D]">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#E5E7EB] pb-4 dark:border-[#202020]">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-[#FF263F]">
              <Compass className="h-5 w-5 shrink-0" aria-hidden="true" />
              <span className="font-mono text-xs font-bold uppercase tracking-wider">
                {isAr ? 'خريطة التنقل المباشر' : 'INTERACTIVE PLATFORM MAP'}
              </span>
            </div>
            <h2 className="font-display text-xl font-extrabold text-zinc-950 dark:text-white">
              {isAr ? 'خريطة موقع Scan Link SM' : 'Scan Link SM Site Map'}
            </h2>
            <p className="text-xs text-zinc-600 dark:text-zinc-400">
              {isAr
                ? 'انتقل مباشرة إلى أي وحدة فحص أو صفحة تعريفية أو ملف فهرسة رسمي في المنصة.'
                : 'Jump directly to any operational workspace, governance page, or crawler discovery endpoint.'}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <a
              href="/sitemap.xml"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] px-3 py-2 font-mono font-semibold text-zinc-800 hover:border-[#FF263F] hover:text-[#FF263F] dark:border-[#202020] dark:bg-black dark:text-zinc-200 transition-colors"
            >
              <FileText className="h-3.5 w-3.5 text-[#FF263F]" aria-hidden="true" />
              <span dir="ltr">/sitemap.xml</span>
              <ExternalLink className="h-3 w-3 opacity-70" aria-hidden="true" />
            </a>
            <a
              href="/robots.txt"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] px-3 py-2 font-mono font-semibold text-zinc-800 hover:border-[#FF263F] hover:text-[#FF263F] dark:border-[#202020] dark:bg-black dark:text-zinc-200 transition-colors"
            >
              <FileText className="h-3.5 w-3.5 text-[#FF263F]" aria-hidden="true" />
              <span dir="ltr">/robots.txt</span>
              <ExternalLink className="h-3 w-3 opacity-70" aria-hidden="true" />
            </a>
          </div>
        </div>

        <div className="mt-5 grid grid-cols-1 gap-6 lg:grid-cols-12 lg:items-start">
          <div className="lg:col-span-8 space-y-5">
            <div>
              <p className="mb-2.5 text-xs font-bold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                {isAr ? 'وحدات الفحص والاستخبارات الأساسية' : 'Core Inspection & Telemetry Workspaces'}
              </p>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                {coreRoutes.map((route) => {
                  const Icon = route.icon;
                  return (
                    <button
                      key={route.path}
                      type="button"
                      onClick={() => onNavigate?.(route.page)}
                      className="group flex min-w-0 flex-col justify-between rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-4 text-start transition-colors hover:border-[#FF263F] dark:border-[#202020] dark:bg-black"
                    >
                      <div>
                        <div className="flex items-center justify-between gap-2">
                          <span className="inline-flex items-center gap-2 text-sm font-bold text-zinc-950 group-hover:text-[#FF263F] dark:text-white transition-colors">
                            <Icon className="h-4 w-4 shrink-0 text-[#FF263F]" aria-hidden="true" />
                            <span>{route.title[lang]}</span>
                          </span>
                          <ArrowUpRight
                            className="h-4 w-4 shrink-0 text-zinc-400 group-hover:text-[#FF263F] transition-colors"
                            aria-hidden="true"
                          />
                        </div>
                        <p className="mt-1.5 text-xs leading-relaxed text-zinc-600 dark:text-zinc-400">
                          {route.summary[lang]}
                        </p>
                      </div>
                      <p dir="ltr" className="mt-2.5 font-mono text-[11px] font-semibold text-zinc-500">
                        {route.path}
                      </p>
                    </button>
                  );
                })}
              </div>
            </div>

            <div>
              <p className="mb-2.5 text-xs font-bold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                {isAr ? 'الهوية والحوكمة والخصوصية' : 'Platform Identity, Privacy & Governance'}
              </p>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                {governanceRoutes.map((route) => {
                  const Icon = route.icon;
                  const isCurrent = route.page === 'about';
                  return (
                    <button
                      key={route.path}
                      type="button"
                      onClick={() => onNavigate?.(route.page)}
                      className={`group flex min-w-0 flex-col justify-between rounded-lg border p-3.5 text-start transition-colors ${
                        isCurrent
                          ? 'border-[#FF263F] bg-white dark:bg-[#080808]'
                          : 'border-[#E5E7EB] bg-[#F7F7F7] hover:border-[#FF263F] dark:border-[#202020] dark:bg-black'
                      }`}
                    >
                      <div>
                        <div className="flex items-center justify-between gap-2">
                          <Icon className="h-4 w-4 shrink-0 text-[#FF263F]" aria-hidden="true" />
                          <span dir="ltr" className="font-mono text-[11px] text-zinc-500">
                            {route.path}
                          </span>
                        </div>
                        <p className="mt-2 text-xs font-bold text-zinc-950 group-hover:text-[#FF263F] dark:text-white transition-colors">
                          {route.title[lang]}
                        </p>
                        <p className="mt-1 text-[11px] leading-relaxed text-zinc-600 dark:text-zinc-400">
                          {route.summary[lang]}
                        </p>
                      </div>
                      {isCurrent && (
                        <p className="mt-2 text-[11px] font-semibold text-[#FF263F]">
                          {isAr ? 'الصفحة الحالية' : 'Current View'}
                        </p>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          <div className="lg:col-span-4 space-y-3">
            <ThreatIntelNetworkVisual lang={lang} />
            <div className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-4 text-xs dark:border-[#202020] dark:bg-black">
              <p className="font-bold text-zinc-950 dark:text-white">
                {isAr ? 'مؤشر الجاهزية الفورية' : 'Platform Structural Summary'}
              </p>
              <p className="mt-1.5 leading-relaxed text-zinc-600 dark:text-zinc-400 tabular-nums">
                {isAr
                  ? `7 مسارات تطبيق نشطة · ${providers.length} مزود استخبارات مسجل · تشفير ونطاقات رسمية موثقة`
                  : `7 application routes · ${providers.length} registered intelligence feeds · strict SSRF isolation`}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Architecture Stack */}
      <div className="rounded-xl border border-[#E5E7EB] bg-white p-6 dark:border-[#202020] dark:bg-[#0D0D0D]">
        <h2 className="font-display text-lg font-bold text-zinc-950 dark:text-white">
          {UI_COPY.about.methodologyTitle[lang]}
        </h2>
        <div className="mt-4 grid grid-cols-1 gap-6 lg:grid-cols-12 lg:items-center">
          <div className="lg:col-span-7 grid grid-cols-1 gap-4 sm:grid-cols-2">
            {stack.map((item) => (
              <div
                key={item.name}
                className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-4 dark:border-[#202020] dark:bg-black"
              >
                <p className="font-mono text-xs font-bold text-[#FF263F]">{item.name}</p>
                <p className="mt-1.5 text-xs leading-relaxed text-zinc-600 dark:text-zinc-400">
                  {item.role[lang]}
                </p>
              </div>
            ))}
          </div>
          <div className="lg:col-span-5">
            <BinaryInspectorVisual lang={lang} />
          </div>
        </div>
      </div>

      {/* Live Providers Snapshot */}
      <div className="rounded-xl border border-[#E5E7EB] bg-white p-6 dark:border-[#202020] dark:bg-[#0D0D0D]">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="font-display text-lg font-bold text-zinc-950 dark:text-white">
            {UI_COPY.homeSections.providersTitle[lang]}
          </h2>
          {onNavigate && (
            <button
              type="button"
              onClick={() => onNavigate('providers')}
              className="inline-flex items-center gap-1.5 text-xs font-bold text-[#FF263F] hover:underline"
            >
              <span>{isAr ? 'عرض الخريطة الكاملة للمزودين' : 'Open Live Provider Map'}</span>
              <ArrowUpRight className="h-3.5 w-3.5" aria-hidden="true" />
            </button>
          )}
        </div>
        <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {providers.map((p) => {
            const ok = p.operationalState === 'active' || p.operationalState === 'configured';
            return (
              <div
                key={p.id}
                className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-3.5 text-xs dark:border-[#202020] dark:bg-black"
              >
                <p className="font-bold text-zinc-950 dark:text-white">{p.name}</p>
                <p className="mt-0.5 text-zinc-500">{p.category}</p>
                <p
                  className={`mt-2 inline-flex items-center gap-1 font-semibold ${
                    ok ? 'text-[#16A34A]' : 'text-[#F59E0B]'
                  }`}
                >
                  <CheckCircle2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                  <span>{tOperationalState(p.operationalState, lang)}</span>
                </p>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
