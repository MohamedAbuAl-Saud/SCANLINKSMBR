import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowDown,
  ArrowRight,
  ArrowUp,
  Camera,
  Check,
  CheckCircle2,
  Clock,
  Cpu,
  Database,
  Globe,
  KeyRound,
  Layers,
  LayoutGrid,
  List,
  Lock,
  Network,
  Power,
  Radio,
  RefreshCw,
  RotateCcw,
  Search,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  XCircle,
} from 'lucide-react';
import type { Language, ProviderDescriptor, ProviderOperationalState } from '../types/scan';
import { tOperationalState, UI_COPY } from '../i18n/translations';
import { cyberAudio } from '../utils/cyberAudio';
import { SubdomainDnsTopologyVisual, ThreatIntelNetworkVisual } from './CyberIllustrations';
import { CyberMascot } from './CyberMascot';
import { CyberSticker } from './CyberStickers';

interface ProvidersViewProps {
  lang: Language;
  providers: ProviderDescriptor[];
  disabledProviders: string[];
  onToggleProvider: (id: string) => void;
  onSetDisabledProviders: (ids: string[]) => void;
  onRefresh: () => void;
  onOpenScanner: () => void;
}

type LayerId = 'edge_dns' | 'threat_feeds' | 'host_certs' | 'visual_capture';
type SelectedMapNode =
  | { kind: 'core_guard' }
  | { kind: 'layer'; layerId: LayerId }
  | { kind: 'provider'; providerId: string }
  | { kind: 'correlation_core' };

type StackPresetId = 'full_fortress' | 'zero_key_only' | 'threat_core' | 'fast_surface' | 'custom';

interface HealthSnapshot {
  status: string;
  service: string;
  engineMode: string;
  timestamp: string;
  officialRegistryStats?: {
    entityCount: number;
    officialDomainCount: number;
    authorizedProviderCount: number;
    paasSuffixCount: number;
    categoryCount: number;
  };
  capabilities: {
    ssrfGuard: boolean;
    dnsAndRdap: boolean;
    tlsSocketInspection: boolean;
    staticHtmlAndBrandAnalysis: boolean;
    websiteSourceIntelligence: boolean;
    multiPageDiscovery: boolean;
    inMemoryFileHeaderCheck: boolean;
    screenshotNeoConfigured: boolean;
    externalCloudBrowserConfigured?: boolean;
  };
}

interface LayerDefinition {
  id: LayerId;
  code: string;
  icon: typeof Layers;
  providerIds: string[];
  title: { en: string; ar: string };
  shortTitle: { en: string; ar: string };
  desc: { en: string; ar: string };
  coreModules: { en: string[]; ar: string[] };
  weightShare: number;
}

const DEFAULT_LAYER_ORDER: LayerId[] = ['edge_dns', 'threat_feeds', 'host_certs', 'visual_capture'];
const LAYER_ORDER_KEY = 'scanlink_layer_order';

function loadInitialLayerOrder(): LayerId[] {
  try {
    const raw = localStorage.getItem(LAYER_ORDER_KEY);
    if (!raw) return DEFAULT_LAYER_ORDER;
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return DEFAULT_LAYER_ORDER;
    const valid = parsed.filter((id): id is LayerId => DEFAULT_LAYER_ORDER.includes(id as LayerId));
    const missing = DEFAULT_LAYER_ORDER.filter((id) => !valid.includes(id));
    return valid.length > 0 ? [...valid, ...missing] : DEFAULT_LAYER_ORDER;
  } catch {
    return DEFAULT_LAYER_ORDER;
  }
}

const LAYER_CATALOG: Record<LayerId, LayerDefinition> = {
  edge_dns: {
    id: 'edge_dns',
    code: 'L1',
    icon: Globe,
    providerIds: ['cloudflare_security_dns', 'doh', 'rdap'],
    title: { en: 'Edge, DNS & Ownership Auth', ar: 'النطاق و DNS وإثبات الملكية' },
    shortTitle: { en: 'Edge & DNS', ar: 'النطاق و DNS' },
    desc: {
      en: 'Resolves PSL official domain ownership, IANA RDAP registries, OS DNS + Cloudflare DoH/DNSSEC, and 1.1.1.2 malware DNS filtering.',
      ar: 'تتحقق من الملكية الرسمية للنطاق، وسجلات IANA RDAP، وDNS/DNSSEC، ومرشح Cloudflare الأمني 1.1.1.2.',
    },
    coreModules: {
      en: ['SSRF IPv4/IPv6 CIDR Guard', 'Official Domain Registry (PSL)', 'IANA RDAP & WHOIS Lookup', 'Cloudflare DoH + 1.1.1.2'],
      ar: ['حماية SSRF ضد الشبكات الخاصة', 'سجل النطاقات الرسمية المعتمد', 'استعلام RDAP و WHOIS', 'فحص DNSSEC ومرشح 1.1.1.2'],
    },
    weightShare: 25,
  },
  threat_feeds: {
    id: 'threat_feeds',
    code: 'L2',
    icon: Shield,
    providerIds: ['virustotal', 'urlhaus', 'openphish', 'phishstats', 'otx', 'feodotracker'],
    title: { en: 'Multi-Feed Threat Intelligence', ar: 'استخبارات التهديدات متعددة المصادر' },
    shortTitle: { en: 'Threat Feeds', ar: 'استخبارات التهديدات' },
    desc: {
      en: 'Cross-queries live malware, phishing, reputation engines, threat pulses, and Botnet C2 IP blocklists in parallel.',
      ar: 'تستعلم بالتوازي قواعد التصيد والبرمجيات الخبيثة ومحركات السمعة ونبضات التهديد وخوادم التحكم C2.',
    },
    coreModules: {
      en: ['VirusTotal Multi-Engine', 'URLhaus & Feodo C2', 'OpenPhish & PhishStats', 'AlienVault OTX Pulses'],
      ar: ['محركات VirusTotal المتعددة', 'قوائم URLhaus و Feodo C2', 'قواعد التصيد OpenPhish و PhishStats', 'مؤشرات AlienVault OTX'],
    },
    weightShare: 35,
  },
  host_certs: {
    id: 'host_certs',
    code: 'L3',
    icon: Network,
    providerIds: ['urlscan', 'crtsh', 'shodan_internetdb'],
    title: { en: 'Host, Certs & Static Inspection', ar: 'الشهادات والخادم والمحتوى الساكن' },
    shortTitle: { en: 'Host & Certs', ar: 'الشهادات والخادم' },
    desc: {
      en: 'Inspects X.509 TLS chains, Certificate Transparency logs, Shodan CVEs/ports, static DOM, brand spoofing, and file magic bytes.',
      ar: 'تفحص سلاسل شهادات TLS وسجلات الشفافية والمنافذ والثغرات، وتحلل DOM وانتحال العلامات وبصمة الملفات.',
    },
    coreModules: {
      en: ['X.509 Socket & SAN Chain', 'crt.sh & Shodan CVEs', 'Static DOM & Form Inspector', 'In-Memory File Magic Bytes'],
      ar: ['فحص شهادة TLS وسلسلتها', 'سجلات crt.sh وثغرات Shodan', 'تحليل DOM وحقول الدخول الساكن', 'فحص بصمة الملفات بالذاكرة'],
    },
    weightShare: 25,
  },
  visual_capture: {
    id: 'visual_capture',
    code: 'L4',
    icon: Camera,
    providerIds: ['screenshot_neo', 'external_cloud_browser'],
    title: { en: 'Level B Runtime & Visual Capture', ar: 'التنفيذ السحابي B والمعاينة البصرية' },
    shortTitle: { en: 'Level B & Visual', ar: 'المستوى B والبصرية' },
    desc: {
      en: 'Executes optional Level B runtime analysis via External Cloud Browser Service, captures visual evidence, and correlates all rules.',
      ar: 'ينفّذ فحص المستوى B عبر خدمة متصفح خارجي سحابي مضبوطة بالخادم، ويلتقط المعاينة البصرية، ويربط جميع قواعد التقييم.',
    },
    coreModules: {
      en: ['External Cloud Browser Service (Level B)', 'Server-Isolated Visual Capture', '16-Section Rule Correlation', 'Zero-AI Deterministic Verdict'],
      ar: ['خدمة متصفح خارجي سحابي (المستوى B)', 'التقاط معاينة بصرية معزولة', 'ربط قواعد ١٦ قسماً أمنياً', 'حكم حتمي بدون ذكاء اصطناعي'],
    },
    weightShare: 15,
  },
};

function findProviderLayerId(providerId: string): LayerId {
  for (const id of DEFAULT_LAYER_ORDER) {
    if (LAYER_CATALOG[id].providerIds.includes(providerId)) return id;
  }
  return 'threat_feeds';
}

function OperationalBadge({
  state,
  lang,
}: {
  state: ProviderOperationalState;
  lang: Language;
}) {
  if (state === 'active' || state === 'configured') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#16A34A] whitespace-nowrap shrink-0">
        <CheckCircle2 className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
        <span>{tOperationalState(state, lang)}</span>
      </span>
    );
  }
  if (state === 'auth_required' || state === 'rate_limited') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#F59E0B] whitespace-nowrap shrink-0">
        {state === 'auth_required' ? (
          <KeyRound className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
        ) : (
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
        )}
        <span>{tOperationalState(state, lang)}</span>
      </span>
    );
  }
  if (state === 'disabled') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-zinc-500 dark:text-zinc-400 whitespace-nowrap shrink-0">
        <XCircle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
        <span>{tOperationalState(state, lang)}</span>
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-zinc-500 dark:text-zinc-400 whitespace-nowrap shrink-0">
      <AlertTriangle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
      <span>{tOperationalState(state, lang)}</span>
    </span>
  );
}

export function ProvidersView({
  lang,
  providers,
  disabledProviders,
  onToggleProvider,
  onSetDisabledProviders,
  onRefresh,
  onOpenScanner,
}: ProvidersViewProps) {
  const [showToast, setShowToast] = useState<string | null>(null);
  const [layerOrder, setLayerOrder] = useState<LayerId[]>(loadInitialLayerOrder);
  const [selectedNode, setSelectedNode] = useState<SelectedMapNode>({ kind: 'layer', layerId: 'threat_feeds' });
  const [focusLayer, setFocusLayer] = useState<'all' | LayerId>('all');
  const [animateSignals, setAnimateSignals] = useState(true);
  const [topologyView, setTopologyView] = useState<'mesh' | 'pipeline'>('mesh');
  const [hoveredNodeKey, setHoveredNodeKey] = useState<string | null>(null);
  const [meshZoom, setMeshZoom] = useState<number>(1);
  const [liveSync, setLiveSync] = useState(true);
  const [health, setHealth] = useState<HealthSnapshot | null>(null);
  const [latencyMs, setLatencyMs] = useState<number | null>(null);
  const [lastSyncedAt, setLastSyncedAt] = useState<string | null>(null);
  const [isPolling, setIsPolling] = useState(false);

  // Matrix controls
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'ready' | 'paused'>('all');
  const [matrixMode, setMatrixMode] = useState<'grid' | 'table'>('grid');

  useEffect(() => {
    try {
      localStorage.setItem(LAYER_ORDER_KEY, JSON.stringify(layerOrder));
    } catch {
      // ignore
    }
  }, [layerOrder]);

  const triggerToast = useCallback((message: string) => {
    setShowToast(message);
    setTimeout(() => {
      setShowToast((curr) => (curr === message ? null : curr));
    }, 2200);
  }, []);

  const probeLiveHealth = useCallback(async () => {
    const start = performance.now();
    setIsPolling(true);
    try {
      const res = await fetch('/api/health', { cache: 'no-store' });
      const elapsed = Math.max(1, Math.round(performance.now() - start));
      if (res.ok) {
        const json = (await res.json()) as HealthSnapshot;
        setHealth(json);
        setLatencyMs(elapsed);
        setLastSyncedAt(new Date().toISOString());
      }
    } catch {
      // Keep last known snapshot cleanly
    } finally {
      setIsPolling(false);
    }
  }, []);

  useEffect(() => {
    void probeLiveHealth();
  }, [probeLiveHealth]);

  useEffect(() => {
    if (!liveSync) return;
    const timer = setInterval(() => {
      onRefresh();
      void probeLiveHealth();
    }, 15000);
    return () => clearInterval(timer);
  }, [liveSync, onRefresh, probeLiveHealth]);

  const handleRefreshClick = () => {
    cyberAudio.playRefresh();
    onRefresh();
    void probeLiveHealth();
    triggerToast(lang === 'ar' ? 'تم تحديث الخريطة وحالة مزودي البيانات مباشرة' : 'Live map & provider statuses refreshed');
  };

  const getEffectiveState = useCallback(
    (p: ProviderDescriptor): ProviderOperationalState =>
      p.toggleableInScan && disabledProviders.includes(p.id) ? 'disabled' : p.operationalState,
    [disabledProviders]
  );

  const isProviderReady = useCallback(
    (p: ProviderDescriptor) => {
      const st = getEffectiveState(p);
      return st === 'active' || st === 'configured';
    },
    [getEffectiveState]
  );

  const orderedLayerMetrics = useMemo(() => {
    return layerOrder.map((layerId, stackIndex) => {
      const def = LAYER_CATALOG[layerId];
      const items = providers.filter((p) => def.providerIds.includes(p.id));
      const readyItems = items.filter(isProviderReady);
      const toggleableItems = items.filter((p) => p.toggleableInScan);
      const enabledToggleable = toggleableItems.filter((p) => !disabledProviders.includes(p.id));
      const ratio = items.length > 0 ? readyItems.length / items.length : 1;
      const strengthPct = Math.round(ratio * 100);
      return {
        ...def,
        stackIndex: stackIndex + 1,
        items,
        readyCount: readyItems.length,
        totalCount: items.length,
        toggleableCount: toggleableItems.length,
        enabledToggleableCount: enabledToggleable.length,
        strengthPct,
      };
    });
  }, [layerOrder, providers, isProviderReady, disabledProviders]);

  const activeCount = useMemo(() => providers.filter(isProviderReady).length, [providers, isProviderReady]);
  const zeroKeyCount = useMemo(
    () => providers.filter((p) => !p.requiresKey && isProviderReady(p)).length,
    [providers, isProviderReady]
  );
  const authCloudCount = useMemo(
    () => providers.filter((p) => p.requiresKey && isProviderReady(p)).length,
    [providers, isProviderReady]
  );

  const overallStrengthPct = useMemo(() => {
    if (providers.length === 0) return 0;
    const weighted = orderedLayerMetrics.reduce(
      (acc, lm) => acc + (lm.strengthPct / 100) * lm.weightShare,
      0
    );
    return Math.round(weighted);
  }, [providers.length, orderedLayerMetrics]);

  // Preset state matching
  const presetTargets = useMemo(() => {
    const toggleable = providers.filter((p) => p.toggleableInScan);
    const fullFortress: string[] = [];
    const zeroKeyOnly = toggleable.filter((p) => p.requiresKey).map((p) => p.id);
    const threatCoreKeep = new Set(['virustotal', 'urlhaus', 'openphish', 'phishstats', 'otx', 'feodotracker']);
    const threatCore = toggleable.filter((p) => !threatCoreKeep.has(p.id)).map((p) => p.id);
    const fastKeep = new Set(['cloudflare_security_dns', 'shodan_internetdb', 'urlscan']);
    const fastSurface = toggleable.filter((p) => !fastKeep.has(p.id)).map((p) => p.id);

    return {
      full_fortress: fullFortress,
      zero_key_only: zeroKeyOnly,
      threat_core: threatCore,
      fast_surface: fastSurface,
    };
  }, [providers]);

  const activePreset = useMemo<StackPresetId>(() => {
    const normalize = (arr: string[]) => Array.from(new Set(arr)).sort().join(',');
    const current = normalize(disabledProviders);
    if (current === normalize(presetTargets.full_fortress)) return 'full_fortress';
    if (current === normalize(presetTargets.zero_key_only)) return 'zero_key_only';
    if (current === normalize(presetTargets.threat_core)) return 'threat_core';
    if (current === normalize(presetTargets.fast_surface)) return 'fast_surface';
    return 'custom';
  }, [disabledProviders, presetTargets]);

  const applyPreset = (presetId: Exclude<StackPresetId, 'custom'>, label: string) => {
    cyberAudio.playRefresh();
    onSetDisabledProviders(presetTargets[presetId]);
    triggerToast(label);
  };

  const toggleWholeLayer = (layerId: LayerId) => {
    const layer = orderedLayerMetrics.find((l) => l.id === layerId);
    if (!layer || layer.toggleableCount === 0) return;
    const toggleableIds = layer.items.filter((p) => p.toggleableInScan).map((p) => p.id);
    const allCurrentlyEnabled = toggleableIds.every((id) => !disabledProviders.includes(id));

    if (allCurrentlyEnabled) {
      // Disable all toggleable feeds in this layer
      onSetDisabledProviders([...disabledProviders, ...toggleableIds]);
      triggerToast(
        lang === 'ar'
          ? `تم إيقاف المصادر القابلة للتبديل في ${layer.shortTitle.ar}`
          : `Paused toggleable feeds in ${layer.shortTitle.en}`
      );
    } else {
      // Enable all toggleable feeds in this layer
      const idSet = new Set(toggleableIds);
      onSetDisabledProviders(disabledProviders.filter((id) => !idSet.has(id)));
      triggerToast(
        lang === 'ar'
          ? `تم تفعيل جميع المصادر في ${layer.shortTitle.ar}`
          : `Enabled all feeds in ${layer.shortTitle.en}`
      );
    }
  };

  const moveLayerOrder = (layerId: LayerId, direction: -1 | 1) => {
    setLayerOrder((prev) => {
      const idx = prev.indexOf(layerId);
      const nextIdx = idx + direction;
      if (idx === -1 || nextIdx < 0 || nextIdx >= prev.length) return prev;
      const copy = [...prev];
      const [moved] = copy.splice(idx, 1);
      copy.splice(nextIdx, 0, moved);
      return copy;
    });
  };

  const resetAllComposition = () => {
    cyberAudio.playRefresh();
    setLayerOrder(DEFAULT_LAYER_ORDER);
    onSetDisabledProviders([]);
    setFocusLayer('all');
    setSearchQuery('');
    setStatusFilter('all');
    triggerToast(
      lang === 'ar'
        ? 'تمت استعادة ترتيب الطبقات الافتراضي وتفعيل كامل المصادر'
        : 'Restored default layer stack and enabled all feeds'
    );
  };

  const visibleProviders = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return providers.filter((p) => {
      if (focusLayer !== 'all' && !LAYER_CATALOG[focusLayer].providerIds.includes(p.id)) {
        return false;
      }
      const ready = isProviderReady(p);
      if (statusFilter === 'ready' && !ready) return false;
      if (statusFilter === 'paused' && ready) return false;
      if (q) {
        const hay = `${p.name} ${p.category} ${p.id} ${p.freeTierNote[lang]}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [providers, focusLayer, statusFilter, searchQuery, isProviderReady, lang]);

  const capabilityList = useMemo(() => {
    const caps = health?.capabilities;
    return [
      { key: 'ssrfGuard', active: caps?.ssrfGuard ?? true, label: { en: 'SSRF IPv4/IPv6 Guard', ar: 'حماية SSRF للشبكات' } },
      { key: 'dnsAndRdap', active: caps?.dnsAndRdap ?? true, label: { en: 'DNS & IANA RDAP', ar: 'سجلات DNS و RDAP' } },
      { key: 'tlsSocketInspection', active: caps?.tlsSocketInspection ?? true, label: { en: 'X.509 TLS Socket', ar: 'فحص شهادات TLS' } },
      { key: 'staticHtmlAndBrandAnalysis', active: caps?.staticHtmlAndBrandAnalysis ?? true, label: { en: 'DOM & Brand Auth', ar: 'المحتوى وانتحال العلامات' } },
      { key: 'websiteSourceIntelligence', active: caps?.websiteSourceIntelligence ?? true, label: { en: 'Source Intelligence', ar: 'استخبارات الشيفرة' } },
      { key: 'multiPageDiscovery', active: caps?.multiPageDiscovery ?? true, label: { en: 'Multi-Page Discovery', ar: 'استكشاف الصفحات' } },
      { key: 'inMemoryFileHeaderCheck', active: caps?.inMemoryFileHeaderCheck ?? true, label: { en: 'In-Memory Magic Bytes', ar: 'بصمات الملفات بالذاكرة' } },
      { key: 'screenshotNeoConfigured', active: caps?.screenshotNeoConfigured ?? false, label: { en: 'Visual Preview Gateway', ar: 'بوابة المعاينة البصرية' } },
      { key: 'externalCloudBrowserConfigured', active: caps?.externalCloudBrowserConfigured ?? false, label: { en: 'External Cloud Browser (Level B)', ar: 'متصفح خارجي سحابي (المستوى B)' } },
    ];
  }, [health]);

  const inspectedLayer = useMemo(() => {
    if (selectedNode.kind === 'layer') {
      return orderedLayerMetrics.find((l) => l.id === selectedNode.layerId) || null;
    }
    return null;
  }, [selectedNode, orderedLayerMetrics]);

  const inspectedProvider = useMemo(() => {
    if (selectedNode.kind === 'provider') {
      return providers.find((p) => p.id === selectedNode.providerId) || null;
    }
    return null;
  }, [selectedNode, providers]);

  const registryStats = health?.officialRegistryStats;

  return (
    <section className="relative mx-auto max-w-7xl space-y-6 px-4 py-8 sm:px-6 lg:px-8">
      {showToast && (
        <div
          role="status"
          className="fixed bottom-6 right-6 z-50 flex items-center gap-2 rounded-xl border border-emerald-500/40 bg-zinc-950/95 px-4 py-2.5 text-xs font-semibold text-emerald-400 shadow-2xl backdrop-blur-md"
        >
          <Check className="h-4 w-4 shrink-0" aria-hidden="true" />
          <span>{showToast}</span>
        </div>
      )}

      {/* Workspace Header & Action Controls */}
      <div className="flex flex-col gap-4 border-b border-[#E5E7EB] pb-6 dark:border-[#202020] lg:flex-row lg:items-end lg:justify-between">
        <div className="flex min-w-0 items-center gap-4">
          <div className="hidden sm:flex shrink-0 items-center gap-2">
            <CyberMascot state={isPolling ? 'scanning' : 'idle'} size={76} />
            <CyberSticker type="subdomain_tree" size={44} interactive={false} />
          </div>
          <div className="min-w-0">
            <p className="font-mono text-xs font-bold tracking-wider text-[#FF263F] uppercase">
              {lang === 'ar'
                ? 'شبكة مزودي البيانات التفاعلية · تركيب الطبقات · التحكم المباشر'
                : 'INTERACTIVE NETWORK MESH · LAYER STACKING · LIVE CONTROL'}
            </p>
            <h1 className="mt-1.5 font-display text-2xl font-bold text-zinc-950 dark:text-white sm:text-3xl text-balance">
              {lang === 'ar'
                ? 'خريطة مزودي البيانات التفاعلية وتركيب طبقات الفحص'
                : 'Interactive Provider Network Map & Layer Control'}
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-relaxed text-zinc-600 dark:text-zinc-400">
              {lang === 'ar'
                ? 'استكشف الشبكة التفاعلية لربط مزودي البيانات مع طبقات الفحص من بوابة الإدخال حتى التقييم النهائي، وتتبع المسارات، وتحكم بتشغيل أو إيقاف كل عقدة مباشرة.'
                : 'Explore the interactive network graph linking providers and inspection layers from ingress shield to final correlation, inspect routes, and toggle nodes live.'}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            type="button"
            onClick={() => setLiveSync((v) => !v)}
            aria-pressed={liveSync}
            className={`inline-flex h-10 items-center gap-2 rounded-lg border px-3.5 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF263F] ${
              liveSync
                ? 'border-[#16A34A]/50 bg-[#16A34A]/10 text-[#16A34A]'
                : 'border-[#E5E7EB] bg-white text-zinc-600 dark:border-[#202020] dark:bg-[#0D0D0D] dark:text-zinc-300'
            }`}
          >
            <Radio className={`h-3.5 w-3.5 shrink-0 ${liveSync ? 'animate-pulse' : ''}`} aria-hidden="true" />
            <span>
              {liveSync
                ? lang === 'ar'
                  ? 'مزامنة حية (15ث)'
                  : 'Live Sync (15s)'
                : lang === 'ar'
                  ? 'المزامنة متوقفة'
                  : 'Sync Paused'}
            </span>
          </button>

          <button
            type="button"
            onClick={handleRefreshClick}
            className="inline-flex h-10 items-center gap-2 rounded-lg border border-[#E5E7EB] bg-white px-3.5 text-xs font-semibold text-zinc-900 hover:border-[#FF263F] dark:border-[#202020] dark:bg-[#0D0D0D] dark:text-white transition-colors whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF263F]"
          >
            <RefreshCw className={`h-3.5 w-3.5 shrink-0 ${isPolling ? 'animate-spin' : ''}`} aria-hidden="true" />
            <span>{UI_COPY.providersPage.refresh[lang]}</span>
          </button>

          <button
            type="button"
            onClick={onOpenScanner}
            className="inline-flex h-10 items-center gap-2 rounded-lg bg-[#FF263F] px-4 text-xs font-bold text-white hover:bg-[#E01E35] transition-colors whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF263F]"
          >
            <span>{lang === 'ar' ? 'تطبيق الطبقات وبدء الفحص' : 'Apply Stack & Scan'}</span>
            <ArrowRight className={`h-3.5 w-3.5 shrink-0 ${lang === 'ar' ? 'rotate-180' : ''}`} aria-hidden="true" />
          </button>
        </div>
      </div>

      {/* Live Telemetry Summary Strip (Single Elevation) */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <div className="rounded-xl border border-[#E5E7EB] bg-white p-4 dark:border-[#202020] dark:bg-[#0D0D0D]">
          <div className="flex items-center justify-between gap-2">
            <span className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
              {lang === 'ar' ? 'قوة الحزمة المركّبة' : 'Composed Stack Coverage'}
            </span>
            <ShieldCheck className="h-4 w-4 text-[#16A34A]" aria-hidden="true" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="font-mono text-2xl font-extrabold text-zinc-950 dark:text-white tabular-nums">
              {overallStrengthPct}%
            </span>
            <span className="text-[11px] font-semibold text-[#16A34A] tabular-nums">
              {activeCount}/{providers.length} {lang === 'ar' ? 'نشط' : 'active'}
            </span>
          </div>
          <div className="mt-2.5 h-1.5 w-full overflow-hidden rounded-full bg-zinc-200 dark:bg-[#1E1E1E]">
            <div
              className="h-full bg-gradient-to-r from-[#FF263F] to-[#16A34A] transition-all duration-300"
              style={{ width: `${overallStrengthPct}%` }}
            />
          </div>
        </div>

        <div className="rounded-xl border border-[#E5E7EB] bg-white p-4 dark:border-[#202020] dark:bg-[#0D0D0D]">
          <div className="flex items-center justify-between gap-2">
            <span className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
              {lang === 'ar' ? 'سجل النطاقات الرسمية' : 'Official Domain Registry'}
            </span>
            <Database className="h-4 w-4 text-[#FF263F]" aria-hidden="true" />
          </div>
          <p className="mt-2 font-mono text-2xl font-extrabold text-zinc-950 dark:text-white tabular-nums">
            {registryStats ? registryStats.officialDomainCount.toLocaleString(lang === 'ar' ? 'ar-EG' : 'en-US') : '—'}
          </p>
          <p className="mt-1.5 text-[11px] text-zinc-500 dark:text-zinc-400 tabular-nums">
            {registryStats
              ? lang === 'ar'
                ? `${registryStats.entityCount} جهة موثقة · ${registryStats.authorizedProviderCount} مزود بنية`
                : `${registryStats.entityCount} entities · ${registryStats.authorizedProviderCount} cloud infra groups`
              : lang === 'ar'
                ? 'جارٍ التحقق من السجل...'
                : 'Probing live registry...'}
          </p>
        </div>

        <div className="rounded-xl border border-[#E5E7EB] bg-white p-4 dark:border-[#202020] dark:bg-[#0D0D0D]">
          <div className="flex items-center justify-between gap-2">
            <span className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
              {lang === 'ar' ? 'مفتوحة + سحابية مؤمّنة' : 'Public + Authenticated Feeds'}
            </span>
            <Cpu className="h-4 w-4 text-zinc-500 dark:text-zinc-400" aria-hidden="true" />
          </div>
          <p dir="ltr" className="mt-2 font-mono text-2xl font-extrabold text-zinc-950 dark:text-white tabular-nums">
            {zeroKeyCount} + {authCloudCount}
          </p>
          <p className="mt-1.5 text-[11px] text-zinc-500 dark:text-zinc-400">
            {lang === 'ar' ? 'تلقائي بدون مفتاح + مؤمّن بالخادم' : 'Zero-key public + Server-isolated cloud'}
          </p>
        </div>

        <div className="rounded-xl border border-[#E5E7EB] bg-white p-4 dark:border-[#202020] dark:bg-[#0D0D0D]">
          <div className="flex items-center justify-between gap-2">
            <span className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
              {lang === 'ar' ? 'زمن الاستجابة وآخر مزامنة' : 'Backend Latency & Sync'}
            </span>
            <Activity className="h-4 w-4 text-[#16A34A]" aria-hidden="true" />
          </div>
          <p dir="ltr" className="mt-2 font-mono text-2xl font-extrabold text-zinc-950 dark:text-white tabular-nums">
            {latencyMs !== null ? `${latencyMs} ms` : '—'}
          </p>
          <p dir="ltr" className="mt-1.5 font-mono text-[11px] text-zinc-500 dark:text-zinc-400 tabular-nums">
            {lastSyncedAt
              ? `${lang === 'ar' ? 'تحديث' : 'Sync'} ${new Date(lastSyncedAt).toLocaleTimeString(lang === 'ar' ? 'ar-EG' : 'en-US')}`
              : health?.status === 'ok'
                ? 'Deterministic Ready'
                : 'Connecting...'}
          </p>
        </div>
      </div>

      {/* Layer Topology & Threat Matrix Visual Showcase */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <ThreatIntelNetworkVisual lang={lang} />
        <SubdomainDnsTopologyVisual lang={lang} />
      </div>

      {/* ZONE A: Interactive Live Node-Edge Pipeline Map + Live Node Inspector */}
      <div className="grid grid-cols-1 gap-5 xl:grid-cols-12">
        {/* Interactive Map Canvas (8 cols) */}
        <div className="xl:col-span-8 rounded-2xl border border-[#E5E7EB] bg-white p-4 sm:p-5 dark:border-[#202020] dark:bg-[#0D0D0D]">
          {/* Map Controls Toolbar */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#E5E7EB] pb-4 dark:border-[#202020]">
            <div>
              <h2 className="font-display text-base font-bold text-zinc-950 dark:text-white sm:text-lg">
                {lang === 'ar' ? 'خريطة الشبكة التفاعلية لمزودي البيانات' : 'Interactive Provider Network Graph'}
              </h2>
              <p className="mt-0.5 text-xs text-zinc-500 dark:text-zinc-400">
                {lang === 'ar'
                  ? 'مرر المؤشر أو اضغط على أي عقدة في الشبكة لتتبع مسارها، وفحص طبقتها، أو تشغيلها وإيقافها مباشرة.'
                  : 'Hover or click any node in the mesh to trace upstream/downstream links, inspect layer telemetry, or toggle feeds live.'}
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {/* View Switcher: Interactive Network Graph vs Layered Matrix */}
              <div className="inline-flex rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-0.5 dark:border-[#202020] dark:bg-black">
                <button
                  type="button"
                  onClick={() => setTopologyView('mesh')}
                  className={`inline-flex h-8 items-center gap-1.5 rounded-md px-2.5 text-xs font-semibold transition-colors whitespace-nowrap ${
                    topologyView === 'mesh'
                      ? 'bg-white text-[#FF263F] shadow-sm dark:bg-[#1A1A1A]'
                      : 'text-zinc-600 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white'
                  }`}
                >
                  <Network className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                  <span>{lang === 'ar' ? 'خريطة الشبكة' : 'Network Mesh'}</span>
                </button>
                <button
                  type="button"
                  onClick={() => setTopologyView('pipeline')}
                  className={`inline-flex h-8 items-center gap-1.5 rounded-md px-2.5 text-xs font-semibold transition-colors whitespace-nowrap ${
                    topologyView === 'pipeline'
                      ? 'bg-white text-[#FF263F] shadow-sm dark:bg-[#1A1A1A]'
                      : 'text-zinc-600 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white'
                  }`}
                >
                  <Layers className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                  <span>{lang === 'ar' ? 'طبقات المسار' : 'Pipeline Layers'}</span>
                </button>
              </div>

              {topologyView === 'mesh' && (
                <div className="inline-flex items-center rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-0.5 dark:border-[#202020] dark:bg-black">
                  {[0.85, 1, 1.15].map((z) => (
                    <button
                      key={z}
                      type="button"
                      onClick={() => setMeshZoom(z)}
                      className={`h-8 rounded-md px-2 font-mono text-[11px] font-semibold transition-colors tabular-nums ${
                        meshZoom === z
                          ? 'bg-white text-zinc-950 shadow-sm dark:bg-[#1A1A1A] dark:text-white'
                          : 'text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white'
                      }`}
                    >
                      {Math.round(z * 100)}%
                    </button>
                  ))}
                </div>
              )}

              <button
                type="button"
                onClick={() => setAnimateSignals((v) => !v)}
                aria-pressed={animateSignals}
                className={`inline-flex h-9 items-center gap-1.5 rounded-lg border px-3 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 ${
                  animateSignals
                    ? 'border-[#FF263F]/50 bg-[#FF263F]/10 text-[#FF263F]'
                    : 'border-[#E5E7EB] bg-[#F7F7F7] text-zinc-600 dark:border-[#202020] dark:bg-black dark:text-zinc-400'
                }`}
              >
                <Activity className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                <span>{lang === 'ar' ? 'تدفق الإشارة' : 'Signal Flow'}</span>
              </button>

              <button
                type="button"
                onClick={resetAllComposition}
                className="inline-flex h-9 items-center gap-1.5 rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] px-3 text-xs font-semibold text-zinc-700 hover:border-[#FF263F] dark:border-[#202020] dark:bg-black dark:text-zinc-300 transition-colors whitespace-nowrap shrink-0"
              >
                <RotateCcw className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
                <span>{lang === 'ar' ? 'إعادة ضبط' : 'Reset Map'}</span>
              </button>
            </div>
          </div>

          {/* Layer Focus Filter Bar */}
          <div className="mt-3 flex flex-wrap items-center gap-1.5">
            <button
              type="button"
              onClick={() => setFocusLayer('all')}
              className={`h-8 rounded-lg border px-3 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 ${
                focusLayer === 'all'
                  ? 'border-[#FF263F] bg-[#FF263F] text-white'
                  : 'border-[#E5E7EB] bg-[#F7F7F7] text-zinc-700 hover:border-[#FF263F]/60 dark:border-[#202020] dark:bg-black dark:text-zinc-300'
              }`}
            >
              {lang === 'ar' ? `كامل الشبكة (${providers.length})` : `Full Mesh (${providers.length})`}
            </button>

            {orderedLayerMetrics.map((layer) => {
              const isFocused = focusLayer === layer.id;
              return (
                <button
                  key={layer.id}
                  type="button"
                  onClick={() => {
                    setFocusLayer(isFocused ? 'all' : layer.id);
                    setSelectedNode({ kind: 'layer', layerId: layer.id });
                  }}
                  className={`h-8 rounded-lg border px-3 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 ${
                    isFocused
                      ? 'border-[#FF263F] bg-[#FF263F]/10 text-[#FF263F]'
                      : 'border-[#E5E7EB] bg-[#F7F7F7] text-zinc-700 hover:border-[#FF263F]/60 dark:border-[#202020] dark:bg-black dark:text-zinc-300'
                  }`}
                >
                  <span className="font-mono">{layer.code}</span> · {layer.shortTitle[lang]}
                </button>
              );
            })}
          </div>

          {topologyView === 'mesh' ? (
            /* INTERACTIVE SVG NETWORK GRAPH MESH */
            <div className="relative mt-4 overflow-auto rounded-xl border border-[#E5E7EB] bg-[#070B14] p-3 dark:border-[#202020]">
              <div
                aria-hidden="true"
                className="pointer-events-none absolute inset-0 opacity-35"
                style={{
                  backgroundImage:
                    'radial-gradient(circle, rgba(56,189,248,0.28) 1px, transparent 1px)',
                  backgroundSize: '22px 22px',
                }}
              />

              {(() => {
                const layerCentersY = [105, 240, 385, 510];
                const layerNodeX = 310;
                const ingressPos = { x: 105, y: 300 };
                const egressPos = { x: 935, y: 300 };

                // Compute clean staggered node coordinates for every provider in each layer
                const providerPositions: Array<{
                  provider: ProviderDescriptor;
                  layerId: LayerId;
                  x: number;
                  y: number;
                  layerX: number;
                  layerY: number;
                }> = [];

                orderedLayerMetrics.forEach((layer, layerIdx) => {
                  const ly = layerCentersY[layerIdx] ?? 110 + layerIdx * 130;
                  const count = layer.items.length;
                  layer.items.forEach((p, idx) => {
                    if (count <= 1) {
                      providerPositions.push({ provider: p, layerId: layer.id, x: 615, y: ly, layerX: layerNodeX, layerY: ly });
                    } else if (count <= 3) {
                      const spread = (idx - (count - 1) / 2) * 34;
                      const staggerX = idx % 2 === 0 ? 575 : 675;
                      providerPositions.push({
                        provider: p,
                        layerId: layer.id,
                        x: staggerX,
                        y: ly + spread,
                        layerX: layerNodeX,
                        layerY: ly,
                      });
                    } else {
                      // 4-6 nodes (e.g. Threat Feeds): arrange in staggered two-column arc
                      const col = idx % 2;
                      const row = Math.floor(idx / 2);
                      const rows = Math.ceil(count / 2);
                      const dy = (row - (rows - 1) / 2) * 44;
                      providerPositions.push({
                        provider: p,
                        layerId: layer.id,
                        x: col === 0 ? 535 : 715,
                        y: ly + dy + (col === 1 ? 14 : -10),
                        layerX: layerNodeX,
                        layerY: ly,
                      });
                    }
                  });
                });

                const activeHoverOrSelectLayerId: LayerId | null = hoveredNodeKey?.startsWith('layer:')
                  ? (hoveredNodeKey.replace('layer:', '') as LayerId)
                  : hoveredNodeKey?.startsWith('provider:')
                    ? findProviderLayerId(hoveredNodeKey.replace('provider:', ''))
                    : selectedNode.kind === 'layer'
                      ? selectedNode.layerId
                      : selectedNode.kind === 'provider'
                        ? findProviderLayerId(selectedNode.providerId)
                        : null;

                const highlightedProviderId = hoveredNodeKey?.startsWith('provider:')
                  ? hoveredNodeKey.replace('provider:', '')
                  : selectedNode.kind === 'provider'
                    ? selectedNode.providerId
                    : null;

                return (
                  <div
                    dir="ltr"
                    style={{ width: `${Math.round(meshZoom * 100)}%`, minWidth: '760px' }}
                    className="relative transition-all duration-200"
                  >
                    <svg
                      viewBox="0 0 1050 610"
                      className="w-full h-auto select-none"
                      role="img"
                      aria-label={
                        lang === 'ar'
                          ? 'خريطة الشبكة التفاعلية لمزودي البيانات وطبقات الفحص'
                          : 'Interactive Threat Provider and Layer Network Mesh'
                      }
                    >
                      <defs>
                        <filter id="meshNodeGlow" x="-25%" y="-25%" width="150%" height="150%">
                          <feGaussianBlur stdDeviation="4" result="blur" />
                          <feMerge>
                            <feMergeNode in="blur" />
                            <feMergeNode in="SourceGraphic" />
                          </feMerge>
                        </filter>
                      </defs>

                      {/* Cross-layer inter-mesh links between Layer Hubs */}
                      {orderedLayerMetrics.slice(0, -1).map((layer, i) => {
                        const y1 = layerCentersY[i];
                        const y2 = layerCentersY[i + 1];
                        return (
                          <path
                            key={`inter-${layer.id}`}
                            d={`M ${layerNodeX} ${y1} Q ${layerNodeX - 38} ${(y1 + y2) / 2} ${layerNodeX} ${y2}`}
                            fill="none"
                            stroke="#334155"
                            strokeWidth="1.2"
                            strokeDasharray="4 4"
                            strokeOpacity="0.6"
                          />
                        );
                      })}

                      {/* Ingress -> 4 Layer Hubs Curved Links */}
                      {orderedLayerMetrics.map((layer, idx) => {
                        const ly = layerCentersY[idx];
                        const isFocused = focusLayer === 'all' || focusLayer === layer.id;
                        const isHot =
                          selectedNode.kind === 'core_guard' ||
                          hoveredNodeKey === 'core_guard' ||
                          activeHoverOrSelectLayerId === layer.id;
                        const color = !isFocused
                          ? '#1E293B'
                          : isHot
                            ? '#FF263F'
                            : layer.strengthPct >= 50
                              ? '#10B981'
                              : '#F59E0B';
                        return (
                          <path
                            key={`in-${layer.id}`}
                            d={`M ${ingressPos.x + 62} ${ingressPos.y} C ${ingressPos.x + 135} ${ingressPos.y}, ${layerNodeX - 135} ${ly}, ${layerNodeX - 66} ${ly}`}
                            fill="none"
                            stroke={color}
                            strokeWidth={isHot ? 2.6 : 1.7}
                            strokeOpacity={isFocused ? (isHot ? 0.95 : 0.6) : 0.18}
                            strokeDasharray={animateSignals && isFocused ? '7 5' : undefined}
                          >
                            {animateSignals && isFocused && (
                              <animate
                                attributeName="stroke-dashoffset"
                                from="24"
                                to="0"
                                dur="1.3s"
                                repeatCount="indefinite"
                              />
                            )}
                          </path>
                        );
                      })}

                      {/* Layer Hubs -> Individual Provider Nodes & Provider Nodes -> Egress Correlation Core */}
                      {providerPositions.map(({ provider, layerId, x, y, layerX, layerY }) => {
                        const ready = isProviderReady(provider);
                        const paused = provider.toggleableInScan && disabledProviders.includes(provider.id);
                        const isLayerFocused = focusLayer === 'all' || focusLayer === layerId;
                        const isProviderHot =
                          highlightedProviderId === provider.id ||
                          hoveredNodeKey === `layer:${layerId}` ||
                          (selectedNode.kind === 'layer' && selectedNode.layerId === layerId) ||
                          selectedNode.kind === 'correlation_core' ||
                          hoveredNodeKey === 'correlation_core';
                        const linkColor = !isLayerFocused
                          ? '#1E293B'
                          : paused
                            ? '#475569'
                            : isProviderHot
                              ? '#FF263F'
                              : ready
                                ? '#00E5FF'
                                : '#F59E0B';
                        const opacity = !isLayerFocused ? 0.15 : paused ? 0.35 : isProviderHot ? 0.95 : 0.55;

                        return (
                          <g key={`edges-${provider.id}`}>
                            {/* Layer Hub -> Provider */}
                            <path
                              d={`M ${layerX + 66} ${layerY} C ${layerX + 125} ${layerY}, ${x - 105} ${y}, ${x - 68} ${y}`}
                              fill="none"
                              stroke={linkColor}
                              strokeWidth={isProviderHot ? 2.2 : 1.3}
                              strokeOpacity={opacity}
                              strokeDasharray={paused ? '3 4' : animateSignals && isLayerFocused && ready ? '6 5' : undefined}
                            >
                              {animateSignals && isLayerFocused && ready && !paused && (
                                <animate
                                  attributeName="stroke-dashoffset"
                                  from="22"
                                  to="0"
                                  dur="1.5s"
                                  repeatCount="indefinite"
                                />
                              )}
                            </path>
                            {/* Provider -> Egress Core */}
                            <path
                              d={`M ${x + 68} ${y} C ${x + 120} ${y}, ${egressPos.x - 135} ${egressPos.y}, ${egressPos.x - 64} ${egressPos.y}`}
                              fill="none"
                              stroke={linkColor}
                              strokeWidth={isProviderHot ? 2 : 1.1}
                              strokeOpacity={opacity * 0.85}
                              strokeDasharray={paused ? '3 4' : animateSignals && isLayerFocused && ready ? '5 6' : undefined}
                            >
                              {animateSignals && isLayerFocused && ready && !paused && (
                                <animate
                                  attributeName="stroke-dashoffset"
                                  from="22"
                                  to="0"
                                  dur="1.7s"
                                  repeatCount="indefinite"
                                />
                              )}
                            </path>
                          </g>
                        );
                      })}

                      {/* NODE: INGRESS SSRF SHIELD */}
                      <g
                        transform={`translate(${ingressPos.x}, ${ingressPos.y})`}
                        className="cursor-pointer"
                        role="button"
                        tabIndex={0}
                        onClick={() => setSelectedNode({ kind: 'core_guard' })}
                        onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && setSelectedNode({ kind: 'core_guard' })}
                        onMouseEnter={() => setHoveredNodeKey('core_guard')}
                        onMouseLeave={() => setHoveredNodeKey(null)}
                      >
                        <rect
                          x="-64"
                          y="-34"
                          width="128"
                          height="68"
                          rx="14"
                          fill="#0F172A"
                          stroke={selectedNode.kind === 'core_guard' ? '#FF263F' : '#00E5FF'}
                          strokeWidth={selectedNode.kind === 'core_guard' ? 2.5 : 1.6}
                          filter={selectedNode.kind === 'core_guard' ? 'url(#meshNodeGlow)' : undefined}
                        />
                        <text x="0" y="-10" textAnchor="middle" fill="#FF263F" fontSize="10" fontWeight="700" fontFamily="JetBrains Mono, monospace">
                          INGRESS GATE
                        </text>
                        <text x="0" y="7" textAnchor="middle" fill="#FFFFFF" fontSize="12" fontWeight="700">
                          SSRF Shield
                        </text>
                        <text x="0" y="23" textAnchor="middle" fill="#10B981" fontSize="10" fontFamily="JetBrains Mono, monospace">
                          {registryStats ? `${registryStats.officialDomainCount} DOMAINS` : 'ACTIVE'}
                        </text>
                      </g>

                      {/* NODES: 4 LAYER HUBS */}
                      {orderedLayerMetrics.map((layer, idx) => {
                        const ly = layerCentersY[idx];
                        const isSelected = selectedNode.kind === 'layer' && selectedNode.layerId === layer.id;
                        const isFocused = focusLayer === 'all' || focusLayer === layer.id;
                        const ringColor = isSelected ? '#FF263F' : layer.strengthPct >= 50 ? '#10B981' : '#F59E0B';
                        return (
                          <g
                            key={`hub-${layer.id}`}
                            transform={`translate(${layerNodeX}, ${ly})`}
                            opacity={isFocused ? 1 : 0.3}
                            className="cursor-pointer"
                            role="button"
                            tabIndex={0}
                            onClick={() => setSelectedNode({ kind: 'layer', layerId: layer.id })}
                            onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && setSelectedNode({ kind: 'layer', layerId: layer.id })}
                            onMouseEnter={() => setHoveredNodeKey(`layer:${layer.id}`)}
                            onMouseLeave={() => setHoveredNodeKey(null)}
                          >
                            <rect
                              x="-66"
                              y="-28"
                              width="132"
                              height="56"
                              rx="12"
                              fill="#0B132B"
                              stroke={ringColor}
                              strokeWidth={isSelected ? 2.5 : 1.6}
                              filter={isSelected ? 'url(#meshNodeGlow)' : undefined}
                            />
                            <text x="-48" y="-8" fill="#FF263F" fontSize="10" fontWeight="700" fontFamily="JetBrains Mono, monospace">
                              #{layer.stackIndex} · {layer.code}
                            </text>
                            <text x="48" y="-8" textAnchor="end" fill="#10B981" fontSize="10" fontWeight="700" fontFamily="JetBrains Mono, monospace">
                              {layer.strengthPct}%
                            </text>
                            <text x="0" y="13" textAnchor="middle" fill="#F8FAFC" fontSize="11.5" fontWeight="700">
                              {layer.shortTitle.en}
                            </text>
                          </g>
                        );
                      })}

                      {/* NODES: INDIVIDUAL PROVIDER LEAF NODES */}
                      {providerPositions.map(({ provider, layerId, x, y }) => {
                        const effState = getEffectiveState(provider);
                        const ready = effState === 'active' || effState === 'configured';
                        const paused = provider.toggleableInScan && disabledProviders.includes(provider.id);
                        const isFocused = focusLayer === 'all' || focusLayer === layerId;
                        const isSelected = selectedNode.kind === 'provider' && selectedNode.providerId === provider.id;
                        const borderCol = isSelected
                          ? '#FF263F'
                          : paused
                            ? '#475569'
                            : ready
                              ? '#10B981'
                              : '#F59E0B';
                        const shortName =
                          provider.name.length > 17 ? `${provider.name.slice(0, 15)}..` : provider.name;

                        return (
                          <g
                            key={`pnode-${provider.id}`}
                            transform={`translate(${x}, ${y})`}
                            opacity={isFocused ? (paused ? 0.68 : 1) : 0.22}
                            className="cursor-pointer"
                            role="button"
                            tabIndex={0}
                            onClick={() => setSelectedNode({ kind: 'provider', providerId: provider.id })}
                            onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && setSelectedNode({ kind: 'provider', providerId: provider.id })}
                            onMouseEnter={() => setHoveredNodeKey(`provider:${provider.id}`)}
                            onMouseLeave={() => setHoveredNodeKey(null)}
                          >
                            <rect
                              x="-68"
                              y="-17"
                              width="136"
                              height="34"
                              rx="9"
                              fill={isSelected ? '#1E0B10' : '#0F172A'}
                              stroke={borderCol}
                              strokeWidth={isSelected ? 2.2 : 1.3}
                              filter={isSelected ? 'url(#meshNodeGlow)' : undefined}
                            />
                            <circle
                              cx="-52"
                              cy="0"
                              r="4"
                              fill={ready ? '#10B981' : paused ? '#64748B' : '#F59E0B'}
                            />
                            <text x="-42" y="4" fill="#F8FAFC" fontSize="10.5" fontWeight="600">
                              {shortName}
                            </text>
                            {provider.toggleableInScan && (
                              <g
                                onClick={(e) => {
                                  e.stopPropagation();
                                  onToggleProvider(provider.id);
                                }}
                                className="cursor-pointer"
                              >
                                <rect
                                  x="40"
                                  y="-9"
                                  width="22"
                                  height="18"
                                  rx="5"
                                  fill={paused ? '#334155' : '#16A34A'}
                                />
                                <text
                                  x="51"
                                  y="3.5"
                                  textAnchor="middle"
                                  fill="#FFFFFF"
                                  fontSize="8.5"
                                  fontWeight="700"
                                  fontFamily="JetBrains Mono, monospace"
                                >
                                  {paused ? 'OFF' : 'ON'}
                                </text>
                              </g>
                            )}
                          </g>
                        );
                      })}

                      {/* NODE: EGRESS 16-SECTION CORRELATION ENGINE */}
                      <g
                        transform={`translate(${egressPos.x}, ${egressPos.y})`}
                        className="cursor-pointer"
                        role="button"
                        tabIndex={0}
                        onClick={() => setSelectedNode({ kind: 'correlation_core' })}
                        onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && setSelectedNode({ kind: 'correlation_core' })}
                        onMouseEnter={() => setHoveredNodeKey('correlation_core')}
                        onMouseLeave={() => setHoveredNodeKey(null)}
                      >
                        <rect
                          x="-66"
                          y="-36"
                          width="132"
                          height="72"
                          rx="14"
                          fill="#052E16"
                          stroke={selectedNode.kind === 'correlation_core' ? '#FF263F' : '#10B981'}
                          strokeWidth={selectedNode.kind === 'correlation_core' ? 2.5 : 1.8}
                          filter={selectedNode.kind === 'correlation_core' ? 'url(#meshNodeGlow)' : undefined}
                        />
                        <text x="0" y="-12" textAnchor="middle" fill="#34D399" fontSize="9.5" fontWeight="700" fontFamily="JetBrains Mono, monospace">
                          EGRESS CORE
                        </text>
                        <text x="0" y="6" textAnchor="middle" fill="#FFFFFF" fontSize="12" fontWeight="700">
                          16-Layer Scorer
                        </text>
                        <text x="0" y="23" textAnchor="middle" fill="#34D399" fontSize="11" fontWeight="800" fontFamily="JetBrains Mono, monospace">
                          {overallStrengthPct}% READY
                        </text>
                      </g>
                    </svg>
                  </div>
                );
              })()}

              {/* Mesh Graph Legend */}
              <div className="relative mt-2 flex flex-wrap items-center justify-between gap-2 border-t border-zinc-800/80 pt-2.5 text-[11px] text-zinc-300">
                <div className="flex flex-wrap items-center gap-4">
                  <span className="inline-flex items-center gap-1.5">
                    <span className="h-2.5 w-2.5 rounded-full bg-[#10B981]" aria-hidden="true" />
                    <span>{lang === 'ar' ? 'نشط ومتصل بالشبكة' : 'Active Mesh Link'}</span>
                  </span>
                  <span className="inline-flex items-center gap-1.5">
                    <span className="h-2.5 w-2.5 rounded-full bg-[#F59E0B]" aria-hidden="true" />
                    <span>{lang === 'ar' ? 'يتطلب مفتاح توثيق' : 'Key Required'}</span>
                  </span>
                  <span className="inline-flex items-center gap-1.5">
                    <span className="h-2.5 w-2.5 rounded-full bg-zinc-500" aria-hidden="true" />
                    <span>{lang === 'ar' ? 'موقوف يدوياً (OFF)' : 'Manually Paused (OFF)'}</span>
                  </span>
                </div>
                <span className="font-mono text-[10px] text-cyan-300">
                  {lang === 'ar' ? 'تلميح: اضغط ON/OFF مباشرة على العقدة للتبديل الفوري' : 'Tip: Click ON/OFF badge directly on any provider node'}
                </span>
              </div>
            </div>
          ) : (
            /* STRUCTURED LAYERED PIPELINE MATRIX VIEW */
            <div className="relative mt-4 overflow-hidden rounded-xl border border-[#E5E7EB] bg-[#F7F7F7] p-4 dark:border-[#202020] dark:bg-black">
            {/* Subtle engineering grid background */}
            <div
              aria-hidden="true"
              className="pointer-events-none absolute inset-0 opacity-35 dark:opacity-25"
              style={{
                backgroundImage:
                  'radial-gradient(circle, rgba(161,161,170,0.45) 1px, transparent 1px)',
                backgroundSize: '20px 20px',
              }}
            />

            <div className="relative space-y-2">
              {/* ROOT NODE: Target URL Intake & SSRF Guard */}
              <div className="flex justify-center">
                <button
                  type="button"
                  onClick={() => setSelectedNode({ kind: 'core_guard' })}
                  className={`group flex w-full max-w-md items-center justify-between gap-3 rounded-xl border px-4 py-3 text-start transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF263F] ${
                    selectedNode.kind === 'core_guard'
                      ? 'border-[#FF263F] bg-white shadow-sm dark:bg-[#0D0D0D]'
                      : 'border-[#E5E7EB] bg-white/95 hover:border-[#FF263F]/60 dark:border-[#202020] dark:bg-[#0D0D0D]/95'
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-[#FF263F]/30 bg-[#FF263F]/10 text-[#FF263F]">
                      <Lock className="h-4 w-4" aria-hidden="true" />
                    </div>
                    <div className="min-w-0">
                      <p className="font-mono text-[11px] font-bold text-[#FF263F]">
                        {lang === 'ar' ? 'نقطة الإدخال ١ · بوابة العزل' : 'INGRESS NODE · SSRF SHIELD'}
                      </p>
                      <p className="truncate font-display text-sm font-bold text-zinc-950 dark:text-white">
                        {lang === 'ar'
                          ? 'تطبيع الرابط + حماية الشبكة + سجل النطاقات الرسمية'
                          : 'URL Normalization + CIDR Guard + Official Registry'}
                      </p>
                    </div>
                  </div>
                  <span className="font-mono text-xs font-bold text-[#16A34A] whitespace-nowrap shrink-0 tabular-nums">
                    {registryStats ? `${registryStats.officialDomainCount} DOMAINS` : 'ACTIVE'}
                  </span>
                </button>
              </div>

              {/* Upper Bus SVG Connectors (Intake -> 4 Stack-Ordered Layers) */}
              <div dir="ltr" className="hidden lg:block">
                <svg viewBox="0 0 1000 54" className="w-full h-[54px]" aria-hidden="true">
                  <line x1="500" y1="0" x2="500" y2="20" stroke="#FF263F" strokeWidth="2" />
                  <line x1="125" y1="20" x2="875" y2="20" stroke="#52525B" strokeOpacity="0.45" strokeWidth="1.5" />
                  {[125, 375, 625, 875].map((cx, i) => {
                    const layer = orderedLayerMetrics[i];
                    const isFocused = focusLayer === 'all' || focusLayer === layer.id;
                    const isSelected =
                      (selectedNode.kind === 'layer' && selectedNode.layerId === layer.id) ||
                      (selectedNode.kind === 'provider' && findProviderLayerId(selectedNode.providerId) === layer.id);
                    const strokeColor = !isFocused
                      ? '#3F3F46'
                      : isSelected
                        ? '#FF263F'
                        : layer.strengthPct >= 50
                          ? '#16A34A'
                          : '#F59E0B';
                    return (
                      <g key={layer.id}>
                        <path
                          d={`M 500 20 L ${cx} 20 L ${cx} 48`}
                          fill="none"
                          stroke={strokeColor}
                          strokeWidth={isSelected ? 2.5 : isFocused ? 1.8 : 1}
                          strokeOpacity={isFocused ? 0.9 : 0.25}
                          strokeDasharray={animateSignals && isFocused ? '6 4' : undefined}
                        >
                          {animateSignals && isFocused && (
                            <animate
                              attributeName="stroke-dashoffset"
                              from="20"
                              to="0"
                              dur="1.2s"
                              repeatCount="indefinite"
                            />
                          )}
                        </path>
                        <circle cx={cx} cy="49" r="4" fill={strokeColor} />
                      </g>
                    );
                  })}
                </svg>
              </div>

              {/* 4 Stacked Layer Columns with Interactive Provider Sub-Nodes */}
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
                {orderedLayerMetrics.map((layer) => {
                  const Icon = layer.icon;
                  const dimmed = focusLayer !== 'all' && focusLayer !== layer.id;
                  const isLayerSelected = selectedNode.kind === 'layer' && selectedNode.layerId === layer.id;
                  const strengthColor =
                    layer.strengthPct >= 75
                      ? 'text-[#16A34A]'
                      : layer.strengthPct >= 40
                        ? 'text-[#F59E0B]'
                        : 'text-[#EF233C]';

                  return (
                    <div
                      key={layer.id}
                      className={`flex flex-col rounded-xl border transition-all ${
                        dimmed
                          ? 'opacity-40 border-[#E5E7EB] bg-white/60 dark:border-[#202020] dark:bg-[#0D0D0D]/60'
                          : isLayerSelected
                            ? 'border-[#FF263F] bg-white shadow-sm dark:bg-[#0D0D0D]'
                            : 'border-[#E5E7EB] bg-white dark:border-[#202020] dark:bg-[#0D0D0D]'
                      }`}
                    >
                      {/* Clickable Layer Hub Header */}
                      <button
                        type="button"
                        onClick={() => setSelectedNode({ kind: 'layer', layerId: layer.id })}
                        aria-pressed={isLayerSelected}
                        className="w-full rounded-t-xl p-3.5 text-start transition-colors hover:bg-zinc-50 dark:hover:bg-[#141414] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF263F]"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="inline-flex items-center gap-1.5 font-mono text-[11px] font-bold text-[#FF263F] tabular-nums">
                            <span>#{layer.stackIndex}</span>
                            <span>·</span>
                            <span>{layer.code}</span>
                            <Icon className="h-3.5 w-3.5" aria-hidden="true" />
                          </span>
                          <span className={`font-mono text-xs font-extrabold tabular-nums ${strengthColor}`}>
                            {layer.strengthPct}%
                          </span>
                        </div>
                        <p className="mt-1.5 font-display text-sm font-bold text-zinc-950 dark:text-white leading-snug">
                          {layer.shortTitle[lang]}
                        </p>
                        <div className="mt-2 flex items-center justify-between text-[11px] text-zinc-500 dark:text-zinc-400 tabular-nums">
                          <span>
                            {layer.readyCount}/{layer.totalCount} {lang === 'ar' ? 'نشط' : 'ready'}
                          </span>
                          <span>
                            {layer.weightShare}% {lang === 'ar' ? 'وزن' : 'weight'}
                          </span>
                        </div>
                      </button>

                      {/* Vertical Trunk Connector & Interactive Provider Sub-Nodes */}
                      <div className="flex-1 space-y-1.5 border-t border-[#E5E7EB] bg-[#FAFAFA] p-2.5 rounded-b-xl dark:border-[#202020] dark:bg-[#070707]">
                        {layer.items.map((p) => {
                          const effState = getEffectiveState(p);
                          const ready = effState === 'active' || effState === 'configured';
                          const paused = p.toggleableInScan && disabledProviders.includes(p.id);
                          const isNodeSelected = selectedNode.kind === 'provider' && selectedNode.providerId === p.id;
                          const dotColor = ready
                            ? 'bg-[#16A34A]'
                            : paused
                              ? 'bg-zinc-400 dark:bg-zinc-600'
                              : 'bg-[#F59E0B]';

                          return (
                            <button
                              key={p.id}
                              type="button"
                              onClick={() => setSelectedNode({ kind: 'provider', providerId: p.id })}
                              aria-pressed={isNodeSelected}
                              className={`flex w-full items-center justify-between gap-2 rounded-lg border px-2.5 py-2 text-start text-xs transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF263F] ${
                                isNodeSelected
                                  ? 'border-[#FF263F] bg-[#FF263F]/10 text-zinc-950 dark:text-white font-semibold'
                                  : 'border-[#E5E7EB] bg-white text-zinc-800 hover:border-[#FF263F]/50 dark:border-[#1E1E1E] dark:bg-[#0D0D0D] dark:text-zinc-200'
                              }`}
                            >
                              <span className="flex min-w-0 items-center gap-2">
                                <span className={`h-2 w-2 shrink-0 rounded-full ${dotColor}`} aria-hidden="true" />
                                <span className="truncate font-medium">{p.name}</span>
                              </span>
                              <span className="font-mono text-[10px] text-zinc-500 dark:text-zinc-400 shrink-0">
                                {paused ? 'OFF' : ready ? 'ON' : '!'}
                              </span>
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Lower Convergence Bus SVG Connectors (4 Layers -> Correlation Engine) */}
              <div dir="ltr" className="hidden lg:block">
                <svg viewBox="0 0 1000 54" className="w-full h-[54px]" aria-hidden="true">
                  {[125, 375, 625, 875].map((cx, i) => {
                    const layer = orderedLayerMetrics[i];
                    const isFocused = focusLayer === 'all' || focusLayer === layer.id;
                    const isSelected =
                      selectedNode.kind === 'correlation_core' ||
                      (selectedNode.kind === 'layer' && selectedNode.layerId === layer.id);
                    const strokeColor = !isFocused
                      ? '#3F3F46'
                      : isSelected
                        ? '#FF263F'
                        : layer.strengthPct >= 50
                          ? '#16A34A'
                          : '#F59E0B';
                    return (
                      <path
                        key={layer.id}
                        d={`M ${cx} 4 L ${cx} 32 L 500 32 L 500 50`}
                        fill="none"
                        stroke={strokeColor}
                        strokeWidth={isSelected ? 2.2 : isFocused ? 1.6 : 1}
                        strokeOpacity={isFocused ? 0.85 : 0.25}
                        strokeDasharray={animateSignals && isFocused ? '6 4' : undefined}
                      >
                        {animateSignals && isFocused && (
                          <animate
                            attributeName="stroke-dashoffset"
                            from="20"
                            to="0"
                            dur="1.2s"
                            repeatCount="indefinite"
                          />
                        )}
                      </path>
                    );
                  })}
                  <circle cx="500" cy="50" r="4" fill="#FF263F" />
                </svg>
              </div>

              {/* TERMINAL NODE: 16-Section Correlation Engine */}
              <div className="flex justify-center">
                <button
                  type="button"
                  onClick={() => setSelectedNode({ kind: 'correlation_core' })}
                  className={`flex w-full max-w-md items-center justify-between gap-3 rounded-xl border px-4 py-3 text-start transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF263F] ${
                    selectedNode.kind === 'correlation_core'
                      ? 'border-[#FF263F] bg-white shadow-sm dark:bg-[#0D0D0D]'
                      : 'border-[#E5E7EB] bg-white/95 hover:border-[#FF263F]/60 dark:border-[#202020] dark:bg-[#0D0D0D]/95'
                  }`}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-[#16A34A]/30 bg-[#16A34A]/10 text-[#16A34A]">
                      <ShieldCheck className="h-4 w-4" aria-hidden="true" />
                    </div>
                    <div className="min-w-0">
                      <p className="font-mono text-[11px] font-bold text-[#16A34A]">
                        {lang === 'ar' ? 'العقدة النهائية · الترابط الحتمي' : 'EGRESS NODE · 16-SECTION ENGINE'}
                      </p>
                      <p className="truncate font-display text-sm font-bold text-zinc-950 dark:text-white">
                        {lang === 'ar'
                          ? 'تقييم المخاطر الحتمي وتقرير الأدلة'
                          : 'Deterministic Risk Scoring & Evidence Report'}
                      </p>
                    </div>
                  </div>
                  <span className="font-mono text-xs font-extrabold text-zinc-950 dark:text-white tabular-nums shrink-0">
                    {overallStrengthPct}%
                  </span>
                </button>
              </div>
            </div>
          </div>
          )}
        </div>

        {/* Interactive Node & Layer Inspector Drawer (4 cols) */}
        <aside className="xl:col-span-4 flex flex-col justify-between rounded-2xl border border-[#E5E7EB] bg-white p-5 dark:border-[#202020] dark:bg-[#0D0D0D]">
          {selectedNode.kind === 'provider' && inspectedProvider ? (
            <div className="space-y-4">
              <div className="flex items-start justify-between gap-3 border-b border-[#E5E7EB] pb-4 dark:border-[#202020]">
                <div className="min-w-0">
                  <p className="font-mono text-[11px] font-bold text-[#FF263F]">
                    {lang === 'ar' ? 'معاينة عقدة مزود بيانات' : 'SELECTED PROVIDER NODE'}
                  </p>
                  <h3 className="mt-1 font-display text-lg font-bold text-zinc-950 dark:text-white break-words">
                    {inspectedProvider.name}
                  </h3>
                  <p className="mt-0.5 text-xs text-zinc-500 dark:text-zinc-400">
                    {inspectedProvider.category}
                  </p>
                </div>
                <OperationalBadge state={getEffectiveState(inspectedProvider)} lang={lang} />
              </div>

              <p className="text-xs leading-relaxed text-zinc-600 dark:text-zinc-300">
                {inspectedProvider.freeTierNote[lang]}
              </p>

              <dl className="space-y-2.5 rounded-xl border border-[#E5E7EB] bg-[#F7F7F7] p-3.5 text-xs dark:border-[#202020] dark:bg-black">
                <div className="flex items-center justify-between gap-2">
                  <dt className="text-zinc-500 dark:text-zinc-400">
                    {lang === 'ar' ? 'الطبقة التابع لها' : 'Assigned Layer'}
                  </dt>
                  <dd className="font-semibold text-zinc-950 dark:text-white">
                    {LAYER_CATALOG[findProviderLayerId(inspectedProvider.id)].shortTitle[lang]}
                  </dd>
                </div>
                <div className="flex items-center justify-between gap-2">
                  <dt className="text-zinc-500 dark:text-zinc-400">
                    {lang === 'ar' ? 'وضع التكامل' : 'Integration Mode'}
                  </dt>
                  <dd className="font-medium text-zinc-900 dark:text-zinc-200">
                    {inspectedProvider.requiresKey
                      ? lang === 'ar'
                        ? 'مؤمّن بالخادم'
                        : 'Server-Authenticated'
                      : lang === 'ar'
                        ? 'مفتوح بدون مفتاح'
                        : 'Zero-Key Open Feed'}
                  </dd>
                </div>
                <div className="flex items-center justify-between gap-2">
                  <dt className="text-zinc-500 dark:text-zinc-400">
                    {UI_COPY.providersPage.lastLookup[lang]}
                  </dt>
                  <dd dir="ltr" className="font-mono text-[11px] text-zinc-800 dark:text-zinc-200 tabular-nums">
                    {inspectedProvider.lastSuccessfulLookup
                      ? new Date(inspectedProvider.lastSuccessfulLookup).toLocaleTimeString(
                          lang === 'ar' ? 'ar-EG' : 'en-US'
                        )
                      : UI_COPY.providersPage.neverRun[lang]}
                  </dd>
                </div>
              </dl>

              {inspectedProvider.toggleableInScan ? (
                <div className="rounded-xl border border-[#E5E7EB] bg-[#F7F7F7] p-3.5 dark:border-[#202020] dark:bg-black">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="text-xs font-bold text-zinc-950 dark:text-white">
                        {lang === 'ar' ? 'التحكم ضمن جلسة الفحص' : 'Scan Session Control'}
                      </p>
                      <p className="mt-0.5 text-[11px] text-zinc-500 dark:text-zinc-400">
                        {disabledProviders.includes(inspectedProvider.id)
                          ? lang === 'ar'
                            ? 'المصدر موقوف مؤقتاً ولن يُحتسب في الفحص'
                            : 'Currently paused for upcoming scans'
                          : lang === 'ar'
                            ? 'المصدر مفعّل وسيعمل أثناء الفحص القادم'
                            : 'Active for upcoming deterministic scans'}
                      </p>
                    </div>
                    <button
                      type="button"
                      role="switch"
                      aria-checked={!disabledProviders.includes(inspectedProvider.id)}
                      onClick={() => onToggleProvider(inspectedProvider.id)}
                      className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF263F] ${
                        !disabledProviders.includes(inspectedProvider.id)
                          ? 'bg-[#FF263F]'
                          : 'bg-zinc-300 dark:bg-zinc-700'
                      }`}
                    >
                      <span
                        className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow transition-transform ${
                          !disabledProviders.includes(inspectedProvider.id)
                            ? lang === 'ar'
                              ? '-translate-x-5'
                              : 'translate-x-5'
                            : 'translate-x-0'
                        }`}
                      />
                    </button>
                  </div>
                </div>
              ) : (
                <div className="rounded-xl border border-[#E5E7EB] bg-[#F7F7F7] p-3.5 text-xs text-zinc-600 dark:border-[#202020] dark:bg-black dark:text-zinc-300">
                  {lang === 'ar'
                    ? 'هذا المصدر جزء إلزامي من البنية الأساسية للفحص ولا يمكن تعطيله حفاظاً على دقة التحقق.'
                    : 'Core architectural primitive — permanently active to preserve scan accuracy.'}
                </div>
              )}

              <button
                type="button"
                onClick={() =>
                  setSelectedNode({ kind: 'layer', layerId: findProviderLayerId(inspectedProvider.id) })
                }
                className="w-full h-9 rounded-lg border border-[#E5E7EB] bg-white text-xs font-semibold text-zinc-800 hover:border-[#FF263F] dark:border-[#202020] dark:bg-black dark:text-zinc-200 transition-colors"
              >
                {lang === 'ar' ? 'العودة لمعاينة الطبقة الأم' : 'Inspect Parent Layer'}
              </button>
            </div>
          ) : selectedNode.kind === 'layer' && inspectedLayer ? (
            <div className="space-y-4">
              <div className="flex items-start justify-between gap-3 border-b border-[#E5E7EB] pb-4 dark:border-[#202020]">
                <div className="min-w-0">
                  <p className="font-mono text-[11px] font-bold text-[#FF263F] tabular-nums">
                    {lang === 'ar'
                      ? `معاينة الطبقة · الترتيب #${inspectedLayer.stackIndex}`
                      : `SELECTED LAYER · STACK #${inspectedLayer.stackIndex}`}
                  </p>
                  <h3 className="mt-1 font-display text-lg font-bold text-zinc-950 dark:text-white">
                    {inspectedLayer.title[lang]}
                  </h3>
                </div>
                <span className="font-mono text-lg font-extrabold text-[#16A34A] tabular-nums shrink-0">
                  {inspectedLayer.strengthPct}%
                </span>
              </div>

              <p className="text-xs leading-relaxed text-zinc-600 dark:text-zinc-300">
                {inspectedLayer.desc[lang]}
              </p>

              {/* Layer Stack Reorder & Bulk Switch Controls */}
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={inspectedLayer.stackIndex === 1}
                  onClick={() => moveLayerOrder(inspectedLayer.id, -1)}
                  className="inline-flex h-9 items-center gap-1.5 rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] px-3 text-xs font-semibold text-zinc-800 hover:border-[#FF263F] disabled:opacity-40 dark:border-[#202020] dark:bg-black dark:text-zinc-200 transition-colors whitespace-nowrap"
                >
                  <ArrowUp className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>{lang === 'ar' ? 'تقديم الطبقة' : 'Move Up'}</span>
                </button>
                <button
                  type="button"
                  disabled={inspectedLayer.stackIndex === orderedLayerMetrics.length}
                  onClick={() => moveLayerOrder(inspectedLayer.id, 1)}
                  className="inline-flex h-9 items-center gap-1.5 rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] px-3 text-xs font-semibold text-zinc-800 hover:border-[#FF263F] disabled:opacity-40 dark:border-[#202020] dark:bg-black dark:text-zinc-200 transition-colors whitespace-nowrap"
                >
                  <ArrowDown className="h-3.5 w-3.5" aria-hidden="true" />
                  <span>{lang === 'ar' ? 'تأخير الطبقة' : 'Move Down'}</span>
                </button>
                {inspectedLayer.toggleableCount > 0 && (
                  <button
                    type="button"
                    onClick={() => toggleWholeLayer(inspectedLayer.id)}
                    className="inline-flex h-9 items-center gap-1.5 rounded-lg bg-[#FF263F] px-3 text-xs font-bold text-white hover:bg-[#E01E35] transition-colors whitespace-nowrap"
                  >
                    <Power className="h-3.5 w-3.5" aria-hidden="true" />
                    <span>
                      {inspectedLayer.enabledToggleableCount === inspectedLayer.toggleableCount
                        ? lang === 'ar'
                          ? 'إيقاف مصادر الطبقة'
                          : 'Pause Layer Feeds'
                        : lang === 'ar'
                          ? 'تفعيل كل مصادر الطبقة'
                          : 'Enable All in Layer'}
                    </span>
                  </button>
                )}
              </div>

              <div className="space-y-2">
                <p className="text-[11px] font-bold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                  {lang === 'ar' ? 'وحدات التحليل المدمجة' : 'Integrated Backend Modules'}
                </p>
                <div className="space-y-1.5">
                  {inspectedLayer.coreModules[lang].map((mod) => (
                    <div
                      key={mod}
                      className="flex items-center gap-2 rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] px-3 py-2 text-xs text-zinc-800 dark:border-[#202020] dark:bg-black dark:text-zinc-200"
                    >
                      <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-[#16A34A]" aria-hidden="true" />
                      <span>{mod}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : selectedNode.kind === 'core_guard' ? (
            <div className="space-y-4">
              <div className="border-b border-[#E5E7EB] pb-4 dark:border-[#202020]">
                <p className="font-mono text-[11px] font-bold text-[#FF263F]">
                  {lang === 'ar' ? 'بوابة الإدخال والحماية الأساسية' : 'INGRESS GATEWAY & REGISTRY'}
                </p>
                <h3 className="mt-1 font-display text-lg font-bold text-zinc-950 dark:text-white">
                  {lang === 'ar' ? 'حارس SSRF وسجل النطاقات الرسمية' : 'SSRF Shield & Official Registry'}
                </h3>
              </div>

              <p className="text-xs leading-relaxed text-zinc-600 dark:text-zinc-300">
                {lang === 'ar'
                  ? 'كل رابط يمر أولاً عبر التطبيع وفحص SSRF لمنع الوصول إلى الشبكات الداخلية، ثم يتحقق محلياً من سجل النطاقات الرسمية الموثّق قبل استدعاء المصادر.'
                  : 'Every submitted URL passes through URL normalization and IPv4/IPv6 CIDR SSRF blocking before authenticating domain ownership against the official registry.'}
              </p>

              <div className="grid grid-cols-1 gap-1.5">
                {capabilityList.map((cap) => (
                  <div
                    key={cap.key}
                    className="flex items-center justify-between gap-2 rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] px-3 py-2 text-xs dark:border-[#202020] dark:bg-black"
                  >
                    <span className="font-medium text-zinc-800 dark:text-zinc-200">{cap.label[lang]}</span>
                    {cap.active ? (
                      <CheckCircle2 className="h-3.5 w-3.5 text-[#16A34A] shrink-0" aria-hidden="true" />
                    ) : (
                      <AlertTriangle className="h-3.5 w-3.5 text-[#F59E0B] shrink-0" aria-hidden="true" />
                    )}
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="border-b border-[#E5E7EB] pb-4 dark:border-[#202020]">
                <p className="font-mono text-[11px] font-bold text-[#16A34A]">
                  {lang === 'ar' ? 'محرك الترابط والنتيجة النهائية' : 'EGRESS CORRELATION ENGINE'}
                </p>
                <h3 className="mt-1 font-display text-lg font-bold text-zinc-950 dark:text-white">
                  {lang === 'ar' ? 'محرك الـ 16 قسماً الحتمي' : '16-Section Deterministic Scorer'}
                </h3>
              </div>

              <p className="text-xs leading-relaxed text-zinc-600 dark:text-zinc-300">
                {lang === 'ar'
                  ? 'يجمع نتائج الطبقات النشطة في ١٦ قسماً جنائياً بدون نماذج لغوية. عند إيقاف أي مزود يدويّاً، يسجّل التقرير ذلك بشفافية دون افتراض السلامة.'
                  : 'Correlates active layer outputs across 16 deterministic sections without LLM guessing. Manually paused feeds reduce signal coverage transparently and are never treated as clean.'}
              </p>

              <dl className="space-y-2.5 rounded-xl border border-[#E5E7EB] bg-[#F7F7F7] p-3.5 text-xs dark:border-[#202020] dark:bg-black">
                <div className="flex items-center justify-between">
                  <dt className="text-zinc-500 dark:text-zinc-400">
                    {lang === 'ar' ? 'قوة الحزمة الحالية' : 'Active Stack Strength'}
                  </dt>
                  <dd className="font-mono font-extrabold text-[#16A34A] tabular-nums">{overallStrengthPct}%</dd>
                </div>
                <div className="flex items-center justify-between">
                  <dt className="text-zinc-500 dark:text-zinc-400">
                    {lang === 'ar' ? 'مصادر موقوفة بالجلسة' : 'Session-Paused Feeds'}
                  </dt>
                  <dd className="font-mono font-bold text-zinc-900 dark:text-white tabular-nums">
                    {disabledProviders.length}
                  </dd>
                </div>
              </dl>

              <button
                type="button"
                onClick={onOpenScanner}
                className="inline-flex h-10 w-full items-center justify-center gap-2 rounded-lg bg-[#FF263F] px-4 text-xs font-bold text-white hover:bg-[#E01E35] transition-colors"
              >
                <span>{lang === 'ar' ? 'تشغيل الفحص بهذه الإعدادات' : 'Run Scan with This Pipeline'}</span>
                <ArrowRight className={`h-3.5 w-3.5 ${lang === 'ar' ? 'rotate-180' : ''}`} aria-hidden="true" />
              </button>
            </div>
          )}

          <div className="mt-5 border-t border-[#E5E7EB] pt-3 text-[11px] text-zinc-500 dark:border-[#202020] dark:text-zinc-400">
            {UI_COPY.providersPage.privacyBanner[lang]}
          </div>
        </aside>
      </div>

      {/* ZONE B: Layer Stack Composer & Security Profiles */}
      <div className="rounded-2xl border border-[#E5E7EB] bg-white p-5 sm:p-6 dark:border-[#202020] dark:bg-[#0D0D0D]">
        <div className="flex flex-col gap-4 border-b border-[#E5E7EB] pb-5 dark:border-[#202020] lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <SlidersHorizontal className="h-4 w-4 text-[#FF263F]" aria-hidden="true" />
              <h2 className="font-display text-base font-bold text-zinc-950 dark:text-white sm:text-lg">
                {lang === 'ar' ? 'تركيب وترتيب طبقات الفحص (Layer Composer)' : 'Inspection Layer Composer & Stack Profiles'}
              </h2>
            </div>
            <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
              {lang === 'ar'
                ? 'اختر قالباً جاهزاً أو أعد ترتيب طبقات الفحص وفعّل/أوقف طبقة كاملة بضغطة واحدة.'
                : 'Select a calibrated scan profile or reorder inspection layers and switch entire layers on or off in one action.'}
            </p>
          </div>

          {/* Curated Stack Presets */}
          <div className="flex flex-wrap items-center gap-2">
            {(
              [
                {
                  id: 'full_fortress' as const,
                  label: { en: 'Full Fortress (All)', ar: 'الحصن الكامل (الكل)' },
                },
                {
                  id: 'zero_key_only' as const,
                  label: { en: 'Zero-Key Open Only', ar: 'المصادر المفتوحة فقط' },
                },
                {
                  id: 'threat_core' as const,
                  label: { en: 'Threat Intel Core', ar: 'تركيز استخبارات التهديد' },
                },
                {
                  id: 'fast_surface' as const,
                  label: { en: 'Fast Surface & Edge', ar: 'فحص سطحي سريع' },
                },
              ] as const
            ).map((preset) => {
              const isActive = activePreset === preset.id;
              return (
                <button
                  key={preset.id}
                  type="button"
                  onClick={() => applyPreset(preset.id, preset.label[lang])}
                  aria-pressed={isActive}
                  className={`h-9 rounded-lg border px-3 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF263F] ${
                    isActive
                      ? 'border-[#FF263F] bg-[#FF263F] text-white'
                      : 'border-[#E5E7EB] bg-[#F7F7F7] text-zinc-700 hover:border-[#FF263F]/60 dark:border-[#202020] dark:bg-black dark:text-zinc-300'
                  }`}
                >
                  {preset.label[lang]}
                </button>
              );
            })}
          </div>
        </div>

        {/* Stackable Layer Rows */}
        <div className="mt-5 grid grid-cols-1 gap-3 lg:grid-cols-2">
          {orderedLayerMetrics.map((layer) => {
            const Icon = layer.icon;
            const allToggleableOn =
              layer.toggleableCount > 0 && layer.enabledToggleableCount === layer.toggleableCount;
            const barColor =
              layer.strengthPct >= 75
                ? 'bg-[#16A34A]'
                : layer.strengthPct >= 40
                  ? 'bg-[#F59E0B]'
                  : 'bg-[#EF233C]';

            return (
              <div
                key={layer.id}
                className="flex flex-col justify-between rounded-xl border border-[#E5E7EB] bg-[#F7F7F7] p-4 dark:border-[#202020] dark:bg-black"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-start gap-3 min-w-0">
                    <div className="flex flex-col items-center gap-1 pt-0.5 shrink-0">
                      <button
                        type="button"
                        disabled={layer.stackIndex === 1}
                        onClick={() => moveLayerOrder(layer.id, -1)}
                        aria-label={lang === 'ar' ? `تحريك ${layer.shortTitle.ar} للأعلى` : `Move ${layer.shortTitle.en} up`}
                        className="flex h-6 w-6 items-center justify-center rounded border border-[#E5E7EB] bg-white text-zinc-600 hover:border-[#FF263F] hover:text-[#FF263F] disabled:opacity-35 dark:border-[#202020] dark:bg-[#0D0D0D] dark:text-zinc-300"
                      >
                        <ArrowUp className="h-3.5 w-3.5" aria-hidden="true" />
                      </button>
                      <span className="font-mono text-[11px] font-bold text-[#FF263F] tabular-nums">
                        #{layer.stackIndex}
                      </span>
                      <button
                        type="button"
                        disabled={layer.stackIndex === orderedLayerMetrics.length}
                        onClick={() => moveLayerOrder(layer.id, 1)}
                        aria-label={lang === 'ar' ? `تحريك ${layer.shortTitle.ar} للأسفل` : `Move ${layer.shortTitle.en} down`}
                        className="flex h-6 w-6 items-center justify-center rounded border border-[#E5E7EB] bg-white text-zinc-600 hover:border-[#FF263F] hover:text-[#FF263F] disabled:opacity-35 dark:border-[#202020] dark:bg-[#0D0D0D] dark:text-zinc-300"
                      >
                        <ArrowDown className="h-3.5 w-3.5" aria-hidden="true" />
                      </button>
                    </div>

                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <Icon className="h-4 w-4 text-[#FF263F] shrink-0" aria-hidden="true" />
                        <button
                          type="button"
                          onClick={() => setSelectedNode({ kind: 'layer', layerId: layer.id })}
                          className="text-start font-display text-sm font-bold text-zinc-950 hover:text-[#FF263F] dark:text-white dark:hover:text-[#FF263F] transition-colors"
                        >
                          {layer.code} · {layer.title[lang]}
                        </button>
                      </div>
                      <p className="mt-1 text-xs leading-relaxed text-zinc-600 dark:text-zinc-400">
                        {layer.desc[lang]}
                      </p>
                    </div>
                  </div>

                  {layer.toggleableCount > 0 ? (
                    <button
                      type="button"
                      role="switch"
                      aria-checked={allToggleableOn}
                      onClick={() => toggleWholeLayer(layer.id)}
                      aria-label={lang === 'ar' ? `تبديل ${layer.shortTitle.ar}` : `Toggle ${layer.shortTitle.en}`}
                      className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF263F] ${
                        allToggleableOn ? 'bg-[#FF263F]' : 'bg-zinc-300 dark:bg-zinc-700'
                      }`}
                    >
                      <span
                        className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow transition-transform ${
                          allToggleableOn
                            ? lang === 'ar'
                              ? '-translate-x-5'
                              : 'translate-x-5'
                            : 'translate-x-0'
                        }`}
                      />
                    </button>
                  ) : (
                    <span className="font-mono text-[11px] font-bold text-[#16A34A] whitespace-nowrap shrink-0">
                      {lang === 'ar' ? 'نواة ثابتة' : 'CORE LOCKED'}
                    </span>
                  )}
                </div>

                {/* Member Feeds & Layer Strength Bar */}
                <div className="mt-3.5 space-y-2 border-t border-[#E5E7EB] pt-3 dark:border-[#202020]">
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[11px] text-zinc-600 dark:text-zinc-400">
                    {layer.items.map((p, idx) => {
                      const ready = isProviderReady(p);
                      return (
                        <span key={p.id} className="inline-flex items-center gap-1">
                          {idx > 0 && <span aria-hidden="true">·</span>}
                          <button
                            type="button"
                            onClick={() => setSelectedNode({ kind: 'provider', providerId: p.id })}
                            className={`font-medium hover:text-[#FF263F] transition-colors ${
                              ready ? 'text-zinc-900 dark:text-zinc-200' : 'text-zinc-400 dark:text-zinc-500 line-through'
                            }`}
                          >
                            {p.name}
                          </button>
                        </span>
                      );
                    })}
                  </div>

                  <div className="flex items-center gap-3">
                    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-zinc-200 dark:bg-[#1E1E1E]">
                      <div
                        className={`h-full transition-all duration-300 ${barColor}`}
                        style={{ width: `${layer.strengthPct}%` }}
                      />
                    </div>
                    <span className="font-mono text-[11px] font-bold text-zinc-700 dark:text-zinc-300 tabular-nums shrink-0">
                      {layer.readyCount}/{layer.totalCount} · {layer.strengthPct}%
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* ZONE C: Live Provider Control Matrix (Search + Filters + Grid/Table) */}
      <div className="space-y-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="font-display text-lg font-bold text-zinc-950 dark:text-white">
              {focusLayer === 'all'
                ? lang === 'ar'
                  ? `لوحة التحكم المباشرة بمزودي البيانات (${visibleProviders.length})`
                  : `Live Provider Control Matrix (${visibleProviders.length})`
                : `${LAYER_CATALOG[focusLayer].shortTitle[lang]} (${visibleProviders.length})`}
            </h2>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">
              {lang === 'ar'
                ? 'اضغط على أي مزود لعرض موقعه على الشبكة التفاعلية أو استخدم مفتاح التشغيل للتحكم الفوري.'
                : 'Click any provider to highlight it on the network mesh or toggle its scan switch immediately.'}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Search Input */}
            <div className="relative">
              <Search
                className={`pointer-events-none absolute top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-400 ${
                  lang === 'ar' ? 'right-3' : 'left-3'
                }`}
                aria-hidden="true"
              />
              <input
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder={lang === 'ar' ? 'بحث في مزودي البيانات...' : 'Search providers...'}
                className={`h-9 w-48 rounded-lg border border-[#E5E7EB] bg-white text-xs text-zinc-900 placeholder:text-zinc-400 focus:border-[#FF263F] focus:outline-none dark:border-[#202020] dark:bg-[#0D0D0D] dark:text-white ${
                  lang === 'ar' ? 'pr-8 pl-3' : 'pl-8 pr-3'
                }`}
              />
            </div>

            {/* Status Filter */}
            <div className="inline-flex rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-0.5 dark:border-[#202020] dark:bg-black">
              {(
                [
                  { id: 'all' as const, label: { en: 'All', ar: 'الكل' } },
                  { id: 'ready' as const, label: { en: 'Ready', ar: 'نشط' } },
                  { id: 'paused' as const, label: { en: 'Paused/Off', ar: 'متوقف' } },
                ] as const
              ).map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setStatusFilter(tab.id)}
                  className={`h-8 rounded-md px-2.5 text-xs font-semibold transition-colors whitespace-nowrap ${
                    statusFilter === tab.id
                      ? 'bg-white text-zinc-950 shadow-sm dark:bg-[#1A1A1A] dark:text-white'
                      : 'text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white'
                  }`}
                >
                  {tab.label[lang]}
                </button>
              ))}
            </div>

            {/* Grid / Table Toggle */}
            <div className="inline-flex rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] p-0.5 dark:border-[#202020] dark:bg-black">
              <button
                type="button"
                onClick={() => setMatrixMode('grid')}
                aria-label={lang === 'ar' ? 'عرض شبكة' : 'Grid view'}
                className={`flex h-8 w-8 items-center justify-center rounded-md transition-colors ${
                  matrixMode === 'grid'
                    ? 'bg-white text-[#FF263F] shadow-sm dark:bg-[#1A1A1A]'
                    : 'text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white'
                }`}
              >
                <LayoutGrid className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
              <button
                type="button"
                onClick={() => setMatrixMode('table')}
                aria-label={lang === 'ar' ? 'عرض جدول' : 'Table view'}
                className={`flex h-8 w-8 items-center justify-center rounded-md transition-colors ${
                  matrixMode === 'table'
                    ? 'bg-white text-[#FF263F] shadow-sm dark:bg-[#1A1A1A]'
                    : 'text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white'
                }`}
              >
                <List className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            </div>
          </div>
        </div>

        {visibleProviders.length === 0 ? (
          <div className="rounded-xl border border-[#E5E7EB] bg-white p-8 text-center dark:border-[#202020] dark:bg-[#0D0D0D]">
            <p className="text-sm font-semibold text-zinc-900 dark:text-white">
              {lang === 'ar' ? 'لا يوجد مزودون يطابقون التصفية الحالية.' : 'No providers match the active filter.'}
            </p>
            <button
              type="button"
              onClick={() => {
                setFocusLayer('all');
                setStatusFilter('all');
                setSearchQuery('');
              }}
              className="mt-3 h-9 rounded-lg border border-[#FF263F] px-4 text-xs font-bold text-[#FF263F] hover:bg-[#FF263F]/10 transition-colors"
            >
              {lang === 'ar' ? 'إظهار جميع المزودين' : 'Clear Filters'}
            </button>
          </div>
        ) : matrixMode === 'table' ? (
          <div className="overflow-x-auto rounded-xl border border-[#E5E7EB] bg-white dark:border-[#202020] dark:bg-[#0D0D0D]">
            <table className="w-full min-w-[720px] border-collapse text-start text-xs">
              <thead>
                <tr className="border-b border-[#E5E7EB] bg-[#F7F7F7] text-[11px] font-semibold uppercase tracking-wider text-zinc-500 dark:border-[#202020] dark:bg-black dark:text-zinc-400">
                  <th className="px-4 py-3 text-start">{lang === 'ar' ? 'المزود' : 'Provider'}</th>
                  <th className="px-4 py-3 text-start">{lang === 'ar' ? 'الطبقة' : 'Layer'}</th>
                  <th className="px-4 py-3 text-start">{lang === 'ar' ? 'نوع التكامل' : 'Mode'}</th>
                  <th className="px-4 py-3 text-start">{lang === 'ar' ? 'الحالة' : 'State'}</th>
                  <th className="px-4 py-3 text-start">{UI_COPY.providersPage.lastLookup[lang]}</th>
                  <th className="px-4 py-3 text-end">{lang === 'ar' ? 'التحكم' : 'Control'}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#E5E7EB] dark:divide-[#202020]">
                {visibleProviders.map((p) => {
                  const effState = getEffectiveState(p);
                  const isUserDisabled = p.toggleableInScan && disabledProviders.includes(p.id);
                  const layerMeta = LAYER_CATALOG[findProviderLayerId(p.id)];
                  const isSelectedOnMap = selectedNode.kind === 'provider' && selectedNode.providerId === p.id;
                  return (
                    <tr
                      key={p.id}
                      onClick={() => setSelectedNode({ kind: 'provider', providerId: p.id })}
                      className={`cursor-pointer transition-colors ${
                        isSelectedOnMap
                          ? 'bg-[#FF263F]/5'
                          : 'hover:bg-zinc-50 dark:hover:bg-[#141414]'
                      }`}
                    >
                      <td className="px-4 py-3">
                        <p className="font-display font-bold text-zinc-950 dark:text-white">{p.name}</p>
                        <p className="text-[11px] text-zinc-500 dark:text-zinc-400">{p.category}</p>
                      </td>
                      <td className="px-4 py-3 font-mono text-[11px] text-zinc-700 dark:text-zinc-300">
                        {layerMeta.code} · {layerMeta.shortTitle[lang]}
                      </td>
                      <td className="px-4 py-3 text-zinc-600 dark:text-zinc-300">
                        {p.requiresKey
                          ? lang === 'ar'
                            ? 'سحابي مؤمّن'
                            : 'Authenticated'
                          : lang === 'ar'
                            ? 'تلقائي مباشر'
                            : 'Zero-Key'}
                      </td>
                      <td className="px-4 py-3">
                        <OperationalBadge state={effState} lang={lang} />
                      </td>
                      <td dir="ltr" className="px-4 py-3 font-mono text-[11px] text-zinc-600 dark:text-zinc-300 tabular-nums">
                        {p.lastSuccessfulLookup
                          ? new Date(p.lastSuccessfulLookup).toLocaleTimeString(lang === 'ar' ? 'ar-EG' : 'en-US')
                          : UI_COPY.providersPage.neverRun[lang]}
                      </td>
                      <td className="px-4 py-3 text-end" onClick={(e) => e.stopPropagation()}>
                        {p.toggleableInScan ? (
                          <button
                            type="button"
                            role="switch"
                            aria-checked={!isUserDisabled}
                            onClick={() => onToggleProvider(p.id)}
                            className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF263F] ${
                              !isUserDisabled ? 'bg-[#FF263F]' : 'bg-zinc-300 dark:bg-zinc-700'
                            }`}
                          >
                            <span
                              className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow transition-transform ${
                                !isUserDisabled
                                  ? lang === 'ar'
                                    ? '-translate-x-5'
                                    : 'translate-x-5'
                                  : 'translate-x-0'
                              }`}
                            />
                          </button>
                        ) : (
                          <span className="font-mono text-[11px] text-zinc-400">
                            {lang === 'ar' ? 'إلزامي' : 'CORE'}
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            {visibleProviders.map((p) => {
              const effectiveState = getEffectiveState(p);
              const isUserDisabled = p.toggleableInScan && disabledProviders.includes(p.id);
              const ready = effectiveState === 'active' || effectiveState === 'configured';
              const layerMeta = LAYER_CATALOG[findProviderLayerId(p.id)];
              const isSelectedOnMap = selectedNode.kind === 'provider' && selectedNode.providerId === p.id;

              return (
                <div
                  key={p.id}
                  className={`flex min-w-0 flex-col justify-between overflow-hidden rounded-xl border bg-white p-5 transition-colors dark:bg-[#0D0D0D] ${
                    isSelectedOnMap
                      ? 'border-[#FF263F]'
                      : 'border-[#E5E7EB] dark:border-[#202020]'
                  }`}
                >
                  <div className="min-w-0">
                    <div className="flex min-w-0 flex-wrap items-start justify-between gap-3">
                      <button
                        type="button"
                        onClick={() => setSelectedNode({ kind: 'provider', providerId: p.id })}
                        className="min-w-0 flex-1 text-start group focus-visible:outline-none"
                      >
                        <p className="font-mono text-[11px] font-bold text-[#FF263F]">
                          {layerMeta.code} · {layerMeta.shortTitle[lang]}
                        </p>
                        <h3 className="mt-0.5 font-display break-words text-base font-bold text-zinc-950 group-hover:text-[#FF263F] dark:text-white dark:group-hover:text-[#FF263F] transition-colors">
                          {p.name}
                        </h3>
                        <p className="mt-0.5 break-words text-xs font-medium text-zinc-500 dark:text-zinc-400">
                          {p.category}
                        </p>
                      </button>
                      <OperationalBadge state={effectiveState} lang={lang} />
                    </div>

                    <p className="mt-3 break-words text-xs leading-relaxed text-zinc-600 dark:text-zinc-300">
                      {p.freeTierNote[lang]}
                    </p>

                    {/* Signal Readiness Meter */}
                    <div className="mt-3.5 space-y-1.5">
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="text-zinc-500 dark:text-zinc-400">
                          {lang === 'ar' ? 'جاهزية الإشارة' : 'Signal Readiness'}
                        </span>
                        <span className={`font-mono font-semibold ${ready ? 'text-[#16A34A]' : 'text-[#F59E0B]'}`}>
                          {ready
                            ? lang === 'ar'
                              ? 'جاهز للفحص المباشر'
                              : 'Live Ready'
                            : isUserDisabled
                              ? lang === 'ar'
                                ? 'معطل من الجلسة'
                                : 'Paused by User'
                              : lang === 'ar'
                                ? 'غير مفعّل'
                                : 'Inactive'}
                        </span>
                      </div>
                      <div className="h-1 w-full overflow-hidden rounded-full bg-zinc-200 dark:bg-[#1E1E1E]">
                        <div
                          className={`h-full transition-all duration-300 ${
                            ready ? 'w-full bg-[#16A34A]' : isUserDisabled ? 'w-1/4 bg-zinc-400' : 'w-1/3 bg-[#F59E0B]'
                          }`}
                        />
                      </div>
                    </div>

                    <dl className="mt-4 space-y-2 border-t border-[#E5E7EB] pt-3 text-xs dark:border-[#202020]">
                      <div className="flex min-w-0 items-center justify-between gap-2">
                        <dt className="text-zinc-500 dark:text-zinc-400">
                          {lang === 'ar' ? 'نوع التكامل' : 'Integration Mode'}
                        </dt>
                        <dd className="min-w-0 break-words text-end font-medium text-[11px] text-zinc-900 dark:text-zinc-200">
                          {p.requiresKey
                            ? lang === 'ar'
                              ? 'تكامل سحابي مؤمّن بالخادم'
                              : 'Server-Authenticated Cloud Feed'
                            : lang === 'ar'
                              ? 'استعلام تلقائي مباشر (بدون مفتاح)'
                              : 'Automatic Public Feed (Zero-Key)'}
                        </dd>
                      </div>
                      <div className="flex min-w-0 items-center justify-between gap-2">
                        <dt className="flex items-center gap-1 text-zinc-500 dark:text-zinc-400">
                          <Clock className="h-3 w-3 shrink-0" aria-hidden="true" />
                          <span>{UI_COPY.providersPage.lastLookup[lang]}</span>
                        </dt>
                        <dd dir="ltr" className="font-mono text-[11px] text-zinc-700 dark:text-zinc-300 tabular-nums">
                          {p.lastSuccessfulLookup
                            ? new Date(p.lastSuccessfulLookup).toLocaleTimeString(
                                lang === 'ar' ? 'ar-EG' : 'en-US'
                              )
                            : UI_COPY.providersPage.neverRun[lang]}
                        </dd>
                      </div>
                    </dl>
                  </div>

                  {p.toggleableInScan && (
                    <div className="mt-4 flex items-center justify-between border-t border-[#E5E7EB] pt-3 dark:border-[#202020]">
                      <span className="text-xs font-medium text-zinc-700 dark:text-zinc-300">
                        {UI_COPY.providersPage.sessionToggle[lang]}
                      </span>
                      <button
                        type="button"
                        role="switch"
                        aria-checked={!isUserDisabled}
                        onClick={() => onToggleProvider(p.id)}
                        className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF263F] ${
                          !isUserDisabled ? 'bg-[#FF263F]' : 'bg-zinc-300 dark:bg-zinc-700'
                        }`}
                      >
                        <span
                          className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow transition-transform ${
                            !isUserDisabled
                              ? lang === 'ar'
                                ? '-translate-x-5'
                                : 'translate-x-5'
                              : 'translate-x-0'
                          }`}
                        />
                      </button>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </section>
  );
}
