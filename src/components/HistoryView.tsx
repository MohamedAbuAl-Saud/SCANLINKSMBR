import { useMemo, useState } from 'react';
import {
  AlertTriangle,
  Camera,
  ExternalLink,
  Globe,
  Home,
  Radar,
  Search,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import type { Language, SavedHistoryEntry, ScanReport } from '../types/scan';
import { tClassification, tVerdict, UI_COPY } from '../i18n/translations';
import { SecurityVaultVisual } from './CyberIllustrations';
import { CyberSticker } from './CyberStickers';
import { safeImageDataUrl } from '../utils/sanitize';

interface HistoryViewProps {
  history: SavedHistoryEntry[];
  isLoading?: boolean;
  storageError?: string | null;
  consentGranted: boolean;
  lang: Language;
  onEnableConsent: () => void;
  onOpenReport: (report: ScanReport) => void;
  onDeleteEntry: (scanId: string) => void;
  onClearAll: () => void;
  onGoToScanner: () => void;
  onGoHome?: () => void;
}

export function HistoryView({
  history,
  isLoading = false,
  storageError = null,
  consentGranted,
  lang,
  onEnableConsent,
  onOpenReport,
  onDeleteEntry,
  onClearAll,
  onGoToScanner,
  onGoHome,
}: HistoryViewProps) {
  const [query, setQuery] = useState('');

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return history;
    return history.filter(
      (item) =>
        item.submittedUrl.toLowerCase().includes(q) ||
        item.finalDestinationUrl.toLowerCase().includes(q) ||
        item.verdict.toLowerCase().includes(q) ||
        item.classification.toLowerCase().includes(q)
    );
  }, [history, query]);

  return (
    <section className="mx-auto max-w-6xl space-y-6 px-4 py-12 sm:px-6 lg:px-8">
      <div className="grid grid-cols-1 gap-6 border-b border-[#E5E7EB] pb-6 dark:border-[#202020] lg:grid-cols-12 lg:items-center">
        <div className="lg:col-span-7 space-y-3">
          <div className="flex items-center gap-3.5">
            <CyberSticker type="vault_shield" size={56} interactive />
            <div>
              <h1 className="font-display text-2xl font-bold text-zinc-950 dark:text-white sm:text-3xl">
                {UI_COPY.history.title[lang]}
              </h1>
              <p className="mt-1 max-w-2xl text-sm text-zinc-600 dark:text-zinc-400">
                {UI_COPY.history.subtitle[lang]}
              </p>
            </div>
          </div>

          {history.length > 0 && (
            <div className="pt-1">
              <button
                type="button"
                onClick={onClearAll}
                className="inline-flex h-10 items-center gap-2 rounded-lg border border-red-500/35 bg-red-500/10 px-4 text-xs font-semibold text-red-700 hover:bg-red-500/20 dark:text-red-300 transition-colors shrink-0"
              >
                <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                <span>{UI_COPY.history.clearAll[lang]}</span>
              </button>
            </div>
          )}
        </div>
        <div className="lg:col-span-5">
          <SecurityVaultVisual lang={lang} />
        </div>
      </div>

      {!consentGranted && (
        <div className="flex flex-col gap-3 rounded-xl border border-amber-500/30 bg-amber-50/70 p-4 text-sm text-amber-950 dark:border-amber-500/25 dark:bg-amber-950/20 dark:text-amber-200 sm:flex-row sm:items-center sm:justify-between">
          <p className="text-xs leading-relaxed">{UI_COPY.history.consentDisabled[lang]}</p>
          <button
            type="button"
            onClick={onEnableConsent}
            className="inline-flex h-9 items-center gap-1.5 rounded-lg bg-[#FF263F] px-3.5 text-xs font-bold text-white hover:bg-[#E01E35] whitespace-nowrap shrink-0"
          >
            <ShieldCheck className="h-3.5 w-3.5" aria-hidden="true" />
            <span>{UI_COPY.history.enableConsent[lang]}</span>
          </button>
        </div>
      )}

      {/* Storage Error State */}
      {storageError && (
        <div
          role="alert"
          className="flex flex-col gap-3 rounded-xl border border-red-500/40 bg-red-500/10 p-5 text-sm text-red-700 dark:text-red-300 sm:flex-row sm:items-center sm:justify-between"
        >
          <div className="flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 shrink-0 text-[#EF233C]" aria-hidden="true" />
            <span>{storageError}</span>
          </div>
          <button
            type="button"
            onClick={onGoToScanner}
            className="inline-flex h-9 items-center gap-1.5 rounded-lg bg-[#FF263F] px-3.5 text-xs font-bold text-white hover:bg-[#E01E35] whitespace-nowrap shrink-0"
          >
            <Radar className="h-3.5 w-3.5" aria-hidden="true" />
            <span>{UI_COPY.history.goToScanner[lang]}</span>
          </button>
        </div>
      )}

      {/* Loading State */}
      {isLoading ? (
        <div
          aria-busy="true"
          className="flex flex-col items-center justify-center rounded-2xl border border-[#E5E7EB] bg-white px-6 py-16 text-center dark:border-[#202020] dark:bg-[#0D0D0D]"
        >
          <CyberSticker type="radar" size={96} interactive={false} />
          <p className="mt-4 text-sm font-semibold text-zinc-600 dark:text-zinc-400">
            {UI_COPY.history.loadingText[lang]}
          </p>
        </div>
      ) : history.length === 0 ? (
        /* Empty State with 3D Interactive Animated Search Sticker */
        <div className="relative overflow-hidden flex flex-col items-center justify-center rounded-2xl border border-[#E5E7EB] bg-white px-6 py-16 text-center dark:border-[#202020] dark:bg-[#0D0D0D]">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-x-0 top-0 h-44 bg-gradient-to-b from-[#FF263F]/[0.07] via-[#00E5FF]/[0.03] to-transparent"
          />
          <div className="relative z-10 flex flex-col items-center">
            <CyberSticker
              type="search_3d"
              size={148}
              onClick={onGoToScanner}
              className="mb-3"
            />
            <h2 className="font-display mt-2 text-xl font-extrabold text-zinc-950 dark:text-white sm:text-2xl">
              {UI_COPY.history.emptyTitle[lang]}
            </h2>
            <p className="mt-2.5 max-w-md text-sm leading-relaxed text-zinc-600 dark:text-zinc-400">
              {UI_COPY.history.emptyDesc[lang]}
            </p>
            <div className="mt-7 flex flex-wrap items-center justify-center gap-3">
              <button
                type="button"
                onClick={onGoToScanner}
                className="inline-flex h-11 items-center gap-2 rounded-xl bg-[#FF263F] px-5 text-xs font-bold text-white hover:bg-[#E01E35] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF263F]"
              >
                <Radar className="h-4 w-4" aria-hidden="true" />
                <span>{UI_COPY.history.goToScanner[lang]}</span>
              </button>
              {onGoHome && (
                <button
                  type="button"
                  onClick={onGoHome}
                  className="inline-flex h-11 items-center gap-2 rounded-xl border border-[#E5E7EB] bg-[#F7F7F7] px-5 text-xs font-semibold text-zinc-800 hover:border-[#FF263F] hover:text-[#FF263F] dark:border-[#202020] dark:bg-black dark:text-zinc-200 transition-colors"
                >
                  <Home className="h-4 w-4" aria-hidden="true" />
                  <span>{UI_COPY.history.backToHome[lang]}</span>
                </button>
              )}
            </div>
          </div>
        </div>
      ) : (
        /* Success State with Preserved Local Scan History */
        <div className="rounded-xl border border-[#E5E7EB] bg-white dark:border-[#202020] dark:bg-[#0D0D0D]">
          <div className="border-b border-[#E5E7EB] p-4 dark:border-[#202020]">
            <div className="relative max-w-sm">
              <Search
                className={`pointer-events-none absolute top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-400 ${
                  lang === 'ar' ? 'right-3' : 'left-3'
                }`}
                aria-hidden="true"
              />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={UI_COPY.history.searchPlaceholder[lang]}
                className={`h-10 w-full rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] text-xs text-zinc-900 focus:border-[#FF263F] focus:outline-none dark:border-[#202020] dark:bg-black dark:text-white ${
                  lang === 'ar' ? 'pr-9 pl-3' : 'pl-9 pr-3'
                }`}
              />
            </div>
          </div>

          {filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center px-6 py-12 text-center">
              <CyberSticker type="search_3d" size={96} interactive={false} />
              <p className="mt-3 text-sm font-medium text-zinc-600 dark:text-zinc-400">
                {UI_COPY.history.noSearchMatches[lang]}
              </p>
            </div>
          ) : (
            <div className="divide-y divide-[#E5E7EB] dark:divide-[#202020]">
              {filtered.map((entry) => {
                const faviconUrl = safeImageDataUrl(entry.siteFaviconDataUrl || entry.report?.siteFaviconDataUrl);
                return (
                  <div
                    key={entry.scanId}
                    className="flex flex-col gap-4 p-4 sm:flex-row sm:items-center sm:justify-between hover:bg-[#F7F7F7] dark:hover:bg-white/[0.02]"
                  >
                    <div className="flex min-w-0 flex-1 items-center gap-3">
                      <div className="flex h-10 w-10 shrink-0 items-center justify-center overflow-hidden rounded-full border border-[#E5E7EB] bg-white dark:border-[#242424] dark:bg-black">
                        {faviconUrl ? (
                          <img
                            src={faviconUrl}
                            alt=""
                            referrerPolicy="no-referrer"
                            className="h-6 w-6 rounded-full object-contain"
                          />
                        ) : (
                          <Globe className="h-4 w-4 text-zinc-400" aria-hidden="true" />
                        )}
                      </div>
                      <div className="min-w-0 flex-1 space-y-1">
                        <p dir="ltr" className="truncate font-mono text-sm font-semibold text-zinc-950 dark:text-white">
                          {entry.submittedUrl}
                        </p>
                        <div className="flex flex-wrap items-center gap-2 text-xs text-zinc-500 dark:text-zinc-400">
                          <span dir="ltr" className="font-mono tabular-nums">
                            {new Date(entry.completedAt).toLocaleString(lang === 'ar' ? 'ar-EG' : 'en-US')}
                          </span>
                          <span aria-hidden="true">·</span>
                          <span className="font-semibold text-zinc-800 dark:text-zinc-200">
                            {tVerdict(entry.verdict, lang)}
                          </span>
                          <span aria-hidden="true">·</span>
                          <span className="inline-flex items-center gap-1">
                            <Camera className="h-3 w-3" aria-hidden="true" />
                            {entry.screenshotAvailable
                              ? UI_COPY.history.screenshotYes[lang]
                              : UI_COPY.history.screenshotNo[lang]}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-3 shrink-0">
                      <div className="text-end">
                        <span className="font-mono text-base font-bold text-[#FF263F] tabular-nums">
                          {entry.riskScore}/100
                        </span>
                        <p className="text-[11px] font-semibold text-zinc-500 dark:text-zinc-400">
                          {tClassification(entry.classification, lang)}
                        </p>
                      </div>

                      <button
                        type="button"
                        onClick={() => onOpenReport(entry.report)}
                        className="inline-flex h-9 items-center gap-1.5 rounded-lg bg-[#FF263F] px-3.5 text-xs font-bold text-white hover:bg-[#E01E35] transition-colors whitespace-nowrap"
                      >
                        <span>{UI_COPY.history.openReport[lang]}</span>
                        <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
                      </button>

                      <button
                        type="button"
                        onClick={() => onDeleteEntry(entry.scanId)}
                        aria-label={UI_COPY.history.delete[lang]}
                        className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-[#E5E7EB] text-zinc-500 hover:border-red-500/40 hover:text-[#EF233C] dark:border-[#202020] dark:text-zinc-400 transition-colors"
                      >
                        <Trash2 className="h-4 w-4" aria-hidden="true" />
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </section>
  );
}
