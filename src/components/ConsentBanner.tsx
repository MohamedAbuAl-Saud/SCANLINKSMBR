import { ShieldCheck } from 'lucide-react';
import type { Language } from '../types/scan';
import { UI_COPY } from '../i18n/translations';

interface ConsentBannerProps {
  visible: boolean;
  lang: Language;
  onAcceptHistory: () => void;
  onEssentialOnly: () => void;
}

export function ConsentBanner({
  visible,
  lang,
  onAcceptHistory,
  onEssentialOnly,
}: ConsentBannerProps) {
  if (!visible) return null;

  return (
    <aside
      aria-label={UI_COPY.consent.title[lang]}
      className="fixed bottom-4 inset-x-4 z-40 mx-auto max-w-4xl rounded-2xl border border-[#E5E7EB] bg-white/95 p-4 shadow-xl backdrop-blur-md dark:border-[#202020] dark:bg-[#0D0D0D]/95 sm:p-5"
    >
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-start gap-3">
          <ShieldCheck className="mt-0.5 h-5 w-5 shrink-0 text-[#FF263F]" aria-hidden="true" />
          <div>
            <p className="text-xs font-bold text-zinc-950 dark:text-white">
              {UI_COPY.consent.title[lang]}
            </p>
            <p className="mt-1 text-xs leading-relaxed text-zinc-600 dark:text-zinc-400">
              {UI_COPY.consent.body[lang]}
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={onEssentialOnly}
            className="h-9 rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] px-3 text-xs font-semibold text-zinc-700 hover:border-zinc-400 dark:border-[#202020] dark:bg-black dark:text-zinc-300 transition-colors whitespace-nowrap"
          >
            {UI_COPY.consent.essentialOnly[lang]}
          </button>
          <button
            type="button"
            onClick={onAcceptHistory}
            className="h-9 rounded-lg bg-[#FF263F] px-3.5 text-xs font-bold text-white hover:bg-[#E01E35] transition-colors whitespace-nowrap"
          >
            {UI_COPY.consent.acceptHistory[lang]}
          </button>
        </div>
      </div>
    </aside>
  );
}
