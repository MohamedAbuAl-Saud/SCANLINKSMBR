import { Home, RotateCcw } from 'lucide-react';
import type { ErrorStatusCode, Language } from '../types/scan';
import { UI_COPY } from '../i18n/translations';
import { BrandMark } from './BrandMark';
import { CyberSticker, type StickerType } from './CyberStickers';

interface ErrorViewProps {
  statusCode: ErrorStatusCode;
  lang: Language;
  onGoHome: () => void;
  onRetry?: () => void;
}

const STICKER_MAP: Record<ErrorStatusCode, StickerType> = {
  401: 'disconnected_plugs',
  403: 'disconnected_plugs',
  404: 'disconnected_plugs',
  429: 'disconnected_plugs',
  500: 'disconnected_plugs',
  502: 'disconnected_plugs',
  503: 'disconnected_plugs',
};

export function ErrorView({ statusCode, lang, onGoHome, onRetry }: ErrorViewProps) {
  const copy = UI_COPY.errors[statusCode] || UI_COPY.errors[404];
  const sticker = STICKER_MAP[statusCode] || 'disconnected_plugs';

  const handleRetry = () => {
    if (onRetry) {
      onRetry();
    } else {
      window.location.reload();
    }
  };

  return (
    <section
      aria-labelledby="error-page-heading"
      className="mx-auto flex min-h-[72vh] max-w-3xl flex-col items-center justify-center px-4 py-14 text-center sm:px-6"
    >
      <div className="mb-6">
        <BrandMark className="mx-auto h-10 w-auto max-w-[200px]" />
      </div>

      <div className="w-full rounded-2xl border border-[#E5E7EB] bg-white p-8 shadow-sm dark:border-[#202020] dark:bg-[#0D0D0D] sm:p-10">
        <div className="mx-auto flex justify-center">
          <CyberSticker type={sticker} size={150} />
        </div>

        <p className="mt-4 font-mono text-sm font-bold tracking-widest text-[#FF263F] tabular-nums">
          HTTP {statusCode}
        </p>

        <h1
          id="error-page-heading"
          className="font-display mt-2 text-2xl font-extrabold text-zinc-950 dark:text-white sm:text-3xl"
        >
          {copy.title[lang]}
        </h1>

        <p className="mx-auto mt-3 max-w-lg text-sm leading-relaxed text-zinc-600 dark:text-zinc-400">
          {copy.desc[lang]}
        </p>

        <div className="mt-7 flex flex-wrap items-center justify-center gap-3">
          <button
            type="button"
            onClick={onGoHome}
            className="inline-flex h-11 items-center gap-2 rounded-xl bg-[#FF263F] px-5 text-sm font-bold text-white hover:bg-[#E01E35] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF263F]"
          >
            <Home className="h-4 w-4" aria-hidden="true" />
            <span>{UI_COPY.errors.backHome[lang]}</span>
          </button>

          <button
            type="button"
            onClick={handleRetry}
            className="inline-flex h-11 items-center gap-2 rounded-xl border border-[#E5E7EB] bg-[#F7F7F7] px-5 text-sm font-semibold text-zinc-900 hover:border-[#FF263F] hover:text-[#FF263F] dark:border-[#202020] dark:bg-black dark:text-zinc-200 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF263F]"
          >
            <RotateCcw className="h-4 w-4" aria-hidden="true" />
            <span>{UI_COPY.errors.retry[lang]}</span>
          </button>
        </div>
      </div>

      <p className="mt-6 text-xs text-zinc-500 dark:text-zinc-400">
        {UI_COPY.footer.rights[lang]} · {UI_COPY.footer.ownerLine[lang]} · {UI_COPY.footer.contactLine[lang]}
      </p>
    </section>
  );
}
