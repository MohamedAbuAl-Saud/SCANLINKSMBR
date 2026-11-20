import { ExternalLink, Send } from 'lucide-react';
import type { AppPage, Language } from '../types/scan';
import { UI_COPY } from '../i18n/translations';
import { BrandMark } from './BrandMark';

interface FooterProps {
  lang: Language;
  onNavigate: (page: AppPage) => void;
  onOpenPrivacy: () => void;
}

export function Footer({ lang, onNavigate, onOpenPrivacy }: FooterProps) {
  return (
    <footer className="border-t border-[#E5E7EB] bg-white dark:border-[#202020] dark:bg-black">
      <div className="mx-auto max-w-7xl px-4 py-9 sm:px-6 lg:px-8">
        <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
          <div className="space-y-3">
            <div className="flex items-center">
              <BrandMark className="h-10 w-auto max-w-[210px]" />
            </div>

            <div className="space-y-1">
              <p className="font-display text-xs font-bold text-zinc-950 dark:text-white">
                {UI_COPY.footer.rights[lang]}
              </p>
              <p className="text-xs font-semibold text-[#FF263F]">
                {UI_COPY.footer.ownerLine[lang]}
              </p>
              <div className="flex flex-wrap items-center gap-2 text-xs text-zinc-600 dark:text-zinc-400">
                <span>{UI_COPY.footer.contactLine[lang]}</span>
                <span aria-hidden="true">·</span>
                <span>{UI_COPY.footer.proprietaryTag[lang]}</span>
              </div>
            </div>
          </div>

          <div className="flex flex-col gap-4 lg:items-end">
            <div className="flex flex-wrap items-center gap-4 text-xs font-medium text-zinc-600 dark:text-zinc-400">
              <button type="button" onClick={() => onNavigate('home')} className="hover:text-[#FF263F]">
                {UI_COPY.nav.home[lang]}
              </button>
              <button type="button" onClick={() => onNavigate('providers')} className="hover:text-[#FF263F]">
                {UI_COPY.nav.providers[lang]}
              </button>
              <button type="button" onClick={() => onNavigate('history')} className="hover:text-[#FF263F]">
                {UI_COPY.nav.history[lang]}
              </button>
              <button type="button" onClick={() => onNavigate('about')} className="hover:text-[#FF263F]">
                {UI_COPY.nav.about[lang]}
              </button>
              <button type="button" onClick={() => onNavigate('privacy')} className="hover:text-[#FF263F]">
                {UI_COPY.nav.privacy[lang]}
              </button>
              <button type="button" onClick={() => onNavigate('terms')} className="hover:text-[#FF263F]">
                {UI_COPY.nav.terms[lang]}
              </button>
              <button type="button" onClick={onOpenPrivacy} className="text-[#FF263F] hover:underline">
                {UI_COPY.consent.manageSettings[lang]}
              </button>
            </div>

            <div className="flex flex-wrap items-center gap-3 text-xs">
              <a
                href={UI_COPY.brand.telegramUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] px-3 py-1.5 font-medium text-zinc-800 hover:border-[#FF263F] hover:text-[#FF263F] dark:border-[#202020] dark:bg-[#0D0D0D] dark:text-zinc-200 transition-colors"
              >
                <Send className="h-3.5 w-3.5 text-[#FF263F]" aria-hidden="true" />
                <span dir="ltr">@A_Y_TR</span>
                <ExternalLink className="h-3 w-3 opacity-60" aria-hidden="true" />
              </a>
            </div>
          </div>
        </div>

        <p className="mt-6 border-t border-[#E5E7EB] pt-4 text-[11px] text-zinc-500 dark:border-[#202020] dark:text-zinc-500">
          {UI_COPY.footer.disclaimer[lang]}
        </p>
      </div>
    </footer>
  );
}
