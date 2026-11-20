import { useState } from 'react';
import { Globe, Menu, Moon, Sun, X } from 'lucide-react';
import type { AppPage, Language, ThemeMode } from '../types/scan';
import { UI_COPY } from '../i18n/translations';
import { BrandMark } from './BrandMark';

interface NavbarProps {
  currentPage: AppPage;
  onNavigate: (page: AppPage) => void;
  lang: Language;
  onToggleLang: () => void;
  theme: ThemeMode;
  onToggleTheme: () => void;
}

export function Navbar({
  currentPage,
  onNavigate,
  lang,
  onToggleLang,
  theme,
  onToggleTheme,
}: NavbarProps) {
  const [mobileOpen, setMobileOpen] = useState(false);

  const navItems: { id: AppPage; label: string }[] = [
    { id: 'home', label: UI_COPY.nav.home[lang] },
    { id: 'scanner', label: UI_COPY.nav.scanner[lang] },
    { id: 'providers', label: UI_COPY.nav.providers[lang] },
    { id: 'history', label: UI_COPY.nav.history[lang] },
    { id: 'about', label: UI_COPY.nav.about[lang] },
  ];

  const handleNav = (id: AppPage) => {
    onNavigate(id);
    setMobileOpen(false);
  };

  return (
    <header className="sticky top-0 z-40 border-b border-[#E5E7EB] bg-white dark:border-[#202020] dark:bg-black transition-colors duration-200">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between gap-6 px-4 sm:px-6 lg:px-8">
        {/* Official SM Logo (Theme-matched, no border or frame) */}
        <button
          type="button"
          onClick={() => handleNav('home')}
          className="flex items-center whitespace-nowrap shrink-0 text-start focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF263F]"
          aria-label="Scan Link SM Home"
        >
          <BrandMark className="h-10 w-auto max-w-[190px]" />
        </button>

        {/* Single-line Top Navigation (5 links max) */}
        <nav aria-label="Main navigation" className="hidden md:flex items-center gap-6">
          {navItems.map((item) => {
            const active = currentPage === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => handleNav(item.id)}
                className={`relative py-1 text-sm font-medium transition-colors whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF263F] rounded ${
                  active
                    ? 'text-[#FF263F]'
                    : 'text-zinc-700 hover:text-zinc-950 dark:text-zinc-300 dark:hover:text-white'
                }`}
              >
                {item.label}
                {active && (
                  <span
                    aria-hidden="true"
                    className="absolute inset-x-0 -bottom-[19px] h-[2px] bg-[#FF263F]"
                  />
                )}
              </button>
            );
          })}
        </nav>

        {/* Language & Theme Switchers */}
        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={onToggleLang}
            aria-label={lang === 'en' ? 'Switch to Arabic' : 'Switch to English'}
            className="inline-flex h-10 items-center gap-1.5 rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] px-3 text-xs font-semibold text-zinc-800 hover:border-[#FF263F]/60 hover:text-[#FF263F] dark:border-[#202020] dark:bg-[#080808] dark:text-zinc-200 dark:hover:border-[#FF263F]/60 dark:hover:text-white transition-colors whitespace-nowrap shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF263F]"
          >
            <Globe className="h-3.5 w-3.5 text-[#FF263F]" aria-hidden="true" />
            <span>{lang === 'en' ? 'العربية' : 'English'}</span>
          </button>

          <button
            type="button"
            onClick={onToggleTheme}
            aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            className="inline-flex h-10 w-10 items-center justify-center rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] text-zinc-800 hover:border-[#FF263F]/60 hover:text-[#FF263F] dark:border-[#202020] dark:bg-[#080808] dark:text-zinc-200 dark:hover:border-[#FF263F]/60 dark:hover:text-white transition-colors shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF263F]"
          >
            {theme === 'dark' ? (
              <Sun className="h-4 w-4" aria-hidden="true" />
            ) : (
              <Moon className="h-4 w-4" aria-hidden="true" />
            )}
          </button>

          <button
            type="button"
            onClick={() => setMobileOpen((v) => !v)}
            aria-expanded={mobileOpen}
            aria-label="Toggle navigation menu"
            className="inline-flex md:hidden h-10 w-10 items-center justify-center rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] text-zinc-800 dark:border-[#202020] dark:bg-[#080808] dark:text-zinc-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#FF263F]"
          >
            {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
          </button>
        </div>
      </div>

      {mobileOpen && (
        <div className="md:hidden border-t border-[#E5E7EB] bg-white px-4 py-3 dark:border-[#202020] dark:bg-[#080808]">
          <nav className="flex flex-col gap-1">
            {navItems.map((item) => {
              const active = currentPage === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => handleNav(item.id)}
                  className={`flex min-h-[44px] items-center rounded-lg px-3 text-sm font-medium transition-colors text-start ${
                    active
                      ? 'bg-[#FF263F]/10 text-[#FF263F]'
                      : 'text-zinc-700 hover:bg-zinc-100 dark:text-zinc-300 dark:hover:bg-white/5'
                  }`}
                >
                  {item.label}
                </button>
              );
            })}
          </nav>
        </div>
      )}
    </header>
  );
}
