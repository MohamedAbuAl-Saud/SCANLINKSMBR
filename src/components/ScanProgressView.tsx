import { AlertTriangle, CheckCircle2, Clock, Loader2, MinusCircle, XCircle } from 'lucide-react';
import type { Language, ScanJobState } from '../types/scan';
import { UI_COPY } from '../i18n/translations';
import { ScanningRadarPulse } from './CyberIllustrations';
import { CyberMascot } from './CyberMascot';
import { CyberSticker } from './CyberStickers';

interface ScanProgressViewProps {
  job: ScanJobState;
  lang: Language;
  onReset: () => void;
}

export function ScanProgressView({ job, lang, onReset }: ScanProgressViewProps) {
  const runningStage = job.stages.find((s) => s.status === 'running');
  const activeSticker =
    runningStage?.id === 'source_intelligence' || runningStage?.id === 'content_phishing'
      ? 'source_code'
      : runningStage?.id === 'domain_rdap' || runningStage?.id === 'dns_resolution'
        ? 'dns_globe'
        : runningStage?.id === 'page_discovery'
          ? 'subdomain_tree'
          : 'scanner';

  return (
    <section className="mx-auto max-w-4xl px-4 py-12 sm:px-6 lg:px-8">
      <div className="rounded-2xl border border-[#E5E7EB] bg-white p-6 shadow-sm dark:border-[#202020] dark:bg-[#0D0D0D] sm:p-8 sm-red-glow">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-4">
            <ScanningRadarPulse />
            <div className="hidden sm:block shrink-0">
              <CyberMascot state={job.status === 'failed' ? 'threat' : 'scanning'} size={78} />
            </div>
            <div>
              <p className="text-xs font-bold tracking-wider text-[#FF263F]">
                {UI_COPY.brand.name[lang]}
              </p>
              <h2 className="font-display mt-1 text-xl font-bold text-zinc-950 dark:text-white sm:text-2xl">
                {UI_COPY.progress.title[lang]}
              </h2>
              <p className="mt-1 text-xs text-zinc-600 dark:text-zinc-400">
                {UI_COPY.progress.subtitle[lang]}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <CyberSticker type={activeSticker} size={46} interactive={false} />
            <span className="font-mono text-2xl font-bold text-[#FF263F] tabular-nums">
              {job.progressPercent}%
            </span>
            <button
              type="button"
              onClick={onReset}
              className="rounded-lg border border-[#E5E7EB] bg-[#F7F7F7] px-3 py-2 text-xs font-semibold text-zinc-800 hover:border-[#FF263F] hover:text-[#FF263F] dark:border-[#202020] dark:bg-black dark:text-zinc-200 transition-colors"
            >
              {UI_COPY.progress.cancelReturn[lang]}
            </button>
          </div>
        </div>

        {/* Target URL */}
        <div className="mt-5 rounded-xl border border-[#E5E7EB] bg-[#F7F7F7] px-4 py-3 dark:border-[#202020] dark:bg-black">
          <p className="text-xs font-medium text-zinc-500 dark:text-zinc-400">
            {UI_COPY.progress.target[lang]}
          </p>
          <p dir="ltr" className="mt-1 break-all font-mono text-sm text-zinc-950 dark:text-white">
            {job.submittedUrl}
          </p>
        </div>

        {/* Real Progress Bar */}
        <div className="mt-4 h-2 w-full overflow-hidden rounded-full bg-zinc-200 dark:bg-[#1E1E1E]">
          <div
            className="h-full bg-[#FF263F] transition-all duration-300"
            style={{ width: `${Math.max(5, job.progressPercent)}%` }}
          />
        </div>

        {job.status === 'failed' && job.error && (
          <div
            role="alert"
            className="mt-6 flex items-start gap-3 rounded-xl border border-red-500/40 bg-red-500/10 p-4 text-sm text-red-700 dark:text-red-300"
          >
            <XCircle className="mt-0.5 h-5 w-5 shrink-0 text-[#EF233C]" aria-hidden="true" />
            <div>
              <p className="font-semibold">{lang === 'en' ? 'Scan Halted' : 'تم إيقاف الفحص'}</p>
              <p className="mt-1">{job.error[lang]}</p>
            </div>
          </div>
        )}

        {/* Genuine Backend Pipeline Stages (Level A & Level B) */}
        <div className="mt-6 divide-y divide-[#E5E7EB] rounded-xl border border-[#E5E7EB] dark:divide-[#202020] dark:border-[#202020]">
          {job.stages.map((st, idx) => {
            const label = UI_COPY.progress.stageStatus[st.status][lang];
            return (
              <div
                key={st.id}
                className="flex flex-col gap-2 px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
              >
                <div className="flex items-start gap-3">
                  <div className="mt-0.5 shrink-0">
                    {st.status === 'completed' && <CheckCircle2 className="h-4 w-4 text-[#16A34A]" aria-hidden="true" />}
                    {st.status === 'running' && <Loader2 className="h-4 w-4 animate-spin text-[#FF263F]" aria-hidden="true" />}
                    {st.status === 'pending' && <Clock className="h-4 w-4 text-zinc-400" aria-hidden="true" />}
                    {st.status === 'warning' && <AlertTriangle className="h-4 w-4 text-[#F59E0B]" aria-hidden="true" />}
                    {st.status === 'failed' && <XCircle className="h-4 w-4 text-[#EF233C]" aria-hidden="true" />}
                    {st.status === 'unavailable' && <MinusCircle className="h-4 w-4 text-zinc-500" aria-hidden="true" />}
                  </div>
                  <div>
                    <p className="text-sm font-medium text-zinc-900 dark:text-white">
                      <span className="me-2 font-mono text-xs text-zinc-400 tabular-nums">
                        {String(idx + 1).padStart(2, '0')}
                      </span>
                      {st.label[lang]}
                    </p>
                    {st.detail && (
                      <p className="mt-0.5 text-xs text-zinc-500 dark:text-zinc-400">
                        {st.detail[lang]}
                      </p>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-3 text-xs tabular-nums shrink-0">
                  {st.durationMs !== undefined && (
                    <span dir="ltr" className="font-mono text-zinc-400">
                      {st.durationMs}ms
                    </span>
                  )}
                  <span
                    className={`font-semibold ${
                      st.status === 'completed'
                        ? 'text-[#16A34A]'
                        : st.status === 'running'
                          ? 'text-[#FF263F]'
                          : st.status === 'warning'
                            ? 'text-[#F59E0B]'
                            : st.status === 'failed'
                              ? 'text-[#EF233C]'
                              : 'text-zinc-500 dark:text-zinc-400'
                    }`}
                  >
                    {label}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
