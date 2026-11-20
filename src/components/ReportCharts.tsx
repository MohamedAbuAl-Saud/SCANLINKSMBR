import { useState } from 'react';
import type { CheckStatus, Language, ScanReport, TechnicalSectionId } from '../types/scan';
import { UI_COPY } from '../i18n/translations';

interface ReportChartsProps {
  report: ScanReport;
  lang: Language;
  onSelectStatusFilter: (status: CheckStatus | 'all') => void;
  onSelectSectionFilter: (section: TechnicalSectionId | 'all') => void;
}

export function ReportCharts({
  report,
  lang,
  onSelectStatusFilter,
  onSelectSectionFilter,
}: ReportChartsProps) {
  const [hoveredSlice, setHoveredSlice] = useState<CheckStatus | null>(null);
  const { passedChecks, warningChecks, failedChecks, incompleteChecks, totalChecks } =
    report.summaryStats;

  const segments: { key: CheckStatus; label: string; count: number; color: string }[] = [
    { key: 'pass', label: UI_COPY.report.stats.passed[lang], count: passedChecks, color: '#16A34A' },
    { key: 'warning', label: UI_COPY.report.stats.warning[lang], count: warningChecks, color: '#F59E0B' },
    { key: 'failed', label: UI_COPY.report.stats.failed[lang], count: failedChecks, color: '#EF233C' },
    { key: 'unknown', label: UI_COPY.report.stats.incomplete[lang], count: incompleteChecks, color: '#71717A' },
  ];

  const radius = 56;
  const circumference = 2 * Math.PI * radius;
  let offsetAcc = 0;

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
      {/* Check Outcomes Donut Chart */}
      <div className="lg:col-span-5 rounded-xl border border-[#E5E7EB] bg-white p-5 dark:border-[#202020] dark:bg-[#0D0D0D]">
        <h3 className="font-display text-sm font-bold text-zinc-950 dark:text-white">
          {UI_COPY.report.charts.distribution[lang]}
        </h3>

        <div className="mt-4 flex flex-col sm:flex-row items-center gap-6">
          <div className="relative h-40 w-40 shrink-0">
            <svg viewBox="0 0 144 144" className="h-full w-full -rotate-90">
              <circle
                cx="72"
                cy="72"
                r={radius}
                fill="none"
                stroke="currentColor"
                strokeWidth="16"
                className="text-zinc-100 dark:text-[#181818]"
              />
              {totalChecks > 0 &&
                segments.map((seg) => {
                  if (seg.count === 0) return null;
                  const dashLen = (seg.count / totalChecks) * circumference;
                  const dashOffset = -offsetAcc;
                  offsetAcc += dashLen;
                  const isHovered = hoveredSlice === seg.key;
                  return (
                    <circle
                      key={seg.key}
                      cx="72"
                      cy="72"
                      r={radius}
                      fill="none"
                      stroke={seg.color}
                      strokeWidth={isHovered ? 20 : 16}
                      strokeDasharray={`${dashLen} ${circumference}`}
                      strokeDashoffset={dashOffset}
                      className="cursor-pointer transition-all duration-150"
                      onMouseEnter={() => setHoveredSlice(seg.key)}
                      onMouseLeave={() => setHoveredSlice(null)}
                      onClick={() => onSelectStatusFilter(seg.key)}
                    />
                  );
                })}
            </svg>
            <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center text-center">
              <span className="font-mono text-2xl font-bold text-zinc-950 dark:text-white tabular-nums">
                {hoveredSlice
                  ? segments.find((s) => s.key === hoveredSlice)?.count ?? totalChecks
                  : totalChecks}
              </span>
              <span className="text-[11px] font-medium text-zinc-500 dark:text-zinc-400">
                {hoveredSlice
                  ? segments.find((s) => s.key === hoveredSlice)?.label
                  : UI_COPY.report.stats.total[lang]}
              </span>
            </div>
          </div>

          <div className="flex-1 w-full space-y-2">
            {segments.map((seg) => {
              const pct = totalChecks > 0 ? Math.round((seg.count / totalChecks) * 100) : 0;
              return (
                <button
                  key={seg.key}
                  type="button"
                  onMouseEnter={() => setHoveredSlice(seg.key)}
                  onMouseLeave={() => setHoveredSlice(null)}
                  onClick={() => onSelectStatusFilter(seg.key)}
                  className="flex w-full items-center justify-between rounded-lg px-2.5 py-1.5 text-xs hover:bg-[#F7F7F7] dark:hover:bg-white/5 transition-colors"
                >
                  <span className="flex items-center gap-2 font-medium text-zinc-800 dark:text-zinc-200">
                    <span
                      className="h-2.5 w-2.5 rounded-sm shrink-0"
                      style={{ backgroundColor: seg.color }}
                      aria-hidden="true"
                    />
                    {seg.label}
                  </span>
                  <span className="font-mono text-zinc-600 dark:text-zinc-400 tabular-nums">
                    {seg.count} ({pct}%)
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Horizontal Stacked Bar Chart across 12 Security Layers */}
      <div className="lg:col-span-7 rounded-xl border border-[#E5E7EB] bg-white p-5 dark:border-[#202020] dark:bg-[#0D0D0D]">
        <h3 className="font-display text-sm font-bold text-zinc-950 dark:text-white">
          {UI_COPY.report.charts.sectionProfile[lang]}
        </h3>

        <div className="mt-4 space-y-2">
          {report.sections.map((sec) => {
            const total = Math.max(1, sec.findingsCount);
            const passPct = (sec.passedCount / total) * 100;
            const warnPct = (sec.warningCount / total) * 100;
            const failPct = (sec.failedCount / total) * 100;
            const unkPct = (sec.unknownCount / total) * 100;

            return (
              <button
                key={sec.id}
                type="button"
                onClick={() => onSelectSectionFilter(sec.id)}
                className="group grid w-full grid-cols-12 items-center gap-3 rounded-md px-1.5 py-1 text-start hover:bg-[#F7F7F7] dark:hover:bg-white/[0.03] transition-colors"
              >
                <span className="col-span-5 sm:col-span-4 truncate text-xs font-medium text-zinc-700 group-hover:text-[#FF263F] dark:text-zinc-300">
                  {sec.title[lang]}
                </span>
                <div className="col-span-5 sm:col-span-6 flex h-2.5 overflow-hidden rounded-full bg-zinc-100 dark:bg-[#1A1A1A]">
                  {sec.findingsCount === 0 ? (
                    <div className="h-full w-full bg-zinc-300 dark:bg-zinc-800" />
                  ) : (
                    <>
                      {passPct > 0 && <div style={{ width: `${passPct}%` }} className="bg-[#16A34A]" />}
                      {warnPct > 0 && <div style={{ width: `${warnPct}%` }} className="bg-[#F59E0B]" />}
                      {failPct > 0 && <div style={{ width: `${failPct}%` }} className="bg-[#EF233C]" />}
                      {unkPct > 0 && <div style={{ width: `${unkPct}%` }} className="bg-zinc-500" />}
                    </>
                  )}
                </div>
                <span className="col-span-2 text-end font-mono text-[11px] text-zinc-500 dark:text-zinc-400 tabular-nums">
                  {sec.findingsCount}
                </span>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
