import { ShieldAlert, CheckCircle2, AlertTriangle, Scale } from 'lucide-react';
import type { Language } from '../types/scan';
import { CURRENT_YEAR } from '../i18n/translations';
import { DomainArchitectureVisual } from './CyberIllustrations';
import { CyberSticker } from './CyberStickers';

interface TermsViewProps {
  lang: Language;
}

export function TermsView({ lang }: TermsViewProps) {
  return (
    <div className="mx-auto max-w-5xl px-4 py-12 sm:px-6 lg:px-8 space-y-10">
      <div className="grid grid-cols-1 gap-8 border-b border-[#E5E7EB] pb-8 dark:border-[#202020] lg:grid-cols-12 lg:items-center">
        <div className="lg:col-span-6 space-y-4">
          <div className="flex items-center gap-3.5">
            <CyberSticker type="policy_book" size={60} interactive />
            <div>
              <h1 className="font-display text-2xl font-extrabold text-zinc-950 dark:text-white sm:text-3xl">
                {lang === 'en' ? 'Terms of Use' : 'شروط الاستخدام'}
              </h1>
              <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400 font-mono">
                {lang === 'en'
                  ? `Scan Link SM · Owner: Mohamed Abu AlSaud SM (@A_Y_TR) · ${CURRENT_YEAR}`
                  : `Scan Link SM · المالك: Mohamed Abu AlSaud SM (@A_Y_TR) · ${CURRENT_YEAR}`}
              </p>
            </div>
          </div>
          <p className="text-sm leading-relaxed text-zinc-600 dark:text-zinc-400">
            {lang === 'en'
              ? 'Authorized security research governance, strict SSRF defensive boundaries, and exclusive proprietary engineering rights.'
              : 'إطار الحوكمة للاستخدام الأمني المصرح به، وحدود الحماية الصارمة SSRF، وحقوق الملكية الحصرية لمنصة Scan Link SM.'}
          </p>
          <div className="flex flex-wrap items-center gap-4 pt-1 text-xs font-medium text-zinc-700 dark:text-zinc-300">
            <span className="inline-flex items-center gap-1.5">
              <Scale className="h-3.5 w-3.5 text-[#FF263F]" aria-hidden="true" />
              {lang === 'en' ? 'Authorized Inspection' : 'فحص مصرح به'}
            </span>
            <span aria-hidden="true" className="text-zinc-400">·</span>
            <span className="inline-flex items-center gap-1.5">
              <ShieldAlert className="h-3.5 w-3.5 text-[#0284C7]" aria-hidden="true" />
              {lang === 'en' ? 'Anti-Abuse Guardrails' : 'ضوابط منع إساءة الاستخدام'}
            </span>
          </div>
        </div>
        <div className="lg:col-span-6">
          <DomainArchitectureVisual lang={lang} />
        </div>
      </div>

      <div className="space-y-8 text-sm leading-relaxed text-zinc-700 dark:text-zinc-300">
        <div className="space-y-3 rounded-2xl border border-[#E5E7EB] bg-white p-6 shadow-sm dark:border-[#202020] dark:bg-[#0D0D0D]">
          <h2 className="font-display text-base font-bold text-zinc-950 dark:text-white flex items-center gap-2">
            <Scale className="h-4 w-4 text-[#FF263F]" aria-hidden="true" />
            <span>{lang === 'en' ? '1. Intended Purpose & Authorization' : '١. الغرض المخصص وشروط الاستخدام'}</span>
          </h2>
          <p>
            {lang === 'en'
              ? 'Scan Link SM is a security intelligence platform developed and owned by Mohamed Abu AlSaud SM (@A_Y_TR), intended strictly for legitimate URL and website inspection, threat research, and defensive verification. You agree to submit only URLs you own or are authorized to inspect.'
              : 'منصة Scan Link SM المملوكة والمطورة بواسطة Mohamed Abu AlSaud SM (@A_Y_TR) مخصصة حصراً لأغراض التحليل الأمني الشرعي للروابط والمواقع والتحقق الدفاعي. توافق على فحص الروابط التي تملكها أو تملك إذناً بفحصها فقط.'}
          </p>
        </div>

        <div className="space-y-3 rounded-2xl border border-[#E5E7EB] bg-white p-6 shadow-sm dark:border-[#202020] dark:bg-[#0D0D0D]">
          <h2 className="font-display text-base font-bold text-zinc-950 dark:text-white flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-[#FF263F]" aria-hidden="true" />
            <span>{lang === 'en' ? '2. Prohibited Conduct & Rate Limits' : '٢. الاستخدام المحظور والحدود التشغيلية'}</span>
          </h2>
          <p>
            {lang === 'en'
              ? 'Automated flooding, denial-of-service abuse, attempting to bypass SSRF network boundaries, or probing internal infrastructure via the scanning engine is strictly prohibited and actively blocked.'
              : 'يُحظر تماماً إرسال طلبات متكررة بقصد الإغراق أو إيقاف الخدمة، أو محاولة تجاوز قيود الحماية الداخلية SSRF أو استغلال محرك الفحص في أغراض غير مشروعة.'}
          </p>
        </div>

        <div className="space-y-3 rounded-2xl border border-[#E5E7EB] bg-white p-6 shadow-sm dark:border-[#202020] dark:bg-[#0D0D0D]">
          <h2 className="font-display text-base font-bold text-zinc-950 dark:text-white flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-[#FF263F]" aria-hidden="true" />
            <span>{lang === 'en' ? '3. Indicators vs. Absolute Guarantees' : '٣. مؤشرات أمنية وليست ضمانات مطلقة'}</span>
          </h2>
          <p>
            {lang === 'en'
              ? 'Scan reports, risk scores, and classifications generated by Scan Link SM are deterministic security indicators based on telemetry available at scan time. No automated inspection platform can guarantee that any website is 100% safe or free from vulnerabilities.'
              : 'تقارير الفحص ودرجات المخاطر الصادرة عن المنصة هي مؤشرات أمنية مبنية على البيانات المتاحة وقت الفحص. لا تضمن أي أداة آلية خلو أي موقع تماماً من الثغرات أو التهديدات المستجدة.'}
          </p>
        </div>

        <div className="space-y-3 rounded-2xl border border-[#E5E7EB] bg-white p-6 shadow-sm dark:border-[#202020] dark:bg-[#0D0D0D]">
          <h2 className="font-display text-base font-bold text-zinc-950 dark:text-white flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 text-[#FF263F]" aria-hidden="true" />
            <span>{lang === 'en' ? '4. Intellectual Property & Third-Party Feeds' : '٤. حقوق الملكية والمصادر الخارجية'}</span>
          </h2>
          <p>
            {lang === 'en'
              ? 'All Scan Link SM engines, source code, branding, and visual architecture remain the exclusive proprietary property of Mohamed Abu AlSaud SM. Availability of external threat intelligence providers is subject to upstream limits.'
              : 'جميع محركات Scan Link SM والشيفرة المصدرية والهوية البصرية مملوكة حصرياً للمطور Mohamed Abu AlSaud SM. كما تخضع استجابة مزودي التهديدات الخارجية لتوافر خدماتهم وقت الفحص.'}
          </p>
        </div>
      </div>
    </div>
  );
}
