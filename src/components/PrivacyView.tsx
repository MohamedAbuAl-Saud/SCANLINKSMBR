import { Shield, Lock, Database, Trash2, Globe, Cookie } from 'lucide-react';
import type { Language } from '../types/scan';
import { CURRENT_YEAR } from '../i18n/translations';
import { SecurityVaultVisual } from './CyberIllustrations';
import { CyberSticker } from './CyberStickers';

interface PrivacyViewProps {
  lang: Language;
}

export function PrivacyView({ lang }: PrivacyViewProps) {
  return (
    <div className="mx-auto max-w-5xl px-4 py-12 sm:px-6 lg:px-8 space-y-10">
      <div className="grid grid-cols-1 gap-8 border-b border-[#E5E7EB] pb-8 dark:border-[#202020] lg:grid-cols-12 lg:items-center">
        <div className="lg:col-span-6 space-y-4">
          <div className="flex items-center gap-3.5">
            <CyberSticker type="vault_shield" size={60} interactive />
            <div>
              <h1 className="font-display text-2xl font-extrabold text-zinc-950 dark:text-white sm:text-3xl">
                {lang === 'en' ? 'Privacy Policy' : 'سياسة الخصوصية'}
              </h1>
              <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400 font-mono">
                {lang === 'en'
                  ? `Scan Link SM · Owned by Mohamed Abu AlSaud SM (@A_Y_TR) · ${CURRENT_YEAR}`
                  : `Scan Link SM · المالك: Mohamed Abu AlSaud SM (@A_Y_TR) · ${CURRENT_YEAR}`}
              </p>
            </div>
          </div>
          <p className="text-sm leading-relaxed text-zinc-600 dark:text-zinc-400">
            {lang === 'en'
              ? 'Zero third-party tracking cookies, explicit browser-only storage consent, and complete backend isolation for external threat intelligence API keys.'
              : 'بدون ملفات تتبع خارجية، وبموافقة صريحة للتخزين المحلي داخل المتصفح فقط، مع عزل تام لمفاتيح استخبارات التهديدات على الخادم.'}
          </p>
          <div className="flex flex-wrap items-center gap-4 pt-1 text-xs font-medium text-zinc-700 dark:text-zinc-300">
            <span className="inline-flex items-center gap-1.5">
              <Lock className="h-3.5 w-3.5 text-[#FF263F]" aria-hidden="true" />
              {lang === 'en' ? 'Server-Only Keys' : 'مفاتيح معزولة بالخادم'}
            </span>
            <span aria-hidden="true" className="text-zinc-400">·</span>
            <span className="inline-flex items-center gap-1.5">
              <Database className="h-3.5 w-3.5 text-[#16A34A]" aria-hidden="true" />
              {lang === 'en' ? 'Local-Only History' : 'سجل محلي بالمتصفح'}
            </span>
          </div>
        </div>
        <div className="lg:col-span-6">
          <SecurityVaultVisual lang={lang} />
        </div>
      </div>

      <div className="space-y-8 text-sm leading-relaxed text-zinc-700 dark:text-zinc-300">
        <div className="space-y-3 rounded-2xl border border-[#E5E7EB] bg-white p-6 shadow-sm dark:border-[#202020] dark:bg-[#0D0D0D]">
          <h2 className="font-display text-base font-bold text-zinc-950 dark:text-white flex items-center gap-2">
            <Shield className="h-4 w-4 text-[#FF263F]" aria-hidden="true" />
            <span>{lang === 'en' ? '1. Information We Collect & Process' : '١. البيانات التي نجمعها ونعالجها'}</span>
          </h2>
          <p>
            {lang === 'en'
              ? 'Scan Link SM is engineered with privacy as a foundational constraint. When you submit a URL or domain for analysis, our backend processes the target strictly for security inspection (DNS resolution, certificate inspection, HTML source analysis, redirect tracing, and threat intelligence lookups). We do not collect personal identifying information (PII) or require user accounts.'
              : 'صُممت منصة Scan Link SM مع مراعاة الخصوصية كأولوية قصوى. عند إدخال رابط أو نطاق للفحص، يعالج الخادم الرابط حصراً لأغراض التحقق الأمني (فحص DNS، الشهادات، محتوى HTML، وتتبع إعادة التوجيه). لا نجمع أي بيانات شخصية تعريفية ولا نطلب إنشاء حسابات.'}
          </p>
        </div>

        <div className="space-y-3 rounded-2xl border border-[#E5E7EB] bg-white p-6 shadow-sm dark:border-[#202020] dark:bg-[#0D0D0D]">
          <h2 className="font-display text-base font-bold text-zinc-950 dark:text-white flex items-center gap-2">
            <Database className="h-4 w-4 text-[#FF263F]" aria-hidden="true" />
            <span>{lang === 'en' ? '2. Scan History & Local Storage' : '٢. سجل الفحوصات والتخزين المحلي'}</span>
          </h2>
          <p>
            {lang === 'en'
              ? 'Scan history reports are stored exclusively within your browser’s local storage (`scanlink_scan_history`) only after you grant optional history storage consent. Scan results are never uploaded to remote user databases. You maintain complete control and can delete individual entries or clear all saved reports instantly using the History panel.'
              : 'تُحفظ تقارير الفحص حصراً داخل التخزين المحلي لمتصفحك فقط بعد منح الموافقة الاختيارية. لا تُرفع تقارير الفحص أبداً إلى قواعد بيانات خارجية. يمكنك حذف أي سجل أو مسح كافة التقارير فوراً من لوحة السجل.'}
          </p>
        </div>

        <div className="space-y-3 rounded-2xl border border-[#E5E7EB] bg-white p-6 shadow-sm dark:border-[#202020] dark:bg-[#0D0D0D]">
          <h2 className="font-display text-base font-bold text-zinc-950 dark:text-white flex items-center gap-2">
            <Globe className="h-4 w-4 text-[#FF263F]" aria-hidden="true" />
            <span>{lang === 'en' ? '3. Third-Party Threat Intelligence Providers' : '٣. مزودو استخبارات التهديدات الخارجية'}</span>
          </h2>
          <p>
            {lang === 'en'
              ? 'To deliver comprehensive threat intelligence, submitted URLs or domain/IP telemetry may be queried from the backend against authorized security feeds (including VirusTotal API v3, URLhaus, OpenPhish, PhishStats, Cloudflare Security DNS, AlienVault OTX, URLScan.io, Shodan InternetDB, and Feodo Tracker). External API keys remain strictly isolated on the backend server.'
              : 'لتقديم تحليلات استخباراتية دقيقة، يتم الاستعلام من الخادم عن الروابط أو النطاقات لدى مزودي أمان معتمدين (مثل VirusTotal وURLhaus وOpenPhish وPhishStats وCloudflare Security DNS وAlienVault OTX وURLScan.io وShodan InternetDB). تبقى كافة مفاتيح الربط معزولة تماماً على الخادم.'}
          </p>
        </div>

        <div className="space-y-3 rounded-2xl border border-[#E5E7EB] bg-white p-6 shadow-sm dark:border-[#202020] dark:bg-[#0D0D0D]">
          <h2 className="font-display text-base font-bold text-zinc-950 dark:text-white flex items-center gap-2">
            <Cookie className="h-4 w-4 text-[#FF263F]" aria-hidden="true" />
            <span>{lang === 'en' ? '4. Preferences & Storage Controls' : '٤. تفضيلات التخزين والتحكم بالخصوصية'}</span>
          </h2>
          <p>
            {lang === 'en'
              ? 'We use minimal browser storage items strictly for essential functionality: remembering your preferred theme (light/dark), language (English/Arabic), and optional history consent. We do not employ third-party advertising cookies, tracking beacons, or cross-site user profiling.'
              : 'نستخدم تخزيناً محلياً أساسياً فقط لتذكر المظهر (فاتح/داكن)، واللغة (إنجليزية/عربية)، وموافقة حفظ السجل. لا نستخدم أي ملفات إعلانية أو أدوات تتبع خارجية.'}
          </p>
        </div>

        <div className="space-y-3 rounded-2xl border border-[#E5E7EB] bg-white p-6 shadow-sm dark:border-[#202020] dark:bg-[#0D0D0D]">
          <h2 className="font-display text-base font-bold text-zinc-950 dark:text-white flex items-center gap-2">
            <Trash2 className="h-4 w-4 text-[#FF263F]" aria-hidden="true" />
            <span>{lang === 'en' ? '5. User Data Deletion & Contact' : '٥. حقوق الحذف والتواصل الرسمي'}</span>
          </h2>
          <p>
            {lang === 'en'
              ? 'Because scan history and preferences reside in your browser storage, clicking "Clear All" in History or choosing "Necessary Only" in Privacy Settings deletes local records immediately. Official contact: @A_Y_TR (Mohamed Abu AlSaud SM).'
              : 'نظراً لأن السجل والتفضيلات محفوظة محلياً في متصفحك، فإن النقر على "مسح الكل" أو اختيار "الضروري فقط" يحذف كافة السجلات فوراً. للتواصل الرسمي: @A_Y_TR (Mohamed Abu AlSaud SM).'}
          </p>
        </div>
      </div>
    </div>
  );
}
