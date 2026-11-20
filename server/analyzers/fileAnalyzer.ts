import crypto from 'node:crypto';
import * as cheerio from 'cheerio';
import type { CheckFinding, FileDownloadCategory, FileDownloadItem } from '../types.ts';

const DANGEROUS_EXTENSIONS = new Set([
  '.exe', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.vbe', '.js', '.jse',
  '.wsf', '.scr', '.pif', '.com', '.hta', '.cpl', '.lnk', '.iso', '.img',
  '.apk', '.dmg', '.pkg', '.jar', '.docm', '.xlsm', '.pptm',
]);

const ARCHIVE_EXTENSIONS = new Set(['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2']);

function detectMagicSignature(buf: Buffer): { label: string; isExecutable: boolean } | undefined {
  if (buf.length < 4) return undefined;
  if (buf[0] === 0x4d && buf[1] === 0x5a) return { label: 'Windows PE Executable (MZ)', isExecutable: true };
  if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
    return { label: 'Linux ELF Executable', isExecutable: true };
  }
  if (buf.slice(0, 5).toString('ascii') === '%PDF-') return { label: 'PDF Document (%PDF-)', isExecutable: false };
  if (buf[0] === 0x50 && buf[1] === 0x4b && (buf[2] === 0x03 || buf[2] === 0x05)) {
    return { label: 'ZIP / OpenXML / APK Container (PK)', isExecutable: false };
  }
  if (buf[0] === 0x52 && buf[1] === 0x61 && buf[2] === 0x72 && buf[3] === 0x21) {
    return { label: 'RAR Archive', isExecutable: false };
  }
  if (buf.length >= 6 && buf[0] === 0x37 && buf[1] === 0x7a && buf[2] === 0xbc && buf[3] === 0xaf) {
    return { label: '7-Zip Archive', isExecutable: false };
  }
  if (buf[0] === 0x1f && buf[1] === 0x8b) return { label: 'GZIP Stream', isExecutable: false };
  return undefined;
}

function hasSuspiciousFilenamePattern(name: string): boolean {
  return /\.(pdf|doc|docx|xls|xlsx|jpg|png)\.(exe|scr|js|vbs|bat|ps1|zip|html?)$/i.test(name) ||
    /(invoice|payment|urgent|update|setup|crack|keygen|patch).*\.(exe|msi|zip|rar|apk|iso|scr|js)$/i.test(name);
}

function isCookieOrSessionResponse(
  finalUrl: string,
  filename: string,
  contentType: string,
  headers: Record<string, string>,
  rawBuffer?: Buffer
): boolean {
  const lowerUrl = finalUrl.toLowerCase();
  const lowerName = filename.toLowerCase();

  // If filename or URL path clearly indicates cookie / session token
  if (
    lowerName === 'cookie' ||
    lowerName === 'cookies' ||
    lowerName === 'cookies.txt' ||
    lowerName.includes('cookie_consent') ||
    lowerName.includes('session_id') ||
    lowerName === 'set-cookie'
  ) {
    return true;
  }

  if (/(?:[/?&])(?:cookie|cookies|set-cookie|session-cookie|consent-cookie|auth-token)\b/i.test(lowerUrl)) {
    return true;
  }

  // If header has set-cookie and content-type is text/plain or json with token
  if (headers['set-cookie'] && (contentType.includes('text/plain') || contentType.includes('application/json') || !contentType)) {
    if (rawBuffer && rawBuffer.length < 4096) {
      const text = rawBuffer.toString('utf8').trim();
      if (/^(?:[\w.-]+=[^;]+(?:;\s*(?:expires|path|domain|secure|httponly|samesite)[^;]*)*)$/i.test(text) || (text.startsWith('{') && text.includes('token'))) {
        return true;
      }
    }
  }

  return false;
}

export function analyzeFileAndDownloads(
  finalUrl: string,
  headers: Record<string, string>,
  rawBuffer: Buffer | undefined
): {
  isDirectDownload: boolean;
  directFile?: FileDownloadItem;
  discoveredDownloads: FileDownloadItem[];
  dynamicAnalysisPerformed: boolean;
  findings: CheckFinding[];
} {
  const now = new Date().toISOString();
  const findings: CheckFinding[] = [];
  const discoveredDownloads: FileDownloadItem[] = [];

  const contentType = (headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  const contentDisp = headers['content-disposition'] || '';
  const contentLength = headers['content-length'] ? Number(headers['content-length']) : rawBuffer?.length;

  const parsedUrl = new URL(finalUrl);
  const pathBase = parsedUrl.pathname.split('/').pop() || '';
  const dispMatch = contentDisp.match(/filename\*?=(?:UTF-8'')?"?([^";\r\n]+)"?/i);
  const filename = dispMatch?.[1] || pathBase || 'download';
  const extMatch = filename.toLowerCase().match(/\.[a-z0-9]{1,8}$/)?.[0] || '';

  const isHtmlOrText =
    contentType.includes('text/html') ||
    contentType.includes('application/xhtml') ||
    contentType.includes('text/plain') ||
    contentType.includes('application/json');

  // Verify that this is an actual file and NOT a cookie / tracking endpoint
  const isCookie = isCookieOrSessionResponse(finalUrl, filename, contentType, headers, rawBuffer);

  const isDirectDownload =
    !isCookie &&
    (contentDisp.toLowerCase().includes('attachment') ||
      DANGEROUS_EXTENSIONS.has(extMatch) ||
      ARCHIVE_EXTENSIONS.has(extMatch) ||
      extMatch === '.pdf' ||
      (Boolean(contentType) && !isHtmlOrText && !contentType.startsWith('image/')));

  let directFile: FileDownloadItem | undefined;

  if (isDirectDownload && rawBuffer) {
    const inspectedSlice = rawBuffer.slice(0, 512 * 1024);
    const sha256 = crypto.createHash('sha256').update(inspectedSlice).digest('hex');
    const magic = detectMagicSignature(inspectedSlice);

    const isPdf = extMatch === '.pdf' || magic?.label.startsWith('PDF');
    const isExeExt = DANGEROUS_EXTENSIONS.has(extMatch);
    const isArchive = ARCHIVE_EXTENSIONS.has(extMatch);
    const suspiciousNaming = hasSuspiciousFilenamePattern(filename);
    const mimeMismatch = Boolean(
      magic &&
        ((magic.isExecutable && !isExeExt) || (magic.label.startsWith('PDF') && extMatch && extMatch !== '.pdf'))
    );

    // Smart risk determination:
    // Only elevate risk if there is an active deception (MIME mismatch, double extension, suspicious naming, or dangerous scripts)
    const isDeceptive = mimeMismatch || suspiciousNaming || ['.scr', '.vbs', '.pif', '.hta', '.cpl', '.bat', '.cmd', '.ps1'].includes(extMatch);
    const riskFlag = isDeceptive ? 'high' : isPdf ? 'low' : isArchive ? 'low' : 'low';

    const isScriptFile = ['.js', '.jse', '.vbs', '.vbe', '.ps1', '.bat', '.cmd', '.hta', '.wsf'].includes(extMatch);
    const isBinaryExecutable = Boolean(magic?.isExecutable || ['.exe', '.msi', '.apk', '.dmg', '.pkg', '.iso', '.img', '.scr', '.pif', '.com', '.jar'].includes(extMatch));
    const hasAutoAttachment = contentDisp.toLowerCase().includes('attachment');
    const downloadCategory: FileDownloadCategory = isDeceptive
      ? 'deceptive_download'
      : isScriptFile
        ? 'script'
        : isBinaryExecutable
          ? 'executable'
          : isArchive
            ? 'archive'
            : isPdf
              ? 'verified_safe_resource'
              : hasAutoAttachment
                ? 'user_initiated_download'
                : 'unknown_file';

    directFile = {
      url: finalUrl,
      filename,
      extension: extMatch || 'none',
      declaredMime: contentType || 'unknown',
      detectedSignature: magic?.label || 'Unrecognized / Stream',
      sizeBytes: contentLength,
      sha256,
      mimeMismatch,
      suspiciousNaming,
      analysisState: rawBuffer.length >= 2 * 1024 * 1024 ? 'blocked_size_limit' : 'header_inspected',
      downloadCategory,
      riskFlag,
      notes: {
        en: isDeceptive
          ? '[WARNING] Suspicious or masqueraded file payload detected. Header & SHA-256 inspected in memory.'
          : isPdf
            ? '[NOTICE] Standard PDF document detected. Static header verified.'
            : '[NOTICE] Direct application or resource download detected. User-initiated downloads on legitimate sites carry no automatic penalty.',
        ar: isDeceptive
          ? '[تحذير أمني] رُصد ملف مشبوه أو تلاعب بالامتداد؛ تم فحص البصمة الثنائية في الذاكرة.'
          : isPdf
            ? '[إشعار] تم التحقق من وثيقة PDF نظامية والتوقيع الثنائي مطابق.'
            : '[إشعار] تم رصد تنزيل ملف أو تطبيق؛ التنزيلات الاختيارية على المواقع النظيفة والمشروعة لا ترفع مستوى الخطر.',
      },
    };

    findings.push({
      id: 'file-direct-download',
      section: 'file_download_analysis',
      test: { en: 'Direct File Signature, Hash & Threat Warning', ar: 'فحص التوقيع الثنائي وبصمة الملف وتحذير التهديدات' },
      result: mimeMismatch
        ? { en: `[WARNING] MIME/Extension mismatch (${magic?.label} disguised as ${extMatch})`, ar: `[تحذير] تضارب في توقيع الملف (${magic?.label} بصيغة ${extMatch})` }
        : isDeceptive
          ? { en: `[WARNING] Deceptive or hazardous file format detected (${filename})`, ar: `[تحذير أمني] صيغة ملف خطرة أو نمط اسم مشبوه (${filename})` }
          : isPdf
            ? { en: `[VERIFIED PDF DOCUMENT] PDF document verified (${filename}) — SHA-256: ${sha256.slice(0, 12)}...`, ar: `[وثيقة PDF نظامية] تم التحقق من وثيقة PDF (${filename}) ولا تشكل خطراً بذاتها.` }
            : {
                en: `[SOFTWARE DOWNLOAD] User-initiated download (${filename}) — Static header inspected cleanly.`,
                ar: `[تنزيل تطبيق/برنامج] رُصد ملف تنزيل (${filename})؛ التنزيل المباشر بمبادرة المستخدم على موقع نظيف لا يمثل خطراً بذاته.`,
              },
      status: isDeceptive ? 'failed' : 'pass',
      severity: isDeceptive ? 'high' : 'informational',
      weight: isDeceptive ? 24 : 0,
      evidence: `File: ${filename} | Category: ${downloadCategory} | Deceptive: ${isDeceptive} | SuspiciousNaming: ${suspiciousNaming} | MIME: ${contentType} | Magic: ${magic?.label ?? 'N/A'} | SHA256: ${sha256}`,
      explanation: {
        en: isDeceptive
          ? '[SECURITY WARNING] The file uses suspicious naming or masquerades its real binary signature, posing potential endpoint threats.'
          : isPdf
            ? 'The response is a standard PDF document with verified header. Standard documents do not pose automatic system threats.'
            : 'The site provides a downloadable application or package. On legitimate corporate or official platforms, user-initiated software downloads are legitimate business operations.',
        ar: isDeceptive
          ? '[تحذير أمني] يستخدم الملف تسمية مضللة أو يخفي نوعه الحقيقي، مما يشكل خطراً محتملاً.'
          : isPdf
            ? 'الاستجابة عبارة عن ملف وثيقة PDF معيارية ذات ترويسة صحيحة، ولا تشكل خطراً بذاتها.'
            : 'يوفر الموقع ملف تطبيق أو حزمة برمجية. في حال كان الموقع تابعاً لشركة أو منصة رسمية بمحتوى نظيف وبناءً على طلب المستخدم، يعتبر التنزيل مشروعاً ولا يرفع مستوى الخطر إلى متوسط.',
      },
      recommendedAction: {
        en: isDeceptive
          ? '[WARNING & REASON] Do not open unverified or masqueraded files. Reason: Mismatched file signature poses malware risks.'
          : 'Verify publisher identity before executing application packages.',
        ar: isDeceptive
          ? '[تحذير والسبب] لا تفتح الملفات المموهة. السبب: تضارب توقيع الملف يشير إلى احتمال وجود برمجيات ضارة.'
          : 'تحقق من هوية الناشر والمصدر الرسمي قبل تثبيت الحزم البرمجية.',
      },
      forensic: {
        whereDetected: { en: `Direct HTTP payload "${filename}" (${contentType})`, ar: `الاستجابة المباشرة للملف "${filename}"` },
        whyRisky: {
          en: 'Direct binary payloads with masqueraded extensions can execute unauthorized code.',
          ar: 'الملفات المموهة قد تنفذ تعليمات برمجية دون إذن المستخدم.',
        },
        howExploited: {
          en: 'Trojans disguise executables as documents or media files.',
          ar: 'تتنكر البرمجيات الخبيثة بأسماء وثائق عادية.',
        },
        userImpact: { en: 'Endpoint compromise if malicious executable is opened.', ar: 'اختراق نظام المستخدم في حال كان الملف خبيثاً.' },
        notProvenAlone: {
          en: 'Legitimate software vendors and official platforms distribute executables and PDFs routinely.',
          ar: 'المواقع الرسمية لشركات البرمجيات والمنصات توزع تطبيقاتها ووثائقها بشكل مشروع وطبيعي.',
        },
      },
      source: 'SM In-Memory File Inspector',
      timestamp: now,
      confidence: 90,
    });
  } else if (rawBuffer && isHtmlOrText) {
    const $ = cheerio.load(rawBuffer.toString('utf8'));
    const seen = new Set<string>();
    $('a[href]').each((_, el) => {
      const href = ($(el).attr('href') || '').trim();
      if (!href || href.startsWith('#') || href.startsWith('javascript:')) return;
      try {
        const resolved = new URL(href, finalUrl).toString();
        if (seen.has(resolved)) return;
        const p = new URL(resolved).pathname.toLowerCase();
        const ext = p.match(/\.[a-z0-9]{1,8}$/)?.[0] || '';
        const fname = p.split('/').pop() || 'file';

        // Filter out cookie-related links
        if (fname.includes('cookie') || p.includes('cookie')) return;

        if (DANGEROUS_EXTENSIONS.has(ext) || ARCHIVE_EXTENSIONS.has(ext) || ext === '.pdf' || $(el).attr('download') !== undefined) {
          seen.add(resolved);
          const hasDoubleExt = /\.(pdf|doc|docx|xls|xlsx|jpg|png)\.(exe|scr|js|vbs|bat|ps1|zip)$/i.test(fname);
          const isMalScript = ['.scr', '.vbs', '.pif', '.hta', '.cpl', '.bat', '.cmd', '.ps1'].includes(ext);
          const isSuspicious = hasDoubleExt || isMalScript || hasSuspiciousFilenamePattern(fname);

          const linkedCategory: FileDownloadCategory = isSuspicious
            ? 'deceptive_download'
            : isMalScript || ext === '.js'
              ? 'script'
              : ARCHIVE_EXTENSIONS.has(ext)
                ? 'archive'
                : DANGEROUS_EXTENSIONS.has(ext)
                  ? 'executable'
                  : ext === '.pdf'
                    ? 'verified_safe_resource'
                    : 'user_initiated_download';

          discoveredDownloads.push({
            url: resolved,
            filename: fname,
            extension: ext || 'unknown',
            mimeMismatch: false,
            suspiciousNaming: isSuspicious,
            analysisState: 'not_fully_analyzed',
            downloadCategory: linkedCategory,
            riskFlag: isSuspicious ? 'high' : 'low',
            notes: {
              en: isSuspicious
                ? '[SECURITY WARNING] Suspicious or macro/script download link detected. Verify before opening.'
                : '[NOTICE] User-clickable software/resource download link detected in page HTML.',
              ar: isSuspicious
                ? '[تحذير أمني] رُصد رابط تنزيل مشبوه أو سكربت في الصفحة؛ يُرجى الحذر الشديد.'
                : '[إشعار] رُصد رابط تنزيل اختياري في الصفحة (مثل تطبيق أو ملف وثائق).',
            },
          });
        }
      } catch {
        // ignore
      }
    });

    const hasDangerousLink = discoveredDownloads.some((d) => d.riskFlag === 'high');
    findings.push({
      id: 'file-linked-downloads',
      section: 'file_download_analysis',
      test: { en: 'Linked Downloadable Resources Threat Warning', ar: 'تحذير التهديدات لروابط التنزيل المضمنة' },
      result:
        discoveredDownloads.length > 0
          ? hasDangerousLink
            ? {
                en: `[WARNING] ${discoveredDownloads.length} download link(s) detected (${discoveredDownloads.filter((d) => d.riskFlag === 'high').length} high-risk deceptive file)`,
                ar: `[تحذير أمني] رُصد ${discoveredDownloads.length} رابط تنزيل (${discoveredDownloads.filter((d) => d.riskFlag === 'high').length} ملفات مشبوهة أو مموهة)`,
              }
            : {
                en: `[OPTIONAL DOWNLOADS] ${discoveredDownloads.length} user-clickable download link(s) detected in page HTML (e.g. app/document buttons).`,
                ar: `[روابط تنزيل اختيارية] رُصد ${discoveredDownloads.length} رابط تنزيل اختياري في الصفحة (مثل أزرار تنزيل التطبيقات أو الوثائق) دون تنزيل تلقائي.`,
              }
          : { en: 'No executable or archive download links detected', ar: 'لا توجد روابط تنزيل تنفيذية أو أرشيفية' },
      status: hasDangerousLink ? 'failed' : 'pass',
      severity: hasDangerousLink ? 'high' : 'low',
      weight: hasDangerousLink ? 18 : 0,
      evidence:
        discoveredDownloads.length > 0
          ? discoveredDownloads.slice(0, 5).map((d) => `${d.filename} (${d.extension})`).join(' | ')
          : 'No risky download anchors found in HTML',
      explanation: {
        en:
          discoveredDownloads.length > 0
            ? hasDangerousLink
              ? '[SECURITY WARNING] Downloadable resource links with deceptive naming or dangerous scripts were detected.'
              : 'Downloadable links detected are standard user-clickable anchors (such as app installer or PDF buttons) without automatic download triggers.'
            : 'No links pointing to executables, scripts, archives, or macro documents were found.',
        ar:
          discoveredDownloads.length > 0
            ? hasDangerousLink
              ? '[تحذير أمني] رُصدت روابط ملفات قابلة للتنزيل بأسماء مضللة أو سكربتات تشكل خطراً.'
              : 'روابط التنزيل المرصودة هي روابط اختيارية للمستخدم (مثل أزرار تنزيل تطبيق المنصة أو وثائق PDF)، ولا يتم تنزيلها تلقائياً بدون نقر المستخدم.'
            : 'لم يتم العثور على روابط لملفات تنفيذية أو سكربتات.',
      },
      recommendedAction: {
        en: hasDangerousLink
          ? '[WARNING & REASON] Do not download unverified files. Reason: Deceptive format poses potential endpoint risks.'
          : 'Review file publisher before executing installed software.',
        ar: hasDangerousLink
          ? '[تحذير والسبب] لا تقم بتنزيل أو تشغيل ملفات مموهة. السبب: تشكل خطراً محتملاً على أمن نظام التشغيل.'
          : 'تحقق من مطور التطبيق قبل تثبيته على جهازك.',
      },
      source: 'SM HTML Download Scanner',
      timestamp: now,
      confidence: 88,
    });
  } else {
    findings.push({
      id: 'file-uninspected',
      section: 'file_download_analysis',
      test: { en: 'File & Download Threat Analysis', ar: 'تحليل تهديدات الملفات والتنزيلات' },
      result: { en: 'Not Fully Analyzed (no response payload)', ar: 'لم يُحلل بالكامل (لا يوجد محتوى)' },
      status: 'unknown',
      severity: 'unknown',
      weight: 0,
      evidence: 'No response body retrieved',
      explanation: {
        en: 'No response payload was retrieved; dynamic file analysis was not performed.',
        ar: 'تعذر استرجاع المحتوى للفحص ولم يتم إجراء تحليل ديناميكي.',
      },
      recommendedAction: {
        en: 'Treat unretrieved files as unverified.',
        ar: 'اعتبر الملفات التي تعذر جلبها غير متحقق منها.',
      },
      source: 'SM In-Memory File Inspector',
      timestamp: now,
      confidence: 20,
    });
  }

  return {
    isDirectDownload,
    directFile,
    discoveredDownloads: discoveredDownloads.slice(0, 15),
    dynamicAnalysisPerformed: false,
    findings,
  };
}
