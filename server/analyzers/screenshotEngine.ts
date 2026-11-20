import { hasSensitiveUrlCredentials, validateTargetAgainstSsrf } from '../security/ssrfGuard.ts';
import type { CheckFinding, ScreenshotResult } from '../types.ts';
import { recordProviderSuccess } from '../providers/threatIntelManager.ts';

export type ScreenshotViewportMode = 'desktop' | 'mobile' | 'full_page';

async function attemptScreenshotNeo(
  targetUrl: string,
  accessKey: string
): Promise<{
  okImage?: { contentType: string; dataUrl: string; byteLength: number };
  errorInfo?: { type: string; info: string; code?: number };
}> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 16000);
  try {
    const params = new URLSearchParams({
      access_key: accessKey,
      url: targetUrl,
    });

    const res = await fetch(`https://api.screenshotneo.com/v1/shot?${params.toString()}`, {
      method: 'GET',
      signal: controller.signal,
    });
    clearTimeout(timer);

    const contentType = (res.headers.get('content-type') || '').toLowerCase();

    // Only accept genuine image payloads with non-zero byte length
    if (res.ok && contentType.startsWith('image/')) {
      const arrBuf = await res.arrayBuffer();
      if (arrBuf.byteLength > 0 && arrBuf.byteLength <= 6 * 1024 * 1024) {
        const base64 = Buffer.from(arrBuf).toString('base64');
        const cleanMime = contentType.split(';')[0].trim() || 'image/webp';
        return {
          okImage: {
            contentType: cleanMime,
            dataUrl: `data:${cleanMime};base64,${base64}`,
            byteLength: arrBuf.byteLength,
          },
        };
      }
      return {
        errorInfo: {
          code: res.status,
          type: 'empty_or_oversized_image',
          info: 'Upstream image payload was empty or exceeded size limit',
        },
      };
    }

    if (contentType.includes('application/json') || contentType.includes('text/json')) {
      const json: any = await res.json().catch(() => null);
      const msg = String(json?.error?.message || json?.error?.info || json?.message || json?.error || '');
      const lower = msg.toLowerCase();
      const isAuth =
        res.status === 401 ||
        res.status === 403 ||
        lower.includes('access_key') ||
        lower.includes('invalid key') ||
        lower.includes('unauthorized') ||
        lower.includes('credential');
      const isQuota =
        res.status === 429 ||
        lower.includes('quota') ||
        lower.includes('limit') ||
        lower.includes('rate');

      return {
        errorInfo: {
          code: res.status,
          type: isAuth ? 'invalid_access_key' : isQuota ? 'usage_limit_reached' : `http_${res.status}`,
          info: msg || `ScreenshotNeo API returned HTTP ${res.status}`,
        },
      };
    }

    if (res.status === 401 || res.status === 403) {
      return {
        errorInfo: {
          code: res.status,
          type: 'invalid_access_key',
          info: 'Authentication rejected by ScreenshotNeo (HTTP 401/403)',
        },
      };
    }

    if (res.status === 429) {
      return {
        errorInfo: {
          code: 429,
          type: 'usage_limit_reached',
          info: 'ScreenshotNeo rate limit or quota exceeded (HTTP 429)',
        },
      };
    }

    return {
      errorInfo: {
        code: res.status,
        type: `http_${res.status}`,
        info: `ScreenshotNeo returned HTTP ${res.status} (${contentType || 'non-image response'})`,
      },
    };
  } catch (err) {
    clearTimeout(timer);
    const isTimeout = (err as any)?.name === 'AbortError';
    return {
      errorInfo: {
        type: isTimeout ? 'timeout' : 'network_error',
        info: isTimeout ? 'ScreenshotNeo capture timed out after 16 seconds' : (err as Error).message,
      },
    };
  }
}

/**
 * Validates the ScreenshotNeo integration by attempting a capture of a safe test target.
 * Never exposes the API key in results or errors.
 */
export async function testScreenshotNeoCapture(testUrl: string = 'https://example.com'): Promise<{
  success: boolean;
  configured: boolean;
  contentType?: string;
  imageBytes?: number;
  error?: string;
}> {
  const accessKey = (process.env.SCREENSHOTNEO_ACCESS_KEY || '').trim();
  if (!accessKey) {
    return {
      success: false,
      configured: false,
      error: 'SCREENSHOTNEO_ACCESS_KEY environment variable is not configured',
    };
  }

  const attempt = await attemptScreenshotNeo(testUrl, accessKey);
  if (attempt.okImage) {
    recordProviderSuccess('screenshot_neo');
    return {
      success: true,
      configured: true,
      contentType: attempt.okImage.contentType,
      imageBytes: attempt.okImage.byteLength,
    };
  }

  return {
    success: false,
    configured: true,
    error:
      attempt.errorInfo?.type === 'invalid_access_key'
        ? 'Invalid or inactive ScreenshotNeo access key'
        : attempt.errorInfo?.info || 'ScreenshotNeo capture failed',
  };
}

export async function captureWebsiteScreenshot(
  targetUrl: string,
  viewportMode: ScreenshotViewportMode = 'desktop'
): Promise<{ screenshot: ScreenshotResult; finding: CheckFinding }> {
  const now = new Date().toISOString();
  const fullPage = viewportMode === 'full_page';

  // Never forward credentials or tokens embedded in URLs to external capture endpoints
  if (hasSensitiveUrlCredentials(targetUrl)) {
    return {
      screenshot: {
        status: 'blocked_private_url',
        method: 'none',
        viewport: viewportMode,
        finalDestinationUrl: targetUrl,
        fullPageAvailable: false,
        reason: {
          en: 'Screenshot capture skipped: URL contains credentials or sensitive query tokens.',
          ar: 'تم تخطي التقاط الصورة: يحتوي الرابط على بيانات اعتماد أو رموز جلسة حساسة.',
        },
      },
      finding: {
        id: 'screenshot-capture',
        section: 'screenshot_evidence',
        test: { en: 'Automated Website Screenshot', ar: 'التقاط صورة تلقائية للموقع' },
        result: { en: 'Skipped due to sensitive URL parameters', ar: 'تم التخطي لوجود معاملات حساسة في الرابط' },
        status: 'unknown',
        severity: 'unknown',
        weight: 0,
        evidence: 'Sensitive token/credential pattern detected in target URL',
        explanation: {
          en: 'For privacy and credential protection, URLs carrying passwords, tokens, or auth codes are never forwarded to visual rendering services.',
          ar: 'لحماية الخصوصية، لا يتم إرسال الروابط التي تتضمن رموز وصول أو كلمات مرور إلى خدمات التقاط الصور.',
        },
        recommendedAction: {
          en: 'Strip query tokens before capturing a preview if you trust the destination.',
          ar: 'أزل معاملات التوثيق الحساسة قبل طلب معاينة مرئية.',
        },
        source: 'SM Screenshot Privacy Guard',
        timestamp: now,
        confidence: 100,
      },
    };
  }

  // Re-verify SSRF policy immediately prior to screenshot capture
  try {
    await validateTargetAgainstSsrf(targetUrl);
  } catch (err) {
    return {
      screenshot: {
        status: 'blocked_private_url',
        method: 'none',
        viewport: viewportMode,
        finalDestinationUrl: targetUrl,
        fullPageAvailable: false,
        reason: { en: (err as Error).message, ar: (err as Error).message },
      },
      finding: {
        id: 'screenshot-capture',
        section: 'screenshot_evidence',
        test: { en: 'Automated Website Screenshot', ar: 'التقاط صورة تلقائية للموقع' },
        result: { en: 'Blocked by SSRF policy', ar: 'تم الحظر بواسطة سياسة الحماية من SSRF' },
        status: 'failed',
        severity: 'high',
        weight: 0,
        evidence: (err as Error).message,
        explanation: {
          en: 'Target URL failed SSRF boundary checks and was blocked from visual capture.',
          ar: 'فشل الهدف في اجتياز فحص SSRF وتم منعه من التقاط المعاينة البصرية.',
        },
        recommendedAction: {
          en: 'Do not render internal or restricted network addresses.',
          ar: 'تجنب فتح عناوين الشبكات الداخلية أو المحظورة.',
        },
        source: 'SM SSRF Guard',
        timestamp: now,
        confidence: 100,
      },
    };
  }

  const accessKey = (process.env.SCREENSHOTNEO_ACCESS_KEY || '').trim();
  if (!accessKey) {
    const missingReason = {
      en: 'ScreenshotNeo integration is unconfigured: SCREENSHOTNEO_ACCESS_KEY environment variable is missing on the backend server.',
      ar: 'خدمة ScreenshotNeo غير مهيأة: متغير البيئة SCREENSHOTNEO_ACCESS_KEY غير محدد في الخادم.',
    };
    return {
      screenshot: {
        status: 'unavailable',
        method: 'none',
        viewport: viewportMode,
        finalDestinationUrl: targetUrl,
        fullPageAvailable: false,
        reason: missingReason,
      },
      finding: {
        id: 'screenshot-capture',
        section: 'screenshot_evidence',
        test: { en: 'Automated Website Screenshot', ar: 'التقاط صورة تلقائية للموقع' },
        result: {
          en: 'Screenshot unavailable (SCREENSHOTNEO_ACCESS_KEY not configured)',
          ar: 'التقاط الصورة غير متاح (SCREENSHOTNEO_ACCESS_KEY غير مهيأ)',
        },
        status: 'unknown',
        severity: 'unknown',
        weight: 0,
        evidence: missingReason.en,
        explanation: {
          en: 'All network, TLS, domain, HTML, deception, and threat-intelligence checks ran independently. Configure SCREENSHOTNEO_ACCESS_KEY on the server to enable visual previews.',
          ar: 'استمرت جميع فحوصات الشبكة والشهادة والمحتوى والاستخبارات بشكل طبيعي. أضف متغير SCREENSHOTNEO_ACCESS_KEY في الخادم لتفعيل الالتقاط المباشر.',
        },
        recommendedAction: {
          en: 'Review the HTML Content, Phishing Detection, and Domain Deception telemetry below rather than visiting the link directly.',
          ar: 'اعتمد على تحليل المحتوى وكشف التصيد وخداع النطاق أدناه بدلاً من فتح الرابط مباشرة.',
        },
        source: 'ScreenshotNeo Engine',
        timestamp: now,
        confidence: 100,
        errorState: missingReason.en,
      },
    };
  }

  const attempt = await attemptScreenshotNeo(targetUrl, accessKey);
  if (attempt.okImage) {
    recordProviderSuccess('screenshot_neo');
    return {
      screenshot: {
        status: 'captured',
        method: 'screenshotneo',
        viewport: viewportMode,
        capturedAt: now,
        finalDestinationUrl: targetUrl,
        imageDataUrl: attempt.okImage.dataUrl,
        fullPageAvailable: fullPage,
      },
      finding: {
        id: 'screenshot-capture',
        section: 'screenshot_evidence',
        test: { en: 'Automated Website Screenshot', ar: 'التقاط صورة تلقائية للموقع' },
        result: {
          en: `Captured live preview via ScreenshotNeo (${Math.round(attempt.okImage.byteLength / 1024)} KB ${attempt.okImage.contentType})`,
          ar: `تم التقاط المعاينة البصرية عبر ScreenshotNeo (${Math.round(attempt.okImage.byteLength / 1024)} كيلوبايت)`,
        },
        status: 'pass',
        severity: 'informational',
        weight: 0,
        evidence: `Method: screenshotneo | Format: ${attempt.okImage.contentType} | Bytes: ${attempt.okImage.byteLength} | Timestamp: ${now}`,
        explanation: {
          en: 'Live visual snapshot rendered safely via the backend ScreenshotNeo capture gateway without opening the link in your local browser.',
          ar: 'تم التقاط لقطة شاشة حية للموقع عبر بوابة ScreenshotNeo من الخادم دون تعريض متصفحك لزيارة الرابط مباشرة.',
        },
        recommendedAction: {
          en: 'Inspect the preview visually for spoofed login pages or fake system warnings before visiting.',
          ar: 'افحص المعاينة بصرياً للبحث عن أي انتحال للعلامات التجارية أو نوافذ خداع قبل زيارة الموقع.',
        },
        source: 'ScreenshotNeo API',
        timestamp: now,
        confidence: 98,
      },
    };
  }

  const errType = attempt.errorInfo?.type || 'provider_error';
  let reason: { en: string; ar: string };
  let shortResult: { en: string; ar: string };

  if (errType === 'invalid_access_key') {
    reason = {
      en: 'ScreenshotNeo authentication failed: Invalid or inactive access key in SCREENSHOTNEO_ACCESS_KEY.',
      ar: 'فشل توثيق ScreenshotNeo: مفتاح الوصول المحدد في SCREENSHOTNEO_ACCESS_KEY غير صالح أو غير نشط.',
    };
    shortResult = {
      en: 'Screenshot capture failed (invalid or rejected access key)',
      ar: 'فشل التقاط صورة الموقع (مفتاح وصول غير صالح أو مرفوض)',
    };
  } else if (errType === 'usage_limit_reached') {
    reason = {
      en: 'ScreenshotNeo quota or rate limit reached on upstream account.',
      ar: 'تم بلوغ الحد الأقصى لطلبات أو حصة ScreenshotNeo لدى المزود.',
    };
    shortResult = {
      en: 'Screenshot capture failed (quota or rate limit reached)',
      ar: 'فشل التقاط صورة الموقع (بلوغ حد الطلبات أو الحصة)',
    };
  } else if (errType === 'timeout') {
    reason = {
      en: 'ScreenshotNeo capture timed out after 16 seconds.',
      ar: 'انتهت مهلة التقاط الصورة من ScreenshotNeo (١٦ ثانية).',
    };
    shortResult = {
      en: 'Screenshot capture timed out',
      ar: 'انتهت مهلة التقاط صورة الموقع',
    };
  } else {
    reason = {
      en: `ScreenshotNeo upstream error: ${attempt.errorInfo?.info || 'capture rejected'}`,
      ar: `أرجع مزود ScreenshotNeo خطأ: ${attempt.errorInfo?.info || 'فشل الالتقاط'}`,
    };
    shortResult = {
      en: 'Screenshot capture failed',
      ar: 'فشل التقاط صورة الموقع',
    };
  }

  return {
    screenshot: {
      status: 'failed',
      method: 'none',
      viewport: viewportMode,
      finalDestinationUrl: targetUrl,
      fullPageAvailable: false,
      reason,
    },
    finding: {
      id: 'screenshot-capture',
      section: 'screenshot_evidence',
      test: { en: 'Automated Website Screenshot', ar: 'التقاط صورة تلقائية للموقع' },
      result: shortResult,
      status: 'unknown',
      severity: 'unknown',
      weight: 0,
      evidence: reason.en,
      explanation: {
        en: 'Screenshot capture did not return a valid image. All structural, TLS, DOM, and threat-intelligence checks ran independently.',
        ar: 'لم ترجع خدمة التقاط الصور صورة صالحة. استمرت جميع الفحوصات الأخرى بشكل مستقل.',
      },
      recommendedAction: {
        en: 'Review the structural and threat-feed evidence below rather than visiting the URL directly.',
        ar: 'اعتمد على نتائج الفحص والأدلة التقنية أدناه بدلاً من فتح الرابط مباشرة.',
      },
      source: 'ScreenshotNeo API',
      timestamp: now,
      confidence: 100,
      errorState: reason.en,
    },
  };
}
