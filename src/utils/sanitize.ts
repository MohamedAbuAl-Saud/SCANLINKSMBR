import type { ScanReport } from '../types/scan';

/**
 * Validates and permits ONLY safe external HTTP/HTTPS href values.
 * Rejects javascript:, data:, vbscript:, file:, and control-character bypasses.
 */
export function safeExternalHref(raw?: string | null): string | undefined {
  if (!raw || typeof raw !== 'string') return undefined;
  const cleaned = raw.replace(/[\u0000-\u001F\u007F]/g, '').trim();
  if (!cleaned) return undefined;

  if (cleaned.startsWith('/') && !cleaned.startsWith('//')) {
    return cleaned;
  }

  try {
    const parsed = new URL(cleaned);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return parsed.toString();
    }
    return undefined;
  } catch {
    return undefined;
  }
}

const STRICT_BASE64_IMAGE_DATA_URL_RE =
  /^data:image\/(?:png|jpe?g|webp|gif|x-icon|vnd\.microsoft\.icon|svg\+xml);base64,[A-Za-z0-9+/=]+$/i;

/**
 * Validates rendered image URIs (favicons & screenshots).
 * Accepts strictly base64-encoded image data URIs or safe local/HTTPS image paths.
 * Blocks raw SVG markup, HTML payloads, and javascript: URIs.
 */
export function safeImageDataUrl(raw?: string | null): string | undefined {
  if (!raw || typeof raw !== 'string') return undefined;
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  if (STRICT_BASE64_IMAGE_DATA_URL_RE.test(trimmed)) {
    return trimmed;
  }
  if (trimmed.startsWith('/') && !trimmed.startsWith('//')) {
    return trimmed;
  }
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
      return parsed.toString();
    }
  } catch {
    // reject invalid
  }
  return undefined;
}

/**
 * Sanitizes URL query parameter input (e.g. ?url=...) before triggering an auto-scan.
 */
export function sanitizeUrlParamForScan(raw?: string | null): string | undefined {
  if (!raw || typeof raw !== 'string') return undefined;
  const cleaned = raw.replace(/[\u0000-\u001F\u007F]/g, '').trim();
  if (!cleaned || cleaned.length > 2048) return undefined;
  if (/^(?:javascript|data|vbscript|file|about|blob):/i.test(cleaned)) {
    return undefined;
  }
  return cleaned;
}

/**
 * Strips control characters from plain text fields hydrated from storage.
 */
export function sanitizePlainText(raw?: unknown): string {
  if (typeof raw !== 'string') return '';
  return raw.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '');
}

/**
 * Sanitizes a ScanReport retrieved from localStorage to prevent stored XSS
 * via tampered URLs, image data URIs, or provider references.
 */
export function sanitizeSavedReport(report: ScanReport): ScanReport {
  return {
    ...report,
    submittedUrl: sanitizePlainText(report.submittedUrl),
    normalizedUrl: sanitizePlainText(report.normalizedUrl),
    finalDestinationUrl: sanitizePlainText(report.finalDestinationUrl),
    pageTitle: report.pageTitle ? sanitizePlainText(report.pageTitle) : undefined,
    siteFaviconDataUrl: safeImageDataUrl(report.siteFaviconDataUrl),
    siteFaviconSourceUrl: safeExternalHref(report.siteFaviconSourceUrl),
    screenshot: report.screenshot
      ? {
          ...report.screenshot,
          finalDestinationUrl: sanitizePlainText(report.screenshot.finalDestinationUrl),
          imageDataUrl: safeImageDataUrl(report.screenshot.imageDataUrl),
          mobileImageDataUrl: safeImageDataUrl(report.screenshot.mobileImageDataUrl),
        }
      : report.screenshot,
    threatProviders: Array.isArray(report.threatProviders)
      ? report.threatProviders.map((p) => ({
          ...p,
          referenceUrl: safeExternalHref(p.referenceUrl),
        }))
      : [],
    levelB: report.levelB
      ? {
          ...report.levelB,
          finalUrl: report.levelB.finalUrl
            ? safeExternalHref(report.levelB.finalUrl) || sanitizePlainText(report.levelB.finalUrl)
            : undefined,
          redirects: Array.isArray(report.levelB.redirects)
            ? report.levelB.redirects.map((r) => ({
                ...r,
                url: sanitizePlainText(r.url),
                note: r.note ? sanitizePlainText(r.note) : undefined,
              }))
            : [],
          screenshot: report.levelB.screenshot
            ? {
                ...report.levelB.screenshot,
                dataUrl: safeImageDataUrl(report.levelB.screenshot.dataUrl),
              }
            : report.levelB.screenshot,
          networkRequests: Array.isArray(report.levelB.networkRequests)
            ? report.levelB.networkRequests.map((req) => ({
                ...req,
                url: sanitizePlainText(req.url),
                domain: sanitizePlainText(req.domain),
                path: sanitizePlainText(req.path),
                method: sanitizePlainText(req.method),
              }))
            : [],
          permissionEvents: Array.isArray(report.levelB.permissionEvents)
            ? report.levelB.permissionEvents.map((ev) => ({
                ...ev,
                api: sanitizePlainText(ev.api),
              }))
            : [],
        }
      : undefined,
  };
}
