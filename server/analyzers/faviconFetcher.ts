import * as cheerio from 'cheerio';
import { validateTargetAgainstSsrf } from '../security/ssrfGuard.ts';

export interface FaviconFetchResult {
  dataUrl?: string;
  sourceUrl?: string;
}

const MAX_FAVICON_BYTES = 150 * 1024;
const FAVICON_TIMEOUT_MS = 3500;

function detectImageMimeFromBytes(buf: Buffer, headerMime: string): string | null {
  if (buf.length < 4) return null;

  // PNG: 89 50 4E 47
  if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) {
    return 'image/png';
  }
  // ICO / CUR: 00 00 01 00 or 00 00 02 00
  if (buf[0] === 0x00 && buf[1] === 0x00 && (buf[2] === 0x01 || buf[2] === 0x02) && buf[3] === 0x00) {
    return 'image/x-icon';
  }
  // JPEG: FF D8 FF
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) {
    return 'image/jpeg';
  }
  // GIF: GIF8
  if (buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x38) {
    return 'image/gif';
  }
  // WEBP: RIFF....WEBP
  if (
    buf.length >= 12 &&
    buf.subarray(0, 4).toString('ascii') === 'RIFF' &&
    buf.subarray(8, 12).toString('ascii') === 'WEBP'
  ) {
    return 'image/webp';
  }

  // SVG: allow only strictly sanitized SVG without scripts or event handlers
  const prefix = buf.subarray(0, 256).toString('utf8').trimStart().toLowerCase();
  if (headerMime.includes('image/svg+xml') || prefix.startsWith('<svg') || (prefix.startsWith('<?xml') && prefix.includes('<svg'))) {
    return 'image/svg+xml';
  }

  return null;
}

function sanitizeSvgBuffer(buf: Buffer): Buffer | null {
  let text = buf.toString('utf8');
  if (!/<svg[\s>]/i.test(text)) return null;
  // Reject active script/foreignObject payloads in SVG icons
  if (/<script\b|<foreignObject\b|javascript:/i.test(text)) {
    text = text
      .replace(/<script\b[\s\S]*?<\/script>/gi, '')
      .replace(/<foreignObject\b[\s\S]*?<\/foreignObject>/gi, '')
      .replace(/\son[a-z]+\s*=\s*(['"])[\s\S]*?\1/gi, '')
      .replace(/javascript:/gi, '');
  }
  return Buffer.from(text, 'utf8');
}

function extractFaviconCandidates(finalUrl: string, htmlBuffer?: Buffer, contentType?: string): string[] {
  const candidates: string[] = [];
  const seen = new Set<string>();

  const pushCandidate = (rawHref: string | undefined) => {
    if (!rawHref) return;
    const trimmed = rawHref.trim();
    if (!trimmed || trimmed.startsWith('data:')) return;
    try {
      const resolved = new URL(trimmed, finalUrl);
      if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') return;
      const href = resolved.toString();
      if (!seen.has(href)) {
        seen.add(href);
        candidates.push(href);
      }
    } catch {
      // Ignore malformed icon URLs
    }
  };

  if (
    htmlBuffer &&
    (!contentType || contentType.toLowerCase().includes('text/html') || contentType.toLowerCase().includes('application/xhtml'))
  ) {
    try {
      const $ = cheerio.load(htmlBuffer.toString('utf8'));
      const selectors = [
        'link[rel="icon"]',
        'link[rel="shortcut icon"]',
        'link[rel~="icon"]',
        'link[rel="apple-touch-icon"]',
        'link[rel="apple-touch-icon-precomposed"]',
      ];
      for (const sel of selectors) {
        $(sel).each((_, el) => {
          pushCandidate($(el).attr('href'));
        });
      }
    } catch {
      // Fall back to /favicon.ico
    }
  }

  try {
    pushCandidate(new URL('/favicon.ico', finalUrl).toString());
  } catch {
    // ignore
  }

  return candidates.slice(0, 4);
}

async function fetchSingleCandidateSafe(candidateUrl: string): Promise<FaviconFetchResult | null> {
  let currentUrl = candidateUrl;

  for (let hop = 0; hop < 2; hop++) {
    await validateTargetAgainstSsrf(currentUrl);
    const res = await fetch(currentUrl, {
      method: 'GET',
      redirect: 'manual',
      signal: AbortSignal.timeout(FAVICON_TIMEOUT_MS),
      headers: {
        'User-Agent': 'ScanLinkSM-IconInspector/2.0',
        Accept: 'image/png,image/x-icon,image/webp,image/jpeg,image/svg+xml,image/*;q=0.8',
      },
    });

    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get('location');
      if (!location) return null;
      currentUrl = new URL(location, currentUrl).toString();
      continue;
    }

    if (!res.ok) return null;

    const declaredMime = (res.headers.get('content-type') || '').toLowerCase();
    const contentLength = Number(res.headers.get('content-length') || '0');
    if (contentLength > MAX_FAVICON_BYTES) return null;

    const arrayBuf = await res.arrayBuffer();
    if (arrayBuf.byteLength === 0 || arrayBuf.byteLength > MAX_FAVICON_BYTES) return null;

    let buf: Buffer = Buffer.from(arrayBuf);
    const detectedMime = detectImageMimeFromBytes(buf, declaredMime);
    if (!detectedMime) return null;

    if (detectedMime === 'image/svg+xml') {
      const sanitized = sanitizeSvgBuffer(buf);
      if (!sanitized) return null;
      buf = sanitized;
    }

    return {
      dataUrl: `data:${detectedMime};base64,${buf.toString('base64')}`,
      sourceUrl: currentUrl,
    };
  }

  return null;
}

export async function fetchSiteFaviconSafely(
  finalUrl: string,
  htmlBuffer?: Buffer,
  contentType?: string
): Promise<FaviconFetchResult> {
  const candidates = extractFaviconCandidates(finalUrl, htmlBuffer, contentType);
  for (const candidate of candidates) {
    try {
      const result = await fetchSingleCandidateSafe(candidate);
      if (result?.dataUrl) {
        return result;
      }
    } catch {
      // Try next candidate
    }
  }
  return {};
}
