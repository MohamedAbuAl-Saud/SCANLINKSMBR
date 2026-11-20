import dns from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { domainToASCII } from 'node:url';

export interface ValidatedTarget {
  originalInput: string;
  normalizedUrl: string;
  parsed: URL;
  asciiHostname: string;
  resolvedIps: string[];
  pinnedIp: string;
}

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  'metadata.google.internal',
  'metadata.goog',
  'metadata.azure.internal',
  '169.254.169.254',
  '169.254.170.2',
  '100.100.100.200',
  'instance-data',
]);

function ipv4ToInt(ip: string): number {
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function inCidr4(ip: string, base: string, maskBits: number): boolean {
  const mask = maskBits === 0 ? 0 : (~0 << (32 - maskBits)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(base) & mask);
}

/**
 * Normalizes IPv6 hex/zero-compressed notation and checks private/reserved IPv4 & IPv6 ranges.
 */
export function isPrivateOrReservedIp(rawIp: string): boolean {
  let ip = rawIp.trim().toLowerCase();
  if (ip.startsWith('[') && ip.endsWith(']')) {
    ip = ip.slice(1, -1);
  }
  if (ip.includes('%')) {
    ip = ip.split('%')[0];
  }

  // Handle IPv4-mapped IPv6 addresses like ::ffff:127.0.0.1 or 0:0:0:0:0:ffff:127.0.0.1
  const v4MappedPrefix = /^((0{1,4}:){5}|::ffff:)/i;
  if (net.isIPv6(ip) && v4MappedPrefix.test(ip)) {
    const tail = ip.split(':').pop() || '';
    if (net.isIPv4(tail)) {
      return isPrivateOrReservedIp(tail);
    }
    // Check hex form ::ffff:7f00:0001
    const hexParts = ip.split(':').filter(Boolean);
    if (hexParts.length >= 2) {
      const hi = parseInt(hexParts[hexParts.length - 2], 16);
      const lo = parseInt(hexParts[hexParts.length - 1], 16);
      if (!Number.isNaN(hi) && !Number.isNaN(lo) && hi <= 0xffff && lo <= 0xffff) {
        const reconstructedV4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
        if (net.isIPv4(reconstructedV4)) {
          return isPrivateOrReservedIp(reconstructedV4);
        }
      }
    }
  }

  if (net.isIPv4(ip)) {
    return (
      inCidr4(ip, '0.0.0.0', 8) ||       // "This" network
      inCidr4(ip, '10.0.0.0', 8) ||      // RFC1918 private
      inCidr4(ip, '100.64.0.0', 10) ||   // CGNAT RFC6598
      inCidr4(ip, '127.0.0.0', 8) ||     // Loopback
      inCidr4(ip, '169.254.0.0', 16) ||  // Link-local / Cloud Metadata
      inCidr4(ip, '172.16.0.0', 12) ||   // RFC1918 private
      inCidr4(ip, '192.0.0.0', 24) ||    // IETF protocol assignments
      inCidr4(ip, '192.0.2.0', 24) ||    // TEST-NET-1
      inCidr4(ip, '192.168.0.0', 16) ||  // RFC1918 private
      inCidr4(ip, '198.18.0.0', 15) ||   // Benchmarking
      inCidr4(ip, '198.51.100.0', 24) || // TEST-NET-2
      inCidr4(ip, '203.0.113.0', 24) ||  // TEST-NET-3
      inCidr4(ip, '224.0.0.0', 4) ||     // Multicast
      inCidr4(ip, '240.0.0.0', 4)        // Reserved / Broadcast
    );
  }

  if (net.isIPv6(ip)) {
    // Expand zero compressions for reliable CIDR comparison
    if (ip === '::' || ip === '::1' || /^0(:0)*(:0{0,4})?$/.test(ip) || /^0(:0)*:1$/.test(ip)) {
      return true;
    }
    const firstHextet = ip.split(':')[0] || '';
    if (
      ip.startsWith('fe80:') ||
      ip.startsWith('fe9') ||
      ip.startsWith('fea') ||
      ip.startsWith('feb') ||
      ip.startsWith('fc') ||
      ip.startsWith('fd') ||
      ip.startsWith('ff') ||
      /^64:ff9b:/i.test(ip) || // NAT64 RFC6052 / RFC8215
      /^100::/i.test(ip) ||    // Discard-only
      /^2001:db8:/i.test(ip) || // Documentation
      firstHextet === '0000'
    ) {
      return true;
    }
    if (ip.includes('.')) {
      const lastColon = ip.lastIndexOf(':');
      const v4 = ip.slice(lastColon + 1);
      if (net.isIPv4(v4)) {
        return isPrivateOrReservedIp(v4);
      }
    }
    return false;
  }

  return true;
}

export function normalizeSubmittedUrl(rawInput: string): URL {
  const trimmed = rawInput.trim();
  if (!trimmed || trimmed.length > 2048) {
    throw new Error('URL must be between 1 and 2048 characters.');
  }

  if (/[\s\u0000-\u001f\u007f]/.test(trimmed)) {
    throw new Error('URL contains invalid whitespace or control characters.');
  }

  const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)
    ? trimmed
    : trimmed.includes(':') && !/^\d/.test(trimmed) && !trimmed.includes('/')
      ? trimmed
      : `https://${trimmed}`;

  let parsed: URL;
  try {
    parsed = new URL(withScheme);
  } catch {
    throw new Error('Malformed URL syntax.');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Unsupported protocol "${parsed.protocol}". Only HTTP and HTTPS are permitted.`);
  }

  if (!parsed.hostname) {
    throw new Error('URL does not contain a valid hostname.');
  }

  return parsed;
}

export async function validateTargetAgainstSsrf(rawUrl: string): Promise<ValidatedTarget> {
  const parsed = normalizeSubmittedUrl(rawUrl);
  const rawHost = parsed.hostname.toLowerCase().replace(/\.$/, '');

  if (
    BLOCKED_HOSTNAMES.has(rawHost) ||
    rawHost.endsWith('.local') ||
    rawHost.endsWith('.internal') ||
    rawHost.endsWith('.localhost')
  ) {
    throw new Error(`SSRF Guard: Hostname "${rawHost}" is blocked (internal/reserved).`);
  }

  const asciiHostname = domainToASCII(rawHost) || rawHost;
  if (!asciiHostname) {
    throw new Error('Invalid internationalized domain name.');
  }

  const strippedHost =
    asciiHostname.startsWith('[') && asciiHostname.endsWith(']')
      ? asciiHostname.slice(1, -1)
      : asciiHostname;

  if (net.isIP(strippedHost)) {
    if (isPrivateOrReservedIp(strippedHost)) {
      throw new Error(`SSRF Guard: Direct access to private/reserved IP (${strippedHost}) is blocked.`);
    }
    return {
      originalInput: rawUrl,
      normalizedUrl: parsed.toString(),
      parsed,
      asciiHostname,
      resolvedIps: [strippedHost],
      pinnedIp: strippedHost,
    };
  }

  let records: { address: string; family: number }[] = [];
  try {
    records = await dns.lookup(asciiHostname, { all: true, verbatim: true });
  } catch (err) {
    throw new Error(`DNS resolution failed for "${asciiHostname}": ${(err as Error).message}`);
  }

  if (!records || records.length === 0) {
    throw new Error(`No DNS address records found for "${asciiHostname}".`);
  }

  const resolvedIps = records.map((r) => r.address);
  for (const ip of resolvedIps) {
    if (isPrivateOrReservedIp(ip)) {
      throw new Error(
        `SSRF Guard: Domain "${asciiHostname}" resolved to a private or reserved IP (${ip}). Connection blocked.`
      );
    }
  }

  return {
    originalInput: rawUrl,
    normalizedUrl: parsed.toString(),
    parsed,
    asciiHostname,
    resolvedIps,
    pinnedIp: resolvedIps[0],
  };
}

export interface SafeFetchOptions {
  timeoutMs?: number;
  maxBytes?: number;
  method?: 'GET' | 'HEAD';
  headers?: Record<string, string>;
}

export interface SafeFetchResult {
  url: string;
  status: number;
  headers: Record<string, string>;
  setCookies?: string[];
  buffer: Buffer;
  truncated: boolean;
  resolvedIp: string;
  latencyMs: number;
}

/**
 * Performs a single non-redirecting HTTP(S) request pinned strictly to the already-validated
 * public IP (`validated.pinnedIp`) via a custom `lookup` hook to prevent TOCTOU DNS rebinding.
 */
export async function safeSingleFetch(
  targetUrl: string,
  options: SafeFetchOptions = {}
): Promise<SafeFetchResult> {
  const timeoutMs = options.timeoutMs ?? 8000;
  const maxBytes = options.maxBytes ?? 2 * 1024 * 1024;
  const start = Date.now();

  const validated = await validateTargetAgainstSsrf(targetUrl);
  const parsed = validated.parsed;
  const pinnedIp = validated.pinnedIp;
  const pinnedFamily = net.isIPv6(pinnedIp) ? 6 : 4;
  const isHttps = parsed.protocol === 'https:';
  const defaultPort = isHttps ? 443 : 80;
  const port = parsed.port ? Number(parsed.port) : defaultPort;

  return new Promise<SafeFetchResult>((resolve, reject) => {
    let settled = false;
    const finishErr = (err: Error) => {
      if (!settled) {
        settled = true;
        reject(err);
      }
    };

    const transport = isHttps ? https : http;
    const reqHeaders: Record<string, string> = {
      'User-Agent': 'ScanLinkSM-SecurityAnalyzer/2.0 (+https://scanlink-sm.local)',
      Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.9',
      'Accept-Encoding': 'identity',
      Host: parsed.host,
      ...(options.headers ?? {}),
    };

    const req = transport.request(
      {
        hostname: parsed.hostname.replace(/^\[|\]$/g, ''),
        port,
        path: `${parsed.pathname || '/'}${parsed.search || ''}`,
        method: options.method ?? 'GET',
        headers: reqHeaders,
        timeout: timeoutMs,
        servername: net.isIP(validated.asciiHostname.replace(/^\[|\]$/g, ''))
          ? undefined
          : validated.asciiHostname,
        rejectUnauthorized: false, // TLS trust is audited independently by tlsInspector without breaking forensic HTML capture
        lookup: (_hostname, lookupOpts, cb) => {
          // Support both (err, address, family) and (err, [{address, family}]) signatures
          if (lookupOpts && typeof lookupOpts === 'object' && lookupOpts.all) {
            (cb as unknown as (err: null, list: { address: string; family: number }[]) => void)(null, [
              { address: pinnedIp, family: pinnedFamily },
            ]);
            return;
          }
          cb(null, pinnedIp, pinnedFamily);
        },
      },
      (res) => {
        const headersObj: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers)) {
          if (typeof v === 'string') {
            headersObj[k.toLowerCase()] = v;
          } else if (Array.isArray(v)) {
            headersObj[k.toLowerCase()] = v.join(', ');
          }
        }
        const rawSetCookie = res.headers['set-cookie'];
        const setCookies = Array.isArray(rawSetCookie)
          ? rawSetCookie
          : typeof rawSetCookie === 'string'
            ? [rawSetCookie]
            : undefined;

        const chunks: Buffer[] = [];
        let totalBytes = 0;
        let truncated = false;

        res.on('data', (chunk: Buffer) => {
          const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          const remaining = maxBytes - totalBytes;
          if (remaining <= 0) {
            truncated = true;
            res.destroy();
            return;
          }
          if (buf.length > remaining) {
            chunks.push(buf.subarray(0, remaining));
            totalBytes += remaining;
            truncated = true;
            res.destroy();
            return;
          }
          chunks.push(buf);
          totalBytes += buf.length;
        });

        const complete = () => {
          if (!settled) {
            settled = true;
            resolve({
              url: validated.normalizedUrl,
              status: res.statusCode ?? 0,
              headers: headersObj,
              setCookies,
              buffer: Buffer.concat(chunks),
              truncated,
              resolvedIp: pinnedIp,
              latencyMs: Date.now() - start,
            });
          }
        };

        res.on('end', complete);
        res.on('close', complete);
        res.on('error', (err) => {
          if (truncated) {
            complete();
          } else {
            finishErr(err);
          }
        });
      }
    );

    req.on('timeout', () => {
      req.destroy(new Error(`Request timeout after ${timeoutMs}ms`));
    });

    req.on('error', (err) => {
      if (!settled) finishErr(err);
    });

    req.end();
  });
}

export function hasSensitiveUrlCredentials(urlStr: string): boolean {
  try {
    const u = new URL(urlStr);
    if (u.username || u.password) return true;
    const sensitiveKeys = [
      'token',
      'auth',
      'password',
      'pass',
      'pwd',
      'secret',
      'session',
      'sid',
      'key',
      'jwt',
      'bearer',
    ];
    for (const [k] of u.searchParams.entries()) {
      const lower = k.toLowerCase();
      if (sensitiveKeys.some((sk) => lower.includes(sk))) {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}
