import net from 'node:net';
import { domainToASCII, domainToUnicode } from 'node:url';
import { parse as parseTldts } from 'tldts';
import type { CheckFinding, UrlEncryptionSegment, UrlEncryptionTelemetry } from '../types.ts';
import { classifyDomainRelationship, lookupDomainOwnership } from './officialDomainRegistry.ts';

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'adf.ly', 'bit.do', 'mcaf.ee', 'su.pr', 'cutt.ly', 'rb.gy', 'shorturl.at',
  'tiny.cc', 'lnkd.in', 'rebrand.ly', 's.id', 'v.gd', 'clk.sh', 't.ly', 'short.io', 'x.co',
]);

const SUSPICIOUS_TLDS = new Set([
  'zip', 'mov', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'icu', 'club',
  'work', 'click', 'link', 'loan', 'download', 'stream', 'bid', 'win', 'xin', 'cfd', 'sbs', 'rest', 'cam',
]);

const MULTI_TENANT_PAAS_SUFFIXES: { suffix: string; provider: string }[] = [
  { suffix: 'sites.google.com', provider: 'Google Sites' },
  { suffix: 'appspot.com', provider: 'Google App Engine' },
  { suffix: 'firebaseapp.com', provider: 'Firebase Hosting' },
  { suffix: 'web.app', provider: 'Firebase Hosting' },
  { suffix: 'github.io', provider: 'GitHub Pages' },
  { suffix: 'pages.dev', provider: 'Cloudflare Pages' },
  { suffix: 'workers.dev', provider: 'Cloudflare Workers' },
  { suffix: 'vercel.app', provider: 'Vercel' },
  { suffix: 'netlify.app', provider: 'Netlify' },
  { suffix: 'herokuapp.com', provider: 'Heroku' },
  { suffix: 'blogspot.com', provider: 'Blogger' },
  { suffix: 'weebly.com', provider: 'Weebly' },
  { suffix: '000webhostapp.com', provider: '000webhost' },
  { suffix: 's3.amazonaws.com', provider: 'AWS S3' },
  { suffix: 'blob.core.windows.net', provider: 'Azure Blob Storage' },
  { suffix: 'trycloudflare.com', provider: 'Cloudflare Quick Tunnel' },
  { suffix: 'ngrok-free.app', provider: 'ngrok Tunnel' },
  { suffix: 'ngrok.io', provider: 'ngrok Tunnel' },
  { suffix: 'up.railway.app', provider: 'Railway Hosted App' },
  { suffix: 'railway.app', provider: 'Railway Hosted App' },
  { suffix: 'onrender.com', provider: 'Render' },
  { suffix: 'fly.dev', provider: 'Fly.io' },
  { suffix: 'hf.space', provider: 'Hugging Face Spaces' },
  { suffix: 'gitlab.io', provider: 'GitLab Pages' },
  { suffix: 'webflow.io', provider: 'Webflow Staging' },
  { suffix: 'notion.site', provider: 'Notion Public Sites' },
  { suffix: 'wixsite.com', provider: 'Wix Free Sites' },
  { suffix: 'wordpress.com', provider: 'WordPress.com' },
  { suffix: 'replit.dev', provider: 'Replit' },
  { suffix: 'glitch.me', provider: 'Glitch' },
];

const EXECUTABLE_EXTENSIONS = new Set([
  '.exe', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jse', '.scr',
  '.pif', '.com', '.hta', '.cpl', '.lnk', '.iso', '.img', '.apk', '.dmg', '.pkg',
]);

const SUSPICIOUS_PARAM_KEYS = [
  'redirect', 'redirect_uri', 'redirect_url', 'next', 'url', 'target', 'dest', 'destination',
  'redir', 'continue', 'return', 'returnurl', 'return_url', 'goto', 'callback', 'login', 'email', 'u', 'cmd', 'exec',
];

const PHISHING_LEXICAL_TOKENS = [
  'login', 'signin', 'verify', 'verification', 'account', 'update', 'secure',
  'security', 'banking', 'wallet', 'confirm', 'suspend', 'locked', 'unlock',
  'webscr', 'billing', 'invoice', 'recover', 'auth', 'sso', 'phish', 'phishing',
];

export interface UrlIntelResult {
  findings: CheckFinding[];
  isShortener: boolean;
  isMultiTenantPaas: boolean;
  paasProvider?: string;
  registrableDomain: string;
  publicSuffix: string;
  unicodeDomain: string;
  asciiDomain: string;
  suspiciousPathTokens: string[];
  encryptionTelemetry: UrlEncryptionTelemetry;
}

export function extractPslBreakdown(hostname: string): {
  eTldPlusOne: string;
  publicSuffix: string;
  subdomain: string;
  isIp: boolean;
} {
  const clean = hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (net.isIP(clean) !== 0) {
    return { eTldPlusOne: clean, publicSuffix: '', subdomain: '', isIp: true };
  }
  const parsed = parseTldts(clean, { allowPrivateDomains: false });
  if (parsed.domain && parsed.publicSuffix) {
    return {
      eTldPlusOne: parsed.domain,
      publicSuffix: parsed.publicSuffix,
      subdomain: parsed.subdomain || '',
      isIp: Boolean(parsed.isIp),
    };
  }
  const parts = clean.split('.').filter(Boolean);
  return {
    eTldPlusOne: parts.length >= 2 ? parts.slice(-2).join('.') : clean,
    publicSuffix: parts.length >= 2 ? parts[parts.length - 1] : '',
    subdomain: parts.length > 2 ? parts.slice(0, -2).join('.') : '',
    isIp: false,
  };
}

export function extractRegistrableDomain(hostname: string): string {
  return extractPslBreakdown(hostname).eTldPlusOne;
}

export function detectPaasHosting(asciiDomain: string): { isPaas: boolean; provider?: string; suffix?: string } {
  const host = asciiDomain.toLowerCase();
  for (const entry of MULTI_TENANT_PAAS_SUFFIXES) {
    if (host === entry.suffix || host.endsWith(`.${entry.suffix}`)) {
      return { isPaas: true, provider: entry.provider, suffix: entry.suffix };
    }
  }
  return { isPaas: false };
}

const BENIGN_TRACKING_PARAM_KEYS = new Set([
  'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
  'fbclid', 'gclid', 'msclkid', 'mc_cid', 'mc_eid', 'ved', 'ei', 'oq', 'gs_lcrp', 'sxsrf', 'sca_esv',
]);

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const STATIC_ASSET_EXT_REGEX = /\.(?:js|mjs|css|png|jpe?g|webp|gif|svg|woff2?|ttf|eot|ico|map|json|xml)$/i;

function computeShannonEntropy(input: string): number {
  if (!input) return 0;
  const freq = new Map<string, number>();
  for (const ch of input) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / input.length;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(2));
}

function isReadableText(str: string): boolean {
  if (!str || str.length < 3) return false;
  let printable = 0;
  let alphaNumOrSymbol = 0;
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if ((code >= 32 && code <= 126) || code >= 0x0600) {
      printable++;
      if (/[A-Za-z0-9/:.@?=&_{}-]/.test(str[i]) || code >= 0x0600) {
        alphaNumOrSymbol++;
      }
    } else if (code !== 9 && code !== 10 && code !== 13) {
      return false;
    }
  }
  return printable / str.length >= 0.88 && alphaNumOrSymbol >= 3;
}

function tryDecodeBase64Payload(val: string): string | null {
  const clean = val.trim();
  if (clean.length < 8 || clean.length % 4 === 1 || !/^[A-Za-z0-9+/_-]+=*$/.test(clean)) return null;
  try {
    const normalized = clean.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
    const buf = Buffer.from(padded, 'base64');
    if (buf.length < 4) return null;
    const decoded = buf.toString('utf8').replace(/\0+$/, '');
    if (!isReadableText(decoded)) return null;
    const looksStructured =
      /https?:\/\/|@|<script|SELECT\s+|javascript:|\/[a-z0-9_/-]{2,}|[a-z0-9_.-]+=[a-z0-9_.-]+|\{.*"[^"]+":/i.test(decoded) ||
      (/^[A-Za-z0-9 _.,:/?=&@%+-]{6,}$/.test(decoded) && /[A-Za-z]{3,}/.test(decoded) && !/^[A-Za-z]+$/.test(clean));
    if (looksStructured) {
      return decoded.slice(0, 140);
    }
  } catch {
    return null;
  }
  return null;
}

function tryDecodeJwtSegment(val: string): string | null {
  if (!/^eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}(?:\.[A-Za-z0-9_-]*)?$/.test(val)) return null;
  const parts = val.split('.');
  try {
    const payload = Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    if (isReadableText(payload)) return `JWT: ${payload.slice(0, 120)}`;
  } catch {
    return null;
  }
  return null;
}

function tryDecodeHexSegment(val: string): { isHex: boolean; decoded?: string } {
  const clean = val.startsWith('0x') || val.startsWith('0X') ? val.slice(2) : val;
  if (clean.length < 16 || clean.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(clean)) {
    return { isHex: false };
  }
  try {
    const decoded = Buffer.from(clean, 'hex').toString('utf8').replace(/\0+$/, '');
    if (isReadableText(decoded)) {
      return { isHex: true, decoded: decoded.slice(0, 140) };
    }
  } catch {
    // opaque cipher/hash hex
  }
  return { isHex: clean.length >= 24 };
}

function inspectUrlSegmentEncoding(
  rawSegment: string,
  location: UrlEncryptionSegment['location'],
  keyOrSegmentIndex: string,
  isOfficialHost: boolean
): UrlEncryptionSegment | null {
  if (!rawSegment || rawSegment.length < 4) return null;
  if (UUID_REGEX.test(rawSegment)) return null;
  if (location === 'path_segment' && STATIC_ASSET_EXT_REGEX.test(rawSegment) && !/%25|%[0-7][0-9a-f]/i.test(rawSegment)) {
    return null;
  }

  // 1. Double percent encoding (%25xx)
  if (/%25[0-9a-fA-F]{2}/.test(rawSegment)) {
    let decoded = rawSegment;
    try {
      decoded = decodeURIComponent(decodeURIComponent(rawSegment));
    } catch {
      try {
        decoded = decodeURIComponent(rawSegment);
      } catch {
        // keep raw
      }
    }
    return {
      location,
      keyOrSegmentIndex,
      technique: 'double_percent_encoding',
      rawSample: rawSegment.slice(0, 96),
      decodedPreview: decoded.slice(0, 140),
      containsSensitiveOrUrl: /https?:\/\/|@|login|redirect|<script/i.test(decoded),
      note: {
        en: 'Double percent-encoded (%25xx) sequence used to disguise underlying paths or parameters.',
        ar: 'ترميز مزدوج (%25xx) يُستخدم لإخفاء المسار أو المعامل الحقيقي عن فلاتر الفحص.',
      },
    };
  }

  // 2. Unicode/Hex escape obfuscation (%uXXXX or \xXX)
  if (/%u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}/i.test(rawSegment)) {
    return {
      location,
      keyOrSegmentIndex,
      technique: 'unicode_escape',
      rawSample: rawSegment.slice(0, 96),
      note: {
        en: 'Unicode/hex escape notation inside URL component.',
        ar: 'تسلسلات هروب Unicode/Hex مموهة داخل مكون الرابط.',
      },
    };
  }

  // 3. Heavy ASCII percent obfuscation (e.g. %6c%6f%67%69%6e) — exclude legitimate non-ASCII UTF-8 (Arabic/CJK/etc.)
  const asciiPercentMatches = rawSegment.match(/%[2-7][0-9a-fA-F]/g) || [];
  if (asciiPercentMatches.length >= 3) {
    let decoded = rawSegment;
    try {
      decoded = decodeURIComponent(rawSegment);
    } catch {
      // ignore
    }
    const pureAsciiDecoded = /^[\x20-\x7E]+$/.test(decoded);
    if (pureAsciiDecoded && (asciiPercentMatches.length >= 4 || asciiPercentMatches.length * 3 >= rawSegment.length * 0.4)) {
      return {
        location,
        keyOrSegmentIndex,
        technique: 'heavy_percent_encoding',
        rawSample: rawSegment.slice(0, 96),
        decodedPreview: decoded.slice(0, 140),
        containsSensitiveOrUrl: /https?:\/\/|@|login|verify|admin|auth|redirect/i.test(decoded),
        note: {
          en: `ASCII characters masked with ${asciiPercentMatches.length} percent-hex codes.`,
          ar: `تم إخفاء حروف ASCII عادية عبر ${asciiPercentMatches.length} ترميزاً سداسياً لإخفاء اسم المسار.`,
        },
      };
    }
  }

  let unescaped = rawSegment;
  try {
    unescaped = decodeURIComponent(rawSegment);
  } catch {
    // keep raw
  }

  // 4. OpenSSL Salted Ciphertext ("U2FsdGVkX1" = Base64 for "Salted__") or Fernet ("gAAAAA")
  if (/^(?:U2FsdGVkX1|gAAAAA)[A-Za-z0-9+/_-]{6,}=*$/.test(unescaped)) {
    return {
      location,
      keyOrSegmentIndex,
      technique: 'high_entropy_cipher',
      rawSample: unescaped.slice(0, 96),
      entropy: computeShannonEntropy(unescaped),
      containsSensitiveOrUrl: true,
      note: {
        en: unescaped.startsWith('U2FsdGVkX1')
          ? 'OpenSSL AES/Salted encrypted payload ("Salted__") embedded in URL.'
          : 'Fernet-encrypted ciphertext token embedded in URL.',
        ar: unescaped.startsWith('U2FsdGVkX1')
          ? 'حمولة مشفرة بخوارزمية OpenSSL/AES ("Salted__") مضمنة داخل الرابط.'
          : 'رمز مشفر عالي الإنتروبيا (Fernet Ciphertext) مضمن داخل الرابط.',
      },
    };
  }

  // 5. JWT / Structured Token
  const jwtDecoded = tryDecodeJwtSegment(unescaped);
  if (jwtDecoded) {
    return {
      location,
      keyOrSegmentIndex,
      technique: 'base64url_token',
      rawSample: unescaped.slice(0, 96),
      decodedPreview: jwtDecoded,
      entropy: computeShannonEntropy(unescaped),
      containsSensitiveOrUrl: /https?:\/\/|@|email|role|admin/i.test(jwtDecoded),
      note: {
        en: 'Encoded Base64URL / JWT token carrying structured claims in URL.',
        ar: 'رمز Base64URL / JWT مشفر يحمل بيانات مضمنة داخل الرابط.',
      },
    };
  }

  // 6. Decodable Base64 / Base64URL payload
  const b64Decoded = tryDecodeBase64Payload(unescaped);
  if (b64Decoded) {
    return {
      location,
      keyOrSegmentIndex,
      technique: 'base64',
      rawSample: unescaped.slice(0, 96),
      decodedPreview: b64Decoded,
      entropy: computeShannonEntropy(unescaped),
      containsSensitiveOrUrl: /https?:\/\/|@|<script|SELECT\s+|javascript:|login|verify|token|pass/i.test(b64Decoded),
      note: {
        en: 'Base64-encoded component decodes cleanly to readable text/URL.',
        ar: 'جزء مشفر بصيغة Base64 تم فك ترميزه وكشف محتواه المقروء.',
      },
    };
  }

  // 7. Hex-encoded path or query segment
  const hexCheck = tryDecodeHexSegment(unescaped);
  if (hexCheck.isHex) {
    return {
      location,
      keyOrSegmentIndex,
      technique: 'hex_encoded',
      rawSample: unescaped.slice(0, 96),
      decodedPreview: hexCheck.decoded,
      entropy: computeShannonEntropy(unescaped),
      containsSensitiveOrUrl: Boolean(hexCheck.decoded && /https?:\/\/|@|login|verify|admin/i.test(hexCheck.decoded)),
      note: {
        en: hexCheck.decoded
          ? 'Hexadecimal-encoded segment decoded to readable plaintext.'
          : 'Long hexadecimal ciphertext/hash-like token embedded in path.',
        ar: hexCheck.decoded
          ? 'مسار مشفر بصيغة Hex تم فك ترميزه إلى نص واضح.'
          : 'سلسلة طويلة مشفرة بصيغة Hex مضمنة داخل المسار.',
      },
    };
  }

  // 8. High-entropy encrypted / cipher path segment (ignore natural hyphenated slugs, pure lowercase words, and benign official tracking params)
  if (location === 'query_param' && isOfficialHost && BENIGN_TRACKING_PARAM_KEYS.has(keyOrSegmentIndex.toLowerCase())) {
    return null;
  }
  const isNaturalSlug = /^[a-z]+(?:-[a-z0-9]+){1,}$/.test(unescaped) || /^[a-z]{1,28}$/.test(unescaped) || /^\d+$/.test(unescaped);
  if (!isNaturalSlug && unescaped.length >= 22 && /^[A-Za-z0-9+/_.:=-]+$/.test(unescaped)) {
    const entropy = computeShannonEntropy(unescaped);
    const hasMixedClasses =
      (/[A-Z]/.test(unescaped) ? 1 : 0) + (/[a-z]/.test(unescaped) ? 1 : 0) + (/[0-9]/.test(unescaped) ? 1 : 0) >= 3;
    if (entropy >= 4.2 && hasMixedClasses && (location === 'path_segment' || !isOfficialHost)) {
      return {
        location,
        keyOrSegmentIndex,
        technique: 'high_entropy_cipher',
        rawSample: unescaped.slice(0, 96),
        entropy,
        containsSensitiveOrUrl: false,
        note: {
          en: `High-entropy encrypted/ciphered token (${unescaped.length} chars, Shannon entropy ${entropy} bits/char).`,
          ar: `مقطع مشفر عالي العشوائية (${unescaped.length} حرفاً، إنتروبيا ${entropy} بت/حرف) قد يخفي مساراً أو معرّفاً سرياً.`,
        },
      };
    }
  }

  return null;
}

export function analyzeUrlIntelligence(submittedUrl: string, normalizedUrl: string): UrlIntelResult {
  const now = new Date().toISOString();
  const findings: CheckFinding[] = [];
  const parsed = new URL(normalizedUrl);
  const hostname = parsed.hostname.toLowerCase();
  const asciiDomain = domainToASCII(hostname) || hostname;
  const unicodeDomain = domainToUnicode(asciiDomain) || hostname;
  const psl = extractPslBreakdown(asciiDomain);
  const registrableDomain = psl.eTldPlusOne;
  const publicSuffix = psl.publicSuffix;
  const tld = asciiDomain.split('.').pop() || '';
  const isIpLiteral = net.isIP(hostname.replace(/^\[|\]$/g, '')) !== 0;
  const paas = detectPaasHosting(asciiDomain);
  const ownership = lookupDomainOwnership(asciiDomain);

  // 1. Transport Protocol & Unusual Port Check
  const isHttps = parsed.protocol === 'https:';
  const port = parsed.port ? Number(parsed.port) : isHttps ? 443 : 80;
  const unusualPort = (isHttps && port !== 443) || (!isHttps && port !== 80);

  findings.push({
    id: 'url-protocol-port',
    section: 'url_intelligence',
    test: { en: 'Transport Protocol & Port Inspection', ar: 'فحص بروتوكول النقل والمنفذ' },
    result: {
      en: `${parsed.protocol.replace(':', '').toUpperCase()} on port ${port}${unusualPort ? ' (unusual port)' : ''}`,
      ar: `${parsed.protocol.replace(':', '').toUpperCase()} على المنفذ ${port}${unusualPort ? ' (منفذ غير قياسي)' : ''}`,
    },
    status: !isHttps || unusualPort ? 'warning' : 'pass',
    severity: !isHttps || unusualPort ? 'medium' : 'informational',
    weight: !isHttps ? 12 : unusualPort ? 8 : 0,
    evidence: `Protocol: ${parsed.protocol} | Port: ${port} | HTTPS alone is transport encryption, not proof of site legitimacy.`,
    explanation: {
      en: !isHttps
        ? 'Unencrypted HTTP allows network observers to read or modify credentials and content in transit.'
        : unusualPort
          ? `Service listens on non-standard port ${port}, often used by temporary phishing kits or C2 panels.`
          : 'URL uses HTTPS on standard port 443. Phishing sites frequently use valid HTTPS certificates.',
      ar: !isHttps
        ? 'الاتصال غير مشفر عبر HTTP مما يعرض البيانات المرسلة للاعتراض أو التعديل.'
        : unusualPort
          ? `يستخدم الرابط منفذاً غير قياسي (${port}) وهو شائع في خوادم الاستغلال المؤقتة.`
          : 'يستخدم الرابط بروتوكول HTTPS على المنفذ القياسي 443؛ علماً بأن التشفير لا يثبت سلامة الموقع.',
    },
    recommendedAction: {
      en: !isHttps ? 'Never enter passwords or payment details over plain HTTP.' : 'Verify domain identity and content checks regardless of HTTPS.',
      ar: !isHttps ? 'لا تدخل أي كلمات مرور أو بيانات دفع عبر اتصال HTTP غير مشفر.' : 'تحقق من هوية النطاق ومحتوى الصفحة بغض النظر عن وجود HTTPS.',
    },
    forensic: {
      whereDetected: { en: `URL scheme "${parsed.protocol}" and port ${port}`, ar: `مخطط الرابط "${parsed.protocol}" والمنفذ ${port}` },
      whyRisky: {
        en: !isHttps ? 'Cleartext transport leaks passwords.' : unusualPort ? 'Non-standard ports bypass casual user inspection.' : 'HTTPS encrypts transport only.',
        ar: !isHttps ? 'الاتصال غير المشفر يكشف كلمات المرور.' : 'المنافذ غير القياسية تُستخدم غالباً في خدمات غير قياسية.',
      },
      howExploited: {
        en: 'Intercepted HTTP sessions or ephemeral custom-port C2/phishing listeners.',
        ar: 'اعتراض الجلسات غير المشفرة أو استضافة أدوات خبيثة على منافذ غير قياسية.',
      },
      userImpact: { en: 'Credential interception or rogue listener access.', ar: 'اعتراض بيانات الدخول أو الوصول لخدمة غير موثوقة.' },
      notProvenAlone: {
        en: 'Using HTTPS does NOT prove safety; similarly, plain HTTP alone does not prove active phishing.',
        ar: 'وجود HTTPS لا يعني الأمان، ووجود HTTP وحده لا يثبت التصيد.',
      },
    },
    source: 'SM URL Parser',
    timestamp: now,
    confidence: 100,
  });

  // 2. IP-Based URL Detection
  if (isIpLiteral) {
    findings.push({
      id: 'url-ip-literal',
      section: 'url_intelligence',
      test: { en: 'IP-Based Hostname Check', ar: 'فحص استخدام عنوان IP مباشر' },
      result: { en: `Raw IP address used (${hostname})`, ar: `استخدام عنوان IP مباشر (${hostname})` },
      status: 'failed',
      severity: 'high',
      weight: 22,
      evidence: `Host is literal IP: ${hostname}`,
      explanation: {
        en: 'Legitimate consumer services do not direct users to raw IP addresses; attackers use IP URLs to bypass domain reputation and age checks.',
        ar: 'نادراً ما تطلب المواقع الموثوقة زيارة عنوان IP مباشر؛ وغالباً ما يُستخدم لتجاوز فحوصات سمعة النطاقات.',
      },
      recommendedAction: {
        en: 'Do not authenticate or download files from raw IP-based web URLs.',
        ar: 'تجنب تسجيل الدخول أو تنزيل الملفات من روابط تعتمد على عناوين IP مباشرة.',
      },
      forensic: {
        whereDetected: { en: `Hostname literal IP: ${hostname}`, ar: `اسم المضيف عنوان IP مباشر: ${hostname}` },
        whyRisky: { en: 'Direct IP links evade domain age, RDAP, and registrar accountability.', ar: 'تتجاوز الروابط المباشرة بعناوين IP فحوصات عمر النطاق ومسجل النطاقات.' },
        howExploited: { en: 'Hosted temporarily on compromised VPS servers to distribute malware or phishing forms.', ar: 'استضافة مؤقتة على خوادم مخترقة لتوزيع برمجيات خبيثة أو صفحات تصيد.' },
        userImpact: { en: 'Connection to unverified infrastructure without domain identity.', ar: 'اتصال بخادم غير معروف الهوية.' },
        notProvenAlone: { en: 'Some routers/enterprise endpoints use public IPs legitimately, but consumer login links never should.', ar: 'قد تستخدم بعض الأجهزة الإدارية عناوين IP لكنها غير مخصصة لروابط تسجيل دخول المستهلكين.' },
      },
      source: 'SM URL Parser',
      timestamp: now,
      confidence: 100,
    });
  }

  // 3. Subdomain Depth & Multi-Tenant PaaS Hosting Context
  const labels = asciiDomain.split('.');
  const subdomainDepth = Math.max(0, labels.length - 2);
  const excessiveSubdomains = !isIpLiteral && !ownership.matched && !paas.isPaas && subdomainDepth >= 3;
  findings.push({
    id: 'url-subdomain-paas',
    section: 'url_intelligence',
    test: { en: 'Subdomain Structure & Hosting Platform Context', ar: 'بنية النطاقات الفرعية وسياق الاستضافة المشتركة' },
    result: paas.isPaas
      ? {
          en: `Hosted on shared multi-tenant PaaS (${paas.provider}) · Contextual note (judged by content & URL)`,
          ar: `مستضاف على منصة سحابية مشتركة (${paas.provider}) · ملاحظة سياقية (يُحكم بالمحتوى والرابط)`,
        }
      : ownership.matched && ownership.isSubdomain
        ? {
            en: `Official Subdomain (${asciiDomain}) under ${registrableDomain} (${ownership.entity?.parentCompany})`,
            ar: `نطاق فرعي رسمي (${asciiDomain}) تابع للنطاق ${registrableDomain}`,
          }
        : {
            en: `${subdomainDepth} subdomain level(s) (${registrableDomain})`,
            ar: `${subdomainDepth} مستوى نطاق فرعي (${registrableDomain})`,
          },
    status: excessiveSubdomains ? 'warning' : 'pass',
    severity: 'informational',
    weight: 0,
    evidence: `Host: ${asciiDomain} | Registrable: ${registrableDomain} | Shared PaaS: ${paas.isPaas ? paas.provider : 'No'} | OfficialRegistry: ${ownership.matched ? ownership.entity?.parentCompany : 'No'}`,
    explanation: {
      en: paas.isPaas
        ? `This URL is hosted on ${paas.provider} (${registrableDomain}). Anyone can deploy arbitrary pages on shared PaaS subdomains; therefore parent domain age and valid TLS belong to ${paas.provider}, NOT the hosted page owner.`
        : ownership.matched && ownership.isSubdomain
          ? `${asciiDomain} is an authentic subdomain directly beneath the official registrable domain ${registrableDomain}.`
          : excessiveSubdomains
            ? 'Excessive subdomain chaining can push the actual registrable domain off-screen on mobile browsers.'
            : 'Subdomain structure is within normal bounds.',
      ar: paas.isPaas
        ? `هذا الرابط مستضاف على منصة ${paas.provider} المشتركة؛ لذا فإن عمر النطاق وشهادة التشفير تخص المزود ولا تثبت موثوقية المحتوى المنشور.`
        : ownership.matched && ownership.isSubdomain
          ? `النطاق الفرعي ${asciiDomain} يتبع مباشرة النطاق الرسمي المسجل ${registrableDomain}.`
          : excessiveSubdomains
            ? 'كثرة النطاقات الفرعية قد تخفي النطاق الحقيقي على شاشات الهواتف.'
            : 'بنية النطاقات الفرعية طبيعية.',
    },
    recommendedAction: {
      en: paas.isPaas ? 'Judge the page strictly by its content, forms, and behavior—not the PaaS domain age.' : 'No action required.',
      ar: paas.isPaas ? 'قيّم الصفحة بناءً على محتواها وسلوكها الفعلي لا بناءً على سمعة مزود الاستضافة.' : 'لا يلزم إجراء.',
    },
    forensic: {
      whereDetected: { en: `Hostname hierarchy "${asciiDomain}"`, ar: `تسلسل النطاقات "${asciiDomain}"` },
      whyRisky: {
        en: 'Multi-tenant PaaS domains and temporary tunnels inherit the parent vendor domain age and HTTPS certificate.',
        ar: 'تستفيد الصفحات على المنصات السحابية المشتركة من قِدم النطاق الأم وشهادة التشفير التلقائية.',
      },
      howExploited: {
        en: 'Phishers deploy credential kits on free PaaS subdomains to appear trusted.',
        ar: 'ينشر المهاجمون صفحات تصيد على نطاقات فرعية مجانية لإظهار النطاق كخدمة موثوقة.',
      },
      userImpact: {
        en: 'Users assume vendor reputation covers third-party deployed apps.',
        ar: 'يظن المستخدم أن سمعة مزود الخدمة السحابية تحمي الصفحة المنشورة.',
      },
      notProvenAlone: {
        en: 'PaaS hosting (Firebase, Vercel, GitHub Pages) hosts millions of legitimate apps; it requires content correlation before declaring risk.',
        ar: 'الاستضافة على Firebase أو Vercel أو GitHub Pages لا تثبت وحدها أي خطر ما لم تقترن بمؤشرات تصيد في المحتوى.',
      },
    },
    source: 'SM URL & PaaS Classifier',
    timestamp: now,
    confidence: 95,
  });

  // 4. Encrypted/Encoded URL, Path Segments, Query Params & Fragment Inspection
  const doubleEncoded = /%25[0-9a-fA-F]{2}/.test(normalizedUrl) || /%25[0-9a-fA-F]{2}/.test(submittedUrl);
  const percentMatches = normalizedUrl.match(/%[0-9a-fA-F]{2}/g) || [];
  const asciiPercentMatches = normalizedUrl.match(/%[2-7][0-9a-fA-F]/g) || [];
  const excessiveLength = normalizedUrl.length > 220;
  const base64Findings: string[] = [];
  const nestedUrls: string[] = [];
  const encryptionSegments: UrlEncryptionSegment[] = [];

  // Inspect raw URL pathname segments (preserves %xx percent obfuscation!)
  const rawPathPart = (() => {
    const subMatch = submittedUrl.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/?#]+([^?#]*)/);
    return subMatch?.[1] || parsed.pathname;
  })();
  const pathSegments = rawPathPart.split('/').filter(Boolean);
  pathSegments.forEach((seg, idx) => {
    const encSeg = inspectUrlSegmentEncoding(seg, 'path_segment', `/${idx + 1}`, ownership.matched);
    if (encSeg) {
      encryptionSegments.push(encSeg);
      if (encSeg.decodedPreview) {
        base64Findings.push(`path[${idx + 1}] -> "${encSeg.decodedPreview}"`);
      }
    }
  });

  // Inspect query parameters
  for (const [k, v] of parsed.searchParams.entries()) {
    const kl = k.toLowerCase();
    if (SUSPICIOUS_PARAM_KEYS.includes(kl) || /https?:\/\//i.test(v)) {
      if (/https?:\/\/|^\/\/[a-z0-9]/i.test(v)) {
        try {
          const targetUrlObj = new URL(v.startsWith('//') ? `https:${v}` : v);
          const rel = classifyDomainRelationship(asciiDomain, targetUrlObj.hostname);
          if (!rel.isBenignOrAuthorized) {
            nestedUrls.push(`${k}=${v.slice(0, 70)}`);
          }
        } catch {
          nestedUrls.push(`${k}=${v.slice(0, 70)}`);
        }
      }
    }
    const encParam = inspectUrlSegmentEncoding(v, 'query_param', k, ownership.matched);
    if (encParam) {
      encryptionSegments.push(encParam);
      if (encParam.decodedPreview) {
        base64Findings.push(`${k} -> "${encParam.decodedPreview}"`);
      }
    }
  }

  // Inspect URL fragment (#...) if non-empty
  const rawHash = parsed.hash.replace(/^#/, '');
  if (rawHash.length >= 6) {
    const encFrag = inspectUrlSegmentEncoding(rawHash, 'fragment', '#fragment', ownership.matched);
    if (encFrag) {
      encryptionSegments.push(encFrag);
      if (encFrag.decodedPreview) {
        base64Findings.push(`#fragment -> "${encFrag.decodedPreview}"`);
      }
    } else if (/https?:\/\//i.test(rawHash)) {
      nestedUrls.push(`#fragment=${rawHash.slice(0, 70)}`);
    }
  }

  // Extract decoded secrets / Telegram bot tokens & chat IDs from URL parameters and decoded Base64/Hex segments
  const decodedSecretsDetected: NonNullable<UrlEncryptionTelemetry['decodedSecretsDetected']> = [];
  const telegramTokenRegex = /\b(\d{6,12}):([A-Za-z0-9_-]{30,55})\b/;
  const redactBotToken = (fullToken: string) => {
    const parts = fullToken.split(':');
    if (parts.length !== 2) return '***REDACTED***';
    return `${parts[0]}:${parts[1].slice(0, 4)}***${parts[1].slice(-3)}`;
  };
  const inspectPayloadForSecrets = (paramName: string, rawOrDecoded: string) => {
    if (!rawOrDecoded) return;
    let candidateText = rawOrDecoded;
    try {
      const b64 = tryDecodeBase64Payload(rawOrDecoded);
      if (b64) candidateText = `${candidateText}\n${b64}`;
    } catch {
      // ignore
    }
    try {
      const pct = decodeURIComponent(rawOrDecoded);
      if (pct !== rawOrDecoded) candidateText = `${candidateText}\n${pct}`;
    } catch {
      // ignore
    }

    const tokenMatch = candidateText.match(telegramTokenRegex);
    const idMatch = candidateText.match(/(?:^|[?&,\s{])(?:chat_id|id|cid|uid|target_id|tg_id)\s*[=:]\s*["']?(-?\d{5,15}|[A-Za-z0-9_-]{4,24})["']?/i);

    if (tokenMatch) {
      const redacted = redactBotToken(tokenMatch[0]);
      const hasChatId = Boolean(idMatch);
      if (!decodedSecretsDetected.some((s) => s.param === paramName && s.kind === 'telegram_bot_token')) {
        decodedSecretsDetected.push({
          param: paramName,
          kind: 'telegram_bot_token',
          redactedPreview: hasChatId ? `id=${idMatch![1]} & token=${redacted}` : `token=${redacted}`,
          hasBotToken: true,
          hasChatId,
          note: {
            en: hasChatId
              ? 'Decoded URL parameter carries a Telegram Bot Token paired with a target Chat/User ID — classic surveillance/phishing exfiltration bootstrap.'
              : 'Decoded URL parameter exposes a Telegram Bot Token.',
            ar: hasChatId
              ? 'يحمل معامل الرابط المفكك رمز بوت تيليجرام (Bot Token) مقترناً بمعرّف محادثة/مستخدم — نمط كلاسيكي لتهيئة قنوات التجسس وتسريب البيانات.'
              : 'يكشف معامل الرابط المفكك عن رمز بوت تيليجرام (Bot Token).',
          },
        });
      }
    } else if (idMatch && /token=|bot|telegram|chat_id/i.test(candidateText)) {
      if (!decodedSecretsDetected.some((s) => s.param === paramName && s.kind === 'chat_id')) {
        decodedSecretsDetected.push({
          param: paramName,
          kind: 'chat_id',
          redactedPreview: `id=${idMatch[1]}`,
          hasBotToken: false,
          hasChatId: true,
          note: {
            en: 'Decoded URL payload contains a target chat/user ID linked to bot/token routing.',
            ar: 'تحتوي الحمولة المفككة على معرّف مستهدف مرتبط بتمرير رمز أو بوت.',
          },
        });
      }
    }
  };

  for (const [k, v] of parsed.searchParams.entries()) {
    inspectPayloadForSecrets(k, v);
  }
  for (const seg of encryptionSegments) {
    if (seg.decodedPreview) {
      inspectPayloadForSecrets(seg.keyOrSegmentIndex, seg.decodedPreview);
    }
  }

  const encodedPathSegmentCount = encryptionSegments.filter((s) => s.location === 'path_segment').length;
  const encodedQueryParamCount = encryptionSegments.filter((s) => s.location === 'query_param' || s.location === 'fragment').length;
  const hasEncryptedSegments = encryptionSegments.length > 0;
  const hasDecodedOrCipherThreat =
    doubleEncoded ||
    decodedSecretsDetected.length > 0 ||
    encryptionSegments.some((s) => s.containsSensitiveOrUrl || s.technique === 'double_percent_encoding' || s.technique === 'heavy_percent_encoding' || s.technique === 'hex_encoded' || s.technique === 'base64') ||
    encodedPathSegmentCount >= 2;

  const encryptionTelemetry: UrlEncryptionTelemetry = {
    hasEncryptedOrEncodedParts: hasEncryptedSegments || doubleEncoded,
    encodedPathSegmentCount,
    encodedQueryParamCount,
    doublePercentEncoded: doubleEncoded,
    totalPercentEncodedChars: percentMatches.length,
    segments: encryptionSegments.slice(0, 16),
    decodedSecretsDetected: decodedSecretsDetected.length > 0 ? decodedSecretsDetected : undefined,
    summary: hasEncryptedSegments || doubleEncoded
      ? {
          en: `Detected ${encodedPathSegmentCount} encoded/encrypted path segment(s) and ${encodedQueryParamCount} encoded query/fragment payload(s)${doubleEncoded ? ' with double percent-encoding' : ''}${decodedSecretsDetected.length ? ` (${decodedSecretsDetected.length} decoded bot token/secret payload(s))` : ''}.`,
          ar: `تم رصد ${encodedPathSegmentCount} مساراً مشفراً/مرمزاً و ${encodedQueryParamCount} معامل/جزء مرمز${doubleEncoded ? ' مع ترميز مزدوج' : ''}${decodedSecretsDetected.length ? ` (${decodedSecretsDetected.length} حمولة رمز بوت/سر مفككة)` : ''}.`,
        }
      : {
          en: 'No encrypted path segments, hex/Base64 obfuscation, or double encoding detected in URL.',
          ar: 'الرابط ومساراته واضحة ولا تحتوي على مسارات مشفرة أو ترميز خبيث.',
        },
  };

  if (decodedSecretsDetected.length > 0) {
    const hasPairedBotAndId = decodedSecretsDetected.some((s) => s.hasBotToken && s.hasChatId) ||
      (decodedSecretsDetected.some((s) => s.hasBotToken) && decodedSecretsDetected.some((s) => s.hasChatId));
    findings.push({
      id: 'url-decoded-credentials',
      section: 'url_intelligence',
      test: {
        en: 'Decoded URL Payload Bot Token & Credential Check',
        ar: 'فحص رموز البوتات والمعرّفات السرية داخل حمولات الرابط المفككة',
      },
      result: {
        en: hasPairedBotAndId
          ? `Exposed/Passed Telegram Bot Token & Chat ID in URL Parameter (${decodedSecretsDetected.map((s) => `${s.param}: ${s.redactedPreview}`).join(' · ')})`
          : `Exposed Bot Token / Sensitive Identifier in URL Parameter (${decodedSecretsDetected.map((s) => `${s.param}: ${s.redactedPreview}`).join(' · ')})`,
        ar: hasPairedBotAndId
          ? `تم كشف تمرير رمز بوت تيليجرام (Bot Token) ومعرّف المحادثة (Chat ID) داخل معامل الرابط (${decodedSecretsDetected.map((s) => `${s.param}: ${s.redactedPreview}`).join(' · ')})`
          : `تم كشف رمز بوت أو معرّف حساس داخل معامل الرابط (${decodedSecretsDetected.map((s) => `${s.param}: ${s.redactedPreview}`).join(' · ')})`,
      },
      status: 'failed',
      severity: hasPairedBotAndId ? 'critical' : 'high',
      weight: hasPairedBotAndId ? 28 : 22,
      evidence: `DecodedURLSecrets: [${decodedSecretsDetected.map((s) => `${s.param}:${s.kind}:${s.redactedPreview}`).join('; ')}]`,
      explanation: {
        en: 'Decoding URL parameters revealed an embedded Telegram Bot Token and/or recipient chat ID passed directly in the link. Attackers distribute encoded trap links (`?u=Base64(...)`) so a single static page forwards captured victim data directly to the attacker bot.',
        ar: 'أدى فك ترميز معاملات الرابط إلى كشف رمز بوت تيليجرام (Bot Token) و/أو معرّف مستلم مضمن داخل الرابط نفسه؛ ويُستخدم هذا الأسلوب في روابط الفخاخ المرمزة (`?u=...`) لإرسال بيانات الضحية مباشرة إلى بوت المهاجم.',
      },
      recommendedAction: {
        en: 'Do not open or interact with this URL; revoke any compromised bot tokens immediately and block trap distribution links.',
        ar: 'لا تفتح هذا الرابط ولا تمنحه أي صلاحيات؛ هذا الرابط مصمم لتوجيه البيانات الملتقطة إلى قناة مراسلة خارجية.',
      },
      source: 'SM URL Payload Decoder',
      timestamp: now,
      confidence: 97,
    });
  }

  const hasEncodingAnomaly =
    doubleEncoded || asciiPercentMatches.length >= 12 || base64Findings.length > 0 || nestedUrls.length > 0 || hasEncryptedSegments;
  const encodingFailed = doubleEncoded || (hasDecodedOrCipherThreat && !ownership.matched) || encodedPathSegmentCount >= 1 && base64Findings.length > 0;

  findings.push({
    id: 'url-encoding-obfuscation',
    section: 'url_intelligence',
    test: { en: 'Encrypted URL, Encoded Paths & Payload Obfuscation', ar: 'فحص تشفير الرابط والمسارات المشفرة والحمولات المرمزة' },
    result: hasEncodingAnomaly
      ? {
          en: `Detected: ${[
            encodedPathSegmentCount ? `${encodedPathSegmentCount} encoded/encrypted path(s)` : '',
            encodedQueryParamCount ? `${encodedQueryParamCount} encoded param(s)` : '',
            doubleEncoded ? 'double-encoding' : '',
            nestedUrls.length ? `${nestedUrls.length} nested URL(s)` : '',
            base64Findings.length ? `decoded: ${base64Findings[0]}` : '',
          ].filter(Boolean).join(' · ')}`,
          ar: `رصد تشفير/ترميز: ${[
            encodedPathSegmentCount ? `${encodedPathSegmentCount} مسار مشفر/مرمز` : '',
            encodedQueryParamCount ? `${encodedQueryParamCount} معامل مشفر` : '',
            doubleEncoded ? 'ترميز مزدوج' : '',
            nestedUrls.length ? `${nestedUrls.length} رابط متداخل` : '',
            base64Findings.length ? `فك التشفير: ${base64Findings[0]}` : '',
          ].filter(Boolean).join(' · ')}`,
        }
      : { en: `Clean URL & paths (${normalizedUrl.length} chars, 0 encrypted/obfuscated segments)`, ar: `رابط ومسارات نظيفة (${normalizedUrl.length} حرف، بدون مسارات مشفرة)` },
    status: encodingFailed ? 'failed' : hasEncodingAnomaly ? 'warning' : 'pass',
    severity: encodingFailed ? 'high' : hasEncodingAnomaly ? 'medium' : 'informational',
    weight:
      (doubleEncoded ? 15 : 0) +
      (base64Findings.length > 0 ? 14 : 0) +
      (encodedPathSegmentCount > 0 && base64Findings.length === 0 ? Math.min(14, encodedPathSegmentCount * 7) : 0) +
      (nestedUrls.length > 0 ? 8 : 0),
    evidence: `DoubleEncoded: ${doubleEncoded} | EncodedPaths: ${encodedPathSegmentCount} | EncodedParams: ${encodedQueryParamCount} | Nested: [${nestedUrls.join('; ') || 'none'}] | Decoded: [${base64Findings.join('; ') || 'none'}] | Length: ${normalizedUrl.length}`,
    explanation: {
      en: hasEncodingAnomaly
        ? 'Encrypted path segments, Base64/Hex/JWT tokens, double percent-encoding, or nested external URLs mask hidden destinations, routing instructions, or tracking tokens.'
        : 'URL path segments, query parameters, and encoding fall within standard readable web patterns.',
      ar: hasEncodingAnomaly
        ? 'تحتوي بنية الرابط أو مساراته على مقاطع مشفرة أو مرمزة (Base64 / Hex / ترميز مزدوج / رموز عالية الإنتروبيا) قد تُستخدم لإخفاء المسارات الحقيقية أو تمرير أوامر ووجهات خفية.'
        : 'مسارات الرابط ومعاملاته مقروءة وتقع ضمن النمط القياسي.',
    },
    recommendedAction: {
      en: hasEncodingAnomaly ? 'Inspect the decoded path segments and parameter previews in the URL Encryption breakdown before opening.' : 'No action required.',
      ar: hasEncodingAnomaly ? 'راجع تفاصيل فك ترميز المسارات والمعاملات في بطاقة فحص تشفير الرابط قبل الوثوق بالرابط.' : 'لا يلزم إجراء.',
    },
    forensic: {
      whereDetected: { en: `URL path "${parsed.pathname}" & query (${normalizedUrl.length} chars)`, ar: `مسار الرابط "${parsed.pathname}" ومعاملاته (${normalizedUrl.length} حرف)` },
      whyRisky: { en: 'Encrypted/encoded path segments obscure destination routes, user IDs, or embedded redirect URLs from manual inspection.', ar: 'تخفي المسارات المشفرة حقيقة الصفحة المستهدفة أو بيانات الضحية أو وجهات التحويل عن عين المستخدم.' },
      howExploited: { en: 'Base64/Hex path tokens, "%252f" double encoding, or high-entropy cipher routes bypass static URL keyword filters.', ar: 'تجاوز مرشحات الأمان باستخدام مسارات Base64/Hex أو الترميز المزدوج.' },
      userImpact: { en: 'Hidden tracking, auto-redirect to attacker domain, or pre-filled phishing login.', ar: 'نقل مخفي إلى موقع خبيث أو تتبع سري أو ملء مسبق لبيانات الضحية.' },
      notProvenAlone: { en: 'Share links, signed CDN tokens, or encrypted session IDs can be legitimate; correlate with JavaScript transmission and domain verification.', ar: 'قد تستخدم الروابط المشتركة أو الجلسات رموزاً مشفرة مشروعة، لذا يُربط الفحص بسلوك الصفحة وأصالة النطاق.' },
    },
    source: 'SM URL Obfuscation Analyzer',
    timestamp: now,
    confidence: 94,
  });

  // 5. Shorteners, Suspicious TLDs, Lexical Tokens & Misleading Extensions (word-boundary safe)
  const lowerPathAndHost = `${asciiDomain}${parsed.pathname}`.toLowerCase();
  const suspiciousPathTokens = PHISHING_LEXICAL_TOKENS.filter((t) =>
    new RegExp(`(?:^|[^a-z0-9])${t}(?:$|[^a-z0-9])`).test(lowerPathAndHost)
  );
  const extMatch = parsed.pathname.toLowerCase().match(/\.[a-z0-9]{1,6}$/)?.[0] || '';
  const hasExecutableExt = EXECUTABLE_EXTENSIONS.has(extMatch);
  const misleadingDoubleExt = /\.(pdf|doc|docx|xls|xlsx|jpg|png)\.(html?|htm|exe|scr|js|zip)$/i.test(parsed.pathname);
  const suspiciousTld = !isIpLiteral && !ownership.matched && SUSPICIOUS_TLDS.has(tld);
  const isShortener = URL_SHORTENERS.has(asciiDomain) || URL_SHORTENERS.has(registrableDomain);

  findings.push({
    id: 'url-shortener-check',
    section: 'url_intelligence',
    test: { en: 'URL Shortener Detection', ar: 'فحص خدمات تقصير الروابط' },
    result: isShortener
      ? { en: `Shortened URL (${registrableDomain}) — final hop resolved separately`, ar: `رابط مختصر (${registrableDomain}) — يتم تتبع الوجهة النهائية` }
      : { en: 'Direct URL (not a known shortener)', ar: 'رابط مباشر (ليس خدمة اختصار)' },
    status: isShortener ? 'warning' : 'pass',
    severity: 'informational',
    weight: 0,
    evidence: `Registrable domain: ${registrableDomain}`,
    explanation: {
      en: isShortener
        ? 'Shortened links mask the final destination until followed. Shortening alone is not proof of malice, so redirect tracing determines the true target.'
        : 'The submitted link is not routed through a recognized URL-shortening service.',
      ar: isShortener
        ? 'تخفي الروابط المختصرة الوجهة النهائية حتى يتم تتبعها؛ ولذلك يتم فحص الوجهة النهائية بشكل مستقل.'
        : 'الرابط لا يمر عبر خدمة اختصار روابط معروفة.',
    },
    recommendedAction: {
      en: isShortener ? 'Review the Final Resolved Destination before opening.' : 'No action required.',
      ar: isShortener ? 'راجع الوجهة النهائية المعلنة في التقرير قبل زيارة الرابط.' : 'لا يلزم إجراء.',
    },
    forensic: {
      whereDetected: { en: `Submitted domain "${registrableDomain}"`, ar: `النطاق المُدخل "${registrableDomain}"` },
      whyRisky: { en: 'Hides the true destination domain until an HTTP redirect executes.', ar: 'يُخفي اسم الموقع الحقيقي حتى لحظة الضغط وإعادة التوجيه.' },
      howExploited: { en: 'Phishers use shorteners to conceal newly registered or abusive landing domains.', ar: 'يخفي المهاجم روابط النطاقات الحديثة أو المشبوهة خلف رابط مختصر.' },
      userImpact: { en: 'Blind navigation to an unknown host.', ar: 'انتقال أعمى إلى موقع غير معروف مسبقاً.' },
      notProvenAlone: { en: 'URL shorteners are widely used legitimately on social media; always judge by the final destination checks.', ar: 'تُستخدم خدمات التقصير بكثرة بشكل مشروع؛ والحكم يعتمد على الوجهة النهائية.' },
    },
    source: 'SM URL Parser',
    timestamp: now,
    confidence: 95,
  });

  // On verified official corporate domains, standard login/account paths like accounts.google.com or github.com/login are normal
  const effectiveSuspiciousTokens = ownership.matched ? [] : suspiciousPathTokens;
  const lexicalAlert =
    hasExecutableExt || misleadingDoubleExt || suspiciousTld || effectiveSuspiciousTokens.length >= 1;
  findings.push({
    id: 'url-lexical-extensions',
    section: 'url_intelligence',
    test: { en: 'Lexical Tokens, TLD & Misleading Extensions', ar: 'الكلمات المفتاحية وامتداد النطاق والملفات المضللة' },
    result: misleadingDoubleExt
      ? { en: `Misleading double extension detected (${parsed.pathname.slice(-30)})`, ar: 'تم رصد امتداد ملف مزدوج مضلل' }
      : hasExecutableExt
        ? { en: `Executable/script extension in URL (${extMatch})`, ar: `امتداد تنفيذي خطير في الرابط (${extMatch})` }
        : lexicalAlert
          ? {
              en: `${effectiveSuspiciousTokens.length} sensitive token(s)${suspiciousTld ? `, high-abuse TLD (.${tld})` : ''}`,
              ar: `${effectiveSuspiciousTokens.length} كلمة حساسة${suspiciousTld ? `، نطاق عالي المخاطر (.${tld})` : ''}`,
            }
          : ownership.matched && suspiciousPathTokens.length > 0
            ? {
                en: `Standard service endpoint on verified official domain (${suspiciousPathTokens.join(', ')})`,
                ar: `مسار خدمة قياسي على نطاق رسمي موثق (${suspiciousPathTokens.join('، ')})`,
              }
            : { en: 'No suspicious lexical tokens or risky extensions', ar: 'لا توجد كلمات حساسة أو امتدادات خطرة' },
    status: misleadingDoubleExt || hasExecutableExt ? 'failed' : lexicalAlert ? 'warning' : 'pass',
    severity: misleadingDoubleExt || hasExecutableExt ? 'high' : lexicalAlert ? 'low' : 'informational',
    weight: misleadingDoubleExt
      ? 24
      : hasExecutableExt
        ? 20
        : 0,
    evidence: `Tokens: [${suspiciousPathTokens.join(', ') || 'none'}] | OfficialContext: ${ownership.matched} | TLD: .${tld} | Ext: ${extMatch || 'none'}`,
    explanation: {
      en: misleadingDoubleExt || hasExecutableExt
        ? 'URL path mimics a document or points directly to an executable/script payload, posing immediate malware risk.'
        : lexicalAlert
          ? 'URL path/host uses credential or phishing-associated keywords or a high-abuse TLD on an unverified domain.'
          : 'No deceptive file extensions or unverified phishing keyword clusters found in the URL string.',
      ar: misleadingDoubleExt || hasExecutableExt
        ? 'ينتهي مسار الرابط بامتداد مزدوج مضلل أو ملف تنفيذي مباشر يمثل خطراً أمنياً.'
        : lexicalAlert
          ? 'يحتوي مسار الرابط على كلمات مرتبطة بتسجيل الدخول أو نطاق عالي الاستغلال على نطاق غير موثق.'
          : 'لم يتم رصد امتدادات ملفات مضللة أو تجمعات كلمات تصيد مشبوهة في بنية الرابط.',
    },
    recommendedAction: {
      en: lexicalAlert ? 'Cross-check these URL signals with content and domain verification findings.' : 'No action required.',
      ar: lexicalAlert ? 'اربط هذه المؤشرات بنتائج فحص المحتوى والنطاق قبل اتخاذ قرار.' : 'لا يلزم إجراء.',
    },
    forensic: {
      whereDetected: { en: `URL host/path "${asciiDomain}${parsed.pathname}"`, ar: `مسار ونطاق الرابط "${asciiDomain}${parsed.pathname}"` },
      whyRisky: { en: 'High-abuse TLDs and login/verify keywords are heavily concentrated in phishing URLs.', ar: 'تتركز الكلمات المتعلقة بالتحقق وتسجيل الدخول وامتدادات الملفات الخطرة في روابط التصيد.' },
      howExploited: { en: 'Tricks users into believing an HTML phishing page or executable is a harmless PDF/invoice or official login portal.', ar: 'إيهام الضحية بأن الملف مستند آمن أو صفحة تحقق رسمية.' },
      userImpact: { en: 'Malware execution or credential compromise.', ar: 'تشغيل برمجية خبيثة أو سرقة الحساب.' },
      notProvenAlone: { en: 'Legitimate sites have "/login" paths too; keywords never elevate risk on verified official domains and require corroborating evidence elsewhere.', ar: 'وجود كلمة "login" أو امتداد TLD معين لا يثبت التصيد وحده دون ارتباطه بمحتوى أو بنية غير موثوقة.' },
    },
    source: 'SM Lexical Engine',
    timestamp: now,
    confidence: 90,
  });

  return {
    findings,
    isShortener,
    isMultiTenantPaas: paas.isPaas,
    paasProvider: paas.provider,
    registrableDomain,
    publicSuffix,
    unicodeDomain,
    asciiDomain,
    suspiciousPathTokens,
    encryptionTelemetry,
  };
}
