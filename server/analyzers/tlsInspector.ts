import net from 'node:net';
import tls from 'node:tls';
import type { CheckFinding, TlsInspectionData } from '../types.ts';
import { isPrivateOrReservedIp } from '../security/ssrfGuard.ts';
import { extractRegistrableDomain } from './urlIntelligence.ts';

function matchesCertSan(hostname: string, sanList: string[]): boolean {
  const host = hostname.toLowerCase();
  for (const rawSan of sanList) {
    const san = rawSan.replace(/^DNS:/i, '').trim().toLowerCase();
    if (!san) continue;
    if (san === host) return true;
    if (san.startsWith('*.')) {
      const suffix = san.slice(2);
      const hostParts = host.split('.');
      if (hostParts.length >= 2 && hostParts.slice(1).join('.') === suffix) {
        return true;
      }
    }
  }
  return false;
}

async function queryCtLogsCount(domain: string): Promise<number | undefined> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const res = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, {
      signal: controller.signal,
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) return undefined;
    const text = await res.text();
    if (text.trimStart().startsWith('<')) return undefined;
    const data = JSON.parse(text);
    return Array.isArray(data) ? data.length : undefined;
  } catch {
    return undefined;
  } finally {
    clearTimeout(timer);
  }
}

export async function inspectTlsCertificate(
  targetUrl: string,
  pinnedIp: string
): Promise<{ data: TlsInspectionData; findings: CheckFinding[] }> {
  const now = new Date().toISOString();
  const parsed = new URL(targetUrl);
  const hostname = parsed.hostname;
  const port = parsed.port ? Number(parsed.port) : 443;
  const findings: CheckFinding[] = [];

  if (isPrivateOrReservedIp(pinnedIp)) {
    return {
      data: { httpsAvailable: false, authorized: false, sanList: [] },
      findings: [
        {
          id: 'tls-ssrf-blocked',
          section: 'ssl_tls_analysis',
          test: { en: 'TLS Socket Inspection', ar: 'فحص شهادة TLS/SSL' },
          result: { en: 'Blocked private IP TLS handshake', ar: 'تم حظر فحص TLS لعنوان خاص' },
          status: 'failed',
          severity: 'critical',
          weight: 0,
          evidence: `Blocked IP: ${pinnedIp}`,
          explanation: {
            en: 'TLS connection refused by SSRF protection.',
            ar: 'تم رفض اتصال TLS بواسطة نظام الحماية من SSRF.',
          },
          recommendedAction: {
            en: 'Do not attempt to probe internal addresses.',
            ar: 'لا تحاول فحص عناوين الشبكات الداخلية.',
          },
          source: 'SM TLS Inspector',
          timestamp: now,
          confidence: 100,
        },
      ],
    };
  }

  const isIpHost = net.isIP(hostname.replace(/^\[|\]$/g, '')) !== 0;

  const tlsResult = await new Promise<TlsInspectionData>((resolve) => {
    let settled = false;
    const done = (val: TlsInspectionData) => {
      if (!settled) {
        settled = true;
        resolve(val);
      }
    };

    const socket = tls.connect(
      {
        host: pinnedIp,
        port,
        servername: isIpHost ? undefined : hostname,
        rejectUnauthorized: false,
        timeout: 6500,
      },
      () => {
        try {
          const cert = socket.getPeerCertificate(true) as tls.DetailedPeerCertificate;
          const protocol = socket.getProtocol() || undefined;
          const cipherInfo = socket.getCipher();
          const authorized = socket.authorized;
          const authorizationError = socket.authorizationError
            ? String(socket.authorizationError)
            : undefined;

          if (!cert || Object.keys(cert).length === 0) {
            socket.destroy();
            done({ httpsAvailable: false, authorized: false, sanList: [] });
            return;
          }

          let chainLength = 0;
          let cur: tls.DetailedPeerCertificate | undefined = cert;
          const visited = new Set<string>();
          while (cur && cur.fingerprint256 && !visited.has(cur.fingerprint256)) {
            visited.add(cur.fingerprint256);
            chainLength++;
            cur = cur.issuerCertificate;
          }

          const sanRaw = cert.subjectaltname || '';
          const sanList = sanRaw
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean);

          const validFrom = cert.valid_from ? new Date(cert.valid_from).toISOString() : undefined;
          const validTo = cert.valid_to ? new Date(cert.valid_to).toISOString() : undefined;
          const daysRemaining = validTo
            ? Math.floor((Date.parse(validTo) - Date.now()) / (1000 * 60 * 60 * 24))
            : undefined;
          const expired = daysRemaining !== undefined ? daysRemaining < 0 : undefined;

          const issuerObj = cert.issuer || {};
          const issuer = [issuerObj.O, issuerObj.CN].flat().filter(Boolean).join(' — ') || undefined;
          const rawCn = cert.subject?.CN;
          const subjectCN = Array.isArray(rawCn) ? rawCn[0] : rawCn;
          const domainMatches = isIpHost
            ? sanList.some((s) => s.toLowerCase().includes(hostname.toLowerCase()))
            : sanList.length > 0
              ? matchesCertSan(hostname, sanList)
              : subjectCN
                ? matchesCertSan(hostname, [subjectCN])
                : false;

          const keyBits = (cert as any).bits ? Number((cert as any).bits) : undefined;
          const sigAlg = (cert as any).sigalg ? String((cert as any).sigalg) : undefined;

          const weakCipherReasons: string[] = [];
          if (protocol === 'TLSv1' || protocol === 'TLSv1.1' || protocol === 'SSLv3') {
            weakCipherReasons.push(`Deprecated protocol (${protocol})`);
          }
          if (cipherInfo?.name && /(RC4|3DES|DES-CBC|EXPORT|NULL|MD5)/i.test(cipherInfo.name)) {
            weakCipherReasons.push(`Weak cipher (${cipherInfo.name})`);
          }
          if (sigAlg && /sha1/i.test(sigAlg)) {
            weakCipherReasons.push(`Weak SHA-1 certificate signature (${sigAlg})`);
          }
          if (keyBits && keyBits < 2048 && !(cert as any).asn1Curve) {
            weakCipherReasons.push(`Short RSA key (${keyBits}-bit)`);
          }

          const sharedSanMatch = sanList.find((s) =>
            /\*\.(?:appspot\.com|firebaseapp\.com|web\.app|github\.io|pages\.dev|workers\.dev|vercel\.app|netlify\.app|herokuapp\.com|blogspot\.com|google\.com|cloudflare\.com|sni\.cloudflaressl\.com)/i.test(s)
          );
          const isSharedMultiTenantCert = Boolean(
            sharedSanMatch ||
              sanList.length >= 10 ||
              (/cloudflare|google trust services|let's encrypt/i.test(issuer || '') && sanList.some((s) => s.includes('*.')))
          );
          const sharedWildcardSanNote = isSharedMultiTenantCert
            ? `Shared/wildcard SAN certificate (${sharedSanMatch || sanList[0] || issuer || 'Multi-tenant'}) covers transport only; Google/Cloudflare/CA SANs never prove page content safety.`
            : undefined;

          socket.destroy();
          done({
            httpsAvailable: true,
            authorized,
            authorizationError,
            protocol,
            cipher: cipherInfo?.name,
            keyBits,
            sigAlg,
            weakProtocolOrCipher: weakCipherReasons.length > 0,
            weakCipherReasons,
            chainLength,
            subjectCN,
            issuer,
            validFrom,
            validTo,
            daysRemaining,
            expired,
            domainMatches,
            sanList: sanList.slice(0, 25),
            sha256Fingerprint: cert.fingerprint256,
            isSharedMultiTenantCert,
            sharedWildcardSanNote,
          });
        } catch {
          socket.destroy();
          done({ httpsAvailable: false, authorized: false, sanList: [] });
        }
      }
    );

    socket.on('timeout', () => {
      socket.destroy();
      done({ httpsAvailable: false, authorized: false, sanList: [], authorizationError: 'TLS handshake timeout' });
    });

    socket.on('error', (err) => {
      socket.destroy();
      done({ httpsAvailable: false, authorized: false, sanList: [], authorizationError: err.message });
    });
  });

  if (!isIpHost && tlsResult.httpsAvailable) {
    const ctCount = await queryCtLogsCount(extractRegistrableDomain(hostname));
    if (ctCount !== undefined) {
      tlsResult.ctLogCount = ctCount;
      tlsResult.ctSource = 'crt.sh';
    }
  }

  if (!tlsResult.httpsAvailable) {
    findings.push({
      id: 'tls-availability',
      section: 'ssl_tls_analysis',
      test: { en: 'HTTPS / TLS Certificate Availability', ar: 'توفر شهادة HTTPS / TLS' },
      result: { en: 'No valid TLS endpoint on port 443', ar: 'لا توجد استجابة TLS صالحة على المنفذ 443' },
      status: 'failed',
      severity: 'high',
      weight: 18,
      evidence: tlsResult.authorizationError || 'TLS handshake failed on port 443',
      explanation: {
        en: 'Server did not complete a TLS handshake on port 443. Without TLS, traffic is unencrypted and exposed to interception.',
        ar: 'لم يكمل الخادم مصافحة TLS على المنفذ 443 مما يعني غياب التشفير أثناء النقل.',
      },
      recommendedAction: {
        en: 'Never submit credentials or personal data to an unencrypted endpoint.',
        ar: 'لا تدخل أي كلمات مرور أو بيانات شخصية في موقع بدون تشفير TLS.',
      },
      forensic: {
        whereDetected: { en: `TCP port ${port} on ${pinnedIp}`, ar: `منفذ TLS رقم ${port} على ${pinnedIp}` },
        whyRisky: {
          en: 'All network packets travel in cleartext, allowing network interception or injection.',
          ar: 'جميع البيانات تمر دون تشفير مما يسمح بالتنصت أو حقن محتوى خبيث على الشبكة.',
        },
        howExploited: {
          en: 'On-path observers on public Wi-Fi or ISP hops read submitted passwords or swap downloads.',
          ar: 'يستطيع المهاجم على الشبكات العامة قراءة كلمات المرور أو استبدال الملفات المنزلة.',
        },
        userImpact: { en: 'Credential exposure and man-in-the-middle tampering.', ar: 'انكشاف كلمات الدخول والتلاعب بالمحتوى.' },
        notProvenAlone: {
          en: 'Lack of TLS indicates insecure transport, not necessarily active malware.',
          ar: 'غياب التشفير يثبت ضعف النقل لكنه لا يثبت وحده وجود برمجيات خبيثة.',
        },
      },
      source: 'SM TLS Socket Inspector',
      timestamp: now,
      confidence: 95,
    });
    return { data: tlsResult, findings };
  }

  const certTrustIssues = !tlsResult.authorized || tlsResult.expired || tlsResult.domainMatches === false;
  findings.push({
    id: 'tls-chain-trust',
    section: 'ssl_tls_analysis',
    test: { en: 'Certificate Chain, Expiration & Hostname Match', ar: 'موثوقية الشهادة وصلاحيتها ومطابقة النطاق' },
    result: certTrustIssues
      ? {
          en: `Invalid TLS (${tlsResult.expired ? 'Expired' : tlsResult.domainMatches === false ? 'Domain Mismatch' : tlsResult.authorizationError || 'Untrusted Chain'})`,
          ar: `شهادة غير صالحة (${tlsResult.expired ? 'منتهية' : tlsResult.domainMatches === false ? 'عدم تطابق النطاق' : 'سلسلة غير موثوقة'})`,
        }
      : {
          en: `Valid TLS transport (${tlsResult.daysRemaining ?? '?'} days left, chain ${tlsResult.chainLength ?? 1}) — encryption only, not site legitimacy`,
          ar: `تشفير TLS صالح (متبقي ${tlsResult.daysRemaining ?? '?'} يوماً) — تشفير للنقل فقط وليس إثباتاً لأمان الموقع`,
        },
    status: certTrustIssues ? 'failed' : 'pass',
    severity: certTrustIssues ? 'high' : 'informational',
    weight: certTrustIssues ? 22 : 0,
    evidence: `Issuer: ${tlsResult.issuer ?? 'Unknown'} | Subject: ${tlsResult.subjectCN ?? 'N/A'} | Chain: ${tlsResult.chainLength ?? 1} | SANs: [${tlsResult.sanList.slice(0, 8).join(', ') || 'none'}] | SharedMultiTenantSAN: ${tlsResult.isSharedMultiTenantCert ? 'Yes' : 'No'} | Valid To: ${tlsResult.validTo ?? 'N/A'} | AuthErr: ${tlsResult.authorizationError ?? 'None'}`,
    explanation: {
      en: certTrustIssues
        ? 'TLS certificate failed chain trust, expiration, or hostname validation.'
        : `TLS certificate verifies encrypted transport to the server.${tlsResult.isSharedMultiTenantCert ? ' This certificate uses shared/wildcard SANs (e.g., Google, Cloudflare, or PaaS TLS); SAN presence proves transport identity to that edge only and NEVER proves hosted page safety.' : ' Phishing websites routinely obtain valid free certificates, so TLS NEVER proves site trustworthiness.'}`,
      ar: certTrustIssues
        ? 'فشلت شهادة TLS في التحقق من الموثوقية أو الصلاحية أو تطابق اسم النطاق.'
        : `تؤكد الشهادة تشفير الاتصال فقط.${tlsResult.isSharedMultiTenantCert ? ' كما أن وجود أسماء SANs تابعة لـ Google أو شبكات CDN أو شهادات wildcard يثبت تشفير المسار فقط ولا يثبت أبداً سلامة كل صفحة مستضافة عليه.' : ' تستخدم مواقع التصيد شهادات HTTPS صالحة بشكل اعتيادي، لذا لا يُعد القفل دليلاً على الأمان.'}`,
    },
    recommendedAction: {
      en: certTrustIssues ? 'Do not bypass browser certificate warnings.' : 'Evaluate website content and threat intelligence independently of HTTPS.',
      ar: certTrustIssues ? 'لا تتجاوز تحذيرات الشهادات في المتصفح.' : 'قيّم محتوى الموقع وسمعته بشكل مستقل عن وجود HTTPS.',
    },
    forensic: {
      whereDetected: { en: `X.509 certificate for "${hostname}"`, ar: `شهادة X.509 للنطاق "${hostname}"` },
      whyRisky: {
        en: certTrustIssues
          ? 'Self-signed, expired, or mismatched certificates prevent identity verification and enable MITM attacks.'
          : 'Attackers issue free DV TLS certificates within seconds for phishing domains.',
        ar: certTrustIssues
          ? 'الشهادة الموقعة ذاتياً أو المنتهية أو المخالفة للنطاق تفتح الباب لهجمات الاعتراض.'
          : 'يستخرج المهاجمون شهادات TLS مجانية خلال ثوانٍ لنطاقات التصيد.',
      },
      howExploited: {
        en: certTrustIssues
          ? 'MITM proxies intercept traffic with untrusted certificates expecting users to click "Proceed anyway".'
          : 'Deceptive login sites showcase valid HTTPS padlocks to reassure victims.',
        ar: certTrustIssues
          ? 'يعترض المهاجم الاتصال بشهادة غير موثوقة منتظراً تجاوز المستخدم للتحذير.'
          : 'تعتمد صفحات التصيد على علامة القفل لتبدو موثوقة للمستخدم.',
      },
      userImpact: {
        en: certTrustIssues ? 'Traffic interception and credential theft.' : 'None from TLS itself — inspect content and domain identity.',
        ar: certTrustIssues ? 'اعتراض الاتصال وسرقة البيانات.' : 'لا يثبت TLS وحده سلامة الموقع.',
      },
      notProvenAlone: {
        en: 'A valid HTTPS certificate NEVER proves a website is legitimate, safe, or operated by a trusted brand.',
        ar: 'صحة شهادة HTTPS لا تثبت مطلقاً أمان الموقع أو شرعيته.',
      },
    },
    source: 'SM TLS Socket Inspector',
    timestamp: now,
    confidence: 100,
  });

  const isWeakCipherOrProto = Boolean(tlsResult.weakProtocolOrCipher);
  findings.push({
    id: 'tls-protocol-cipher',
    section: 'ssl_tls_analysis',
    test: { en: 'TLS Protocol, Cipher Strength & CT Logs', ar: 'إصدار بروتوكول TLS وقوة التشفير وسجلات الشفافية' },
    result: isWeakCipherOrProto
      ? {
          en: `Weak TLS configuration (${tlsResult.weakCipherReasons?.join('; ')})`,
          ar: `إعدادات تشفير ضعيفة (${tlsResult.weakCipherReasons?.join('؛ ')})`,
        }
      : {
          en: `${tlsResult.protocol ?? 'Unknown'} · ${tlsResult.cipher ?? 'Unknown'}${tlsResult.keyBits ? ` · ${tlsResult.keyBits}-bit` : ''}`,
          ar: `${tlsResult.protocol ?? 'غير معروف'} · ${tlsResult.cipher ?? 'غير معروف'}${tlsResult.keyBits ? ` · ${tlsResult.keyBits} بت` : ''}`,
        },
    status: isWeakCipherOrProto ? 'warning' : 'pass',
    severity: isWeakCipherOrProto ? 'medium' : 'informational',
    weight: isWeakCipherOrProto ? 8 : 0,
    evidence: `Protocol: ${tlsResult.protocol} | Cipher: ${tlsResult.cipher} | KeyBits: ${tlsResult.keyBits ?? 'EC/Unknown'} | SigAlg: ${tlsResult.sigAlg ?? 'Unknown'} | WeakReasons: [${tlsResult.weakCipherReasons?.join(', ') || 'none'}] | CT Logs: ${tlsResult.ctLogCount ?? 'Unavailable'}`,
    explanation: {
      en: isWeakCipherOrProto
        ? `Server negotiated deprecated TLS parameters: ${tlsResult.weakCipherReasons?.join(', ')}.`
        : 'Server supports modern TLS protocol and cipher suite negotiation.',
      ar: isWeakCipherOrProto
        ? `تفاوض الخادم على إعدادات تشفير قديمة أو ضعيفة: ${tlsResult.weakCipherReasons?.join('، ')}.`
        : 'يدعم الخادم إصدارات وخوارزميات TLS الحديثة.',
    },
    recommendedAction: {
      en: isWeakCipherOrProto ? 'Avoid transmitting sensitive secrets over legacy cipher suites.' : 'No action required for TLS cipher strength.',
      ar: isWeakCipherOrProto ? 'تجنب إرسال بيانات حساسة عبر تشفير ضعيف.' : 'لا يلزم إجراء إضافي لإعدادات التشفير الحديثة.',
    },
    source: tlsResult.ctLogCount !== undefined ? 'SM TLS Inspector & crt.sh' : 'SM TLS Socket Inspector',
    timestamp: now,
    confidence: 95,
  });

  return { data: tlsResult, findings };
}
