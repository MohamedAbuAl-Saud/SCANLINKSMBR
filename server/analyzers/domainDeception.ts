import net from 'node:net';
import { domainToASCII, domainToUnicode } from 'node:url';
import * as cheerio from 'cheerio';
import type { CheckFinding, DomainDeceptionData, RedirectHop } from '../types.ts';
import {
  BRAND_INTELLIGENCE_DB,
  detectCompoundBrandLookalike,
  levenshtein,
  normalizeLeetHomoglyphs,
} from './brandIntelligence.ts';
import { classifyDomainRelationship, lookupDomainOwnership } from './officialDomainRegistry.ts';
import { detectPaasHosting, extractPslBreakdown, extractRegistrableDomain } from './urlIntelligence.ts';

// High-risk Unicode Confusables (UTS #39 skeleton subset for Cyrillic, Greek, Latin lookalikes)
const CONFUSABLE_CHAR_MAP: Record<string, { ascii: string; script: string }> = {
  '\u0430': { ascii: 'a', script: 'Cyrillic' },
  '\u0435': { ascii: 'e', script: 'Cyrillic' },
  '\u0451': { ascii: 'e', script: 'Cyrillic' },
  '\u043E': { ascii: 'o', script: 'Cyrillic' },
  '\u0440': { ascii: 'p', script: 'Cyrillic' },
  '\u0441': { ascii: 'c', script: 'Cyrillic' },
  '\u0443': { ascii: 'y', script: 'Cyrillic' },
  '\u0445': { ascii: 'x', script: 'Cyrillic' },
  '\u0456': { ascii: 'i', script: 'Cyrillic' },
  '\u0458': { ascii: 'j', script: 'Cyrillic' },
  '\u0455': { ascii: 's', script: 'Cyrillic' },
  '\u04CF': { ascii: 'l', script: 'Cyrillic' },
  '\u043A': { ascii: 'k', script: 'Cyrillic' },
  '\u043C': { ascii: 'm', script: 'Cyrillic' },
  '\u0442': { ascii: 't', script: 'Cyrillic' },
  '\u043D': { ascii: 'h', script: 'Cyrillic' },
  '\u0432': { ascii: 'b', script: 'Cyrillic' },
  '\u03B1': { ascii: 'a', script: 'Greek' },
  '\u03B5': { ascii: 'e', script: 'Greek' },
  '\u03BF': { ascii: 'o', script: 'Greek' },
  '\u03C1': { ascii: 'p', script: 'Greek' },
  '\u03BD': { ascii: 'v', script: 'Greek' },
  '\u03B9': { ascii: 'i', script: 'Greek' },
  '\u03BA': { ascii: 'k', script: 'Greek' },
  '\u03C4': { ascii: 't', script: 'Greek' },
  '\u03C7': { ascii: 'x', script: 'Greek' },
  '\u03C5': { ascii: 'u', script: 'Greek' },
  '\u0261': { ascii: 'g', script: 'Latin-IPA' },
  '\u0131': { ascii: 'i', script: 'Latin-Extended' },
  '\u0237': { ascii: 'j', script: 'Latin-Extended' },
  '\u026A': { ascii: 'i', script: 'Latin-IPA' },
  '\u028F': { ascii: 'y', script: 'Latin-IPA' },
  '\u0410': { ascii: 'a', script: 'Cyrillic' },
  '\u0412': { ascii: 'b', script: 'Cyrillic' },
  '\u0415': { ascii: 'e', script: 'Cyrillic' },
  '\u041A': { ascii: 'k', script: 'Cyrillic' },
  '\u041C': { ascii: 'm', script: 'Cyrillic' },
  '\u041D': { ascii: 'h', script: 'Cyrillic' },
  '\u041E': { ascii: 'o', script: 'Cyrillic' },
  '\u0420': { ascii: 'p', script: 'Cyrillic' },
  '\u0421': { ascii: 'c', script: 'Cyrillic' },
  '\u0422': { ascii: 't', script: 'Cyrillic' },
  '\u0425': { ascii: 'x', script: 'Cyrillic' },
};

const BIDI_CHAR_NAMES: Record<string, string> = {
  '\u202A': 'LEFT-TO-RIGHT EMBEDDING',
  '\u202B': 'RIGHT-TO-LEFT EMBEDDING',
  '\u202C': 'POP DIRECTIONAL FORMATTING',
  '\u202D': 'LEFT-TO-RIGHT OVERRIDE',
  '\u202E': 'RIGHT-TO-LEFT OVERRIDE (RLO)',
  '\u2066': 'LEFT-TO-RIGHT ISOLATE',
  '\u2067': 'RIGHT-TO-LEFT ISOLATE',
  '\u2068': 'FIRST STRONG ISOLATE',
  '\u2069': 'POP DIRECTIONAL ISOLATE',
  '\u200E': 'LEFT-TO-RIGHT MARK',
  '\u200F': 'RIGHT-TO-LEFT MARK',
};

const ZERO_WIDTH_REGEX = /[\u200B\u200C\u200D\u2060\uFEFF\u00AD]/g;

const REDIRECT_PARAM_NAMES = new Set([
  'redirect',
  'redirect_uri',
  'redirect_url',
  'next',
  'url',
  'target',
  'dest',
  'destination',
  'redir',
  'continue',
  'return',
  'returnurl',
  'return_url',
  'goto',
  'callback',
  'u',
  'out',
  'r',
]);

function buildConfusableSkeleton(unicodeHost: string): {
  skeleton: string;
  chars: { char: string; codePoint: string; lookalikeAscii: string; script: string }[];
} {
  const chars: { char: string; codePoint: string; lookalikeAscii: string; script: string }[] = [];
  let skeleton = '';
  for (const ch of unicodeHost) {
    const mapped = CONFUSABLE_CHAR_MAP[ch];
    if (mapped) {
      const cp = `U+${(ch.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}`;
      chars.push({ char: ch, codePoint: cp, lookalikeAscii: mapped.ascii, script: mapped.script });
      skeleton += mapped.ascii;
    } else {
      skeleton += ch.toLowerCase();
    }
  }
  return { skeleton, chars };
}

function tryExtractEmbeddedUrl(rawVal: string): { url: string; host: string } | null {
  const val = rawVal.trim();
  if (!val) return null;

  if (/^https?:\/\//i.test(val) || /^\/\/[a-z0-9.-]+\.[a-z]{2,}/i.test(val)) {
    try {
      const normalized = val.startsWith('//') ? `https:${val}` : val;
      const u = new URL(normalized);
      return { url: u.toString(), host: u.hostname.toLowerCase() };
    } catch {
      return null;
    }
  }

  if (val.length >= 12 && /^[A-Za-z0-9+/_-]+=*$/.test(val)) {
    try {
      const decoded = Buffer.from(val.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
      const m = decoded.match(/https?:\/\/[^\s"'<>]+/i);
      if (m) {
        const u = new URL(m[0]);
        return { url: u.toString(), host: u.hostname.toLowerCase() };
      }
    } catch {
      return null;
    }
  }

  return null;
}

function classifyTyposquatEdit(
  candidateLabel: string,
  officialLabel: string,
  offReg: string,
  distance: number
): NonNullable<DomainDeceptionData['typosquatDiff']> {
  const maxLen = Math.max(candidateLabel.length, officialLabel.length, 1);
  const similarityScore = Math.max(0, Math.min(99, Math.round((1 - distance / maxLen) * 100)));

  if (candidateLabel.length > officialLabel.length) {
    // Check if adjacent character repetition (e.g. payppal vs paypal)
    const collapsed = candidateLabel.replace(/(.)\1+/g, '$1');
    const offCollapsed = officialLabel.replace(/(.)\1+/g, '$1');
    const isRepetition = collapsed === offCollapsed && candidateLabel !== officialLabel;
    return {
      technique: isRepetition ? 'repetition' : 'insertion',
      targetDomain: offReg,
      similarityScore,
      differenceSummary: isRepetition
        ? {
            en: `Character repetition detected ("${candidateLabel}" vs "${officialLabel}", ${similarityScore}% similar).`,
            ar: `تم رصد تكرار حرف ("${candidateLabel}" مقارنة بـ "${officialLabel}"، تشابه ${similarityScore}%).`,
          }
        : {
            en: `Character insertion detected ("${candidateLabel}" adds ${candidateLabel.length - officialLabel.length} char(s) vs "${officialLabel}", ${similarityScore}% similar).`,
            ar: `تم رصد إدخال حرف إضافي ("${candidateLabel}" مقارنة بـ "${officialLabel}"، تشابه ${similarityScore}%).`,
          },
    };
  }

  if (candidateLabel.length < officialLabel.length) {
    return {
      technique: 'omission',
      targetDomain: offReg,
      similarityScore,
      differenceSummary: {
        en: `Character omission detected ("${candidateLabel}" drops ${officialLabel.length - candidateLabel.length} char(s) vs "${officialLabel}", ${similarityScore}% similar).`,
        ar: `تم رصد حذف حرف ("${candidateLabel}" مقارنة بـ "${officialLabel}"، تشابه ${similarityScore}%).`,
      },
    };
  }

  return {
    technique: 'substitution',
    targetDomain: offReg,
    similarityScore,
    differenceSummary: {
      en: `Character substitution/transposition ("${candidateLabel}" differs by ${distance} edit(s) from "${officialLabel}", ${similarityScore}% similar).`,
      ar: `تم رصد استبدال/تبديل أحرف ("${candidateLabel}" يختلف بمقدار ${distance} عن "${officialLabel}"، تشابه ${similarityScore}%).`,
    },
  };
}

function hasSubdomainToken(subdomainsPart: string, token: string): boolean {
  if (!subdomainsPart || !token) return false;
  const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(?:^|[.-])${escaped}(?:$|[.-])`, 'i').test(subdomainsPart);
}

export function analyzeDomainDeceptionAndIdentity(params: {
  submittedUrl: string;
  finalUrl: string;
  redirects: RedirectHop[];
  htmlBuffer?: Buffer;
  contentType?: string;
}): { data: DomainDeceptionData; findings: CheckFinding[] } {
  const now = new Date().toISOString();
  const findings: CheckFinding[] = [];

  const submittedParsed = new URL(
    params.submittedUrl.startsWith('http') ? params.submittedUrl : `https://${params.submittedUrl}`
  );
  const finalParsed = new URL(params.finalUrl);

  const submittedHost = submittedParsed.hostname.toLowerCase();
  const finalHost = finalParsed.hostname.toLowerCase();
  const asciiDomain = domainToASCII(finalHost) || finalHost;
  const unicodeDomain = domainToUnicode(asciiDomain) || finalHost;
  const pslFinal = extractPslBreakdown(asciiDomain);
  const registrableDomain = pslFinal.eTldPlusOne;

  const submittedAscii = domainToASCII(submittedHost) || submittedHost;
  const submittedUnicode = domainToUnicode(submittedAscii) || submittedHost;

  // Bidi, Zero-Width & Fragment Deception checks on raw submitted URL
  const bidiChars: { char: string; codePoint: string; name: string }[] = [];
  for (const ch of params.submittedUrl) {
    if (BIDI_CHAR_NAMES[ch]) {
      const cp = `U+${(ch.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}`;
      if (!bidiChars.some((x) => x.codePoint === cp)) {
        bidiChars.push({ char: ch, codePoint: cp, name: BIDI_CHAR_NAMES[ch] });
      }
    }
  }
  const bidiControlsDetected = bidiChars.length > 0;

  let decodedSubmittedUrl = params.submittedUrl;
  try {
    decodedSubmittedUrl = decodeURIComponent(params.submittedUrl);
  } catch {
    decodedSubmittedUrl = params.submittedUrl;
  }
  const zeroWidthMatches = decodedSubmittedUrl.match(ZERO_WIDTH_REGEX) || [];
  const zeroWidthDetected = zeroWidthMatches.length > 0;
  const zeroWidthCount = zeroWidthMatches.length;

  const rawFragment = submittedParsed.hash || '';
  const fragmentDeception =
    rawFragment.length > 2 &&
    (/https?:\/\//i.test(rawFragment) ||
      /@[a-z0-9.-]+\.[a-z]{2,}/i.test(rawFragment) ||
      /\.exe|\.scr|\.zip|paypal|apple|microsoft|google|binance/i.test(rawFragment));
  const fragmentEvidence = fragmentDeception ? `Fragment: ${rawFragment.slice(0, 120)}` : undefined;

  // Inspect both submitted and final hosts for Punycode & Unicode Confusables
  const activeUnicode = submittedUnicode !== submittedAscii ? submittedUnicode : unicodeDomain;
  const activeAscii = submittedUnicode !== submittedAscii ? submittedAscii : asciiDomain;
  const isPunycode = activeAscii.includes('xn--') || activeUnicode !== activeAscii;
  const mixedScripts = /[^\u0000-\u007f]/.test(activeUnicode) && /[a-zA-Z]/.test(activeUnicode);

  const { skeleton: confusableSkeleton, chars: confusableCharacters } = buildConfusableSkeleton(activeUnicode);
  const confusableDetected = confusableCharacters.length > 0;

  let confusableLookalikeDomain: string | undefined;
  let typosquatTarget: DomainDeceptionData['typosquatTarget'];
  let typosquatDiff: DomainDeceptionData['typosquatDiff'];
  let similarityOnly = false;
  const brandSimilarityMatches: NonNullable<DomainDeceptionData['brandSimilarityMatches']> = [];

  const hostOwnership = lookupDomainOwnership(asciiDomain);
  const paas = detectPaasHosting(asciiDomain);
  const regSkeleton = extractRegistrableDomain(confusableSkeleton);
  const paasTenantPrefix =
    paas.isPaas && paas.suffix && asciiDomain.endsWith(`.${paas.suffix}`)
      ? asciiDomain.slice(0, -(paas.suffix.length + 1))
      : '';
  const domainLabel = paas.isPaas
    ? (paasTenantPrefix.split('.').pop() || '')
    : (registrableDomain.split('.')[0] || '');
  const leetLabel = normalizeLeetHomoglyphs(domainLabel);

  for (const sig of BRAND_INTELLIGENCE_DB) {
    const isRelatedOrOfficial = sig.officialDomains.some(
      (off) => classifyDomainRelationship(asciiDomain, off).isSameOrganization
    );
    if (isRelatedOrOfficial) continue;

    for (const off of sig.officialDomains) {
      const offReg = extractRegistrableDomain(off);
      const offLabel = offReg.split('.')[0] || '';
      if (confusableDetected && (regSkeleton === offReg || levenshtein(regSkeleton, offReg) <= 1)) {
        confusableLookalikeDomain = offReg;
        const dist = levenshtein(regSkeleton, offReg);
        typosquatTarget = {
          brand: sig.brand,
          officialDomain: offReg,
          distance: dist,
          technique: 'Unicode Homoglyph / Confusable Substitution',
        };
        typosquatDiff = {
          technique: 'homoglyph',
          targetDomain: offReg,
          similarityScore: Math.max(80, Math.round((1 - dist / Math.max(offReg.length, 1)) * 100)),
          differenceSummary: {
            en: `Unicode confusable glyphs visually mimic "${offReg}" (${confusableCharacters.length} non-Latin substitution(s)).`,
            ar: `تطابق بصري عبر أحرف Unicode المتشابهة لتقليد "${offReg}" (${confusableCharacters.length} حرف مُبدل).`,
          },
        };
        brandSimilarityMatches.push({
          brand: sig.brand,
          officialDomain: offReg,
          similarityType: 'homoglyph',
          matchedToken: confusableSkeleton,
          evidence: `Unicode skeleton "${confusableSkeleton}" visually mimics "${offReg}"`,
        });
        break;
      }

      if (offLabel.length >= 4 && domainLabel.length >= 4 && !net.isIP(asciiDomain.replace(/^\[|\]$/g, ''))) {
        const distRaw = levenshtein(domainLabel, offLabel);
        const distLeet = levenshtein(leetLabel, offLabel);
        const maxDist = offLabel.length >= 5 ? 2 : 1;
        if (distRaw > 0 && distRaw <= maxDist) {
          const diffInfo = classifyTyposquatEdit(domainLabel, offLabel, offReg, distRaw);
          typosquatTarget = {
            brand: sig.brand,
            officialDomain: offReg,
            distance: distRaw,
            technique: `Typosquatting (${diffInfo.technique})`,
          };
          typosquatDiff = diffInfo;
          brandSimilarityMatches.push({
            brand: sig.brand,
            officialDomain: offReg,
            similarityType: 'typosquat',
            matchedToken: domainLabel,
            evidence: diffInfo.differenceSummary.en,
          });
          break;
        }
        if (distLeet === 0 && leetLabel !== domainLabel) {
          typosquatTarget = {
            brand: sig.brand,
            officialDomain: offReg,
            distance: 1,
            technique: 'Visual Digraph / Leetspeak Substitution (rn->m, 0->o, 1->l)',
          };
          typosquatDiff = {
            technique: 'digraph',
            targetDomain: offReg,
            similarityScore: Math.max(75, Math.round((1 - 1 / Math.max(offLabel.length, 1)) * 100)),
            differenceSummary: {
              en: `Leetspeak/digraph substitution "${domainLabel}" maps visually to "${offLabel}".`,
              ar: `تمويه بصري باستبدال أرقام أو ثنائيات أحرف ("${domainLabel}" يشبه "${offLabel}").`,
            },
          };
          brandSimilarityMatches.push({
            brand: sig.brand,
            officialDomain: offReg,
            similarityType: 'leetspeak_lookalike',
            matchedToken: domainLabel,
            evidence: typosquatDiff.differenceSummary.en,
          });
          break;
        }
      }
    }
    if (typosquatTarget) break;
  }

  // Compound or leetspeak brand lookalikes (e.g., google-login-example.com, g00gle-example.com,
  // facebook-security-example.com, github-login-example.com).
  // Flag non-accusatorily: similarity detected, impersonation not proven from domain name alone.
  if (!typosquatTarget && !hostOwnership.matched) {
    const compound = detectCompoundBrandLookalike(asciiDomain, registrableDomain);
    if (compound) {
      similarityOnly = true;
      typosquatTarget = {
        brand: compound.brand,
        officialDomain: compound.officialDomain,
        distance: Math.max(1, domainLabel.length - compound.matchedToken.length),
        technique:
          compound.similarityType === 'leetspeak_lookalike'
            ? 'Brand Lookalike (Leetspeak / Visual Substitution)'
            : 'Brand Name Similarity (Compound Domain)',
      };
      typosquatDiff = {
        technique: 'compound_lookalike',
        targetDomain: compound.officialDomain,
        similarityScore: 72,
        differenceSummary: {
          en: `Domain name similarity to a known brand (${compound.brand} / ${compound.officialDomain}) was detected; impersonation has not been proven.`,
          ar: `تم اكتشاف تشابه في اسم النطاق مع علامة تجارية معروفة (${compound.brand} / ${compound.officialDomain})، ولم يتم إثبات الانتحال.`,
        },
      };
      brandSimilarityMatches.push({
        brand: compound.brand,
        officialDomain: compound.officialDomain,
        similarityType: compound.similarityType,
        matchedToken: compound.matchedToken,
        evidence: compound.evidence,
      });
    }
  }

  // Subdomain Spoofing Check (strict PSL + word-boundary + relationship-aware)
  const subdomainsPart = pslFinal.subdomain;
  let subdomainSpoofing = false;
  let spoofedTargetDomain: string | undefined;

  if (!hostOwnership.matched && subdomainsPart) {
    for (const sig of BRAND_INTELLIGENCE_DB) {
      const isRelated = sig.officialDomains.some(
        (off) => classifyDomainRelationship(asciiDomain, off).isSameOrganization
      );
      if (isRelated) continue;

      const hitOfficial = sig.officialDomains.find(
        (off) => subdomainsPart === off || subdomainsPart.endsWith(`.${off}`) || subdomainsPart.includes(off)
      );
      const hitToken = sig.tokens.find((tok) => tok.length >= 4 && hasSubdomainToken(subdomainsPart, tok));
      if (hitOfficial || hitToken) {
        subdomainSpoofing = true;
        spoofedTargetDomain = hitOfficial || sig.officialDomains[0];
        brandSimilarityMatches.push({
          brand: sig.brand,
          officialDomain: sig.officialDomains[0],
          similarityType: 'subdomain_spoof',
          matchedToken: hitOfficial || hitToken || subdomainsPart,
          evidence: `Subdomain "${subdomainsPart}" embeds brand/domain "${hitOfficial || hitToken}" while true eTLD+1 is "${registrableDomain}"`,
        });
        break;
      }
    }

    if (!subdomainSpoofing && /(?:^|\.)[a-z0-9-]+\.(com|org|net|gov|edu|io)$/i.test(subdomainsPart)) {
      subdomainSpoofing = true;
      spoofedTargetDomain = subdomainsPart;
    }
  }

  // Authority @ Masking
  const authorityMasking =
    Boolean(submittedParsed.username || submittedParsed.password || finalParsed.username || finalParsed.password) ||
    /^https?:\/\/[^/?#]*@/.test(params.submittedUrl);
  const apparentUserDomain = authorityMasking
    ? `${submittedParsed.username || 'user'}@${submittedHost}`
    : submittedHost;

  // Embedded Redirect URLs & Open Redirect Confirmation (exclude benign same-org / authorized SSO flows)
  const embeddedRedirectUrls: { param: string; targetUrl: string; targetHost: string }[] = [];
  for (const p of [submittedParsed, finalParsed]) {
    for (const [k, v] of p.searchParams.entries()) {
      const kl = k.toLowerCase();
      const extracted = tryExtractEmbeddedUrl(v);
      if (extracted && !classifyDomainRelationship(p.hostname, extracted.host).isBenignOrAuthorized) {
        if (REDIRECT_PARAM_NAMES.has(kl) || extracted.host !== extractRegistrableDomain(p.hostname)) {
          if (!embeddedRedirectUrls.some((item) => item.param === k && item.targetUrl === extracted.url)) {
            embeddedRedirectUrls.push({
              param: k,
              targetUrl: extracted.url.slice(0, 160),
              targetHost: extracted.host,
            });
          }
        }
      }
    }
  }

  let openRedirectConfirmed = false;
  let openRedirectEvidence: string | undefined;
  const submittedReg = extractRegistrableDomain(submittedHost);
  const finalReg = extractRegistrableDomain(finalHost);
  if (
    embeddedRedirectUrls.length > 0 &&
    params.redirects.length > 1 &&
    finalReg !== submittedReg &&
    !classifyDomainRelationship(submittedHost, finalHost).isBenignOrAuthorized
  ) {
    const matchingEmbedded = embeddedRedirectUrls.find((item) => {
      const embReg = extractRegistrableDomain(item.targetHost);
      return (
        embReg !== submittedReg &&
        (embReg === finalReg || params.redirects.some((h) => extractRegistrableDomain(h.hostname) === embReg))
      );
    });
    if (matchingEmbedded) {
      openRedirectConfirmed = true;
      openRedirectEvidence = `Query parameter "${matchingEmbedded.param}=${matchingEmbedded.targetUrl}" matched actual HTTP cross-domain redirect destination "${finalHost}"`;
    }
  }

  // Visible Link vs Real Destination Mismatches inside HTML anchors (ignore same-org / authorized relations)
  const visibleVsRealMismatches: { visibleText: string; actualHost: string; actualUrl: string }[] = [];
  if (
    params.htmlBuffer &&
    (!params.contentType ||
      params.contentType.toLowerCase().includes('html') ||
      params.htmlBuffer.slice(0, 400).toString('utf8').toLowerCase().includes('<a'))
  ) {
    try {
      const $ = cheerio.load(params.htmlBuffer.toString('utf8'));
      $('a[href]').each((_, el) => {
        if (visibleVsRealMismatches.length >= 10) return;
        const href = ($(el).attr('href') || '').trim();
        const visibleText = $(el).text().replace(/\s+/g, ' ').trim();
        if (!href || !visibleText) return;
        const visibleUrlMatch = visibleText.match(/\b(?:https?:\/\/)?([a-z0-9.-]+\.[a-z]{2,20})(?:\/[^\s]*)?\b/i);
        if (visibleUrlMatch) {
          try {
            const visibleDomain = extractRegistrableDomain(visibleUrlMatch[1].toLowerCase());
            const resolvedHref = new URL(href, params.finalUrl);
            const actualDomain = extractRegistrableDomain(resolvedHref.hostname.toLowerCase());
            if (
              visibleDomain &&
              actualDomain &&
              visibleDomain !== actualDomain &&
              !classifyDomainRelationship(visibleDomain, resolvedHref.hostname).isBenignOrAuthorized
            ) {
              visibleVsRealMismatches.push({
                visibleText: visibleText.slice(0, 90),
                actualHost: resolvedHref.hostname.toLowerCase(),
                actualUrl: resolvedHref.toString().slice(0, 140),
              });
            }
          } catch {
            // ignore
          }
        }
      });
    } catch {
      // ignore
    }
  }

  // Finding 1: Unicode Confusables, Punycode & Lookalike Analysis
  const hasHomographOrStrictTyposquat = confusableDetected || mixedScripts || (Boolean(typosquatTarget) && !similarityOnly);
  const hasBrandSimilarityOnly = Boolean(typosquatTarget) && similarityOnly && !confusableDetected && !mixedScripts;
  findings.push({
    id: 'deception-homograph-confusables',
    section: 'domain_deception',
    test: {
      en: 'Unicode Confusables, Punycode & Lookalike Detection',
      ar: 'كشف خداع Unicode و Punycode والنطاقات المتشابهة',
    },
    result: confusableDetected
      ? {
          en: `Unicode homoglyph confusables detected (${confusableCharacters.length} non-Latin char(s) -> "${confusableSkeleton}")`,
          ar: `رصد أحرف متشابهة بصرياً (${confusableCharacters.length} حرف غير لاتيني -> "${confusableSkeleton}")`,
        }
      : hasBrandSimilarityOnly && typosquatTarget
        ? {
            en: `Domain name similarity to ${typosquatTarget.brand} (${typosquatTarget.officialDomain}) detected — impersonation not proven`,
            ar: 'تم اكتشاف تشابه في اسم النطاق مع علامة تجارية معروفة، ولم يتم إثبات الانتحال',
          }
        : typosquatTarget
          ? {
              en: `Domain name closely resembles ${typosquatTarget.brand} (${typosquatTarget.officialDomain}) via ${typosquatTarget.technique}`,
              ar: `تم اكتشاف تشابه في اسم النطاق مع ${typosquatTarget.brand} (${typosquatTarget.officialDomain})`,
            }
          : isPunycode
            ? {
                en: `Internationalized Punycode domain (${activeUnicode} / ${activeAscii})`,
                ar: `نطاق دولي مرمز بـ Punycode (${activeUnicode} / ${activeAscii})`,
              }
            : {
                en: 'No Unicode confusables or known typosquatting patterns detected',
                ar: 'لا توجد أحرف تمويه Unicode أو أنماط نطاقات متشابهة',
              },
    status: hasHomographOrStrictTyposquat ? 'failed' : hasBrandSimilarityOnly || isPunycode ? 'warning' : 'pass',
    severity: confusableDetected
      ? 'high'
      : hasHomographOrStrictTyposquat
        ? 'high'
        : hasBrandSimilarityOnly
          ? 'medium'
          : isPunycode
            ? 'low'
            : 'informational',
    weight: confusableDetected ? 28 : hasHomographOrStrictTyposquat ? 24 : hasBrandSimilarityOnly ? 16 : isPunycode ? 4 : 0,
    evidence: `ASCII: ${activeAscii} | Unicode: ${activeUnicode} | eTLD+1: ${registrableDomain} | Confusables: [${confusableCharacters.map((c) => `${c.char}(${c.codePoint}->${c.lookalikeAscii},${c.script})`).join(', ') || 'none'}] | Lookalike: ${confusableLookalikeDomain || typosquatTarget?.officialDomain || 'none'}${typosquatDiff ? ` | SimilarityOnly: ${similarityOnly} | Similarity: ${typosquatDiff.similarityScore}%` : ''}`,
    relatedUrl: params.finalUrl,
    pageFoundOn: params.submittedUrl,
    explanation: {
      en: typosquatDiff
        ? typosquatDiff.differenceSummary.en
        : hasHomographOrStrictTyposquat
          ? 'Visual character substitution replaces Latin letters with nearly identical Cyrillic/Greek glyphs or typos to deceive users into thinking they are visiting a trusted brand.'
          : isPunycode
            ? 'The domain uses Punycode (xn--) encoding for non-ASCII characters; verify its decoded Unicode form carefully.'
            : 'Hostname consists of standard non-confusable characters with no detected lookalike impersonation.',
      ar: typosquatDiff
        ? typosquatDiff.differenceSummary.ar
        : hasHomographOrStrictTyposquat
          ? 'يستبدل المهاجم أحرفاً لاتينية بأحرف من أبجديات أخرى متطابقة في الشكل أو بأخطاء إملائية طفيفة لخداع المستخدم بانتحال نطاق موثوق.'
          : isPunycode
            ? 'يستخدم النطاق ترميز Punycode الدولي؛ يجب مراجعة النطاق المفكك بصرياً.'
            : 'النطاق يستخدم أحرفاً قياسية بدون استبدال بصري أو تشابه انتحال مكتشف.',
    },
    recommendedAction: {
      en:
        hasHomographOrStrictTyposquat || hasBrandSimilarityOnly
          ? `Do not assume this domain is operated by ${typosquatTarget?.brand || 'the referenced brand'}. Verify the official address${typosquatTarget ? ` (${typosquatTarget.officialDomain})` : ''} directly.`
          : 'No action required.',
      ar:
        hasHomographOrStrictTyposquat || hasBrandSimilarityOnly
          ? `تحقق من هوية الجهة المشغلة ولا تفترض تبعيته للعلامة التجارية؛ افتح الموقع الرسمي مباشرة${typosquatTarget ? ` (${typosquatTarget.officialDomain})` : ''}.`
          : 'لا يلزم إجراء.',
    },
    forensic: {
      whereDetected: {
        en: `Hostname "${activeUnicode}" (ASCII Punycode: "${activeAscii}", True eTLD+1: "${registrableDomain}")`,
        ar: `اسم النطاق المفحوص "${activeUnicode}" (ASCII: "${activeAscii}"، النطاق الأساسي: "${registrableDomain}")`,
      },
      whyRisky: {
        en: 'Users may confuse lookalike or brand-containing domains with official services unless ownership is independently confirmed.',
        ar: 'قد يخلط المستخدم بين النطاقات المتشابهة أو التي تتضمن اسم علامة تجارية وبين النطاق الرسمي المعتمد.',
      },
      howExploited: {
        en: 'Lookalike domains are sometimes registered to host credential-harvesting login pages with valid TLS certificates.',
        ar: 'تُستخدم النطاقات المقلدة أحياناً في حملات التصيد حتى لو كانت تملك شهادة HTTPS صالحة.',
      },
      userImpact: {
        en: 'Risk of misplaced trust in an unaffiliated domain.',
        ar: 'احتمالية منح الثقة لنطاق غير تابع للجهة الرسمية.',
      },
      notProvenAlone: {
        en: 'Domain-name similarity alone does NOT prove malicious intent or active impersonation without supporting phishing content, credential theft, or threat-feed evidence.',
        ar: 'تشابه اسم النطاق وحده لا يثبت وجود انتحال فعلي أو نشاط خبيث ما لم تتوفر أدلة محتوى أو استخبارات تهديدات داعمة.',
      },
    },
    source: 'SM Domain Deception & Confusables Engine',
    timestamp: now,
    confidence: hasHomographOrStrictTyposquat ? 96 : hasBrandSimilarityOnly ? 85 : 90,
  });

  // Finding 2: Subdomain Spoofing & Visible vs Real Domain Mismatch
  const hasVisibleMismatch = visibleVsRealMismatches.length > 0;
  const hasDomainMasking = subdomainSpoofing || authorityMasking || hasVisibleMismatch;
  findings.push({
    id: 'deception-subdomain-identity-mismatch',
    section: 'domain_deception',
    test: {
      en: 'Subdomain Spoofing & Visible vs Real Domain Check',
      ar: 'كشف تمويه النطاقات الفرعية واختلاف النطاق الظاهر عن الحقيقي',
    },
    result: authorityMasking
      ? {
          en: `Authority masking (@) hides true host "${finalHost}" behind deceptive userinfo`,
          ar: `التمويه بالرمز "@" يخفي النطاق الحقيقي "${finalHost}"`,
        }
      : subdomainSpoofing
        ? {
            en: `Subdomain spoofs "${spoofedTargetDomain}" while true eTLD+1 domain is "${registrableDomain}"`,
            ar: `النطاق الفرعي ينتحل "${spoofedTargetDomain}" بينما النطاق الحقيقي هو "${registrableDomain}"`,
          }
        : hasVisibleMismatch
          ? {
              en: `${visibleVsRealMismatches.length} anchor link(s) display a domain different from the actual href target`,
              ar: `رصد ${visibleVsRealMismatches.length} رابط يعرض نص نطاق يختلف عن وجهته الحقيقية`,
            }
          : {
              en: `True registrable domain "${registrableDomain}" matches visible authority cleanly`,
              ar: `النطاق المسجل الحقيقي "${registrableDomain}" واضح بدون تمويه فرعي أو نصي`,
            },
    status: authorityMasking || subdomainSpoofing || hasVisibleMismatch ? 'failed' : 'pass',
    severity: authorityMasking || subdomainSpoofing ? 'high' : hasVisibleMismatch ? 'medium' : 'informational',
    weight: (authorityMasking ? 28 : 0) + (subdomainSpoofing ? 32 : 0) + (hasVisibleMismatch ? 14 : 0),
    evidence: `True eTLD+1: ${registrableDomain} | SubdomainSpoofing: ${subdomainSpoofing} (${spoofedTargetDomain ?? 'none'}) | Authority@: ${authorityMasking} | AnchorMismatches: [${visibleVsRealMismatches.map((m) => `"${m.visibleText}" -> ${m.actualHost}`).join('; ') || 'none'}]`,
    relatedUrl: params.finalUrl,
    pageFoundOn: params.finalUrl,
    sourceCodeEvidence: visibleVsRealMismatches.length > 0
      ? visibleVsRealMismatches.map((m) => `<a href="${m.actualUrl}">${m.visibleText}</a>`).slice(0, 3).join(' | ')
      : undefined,
    explanation: {
      en: hasDomainMasking
        ? 'Deceptive domain structure places trusted names to the left (userinfo or subdomains) or displays misleading anchor text so the true registrable domain is obscured.'
        : 'Subdomain hierarchy and page anchor labels match actual destination hostnames.',
      ar: hasDomainMasking
        ? 'يضع التمويه أسماء موثوقة في جهة اليسار أو داخل النطاقات الفرعية أو نص الرابط لإخفاء النطاق الحقيقي المتحكم بالوجهة.'
        : 'بنية النطاقات الفرعية ونصوص الروابط تتطابق مع النطاق الحقيقي.',
    },
    recommendedAction: {
      en: hasDomainMasking
        ? `Verify the rightmost registrable eTLD+1 domain ("${registrableDomain}") before proceeding.`
        : 'No action required.',
      ar: hasDomainMasking
        ? `تحقق من النطاق الأساسي في أقصى اليمين قبل التمدد ("${registrableDomain}") ولا تعتمد على النطاقات الفرعية.`
        : 'لا يلزم إجراء.',
    },
    forensic: {
      whereDetected: {
        en: `Hostname "${asciiDomain}" / PSL eTLD+1 "${registrableDomain}"${hasVisibleMismatch ? ` and ${visibleVsRealMismatches.length} HTML <a> link(s)` : ''}`,
        ar: `المضيف "${asciiDomain}" / النطاق الأساسي "${registrableDomain}"`,
      },
      whyRisky: {
        en: 'Users often inspect only the beginning of a URL and fail to notice the actual controlling root domain.',
        ar: 'يقرأ معظم المستخدمين بداية الرابط فقط ويغفلون عن النطاق الأساسي المسؤول فعلياً عن الخادم.',
      },
      howExploited: {
        en: 'Attackers create subdomains like "paypal.com.verify-login.tld" or disguise phishing buttons behind trusted anchor labels.',
        ar: 'ينشئ المهاجم نطاقات فرعية باسم العلامة التجارية أو يضع نص رابط موثوق يشير برمجياً إلى موقع آخر.',
      },
      userImpact: {
        en: 'Unwitting authentication on an attacker domain.',
        ar: 'تسليم بيانات الدخول أو الدفع لموقع مخادع دون انتباه.',
      },
      notProvenAlone: {
        en: 'Legitimate multi-tenant integrations may embed partner names in subdomains; ownership confirmation checks root domain registration and page content.',
        ar: 'قد تستخدم بعض التكاملات المشروعة أسماء شركاء في النطاق الفرعي؛ لذا يُقارن دائماً مع هوية النطاق الأساسي ومحتوى الصفحة.',
      },
    },
    source: 'SM Domain Deception & Identity Engine',
    timestamp: now,
    confidence: hasDomainMasking ? 95 : 90,
  });

  // Finding 3: Bidi Control Characters, Zero-Width Chars & URL Fragment Deception
  const hasInvisibleOrFragmentTrick = bidiControlsDetected || zeroWidthDetected || fragmentDeception;
  findings.push({
    id: 'deception-bidi-zerowidth-fragment',
    section: 'domain_deception',
    test: {
      en: 'Unicode Bidi Controls, Zero-Width Characters & Fragment Deception',
      ar: 'كشف أحرف التحكم البصري (Bidi) والأحرف المخفية وخداع Fragment',
    },
    result: hasInvisibleOrFragmentTrick
      ? {
          en: [
            bidiControlsDetected ? `${bidiChars.length} Bidi override char(s)` : '',
            zeroWidthDetected ? `${zeroWidthCount} invisible zero-width char(s)` : '',
            fragmentDeception ? 'Deceptive #fragment masking detected' : '',
          ]
            .filter(Boolean)
            .join(' · '),
          ar: [
            bidiControlsDetected ? `${bidiChars.length} حرف توجيه بصري Bidi` : '',
            zeroWidthDetected ? `${zeroWidthCount} حرف صفري مخفي` : '',
            fragmentDeception ? 'تمويه في جزء #fragment' : '',
          ]
            .filter(Boolean)
            .join(' · '),
        }
      : {
          en: 'No Bidi override controls, zero-width characters, or deceptive URL fragments detected',
          ar: 'لا توجد أحرف توجيه Bidi أو أحرف مخفية أو تمويه في #fragment',
        },
    status: bidiControlsDetected || zeroWidthDetected ? 'failed' : fragmentDeception ? 'warning' : 'pass',
    severity: bidiControlsDetected ? 'high' : zeroWidthDetected || fragmentDeception ? 'medium' : 'informational',
    weight: (bidiControlsDetected ? 24 : 0) + (zeroWidthDetected ? 16 : 0) + (fragmentDeception ? 10 : 0),
    evidence: `Bidi: [${bidiChars.map((b) => `${b.codePoint} (${b.name})`).join(', ') || 'none'}] | ZeroWidthCount: ${zeroWidthCount} | ${fragmentEvidence || 'Fragment: clean'}`,
    relatedUrl: params.submittedUrl,
    explanation: {
      en: hasInvisibleOrFragmentTrick
        ? 'Invisible formatting characters, Bidi directional overrides (like U+202E), or crafted #fragment strings visually reorder or disguise filenames and destinations.'
        : 'URL contains no hidden directional overrides, invisible spacing characters, or deceptive fragment payloads.',
      ar: hasInvisibleOrFragmentTrick
        ? 'تُستخدم أحرف التحكم في الاتجاه (مثل U+202E) والأحرف غير المرئية وجزء #fragment لخداع العين وإخفاء الوجهة أو الامتداد الحقيقي.'
        : 'يخلو الرابط من أحرف التوجيه المخفية والأحرف غير المرئية وتمويه #fragment.',
    },
    recommendedAction: {
      en: hasInvisibleOrFragmentTrick ? 'Do not trust visual rendering of this URL; inspect raw ASCII/Punycode.' : 'No action required.',
      ar: hasInvisibleOrFragmentTrick ? 'لا تعتمد على العرض البصري لهذا الرابط وراجع صيغة ASCII الأصلية.' : 'لا يلزم إجراء.',
    },
    source: 'SM Unicode & Bidi Deception Auditor',
    timestamp: now,
    confidence: 96,
  });

  // Finding 4: Embedded Redirect Parameters & Open Redirect Proof Verification
  findings.push({
    id: 'deception-open-redirect-relays',
    section: 'domain_deception',
    test: {
      en: 'Embedded Parameter URLs & Open Redirect Relay Check',
      ar: 'الروابط المضمنة بالمعاملات وكشف إعادة التوجيه المفتوحة (Open Redirect)',
    },
    result: openRedirectConfirmed
      ? {
          en: `Confirmed cross-domain open redirect relay via query parameter to "${finalHost}"`,
          ar: `تم تأكيد إعادة توجيه مفتوحة عبر معاملات الرابط نحو "${finalHost}"`,
        }
      : embeddedRedirectUrls.length > 0
        ? {
            en: `${embeddedRedirectUrls.length} destination URL(s) embedded inside query parameters (${embeddedRedirectUrls.map((e) => e.param).join(', ')})`,
            ar: `رصد ${embeddedRedirectUrls.length} رابط وجهة مضمن داخل معاملات URL (${embeddedRedirectUrls.map((e) => e.param).join(', ')})`,
          }
        : {
            en: 'No deceptive relay parameters or open redirect chains detected',
            ar: 'لا توجد روابط مضمنة للتمويه أو إعادة توجيه مفتوحة',
          },
    status: openRedirectConfirmed ? 'failed' : embeddedRedirectUrls.length > 0 ? 'warning' : 'pass',
    severity: openRedirectConfirmed ? 'high' : embeddedRedirectUrls.length > 0 ? 'medium' : 'informational',
    weight: openRedirectConfirmed ? 22 : embeddedRedirectUrls.length > 0 ? 8 : 0,
    evidence:
      openRedirectEvidence ||
      (embeddedRedirectUrls.length > 0
        ? embeddedRedirectUrls.map((e) => `${e.param} -> ${e.targetUrl}`).join(' | ')
        : 'No redirect/destination parameters carrying external URLs'),
    relatedUrl: params.finalUrl,
    explanation: {
      en: openRedirectConfirmed
        ? 'Submitted URL leveraged a redirect query parameter and HTTP redirection actually bounced traffic onto an external third-party domain.'
        : embeddedRedirectUrls.length > 0
          ? 'URL parameters embed external destination addresses. While common in OAuth/SSO callbacks, attackers also exploit open redirects on trusted domains to bounce victims to phishing sites.'
          : 'No hidden or nested redirect destination parameters found.',
      ar: openRedirectConfirmed
        ? 'استغل الرابط معامل إعادة توجيه وأثبت التتبع الفعلي انتقال الزائر عبره إلى نطاق خارجي مختلف.'
        : embeddedRedirectUrls.length > 0
          ? 'تحتوي معاملات الرابط على عناوين خارجية مضمنة؛ ورغم استخدامها أحياناً في OAuth/SSO إلا أنها تُستغل أيضاً في استغلال ثغرات Open Redirect.'
          : 'لم تُرصد معاملات تحمل روابط خارجية مضمنة أو سلاسل تمرير خادعة.',
    },
    recommendedAction: {
      en:
        openRedirectConfirmed || embeddedRedirectUrls.length > 0
          ? 'Inspect the exact Final Destination domain shown at the top of the report rather than trusting the initial domain.'
          : 'No action required.',
      ar:
        openRedirectConfirmed || embeddedRedirectUrls.length > 0
          ? 'راجع النطاق النهائي الذي انتهى إليه الفحص ولا تكتفِ باسم النطاق الأول في الرابط.'
          : 'لا يلزم إجراء.',
    },
    forensic: {
      whereDetected: {
        en: embeddedRedirectUrls.length > 0 ? `URL query string parameters (${embeddedRedirectUrls.map((e) => e.param).join(', ')})` : 'URL query parameters',
        ar: embeddedRedirectUrls.length > 0 ? `معاملات الاستعلام (${embeddedRedirectUrls.map((e) => e.param).join(', ')})` : 'معاملات الاستعلام في الرابط',
      },
      whyRisky: {
        en: 'Trusted brands with unvalidated redirect endpoints can be abused as trusted launchpads into malicious sites.',
        ar: 'تُستغل المواقع الموثوقة التي تفتقر لتقييد وجهات التوجيه كجسر موثوق لإرسال الضحايا نحو صفحات احتيالية.',
      },
      howExploited: {
        en: 'Phishing campaigns craft URLs starting with "https://trusted.com/go?next=https://evil.tld" to bypass mail filters and user vigilance.',
        ar: 'تُرسل روابط تبدأ بنطاق موثوق وتخفي الوجهة الخبيثة داخل معامل مثل ?next= أو ?url= لتجاوز فلاتر البريد.',
      },
      userImpact: {
        en: 'Silent transfer to an untrusted phishing destination.',
        ar: 'نقل المستخدم تلقائياً إلى موقع احتيالي دون أن يلحظ تغيّر الوجهة.',
      },
      notProvenAlone: {
        en: 'Presence of a "?next=" or "?redirect_uri=" parameter is NOT proof of an Open Redirect vulnerability unless live HTTP execution confirms cross-domain redirection to an arbitrary host.',
        ar: 'وجود معامل "?next=" أو "?redirect=" لا يثبت وجود ثغرة Open Redirect ما لم يثبت التتبع الفعلي انتقالاً غير مقيد نحو النطاق الخارجي.',
      },
    },
    source: 'SM Redirect & Relay Auditor',
    timestamp: now,
    confidence: openRedirectConfirmed ? 96 : 85,
  });

  return {
    data: {
      submittedHost,
      finalHost,
      originalDomain: submittedHost,
      normalizedDomain: asciiDomain,
      apparentUserDomain,
      publicSuffix: pslFinal.publicSuffix,
      eTldPlusOne: registrableDomain,
      registrableDomain,
      asciiDomain,
      unicodeDomain,
      isPunycode,
      mixedScripts,
      bidiControlsDetected,
      bidiChars,
      zeroWidthDetected,
      zeroWidthCount,
      fragmentDeception,
      fragmentEvidence,
      confusableDetected,
      confusableSkeleton: confusableDetected ? confusableSkeleton : undefined,
      confusableLookalikeDomain,
      confusableCharacters,
      subdomainSpoofing,
      spoofedTargetDomain,
      authorityMasking,
      visibleVsRealMismatches,
      embeddedRedirectUrls,
      openRedirectConfirmed,
      openRedirectEvidence,
      typosquatTarget,
      typosquatDiff,
      similarityOnly,
      brandSimilarityMatches,
    },
    findings,
  };
}
