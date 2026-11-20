export interface BrandSignature {
  brand: string;
  category: 'Tech' | 'Social' | 'Commerce' | 'Finance' | 'Logistics' | 'Crypto' | 'Telecom' | 'Developer' | 'Gaming' | 'Government';
  officialDomains: string[];
  tokens: string[];
  contentKeywords: string[];
}

export const BRAND_INTELLIGENCE_DB: BrandSignature[] = [
  {
    brand: 'Google',
    category: 'Tech',
    officialDomains: ['google.com', 'accounts.google.com', 'gmail.com', 'youtube.com', 'workspace.google.com'],
    tokens: ['google', 'gmail', 'googledrive', 'googleaccount'],
    contentKeywords: ['sign in with google', 'google account', 'gmail', 'google workspace'],
  },
  {
    brand: 'Microsoft',
    category: 'Tech',
    officialDomains: ['microsoft.com', 'login.microsoftonline.com', 'live.com', 'outlook.com', 'office.com', 'onedrive.live.com'],
    tokens: ['microsoft', 'office365', 'outlook', 'onedrive', 'sharepoint', 'micros0ft'],
    contentKeywords: ['microsoft account', 'office 365', 'microsoft 365', 'outlook web', 'onedrive'],
  },
  {
    brand: 'Apple',
    category: 'Tech',
    officialDomains: ['apple.com', 'icloud.com', 'appleid.apple.com'],
    tokens: ['appleid', 'icloud', 'apple-support', 'itunes', 'app1e'],
    contentKeywords: ['apple id', 'icloud', 'apple account', 'find my iphone'],
  },
  {
    brand: 'Yahoo Mail',
    category: 'Tech',
    officialDomains: ['yahoo.com', 'mail.yahoo.com'],
    tokens: ['yahoomail', 'yahoo-login', 'yhaoo'],
    contentKeywords: ['yahoo mail', 'sign in to yahoo'],
  },
  {
    brand: 'Proton Mail',
    category: 'Tech',
    officialDomains: ['proton.me', 'protonmail.com'],
    tokens: ['protonmail', 'proton-verify'],
    contentKeywords: ['proton mail', 'proton account'],
  },
  {
    brand: 'Meta / Facebook',
    category: 'Social',
    officialDomains: ['meta.com', 'facebook.com', 'fb.com', 'messenger.com'],
    tokens: ['facebook', 'meta-security', 'fb-verify', 'messenger', 'faceb00k'],
    contentKeywords: ['facebook', 'meta business', 'meta account', 'facebook security'],
  },
  {
    brand: 'Instagram',
    category: 'Social',
    officialDomains: ['instagram.com'],
    tokens: ['instagram', 'instagrarn', 'ig-verify'],
    contentKeywords: ['instagram', 'verified badge', 'instagram copyright'],
  },
  {
    brand: 'WhatsApp',
    category: 'Social',
    officialDomains: ['whatsapp.com'],
    tokens: ['whatsapp', 'whatsap', 'whats-app'],
    contentKeywords: ['whatsapp web', 'whatsapp verification'],
  },
  {
    brand: 'Discord',
    category: 'Social',
    officialDomains: ['discord.com', 'discord.gg', 'discordapp.com'],
    tokens: ['discord', 'dlscord', 'discord-nitro', 'discordapp'],
    contentKeywords: ['discord nitro', 'claim discord', 'discord login'],
  },
  {
    brand: 'X / Twitter',
    category: 'Social',
    officialDomains: ['x.com', 'twitter.com'],
    tokens: ['twitter', 'tw1tter'],
    contentKeywords: ['sign in to x', 'twitter account'],
  },
  {
    brand: 'LinkedIn',
    category: 'Social',
    officialDomains: ['linkedin.com'],
    tokens: ['linkedin', '1inkedin'],
    contentKeywords: ['linkedin', 'linkedin account'],
  },
  {
    brand: 'GitHub',
    category: 'Developer',
    officialDomains: ['github.com'],
    tokens: ['github', 'githuh'],
    contentKeywords: ['sign in to github', 'github personal access'],
  },
  {
    brand: 'PayPal',
    category: 'Finance',
    officialDomains: ['paypal.com'],
    tokens: ['paypal', 'paypa1', 'pp-secure'],
    contentKeywords: ['paypal', 'paypal account', 'paypal resolution center'],
  },
  {
    brand: 'Amazon',
    category: 'Commerce',
    officialDomains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.ae', 'amazon.sa', 'aws.amazon.com'],
    tokens: ['amazon', 'amzn', 'aws-login', 'arnazon'],
    contentKeywords: ['amazon prime', 'amazon account', 'aws management console'],
  },
  {
    brand: 'eBay',
    category: 'Commerce',
    officialDomains: ['ebay.com', 'ebay.co.uk'],
    tokens: ['ebay-secure', 'ebay-verify'],
    contentKeywords: ['ebay account', 'ebay resolution'],
  },
  {
    brand: 'Shopify',
    category: 'Commerce',
    officialDomains: ['shopify.com', 'myshopify.com'],
    tokens: ['shopify-support', 'shopify-verify'],
    contentKeywords: ['shopify admin', 'shopify store verification'],
  },
  {
    brand: 'Netflix',
    category: 'Commerce',
    officialDomains: ['netflix.com'],
    tokens: ['netflix', 'netfiix', 'netf1ix'],
    contentKeywords: ['netflix', 'netflix membership', 'restart your membership'],
  },
  {
    brand: 'Spotify',
    category: 'Commerce',
    officialDomains: ['spotify.com'],
    tokens: ['spotify', 'sp0tify'],
    contentKeywords: ['spotify', 'spotify premium'],
  },
  {
    brand: 'Steam',
    category: 'Gaming',
    officialDomains: ['steampowered.com', 'steamcommunity.com'],
    tokens: ['steampowered', 'steamcommunity', 'stearn'],
    contentKeywords: ['steam guard', 'steam community', 'steam account'],
  },
  {
    brand: 'Roblox',
    category: 'Gaming',
    officialDomains: ['roblox.com'],
    tokens: ['roblox', 'r0blox', 'robux-free'],
    contentKeywords: ['roblox account', 'free robux'],
  },
  {
    brand: 'Epic Games',
    category: 'Gaming',
    officialDomains: ['epicgames.com'],
    tokens: ['epicgames', 'epic-games-gift'],
    contentKeywords: ['epic games account', 'fortnite vbucks'],
  },
  {
    brand: 'PlayStation',
    category: 'Gaming',
    officialDomains: ['playstation.com', 'sonyentertainmentnetwork.com'],
    tokens: ['playstation', 'psn-login'],
    contentKeywords: ['playstation network', 'psn sign in'],
  },
  {
    brand: 'Stripe',
    category: 'Finance',
    officialDomains: ['stripe.com'],
    tokens: ['stripe'],
    contentKeywords: ['stripe dashboard', 'stripe payout'],
  },
  {
    brand: 'Visa / Mastercard',
    category: 'Finance',
    officialDomains: ['visa.com', 'mastercard.com'],
    tokens: ['visa-verify', 'mastercard-secure'],
    contentKeywords: ['verified by visa', 'mastercard securecode'],
  },
  {
    brand: 'Binance',
    category: 'Crypto',
    officialDomains: ['binance.com', 'binance.us'],
    tokens: ['binance', 'binnance'],
    contentKeywords: ['binance', 'binance wallet'],
  },
  {
    brand: 'Coinbase',
    category: 'Crypto',
    officialDomains: ['coinbase.com'],
    tokens: ['coinbase', 'c0inbase'],
    contentKeywords: ['coinbase wallet', 'coinbase account'],
  },
  {
    brand: 'MetaMask',
    category: 'Crypto',
    officialDomains: ['metamask.io'],
    tokens: ['metamask', 'metarnask'],
    contentKeywords: ['metamask', 'secret recovery phrase'],
  },
  {
    brand: 'Ledger / Trust Wallet',
    category: 'Crypto',
    officialDomains: ['ledger.com', 'trustwallet.com'],
    tokens: ['ledgerlive', 'ledger-sync', 'trustwallet', 'trust-wallet'],
    contentKeywords: ['ledger live', 'trust wallet', 'recovery seed'],
  },
  {
    brand: 'DHL',
    category: 'Logistics',
    officialDomains: ['dhl.com'],
    tokens: ['dhl', 'dhl-express', 'dhl-parcel'],
    contentKeywords: ['dhl express', 'dhl tracking', 'dhl delivery'],
  },
  {
    brand: 'FedEx',
    category: 'Logistics',
    officialDomains: ['fedex.com'],
    tokens: ['fedex'],
    contentKeywords: ['fedex tracking', 'fedex delivery'],
  },
  {
    brand: 'UPS',
    category: 'Logistics',
    officialDomains: ['ups.com'],
    tokens: ['ups-delivery', 'ups-tracking'],
    contentKeywords: ['ups tracking', 'ups delivery'],
  },
  {
    brand: 'Aramex',
    category: 'Logistics',
    officialDomains: ['aramex.com'],
    tokens: ['aramex'],
    contentKeywords: ['aramex tracking', 'aramex shipment'],
  },
  {
    brand: 'Al Rajhi Bank',
    category: 'Finance',
    officialDomains: ['alrajhibank.com.sa'],
    tokens: ['alrajhi', 'alrajhibank'],
    contentKeywords: ['al rajhi', 'alrajhi bank', 'مصرف الراجحي', 'الراجحي'],
  },
  {
    brand: 'SNB / AlAhli',
    category: 'Finance',
    officialDomains: ['alahli.com'],
    tokens: ['alahli', 'snb-alahli'],
    contentKeywords: ['saudi national bank', 'البنك الأهلي السعودي'],
  },
  {
    brand: 'STC / stc pay',
    category: 'Telecom',
    officialDomains: ['stc.com.sa', 'stcpay.com.sa'],
    tokens: ['stcpay', 'mystc'],
    contentKeywords: ['stc pay', 'mystc', 'اس تي سي باي'],
  },
  {
    brand: 'National Bank of Egypt / CIB',
    category: 'Finance',
    officialDomains: ['nbe.com.eg', 'cibeg.com'],
    tokens: ['nbe-egypt', 'alahlynet', 'cib-egypt'],
    contentKeywords: ['national bank of egypt', 'البنك الأهلي المصري', 'البنك التجاري الدولي'],
  },
  {
    brand: 'Vodafone / Orange / Etisalat',
    category: 'Telecom',
    officialDomains: ['vodafone.com', 'vodafone.com.eg', 'orange.eg', 'etisalat.ae', 'eand.com'],
    tokens: ['vodafone-cash', 'vodaf0ne', 'etisalat-bill'],
    contentKeywords: ['vodafone cash', 'فودافون كاش', 'etisalat'],
  },
  {
    brand: 'Government e-Services (Absher / IRS / GOV.UK)',
    category: 'Government',
    officialDomains: ['absher.sa', 'my.gov.sa', 'irs.gov', 'gov.uk', 'digital.gov.eg'],
    tokens: ['absher-verify', 'gov-tax-refund', 'irs-refund'],
    contentKeywords: ['absher login', 'منصة أبشر', 'tax refund claim', 'gov.uk verify'],
  },
  {
    brand: 'Cloudflare',
    category: 'Developer',
    officialDomains: ['cloudflare.com'],
    tokens: ['cloudflare', 'c1oudflare'],
    contentKeywords: ['verify you are human', 'cloudflare ray id'],
  },
  {
    brand: 'Telegram',
    category: 'Social',
    officialDomains: ['telegram.org', 't.me', 'telegram.me'],
    tokens: ['telegram', 'te1egram', 'telegram-verify'],
    contentKeywords: ['telegram web', 'telegram login', 'confirm telegram'],
  },
  {
    brand: 'OpenAI / ChatGPT',
    category: 'Tech',
    officialDomains: ['openai.com', 'chatgpt.com'],
    tokens: ['openai', 'chatgpt', '0penai'],
    contentKeywords: ['openai account', 'chatgpt login', 'chatgpt plus'],
  },
  {
    brand: 'Anthropic / Claude',
    category: 'Tech',
    officialDomains: ['anthropic.com', 'claude.ai'],
    tokens: ['anthropic', 'claude-ai'],
    contentKeywords: ['claude login', 'anthropic console'],
  },
  {
    brand: 'TikTok',
    category: 'Social',
    officialDomains: ['tiktok.com'],
    tokens: ['tiktok', 'tikt0k'],
    contentKeywords: ['tiktok creator', 'tiktok verification'],
  },
  {
    brand: 'Snapchat',
    category: 'Social',
    officialDomains: ['snapchat.com', 'snap.com'],
    tokens: ['snapchat', 'snap-login'],
    contentKeywords: ['snapchat login', 'snapchat support'],
  },
  {
    brand: 'Adobe / DocuSign',
    category: 'Tech',
    officialDomains: ['adobe.com', 'docusign.com', 'docusign.net'],
    tokens: ['adobesign', 'docusign', 'adobe-pdf'],
    contentKeywords: ['adobe document cloud', 'docusign envelope', 'review document'],
  },
  {
    brand: 'Dropbox',
    category: 'Tech',
    officialDomains: ['dropbox.com'],
    tokens: ['dropbox', 'dr0pbox'],
    contentKeywords: ['dropbox shared file', 'sign in to dropbox'],
  },
  {
    brand: 'Riyad Bank / Alinma Bank',
    category: 'Finance',
    officialDomains: ['riyadbank.com', 'alinma.com', 'bankalbilad.com', 'sab.com'],
    tokens: ['riyadbank', 'alinma', 'bankalbilad'],
    contentKeywords: ['riyad bank', 'alinma bank', 'بنك الرياض', 'مصرف الإنماء'],
  },
  {
    brand: 'Emirates NBD / FAB / QNB',
    category: 'Finance',
    officialDomains: ['emiratesnbd.com', 'bankfab.com', 'adcb.com', 'qnb.com', 'nbk.com'],
    tokens: ['emiratesnbd', 'bankfab'],
    contentKeywords: ['emirates nbd', 'first abu dhabi bank', 'qatar national bank'],
  },
  {
    brand: 'Banque Misr / InstaPay / Fawry',
    category: 'Finance',
    officialDomains: ['banquemisr.com', 'instapay.eg', 'fawry.com'],
    tokens: ['banquemisr', 'instapay'],
    contentKeywords: ['banque misr', 'بنك مصر', 'انستاباي', 'فوري'],
  },
  {
    brand: 'Nafath / ZATCA / Saudi Post (SPL)',
    category: 'Government',
    officialDomains: ['nafath.sa', 'zatca.gov.sa', 'splonline.com.sa', 'qiwa.sa'],
    tokens: ['nafath-verify', 'zatca-tax', 'smsaexpress'],
    contentKeywords: ['نفاذ الوطني', 'هيئة الزكاة', 'البريد السعودي', 'سمسا'],
  },
  {
    brand: 'SAUDIA / Emirates Airlines',
    category: 'Commerce',
    officialDomains: ['saudia.com', 'emirates.com', 'qatarairways.com', 'booking.com', 'airbnb.com'],
    tokens: ['saudia', 'emirates-miles', 'booking-verify'],
    contentKeywords: ['booking confirmation', 'alfursan miles', 'skywards miles'],
  },
];

import { classifyDomainRelationship, lookupDomainOwnership } from './officialDomainRegistry.ts';
import { detectPaasHosting } from './urlIntelligence.ts';

function getTenantHostnameScope(fullHost: string, registrableDomain: string): {
  isPaas: boolean;
  tenantPrefix: string;
  effectiveDomainLabel: string;
} {
  const hostLower = fullHost.toLowerCase();
  const paas = detectPaasHosting(hostLower);
  if (paas.isPaas && paas.suffix) {
    const suffixWithDot = `.${paas.suffix}`;
    const tenantPrefix = hostLower.endsWith(suffixWithDot)
      ? hostLower.slice(0, -suffixWithDot.length)
      : '';
    const tenantLabel = tenantPrefix.split('.').pop() || '';
    return {
      isPaas: true,
      tenantPrefix,
      effectiveDomainLabel: tenantLabel,
    };
  }
  const regLower = registrableDomain.toLowerCase();
  return {
    isPaas: false,
    tenantPrefix: hostLower,
    effectiveDomainLabel: regLower.split('.')[0] || '',
  };
}

export function normalizeLeetHomoglyphs(input: string): string {
  return input
    .toLowerCase()
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/7/g, 't')
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/cl/g, 'd');
}

export function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
  }
  return dp[m][n];
}

export interface BrandImpersonationMatch {
  brand: string;
  officialDomain: string;
  confidence: number;
  evidence: string[];
  similarityOnly?: boolean;
}

export interface CompoundBrandLookalikeMatch {
  brand: string;
  officialDomain: string;
  similarityType: 'compound_brand_name' | 'leetspeak_lookalike';
  matchedToken: string;
  evidence: string;
}

/**
 * Checks whether an unverified domain's registrable label embeds or leetspeak-mimics
 * a protected brand name (e.g., google-login-example.com, g00gle-example.com,
 * facebook-security-example.com, github-login-example.com).
 * Never triggers on verified official domains or subdomains.
 */
export function detectCompoundBrandLookalike(
  fullHost: string,
  registrableDomain: string
): CompoundBrandLookalikeMatch | undefined {
  const ownership = lookupDomainOwnership(fullHost);
  if (ownership.matched) {
    return undefined;
  }

  const scope = getTenantHostnameScope(fullHost, registrableDomain);
  const domainLabel = scope.effectiveDomainLabel;
  if (domainLabel.length < 4) return undefined;

  const segments = domainLabel.split('-').filter(Boolean);
  const leetLabel = normalizeLeetHomoglyphs(domainLabel);
  const leetSegments = leetLabel.split('-').filter(Boolean);

  for (const sig of BRAND_INTELLIGENCE_DB) {
    if (sig.officialDomains.some((off) => classifyDomainRelationship(fullHost, off).isSameOrganization)) {
      continue;
    }

    const genericServiceLabels = new Set(['accounts', 'workspace', 'login', 'mail', 'auth', 'secure', 'portal', 'support', 'signin', 'account', 'verify', 'update', 'live']);
    const candidateCoreNames = Array.from(
      new Set([
        ...sig.officialDomains
          .filter((d) => d.split('.').length <= 2 || !genericServiceLabels.has(d.split('.')[0]))
          .map((d) => d.split('.')[0])
          .filter((l) => l.length >= 4 && !genericServiceLabels.has(l)),
        ...sig.tokens.filter((t) => t.length >= 4 && !t.includes('-') && !genericServiceLabels.has(t)),
      ])
    );

    for (const core of candidateCoreNames) {
      if (domainLabel === core) continue; // handled elsewhere if different TLD

      // Segment or compound prefix/suffix match (e.g., google-login-example, facebook-security-example, github-login-example)
      const exactSegMatch = segments.includes(core);
      const compoundMatch =
        domainLabel.includes('-') &&
        (domainLabel.startsWith(`${core}-`) ||
          domainLabel.includes(`-${core}-`) ||
          domainLabel.endsWith(`-${core}`));

      if (exactSegMatch || compoundMatch) {
        return {
          brand: sig.brand,
          officialDomain: sig.officialDomains[0],
          similarityType: 'compound_brand_name',
          matchedToken: core,
          evidence: `Registrable label "${domainLabel}" embeds brand name "${core}" outside official "${sig.officialDomains[0]}"`,
        };
      }

      // Leetspeak compound or full-label match (e.g., g00gle-example.com -> google-example)
      const leetExactSegMatch = leetSegments.includes(core);
      const leetCompoundMatch =
        leetLabel.includes('-') &&
        (leetLabel.startsWith(`${core}-`) ||
          leetLabel.includes(`-${core}-`) ||
          leetLabel.endsWith(`-${core}`));

      if (leetExactSegMatch || leetCompoundMatch || (leetLabel === core && domainLabel !== core)) {
        return {
          brand: sig.brand,
          officialDomain: sig.officialDomains[0],
          similarityType: 'leetspeak_lookalike',
          matchedToken: core,
          evidence: `Registrable label "${domainLabel}" visually maps via character substitution to "${core}" (${sig.officialDomains[0]})`,
        };
      }
    }
  }

  return undefined;
}

function hasWordBoundaryToken(haystack: string, token: string): boolean {
  const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(?:^|[^a-z0-9])${escaped}(?:$|[^a-z0-9])`, 'i').test(haystack);
}

export function detectBrandImpersonation(params: {
  fullHost: string;
  registrableDomain: string;
  pageTitle: string;
  visibleTextSample: string;
  hasCredentialFields: boolean;
  ogSiteName?: string;
}): BrandImpersonationMatch | undefined {
  const hostLower = params.fullHost.toLowerCase();
  const regLower = params.registrableDomain.toLowerCase();
  const ownership = lookupDomainOwnership(hostLower);
  if (ownership.matched) {
    return undefined;
  }

  const scope = getTenantHostnameScope(hostLower, regLower);
  const domainLabel = scope.effectiveDomainLabel;
  const normalizedLabel = normalizeLeetHomoglyphs(domainLabel);
  const titleLower = params.pageTitle.toLowerCase();
  const ogSiteLower = (params.ogSiteName || '').toLowerCase();

  for (const sig of BRAND_INTELLIGENCE_DB) {
    // Never flag related parent/product domains or official domains
    const isRelatedOrOfficial = sig.officialDomains.some(
      (official) => classifyDomainRelationship(hostLower, official).isSameOrganization
    );
    if (isRelatedOrOfficial) continue;

    const evidence: string[] = [];
    let hasDomainSignal = false;
    let hasIdentityClaim = false;

    // 1. Subdomain / hostname token trick (word-boundary safe; excludes shared PaaS hosting suffix like github.io)
    const tokenScope = scope.isPaas ? scope.tenantPrefix : hostLower;
    if (tokenScope) {
      for (const tok of sig.tokens) {
        if (tok.length >= 4 && hasWordBoundaryToken(tokenScope, tok)) {
          hasDomainSignal = true;
          evidence.push(
            `Hostname "${tokenScope}" embeds brand token "${tok}" outside official domain ${sig.officialDomains[0]}`
          );
        }
      }
    }

    // 2. Typosquatting / homoglyph similarity on registrable domain label (or tenant subdomain on PaaS)
    for (const official of sig.officialDomains) {
      const offLabel = official.split('.')[0];
      if (offLabel.length >= 4 && domainLabel.length >= 4) {
        const distRaw = levenshtein(domainLabel, offLabel);
        const distNorm = levenshtein(normalizedLabel, offLabel);
        const maxDist = offLabel.length >= 5 ? 2 : 1;
        if (distRaw > 0 && distRaw <= maxDist) {
          hasDomainSignal = true;
          evidence.push(`Domain spelling "${domainLabel}" has edit distance ${distRaw} from official "${offLabel}"`);
        } else if (distNorm <= 1 && normalizedLabel !== domainLabel) {
          hasDomainSignal = true;
          evidence.push(`Domain "${domainLabel}" uses visual character substitution resembling "${offLabel}"`);
        }
      }
    }

    // 2b. Compound brand lookalike (e.g., google-login-example, g00gle-example)
    const compoundHit = detectCompoundBrandLookalike(hostLower, regLower);
    if (compoundHit && compoundHit.brand === sig.brand) {
      hasDomainSignal = true;
      evidence.push(compoundHit.evidence);
    }

    // 3. Explicit identity claim in <title> or og:site_name
    // Note: visible body text mentioning "Sign in with Google" or "Follow us on Instagram"
    // on an unrelated site with a login form is a standard OAuth/social link, NOT impersonation.
    for (const kw of sig.contentKeywords) {
      if (titleLower.includes(kw) || ogSiteLower.includes(kw)) {
        hasIdentityClaim = true;
        evidence.push(`Page <title>/site identity explicitly claims "${kw}"`);
      }
    }

    const uniqueEvidence = Array.from(new Set(evidence));
    if (hasDomainSignal && (hasIdentityClaim || params.hasCredentialFields)) {
      const confidence = Math.min(96, 55 + uniqueEvidence.length * 14 + (params.hasCredentialFields ? 14 : 0));
      return {
        brand: sig.brand,
        officialDomain: sig.officialDomains[0],
        confidence,
        evidence: uniqueEvidence,
        similarityOnly: false,
      };
    }

    // Domain similarity alone without phishing/title/credential impersonation proof -> non-accusatory similarity flag
    if (hasDomainSignal && !hasIdentityClaim && !params.hasCredentialFields) {
      return {
        brand: sig.brand,
        officialDomain: sig.officialDomains[0],
        confidence: 65,
        evidence: uniqueEvidence,
        similarityOnly: true,
      };
    }
  }

  return undefined;
}

