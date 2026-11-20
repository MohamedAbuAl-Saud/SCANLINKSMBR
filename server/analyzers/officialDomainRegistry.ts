import net from 'node:net';
import { domainToASCII } from 'node:url';
import { parse as parseTldts } from 'tldts';
import type { BilingualText, DomainHostingMetadata } from '../types.ts';

export type DomainAuthenticityStatus =
  | 'official_verified'
  | 'official_subdomain'
  | 'authorized_third_party'
  | 'partner_or_provider'
  | 'brand_lookalike'
  | 'unknown_unverified';

export type DomainRelationshipType =
  | 'same_domain'
  | 'official_subdomain'
  | 'parent_company'
  | 'official_product'
  | 'authorized_third_party_provider'
  | 'external_integration'
  | 'unverified_relationship';

export type EntityCategory =
  | 'Tech'
  | 'Social'
  | 'Commerce'
  | 'Finance'
  | 'Logistics'
  | 'Crypto'
  | 'Telecom'
  | 'Developer'
  | 'Gaming'
  | 'Government'
  | 'AI'
  | 'Security'
  | 'Media'
  | 'Education'
  | 'Travel';

export interface OfficialEntityDefinition {
  orgId: string;
  parentCompany: string;
  category: EntityCategory;
  /** Exact registrable corporate/product eTLD+1 domains (or explicit corporate hostnames) owned by this organization. */
  officialDomains: string[];
  /** Product labels per official domain. */
  productMap: Record<string, string>;
  /** Multi-tenant user-content platforms owned by the org (NOT official corporate portals on subdomains). */
  userContentPaasDomains?: string[];
  /** Brand tokens used to detect lookalikes/compounds outside official domains. */
  brandTokens: string[];
  /** Official documentation or published domain-ownership references. */
  registrySources: string[];
  /** Expected RDAP/WHOIS registrant/registrar/nameserver patterns for live corroboration. */
  expectedRdapHints: string[];
  /** Expected ASN numbers or network names for live corroboration. */
  expectedAsnHints: string[];
}

export interface AuthorizedProviderDefinition {
  providerId: string;
  name: string;
  role: 'cdn' | 'dns' | 'auth_sso' | 'analytics' | 'fonts_assets' | 'payments' | 'security';
  domains: string[];
}

export const GENERAL_USER_CONTENT_PAAS_DOMAINS: string[] = [
  'vercel.app',
  'netlify.app',
  'herokuapp.com',
  'up.railway.app',
  'railway.app',
  'onrender.com',
  'fly.dev',
  'hf.space',
  'gitlab.io',
  'bitbucket.io',
  'weebly.com',
  'wixsite.com',
  'wordpress.com',
  '000webhostapp.com',
  'ngrok-free.app',
  'ngrok.io',
  'notion.site',
  'webflow.io',
  'framer.website',
  'carrd.co',
  'glitch.me',
  'replit.dev',
  'repl.co',
  'supabase.co',
];

export const OFFICIAL_ENTITIES: OfficialEntityDefinition[] = [
  // =========================================================================
  // 1. BIG TECH & CLOUD ECOSYSTEMS
  // =========================================================================
  {
    orgId: 'google',
    parentCompany: 'Google LLC (Alphabet Inc.)',
    category: 'Tech',
    officialDomains: [
      'google.com',
      'google.co.uk',
      'google.de',
      'google.fr',
      'google.es',
      'google.it',
      'google.nl',
      'google.pl',
      'google.se',
      'google.sa',
      'google.ae',
      'google.com.eg',
      'google.com.sa',
      'google.iq',
      'google.jo',
      'google.com.kw',
      'google.com.qa',
      'google.com.bh',
      'google.com.om',
      'google.com.lb',
      'google.dz',
      'google.ma',
      'google.tn',
      'google.ca',
      'google.co.jp',
      'google.co.in',
      'google.com.au',
      'google.com.br',
      'google.com.mx',
      'google.com.tr',
      'google.ru',
      'youtube.com',
      'youtu.be',
      'youtube-nocookie.com',
      'ytimg.com',
      'googlevideo.com',
      'gmail.com',
      'gstatic.com',
      'googleapis.com',
      'googleusercontent.com',
      'googleblog.com',
      'android.com',
      'chromium.org',
      'g.co',
      'goo.gl',
      'withgoogle.com',
      'abc.xyz',
      'waymo.com',
      'waze.com',
      'fitbit.com',
      'deepmind.google',
      'gemini.google.com',
      'ai.google.dev',
      'developers.google.com',
      'firebase.google.com',
      'cloud.google.com',
      'accounts.google.com',
      'workspace.google.com',
      'docs.google.com',
      'drive.google.com',
      'play.google.com',
      'maps.google.com',
      'translate.google.com',
      'scholar.google.com',
      'chromewebstore.google.com',
      'kaggle.com',
      'go.dev',
      'golang.org',
      'tensorflow.org',
      'flutter.dev',
      'dart.dev',
      'opensource.google',
      'domains.google',
    ],
    productMap: {
      'google.com': 'Google',
      'accounts.google.com': 'Google Accounts',
      'cloud.google.com': 'Google Cloud',
      'workspace.google.com': 'Google Workspace',
      'firebase.google.com': 'Firebase Console',
      'gemini.google.com': 'Google Gemini',
      'ai.google.dev': 'Google AI for Developers',
      'deepmind.google': 'Google DeepMind',
      'youtube.com': 'YouTube',
      'youtu.be': 'YouTube Shortlinks',
      'gmail.com': 'Gmail',
      'gstatic.com': 'Google Static Assets',
      'googleapis.com': 'Google APIs',
      'googleusercontent.com': 'Google User Content',
      'android.com': 'Android',
      'g.co': 'Google Official Shortener',
      'abc.xyz': 'Alphabet Inc.',
      'kaggle.com': 'Kaggle (Google)',
      'flutter.dev': 'Flutter (Google)',
      'go.dev': 'Go Language (Google)',
    },
    userContentPaasDomains: ['appspot.com', 'firebaseapp.com', 'web.app', 'blogspot.com', 'sites.google.com'],
    brandTokens: ['google', 'gmail', 'youtube', 'googledrive', 'googleaccount', 'g00gle', 'y0utube'],
    registrySources: ['Google Registry & ASN AS15169 Documentation', 'IANA RDAP (MarkMonitor / Google LLC)'],
    expectedRdapHints: ['google', 'markmonitor', 'ns1.google.com', 'ns2.google.com', 'ns3.google.com', 'ns4.google.com'],
    expectedAsnHints: ['as15169', 'as36040', 'as396982', 'google'],
  },
  {
    orgId: 'meta',
    parentCompany: 'Meta Platforms, Inc.',
    category: 'Social',
    officialDomains: [
      'meta.com',
      'facebook.com',
      'fb.com',
      'fb.me',
      'fbcdn.net',
      'fbsbx.com',
      'messenger.com',
      'm.me',
      'instagram.com',
      'cdninstagram.com',
      'ig.me',
      'whatsapp.com',
      'whatsapp.net',
      'wa.me',
      'threads.net',
      'threads.com',
      'oculus.com',
      'workplace.com',
      'atlassolutions.com',
      'react.dev',
      'opensource.fb.com',
      'llama.com',
    ],
    productMap: {
      'meta.com': 'Meta Platforms',
      'facebook.com': 'Facebook',
      'fb.com': 'Facebook',
      'fb.me': 'Facebook Shortlinks',
      'fbcdn.net': 'Meta / Facebook CDN',
      'messenger.com': 'Messenger',
      'm.me': 'Messenger Links',
      'instagram.com': 'Instagram',
      'cdninstagram.com': 'Instagram CDN',
      'whatsapp.com': 'WhatsApp',
      'whatsapp.net': 'WhatsApp Infrastructure',
      'wa.me': 'WhatsApp Links',
      'threads.net': 'Threads',
      'threads.com': 'Threads',
      'react.dev': 'React (Meta Open Source)',
      'llama.com': 'Meta Llama',
    },
    brandTokens: [
      'facebook',
      'faceb00k',
      'instagram',
      'instagrarn',
      'whatsapp',
      'whatsap',
      'messenger',
      'meta-security',
      'fb-verify',
      'ig-verify',
    ],
    registrySources: ['Meta Platforms Corporate Domain Registry', 'IANA RDAP (RegistrarSafe, LLC / Meta Platforms)'],
    expectedRdapHints: [
      'meta platforms',
      'facebook',
      'instagram',
      'whatsapp',
      'registrarsafe',
      'a.ns.facebook.com',
      'b.ns.facebook.com',
      'c.ns.facebook.com',
      'd.ns.facebook.com',
    ],
    expectedAsnHints: ['as32934', 'facebook', 'meta'],
  },
  {
    orgId: 'microsoft',
    parentCompany: 'Microsoft Corporation',
    category: 'Tech',
    officialDomains: [
      'microsoft.com',
      'microsoftonline.com',
      'live.com',
      'outlook.com',
      'hotmail.com',
      'office.com',
      'office365.com',
      'azure.com',
      'azureedge.net',
      'msn.com',
      'bing.com',
      'xbox.com',
      'xboxlive.com',
      'skype.com',
      'aka.ms',
      'msft.net',
      'msecnd.net',
      'visualstudio.com',
      'code.visualstudio.com',
      'dev.azure.com',
      'copilot.microsoft.com',
      'teams.microsoft.com',
      'dotnet.microsoft.com',
      'powerbi.com',
      'dynamics.com',
      'typescriptlang.org',
      'github.com',
      'github.blog',
      'github.dev',
      'github.community',
      'githubassets.com',
      'githubusercontent.com',
      'ghcr.io',
      'npm.im',
      'npmjs.com',
      'npmjs.org',
      'nuget.org',
      'linkedin.com',
      'licdn.com',
      'lnkd.in',
      'windows.com',
      'windowsupdate.com',
    ],
    productMap: {
      'microsoft.com': 'Microsoft',
      'microsoftonline.com': 'Microsoft Entra / Identity',
      'live.com': 'Microsoft Account / Live',
      'outlook.com': 'Outlook',
      'hotmail.com': 'Outlook / Hotmail',
      'office.com': 'Microsoft 365 / Office',
      'azure.com': 'Microsoft Azure',
      'bing.com': 'Bing',
      'xbox.com': 'Xbox',
      'aka.ms': 'Microsoft Official Shortener',
      'github.com': 'GitHub (Microsoft Subsidiary)',
      'github.blog': 'GitHub Blog',
      'githubassets.com': 'GitHub Static Assets',
      'githubusercontent.com': 'GitHub Raw Content',
      'npmjs.com': 'npm Registry (GitHub)',
      'linkedin.com': 'LinkedIn (Microsoft Subsidiary)',
      'licdn.com': 'LinkedIn CDN',
      'lnkd.in': 'LinkedIn Shortlinks',
      'typescriptlang.org': 'TypeScript (Microsoft)',
    },
    userContentPaasDomains: ['github.io', 'azurewebsites.net', 'blob.core.windows.net'],
    brandTokens: [
      'microsoft',
      'micros0ft',
      'office365',
      'outlook',
      'onedrive',
      'sharepoint',
      'github',
      'githuh',
      'linkedin',
      '1inkedin',
    ],
    registrySources: [
      'Microsoft Corporate Domain & Entra Identity Documentation',
      'GitHub Official Meta API / Domains Documentation',
      'IANA RDAP (MarkMonitor / CSC Corporate Domains)',
    ],
    expectedRdapHints: ['microsoft', 'github', 'linkedin', 'markmonitor', 'csc corporate', 'azure-dns', 'nsone.net', 'awsdns', 'ultradns', 'dynect'],
    expectedAsnHints: ['as8075', 'as8068', 'as36459', 'as14413', 'microsoft', 'github', 'linkedin', 'fastly', 'akamai', 'azure'],
  },
  {
    orgId: 'apple',
    parentCompany: 'Apple Inc.',
    category: 'Tech',
    officialDomains: [
      'apple.com',
      'icloud.com',
      'me.com',
      'mac.com',
      'apple.co',
      'cdn-apple.com',
      'mzstatic.com',
      'itunes.com',
      'apple.news',
      'swift.org',
      'webkit.org',
      'developer.apple.com',
      'appleid.apple.com',
      'support.apple.com',
      'apps.apple.com',
      'music.apple.com',
      'tv.apple.com',
    ],
    productMap: {
      'apple.com': 'Apple',
      'icloud.com': 'iCloud',
      'me.com': 'Apple Mail',
      'apple.co': 'Apple Shortlinks',
      'cdn-apple.com': 'Apple CDN',
      'mzstatic.com': 'Apple Media Static',
      'swift.org': 'Swift Programming Language',
    },
    brandTokens: ['appleid', 'icloud', 'apple-support', 'itunes', 'app1e', 'apple'],
    registrySources: ['Apple Inc. Official Domains & PKI Policy', 'IANA RDAP (CSC Corporate Domains / Apple Inc.)'],
    expectedRdapHints: ['apple inc', 'csc corporate', 'a.ns.apple.com', 'b.ns.apple.com', 'c.ns.apple.com', 'd.ns.apple.com'],
    expectedAsnHints: ['as714', 'as6185', 'apple', 'akamai'],
  },
  {
    orgId: 'amazon',
    parentCompany: 'Amazon.com, Inc.',
    category: 'Commerce',
    officialDomains: [
      'amazon.com',
      'amazon.co.uk',
      'amazon.de',
      'amazon.fr',
      'amazon.es',
      'amazon.it',
      'amazon.nl',
      'amazon.ae',
      'amazon.sa',
      'amazon.eg',
      'amazon.ca',
      'amazon.co.jp',
      'amazon.in',
      'amazon.com.au',
      'amazon.com.br',
      'amazon.com.tr',
      'amazon.sg',
      'aboutamazon.com',
      'media-amazon.com',
      'ssl-images-amazon.com',
      'images-amazon.com',
      'a.co',
      'amzn.to',
      'amzn.eu',
      'amzn.asia',
      'aws.amazon.com',
      'console.aws.amazon.com',
      'signin.aws.amazon.com',
      'docs.aws.amazon.com',
      'primevideo.com',
      'audible.com',
      'twitch.tv',
      'ttvnw.net',
      'jtvnw.net',
      'imdb.com',
      'goodreads.com',
      'zappos.com',
      'wholefoodsmarket.com',
    ],
    productMap: {
      'amazon.com': 'Amazon Storefront',
      'aws.amazon.com': 'Amazon Web Services',
      'primevideo.com': 'Amazon Prime Video',
      'twitch.tv': 'Twitch (Amazon)',
      'audible.com': 'Audible (Amazon)',
      'imdb.com': 'IMDb (Amazon)',
      'a.co': 'Amazon Shortlinks',
      'amzn.to': 'Amazon Shortlinks',
    },
    userContentPaasDomains: ['s3.amazonaws.com', 'cloudfront.net'],
    brandTokens: ['amazon', 'arnazon', 'aws-login', 'primevideo'],
    registrySources: ['Amazon Corporate Domain & AWS IP Range Registry', 'IANA RDAP (MarkMonitor / Amazon Technologies)'],
    expectedRdapHints: ['amazon', 'markmonitor', 'awsdns'],
    expectedAsnHints: ['as16509', 'as14618', 'amazon'],
  },

  // =========================================================================
  // 2. AI LABS & FOUNDATION MODEL PLATFORMS
  // =========================================================================
  {
    orgId: 'openai',
    parentCompany: 'OpenAI, Inc.',
    category: 'AI',
    officialDomains: ['openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com', 'sora.com'],
    productMap: {
      'openai.com': 'OpenAI',
      'chatgpt.com': 'ChatGPT (OpenAI)',
      'sora.com': 'Sora (OpenAI)',
    },
    brandTokens: ['openai', 'chatgpt', '0penai'],
    registrySources: ['OpenAI Official Platform Documentation', 'IANA RDAP (MarkMonitor / Cloudflare)'],
    expectedRdapHints: ['openai', 'markmonitor', 'cloudflare'],
    expectedAsnHints: ['cloudflare', 'microsoft', 'azure'],
  },
  {
    orgId: 'anthropic',
    parentCompany: 'Anthropic PBC',
    category: 'AI',
    officialDomains: ['anthropic.com', 'claude.ai', 'claude.com'],
    productMap: { 'anthropic.com': 'Anthropic', 'claude.ai': 'Claude (Anthropic)' },
    brandTokens: ['anthropic', 'claude'],
    registrySources: ['Anthropic Official Platform Registry', 'IANA RDAP'],
    expectedRdapHints: ['anthropic', 'cloudflare'],
    expectedAsnHints: ['cloudflare', 'google', 'amazon'],
  },
  {
    orgId: 'xai',
    parentCompany: 'xAI Corp.',
    category: 'AI',
    officialDomains: ['x.ai', 'grok.com'],
    productMap: { 'x.ai': 'xAI', 'grok.com': 'Grok (xAI)' },
    brandTokens: ['grok-ai'],
    registrySources: ['xAI Official Documentation'],
    expectedRdapHints: ['xai', 'cloudflare'],
    expectedAsnHints: ['cloudflare'],
  },
  {
    orgId: 'huggingface',
    parentCompany: 'Hugging Face, Inc.',
    category: 'AI',
    officialDomains: ['huggingface.co', 'hf.co'],
    productMap: { 'huggingface.co': 'Hugging Face', 'hf.co': 'Hugging Face Shortlinks' },
    userContentPaasDomains: ['hf.space'],
    brandTokens: ['huggingface'],
    registrySources: ['Hugging Face Official Domain Documentation'],
    expectedRdapHints: ['huggingface', 'awsdns'],
    expectedAsnHints: ['amazon', 'cloudflare'],
  },
  {
    orgId: 'mistral_perplexity_cohere',
    parentCompany: 'Mistral AI / Perplexity AI / Cohere',
    category: 'AI',
    officialDomains: ['mistral.ai', 'perplexity.ai', 'pplx.ai', 'cohere.com', 'cohere.ai', 'midjourney.com', 'stability.ai'],
    productMap: {
      'mistral.ai': 'Mistral AI',
      'perplexity.ai': 'Perplexity AI',
      'cohere.com': 'Cohere',
      'midjourney.com': 'Midjourney',
      'stability.ai': 'Stability AI',
    },
    brandTokens: ['mistral', 'perplexity', 'midjourney'],
    registrySources: ['Verified AI Platform Registries'],
    expectedRdapHints: ['cloudflare', 'awsdns', 'gandi'],
    expectedAsnHints: ['cloudflare', 'amazon'],
  },
  {
    orgId: 'nvidia',
    parentCompany: 'NVIDIA Corporation',
    category: 'Tech',
    officialDomains: ['nvidia.com', 'geforce.com', 'nvidia.custhelp.com'],
    productMap: { 'nvidia.com': 'NVIDIA', 'geforce.com': 'GeForce (NVIDIA)' },
    brandTokens: ['nvidia', 'geforce'],
    registrySources: ['NVIDIA Corporate Domain Registry', 'IANA RDAP'],
    expectedRdapHints: ['nvidia', 'csc corporate'],
    expectedAsnHints: ['as20026', 'akamai', 'amazon'],
  },

  // =========================================================================
  // 3. DEVELOPER PLATFORMS, CLOUD INFRASTRUCTURE & OPEN ECOSYSTEMS
  // =========================================================================
  {
    orgId: 'cloudflare',
    parentCompany: 'Cloudflare, Inc.',
    category: 'Developer',
    officialDomains: [
      'cloudflare.com',
      'cloudflare.net',
      'cloudflare.tv',
      'cloudflarestatus.com',
      'cloudflareinsights.com',
      'cloudflareclient.com',
      'one.one.one.one',
      '1.1.1.1',
    ],
    productMap: {
      'cloudflare.com': 'Cloudflare',
      'cloudflarestatus.com': 'Cloudflare System Status',
      'cloudflareinsights.com': 'Cloudflare Web Analytics',
    },
    userContentPaasDomains: ['pages.dev', 'workers.dev', 'trycloudflare.com', 'r2.dev'],
    brandTokens: ['cloudflare', 'c1oudflare'],
    registrySources: ['Cloudflare Official IP & Domain Documentation', 'IANA RDAP (Cloudflare, Inc.)'],
    expectedRdapHints: ['cloudflare', 'ns3.cloudflare.com', 'ns4.cloudflare.com', 'ns5.cloudflare.com'],
    expectedAsnHints: ['as13335', 'cloudflare'],
  },
  {
    orgId: 'vercel',
    parentCompany: 'Vercel Inc.',
    category: 'Developer',
    officialDomains: ['vercel.com', 'vercel-dns.com', 'nextjs.org', 'turborepo.com', 'v0.dev'],
    productMap: { 'vercel.com': 'Vercel', 'nextjs.org': 'Next.js (Vercel)', 'v0.dev': 'v0 (Vercel)' },
    userContentPaasDomains: ['vercel.app'],
    brandTokens: ['vercel', 'nextjs'],
    registrySources: ['Vercel Official Documentation', 'IANA RDAP'],
    expectedRdapHints: ['vercel', 'zeit'],
    expectedAsnHints: ['cloudflare', 'amazon', 'vercel'],
  },
  {
    orgId: 'netlify_railway_digitalocean',
    parentCompany: 'Cloud Hosting & PaaS Vendors (Official Corporate Portals)',
    category: 'Developer',
    officialDomains: [
      'netlify.com',
      'railway.com',
      'railway.app',
      'render.com',
      'fly.io',
      'digitalocean.com',
      'linode.com',
      'vultr.com',
      'hetzner.com',
      'ovhcloud.com',
      'heroku.com',
      'supabase.com',
      'neon.tech',
      'planetscale.com',
      'upstash.com',
      'turso.tech',
    ],
    productMap: {
      'netlify.com': 'Netlify',
      'railway.com': 'Railway',
      'railway.app': 'Railway Platform',
      'render.com': 'Render',
      'fly.io': 'Fly.io',
      'digitalocean.com': 'DigitalOcean',
      'hetzner.com': 'Hetzner',
      'ovhcloud.com': 'OVHcloud',
      'heroku.com': 'Heroku (Salesforce)',
      'supabase.com': 'Supabase',
    },
    brandTokens: ['digitalocean', 'supabase', 'heroku'],
    registrySources: ['Cloud Vendor Official Registries'],
    expectedRdapHints: ['digitalocean', 'hetzner', 'ovh', 'cloudflare', 'awsdns', 'markmonitor'],
    expectedAsnHints: ['as14061', 'as24940', 'as16276', 'cloudflare', 'amazon'],
  },
  {
    orgId: 'gitlab',
    parentCompany: 'GitLab Inc.',
    category: 'Developer',
    officialDomains: ['gitlab.com', 'gitlab.net'],
    productMap: { 'gitlab.com': 'GitLab' },
    userContentPaasDomains: ['gitlab.io'],
    brandTokens: ['gitlab'],
    registrySources: ['GitLab Official Registry'],
    expectedRdapHints: ['gitlab', 'markmonitor', 'cloudflare'],
    expectedAsnHints: ['google', 'cloudflare'],
  },
  {
    orgId: 'atlassian',
    parentCompany: 'Atlassian Corporation',
    category: 'Developer',
    officialDomains: ['atlassian.com', 'bitbucket.org', 'trello.com', 'statuspage.io'],
    productMap: {
      'atlassian.com': 'Atlassian',
      'bitbucket.org': 'Bitbucket',
      'trello.com': 'Trello',
      'statuspage.io': 'Atlassian Statuspage',
    },
    brandTokens: ['atlassian', 'bitbucket', 'trello'],
    registrySources: ['Atlassian Official Domain Registry'],
    expectedRdapHints: ['atlassian', 'csc corporate'],
    expectedAsnHints: ['as396898', 'amazon', 'cloudflare'],
  },
  {
    orgId: 'docker_cncf_linux',
    parentCompany: 'Docker / CNCF / Linux Foundation / Open Source Foundations',
    category: 'Developer',
    officialDomains: [
      'docker.com',
      'docker.io',
      'kubernetes.io',
      'k8s.io',
      'linuxfoundation.org',
      'cncf.io',
      'kernel.org',
      'gnu.org',
      'apache.org',
      'eclipse.org',
      'python.org',
      'pypi.org',
      'pythonhosted.org',
      'rust-lang.org',
      'crates.io',
      'docs.rs',
      'nodejs.org',
      'expressjs.com',
      'vitejs.dev',
      'vuejs.org',
      'angular.dev',
      'svelte.dev',
      'tailwindcss.com',
      'php.net',
      'laravel.com',
      'ruby-lang.org',
      'rubygems.org',
      'cpan.org',
      'packagist.org',
      'ubuntu.com',
      'canonical.com',
      'debian.org',
      'fedoraproject.org',
      'redhat.com',
      'archlinux.org',
      'kalilinux.org',
      'kali.org',
      'mozilla.org',
      'firefox.com',
      'thunderbird.net',
      'w3.org',
      'ietf.org',
      'rfc-editor.org',
    ],
    productMap: {
      'docker.com': 'Docker',
      'kubernetes.io': 'Kubernetes (CNCF)',
      'python.org': 'Python Software Foundation',
      'pypi.org': 'PyPI Registry',
      'rust-lang.org': 'Rust Foundation',
      'crates.io': 'crates.io Registry',
      'nodejs.org': 'Node.js (OpenJS Foundation)',
      'apache.org': 'Apache Software Foundation',
      'mozilla.org': 'Mozilla Foundation',
      'ubuntu.com': 'Ubuntu (Canonical)',
      'redhat.com': 'Red Hat (IBM)',
      'w3.org': 'World Wide Web Consortium (W3C)',
    },
    brandTokens: ['dockerhub', 'kubernetes', 'pypi', 'mozilla'],
    registrySources: ['Open Source Foundation & Language Registry Records'],
    expectedRdapHints: ['canonical', 'mozilla', 'redhat', 'linux foundation', 'fastly', 'cloudflare'],
    expectedAsnHints: ['fastly', 'cloudflare', 'amazon', 'akamai'],
  },
  {
    orgId: 'oracle_ibm_salesforce_sap',
    parentCompany: 'Enterprise Software Vendors (Oracle / IBM / Salesforce / SAP / Cisco)',
    category: 'Tech',
    officialDomains: [
      'oracle.com',
      'java.com',
      'mysql.com',
      'ibm.com',
      'salesforce.com',
      'slack.com',
      'slack-edge.com',
      'slack-imgs.com',
      'tableau.com',
      'sap.com',
      'servicenow.com',
      'snowflake.com',
      'databricks.com',
      'elastic.co',
      'mongodb.com',
      'redis.io',
      'postgresql.org',
      'sqlite.org',
      'jetbrains.com',
      'postman.com',
      'datadoghq.com',
      'grafana.com',
      'newrelic.com',
      'splunk.com',
      'twilio.com',
      'sendgrid.com',
      'hubspot.com',
      'zendesk.com',
      'intercom.com',
      'zoom.us',
      'zoom.com',
      'zoomgov.com',
    ],
    productMap: {
      'oracle.com': 'Oracle',
      'ibm.com': 'IBM',
      'salesforce.com': 'Salesforce',
      'slack.com': 'Slack (Salesforce)',
      'sap.com': 'SAP',
      'jetbrains.com': 'JetBrains',
      'postman.com': 'Postman',
      'mongodb.com': 'MongoDB',
      'postgresql.org': 'PostgreSQL Global Development Group',
      'zoom.us': 'Zoom',
    },
    brandTokens: ['salesforce', 'jetbrains', 'docusign', 'zoom-meeting'],
    registrySources: ['Enterprise Software Official Domain Registries'],
    expectedRdapHints: ['oracle', 'ibm', 'salesforce', 'markmonitor', 'csc corporate'],
    expectedAsnHints: ['akamai', 'cloudflare', 'amazon', 'oracle', 'ibm'],
  },
  {
    orgId: 'creative_productivity',
    parentCompany: 'Adobe / Figma / Canva / Dropbox / Notion / Stack Exchange',
    category: 'Developer',
    officialDomains: [
      'adobe.com',
      'behance.net',
      'typekit.net',
      'figma.com',
      'canva.com',
      'dropbox.com',
      'dropboxstatic.com',
      'box.com',
      'notion.so',
      'notion.com',
      'miro.com',
      'asana.com',
      'monday.com',
      'clickup.com',
      'linear.app',
      'stackoverflow.com',
      'stackexchange.com',
      'serverfault.com',
      'superuser.com',
      'askubuntu.com',
      'sstatic.net',
      'codepen.io',
      'codesandbox.io',
      'stackblitz.com',
      'jsfiddle.net',
      'grammarly.com',
      'deepl.com',
      'docusign.com',
      'docusign.net',
    ],
    productMap: {
      'adobe.com': 'Adobe',
      'figma.com': 'Figma',
      'canva.com': 'Canva',
      'dropbox.com': 'Dropbox',
      'notion.so': 'Notion',
      'stackoverflow.com': 'Stack Overflow',
      'docusign.com': 'DocuSign',
    },
    brandTokens: ['dropbox', 'docusign', 'adobe', 'figma', 'canva', 'stackoverflow'],
    registrySources: ['Vendor Official Registries & IANA RDAP'],
    expectedRdapHints: ['adobe', 'dropbox', 'markmonitor', 'csc corporate', 'cloudflare'],
    expectedAsnHints: ['cloudflare', 'amazon', 'fastly', 'akamai'],
  },

  // =========================================================================
  // 4. SOCIAL MEDIA, MESSAGING & CONTENT NETWORKS
  // =========================================================================
  {
    orgId: 'telegram',
    parentCompany: 'Telegram Messenger Inc.',
    category: 'Social',
    officialDomains: ['telegram.org', 't.me', 'telegram.me', 'telegra.ph', 'telesco.pe', 'tdesktop.com'],
    productMap: {
      'telegram.org': 'Telegram',
      't.me': 'Telegram Links',
      'telegram.me': 'Telegram Links',
      'telegra.ph': 'Telegraph',
    },
    brandTokens: ['telegram', 'te1egram', 'telegram-verify'],
    registrySources: ['Telegram Official Domain Documentation', 'IANA RDAP'],
    expectedRdapHints: ['telegram', 'cloudflare', 'dnspod'],
    expectedAsnHints: ['as62041', 'as62014', 'as59930', 'as44907', 'telegram'],
  },
  {
    orgId: 'discord',
    parentCompany: 'Discord Inc.',
    category: 'Social',
    officialDomains: ['discord.com', 'discord.gg', 'discordapp.com', 'discord.media', 'discordapp.net', 'discordstatus.com'],
    productMap: { 'discord.com': 'Discord', 'discord.gg': 'Discord Invites' },
    brandTokens: ['discord', 'dlscord', 'discord-nitro', 'discordapp'],
    registrySources: ['Discord Official Domain List'],
    expectedRdapHints: ['discord', 'cloudflare'],
    expectedAsnHints: ['cloudflare'],
  },
  {
    orgId: 'x_twitter',
    parentCompany: 'X Corp.',
    category: 'Social',
    officialDomains: ['x.com', 'twitter.com', 't.co', 'twimg.com'],
    productMap: { 'x.com': 'X', 'twitter.com': 'X (Twitter)', 't.co': 'X Shortener' },
    brandTokens: ['twitter', 'tw1tter'],
    registrySources: ['X Corp. Official Domain Registry'],
    expectedRdapHints: ['x corp', 'twitter', 'csc corporate'],
    expectedAsnHints: ['as13414', 'twitter', 'cloudflare'],
  },
  {
    orgId: 'tiktok',
    parentCompany: 'ByteDance / TikTok',
    category: 'Social',
    officialDomains: ['tiktok.com', 'tiktokcdn.com', 'tiktokv.com', 'capcut.com'],
    productMap: { 'tiktok.com': 'TikTok', 'capcut.com': 'CapCut (ByteDance)' },
    brandTokens: ['tiktok', 'tikt0k'],
    registrySources: ['TikTok Official Registry'],
    expectedRdapHints: ['tiktok', 'bytedance', 'csc corporate'],
    expectedAsnHints: ['akamai', 'fastly', 'cloudflare'],
  },
  {
    orgId: 'snapchat',
    parentCompany: 'Snap Inc.',
    category: 'Social',
    officialDomains: ['snapchat.com', 'snap.com', 'sc-cdn.net', 'bitmoji.com'],
    productMap: { 'snapchat.com': 'Snapchat', 'snap.com': 'Snap Inc.' },
    brandTokens: ['snapchat', 'snap-login'],
    registrySources: ['Snap Inc. Official Domain Registry'],
    expectedRdapHints: ['snap', 'markmonitor'],
    expectedAsnHints: ['google', 'amazon', 'fastly'],
  },
  {
    orgId: 'reddit_pinterest_quora',
    parentCompany: 'Reddit / Pinterest / Quora / Signal / Medium',
    category: 'Social',
    officialDomains: [
      'reddit.com',
      'redd.it',
      'redditstatic.com',
      'redditmedia.com',
      'pinterest.com',
      'pin.it',
      'pinimg.com',
      'quora.com',
      'quoracdn.net',
      'signal.org',
      'signal.art',
      'viber.com',
      'line.me',
      'medium.com',
      'substack.com',
      'tumblr.com',
      'patreon.com',
      'kickstarter.com',
    ],
    productMap: {
      'reddit.com': 'Reddit',
      'pinterest.com': 'Pinterest',
      'quora.com': 'Quora',
      'signal.org': 'Signal Messenger',
      'medium.com': 'Medium',
      'substack.com': 'Substack',
      'patreon.com': 'Patreon',
    },
    brandTokens: ['reddit', 'pinterest', 'substack', 'patreon'],
    registrySources: ['Official Platform Domain Registries'],
    expectedRdapHints: ['reddit', 'pinterest', 'markmonitor', 'cloudflare', 'fastly'],
    expectedAsnHints: ['fastly', 'cloudflare', 'amazon'],
  },

  // =========================================================================
  // 5. CYBERSECURITY, THREAT INTELLIGENCE & PKI AUTHORITIES
  // =========================================================================
  {
    orgId: 'security_vendors',
    parentCompany: 'Global Cybersecurity & Threat Intelligence Authorities',
    category: 'Security',
    officialDomains: [
      'virustotal.com',
      'abuse.ch',
      'urlhaus.abuse.ch',
      'bazaar.abuse.ch',
      'threatfox.abuse.ch',
      'urlscan.io',
      'shodan.io',
      'censys.io',
      'greynoise.io',
      'haveibeenpwned.com',
      'alienvault.com',
      'cisco.com',
      'talosintelligence.com',
      'opendns.com',
      'umbrella.com',
      'duo.com',
      'paloaltonetworks.com',
      'fortinet.com',
      'crowdstrike.com',
      'sentinelone.com',
      'checkpoint.com',
      'kaspersky.com',
      'bitdefender.com',
      'eset.com',
      'malwarebytes.com',
      'norton.com',
      'mcafee.com',
      'avast.com',
      'sophos.com',
      'okta.com',
      'auth0.com',
      '1password.com',
      'bitwarden.com',
      'yubico.com',
      'proton.me',
      'protonmail.com',
      'protonvpn.com',
      'tuta.com',
      'mullvad.net',
      'nordvpn.com',
      'expressvpn.com',
      'surfshark.com',
      'torproject.org',
      'letsencrypt.org',
      'lencr.org',
      'digicert.com',
      'sectigo.com',
      'verisign.com',
      'globalsign.com',
      'iana.org',
      'icann.org',
      'owasp.org',
      'mitre.org',
      'cve.org',
      'krebsonsecurity.com',
      'bleepingcomputer.com',
    ],
    productMap: {
      'virustotal.com': 'VirusTotal',
      'abuse.ch': 'abuse.ch',
      'urlscan.io': 'urlscan.io',
      'shodan.io': 'Shodan',
      'haveibeenpwned.com': 'Have I Been Pwned',
      'cisco.com': 'Cisco',
      'crowdstrike.com': 'CrowdStrike',
      'paloaltonetworks.com': 'Palo Alto Networks',
      'fortinet.com': 'Fortinet',
      'okta.com': 'Okta',
      'auth0.com': 'Auth0 (Okta)',
      '1password.com': '1Password',
      'bitwarden.com': 'Bitwarden',
      'proton.me': 'Proton',
      'protonmail.com': 'Proton Mail',
      'letsencrypt.org': "Let's Encrypt (ISRG)",
      'digicert.com': 'DigiCert',
      'iana.org': 'IANA',
      'icann.org': 'ICANN',
      'owasp.org': 'OWASP Foundation',
      'mitre.org': 'MITRE Corporation',
    },
    brandTokens: ['protonmail', 'proton-verify', 'virustotal', '1password', 'bitwarden', 'letsencrypt'],
    registrySources: ['Security & PKI Authority Official Registries', 'IANA RDAP'],
    expectedRdapHints: ['cloudflare', 'markmonitor', 'csc corporate', 'cisco', 'digicert', 'verisign', 'proton'],
    expectedAsnHints: ['cloudflare', 'amazon', 'akamai', 'fastly', 'as62371'],
  },

  // =========================================================================
  // 6. GLOBAL FINANCE, PAYMENTS & BANKING
  // =========================================================================
  {
    orgId: 'paypal',
    parentCompany: 'PayPal Holdings, Inc.',
    category: 'Finance',
    officialDomains: ['paypal.com', 'paypal.me', 'paypalobjects.com', 'venmo.com', 'braintreepayments.com', 'xoom.com'],
    productMap: {
      'paypal.com': 'PayPal',
      'paypal.me': 'PayPal.Me',
      'venmo.com': 'Venmo (PayPal)',
      'xoom.com': 'Xoom (PayPal)',
    },
    brandTokens: ['paypal', 'paypa1', 'pp-secure'],
    registrySources: ['PayPal Corporate Registry', 'IANA RDAP (MarkMonitor / PayPal Inc.)'],
    expectedRdapHints: ['paypal', 'markmonitor'],
    expectedAsnHints: ['as17012', 'paypal', 'akamai', 'fastly'],
  },
  {
    orgId: 'stripe',
    parentCompany: 'Stripe, Inc.',
    category: 'Finance',
    officialDomains: ['stripe.com', 'stripe.network', 'stripecdn.com'],
    productMap: { 'stripe.com': 'Stripe' },
    brandTokens: ['stripe'],
    registrySources: ['Stripe Official Domain Registry'],
    expectedRdapHints: ['stripe', 'markmonitor', 'awsdns'],
    expectedAsnHints: ['stripe', 'amazon', 'fastly', 'cloudflare'],
  },
  {
    orgId: 'global_payments_fintech',
    parentCompany: 'Global Payment Networks & Fintech Platforms',
    category: 'Finance',
    officialDomains: [
      'visa.com',
      'mastercard.com',
      'americanexpress.com',
      'discover.com',
      'wise.com',
      'revolut.com',
      'adyen.com',
      'squareup.com',
      'block.xyz',
      'cash.app',
      'klarna.com',
      'payoneer.com',
      'westernunion.com',
      'moneygram.com',
      'remitly.com',
      'skrill.com',
      'checkout.com',
      'plaid.com',
      'intuit.com',
      'quickbooks.intuit.com',
      'turbotax.intuit.com',
    ],
    productMap: {
      'visa.com': 'Visa',
      'mastercard.com': 'Mastercard',
      'americanexpress.com': 'American Express',
      'wise.com': 'Wise',
      'revolut.com': 'Revolut',
      'adyen.com': 'Adyen',
      'squareup.com': 'Square (Block)',
      'cash.app': 'Cash App (Block)',
      'klarna.com': 'Klarna',
      'payoneer.com': 'Payoneer',
      'westernunion.com': 'Western Union',
      'intuit.com': 'Intuit',
    },
    brandTokens: ['visa-verify', 'mastercard-secure', 'revolut', 'payoneer', 'westernunion', 'cashapp'],
    registrySources: ['Card Network & Regulated Fintech Registries'],
    expectedRdapHints: ['visa', 'mastercard', 'csc corporate', 'markmonitor', 'cloudflare', 'awsdns'],
    expectedAsnHints: ['akamai', 'cloudflare', 'amazon'],
  },
  {
    orgId: 'global_banks',
    parentCompany: 'Major International Banking Institutions',
    category: 'Finance',
    officialDomains: [
      'chase.com',
      'jpmorgan.com',
      'jpmorganchase.com',
      'bankofamerica.com',
      'wellsfargo.com',
      'citibank.com',
      'citi.com',
      'goldmansachs.com',
      'morganstanley.com',
      'capitalone.com',
      'hsbc.com',
      'hsbc.co.uk',
      'barclays.co.uk',
      'barclays.com',
      'lloydsbank.com',
      'natwest.com',
      'santander.co.uk',
      'bnpparibas.com',
      'ubs.com',
      'ing.com',
      'sc.com',
      'rbc.com',
      'td.com',
      'commbank.com.au',
      'anz.com.au',
      'dbs.com',
    ],
    productMap: {
      'chase.com': 'Chase Bank (JPMorgan)',
      'bankofamerica.com': 'Bank of America',
      'wellsfargo.com': 'Wells Fargo',
      'citibank.com': 'Citibank',
      'hsbc.com': 'HSBC',
      'barclays.co.uk': 'Barclays UK',
      'ubs.com': 'UBS',
    },
    brandTokens: ['chase-bank', 'wellsfargo', 'bankofamerica', 'citibank', 'barclays'],
    registrySources: ['Regulated Banking Institution Domain Registries'],
    expectedRdapHints: ['jpmorgan', 'bank of america', 'csc corporate', 'markmonitor', 'akamai'],
    expectedAsnHints: ['akamai', 'cloudflare'],
  },

  // =========================================================================
  // 7. MENA BANKS, FINTECH & TELECOM (SAUDI, UAE, EGYPT, QATAR, KUWAIT, JORDAN)
  // =========================================================================
  {
    orgId: 'saudi_banks_fintech',
    parentCompany: 'Saudi Banking & SAMA-Regulated Fintech Ecosystem',
    category: 'Finance',
    officialDomains: [
      'alrajhibank.com.sa',
      'alahli.com',
      'alahlionline.com',
      'riyadbank.com',
      'alinma.com',
      'bankalbilad.com',
      'aljazira.com.sa',
      'sab.com',
      'sabb.com',
      'anb.com.sa',
      'bsf.sa',
      'saib.com.sa',
      'gib.com',
      'sama.gov.sa',
      'mada.com.sa',
      'sadad.com',
      'stcpay.com.sa',
      'stcbank.com.sa',
      'urpay.com.sa',
      'tamara.co',
      'tabby.ai',
    ],
    productMap: {
      'alrajhibank.com.sa': 'Al Rajhi Bank',
      'alahli.com': 'Saudi National Bank (SNB AlAhli)',
      'riyadbank.com': 'Riyad Bank',
      'alinma.com': 'Alinma Bank',
      'bankalbilad.com': 'Bank Albilad',
      'sab.com': 'Saudi Awwal Bank (SAB)',
      'anb.com.sa': 'Arab National Bank (ANB)',
      'bsf.sa': 'Banque Saudi Fransi',
      'sama.gov.sa': 'Saudi Central Bank (SAMA)',
      'stcpay.com.sa': 'stc pay',
      'stcbank.com.sa': 'stc bank',
      'tamara.co': 'Tamara',
      'tabby.ai': 'Tabby',
    },
    brandTokens: ['alrajhi', 'alrajhibank', 'alahli', 'snb-alahli', 'riyadbank', 'alinma', 'stcpay'],
    registrySources: ['Saudi Central Bank (SAMA) & .SA Registry Records'],
    expectedRdapHints: ['al rajhi', 'alrajhi', 'saudi national bank', 'alahli', 'nic.sa', 'riyad'],
    expectedAsnHints: ['alrajhi', 'alahli', 'stc', 'cloudflare', 'akamai'],
  },
  {
    orgId: 'gcc_banks',
    parentCompany: 'UAE, Qatar, Kuwait & Bahrain Regulated Banks',
    category: 'Finance',
    officialDomains: [
      'emiratesnbd.com',
      'adcb.com',
      'bankfab.com',
      'dib.ae',
      'adib.ae',
      'mashreqbank.com',
      'cbd.ae',
      'rakbank.ae',
      'qnb.com',
      'qib.com.qa',
      'cbq.qa',
      'nbk.com',
      'kfh.com',
      'cbk.com',
      'boubyan.com',
      'arabbank.com',
    ],
    productMap: {
      'emiratesnbd.com': 'Emirates NBD',
      'adcb.com': 'Abu Dhabi Commercial Bank',
      'bankfab.com': 'First Abu Dhabi Bank (FAB)',
      'dib.ae': 'Dubai Islamic Bank',
      'qnb.com': 'Qatar National Bank (QNB)',
      'nbk.com': 'National Bank of Kuwait',
      'kfh.com': 'Kuwait Finance House',
      'arabbank.com': 'Arab Bank',
    },
    brandTokens: ['emiratesnbd', 'bankfab', 'mashreq'],
    registrySources: ['GCC Central Bank Regulated Institution Registries'],
    expectedRdapHints: ['emirates', 'qnb', 'nbk', 'akamai', 'cloudflare'],
    expectedAsnHints: ['akamai', 'cloudflare', 'etisalat', 'ooredoo'],
  },
  {
    orgId: 'egypt_banks_fintech',
    parentCompany: 'Egyptian Banking & CBE-Regulated Fintech Ecosystem',
    category: 'Finance',
    officialDomains: [
      'nbe.com.eg',
      'cibeg.com',
      'banquemisr.com',
      'qnbalahli.com',
      'alexbank.com',
      'aaib.com',
      'faisalbank.com.eg',
      'bdc.com.eg',
      'cbe.org.eg',
      'instapay.eg',
      'fawry.com',
      'paymob.com',
      'telda.app',
    ],
    productMap: {
      'nbe.com.eg': 'National Bank of Egypt',
      'cibeg.com': 'CIB Egypt',
      'banquemisr.com': 'Banque Misr',
      'alexbank.com': 'ALEXBANK',
      'cbe.org.eg': 'Central Bank of Egypt',
      'instapay.eg': 'InstaPay Egypt',
      'fawry.com': 'Fawry',
      'paymob.com': 'Paymob',
    },
    brandTokens: ['nbe-egypt', 'alahlynet', 'cib-egypt', 'banquemisr', 'instapay'],
    registrySources: ['Central Bank of Egypt (CBE) Regulated Registry'],
    expectedRdapHints: ['national bank of egypt', 'commercial international bank', 'banque misr', 'fawry'],
    expectedAsnHints: ['cloudflare', 'akamai', 'telecom egypt'],
  },
  {
    orgId: 'mena_telecom',
    parentCompany: 'MENA & Global Telecom Operators',
    category: 'Telecom',
    officialDomains: [
      'stc.com.sa',
      'mobily.com.sa',
      'zain.com',
      'sa.zain.com',
      'zain.jo',
      'iq.zain.com',
      'etisalat.ae',
      'eand.com',
      'du.ae',
      'ooredoo.com',
      'ooredoo.qa',
      'vodafone.com',
      'vodafone.co.uk',
      'vodafone.com.eg',
      'orange.com',
      'orange.eg',
      'orange.jo',
      'etisalat.eg',
      'te.eg',
      'we.eg',
      'asiacell.com',
      'att.com',
      'verizon.com',
      't-mobile.com',
    ],
    productMap: {
      'stc.com.sa': 'stc Saudi Arabia',
      'mobily.com.sa': 'Mobily',
      'zain.com': 'Zain Group',
      'etisalat.ae': 'e& UAE',
      'eand.com': 'e& Group',
      'du.ae': 'du UAE',
      'ooredoo.com': 'Ooredoo',
      'vodafone.com': 'Vodafone Group',
      'vodafone.com.eg': 'Vodafone Egypt',
      'te.eg': 'Telecom Egypt (WE)',
      'we.eg': 'WE Egypt',
    },
    brandTokens: ['mystc', 'vodafone-cash', 'vodaf0ne', 'etisalat-bill'],
    registrySources: ['Telecom Operator Official Registries'],
    expectedRdapHints: ['stc', 'saudi telecom', 'vodafone', 'etisalat', 'orange', 'ooredoo'],
    expectedAsnHints: ['stc', 'vodafone', 'etisalat', 'akamai', 'cloudflare'],
  },

  // =========================================================================
  // 8. E-COMMERCE, MARKETPLACES, DELIVERY & TRAVEL
  // =========================================================================
  {
    orgId: 'global_commerce',
    parentCompany: 'Global E-Commerce & Retail Marketplaces',
    category: 'Commerce',
    officialDomains: [
      'ebay.com',
      'ebay.co.uk',
      'ebay.de',
      'shopify.com',
      'myshopify.com',
      'walmart.com',
      'target.com',
      'bestbuy.com',
      'costco.com',
      'ikea.com',
      'aliexpress.com',
      'alibaba.com',
      'temu.com',
      'shein.com',
      'etsy.com',
      'rakuten.co.jp',
      'mercadolibre.com',
    ],
    productMap: {
      'ebay.com': 'eBay',
      'shopify.com': 'Shopify',
      'walmart.com': 'Walmart',
      'ikea.com': 'IKEA',
      'aliexpress.com': 'AliExpress',
      'alibaba.com': 'Alibaba',
      'etsy.com': 'Etsy',
    },
    brandTokens: ['ebay-secure', 'ebay-verify', 'shopify-support', 'aliexpress'],
    registrySources: ['Corporate Retail Domain Registries'],
    expectedRdapHints: ['ebay', 'shopify', 'markmonitor', 'csc corporate'],
    expectedAsnHints: ['cloudflare', 'akamai', 'fastly'],
  },
  {
    orgId: 'mena_commerce_delivery',
    parentCompany: 'MENA Marketplaces & Delivery Platforms',
    category: 'Commerce',
    officialDomains: [
      'noon.com',
      'namshi.com',
      'jarir.com',
      'extra.com',
      'haraj.com.sa',
      'jumia.com',
      'jumia.com.eg',
      'talabat.com',
      'hungerstation.com',
      'jahez.net',
      'mrsool.co',
      'careem.com',
    ],
    productMap: {
      'noon.com': 'Noon',
      'jarir.com': 'Jarir Bookstore',
      'extra.com': 'eXtra Stores',
      'haraj.com.sa': 'Haraj',
      'talabat.com': 'Talabat',
      'hungerstation.com': 'HungerStation',
      'careem.com': 'Careem',
    },
    brandTokens: ['noon-pay', 'talabat', 'hungerstation', 'haraj'],
    registrySources: ['MENA Commerce Official Registries'],
    expectedRdapHints: ['noon', 'cloudflare', 'awsdns'],
    expectedAsnHints: ['cloudflare', 'amazon', 'akamai'],
  },
  {
    orgId: 'travel_airlines_mobility',
    parentCompany: 'Global Travel, Hospitality & Airlines',
    category: 'Travel',
    officialDomains: [
      'uber.com',
      'ubereats.com',
      'lyft.com',
      'doordash.com',
      'airbnb.com',
      'booking.com',
      'expedia.com',
      'tripadvisor.com',
      'agoda.com',
      'skyscanner.net',
      'saudia.com',
      'flynas.com',
      'flyadeal.com',
      'emirates.com',
      'etihad.com',
      'qatarairways.com',
      'egyptair.com',
      'turkishairlines.com',
      'lufthansa.com',
      'britishairways.com',
      'airfrance.com',
      'delta.com',
      'united.com',
      'aa.com',
    ],
    productMap: {
      'airbnb.com': 'Airbnb',
      'booking.com': 'Booking.com',
      'uber.com': 'Uber',
      'saudia.com': 'SAUDIA Airlines',
      'emirates.com': 'Emirates Airline',
      'qatarairways.com': 'Qatar Airways',
      'egyptair.com': 'EGYPTAIR',
    },
    brandTokens: ['booking-verify', 'airbnb', 'saudia', 'emirates-miles'],
    registrySources: ['Airline & Travel Official Registries'],
    expectedRdapHints: ['booking', 'airbnb', 'uber', 'csc corporate', 'markmonitor'],
    expectedAsnHints: ['cloudflare', 'akamai', 'fastly', 'amazon'],
  },

  // =========================================================================
  // 9. LOGISTICS & SHIPPING
  // =========================================================================
  {
    orgId: 'logistics_global',
    parentCompany: 'Global & Regional Postal / Express Carriers',
    category: 'Logistics',
    officialDomains: [
      'dhl.com',
      'dhl.de',
      'fedex.com',
      'ups.com',
      'usps.com',
      'royalmail.com',
      'aramex.com',
      'smsaexpress.com',
      'splonline.com.sa',
      'egyptpost.org',
      'maersk.com',
    ],
    productMap: {
      'dhl.com': 'DHL Express',
      'fedex.com': 'FedEx',
      'ups.com': 'UPS',
      'usps.com': 'USPS',
      'royalmail.com': 'Royal Mail',
      'aramex.com': 'Aramex',
      'smsaexpress.com': 'SMSA Express',
      'splonline.com.sa': 'Saudi Post (SPL)',
      'maersk.com': 'Maersk',
    },
    brandTokens: ['dhl-express', 'dhl-parcel', 'fedex', 'ups-delivery', 'ups-tracking', 'aramex', 'smsaexpress'],
    registrySources: ['Logistics & National Postal Registries'],
    expectedRdapHints: ['dhl', 'fedex', 'united parcel service', 'aramex', 'csc corporate'],
    expectedAsnHints: ['akamai', 'cloudflare', 'amazon'],
  },

  // =========================================================================
  // 10. CRYPTOCURRENCY EXCHANGES, EXPLORERS & HARDWARE WALLETS
  // =========================================================================
  {
    orgId: 'crypto_platforms',
    parentCompany: 'Verified Cryptocurrency Exchanges, Explorers & Wallets',
    category: 'Crypto',
    officialDomains: [
      'binance.com',
      'binance.us',
      'bnbstatic.com',
      'coinbase.com',
      'kraken.com',
      'bybit.com',
      'okx.com',
      'kucoin.com',
      'bitget.com',
      'crypto.com',
      'gemini.com',
      'bitfinex.com',
      'blockchain.com',
      'etherscan.io',
      'bscscan.com',
      'polygonscan.com',
      'solscan.io',
      'coingecko.com',
      'coinmarketcap.com',
      'metamask.io',
      'consensys.io',
      'phantom.app',
      'ledger.com',
      'trezor.io',
      'trustwallet.com',
      'uniswap.org',
      'opensea.io',
      'ethereum.org',
      'bitcoin.org',
    ],
    productMap: {
      'binance.com': 'Binance',
      'coinbase.com': 'Coinbase',
      'kraken.com': 'Kraken',
      'bybit.com': 'Bybit',
      'okx.com': 'OKX',
      'metamask.io': 'MetaMask (Consensys)',
      'ledger.com': 'Ledger',
      'trezor.io': 'Trezor',
      'trustwallet.com': 'Trust Wallet',
      'etherscan.io': 'Etherscan',
      'coingecko.com': 'CoinGecko',
      'coinmarketcap.com': 'CoinMarketCap',
      'ethereum.org': 'Ethereum Foundation',
    },
    brandTokens: [
      'binance',
      'binnance',
      'coinbase',
      'c0inbase',
      'metamask',
      'metarnask',
      'ledgerlive',
      'ledger-sync',
      'trustwallet',
      'trust-wallet',
      'trezor',
      'phantom-wallet',
    ],
    registrySources: ['Verified Web3 & Exchange Domain Registries'],
    expectedRdapHints: ['binance', 'coinbase', 'consensys', 'ledger', 'cloudflare', 'markmonitor'],
    expectedAsnHints: ['cloudflare', 'amazon', 'fastly'],
  },

  // =========================================================================
  // 11. GAMING & STREAMING MEDIA
  // =========================================================================
  {
    orgId: 'gaming_platforms',
    parentCompany: 'Major Gaming Publishers & Storefronts',
    category: 'Gaming',
    officialDomains: [
      'steampowered.com',
      'steamcommunity.com',
      'valvesoftware.com',
      'steamstatic.com',
      'roblox.com',
      'rbxcdn.com',
      'epicgames.com',
      'unrealengine.com',
      'fortnite.com',
      'playstation.com',
      'sonyentertainmentnetwork.com',
      'sony.com',
      'nintendo.com',
      'nintendo.co.jp',
      'ea.com',
      'ubisoft.com',
      'blizzard.com',
      'battle.net',
      'activision.com',
      'riotgames.com',
      'leagueoflegends.com',
      'playvalorant.com',
      'minecraft.net',
      'mojang.com',
      'rockstargames.com',
      'unity.com',
      'gog.com',
      'itch.io',
    ],
    productMap: {
      'steampowered.com': 'Steam Store (Valve)',
      'steamcommunity.com': 'Steam Community (Valve)',
      'roblox.com': 'Roblox',
      'epicgames.com': 'Epic Games',
      'fortnite.com': 'Fortnite (Epic Games)',
      'playstation.com': 'PlayStation (Sony)',
      'nintendo.com': 'Nintendo',
      'riotgames.com': 'Riot Games',
      'battle.net': 'Battle.net (Blizzard)',
      'minecraft.net': 'Minecraft (Mojang/Microsoft)',
    },
    brandTokens: ['steampowered', 'steamcommunity', 'stearn', 'roblox', 'r0blox', 'robux-free', 'epicgames', 'playstation', 'psn-login', 'valorant'],
    registrySources: ['Gaming Publisher Official Registries'],
    expectedRdapHints: ['valve', 'roblox', 'epic games', 'sony', 'nintendo', 'markmonitor', 'csc corporate'],
    expectedAsnHints: ['as32590', 'as22697', 'akamai', 'cloudflare', 'amazon'],
  },
  {
    orgId: 'streaming_media',
    parentCompany: 'Global & Regional Streaming / News / Reference Platforms',
    category: 'Media',
    officialDomains: [
      'netflix.com',
      'nflxext.com',
      'nflximg.net',
      'nflxso.net',
      'spotify.com',
      'scdn.co',
      'spotifycdn.com',
      'disneyplus.com',
      'disney.com',
      'hulu.com',
      'max.com',
      'shahid.mbc.net',
      'mbc.net',
      'bein.com',
      'tod.tv',
      'soundcloud.com',
      'vimeo.com',
      'dailymotion.com',
      'wikipedia.org',
      'wikimedia.org',
      'wikidata.org',
      'wiktionary.org',
      'wikisource.org',
      'archive.org',
      'reuters.com',
      'apnews.com',
      'bbc.com',
      'bbc.co.uk',
      'cnn.com',
      'nytimes.com',
      'washingtonpost.com',
      'theguardian.com',
      'bloomberg.com',
      'wsj.com',
      'ft.com',
      'forbes.com',
      'economist.com',
      'aljazeera.net',
      'aljazeera.com',
      'alarabiya.net',
      'asharq.com',
      'skynewsarabia.com',
    ],
    productMap: {
      'netflix.com': 'Netflix',
      'spotify.com': 'Spotify',
      'disneyplus.com': 'Disney+',
      'shahid.mbc.net': 'Shahid (MBC Group)',
      'mbc.net': 'MBC Group',
      'wikipedia.org': 'Wikipedia (Wikimedia)',
      'wikimedia.org': 'Wikimedia Foundation',
      'archive.org': 'Internet Archive',
      'bbc.com': 'BBC',
      'reuters.com': 'Reuters',
      'aljazeera.net': 'Al Jazeera',
      'alarabiya.net': 'Al Arabiya',
    },
    brandTokens: ['netflix', 'netfiix', 'netf1ix', 'spotify', 'sp0tify', 'wikipedia', 'wikimedia', 'disneyplus'],
    registrySources: ['Media & Wikimedia Official Domain Lists'],
    expectedRdapHints: ['netflix', 'spotify', 'wikimedia', 'bbc', 'markmonitor', 'csc corporate', 'cloudflare'],
    expectedAsnHints: ['as2906', 'as14907', 'fastly', 'cloudflare', 'akamai', 'amazon'],
  },

  // =========================================================================
  // 12. OFFICIAL GOVERNMENT, INTERNATIONAL BODIES & EDUCATION PORTALS
  // =========================================================================
  {
    orgId: 'gov_saudi',
    parentCompany: 'Kingdom of Saudi Arabia Official Government Portals',
    category: 'Government',
    officialDomains: [
      'my.gov.sa',
      'absher.sa',
      'nafath.sa',
      'iam.gov.sa',
      'qiwa.sa',
      'mudad.com.sa',
      'gosi.gov.sa',
      'zatca.gov.sa',
      'moh.gov.sa',
      'moe.gov.sa',
      'moi.gov.sa',
      'mofa.gov.sa',
      'mc.gov.sa',
      'moj.gov.sa',
      'hrsd.gov.sa',
      'sdaia.gov.sa',
      'nca.gov.sa',
      'cst.gov.sa',
      'spa.gov.sa',
      'najiz.sa',
      'ejar.sa',
      'sakani.sa',
      'balady.gov.sa',
      'elm.sa',
      'nic.sa',
    ],
    productMap: {
      'my.gov.sa': 'Saudi National Unified Portal (GOV.SA)',
      'absher.sa': 'Absher Portal',
      'nafath.sa': 'Nafath National Single Sign-On',
      'qiwa.sa': 'Qiwa Platform',
      'zatca.gov.sa': 'ZATCA',
      'najiz.sa': 'Najiz (Ministry of Justice)',
      'sdaia.gov.sa': 'SDAIA',
      'nca.gov.sa': 'National Cybersecurity Authority (NCA)',
    },
    brandTokens: ['absher-verify', 'nafath-verify', 'qiwa-login', 'zatca-tax'],
    registrySources: ['SaudiNIC (.gov.sa / .sa) Authoritative Registry Records'],
    expectedRdapHints: ['nic.sa', 'saudinic', 'government', 'elm'],
    expectedAsnHints: ['nic.sa', 'stc', 'cloudflare', 'akamai'],
  },
  {
    orgId: 'gov_egypt_gcc',
    parentCompany: 'Egypt & GCC Official Government Portals',
    category: 'Government',
    officialDomains: [
      'digital.gov.eg',
      'egypt.gov.eg',
      'sis.gov.eg',
      'moi.gov.eg',
      'mohp.gov.eg',
      'moe.gov.eg',
      'mohesr.gov.eg',
      'eta.gov.eg',
      'mof.gov.eg',
      'u.ae',
      'government.ae',
      'icp.gov.ae',
      'mohre.gov.ae',
      'dubaipolice.gov.ae',
      'hukoomi.gov.qa',
      'e.gov.kw',
      'bahrain.bh',
      'oman.om',
    ],
    productMap: {
      'digital.gov.eg': 'Digital Egypt (مصر الرقمية)',
      'egypt.gov.eg': 'Egyptian Government Portal',
      'u.ae': 'UAE Government Portal',
      'hukoomi.gov.qa': 'Hukoomi Qatar',
      'bahrain.bh': 'Bahrain eGovernment',
    },
    brandTokens: ['digital-egypt', 'gov-tax-refund'],
    registrySources: ['National e-Government TLD Registries (.gov.eg / .gov.ae / .gov.qa)'],
    expectedRdapHints: ['government', 'etisalat', 'tdra', 'mcit'],
    expectedAsnHints: ['cloudflare', 'akamai', 'etisalat'],
  },
  {
    orgId: 'gov_intl',
    parentCompany: 'US, UK, EU & International Organizations',
    category: 'Government',
    officialDomains: [
      'usa.gov',
      'irs.gov',
      'ssa.gov',
      'usajobs.gov',
      'state.gov',
      'whitehouse.gov',
      'nasa.gov',
      'nih.gov',
      'cdc.gov',
      'fda.gov',
      'sec.gov',
      'ftc.gov',
      'fbi.gov',
      'nist.gov',
      'cisa.gov',
      'gov.uk',
      'nhs.uk',
      'parliament.uk',
      'europa.eu',
      'ec.europa.eu',
      'un.org',
      'who.int',
      'worldbank.org',
      'imf.org',
      'unesco.org',
    ],
    productMap: {
      'usa.gov': 'USA.gov',
      'irs.gov': 'IRS',
      'nasa.gov': 'NASA',
      'nist.gov': 'NIST',
      'cisa.gov': 'CISA',
      'gov.uk': 'GOV.UK',
      'nhs.uk': 'UK NHS',
      'europa.eu': 'European Union Portal',
      'un.org': 'United Nations',
      'who.int': 'World Health Organization',
    },
    brandTokens: ['irs-refund', 'gov-uk-verify'],
    registrySources: ['Authoritative .gov / .gov.uk / .int / .europa.eu Registries'],
    expectedRdapHints: ['gov', 'verisign', 'nominet', 'cisa', 'irs'],
    expectedAsnHints: ['akamai', 'cloudflare', 'fastly', 'amazon'],
  },
  {
    orgId: 'education_research',
    parentCompany: 'Universities, Academic Publishers & Learning Platforms',
    category: 'Education',
    officialDomains: [
      'harvard.edu',
      'mit.edu',
      'stanford.edu',
      'berkeley.edu',
      'ox.ac.uk',
      'cam.ac.uk',
      'ksu.edu.sa',
      'kau.edu.sa',
      'kfupm.edu.sa',
      'cu.edu.eg',
      'coursera.org',
      'edx.org',
      'udemy.com',
      'khanacademy.org',
      'duolingo.com',
      'arxiv.org',
      'ieee.org',
      'acm.org',
      'nature.com',
      'springer.com',
      'sciencedirect.com',
      'researchgate.net',
    ],
    productMap: {
      'harvard.edu': 'Harvard University',
      'mit.edu': 'MIT',
      'stanford.edu': 'Stanford University',
      'ox.ac.uk': 'University of Oxford',
      'cam.ac.uk': 'University of Cambridge',
      'ksu.edu.sa': 'King Saud University',
      'coursera.org': 'Coursera',
      'khanacademy.org': 'Khan Academy',
      'duolingo.com': 'Duolingo',
      'arxiv.org': 'arXiv (Cornell University)',
    },
    brandTokens: ['coursera', 'duolingo'],
    registrySources: ['EDUCAUSE .edu / Jisc .ac.uk / SaudiNIC .edu.sa Registries'],
    expectedRdapHints: ['educause', 'nominet', 'nic.sa', 'markmonitor', 'cloudflare'],
    expectedAsnHints: ['fastly', 'cloudflare', 'akamai', 'amazon'],
  },
];

export const AUTHORIZED_THIRD_PARTY_PROVIDERS: AuthorizedProviderDefinition[] = [
  {
    providerId: 'cloudflare_cdn',
    name: 'Cloudflare CDN / Security / Turnstile',
    role: 'cdn',
    domains: ['cdnjs.cloudflare.com', 'challenges.cloudflare.com', 'static.cloudflareinsights.com', 'cloudflareinsights.com'],
  },
  {
    providerId: 'jsdelivr',
    name: 'jsDelivr Open Source CDN',
    role: 'cdn',
    domains: ['cdn.jsdelivr.net', 'jsdelivr.net'],
  },
  {
    providerId: 'unpkg',
    name: 'unpkg CDN',
    role: 'cdn',
    domains: ['unpkg.com'],
  },
  {
    providerId: 'fastly',
    name: 'Fastly Edge CDN',
    role: 'cdn',
    domains: ['fastly.net', 'fastlylb.net'],
  },
  {
    providerId: 'akamai',
    name: 'Akamai Edge CDN',
    role: 'cdn',
    domains: ['akamaized.net', 'akamaihd.net', 'akamai.net', 'edgekey.net', 'edgesuite.net'],
  },
  {
    providerId: 'google_assets',
    name: 'Google Fonts / Analytics / reCAPTCHA / Tag Manager',
    role: 'analytics',
    domains: [
      'fonts.googleapis.com',
      'fonts.gstatic.com',
      'ajax.googleapis.com',
      'googletagmanager.com',
      'google-analytics.com',
      'recaptcha.net',
      'www.gstatic.com',
    ],
  },
  {
    providerId: 'captcha_security',
    name: 'hCaptcha / Arkose / Friendly Captcha',
    role: 'security',
    domains: ['hcaptcha.com', 'js.hcaptcha.com', 'newassets.hcaptcha.com', 'arkoselabs.com', 'friendlycaptcha.com'],
  },
  {
    providerId: 'auth_brokers',
    name: 'Okta / Auth0 / AWS Cognito / Clerk Identity Brokers',
    role: 'auth_sso',
    domains: ['auth0.com', 'cdn.auth0.com', 'okta.com', 'oktacdn.com', 'clerk.com', 'clerk.accounts.dev', 'amazoncognito.com'],
  },
  {
    providerId: 'stripe_payments',
    name: 'Stripe / Adyen / Braintree / Checkout Payment Gateways',
    role: 'payments',
    domains: ['js.stripe.com', 'checkout.stripe.com', 'stripe.com', 'checkoutshopper-live.adyen.com', 'js.braintreegateway.com', 'js.checkout.com'],
  },
  {
    providerId: 'telemetry_observability',
    name: 'Sentry / Datadog / Algolia / Intercom',
    role: 'analytics',
    domains: ['sentry.io', 'sentry-cdn.com', 'browser-intake-datadoghq.com', 'algolianet.com', 'algolia.net', 'widget.intercom.io'],
  },
  {
    providerId: 'jquery_bootstrap_cdn',
    name: 'Standard Frontend Asset CDNs',
    role: 'fonts_assets',
    domains: ['code.jquery.com', 'stackpath.bootstrapcdn.com', 'maxcdn.bootstrapcdn.com', 'cdn.tailwindcss.com', 'use.typekit.net', 'kit.fontawesome.com'],
  },
];

// Fast O(1) lookup indexes compiled once at startup
const USER_CONTENT_PAAS_LIST: string[] = Array.from(
  new Set([
    ...GENERAL_USER_CONTENT_PAAS_DOMAINS,
    ...OFFICIAL_ENTITIES.flatMap((e) => e.userContentPaasDomains || []),
  ])
);

const OFFICIAL_DOMAIN_INDEX = new Map<
  string,
  { entity: OfficialEntityDefinition; matchedOfficialDomain: string }
>();

for (const entity of OFFICIAL_ENTITIES) {
  for (const domain of entity.officialDomains) {
    const clean = domain.toLowerCase();
    if (!OFFICIAL_DOMAIN_INDEX.has(clean)) {
      OFFICIAL_DOMAIN_INDEX.set(clean, { entity, matchedOfficialDomain: clean });
    }
  }
}

const SSO_OAUTH_INTEGRATION_HOSTS = new Set([
  'accounts.google.com',
  'login.microsoftonline.com',
  'login.live.com',
  'appleid.apple.com',
  'github.com',
  'www.facebook.com',
  'facebook.com',
  'discord.com',
  'x.com',
  'twitter.com',
  'linkedin.com',
  'www.linkedin.com',
  'gitlab.com',
  'bitbucket.org',
  'slack.com',
  'zoom.us',
  'id.twitch.tv',
  'steamcommunity.com',
  'auth.openai.com',
  'nafath.sa',
  'iam.gov.sa',
]);

export function getOfficialRegistryStats(): {
  entityCount: number;
  officialDomainCount: number;
  authorizedProviderCount: number;
  paasSuffixCount: number;
  categories: EntityCategory[];
} {
  return {
    entityCount: OFFICIAL_ENTITIES.length,
    officialDomainCount: OFFICIAL_DOMAIN_INDEX.size,
    authorizedProviderCount: AUTHORIZED_THIRD_PARTY_PROVIDERS.length,
    paasSuffixCount: USER_CONTENT_PAAS_LIST.length,
    categories: Array.from(new Set(OFFICIAL_ENTITIES.map((e) => e.category))),
  };
}

export function pslParseHostname(hostname: string): {
  asciiHost: string;
  eTldPlusOne: string;
  publicSuffix: string;
  subdomain: string;
  isIp: boolean;
} {
  const clean = hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (net.isIP(clean) !== 0) {
    return { asciiHost: clean, eTldPlusOne: clean, publicSuffix: '', subdomain: '', isIp: true };
  }
  const asciiHost = domainToASCII(clean) || clean;
  const parsed = parseTldts(asciiHost, { allowPrivateDomains: false });
  if (parsed.domain && parsed.publicSuffix) {
    return {
      asciiHost,
      eTldPlusOne: parsed.domain,
      publicSuffix: parsed.publicSuffix,
      subdomain: parsed.subdomain || '',
      isIp: Boolean(parsed.isIp),
    };
  }
  const parts = asciiHost.split('.').filter(Boolean);
  return {
    asciiHost,
    eTldPlusOne: parts.length >= 2 ? parts.slice(-2).join('.') : asciiHost,
    publicSuffix: parts.length >= 2 ? parts[parts.length - 1] : '',
    subdomain: parts.length > 2 ? parts.slice(0, -2).join('.') : '',
    isIp: false,
  };
}

export interface DomainRegistryMatch {
  matched: boolean;
  isUserContentPaas: boolean;
  entity?: OfficialEntityDefinition;
  productName?: string;
  matchedOfficialDomain?: string;
  isSubdomain: boolean;
  subdomain: string;
  eTldPlusOne: string;
  authorizedProvider?: AuthorizedProviderDefinition;
}

/**
 * Checks whether an exact PSL eTLD+1 (not a substring or subdomain trick)
 * belongs to an official corporate/product registry or an authorized third-party provider.
 */
export function lookupDomainOwnership(hostname: string): DomainRegistryMatch {
  const psl = pslParseHostname(hostname);
  if (psl.isIp) {
    return {
      matched: false,
      isUserContentPaas: false,
      isSubdomain: false,
      subdomain: '',
      eTldPlusOne: psl.eTldPlusOne,
    };
  }

  // Check if host is a multi-tenant PaaS / user-content host (never official corporate entity)
  if (USER_CONTENT_PAAS_LIST.some((paas) => psl.asciiHost === paas || psl.asciiHost.endsWith(`.${paas}`))) {
    return {
      matched: false,
      isUserContentPaas: true,
      isSubdomain: Boolean(psl.subdomain),
      subdomain: psl.subdomain,
      eTldPlusOne: psl.eTldPlusOne,
    };
  }

  const matchedProvider = AUTHORIZED_THIRD_PARTY_PROVIDERS.find((prov) =>
    prov.domains.some((d) => psl.asciiHost === d || psl.eTldPlusOne === d || psl.asciiHost.endsWith(`.${d}`))
  );

  // Check exact full-host match first (e.g. firebase.google.com, shahid.mbc.net) then eTLD+1
  const indexedMatch =
    OFFICIAL_DOMAIN_INDEX.get(psl.asciiHost) || OFFICIAL_DOMAIN_INDEX.get(psl.eTldPlusOne);

  if (indexedMatch) {
    const { entity } = indexedMatch;
    const productName =
      entity.productMap[psl.asciiHost] ||
      entity.productMap[psl.eTldPlusOne] ||
      entity.parentCompany;
    const isNamedSubdomain = Boolean(psl.subdomain && psl.subdomain !== 'www');
    return {
      matched: true,
      isUserContentPaas: false,
      entity,
      productName,
      matchedOfficialDomain: psl.eTldPlusOne,
      isSubdomain: isNamedSubdomain,
      subdomain: psl.subdomain,
      eTldPlusOne: psl.eTldPlusOne,
      authorizedProvider: matchedProvider,
    };
  }

  // Check authorized third-party CDN / infrastructure providers
  if (matchedProvider) {
    return {
      matched: false,
      isUserContentPaas: false,
      isSubdomain: Boolean(psl.subdomain),
      subdomain: psl.subdomain,
      eTldPlusOne: psl.eTldPlusOne,
      authorizedProvider: matchedProvider,
    };
  }

  return {
    matched: false,
    isUserContentPaas: false,
    isSubdomain: Boolean(psl.subdomain),
    subdomain: psl.subdomain,
    eTldPlusOne: psl.eTldPlusOne,
  };
}

/**
 * Determines the deterministic relationship between two hostnames
 * (e.g., Facebook <-> Instagram, Google <-> YouTube, GitHub <-> Microsoft, or site <-> Cloudflare CDN).
 */
export function classifyDomainRelationship(
  sourceHostname: string,
  targetHostname: string
): {
  relationship: DomainRelationshipType;
  isSameOrganization: boolean;
  isBenignOrAuthorized: boolean;
  detail: string;
} {
  const srcPsl = pslParseHostname(sourceHostname);
  const tgtPsl = pslParseHostname(targetHostname);

  if (srcPsl.asciiHost === tgtPsl.asciiHost) {
    return { relationship: 'same_domain', isSameOrganization: true, isBenignOrAuthorized: true, detail: 'Identical host' };
  }
  if (srcPsl.eTldPlusOne === tgtPsl.eTldPlusOne) {
    return {
      relationship: 'official_subdomain',
      isSameOrganization: true,
      isBenignOrAuthorized: true,
      detail: `Shared registrable domain (${srcPsl.eTldPlusOne})`,
    };
  }

  const srcOwn = lookupDomainOwnership(srcPsl.asciiHost);
  const tgtOwn = lookupDomainOwnership(tgtPsl.asciiHost);

  if (srcOwn.matched && tgtOwn.matched && srcOwn.entity?.orgId === tgtOwn.entity?.orgId) {
    const sameParent = srcOwn.entity!.parentCompany;
    const isParent = tgtOwn.eTldPlusOne === srcOwn.entity!.officialDomains[0];
    return {
      relationship: isParent ? 'parent_company' : 'official_product',
      isSameOrganization: true,
      isBenignOrAuthorized: true,
      detail: `Both domains belong to ${sameParent} (${srcOwn.productName} ↔ ${tgtOwn.productName})`,
    };
  }

  if (tgtOwn.authorizedProvider) {
    return {
      relationship: 'authorized_third_party_provider',
      isSameOrganization: false,
      isBenignOrAuthorized: true,
      detail: `Authorized infrastructure provider (${tgtOwn.authorizedProvider.name})`,
    };
  }

  // OAuth / SSO external integration check (e.g., third-party site integrating "Sign in with Google / GitHub / Apple / Microsoft / Facebook / Nafath")
  if (tgtOwn.matched && SSO_OAUTH_INTEGRATION_HOSTS.has(tgtPsl.asciiHost)) {
    return {
      relationship: 'external_integration',
      isSameOrganization: false,
      isBenignOrAuthorized: true,
      detail: `External SSO / OAuth integration with ${tgtOwn.productName}`,
    };
  }

  return {
    relationship: 'unverified_relationship',
    isSameOrganization: false,
    isBenignOrAuthorized: false,
    detail: `No verified ownership or provider relationship between ${srcPsl.eTldPlusOne} and ${tgtPsl.eTldPlusOne}`,
  };
}

export interface CorroborationSignal {
  source: string;
  signal: string;
  verified: boolean;
  timestamp?: string;
}

export interface DomainAuthenticityAssessment {
  status: DomainAuthenticityStatus;
  label: BilingualText;
  registrableDomain: string;
  subdomain: string;
  publicSuffix: string;
  parentCompany?: string;
  officialProduct?: string;
  relationshipLabel?: BilingualText;
  corroborated: boolean;
  corroborationSources: CorroborationSignal[];
  registrySources: string[];
  disclaimer: BilingualText;
  conflictDetected: boolean;
  conflictDetail?: BilingualText;
  hostingMetadata?: DomainHostingMetadata;
}

export interface CorroborationTelemetryInput {
  hostname: string;
  dnsResolved?: boolean;
  dnsNameservers?: string[];
  cdnOrProxyProvider?: string;
  rdapRegistrar?: string;
  rdapOwner?: string;
  rdapRegistry?: string;
  asn?: string;
  networkName?: string;
  tlsAuthorized?: boolean;
  tlsExpired?: boolean;
  tlsDomainMatches?: boolean;
  tlsIssuer?: string;
  otxAllowlisted?: boolean;
  deceptionDetected?: boolean;
  similarityTarget?: { brand: string; officialDomain: string; reason: string };
}

/**
 * Evaluates Domain Authenticity using PSL extraction, Official Registry membership,
 * AND live technical corroboration (DNS, TLS, RDAP/WHOIS, ASN, OTX) — never trusting
 * domain string or HTTPS alone!
 */
export function assessDomainAuthenticity(input: CorroborationTelemetryInput): DomainAuthenticityAssessment {
  const psl = pslParseHostname(input.hostname);
  const ownership = lookupDomainOwnership(psl.asciiHost);
  const now = new Date().toISOString();

  const disclaimer: BilingualText = {
    en: 'Domain authenticity verifies ownership/identity of the domain according to available registry and network sources. It does NOT guarantee the website is free of vulnerabilities, compromised pages, or malicious third-party/user-submitted links.',
    ar: 'يثبت التحقق من أصالة النطاق انتماء النطاق للجهة المعروفة وفق المصادر المتاحة، لكنه لا يضمن خلو الموقع من الثغرات الأمنية أو الاختراق أو الروابط الضارة داخله.',
  };

  // Case 1: Official corporate/product domain in registry
  if (ownership.matched && ownership.entity) {
    const ent = ownership.entity;
    const signals: CorroborationSignal[] = [];

    // Signal A: PSL Registry Exact Match
    signals.push({
      source: ent.registrySources[0] || 'Official Domain Registry',
      signal: `Exact PSL eTLD+1 match: ${psl.eTldPlusOne} (${ent.parentCompany})`,
      verified: true,
      timestamp: now,
    });

    // Signal B: Live DNS resolution
    if (input.dnsResolved !== undefined) {
      signals.push({
        source: 'DNS Resolver',
        signal: input.dnsResolved ? 'Public DNS A/AAAA resolution succeeded' : 'DNS resolution failed',
        verified: Boolean(input.dnsResolved),
        timestamp: now,
      });
    }

    // Signal C: Live TLS Certificate validation
    const tlsValid = Boolean(input.tlsAuthorized && !input.tlsExpired && input.tlsDomainMatches !== false);
    if (input.tlsAuthorized !== undefined) {
      signals.push({
        source: 'X.509 TLS Handshake',
        signal: tlsValid
          ? `CA-trusted certificate matching "${psl.asciiHost}" (${input.tlsIssuer || 'Trusted CA'})`
          : 'TLS certificate invalid, expired, or mismatched',
        verified: tlsValid,
        timestamp: now,
      });
    }

    // Signal D: RDAP / WHOIS / Nameserver corroboration
    const rdapBlob = `${input.rdapRegistrar || ''} ${input.rdapOwner || ''} ${(input.dnsNameservers || []).join(' ')}`.toLowerCase();
    const rdapMatchedHint = ent.expectedRdapHints.find((h) => rdapBlob.includes(h));
    if (rdapBlob.trim()) {
      signals.push({
        source: input.rdapRegistry ? `RDAP (${input.rdapRegistry})` : 'RDAP / DNS NS',
        signal: rdapMatchedHint
          ? `Registration/nameserver metadata matches official hint ("${rdapMatchedHint}")`
          : `RDAP/NS observed (${input.rdapRegistrar || (input.dnsNameservers || [])[0] || 'recorded'})`,
        verified: Boolean(rdapMatchedHint),
        timestamp: now,
      });
    }

    // Signal E: ASN / Network corroboration
    const asnBlob = `${input.asn || ''} ${input.networkName || ''}`.toLowerCase();
    const asnMatchedHint = ent.expectedAsnHints.find((h) => asnBlob.includes(h));
    if (asnBlob.trim()) {
      signals.push({
        source: 'IP / ASN Telemetry',
        signal: asnMatchedHint
          ? `Network ASN/Org matches expected infrastructure ("${asnMatchedHint}")`
          : `Hosted on ${input.asn || ''} ${input.networkName || ''}`.trim(),
        verified: Boolean(asnMatchedHint),
        timestamp: now,
      });
    }

    // Signal F: OTX validation list
    if (input.otxAllowlisted) {
      signals.push({
        source: 'AlienVault OTX Validation',
        signal: 'Domain listed in global top-domain provenance lists (Tranco/Majestic/Umbrella)',
        verified: true,
        timestamp: now,
      });
    }

    const liveNetworkAttempted =
      input.dnsResolved !== undefined || input.tlsAuthorized !== undefined || Boolean(rdapBlob.trim()) || Boolean(asnBlob.trim());
    const hasInfraCorroboration = Boolean(rdapMatchedHint || asnMatchedHint || input.otxAllowlisted);
    const hasValidTransport = input.dnsResolved !== false && (input.tlsAuthorized === undefined || tlsValid);
    const conflictDetected = Boolean(input.deceptionDetected || input.tlsAuthorized === false || input.dnsResolved === false);
    const corroborated = !conflictDetected && (!liveNetworkAttempted || (hasValidTransport && (hasInfraCorroboration || tlsValid)));

    const status: DomainAuthenticityStatus = conflictDetected
      ? 'unknown_unverified'
      : ownership.isSubdomain
        ? 'official_subdomain'
        : 'official_verified';

    return {
      status,
      label:
        status === 'official_subdomain'
          ? {
              en: `Official Subdomain Verified (${ownership.productName})`,
              ar: `نطاق فرعي رسمي موثق (${ownership.productName})`,
            }
          : status === 'official_verified'
            ? {
                en: `Official Domain Verified (${ownership.productName})`,
                ar: `نطاق رسمي موثق (${ownership.productName})`,
              }
            : {
                en: 'Ownership Verification Conflict Detected',
                ar: 'تعارض في التحقق من أصالة النطاق',
              },
      registrableDomain: psl.eTldPlusOne,
      subdomain: psl.subdomain,
      publicSuffix: psl.publicSuffix,
      parentCompany: ent.parentCompany,
      officialProduct: ownership.productName,
      relationshipLabel: ownership.isSubdomain
        ? {
            en: `Official Subdomain of ${psl.eTldPlusOne} (${ent.parentCompany})`,
            ar: `نطاق فرعي رسمي تابع للنطاق ${psl.eTldPlusOne} (${ent.parentCompany})`,
          }
        : {
            en: `Official Corporate / Product Domain (${ent.parentCompany})`,
            ar: `النطاق الرسمي المعتمد (${ent.parentCompany})`,
          },
      corroborated,
      corroborationSources: signals,
      registrySources: ent.registrySources,
      disclaimer,
      conflictDetected,
      conflictDetail: conflictDetected
        ? {
            en: 'Domain name matches an official registry entry, but live DNS, TLS validation, or URL deception checks failed/conflicted. Do not trust blindly.',
            ar: 'اسم النطاق يطابق السجل الرسمي، لكن فحوصات DNS أو شهادة TLS أو سلامة الرابط الفعلية أظهرت تعارضاً أو فشلاً.',
          }
        : undefined,
    };
  }

  // Case 2: Authorized third-party infrastructure / CDN provider
  if (ownership.authorizedProvider) {
    return {
      status: 'authorized_third_party',
      label: {
        en: `Authorized Third-Party Provider (${ownership.authorizedProvider.name})`,
        ar: `مزود خدمة خارجية معتمد (${ownership.authorizedProvider.name})`,
      },
      registrableDomain: psl.eTldPlusOne,
      subdomain: psl.subdomain,
      publicSuffix: psl.publicSuffix,
      officialProduct: ownership.authorizedProvider.name,
      corroborated: Boolean(input.tlsAuthorized !== false),
      corroborationSources: [
        {
          source: 'Authorized Provider Registry',
          signal: `Recognized ${ownership.authorizedProvider.role.toUpperCase()} infrastructure domain`,
          verified: true,
          timestamp: now,
        },
      ],
      registrySources: ['Authorized Infrastructure Provider List'],
      disclaimer,
      conflictDetected: false,
    };
  }

  // Case 3: Brand name similarity / lookalike (NOT official!)
  if (input.similarityTarget) {
    return {
      status: 'brand_lookalike',
      label: {
        en: `Similar to ${input.similarityTarget.brand} — NOT Official`,
        ar: `نطاق مشابه لعلامة ${input.similarityTarget.brand} — غير رسمي`,
      },
      registrableDomain: psl.eTldPlusOne,
      subdomain: psl.subdomain,
      publicSuffix: psl.publicSuffix,
      corroborated: false,
      corroborationSources: [
        {
          source: 'SM Domain Similarity & PSL Engine',
          signal: input.similarityTarget.reason,
          verified: false,
          timestamp: now,
        },
      ],
      registrySources: [],
      disclaimer: {
        en: 'Domain name similarity to a known brand was detected; impersonation is not automatically proven without corroborating phishing or threat-intelligence evidence.',
        ar: 'تم اكتشاف تشابه في اسم النطاق مع علامة تجارية معروفة، ولم يتم إثبات الانتحال ما لم تتوفر أدلة تقنية داعمة.',
      },
      conflictDetected: false,
    };
  }

  // Case 4: Unrecognized / Unknown domain (does NOT imply malicious!)
  const paasProviderLabel = ownership.isUserContentPaas
    ? psl.eTldPlusOne === 'up.railway.app' || psl.eTldPlusOne === 'railway.app'
      ? 'Railway'
      : psl.eTldPlusOne === 'vercel.app'
        ? 'Vercel'
        : psl.eTldPlusOne === 'netlify.app'
          ? 'Netlify'
          : psl.eTldPlusOne === 'herokuapp.com'
            ? 'Heroku'
            : psl.eTldPlusOne === 'onrender.com'
              ? 'Render'
              : psl.eTldPlusOne === 'fly.dev'
                ? 'Fly.io'
                : psl.eTldPlusOne === 'github.io'
                  ? 'GitHub Pages'
                  : psl.eTldPlusOne === 'pages.dev' || psl.eTldPlusOne === 'workers.dev'
                    ? 'Cloudflare'
                    : psl.eTldPlusOne === 'web.app' || psl.eTldPlusOne === 'firebaseapp.com'
                      ? 'Firebase'
                      : psl.eTldPlusOne
    : undefined;

  const hostingMetadata: DomainHostingMetadata | undefined = ownership.isUserContentPaas
    ? {
        isSharedPaas: true,
        hostingProvider: paasProviderLabel,
        customDomainOwnership: 'unverified',
        websiteIdentity: {
          en: 'Independent Hosted Application',
          ar: 'تطبيق مستضاف مستقل',
        },
      }
    : undefined;

  return {
    status: ownership.isUserContentPaas ? 'partner_or_provider' : 'unknown_unverified',
    label: ownership.isUserContentPaas
      ? {
          en: `Independent Hosted Application on ${paasProviderLabel || psl.eTldPlusOne} (Shared Hosting · Domain Ownership Unverified)`,
          ar: `تطبيق مستضاف مستقل على ${paasProviderLabel || psl.eTldPlusOne} (استضافة مشتركة · ملكية النطاق غير موثقة)`,
        }
      : {
          en: 'Unrecognized / Unverified Domain (Not Proof of Malice)',
          ar: 'نطاق غير معروف / غير موثق رسمياً (لا يعني أنه خبيث)',
        },
    registrableDomain: psl.eTldPlusOne,
    subdomain: psl.subdomain,
    publicSuffix: psl.publicSuffix,
    corroborated: false,
    corroborationSources: [],
    registrySources: [],
    disclaimer: {
      en: ownership.isUserContentPaas
        ? `Hosted on shared PaaS infrastructure (${paasProviderLabel || psl.eTldPlusOne}). Hosting on shared cloud infrastructure is normal and carries 0 risk penalty, while the independent application owner remains unverified.`
        : 'This domain is not in the official corporate registry. Being unrecognized is NOT evidence of malicious intent.',
      ar: ownership.isUserContentPaas
        ? `مستضاف على بنية سحابية مشتركة (${paasProviderLabel || psl.eTldPlusOne}). الاستضافة المشتركة أمر طبيعي ولا يرفع الخطورة، بينما تبقى هوية المالك المستقل للتطبيق غير موثقة.`
        : 'هذا النطاق غير مدرج ضمن السجل الرسمي للشركات المعروفة. عدم معرفة النطاق لا يعني أنه خبيث.',
    },
    conflictDetected: false,
    hostingMetadata,
  };
}
