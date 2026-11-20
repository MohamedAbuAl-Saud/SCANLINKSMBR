# Scan Link SM — Scan Smart. Stay Safe.

**Scan Link SM** is a deterministic, bilingual (English / Arabic RTL) website and URL threat-intelligence platform owned and developed by **Mohamed Abu AlSaud SM**. It contains **zero AI/LLM models** and relies exclusively on verified network telemetry, SSRF-guarded inspection, rule correlation, and live threat-intelligence feeds.

## Security & Inspection Modules
- **URL Structure & Obfuscation**: Checks HTTP/HTTPS syntax, raw IPs, embedded URL parameters, Base64 payloads, double encoding, double extensions, multi-tenant PaaS hosts, and link shorteners.
- **Domain Deception & Official Domain Intelligence**: Verifies official domains and cross-service relationships using Public Suffix List (PSL) `eTLD+1`, RDAP/WHOIS, ASN, TLS corroboration, Unicode Confusables, Punycode/IDN, typosquatting, subdomain spoofing, `@` authority masking, and confirmed Open Redirect relays.
- **SSRF-Guarded Redirect Tracer**: Traces redirect chains hop-by-hop with pinned DNS resolution while validating every resolved IP against private IPv4/IPv6 ranges, localhost, and cloud metadata endpoints (`169.254.169.254`).
- **Domain & DNS Intelligence**: Queries authoritative IANA RDAP bootstrap servers with port-43 WHOIS fallback, OS DNS + Cloudflare DoH (`DO=1` DNSSEC validation & TTL Fast Flux checks), SOA/PTR records, DNS/CDN detection, and SPF/DMARC posture.
- **SSL/TLS Inspection**: Direct TLS socket inspection verifying X.509 certificate trust chains, depth, key bits, signature algorithm, weak protocol/cipher detection, expiration, SAN coverage, and Certificate Transparency (`crt.sh`) logs.
- **Content, Phishing & Brand Impersonation**: Non-executing DOM parsing (`cheerio`) detecting credential harvesting, fake lures, popups, auto-redirects, obfuscated scripts, and brand impersonation.
- **File & Download Intelligence**: Bounded in-memory inspection (`512 KB` slice), SHA-256 hashing, and magic-byte vs declared MIME mismatch detection without writing or executing files.
- **External Threat Feeds & Multi-Signal Correlation**: Correlates VirusTotal v3, URLhaus (`abuse.ch`), OpenPhish, PhishStats, Cloudflare Security DNS (`1.1.1.2`), AlienVault OTX, URLScan.io, Shodan InternetDB, and Feodo Tracker C2.
- **Visual Preview Gateway**: Backend-only `ScreenshotNeo` capture support when `SCREENSHOTNEO_ACCESS_KEY` is configured on the server.

## Official Project Identity
- **Platform**: Scan Link SM
- **Owner & Developer 1**: Mohamed Abu AlSaud SM
- **Developer 2**: Omar Mohamed (عمر محمد)
- **Official Contact**: [@A_Y_TR](https://t.me/A_Y_TR)
- **Licensing**: Proprietary closed-source software. All rights reserved.
