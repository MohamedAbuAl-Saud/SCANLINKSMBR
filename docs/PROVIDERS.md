# Threat Intelligence Providers & Limits

| Provider | Key Required | Env Variable | Notes |
| --- | --- | --- | --- |
| Cloudflare Security DNS (`1.1.1.2`) | No | — | Real-time DoH malware/phishing sinkhole verification |
| PhishStats Public Feed | No | — | Live public phishing database lookup |
| OpenPhish Community Feed | No | — | Live community phishing feed cached locally for 30 minutes |
| Shodan InternetDB | No | — | Open IP port, CVE, and compromised tag lookup |
| Feodo Tracker C2 (`abuse.ch`) | No | — | Live botnet C2 IP blocklist cached every 30 minutes |
| URLScan.io Public Search | Optional | `URLSCAN_API_KEY` | Public search endpoint; upstream rate limits apply without key |
| AlienVault OTX | Optional | `OTX_API_KEY` | Domain & IPv4 pulse lookup with allowlist filtering |
| IANA / Registry RDAP & WHOIS | No | — | Direct registry RDAP lookup via IANA bootstrap & port-43 WHOIS |
| Cloudflare DoH & OS DNS | No | — | Dual DNS validation via `1.1.1.1/dns-query` (`DO=1` DNSSEC/TTL) & Node DNS |
| Certificate Transparency (`crt.sh`) | No | — | Public CT log queries |
| URLhaus (`abuse.ch`) | Yes | `URLHAUS_AUTH_KEY` | Backend Auth-Key required |
| VirusTotal API v3 | Yes | `VIRUSTOTAL_API_KEY` | Backend API key required (URL / Domain / IP) |
