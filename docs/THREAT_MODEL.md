# Scan Link SM — Threat Model & Scoring Philosophy

## Core Guarantees
1. **No AI/LLM Dependency**: Zero generative AI calls exist anywhere in the runtime. Every score is reproducible from recorded `CheckFinding` weights and multi-signal correlation rules.
2. **Never Assume Safety From Transport Encryption**: Valid HTTPS certificates prove transport encryption to the domain holder—not legitimacy. Phishing hosted on trusted PaaS domains (e.g., `*.appspot.com`, `*.web.app`, `*.pages.dev`) frequently carries valid wildcard TLS certs.
3. **Never Count Missing Providers as Clean**: Unconfigured, rate-limited, or failed providers map to `unknown` / `unavailable` / `auth_required` and reduce confidence rather than reducing risk.
4. **Correlation Rules**:
   - External threat feed hit -> forced `CRITICAL`.
   - Unwrapped password field outside `<form>` + deceptive alert/lure/missing `<title>` -> forced `HIGH` or `CRITICAL`.
   - Credential fields + fake software update / social engineering / cross-origin form / brand impersonation -> elevated score floor (`>= 66–82`).
   - Brand impersonation + newly registered domain or shared PaaS subdomain -> elevated score floor (`>= 74`).
