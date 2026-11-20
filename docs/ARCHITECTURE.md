# Scan Link SM — Architecture & Deployment Guide

## System Topology
1. **Frontend (`src/`)**: React 19 + TypeScript + Tailwind CSS SPA providing bilingual (English LTR / Arabic RTL) views, pure-black Dark Mode & Light Mode, interactive evidence analytics, Providers status dashboard, and consented local history. Contains zero secrets or AI models.
2. **Backend API & Deterministic Engine (`server.ts` + `server/`)**: Express server hardened with Helmet CSP, `express-rate-limit`, strict CORS, Origin/CSRF check on `POST /api/scans`, Zod payload validation, and pinned-IP SSRF protection (`ssrfGuard.ts`). Streams stage completion events via Server-Sent Events (`/api/scans/:id/stream`).
3. **Optional Isolated Browser Worker (`screenshot-worker/` -> `SCREENSHOT_WORKER_URL`)**: For full live visual captures, deploy the standalone Playwright/Chromium microservice in `screenshot-worker/` on an egress-firewalled subnet (blocking RFC1918 and cloud metadata IPs) with strict memory/CPU/timeout limits.
4. **Optional Screenshotlayer Fallback (`SCREENSHOTLAYER_API_KEY`)**: Backend-only fallback used when the isolated worker is unreachable or unconfigured, governed by `SCREENSHOTLAYER_MONTHLY_QUOTA`.
