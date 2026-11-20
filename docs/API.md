# Scan Link SM — REST & SSE API Reference

## `GET /api/health`
Returns service health and active deterministic inspection capabilities.

## `GET /api/providers`
Returns configuration metadata and operational states (`active`, `configured`, `disabled`, `rate_limited`, `unavailable`, `auth_required`) plus last successful lookup timestamps without ever exposing secret values.

## `POST /api/scans`
Starts an asynchronous 10-stage deterministic scan job.

Request JSON:
```json
{
  "url": "https://example.com",
  "viewport": "desktop",
  "disabledProviders": []
}
```
- `viewport`: `"desktop" | "mobile" | "full_page"` (defaults to `"desktop"`)
- Returns HTTP `202` with `scanId`, `status`, `progressPercent`, and initial 10 `stages`.

## `GET /api/scans/:scanId`
Polls current `ScanJobState` and completed `ScanReport`.

## `GET /api/scans/:scanId/stream`
Server-Sent Events (`text/event-stream`) emitting live `ScanJobState` updates until `completed` or `failed`.
