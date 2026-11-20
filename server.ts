import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { z } from 'zod';
import { createServer as createViteServer, type ViteDevServer } from 'vite';
import { getJobEmitter, getScanJob, startScanJob } from './server/scanManager.ts';
import { listConfiguredProviders } from './server/providers/threatIntelManager.ts';
import { testScreenshotNeoCapture } from './server/analyzers/screenshotEngine.ts';
import { getOfficialRegistryStats } from './server/analyzers/officialDomainRegistry.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 3000);
const IS_PROD =
  process.env.NODE_ENV === 'production' ||
  (Boolean(process.env.RAILWAY_ENVIRONMENT || process.env.RAILWAY_SERVICE_ID || process.env.RAILWAY_PROJECT_ID) &&
    process.env.NODE_ENV !== 'development');

const VALID_SPA_ROUTES = new Set([
  '/',
  '/scanner',
  '/providers',
  '/history',
  '/about',
  '/privacy',
  '/terms',
]);

const VALID_ERROR_CODES = new Set([401, 403, 404, 429, 500, 502, 503]);

const SENSITIVE_PATH_PREFIXES = ['/server', '/tests', '/docs', '/.git', '/.aistudio'];
const SENSITIVE_EXACT_PATHS = new Set([
  '/server.ts',
  '/package.json',
  '/package-lock.json',
  '/bun.lock',
  '/tsconfig.json',
  '/vite.config.ts',
  '/metadata.json',
  '/readme.md',
  '/security.md',
  '/license',
]);
const SENSITIVE_EXTENSIONS = /\.(env|db|sqlite|sqlite3|sql|bak|orig|log|pem|key|map)$/i;

const startScanSchema = z.object({
  url: z.string().trim().min(1, 'URL is required').max(2048, 'URL exceeds 2048 character limit'),
  viewport: z.enum(['desktop', 'mobile', 'full_page']).optional().default('desktop'),
  disabledProviders: z.array(z.string().max(64)).max(20).optional().default([]),
});

function sanitizeUrlForAuditLog(rawUrl: string): string {
  try {
    const u = new URL(/^[a-z]+:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`);
    return `${u.protocol}//${u.hostname}${u.pathname}`;
  } catch {
    return '[invalid-url]';
  }
}

function redactSecretValues(input: string): string {
  const secretKeys = [
    process.env.VIRUSTOTAL_API_KEY,
    process.env.URLHAUS_AUTH_KEY,
    process.env.URLSCAN_API_KEY,
    process.env.OTX_API_KEY,
    process.env.SCREENSHOTNEO_ACCESS_KEY,
    process.env.CLOUD_BROWSER_API_KEY,
    process.env.CLOUD_BROWSER_ENDPOINT,
  ].filter((v): v is string => Boolean(v && v.length > 4));
  let out = input;
  for (const secret of secretKeys) {
    out = out.split(secret).join('[REDACTED]');
  }
  return out.replace(/\/[^\s]*\/(server|src|node_modules)\/[^\s]*/g, '[internal-path]');
}

function resolvePublicBaseUrl(req: express.Request): string {
  const configured = (process.env.APP_URL || '').trim().replace(/\/+$/, '');
  if (/^https?:\/\/[^/]+$/i.test(configured) && !configured.includes('your-domain.example')) {
    return configured;
  }
  const forwardedProto = req.headers['x-forwarded-proto'];
  const proto = (Array.isArray(forwardedProto) ? forwardedProto[0] : forwardedProto) || req.protocol || 'https';
  const forwardedHost = req.headers['x-forwarded-host'];
  const host = (Array.isArray(forwardedHost) ? forwardedHost[0] : forwardedHost) || req.get('host') || 'localhost:3000';
  return `${proto.split(',')[0].trim()}://${host.split(',')[0].trim()}`;
}

function isOriginPermitted(req: express.Request, allowedOrigins: string[]): boolean {
  const origin = req.headers.origin;
  if (!origin) return true;
  if (allowedOrigins.includes('*') || allowedOrigins.includes(origin)) return true;

  const host = req.headers.host;
  const forwardedHost = req.headers['x-forwarded-host'];
  const effectiveHost = (Array.isArray(forwardedHost) ? forwardedHost[0] : forwardedHost) || host;

  if (allowedOrigins.length === 0) return true;
  if (!effectiveHost) return false;

  try {
    const originUrl = new URL(origin);
    const originHost = originUrl.host.toLowerCase();
    const originHostname = originUrl.hostname.toLowerCase();
    const cleanEffective = effectiveHost.split(',')[0].trim().toLowerCase();
    const cleanEffectiveName = cleanEffective.split(':')[0];
    if (
      originHost === cleanEffective ||
      originHostname === cleanEffectiveName ||
      originHostname.endsWith('.run.app')
    ) {
      return true;
    }
  } catch {
    return false;
  }
  return false;
}

export async function createApp(options: { enableVite?: boolean; viteHmr?: boolean } = {}) {
  const app = express();
  const useVite = options.enableVite ?? !IS_PROD;
  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  const allowedOrigins = [
    ...(process.env.ALLOWED_ORIGINS || '').split(','),
    process.env.APP_URL || '',
  ]
    .map((s) => s.trim().replace(/\/+$/, ''))
    .filter((s) => Boolean(s) && !s.includes('your-domain.example'));

  let vite: ViteDevServer | null = null;

  const renderHtmlStatusPage = async (res: express.Response, status: number) => {
    try {
      const targetIndex = useVite
        ? path.resolve(__dirname, 'index.html')
        : path.resolve(__dirname, 'dist', 'index.html');
      const fallbackIndex = path.resolve(__dirname, 'index.html');
      const htmlPath = fs.existsSync(targetIndex) ? targetIndex : fallbackIndex;
      if (!fs.existsSync(htmlPath)) {
        res.status(status).type('text/plain').send(`HTTP ${status}`);
        return;
      }
      let html = fs.readFileSync(htmlPath, 'utf-8');
      if (useVite && vite) {
        html = await vite.transformIndexHtml('/', html);
      }
      if (status !== 200) {
        html = html.replace(
          '<head>',
          `<head>\n    <meta name="robots" content="noindex, nofollow" />\n    <meta name="scanlink-error-code" content="${status}" />`
        );
      }
      res.status(status).setHeader('Content-Type', 'text/html; charset=utf-8').send(html);
    } catch (err) {
      console.error('[ScanLinkSM] HTML render error:', redactSecretValues((err as Error).message));
      res.status(status).type('text/plain').send(`HTTP ${status}`);
    }
  };

  // 1. Pre-Routing Security Shield: block path traversal, dotfiles, secrets, source/backup exposure
  app.use(async (req, res, next) => {
    const rawUrl = req.originalUrl || req.url || '/';
    const accept = String(req.headers.accept || '').toLowerCase();
    const secDest = String(req.headers['sec-fetch-dest'] || '').toLowerCase();
    const isAssetSubrequest = ['script', 'style', 'image', 'font', 'manifest', 'worker', 'audio', 'video'].includes(
      secDest
    );

    let decodedPath = req.path;
    try {
      decodedPath = decodeURIComponent(req.path);
    } catch {
      if (req.path.startsWith('/api')) {
        res.status(400).json({ error: 'Malformed request path encoding.' });
      } else if (req.method === 'GET' && !isAssetSubrequest && accept.includes('text/html')) {
        await renderHtmlStatusPage(res, 403);
      } else {
        res.status(400).type('text/plain').send('Bad Request');
      }
      return;
    }

    const lowerPath = decodedPath.toLowerCase();
    const lowerRaw = rawUrl.toLowerCase();
    const wantsHtmlErrorPage =
      req.method === 'GET' && !lowerPath.startsWith('/api') && !isAssetSubrequest && accept.includes('text/html');

    // Block null bytes, backslashes, or dot-dot traversal
    if (
      lowerRaw.includes('%00') ||
      decodedPath.includes('\0') ||
      decodedPath.includes('\\') ||
      /(^|\/)\.\.(\/|$)/.test(decodedPath) ||
      lowerRaw.includes('%2e%2e')
    ) {
      if (lowerPath.startsWith('/api')) {
        res.status(400).json({ error: 'Invalid path traversal sequence rejected.' });
      } else if (wantsHtmlErrorPage) {
        await renderHtmlStatusPage(res, 403);
      } else {
        res.status(403).type('text/plain').send('Forbidden');
      }
      return;
    }

    // Allow Vite dev-mode pre-bundled dependencies (/node_modules/.vite/deps/...) while blocking all other dotfiles
    const isViteDevCachePath =
      useVite && (lowerPath.startsWith('/node_modules/.vite/') || lowerPath.startsWith('/.vite/'));

    // Block hidden dotfiles (.env, .git, .htaccess, etc.) except .well-known and Vite's dev dependency cache
    const segments = lowerPath.split('/').filter(Boolean);
    if (
      segments.some(
        (seg) =>
          seg.startsWith('.') &&
          seg !== '.well-known' &&
          !(isViteDevCachePath && (seg === '.vite' || seg === '.vite-temp'))
      )
    ) {
      if (wantsHtmlErrorPage) {
        await renderHtmlStatusPage(res, 403);
      } else {
        res.status(403).type('application/json').json({ error: 'Access to hidden or configuration files is forbidden.' });
      }
      return;
    }

    // Block internal backend directories & config/backup/source files
    const hitsSensitivePrefix =
      SENSITIVE_PATH_PREFIXES.some((prefix) => lowerPath === prefix || lowerPath.startsWith(`${prefix}/`)) ||
      (IS_PROD &&
        (lowerPath === '/src' ||
          (lowerPath.startsWith('/src/') && !lowerPath.startsWith('/src/assets/')) ||
          lowerPath.startsWith('/node_modules/')));

    const hitsSensitiveFile =
      SENSITIVE_EXACT_PATHS.has(lowerPath) ||
      (SENSITIVE_EXTENSIONS.test(lowerPath) && !(useVite && lowerPath.endsWith('.map')));

    // Even in dev mode, direct browser document navigation to /src/* or /node_modules/* should show the 403 error page
    const hitsDirectSourceDocument =
      useVite &&
      wantsHtmlErrorPage &&
      (lowerPath === '/src' || lowerPath.startsWith('/src/') || lowerPath.startsWith('/node_modules/'));

    if (hitsSensitivePrefix || hitsSensitiveFile || hitsDirectSourceDocument) {
      if (wantsHtmlErrorPage) {
        await renderHtmlStatusPage(res, 403);
      } else {
        res.status(403).type('application/json').json({ error: 'Access to protected server resources is forbidden.' });
      }
      return;
    }

    next();
  });

  // 2. Strict Security Headers (Helmet + HSTS + Permissions-Policy)
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: IS_PROD ? ["'self'"] : ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
          styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
          fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
          imgSrc: ["'self'", 'data:', 'blob:'],
          manifestSrc: ["'self'"],
          connectSrc: IS_PROD ? ["'self'"] : ["'self'", 'ws:', 'wss:'],
          objectSrc: ["'none'"],
          baseUri: ["'self'"],
          formAction: ["'self'"],
          frameAncestors: [
            "'self'",
            'https://*.google.com',
            'https://*.googleusercontent.com',
            'https://*.usercontent.goog',
            'https://*.run.app',
          ],
          upgradeInsecureRequests: null,
        },
      },
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
      hsts: IS_PROD ? { maxAge: 31536000, includeSubDomains: true } : false,
      crossOriginEmbedderPolicy: false,
      frameguard: false,
    })
  );

  app.use((_req, res, next) => {
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    next();
  });

  // 3. Robust CORS & Same-Host Proxy-Aware Policy
  app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin && isOriginPermitted(req, allowedOrigins)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }
    next();
  });

  app.use('/api', express.json({ limit: '64kb' }));

  const scanLimiter = rateLimit({
    windowMs: Number(process.env.SCAN_RATE_LIMIT_WINDOW_MS || 60000),
    max: Number(process.env.SCAN_RATE_LIMIT_MAX || 20),
    standardHeaders: true,
    legacyHeaders: false,
    message: {
      error: 'Too many scan requests from this client. Please wait before submitting another URL.',
    },
  });

  const verifyLimiter = rateLimit({
    windowMs: 60000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
      error: 'Too many screenshot verification requests. Please wait a minute.',
    },
  });

  // 4. Dynamic SEO Endpoints: /robots.txt & /sitemap.xml
  app.get('/robots.txt', (req, res) => {
    const baseUrl = resolvePublicBaseUrl(req);
    const body = [
      'User-agent: *',
      'Allow: /',
      'Allow: /about',
      'Allow: /providers',
      'Allow: /privacy',
      'Allow: /terms',
      'Disallow: /api/',
      'Disallow: /history',
      'Disallow: /scanner',
      'Disallow: /error/',
      `Sitemap: ${baseUrl}/sitemap.xml`,
      '',
    ].join('\n');
    res.status(200).type('text/plain; charset=utf-8').send(body);
  });

  app.get('/sitemap.xml', (req, res) => {
    const baseUrl = resolvePublicBaseUrl(req);
    const lastmod = new Date().toISOString().split('T')[0];
    const entries = [
      { path: '/', priority: '1.0', changefreq: 'daily' },
      { path: '/providers', priority: '0.8', changefreq: 'weekly' },
      { path: '/about', priority: '0.7', changefreq: 'monthly' },
      { path: '/privacy', priority: '0.5', changefreq: 'monthly' },
      { path: '/terms', priority: '0.5', changefreq: 'monthly' },
    ];
    const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${entries
      .map(
        (e) =>
          `  <url>\n    <loc>${baseUrl}${e.path}</loc>\n    <lastmod>${lastmod}</lastmod>\n    <changefreq>${e.changefreq}</changefreq>\n    <priority>${e.priority}</priority>\n  </url>`
      )
      .join('\n')}\n</urlset>\n`;
    res.status(200).type('application/xml; charset=utf-8').send(xml);
  });

  // 5. Backend API Routes
  app.get('/api/health', (_req, res) => {
    const registryStats = getOfficialRegistryStats();
    res.json({
      status: 'ok',
      service: 'Scan Link SM',
      engineMode: 'deterministic',
      timestamp: new Date().toISOString(),
      officialRegistryStats: {
        entityCount: registryStats.entityCount,
        officialDomainCount: registryStats.officialDomainCount,
        authorizedProviderCount: registryStats.authorizedProviderCount,
        paasSuffixCount: registryStats.paasSuffixCount,
        categoryCount: registryStats.categories.length,
      },
      capabilities: {
        ssrfGuard: true,
        dnsAndRdap: true,
        tlsSocketInspection: true,
        staticHtmlAndBrandAnalysis: true,
        websiteSourceIntelligence: true,
        multiPageDiscovery: true,
        inMemoryFileHeaderCheck: true,
        screenshotNeoConfigured: Boolean(process.env.SCREENSHOTNEO_ACCESS_KEY),
        externalCloudBrowserConfigured: Boolean(
          (process.env.CLOUD_BROWSER_ENDPOINT || '').trim() && (process.env.CLOUD_BROWSER_API_KEY || '').trim()
        ),
      },
    });
  });

  app.get('/api/providers', (_req, res) => {
    res.json({
      providers: listConfiguredProviders(),
      screenshot: {
        provider: 'ScreenshotNeo',
        configured: Boolean(process.env.SCREENSHOTNEO_ACCESS_KEY),
      },
      levelB: {
        provider: 'External Cloud Browser Service',
        configured: Boolean(
          (process.env.CLOUD_BROWSER_ENDPOINT || '').trim() && (process.env.CLOUD_BROWSER_API_KEY || '').trim()
        ),
      },
    });
  });

  app.get('/api/screenshot/verify', verifyLimiter, async (_req, res) => {
    try {
      const result = await testScreenshotNeoCapture('https://example.com');
      res.json(result);
    } catch (err) {
      console.error('[ScanLinkSM] Screenshot verify failed:', redactSecretValues((err as Error).message));
      res.status(502).json({ success: false, error: 'Visual verification gateway temporarily unavailable.' });
    }
  });

  app.post('/api/scans', scanLimiter, (req, res) => {
    if (!isOriginPermitted(req, allowedOrigins)) {
      res.status(403).json({ error: 'Cross-origin scan submission rejected by security policy.' });
      return;
    }

    if (!req.is('application/json')) {
      res.status(415).json({ error: 'Content-Type must be application/json.' });
      return;
    }

    const parsed = startScanSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({
        error: parsed.error.issues[0]?.message || 'Invalid scan request payload.',
      });
      return;
    }

    const job = startScanJob(parsed.data);
    console.info(
      `[ScanLinkSM] scan=${job.scanId} target=${sanitizeUrlForAuditLog(parsed.data.url)} viewport=${parsed.data.viewport}`
    );

    res.status(202).json({
      scanId: job.scanId,
      status: job.status,
      progressPercent: job.progressPercent,
      stages: job.stages,
    });
  });

  app.get('/api/scans/:scanId', (req, res) => {
    const scanId = String(req.params.scanId || '').trim();
    if (!/^[0-9a-f-]{36}$/i.test(scanId)) {
      res.status(400).json({ error: 'Invalid scanId format.' });
      return;
    }
    const job = getScanJob(scanId);
    if (!job) {
      res.status(404).json({ error: 'Scan report not found or expired from memory.' });
      return;
    }
    res.json(job);
  });

  app.get('/api/scans/:scanId/stream', (req, res) => {
    const scanId = String(req.params.scanId || '').trim();
    if (!/^[0-9a-f-]{36}$/i.test(scanId)) {
      res.status(400).json({ error: 'Invalid scanId format.' });
      return;
    }
    const job = getScanJob(scanId);
    const emitter = getJobEmitter(scanId);
    if (!job || !emitter) {
      res.status(404).json({ error: 'Scan job not found.' });
      return;
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();

    const sendSnapshot = (payload: typeof job) => {
      res.write(`data: ${JSON.stringify(payload)}\n\n`);
      if (payload.status === 'completed' || payload.status === 'failed') {
        cleanup();
        res.end();
      }
    };

    const onUpdate = (updated: typeof job) => sendSnapshot(updated);
    const cleanup = () => {
      emitter.off('update', onUpdate);
    };

    req.on('close', cleanup);
    emitter.on('update', onUpdate);
    sendSnapshot(job);
  });

  app.use('/api', (_req, res) => {
    res.status(404).type('application/json').json({ error: 'API endpoint not found.' });
  });

  // 6. Sanitized Express Error Handler (never leaks stack traces, paths, or secrets)
  app.use(
    (
      err: Error & { status?: number; statusCode?: number; type?: string },
      _req: express.Request,
      res: express.Response,
      _next: express.NextFunction
    ) => {
      if (res.headersSent) return;
      const isMalformedJson = err.type === 'entity.parse.failed' || err instanceof SyntaxError;
      const statusCode = isMalformedJson ? 400 : err.status || err.statusCode || 500;
      console.error(`[ScanLinkSM] HTTP ${statusCode}:`, redactSecretValues(err.message || 'error'));
      const safeMessage = isMalformedJson
        ? 'Malformed JSON request payload.'
        : statusCode >= 500
          ? 'An internal server error occurred.'
          : err.message || 'Request rejected.';
      res.status(statusCode).type('application/json').json({ error: safeMessage });
    }
  );

  // Helper to determine true HTTP status code for SPA / Error routes
  const resolveRouteStatus = (reqPath: string): number => {
    const normalized = reqPath === '/' ? '/' : reqPath.replace(/\/+$/, '');
    if (VALID_SPA_ROUTES.has(normalized)) return 200;
    const errMatch = normalized.match(/^\/error\/(\d{3})$/);
    if (errMatch) {
      const code = Number(errMatch[1]);
      return VALID_ERROR_CODES.has(code) ? code : 404;
    }
    return 404;
  };

  // 7. Static / Vite Middleware + Real HTTP Status Code Routing (403/404 render ErrorView HTML with real status)
  if (useVite) {
    vite = await createViteServer({
      server: {
        middlewareMode: true,
        ...(options.viteHmr === false ? { hmr: false } : {}),
      },
      appType: 'custom',
    });
    app.locals.viteServer = vite;
    app.use(vite.middlewares);

    app.get('*', async (req, res) => {
      const status = resolveRouteStatus(req.path);
      await renderHtmlStatusPage(res, status);
    });
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    const publicPath = path.resolve(__dirname, 'public');
    const distIndexPath = path.join(distPath, 'index.html');
    app.use(
      express.static(distPath, {
        dotfiles: 'deny',
        index: false,
      })
    );
    app.use(
      express.static(publicPath, {
        dotfiles: 'deny',
        index: false,
      })
    );

    app.get('*', async (req, res) => {
      const accept = String(req.headers.accept || '').toLowerCase();
      const secDest = String(req.headers['sec-fetch-dest'] || '').toLowerCase();
      const isAssetSubrequest = ['script', 'style', 'image', 'font', 'manifest', 'worker', 'audio', 'video'].includes(
        secDest
      );
      const wantsHtml = req.method === 'GET' && !isAssetSubrequest && accept.includes('text/html');

      // Asset subrequests or non-HTML fetches for missing asset extensions get 404 plain text
      if (/\.(js|css|png|jpg|jpeg|webp|svg|ico|woff2?|json|xml|txt)$/i.test(req.path) && !wantsHtml) {
        res.status(404).type('text/plain').send('Not Found');
        return;
      }

      const status = resolveRouteStatus(req.path);
      if (fs.existsSync(distIndexPath)) {
        await renderHtmlStatusPage(res, status);
      } else {
        res.status(status).type('text/plain').send(status === 404 ? '404 Not Found' : 'Service Ready');
      }
    });
  }

  return app;
}

async function bootstrap() {
  const app = await createApp();
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Scan Link SM deterministic server listening on http://0.0.0.0:${PORT}`);
  });
}

const isDirectEntry =
  Boolean(process.argv[1]) && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (isDirectEntry) {
  bootstrap().catch((err) => {
    console.error('Failed to start Scan Link SM server:', redactSecretValues((err as Error).message));
    process.exit(1);
  });
}
