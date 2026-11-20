import * as acorn from 'acorn';
import * as cheerio from 'cheerio';
import type {
  BilingualText,
  CheckFinding,
  CookieAuditItem,
  CookieAuditSummary,
  XssAssessmentData,
  XssIndicatorItem,
} from '../types.ts';

export interface XssAnalyzerInput {
  submittedUrl: string;
  finalUrl: string;
  headers: Record<string, string>;
  htmlBuffer?: Buffer;
  fetchedScripts?: { url: string; code: string }[];
  cookieAudit?: CookieAuditSummary;
  contentBlocked?: boolean;
}

interface AstNode {
  type: string;
  start: number;
  end: number;
  loc?: { start: { line: number; column: number } };
  [key: string]: any;
}

const SANITIZER_FN_RE =
  /(?:DOMPurify\.sanitize|sanitizeHtml|sanitize|escapeHtml|htmlEscape|encodeURIComponent|encodeURI|parseInt|parseFloat|Number|Boolean)\b/i;

const DOM_TAINT_SOURCES_RE =
  /^(?:window\.)?(?:location\.(?:search|hash|href)|document\.(?:URL|documentURI|referrer)|window\.name)$/;

const COMMON_BENIGN_PARAM_VALUES = new Set([
  'en',
  'ar',
  'fr',
  'es',
  'de',
  'true',
  'false',
  'null',
  'none',
  'dark',
  'light',
  'home',
  'index',
  'page',
  'desktop',
  'mobile',
  'utf8',
  'utf-8',
]);

function htmlEscapeSample(raw: string): string {
  return raw
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function getCalleePath(node: AstNode | null | undefined): string {
  if (!node) return '';
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'ThisExpression') return 'this';
  if (node.type === 'MemberExpression') {
    const obj = getCalleePath(node.object);
    let prop = '';
    if (!node.computed && node.property?.type === 'Identifier') {
      prop = node.property.name;
    } else if (node.computed && node.property?.type === 'Literal' && typeof node.property.value === 'string') {
      prop = node.property.value;
    }
    return obj && prop ? `${obj}.${prop}` : obj || prop;
  }
  if (node.type === 'ChainExpression') return getCalleePath(node.expression);
  return '';
}

function safeSnippet(code: string, node: AstNode | undefined, max = 150): string {
  if (!node || typeof node.start !== 'number' || typeof node.end !== 'number') return '';
  return code.slice(node.start, Math.min(node.end, node.start + max)).replace(/\s+/g, ' ').trim();
}

function walkChildren(node: any, cb: (child: AstNode) => void): void {
  if (!node || typeof node !== 'object') return;
  for (const key of Object.keys(node)) {
    if (key === 'loc' || key === 'start' || key === 'end' || key === 'type') continue;
    const val = node[key];
    if (Array.isArray(val)) {
      for (const item of val) {
        if (item && typeof item.type === 'string') cb(item);
      }
    } else if (val && typeof val.type === 'string') {
      cb(val);
    }
  }
}

function analyzeCspHeader(cspHeader?: string): {
  cspStatus: 'strict' | 'weak' | 'missing';
  weakDirectives: string[];
} {
  if (!cspHeader || !cspHeader.trim()) {
    return { cspStatus: 'missing', weakDirectives: [] };
  }

  const directives = cspHeader
    .split(';')
    .map((d) => d.trim())
    .filter(Boolean);
  const scriptDir =
    directives.find((d) => /^script-src\b/i.test(d)) ||
    directives.find((d) => /^default-src\b/i.test(d)) ||
    '';

  const weakTokens: string[] = [];
  if (/'unsafe-inline'/i.test(scriptDir)) weakTokens.push("'unsafe-inline'");
  if (/'unsafe-eval'/i.test(scriptDir)) weakTokens.push("'unsafe-eval'");
  if (/(?:^|\s)\*(?:\s|$)/i.test(scriptDir)) weakTokens.push('wildcard (*)');
  if (/(?:^|\s)data:/i.test(scriptDir)) weakTokens.push('data:');
  if (!scriptDir) weakTokens.push('missing script-src/default-src');

  return {
    cspStatus: weakTokens.length > 0 ? 'weak' : 'strict',
    weakDirectives: weakTokens,
  };
}

function exprUsesDomTaint(
  node: AstNode | null | undefined,
  taintedVars: Map<string, string>,
  depth = 0
): string | null {
  if (!node || depth > 8) return null;

  if (node.type === 'Identifier') {
    return taintedVars.get(node.name) || null;
  }

  if (node.type === 'MemberExpression') {
    const path = getCalleePath(node);
    if (DOM_TAINT_SOURCES_RE.test(path)) return path;
    // Handle nested property access like URLSearchParams.get('x') result or event.data
    if (path === 'event.data' || path === 'e.data' || path === 'ev.data' || path === 'msg.data') {
      return path;
    }
    return exprUsesDomTaint(node.object, taintedVars, depth + 1);
  }

  if (node.type === 'NewExpression') {
    const callee = getCalleePath(node.callee);
    if (callee === 'URLSearchParams' && node.arguments?.[0]) {
      return exprUsesDomTaint(node.arguments[0], taintedVars, depth + 1) || 'location.search';
    }
    if (callee === 'URL' && node.arguments?.[0]) {
      return exprUsesDomTaint(node.arguments[0], taintedVars, depth + 1);
    }
  }

  if (node.type === 'CallExpression') {
    const callee = getCalleePath(node.callee);
    if (SANITIZER_FN_RE.test(callee)) {
      return null;
    }
    if (callee.endsWith('.get') || callee.endsWith('.getAll')) {
      const obj = getCalleePath(node.callee?.object);
      if (taintedVars.has(obj) || /URLSearchParams/i.test(safeSnippet('', node.callee)) || /params|searchParams|query/i.test(obj)) {
        const inner = exprUsesDomTaint(node.callee?.object, taintedVars, depth + 1);
        if (inner) return `${inner}.get(${node.arguments?.[0]?.value ?? ''})`;
      }
    }
    if (callee === 'atob' || callee === 'window.atob' || callee === 'decodeURIComponent' || callee === 'decodeURI' || callee === 'unescape' || callee.endsWith('.trim') || callee.endsWith('.slice') || callee.endsWith('.replace')) {
      const prefix = callee === 'atob' || callee === 'window.atob' ? 'atob(' : '';
      const suffix = prefix ? ')' : '';
      if (node.callee?.object) {
        const innerObj = exprUsesDomTaint(node.callee.object, taintedVars, depth + 1);
        if (innerObj) return `${prefix}${innerObj}${suffix}`;
      }
      if (node.arguments?.[0]) {
        const innerArg = exprUsesDomTaint(node.arguments[0], taintedVars, depth + 1);
        if (innerArg) return `${prefix}${innerArg}${suffix}`;
      }
    }
    return null;
  }

  if (node.type === 'BinaryExpression' && node.operator === '+') {
    return (
      exprUsesDomTaint(node.left, taintedVars, depth + 1) ||
      exprUsesDomTaint(node.right, taintedVars, depth + 1)
    );
  }

  if (node.type === 'TemplateLiteral') {
    for (const ex of node.expressions || []) {
      const hit = exprUsesDomTaint(ex, taintedVars, depth + 1);
      if (hit) return hit;
    }
  }

  if (node.type === 'ConditionalExpression') {
    return (
      exprUsesDomTaint(node.consequent, taintedVars, depth + 1) ||
      exprUsesDomTaint(node.alternate, taintedVars, depth + 1)
    );
  }

  if (node.type === 'LogicalExpression') {
    return (
      exprUsesDomTaint(node.left, taintedVars, depth + 1) ||
      exprUsesDomTaint(node.right, taintedVars, depth + 1)
    );
  }

  return null;
}

const DEV_BUNDLER_XSS_RE =
  /(?:\/@vite\/client|\/@react-refresh|\/__vite_ping|\/vite-hmr|\/node_modules\/\.vite\/|\/webpack-dev-server|\/sockjs-node)(?:$|[?#])/i;

function inspectDomXssAst(
  scripts: { source: string; code: string }[]
): XssIndicatorItem[] {
  const indicators: XssIndicatorItem[] = [];
  const seen = new Set<string>();

  for (const script of scripts) {
    if (!script.code || script.code.length > 350000) continue;
    if (DEV_BUNDLER_XSS_RE.test(script.source)) continue;
    let ast: AstNode | null = null;
    for (const sourceType of ['module', 'script'] as const) {
      try {
        ast = acorn.parse(script.code, {
          ecmaVersion: 'latest',
          sourceType,
          allowReturnOutsideFunction: true,
          locations: true,
        }) as unknown as AstNode;
        break;
      } catch {
        // retry
      }
    }
    if (!ast) continue;

    const taintedVars = new Map<string, string>();
    let inMessageListener = false;

    const recordDomSink = (sinkName: string, sourceExpr: string, node: AstNode, isDirectHighRisk: boolean) => {
      const isDecodedParam = /^atob\(/i.test(sourceExpr);
      const isPostMsg = /postMessage/i.test(sourceExpr);
      const indType: XssIndicatorItem['type'] = isPostMsg
        ? 'unsafe_postmessage'
        : isDecodedParam
          ? 'decoded_param_sink'
          : 'dom_sink';
      const key = `${indType}|${sinkName}|${sourceExpr}`;
      if (seen.has(key)) return;
      seen.add(key);

      indicators.push({
        id: `xss-dom-${indicators.length + 1}`,
        type: indType,
        severity: isDirectHighRisk ? 'high' : 'medium',
        parameterOrSink: `${sourceExpr} -> ${sinkName}`,
        context: `${script.source}${node.loc ? ` (line ${node.loc.start.line})` : ''}`,
        detail: isDecodedParam
          ? {
              en: `Decoded Base64 URL/DOM source "${sourceExpr}" flows unsanitized into execution sink "${sinkName}".`,
              ar: `يتدفق معامل مفكوك من Base64 (${sourceExpr}) دون تعقيم مباشر إلى منفذ التنفيذ "${sinkName}".`,
            }
          : isPostMsg
            ? {
                en: `Cross-origin "${sourceExpr}" flows without origin verification into unsafe sink "${sinkName}".`,
                ar: `يتدفق "${sourceExpr}" دون تحقق من المصدر (origin) إلى منفذ غير آمن "${sinkName}".`,
              }
            : {
                en: `DOM source "${sourceExpr}" flows without sanitization into unsafe sink "${sinkName}".`,
                ar: `يتدفق مصدر الإدخال "${sourceExpr}" دون تعقيم مباشر إلى منفذ التنفيذ غير الآمن "${sinkName}".`,
              },
        excerpt: safeSnippet(script.code, node),
      });
    };

    const visit = (node: AstNode) => {
      if (!node || typeof node !== 'object') return;

      let enteredMsg = false;
      if (
        node.type === 'CallExpression' &&
        getCalleePath(node.callee).endsWith('addEventListener') &&
        node.arguments?.[0]?.type === 'Literal' &&
        node.arguments[0].value === 'message' &&
        (node.arguments?.[1]?.type === 'FunctionExpression' || node.arguments?.[1]?.type === 'ArrowFunctionExpression')
      ) {
        const handlerNode = node.arguments[1];
        const paramName = handlerNode.params?.[0]?.type === 'Identifier' ? handlerNode.params[0].name : null;
        const handlerSrc = script.code.slice(handlerNode.start, Math.min(handlerNode.end, handlerNode.start + 1500));
        const checksOrigin =
          /\.(?:origin)\b|origin\s*[!=]==?|\.source\s*===\s*(?:window|self|parent|top)\b/i.test(handlerSrc);
        if (!checksOrigin && /\.(?:data)\b/.test(handlerSrc)) {
          const pmKey = `unsafe_postmessage|listener|${node.loc?.start.line || 0}`;
          if (!seen.has(pmKey)) {
            seen.add(pmKey);
            indicators.push({
              id: `xss-pm-${indicators.length + 1}`,
              type: 'unsafe_postmessage',
              severity: 'medium',
              parameterOrSink: 'window.addEventListener("message") [no origin check]',
              context: `${script.source}${node.loc ? ` (line ${node.loc.start.line})` : ''}`,
              detail: {
                en: 'Message event listener reads incoming postMessage data without validating event.origin.',
                ar: 'مستمع رسائل postMessage يقرأ البيانات الواردة دون التحقق من event.origin.',
              },
              excerpt: safeSnippet(script.code, node),
            });
          }
        }
        if (paramName) {
          taintedVars.set(`${paramName}.data`, 'postMessage event.data');
          taintedVars.set(paramName, 'postMessage event');
        }
        inMessageListener = true;
        enteredMsg = true;
      }

      if (node.type === 'VariableDeclarator' && node.id?.type === 'Identifier' && node.init) {
        const initText = safeSnippet(script.code, node.init, 120);
        if (
          node.init.type === 'NewExpression' &&
          getCalleePath(node.init.callee) === 'URLSearchParams'
        ) {
          const argTaint = exprUsesDomTaint(node.init.arguments?.[0], taintedVars);
          if (argTaint || /location\.(?:search|hash|href)/i.test(initText)) {
            taintedVars.set(node.id.name, argTaint || 'URLSearchParams(location.search)');
          }
        } else {
          const hit = exprUsesDomTaint(node.init, taintedVars);
          if (hit) taintedVars.set(node.id.name, hit);
        }
      }

      if (node.type === 'AssignmentExpression') {
        const leftPath = getCalleePath(node.left);
        // Check taint propagation to local variable
        if (node.left?.type === 'Identifier') {
          const hit = exprUsesDomTaint(node.right, taintedVars);
          if (hit) taintedVars.set(node.left.name, hit);
        }

        // Ignore safe sinks explicitly
        if (
          leftPath === 'textContent' ||
          leftPath.endsWith('.textContent') ||
          leftPath === 'innerText' ||
          leftPath.endsWith('.innerText')
        ) {
          walkChildren(node, visit);
          if (enteredMsg) inMessageListener = false;
          return;
        }

        // Unsafe DOM HTML sinks
        if (
          leftPath === 'innerHTML' ||
          leftPath.endsWith('.innerHTML') ||
          leftPath === 'outerHTML' ||
          leftPath.endsWith('.outerHTML')
        ) {
          const hit = exprUsesDomTaint(node.right, taintedVars);
          if (hit) {
            recordDomSink(leftPath.split('.').pop() || 'innerHTML', hit, node, true);
          }
        }

        // Unvalidated open-redirect / javascript: URI assignment sink
        if (/^(?:window\.)?location(?:\.href)?$/.test(leftPath)) {
          const hit = exprUsesDomTaint(node.right, taintedVars);
          if (hit) {
            recordDomSink('location.href', hit, node, false);
          }
        }
      }

      if (node.type === 'CallExpression') {
        const callee = getCalleePath(node.callee);

        if (callee === 'document.write' || callee === 'document.writeln') {
          for (const arg of node.arguments || []) {
            const hit = exprUsesDomTaint(arg, taintedVars);
            if (hit) recordDomSink(callee, hit, node, true);
          }
        }

        if (callee === 'insertAdjacentHTML' || callee.endsWith('.insertAdjacentHTML')) {
          const hit = exprUsesDomTaint(node.arguments?.[1], taintedVars);
          if (hit) recordDomSink('insertAdjacentHTML', hit, node, true);
        }

        if (callee === 'eval' || callee === 'window.eval' || callee === 'Function') {
          const hit = exprUsesDomTaint(node.arguments?.[0], taintedVars);
          if (hit) recordDomSink(callee, hit, node, true);
        }

        if ((callee === 'setTimeout' || callee === 'setInterval' || callee === 'window.setTimeout' || callee === 'window.setInterval') && node.arguments?.[0]) {
          const firstArg = node.arguments[0];
          if (firstArg.type !== 'FunctionExpression' && firstArg.type !== 'ArrowFunctionExpression') {
            const hit = exprUsesDomTaint(firstArg, taintedVars);
            if (hit) recordDomSink(`${callee}(string)`, hit, node, true);
          }
        }

        if (callee === 'location.assign' || callee === 'location.replace' || callee === 'window.location.assign' || callee === 'window.location.replace') {
          const hit = exprUsesDomTaint(node.arguments?.[0], taintedVars);
          if (hit) recordDomSink(callee, hit, node, false);
        }

        if (((callee === 'html' || callee.endsWith('.html')) && /^(?:\$|jQuery)\b/.test(safeSnippet(script.code, node.callee, 40))) && node.arguments?.[0]) {
          const hit = exprUsesDomTaint(node.arguments[0], taintedVars);
          if (hit) recordDomSink('$(...).html', hit, node, true);
        }
      }

      if (inMessageListener && node.type === 'MemberExpression') {
        const path = getCalleePath(node);
        if (path.endsWith('.data') && taintedVars.has(path)) {
          // Already tracked via taintedVars
        }
      }

      walkChildren(node, visit);
      if (enteredMsg) inMessageListener = false;
    };

    visit(ast);
  }

  return indicators;
}

function inspectPassiveReflection(
  urls: string[],
  rawHtml: string,
  $: cheerio.CheerioAPI
): XssIndicatorItem[] {
  const indicators: XssIndicatorItem[] = [];
  const seenParams = new Set<string>();

  const candidateParams: { name: string; value: string }[] = [];
  for (const rawUrl of urls) {
    try {
      const parsed = new URL(rawUrl);
      parsed.searchParams.forEach((value, name) => {
        const trimmed = value.trim();
        if (trimmed.length < 3 || trimmed.length > 180) return;
        if (COMMON_BENIGN_PARAM_VALUES.has(trimmed.toLowerCase())) return;
        if (/^\d{1,12}$/.test(trimmed)) return;
        const key = `${name}=${trimmed}`;
        if (seenParams.has(key)) return;
        seenParams.add(key);
        candidateParams.push({ name, value: trimmed });
      });
    } catch {
      // ignore invalid URL
    }
  }

  if (candidateParams.length === 0) return indicators;

  const inlineScripts: string[] = [];
  $('script:not([src])').each((_, el) => {
    const content = $(el).html() || '';
    if (content) inlineScripts.push(content);
  });

  // Collect inline event handler / dangerous URL attributes
  const dangerousAttrs: { tag: string; attr: string; val: string }[] = [];
  $('*').each((_, el) => {
    const node = el as any;
    const tag = (node.tagName || 'element').toLowerCase();
    for (const attr of node.attribs ? Object.keys(node.attribs) : []) {
      const val = String(node.attribs[attr] || '');
      if (!val) continue;
      if (/^on[a-z]+$/i.test(attr) || /^(?:href|src|action|formaction|data)$/i.test(attr)) {
        dangerousAttrs.push({ tag, attr, val });
      }
    }
  });

  for (const param of candidateParams.slice(0, 15)) {
    const val = param.value;
    const hasHtmlMeta = /[<>"'`]/.test(val);
    const escapedVal = htmlEscapeSample(val);
    const rawAppearsInHtml = rawHtml.includes(val);
    const escapedOnly = !rawAppearsInHtml && escapedVal !== val && rawHtml.includes(escapedVal);

    if (escapedOnly) {
      // Properly HTML-entity encoded — safe!
      continue;
    }

    // 1. Check inline <script> reflection
    const scriptIdx = inlineScripts.findIndex((sc) => sc.includes(val));
    if (scriptIdx !== -1) {
      const sc = inlineScripts[scriptIdx];
      const pos = sc.indexOf(val);
      const excerpt = sc.slice(Math.max(0, pos - 40), Math.min(sc.length, pos + val.length + 40)).replace(/\s+/g, ' ').trim();
      const hasScriptBreakout = /['"`<>\\;()]|<\/script/i.test(val);
      indicators.push({
        id: `xss-reflected-script-${indicators.length + 1}`,
        type: 'reflected_param',
        severity: hasScriptBreakout ? 'high' : 'medium',
        parameterOrSink: `?${param.name}=...`,
        context: 'inline <script> block',
        detail: {
          en: hasScriptBreakout
            ? `Query parameter "${param.name}" reflects unescaped script/quote characters directly inside an inline <script> block.`
            : `Query parameter "${param.name}" is reflected inside an inline <script> block without visible escaping.`,
          ar: hasScriptBreakout
            ? `ينعكس معامل الرابط "${param.name}" بأحرف تحكم غير معقّمة داخل كتلة <script> مباشرة.`
            : `ينعكس معامل الرابط "${param.name}" داخل وسم <script> مباشر؛ يُنصح بترميز JSON الآمن.`,
        },
        excerpt,
      });
      continue;
    }

    // 2. Check event handler / dangerous attribute reflection
    const attrHit = dangerousAttrs.find((a) => a.val.includes(val));
    if (attrHit && (/^on[a-z]+$/i.test(attrHit.attr) || /^\s*(?:javascript|data|vbscript):/i.test(attrHit.val) || hasHtmlMeta)) {
      indicators.push({
        id: `xss-reflected-attr-${indicators.length + 1}`,
        type: 'reflected_param',
        severity: 'high',
        parameterOrSink: `?${param.name}=...`,
        context: `<${attrHit.tag} ${attrHit.attr}="...">`,
        detail: {
          en: `Query parameter "${param.name}" reflects unescaped into dangerous HTML attribute "${attrHit.attr}" on <${attrHit.tag}>.`,
          ar: `ينعكس معامل الرابط "${param.name}" دون تعقيم داخل السمة الخطرة "${attrHit.attr}" في وسم <${attrHit.tag}>.`,
        },
        excerpt: `<${attrHit.tag} ${attrHit.attr}="${attrHit.val.slice(0, 100)}">`,
      });
      continue;
    }

    // 3. Check raw unescaped HTML metacharacter reflection in DOM
    if (hasHtmlMeta && rawAppearsInHtml) {
      const pos = rawHtml.indexOf(val);
      const excerpt = rawHtml.slice(Math.max(0, pos - 40), Math.min(rawHtml.length, pos + val.length + 40)).replace(/\s+/g, ' ').trim();
      indicators.push({
        id: `xss-reflected-html-${indicators.length + 1}`,
        type: 'reflected_param',
        severity: 'high',
        parameterOrSink: `?${param.name}=...`,
        context: 'raw HTML markup (unescaped metacharacters)',
        detail: {
          en: `Query parameter "${param.name}" containing HTML metacharacters (<, >, ", ') is reflected unescaped in HTML response.`,
          ar: `ينعكس معامل الرابط "${param.name}" المحتوي على محارف HTML الخاصة دون ترميز HTML Entities في الصفحة.`,
        },
        excerpt,
      });
    }
  }

  return indicators;
}

export function analyzeTargetXssVulnerabilities(input: XssAnalyzerInput): {
  data: XssAssessmentData;
  finding: CheckFinding;
} {
  const now = new Date().toISOString();
  const { cspStatus, weakDirectives } = analyzeCspHeader(input.headers['content-security-policy']);

  const sessionCookies = (input.cookieAudit?.cookiesDetected || []).filter(
    (c: CookieAuditItem) =>
      c.source === 'http_set_cookie' &&
      (c.category === 'security_cookie' || /(?:^|[_-])(sess|session|sid|auth|jwt|token)(?:$|[_-])/i.test(c.name))
  );
  const httpOnlySessionCookiesMissing = sessionCookies.some(
    (c: CookieAuditItem) => c.securityFlags && !c.securityFlags.httpOnly
  );

  if (input.contentBlocked || !input.htmlBuffer || input.htmlBuffer.length === 0) {
    const unavailableData: XssAssessmentData = {
      status: 'unavailable',
      label: {
        en: 'XSS Inspection Unavailable (HTML Not Readable)',
        ar: 'تعذر فحص XSS لعدم توفر محتوى HTML',
      },
      summary: {
        en: 'Passive HTML reflection and DOM XSS inspection could not run because HTML content was unreachable or blocked by the target.',
        ar: 'تعذر إجراء الفحص السلبي لثغرات XSS لعدم إمكانية قراءة كود HTML أو بسبب حظر الخادم.',
      },
      reflectedParamsCount: 0,
      domSinkCount: 0,
      cspStatus,
      httpOnlySessionCookiesMissing,
      indicators: [],
      remediationGuidance: [
        {
          en: 'Ensure strict Content-Security-Policy (no unsafe-inline/unsafe-eval) and context-aware output encoding.',
          ar: 'تأكد من تفعيل سياسة CSP صارمة دون unsafe-inline مع ترميز جميع المخرجات حسب السياق.',
        },
      ],
    };

    return {
      data: unavailableData,
      finding: {
        id: 'xss-reflection-dom-audit',
        section: 'xss_security',
        test: {
          en: 'Passive Target XSS & DOM Sink Audit',
          ar: 'الفحص السلبي لثغرات XSS ومنافذ DOM',
        },
        result: unavailableData.label,
        status: 'unknown',
        severity: 'unknown',
        weight: 0,
        evidence: `CSP: ${cspStatus} | HtmlAvailable: false`,
        explanation: unavailableData.summary,
        recommendedAction: unavailableData.remediationGuidance[0],
        source: 'SM Passive XSS Analyzer',
        timestamp: now,
        confidence: 25,
        errorState: 'HTML unavailable for passive XSS inspection',
      },
    };
  }

  const rawHtml = input.htmlBuffer.toString('utf8');
  const $ = cheerio.load(rawHtml);

  const reflectedIndicators = inspectPassiveReflection(
    [input.submittedUrl, input.finalUrl],
    rawHtml,
    $
  );

  const scriptInputs: { source: string; code: string }[] = [];
  $('script:not([src])').each((idx, el) => {
    const code = $(el).html() || '';
    if (code.trim()) scriptInputs.push({ source: `<script>#${idx + 1}`, code });
  });
  for (const ext of input.fetchedScripts || []) {
    if (ext.code?.trim()) scriptInputs.push({ source: ext.url, code: ext.code });
  }

  const domIndicators = inspectDomXssAst(scriptInputs);
  const indicators: XssIndicatorItem[] = [...reflectedIndicators, ...domIndicators];

  if (cspStatus === 'weak') {
    indicators.push({
      id: 'xss-csp-weak',
      type: 'weak_csp',
      severity: 'low',
      parameterOrSink: 'Content-Security-Policy',
      context: `Weak directive(s): ${weakDirectives.join(', ')}`,
      detail: {
        en: `CSP header permits unsafe script directives (${weakDirectives.join(', ')}), weakening XSS defense-in-depth.`,
        ar: `تسمح ترويسة CSP بتوجيهات غير آمنة (${weakDirectives.join('، ')}) مما يُضعف الحماية من XSS.`,
      },
    });
  } else if (cspStatus === 'missing') {
    indicators.push({
      id: 'xss-csp-missing',
      type: 'missing_csp',
      severity: 'informational',
      parameterOrSink: 'Content-Security-Policy',
      context: 'Header absent in HTTP response',
      detail: {
        en: 'No Content-Security-Policy header is present; defense relies solely on application escaping.',
        ar: 'ترويسة Content-Security-Policy غير موجودة؛ تعتمد الحماية فقط على تعقيم الكود.',
      },
    });
  }

  if (httpOnlySessionCookiesMissing) {
    indicators.push({
      id: 'xss-cookie-httponly',
      type: 'cookie_httponly',
      severity: 'low',
      parameterOrSink: 'Set-Cookie (Session)',
      context: 'Missing HttpOnly flag on session cookie',
      detail: {
        en: 'Authentication/session cookie lacks HttpOnly, allowing JavaScript access if XSS ever occurs.',
        ar: 'كوكي الجلسة يفتقر إلى سمة HttpOnly مما قد يسمح بقراءته عبر JavaScript إذا وُجدت ثغرة XSS.',
      },
    });
  }

  const highRiskIndicators = [...reflectedIndicators, ...domIndicators].filter((i) => i.severity === 'high');
  const mediumIndicators = [...reflectedIndicators, ...domIndicators].filter((i) => i.severity === 'medium');

  let status: XssAssessmentData['status'] = 'safe';
  if (highRiskIndicators.length > 0) {
    status = 'high_risk';
  } else if (mediumIndicators.length > 0) {
    status = 'potential_weakness';
  }

  const remediationGuidance: BilingualText[] = [];
  if (reflectedIndicators.length > 0) {
    remediationGuidance.push({
      en: 'Apply strict context-aware HTML/JS output encoding and never interpolate raw URL query parameters into <script> tags or event attributes.',
      ar: 'قم بترميز جميع المدخلات حسب السياق (HTML/JS Encoding) وتجنب حقن معاملات الرابط مباشرة داخل وسوم <script> أو سمات الأحداث.',
    });
  }
  const hasHtmlOrEvalSink = domIndicators.some(
    (i) => i.type === 'dom_sink' || i.type === 'decoded_param_sink'
  );
  const hasPostMessageIssue = domIndicators.some((i) => i.type === 'unsafe_postmessage');

  if (hasHtmlOrEvalSink) {
    remediationGuidance.push({
      en: 'Replace innerHTML / document.write / eval sinks with textContent or innerText, or sanitize untrusted HTML via DOMPurify before rendering.',
      ar: 'استبدل innerHTML وdocument.write وeval باستخدام textContent/innerText الآمن أو عقّم المحتوى عبر DOMPurify.',
    });
  }
  if (hasPostMessageIssue) {
    remediationGuidance.push({
      en: 'Strictly validate event.origin against an explicit allowlist inside window.addEventListener("message") handlers before reading event.data.',
      ar: 'تحقق بدقة من event.origin مقابل قائمة نطاقات معتمدة داخل مستمع window.addEventListener("message") قبل قراءة event.data.',
    });
  }
  if (cspStatus !== 'strict') {
    remediationGuidance.push({
      en: "Configure a strict Content-Security-Policy (e.g., script-src 'self' with nonces, removing 'unsafe-inline' and 'unsafe-eval').",
      ar: "أضف سياسة Content-Security-Policy صارمة (مثل script-src 'self' بدون 'unsafe-inline' أو 'unsafe-eval').",
    });
  }
  if (httpOnlySessionCookiesMissing) {
    remediationGuidance.push({
      en: 'Set HttpOnly, Secure, and SameSite flags on all authentication and session cookies.',
      ar: 'فعّل سمات HttpOnly وSecure وSameSite على جميع ملفات تعريف الجلسة والمصادقة.',
    });
  }
  if (remediationGuidance.length === 0) {
    remediationGuidance.push({
      en: 'Maintain current escaping, strict CSP directives, and HttpOnly session cookie protections.',
      ar: 'حافظ على ممارسات الترميز الحالية وسياسة CSP الصارمة وحماية HttpOnly لكوكيز الجلسات.',
    });
  }

  const label: BilingualText =
    status === 'high_risk'
      ? {
          en: `High XSS Risk (${reflectedIndicators.length} reflected, ${domIndicators.length} DOM sink)`,
          ar: `مخاطر XSS مرتفعة (${reflectedIndicators.length} انعكاس، ${domIndicators.length} منفذ DOM)`,
        }
      : status === 'potential_weakness'
        ? {
            en: `Potential XSS Weakness (${reflectedIndicators.length} reflected, ${domIndicators.length} DOM sink)`,
            ar: `ضعف محتمل تجاه XSS (${reflectedIndicators.length} انعكاس، ${domIndicators.length} منفذ DOM)`,
          }
        : {
            en: `No XSS Vulnerabilities Detected (0 reflected, 0 DOM sinks)`,
            ar: 'سليم — لم تُرصد ثغرات XSS أو منافذ DOM غير آمنة',
          };

  const summary: BilingualText =
    status === 'high_risk'
      ? {
          en: `Passive audit identified ${highRiskIndicators.length} high-risk XSS pattern(s) where unescaped parameters or tainted DOM sources reach execution sinks.`,
          ar: `كشف الفحص السلبي عن ${highRiskIndicators.length} نمط XSS عالي الخطورة حيث تصل مدخلات غير معقّمة أو مصادر DOM إلى منافذ تنفيذ خطرة.`,
        }
      : status === 'potential_weakness'
        ? {
            en: `Passive audit noted ${mediumIndicators.length} potential XSS weakness(es) (inline script reflection or unvalidated DOM navigation) without confirmed markup breakout.`,
            ar: `رصد الفحص السلبي ${mediumIndicators.length} مؤشر ضعف محتمل تجاه XSS دون إثبات كسر مباشر لبنية HTML.`,
          }
        : {
            en: `Zero unescaped reflected query parameters and zero tainted DOM XSS sinks detected across ${scriptInputs.length} inspected script(s). CSP is ${cspStatus}.`,
            ar: `لم يُرصد أي انعكاس غير معقّم لمعاملات الرابط أو تدفق DOM ملوث عبر ${scriptInputs.length} سكربت مفحوص. حالة CSP: ${cspStatus}.`,
          };

  const data: XssAssessmentData = {
    status,
    label,
    summary,
    reflectedParamsCount: reflectedIndicators.length,
    domSinkCount: domIndicators.length,
    cspStatus,
    httpOnlySessionCookiesMissing,
    indicators,
    remediationGuidance,
  };

  const findingStatus = status === 'high_risk' ? 'failed' : status === 'potential_weakness' ? 'warning' : 'pass';
  const findingSeverity = status === 'high_risk' ? 'high' : status === 'potential_weakness' ? 'medium' : 'informational';
  const findingWeight = status === 'high_risk' ? 24 : status === 'potential_weakness' ? 12 : 0;

  const finding: CheckFinding = {
    id: 'xss-reflection-dom-audit',
    section: 'xss_security',
    test: {
      en: 'Passive Target XSS & DOM Sink Audit',
      ar: 'الفحص السلبي لثغرات XSS ومنافذ DOM',
    },
    result: label,
    status: findingStatus,
    severity: findingSeverity,
    weight: findingWeight,
    evidence: `Status: ${status} | Reflected: ${reflectedIndicators.length} | DomSinks: ${domIndicators.length} | CSP: ${cspStatus} | SessionCookieMissingHttpOnly: ${httpOnlySessionCookiesMissing}`,
    sourceCodeEvidence: (highRiskIndicators[0] || mediumIndicators[0])?.excerpt,
    explanation: summary,
    recommendedAction: remediationGuidance[0],
    source: 'SM Passive XSS Analyzer',
    timestamp: now,
    confidence: status === 'high_risk' ? 92 : 88,
  };

  return { data, finding };
}
