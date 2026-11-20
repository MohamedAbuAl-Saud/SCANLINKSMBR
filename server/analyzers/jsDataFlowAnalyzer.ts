import * as acorn from 'acorn';
import type {
  CookieAstOperation,
  PlantedBackdoorItem,
  StaticDataFlowTaintItem,
  TransmittedDataType,
} from '../types.ts';
import { classifyNetworkChannel } from './remoteBrowserAdapter.ts';

export interface ScriptInput {
  source: string;
  code: string;
}

export type TaintSourceTag =
  | 'cookies'
  | 'storage'
  | 'credentials'
  | 'session_tokens'
  | 'financial_pii'
  | 'keystrokes_clipboard'
  | 'device_fingerprint'
  | 'geolocation'
  | 'camera_mic'
  | 'ip_profiling'
  | 'url_params'
  | 'form_inputs'
  | 'analytics_metrics'
  | 'error_telemetry'
  | 'functional_state';

export type AstTriggerKind =
  | 'immediate_load'
  | 'dom_ready'
  | 'timer_interval'
  | 'page_exit'
  | 'user_click'
  | 'form_submit'
  | 'keystroke_event'
  | 'unknown';

export interface AstNetworkTransmission {
  sourceScript: string;
  sourceFunction: string;
  method: 'fetch' | 'xhr' | 'sendBeacon' | 'websocket' | 'eventsource' | 'dynamic_beacon';
  httpMethod: string;
  destinationUrl: string;
  obfuscatedUrl: boolean;
  decodedFrom?: string;
  taintTags: TaintSourceTag[];
  hasUnknownPayload: boolean;
  trigger: AstTriggerKind;
  frequency: 'once' | 'on_event' | 'periodic' | 'on_exit' | 'unknown';
  excerpt: string;
  line: number;
  consentGated: boolean;
}

export interface AstCookieAccessEvent {
  sourceScript: string;
  sourceFunction: string;
  kind: 'write' | 'read';
  cookieName?: string;
  operations: CookieAstOperation[];
  valueExprPreview?: string;
  flowsToExternalTx: boolean;
  flowsToStorage: boolean;
  usesObfuscationOrDynamicPayload: boolean;
  usesMaliciousInjection?: boolean;
  consentGated: boolean;
  excerpt: string;
  line: number;
}

export interface AstBehavioralSignal {
  id: string;
  sourceScript: string;
  sourceFunction: string;
  category:
    | 'obfuscation'
    | 'dynamic_eval'
    | 'dom_injection'
    | 'redirect'
    | 'exfiltration'
    | 'fingerprinting'
    | 'clipboard'
    | 'keystroke_harvest'
    | 'popup'
    | 'download_trigger'
    | 'anti_debug'
    | 'form_rewrite'
    | 'password_hook'
    | 'wallet_drainer'
    | 'cryptominer'
    | 'popunder';
  indicator: string;
  excerpt: string;
  benignContextPossible: boolean;
  confirmedMaliciousContext: boolean;
  line: number;
}

export interface AstBackgroundCollectionSignal {
  category:
    | 'cookies_storage'
    | 'credentials_inputs'
    | 'browser_fingerprinting'
    | 'keystrokes_clipboard'
    | 'device_network_webrtc'
    | 'background_polling';
  apisUsed: string[];
  triggers: string[];
  sourceScript: string;
  sourceFunction: string;
  excerpt: string;
  transmittedExternally: boolean;
  consentGated: boolean;
  isBenignStandalone: boolean;
}

export interface AstPermissionCallSite {
  api: string;
  sourceScript: string;
  sourceFunction: string;
  triggeredOnEntry: boolean;
  triggerKind?: AstTriggerKind;
  targetElementHint?: string;
  triggerDescription: string;
}

export interface JsDataFlowAnalysisResult {
  scriptsParsed: number;
  scriptsFallback: number;
  transmissions: AstNetworkTransmission[];
  cookieEvents: AstCookieAccessEvent[];
  behavioralSignals: AstBehavioralSignal[];
  backgroundCollections: AstBackgroundCollectionSignal[];
  serviceWorkerUrls: string[];
  webWorkerUrls: string[];
  permissionSites: AstPermissionCallSite[];
  dataFlowTaints: StaticDataFlowTaintItem[];
  plantedBackdoors: PlantedBackdoorItem[];
  consentMechanismInJs: {
    hasConsentApiOrGate: boolean;
    hasRejectOrWithdrawHandler: boolean;
    hasConsentUiTextInJs: boolean;
    evidence: string[];
  };
  obfuscationMarkerCount: number;
  isMinifiedBundlePresent: boolean;
  domMutationExcerpts: string[];
}

interface AstNode {
  type: string;
  start: number;
  end: number;
  loc?: { start: { line: number; column: number } };
  [key: string]: any;
}

interface ResolvedString {
  value?: string;
  obfuscated?: boolean;
  decodedFrom?: string;
}

interface ScriptContext {
  source: string;
  code: string;
  varStrings: Map<string, ResolvedString>;
  varTaints: Map<string, Set<TaintSourceTag>>;
  xhrVars: Map<string, { url?: string; httpMethod?: string; obfuscatedUrl?: boolean; decodedFrom?: string }>;
  fnDefs: Map<string, AstNode>;
  fnTaints: Map<string, Set<TaintSourceTag>>;
  currentFnStack: string[];
  triggerStack: AstTriggerKind[];
  consentBranchDepth: number;
}

const CONSENT_IDENTIFIERS_RE =
  /(?:cookieConsent|consent|gdpr|optIn|allowAnalytics|hasConsent|canTrack|__tcfapi|OneTrust|Cookiebot|gtag\s*\(\s*['"]consent)/i;

const CREDENTIAL_KEY_RE =
  /\b(?:pass(?:word)?|pwd|passwd|passphrase|seed_?phrase|recovery_?phrase|private_?key|keystroke)\b/i;

const FINANCIAL_KEY_RE =
  /\b(?:cvv|cvc|card_?number|credit_?card|iban|ssn)\b/i;

const SESSION_TOKEN_KEY_RE =
  /\b(?:auth_?token|access_?token|refresh_?token|id_?token|session_?id|csrf_?token|token|session)\b/i;

const SENSITIVE_KEY_RE =
  /\b(?:pass(?:word)?|pwd|passwd|passphrase|cvv|cvc|card_?number|credit_?card|iban|ssn|cookie|keystroke)\b/i;

const DEV_BUILD_ENDPOINT_RE =
  /(?:^|\/)(?:@vite\/client|@react-refresh|vite-hmr|__vite_ping|sockjs-node|__webpack_hmr|hot-update\.(?:js|json))(?:\?|$|#)|\/node_modules\/\.vite\//i;

const BENIGN_METRICS_KEY_RE =
  /\b(?:pageView|page_view|loadTime|load_time|timing|duration|latency|viewport|screen|lang|language|locale|theme|darkMode|metric|metrics|telemetry|event|category|action|scroll|performance|error|stack|version)\b/i;

const FUNCTIONAL_STATE_KEY_RE =
  /\b(?:theme|lang|language|locale|currency|sidebar|collapsed|tab|filter|sort|cartCount|page|limit|offset|search|query|status)\b/i;

const AD_OR_MINER_DOMAINS_RE =
  /(?:coinhive|coin-hive|crypto-loot|cryptoloot|jsecoin|authedmine|webminepool|minero|monero|popads\.net|popcash\.net|propellerads|adsterra|clickadu|hilltopads|exoclick)/i;

function safeSlice(code: string, node: AstNode | undefined, max = 180): string {
  if (!node || typeof node.start !== 'number' || typeof node.end !== 'number') return '';
  return code.slice(node.start, Math.min(node.end, node.start + max)).replace(/\s+/g, ' ').trim();
}

function tryDecodeBase64Ascii(raw: string): string | null {
  if (!raw || raw.length < 4 || !/^[A-Za-z0-9+/=_-]+$/.test(raw)) return null;
  try {
    const normalized = raw.replace(/-/g, '+').replace(/_/g, '/');
    const pad = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
    const decoded = Buffer.from(pad, 'base64').toString('utf8');
    if (/^[\x20-\x7E\r\n\t]+$/.test(decoded) && decoded.length >= 2) {
      return decoded;
    }
  } catch {
    // ignore
  }
  return null;
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

function resolveStringExpr(node: AstNode | null | undefined, ctx: ScriptContext, depth = 0): ResolvedString {
  if (!node || depth > 8) return {};
  if (node.type === 'Literal' && typeof node.value === 'string') {
    return { value: node.value };
  }
  if (node.type === 'Identifier') {
    return ctx.varStrings.get(node.name) || {};
  }
  if (node.type === 'TemplateLiteral') {
    if (!node.expressions?.length && node.quasis?.length === 1) {
      return { value: node.quasis[0].value?.cooked ?? node.quasis[0].value?.raw ?? '' };
    }
    let out = '';
    let obfuscated = false;
    let decodedFrom: string | undefined;
    for (let i = 0; i < node.quasis.length; i++) {
      out += node.quasis[i].value?.cooked ?? '';
      if (i < node.expressions.length) {
        const sub = resolveStringExpr(node.expressions[i], ctx, depth + 1);
        if (sub.value !== undefined) {
          out += sub.value;
          if (sub.obfuscated) {
            obfuscated = true;
            decodedFrom = sub.decodedFrom;
          }
        } else {
          out += '${...}';
        }
      }
    }
    return { value: out, obfuscated, decodedFrom };
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const l = resolveStringExpr(node.left, ctx, depth + 1);
    const r = resolveStringExpr(node.right, ctx, depth + 1);
    if (l.value !== undefined && r.value !== undefined) {
      return {
        value: l.value + r.value,
        obfuscated: Boolean(l.obfuscated || r.obfuscated),
        decodedFrom: l.decodedFrom || r.decodedFrom,
      };
    }
    if (l.value && /^https?:\/\//i.test(l.value)) return { value: l.value };
    return {};
  }
  if (node.type === 'CallExpression') {
    const callee = getCalleePath(node.callee);
    if ((callee === 'atob' || callee === 'window.atob') && node.arguments?.length >= 1) {
      const arg = resolveStringExpr(node.arguments[0], ctx, depth + 1);
      if (arg.value) {
        const decoded = tryDecodeBase64Ascii(arg.value);
        if (decoded) {
          return { value: decoded, obfuscated: true, decodedFrom: `atob("${arg.value.slice(0, 32)}")` };
        }
      }
    }
    if (callee === 'String.fromCharCode' && node.arguments?.length >= 2) {
      const nums = node.arguments
        .map((a: AstNode) => (a.type === 'Literal' && typeof a.value === 'number' ? a.value : null))
        .filter((n: number | null): n is number => n !== null && n >= 0 && n <= 0x10ffff);
      if (nums.length === node.arguments.length) {
        const decoded = String.fromCharCode(...nums);
        return { value: decoded, obfuscated: true, decodedFrom: 'String.fromCharCode(...)' };
      }
    }
    if (callee === 'decodeURIComponent' && node.arguments?.length >= 1) {
      const arg = resolveStringExpr(node.arguments[0], ctx, depth + 1);
      if (arg.value) {
        try {
          return { value: decodeURIComponent(arg.value), obfuscated: arg.obfuscated, decodedFrom: arg.decodedFrom };
        } catch {
          return { value: arg.value };
        }
      }
    }
  }
  if (node.type === 'ChainExpression') return resolveStringExpr(node.expression, ctx, depth + 1);
  return {};
}

function collectExprTaints(node: AstNode | null | undefined, ctx: ScriptContext, depth = 0): {
  taints: Set<TaintSourceTag>;
  hasUnknownIdentifier: boolean;
  benignMetricKeys: number;
  functionalKeys: number;
  sensitiveKeys: number;
} {
  const taints = new Set<TaintSourceTag>();
  let hasUnknownIdentifier = false;
  let benignMetricKeys = 0;
  let functionalKeys = 0;
  let sensitiveKeys = 0;

  function visit(n: AstNode | null | undefined, d: number): void {
    if (!n || d > 12) return;
    if (n.type === 'Identifier') {
      const varT = ctx.varTaints.get(n.name);
      if (varT && varT.size > 0) {
        varT.forEach((t) => taints.add(t));
      } else if (
        n.name === 'e' ||
        n.name === 'ev' ||
        n.name === 'event' ||
        n.name === 'keylog' ||
        n.name === 'keystrokes'
      ) {
        if (ctx.triggerStack.includes('keystroke_event')) {
          taints.add('keystrokes_clipboard');
        }
      } else if (
        !ctx.varStrings.has(n.name) &&
        !['JSON', 'Math', 'Date', 'Object', 'Array', 'String', 'Number', 'Boolean', 'encodeURIComponent', 'btoa', 'window', 'document', 'navigator', 'console', 'undefined', 'null'].includes(n.name)
      ) {
        hasUnknownIdentifier = true;
      }
      return;
    }

    if (n.type === 'AwaitExpression') {
      visit(n.argument, d + 1);
      return;
    }

    if (n.type === 'MemberExpression') {
      const path = getCalleePath(n);
      if (path === 'document.cookie' || path.endsWith('.cookie')) {
        taints.add('cookies');
        return;
      }
      if (/^(?:window\.)?(?:localStorage|sessionStorage)\b/.test(path)) {
        taints.add('storage');
        return;
      }
      if (/^(?:window\.)?location\.(?:search|hash|href)$/.test(path)) {
        taints.add('url_params');
        return;
      }
      if (/\.(?:value|files)$/.test(path)) {
        const rawText = path.toLowerCase();
        if (/(?:pass|pwd|pw|pin|otp|cvv|card|secret)/.test(rawText)) {
          taints.add('credentials');
        } else {
          taints.add('form_inputs');
        }
        return;
      }
      if (/^(?:e|ev|event)\.(?:key|code|keyCode|which|charCode)$/.test(path) && ctx.triggerStack.includes('keystroke_event')) {
        taints.add('keystrokes_clipboard');
        return;
      }
      if (/^(?:navigator\.(?:userAgent|platform|plugins|hardwareConcurrency|deviceMemory|language)|screen\.)/.test(path)) {
        taints.add('device_fingerprint');
        return;
      }
      visit(n.object, d + 1);
      if (n.computed) visit(n.property, d + 1);
      return;
    }

    if (n.type === 'CallExpression') {
      const callee = getCalleePath(n.callee);
      if (/^(?:window\.)?(?:localStorage|sessionStorage)\.getItem$/.test(callee)) {
        taints.add('storage');
      } else if (/^navigator\.clipboard\.read(?:Text)?$/.test(callee)) {
        taints.add('keystrokes_clipboard');
      } else if (/^navigator\.mediaDevices\.(?:getUserMedia|getDisplayMedia)$/.test(callee)) {
        taints.add('camera_mic');
      } else if (/^navigator\.geolocation\.(?:getCurrentPosition|watchPosition)$/.test(callee)) {
        taints.add('geolocation');
      } else if (callee === 'fetch' || callee === 'window.fetch') {
        const urlArg = resolveStringExpr(n.arguments?.[0], ctx).value || '';
        if (/(?:ipapi\.co|ipinfo\.io|api\.ipify\.org|ipwho\.is|ifconfig\.me|ip-api\.com)/i.test(urlArg)) {
          taints.add('ip_profiling');
        }
      } else if (callee === 'atob' || callee === 'window.atob' || callee === 'decodeURIComponent') {
        for (const arg of n.arguments || []) visit(arg, d + 1);
        return;
      } else if (callee.endsWith('.get') || callee.endsWith('.getAll')) {
        const obj = getCalleePath(n.callee?.object);
        if (ctx.varTaints.has(obj) || /params|searchParams|query/i.test(obj)) {
          taints.add('url_params');
        }
      } else if (/\.json$|\.text$|\.blob$|\.arrayBuffer$|toBlob$/.test(callee) && n.callee?.object) {
        visit(n.callee.object, d + 1);
      } else if (/toDataURL$|getImageData$|createOscillator$|getSupportedExtensions$/.test(callee)) {
        taints.add('device_fingerprint');
      } else if (/querySelector(?:All)?$|getElementById$|getElementsBy/.test(callee)) {
        const selector = resolveStringExpr(n.arguments?.[0], ctx).value || '';
        if (/password|pwd|pass|cvv|card|pin|otp/i.test(selector)) {
          taints.add('credentials');
        } else if (/email|user|login|form/i.test(selector)) {
          taints.add('form_inputs');
        }
      } else if (callee === 'JSON.stringify') {
        visit(n.arguments?.[0], d + 1);
        return;
      }
      for (const arg of n.arguments || []) visit(arg, d + 1);
      return;
    }

    if (n.type === 'NewExpression') {
      const callee = getCalleePath(n.callee);
      if (callee === 'FormData') {
        taints.add('form_inputs');
        return;
      }
      if (callee === 'URLSearchParams') {
        taints.add('url_params');
        for (const arg of n.arguments || []) visit(arg, d + 1);
        return;
      }
      if (callee === 'Blob' || callee === 'File') {
        for (const arg of n.arguments || []) visit(arg, d + 1);
        return;
      }
      for (const arg of n.arguments || []) visit(arg, d + 1);
      return;
    }

    if (n.type === 'ObjectExpression') {
      for (const prop of n.properties || []) {
        const keyName =
          prop.key?.type === 'Identifier'
            ? prop.key.name
            : prop.key?.type === 'Literal'
              ? String(prop.key.value)
              : '';
        if (keyName) {
          if (FINANCIAL_KEY_RE.test(keyName)) {
            sensitiveKeys++;
            taints.add('financial_pii');
          } else if (/cookie/i.test(keyName)) {
            sensitiveKeys++;
            taints.add('cookies');
          } else if (/keystroke/i.test(keyName)) {
            sensitiveKeys++;
            taints.add('keystrokes_clipboard');
          } else if (CREDENTIAL_KEY_RE.test(keyName)) {
            sensitiveKeys++;
            taints.add('credentials');
          } else if (SESSION_TOKEN_KEY_RE.test(keyName)) {
            taints.add('session_tokens');
          } else if (BENIGN_METRICS_KEY_RE.test(keyName)) {
            benignMetricKeys++;
            if (/error|stack/i.test(keyName)) taints.add('error_telemetry');
            else taints.add('analytics_metrics');
          } else if (FUNCTIONAL_STATE_KEY_RE.test(keyName)) {
            functionalKeys++;
            taints.add('functional_state');
          }
        }
        visit(prop.value, d + 1);
      }
      return;
    }

    if (n.type === 'BinaryExpression') {
      visit(n.left, d + 1);
      visit(n.right, d + 1);
      return;
    }

    if (n.type === 'TemplateLiteral') {
      for (const q of n.quasis || []) {
        const raw = q.value?.cooked || '';
        if (/\b(?:cookie|cookies|pwd|password|keystroke)=/i.test(raw)) {
          if (/cookie/i.test(raw)) taints.add('cookies');
          if (/pwd|password/i.test(raw)) taints.add('credentials');
        }
      }
      for (const e of n.expressions || []) visit(e, d + 1);
      return;
    }

    if (n.type === 'Literal' && typeof n.value === 'string') {
      const s = n.value.toLowerCase();
      if (/^(?:cookies?|pwd|password|pass)=/.test(s)) {
        if (s.startsWith('cookie')) taints.add('cookies');
        else taints.add('credentials');
      } else if (BENIGN_METRICS_KEY_RE.test(s) && !SENSITIVE_KEY_RE.test(s)) {
        taints.add('analytics_metrics');
      }
      return;
    }

    if (n.type === 'ArrayExpression') {
      for (const el of n.elements || []) visit(el, d + 1);
    }
  }

  visit(node, depth);
  return { taints, hasUnknownIdentifier, benignMetricKeys, functionalKeys, sensitiveKeys };
}

function parseScriptAst(code: string): AstNode | null {
  for (const sourceType of ['script', 'module'] as const) {
    try {
      return acorn.parse(code, {
        ecmaVersion: 'latest',
        sourceType,
        allowHashBang: true,
        allowReturnOutsideFunction: true,
        locations: true,
      }) as unknown as AstNode;
    } catch {
      // try next sourceType
    }
  }
  return null;
}

function walkChildren(node: AstNode, visitor: (child: AstNode, parent: AstNode) => void): void {
  for (const key of Object.keys(node)) {
    if (key === 'type' || key === 'start' || key === 'end' || key === 'loc') continue;
    const val = node[key];
    if (Array.isArray(val)) {
      for (const item of val) {
        if (item && typeof item.type === 'string') visitor(item, node);
      }
    } else if (val && typeof val.type === 'string') {
      visitor(val, node);
    }
  }
}

export function taintsToTransmittedTypes(taints: Set<TaintSourceTag>, urlStr: string): TransmittedDataType[] {
  const out = new Set<TransmittedDataType>();
  if (taints.has('credentials')) out.add('credentials');
  if (taints.has('cookies')) out.add('cookies');
  if (taints.has('session_tokens')) out.add('session_tokens');
  if (taints.has('financial_pii')) out.add('financial_pii');
  if (taints.has('keystrokes_clipboard')) out.add('keystrokes_clipboard');
  if (taints.has('device_fingerprint')) out.add('device_fingerprint');
  if (taints.has('storage')) out.add('storage_data');
  if (taints.has('geolocation') || taints.has('ip_profiling')) out.add('geolocation');
  if (taints.has('camera_mic')) out.add('personal_pii');
  if (taints.has('url_params')) out.add('api_keys');
  if (taints.has('form_inputs')) out.add('form_inputs');
  if (taints.has('error_telemetry')) out.add('error_telemetry');
  if (taints.has('analytics_metrics')) out.add('analytics_metrics');
  if (taints.has('functional_state')) out.add('functional_state');

  if (out.size === 0) {
    if (/sentry|bugsnag|rollbar|datadoghq/i.test(urlStr)) out.add('error_telemetry');
    else if (/google-analytics|googletagmanager|analytics|plausible|matomo|mixpanel|posthog|amplitude/i.test(urlStr)) {
      out.add('analytics_metrics');
    } else {
      out.add('unknown');
    }
  }
  return Array.from(out);
}

export function analyzeScriptsWithAst(scripts: ScriptInput[]): JsDataFlowAnalysisResult {
  const transmissions: AstNetworkTransmission[] = [];
  const cookieEvents: AstCookieAccessEvent[] = [];
  const behavioralSignals: AstBehavioralSignal[] = [];
  const backgroundCollections: AstBackgroundCollectionSignal[] = [];
  const serviceWorkerUrls: string[] = [];
  const webWorkerUrls: string[] = [];
  const permissionSites: AstPermissionCallSite[] = [];
  const dataFlowTaints: StaticDataFlowTaintItem[] = [];
  const plantedBackdoors: PlantedBackdoorItem[] = [];
  const seenBackdoorKeys = new Set<string>();
  const domMutationExcerpts: string[] = [];
  const consentEvidence: string[] = [];

  const pushBackdoor = (item: Omit<PlantedBackdoorItem, 'id'>) => {
    const key = `${item.kind}|${item.evidence.slice(0, 64)}`;
    if (seenBackdoorKeys.has(key)) return;
    seenBackdoorKeys.add(key);
    plantedBackdoors.push({ id: `backdoor-${plantedBackdoors.length + 1}`, ...item });
  };

  let scriptsParsed = 0;
  let scriptsFallback = 0;
  let hasConsentApiOrGate = false;
  let hasRejectOrWithdrawHandler = false;
  let hasConsentUiTextInJs = false;
  let obfuscationMarkerCount = 0;
  let isMinifiedBundlePresent = false;

  const scriptQueue: { source: string; code: string; depth: number }[] = scripts
    .slice(0, 12)
    .map((s) => ({ source: s.source, code: s.code, depth: 0 }));

  for (let qi = 0; qi < scriptQueue.length && qi < 24; qi++) {
    const script = scriptQueue[qi];
    const code = script.code || '';
    if (!code.trim()) continue;

    // Minified bundle heuristic (structural layout, NOT obfuscation!)
    const lines = code.split('\n');
    const maxLineLen = lines.reduce((m, l) => Math.max(m, l.length), 0);
    if (code.length > 4000 && maxLineLen > 400 && lines.length < 25) {
      isMinifiedBundlePresent = true;
    }

    if (/(?:reject|decline|deny|withdraw|opt[_-]?out|necessaryOnly|essentialOnly)/i.test(code) && /cookie|consent/i.test(code)) {
      hasRejectOrWithdrawHandler = true;
      consentEvidence.push(`${script.source}: static consent reject/opt-out handler`);
    }
    if (CONSENT_IDENTIFIERS_RE.test(code)) {
      hasConsentApiOrGate = true;
    }
    if (
      /(?:we use cookies|this (?:site|website) uses cookies|accept (?:all )?cookies|cookie (?:consent|notice|preferences|policy|banner|settings)|نستخدم ملفات تعريف الارتباط|سياسة الكوكيز|قبول الكوكيز|موافق على استخدام الكوكيز|CookieConsent|klaro|tarteaucitron|axeptio|osano|borlabs|cmplz|moove_gdpr)/i.test(
        code
      )
    ) {
      hasConsentUiTextInJs = true;
      consentEvidence.push(`${script.source}: JS consent UI / cookie notice text`);
    }

    // Planted backdoor static secret scan (tokens redacted immediately)
    const botTokenMatch = code.match(/\b(\d{6,12}):([A-Za-z0-9_-]{30,})\b/);
    if (botTokenMatch) {
      pushBackdoor({
        kind: 'hardcoded_bot_token',
        severity: 'critical',
        evidence: `${script.source}: Telegram bot token ${botTokenMatch[1]}:***REDACTED***`,
        detail: {
          en: `Hardcoded messaging bot token (${botTokenMatch[1]}:***) embedded directly inside client-side script "${script.source}".`,
          ar: `رمز بوت مراسلة مدمج مباشرة داخل كود العميل (${botTokenMatch[1]}:***) في "${script.source}".`,
        },
      });
    }
    const apiSecretMatch = code.match(/\b(sk_live_[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{30,})\b/);
    if (apiSecretMatch) {
      pushBackdoor({
        kind: 'hardcoded_api_secret',
        severity: 'high',
        evidence: `${script.source}: ${apiSecretMatch[1].slice(0, 8)}***REDACTED***`,
        detail: {
          en: `Hardcoded private/API secret prefix (${apiSecretMatch[1].slice(0, 8)}***) exposed in client-side script "${script.source}".`,
          ar: `مفتاح برمجي خاص أو سري مكشوف داخل كود الواجهة الأمامية (${apiSecretMatch[1].slice(0, 8)}***).`,
        },
      });
    }

    const ast = parseScriptAst(code);
    if (!ast) {
      scriptsFallback++;
      continue;
    }
    scriptsParsed++;

    const ctx: ScriptContext = {
      source: script.source,
      code,
      varStrings: new Map(),
      varTaints: new Map(),
      xhrVars: new Map(),
      fnDefs: new Map(),
      fnTaints: new Map(),
      currentFnStack: ['(top-level)'],
      triggerStack: ['immediate_load'],
      consentBranchDepth: 0,
    };

    // Pass 1: Index named functions so call-graph trigger propagation resolves helper functions called from click/load handlers
    function indexFunctions(node: AstNode): void {
      if (node.type === 'FunctionDeclaration' && node.id?.name) {
        ctx.fnDefs.set(node.id.name, node);
      } else if (
        node.type === 'VariableDeclarator' &&
        node.id?.type === 'Identifier' &&
        node.init &&
        (node.init.type === 'FunctionExpression' || node.init.type === 'ArrowFunctionExpression')
      ) {
        ctx.fnDefs.set(node.id.name, node.init);
      }
      walkChildren(node, (child) => indexFunctions(child));
    }
    indexFunctions(ast);

    // Track per-function invocation triggers from event listeners & timers
    const fnCallTriggers = new Map<string, AstTriggerKind>();
    function markInvokedHelpersInHandler(handlerNode: AstNode | undefined, trig: AstTriggerKind): void {
      if (!handlerNode || trig === 'unknown') return;
      if (handlerNode.type === 'Identifier') {
        fnCallTriggers.set(handlerNode.name, trig);
        return;
      }
      if (handlerNode.type === 'ArrowFunctionExpression' || handlerNode.type === 'FunctionExpression') {
        const scanBody = (sub: AstNode): void => {
          if (!sub || typeof sub.type !== 'string') return;
          if (sub.type === 'CallExpression' && sub.callee?.type === 'Identifier') {
            fnCallTriggers.set(sub.callee.name, trig);
          }
          walkChildren(sub, scanBody);
        };
        scanBody(handlerNode);
      }
    }

    function indexTriggerEdges(node: AstNode): void {
      if (node.type === 'CallExpression') {
        const callee = getCalleePath(node.callee);
        if ((callee === 'addEventListener' || callee.endsWith('.addEventListener')) && node.arguments?.length >= 2) {
          const evType = resolveStringExpr(node.arguments[0], ctx).value?.toLowerCase();
          const handler = node.arguments[1];
          const trig: AstTriggerKind =
            evType === 'click' || evType === 'pointerdown' || evType === 'mousedown' || evType === 'touchstart'
              ? 'user_click'
              : evType === 'submit'
                ? 'form_submit'
                : evType === 'keydown' || evType === 'keyup' || evType === 'keypress'
                  ? 'keystroke_event'
                  : evType === 'beforeunload' || evType === 'pagehide' || evType === 'unload'
                    ? 'page_exit'
                    : evType === 'domcontentloaded' || evType === 'load'
                      ? 'dom_ready'
                      : 'unknown';
          markInvokedHelpersInHandler(handler, trig);
        } else if (callee === 'setInterval' || callee === 'setTimeout' || callee === 'window.setInterval' || callee === 'window.setTimeout') {
          markInvokedHelpersInHandler(node.arguments?.[0], 'timer_interval');
        }
      } else if (
        node.type === 'AssignmentExpression' &&
        node.left?.type === 'MemberExpression'
      ) {
        const propName = (!node.left.computed && node.left.property?.name) || '';
        if (propName === 'onclick' || propName === 'onmousedown' || propName === 'ontouchstart') {
          markInvokedHelpersInHandler(node.right, 'user_click');
        } else if (propName === 'onsubmit') {
          markInvokedHelpersInHandler(node.right, 'form_submit');
        } else if (propName === 'onload') {
          markInvokedHelpersInHandler(node.right, 'dom_ready');
        }
      }
      walkChildren(node, (child) => indexTriggerEdges(child));
    }
    indexTriggerEdges(ast);

    const hasHexArrayObfuscation = /\b_0x[a-f0-9]{4,}\b/i.test(code);
    if (hasHexArrayObfuscation) {
      const hexMatches = code.match(/\b_0x[a-f0-9]{4,}\b/gi) || [];
      const hasExplicitDecl = /\b(?:var|let|const|function)\s+_0x[a-f0-9]{4,}\b/i.test(code);
      if (hexMatches.length >= 2 || hasExplicitDecl) {
        obfuscationMarkerCount += Math.max(hexMatches.length, 2);
        behavioralSignals.push({
          id: `obf-hex-id-${behavioralSignals.length + 1}`,
          sourceScript: script.source,
          sourceFunction: '(module)',
          category: 'obfuscation',
          indicator: `Hex obfuscator identifiers (_0x... x${hexMatches.length})`,
          excerpt: code.slice(0, 140).replace(/\s+/g, ' ').trim(),
          benignContextPossible: false,
          confirmedMaliciousContext: true,
          line: 1,
        });
      }
    }

    const activeTrigger = (): AstTriggerKind => {
      for (let i = ctx.triggerStack.length - 1; i >= 0; i--) {
        if (ctx.triggerStack[i] !== 'immediate_load') return ctx.triggerStack[i];
      }
      return 'immediate_load';
    };

    const currentFnName = (): string => ctx.currentFnStack[ctx.currentFnStack.length - 1] || '(top-level)';

    function recordTx(
      method: AstNetworkTransmission['method'],
      urlNode: AstNode | undefined,
      payloadNode: AstNode | undefined,
      httpMethod: string,
      callNode: AstNode,
      explicitTaints?: Set<TaintSourceTag>
    ): void {
      const resolved = resolveStringExpr(urlNode, ctx);
      const destinationUrl = (resolved.value || '').trim();
      if (!destinationUrl) return;
      const lowerUrl = destinationUrl.toLowerCase();
      if (lowerUrl.startsWith('data:') || lowerUrl.startsWith('blob:') || lowerUrl === '#') return;
      if (DEV_BUILD_ENDPOINT_RE.test(lowerUrl)) return;

      const payloadInfo = collectExprTaints(payloadNode, ctx);
      const urlInfo = collectExprTaints(urlNode, ctx);
      const fnScopeTaints = ctx.fnTaints.get(currentFnName());
      const isBotOrExternalSink =
        /^https?:\/\/api\.telegram\.org\/|^https?:\/\/discord(?:app)?\.com\/api\/webhooks\//i.test(destinationUrl) ||
        /^https?:\/\/hooks\.slack\.com\/|^https?:\/\/webhook\.site\//i.test(destinationUrl) ||
        Boolean(resolved.obfuscated);
      const combinedTaints = new Set<TaintSourceTag>([
        ...payloadInfo.taints,
        ...urlInfo.taints,
        ...(isBotOrExternalSink && fnScopeTaints ? Array.from(fnScopeTaints) : []),
        ...(explicitTaints ? Array.from(explicitTaints) : []),
      ]);

      const trig = activeTrigger();
      const frequency: AstNetworkTransmission['frequency'] =
        trig === 'timer_interval'
          ? 'periodic'
          : trig === 'page_exit'
            ? 'on_exit'
            : trig === 'user_click' || trig === 'form_submit' || trig === 'keystroke_event'
              ? 'on_event'
              : 'once';

      const hasUnknownPayload =
        combinedTaints.size === 0 && (Boolean(payloadNode) && payloadInfo.hasUnknownIdentifier);

      if (combinedTaints.has('cookies')) {
        // Also upgrade matching cookie read events to flowsToExternalTx = true
        for (const ckEv of cookieEvents) {
          if (ckEv.sourceScript === script.source && !ckEv.flowsToExternalTx) {
            ckEv.flowsToExternalTx = true;
            if (!ckEv.operations.includes('transmit')) ckEv.operations.push('transmit');
            if (!ckEv.operations.includes('theft')) ckEv.operations.push('theft');
          }
        }
      }

      transmissions.push({
        sourceScript: script.source,
        sourceFunction: currentFnName(),
        method,
        httpMethod,
        destinationUrl,
        obfuscatedUrl: Boolean(resolved.obfuscated),
        decodedFrom: resolved.decodedFrom,
        taintTags: Array.from(combinedTaints),
        hasUnknownPayload,
        trigger: trig,
        frequency,
        excerpt: safeSlice(code, callNode),
        line: callNode.loc?.start.line || 1,
        consentGated: ctx.consentBranchDepth > 0,
      });
    }

    function inspectCookieAstNode(memberNode: AstNode, parentNode: AstNode, grandparent?: AstNode): void {
      const line = memberNode.loc?.start.line || 1;
      const consentGated = ctx.consentBranchDepth > 0;
      const fnName = currentFnName();

      if (parentNode.type === 'AssignmentExpression' && parentNode.left === memberNode) {
        // document.cookie = ...
        const rhs = parentNode.right;
        const resolvedRhs = resolveStringExpr(rhs, ctx);
        const rawText = safeSlice(code, parentNode);
        const nameMatch = (resolvedRhs.value || rawText).match(/^\s*([A-Za-z0-9_.-]+)\s*=/);
        const cookieName = nameMatch?.[1];
        const ops: CookieAstOperation[] = ['read'];
        if (/encodeURIComponent|btoa/i.test(rawText)) ops.push('encode');
        if (/decodeURIComponent|unescape/i.test(rawText)) ops.push('decode');
        // Note Rule: decodeURIComponent/encoded config alone is NOT malicious unless paired with malicious injection/popunder/XSS/exfil
        const decodedText = resolvedRhs.value || '';
        const hasMaliciousCookieInjection =
          /popunder|cookie_?stuff|aff_sub|ad_?payload/i.test(`${rawText} ${decodedText}`) ||
          /<script|javascript:|onerror\s*=|onload\s*=|\beval\s*\(|\bfetch\s*\(/i.test(decodedText);
        const hasObfuscatedRhs =
          hasMaliciousCookieInjection ||
          Boolean(resolvedRhs.obfuscated) ||
          /\b(?:atob|String\.fromCharCode)\s*\(/.test(rawText);

        cookieEvents.push({
          sourceScript: script.source,
          sourceFunction: fnName,
          kind: 'write',
          cookieName,
          operations: Array.from(new Set(ops)),
          valueExprPreview: resolvedRhs.value?.slice(0, 60),
          flowsToExternalTx: false,
          flowsToStorage: false,
          usesObfuscationOrDynamicPayload: hasObfuscatedRhs,
          usesMaliciousInjection: hasMaliciousCookieInjection,
          consentGated,
          excerpt: rawText,
          line,
        });
        return;
      }

      // document.cookie read — inspect exact AST operation chain!
      const ops: CookieAstOperation[] = ['read'];
      const ancestorSnippet = safeSlice(code, grandparent || parentNode, 180);
      if (/\.(?:split|match|replace|exec)\s*\(/.test(ancestorSnippet)) ops.push('parse');
      if (/\.(?:includes|indexOf|startsWith|endsWith|test|some)\s*\(/.test(ancestorSnippet)) ops.push('validate');
      if (/\.(?:filter|find|map|slice)\s*\(/.test(ancestorSnippet)) ops.push('filter');
      if (/\b(?:encodeURIComponent|btoa)\s*\(/.test(ancestorSnippet)) ops.push('encode');
      if (/\b(?:decodeURIComponent|unescape)\s*\(/.test(ancestorSnippet)) ops.push('decode');

      cookieEvents.push({
        sourceScript: script.source,
        sourceFunction: fnName,
        kind: 'read',
        operations: Array.from(new Set(ops)),
        flowsToExternalTx: false,
        flowsToStorage: false,
        usesObfuscationOrDynamicPayload: false,
        consentGated,
        excerpt: ancestorSnippet || safeSlice(code, memberNode),
        line,
      });
    }

    function checkEvalAndDynamicExecution(callNode: AstNode, callee: string): void {
      const line = callNode.loc?.start.line || 1;
      const arg0 = callNode.arguments?.[0];
      const resolved = resolveStringExpr(arg0, ctx);
      const raw = safeSlice(code, callNode);
      const isObfuscatedExec =
        Boolean(resolved.obfuscated) ||
        /\b(?:atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\(/i.test(raw) ||
        /\b_0x[a-f0-9]+/i.test(raw);

      if (isObfuscatedExec || (resolved.value && /(?:fetch|sendBeacon|document\.cookie|location\.replace|XMLHttpRequest)/i.test(resolved.value))) {
        behavioralSignals.push({
          id: `dyn-eval-${behavioralSignals.length + 1}`,
          sourceScript: script.source,
          sourceFunction: currentFnName(),
          category: 'dynamic_eval',
          indicator: `${callee}(...) with encoded/obfuscated or network payload`,
          excerpt: raw,
          benignContextPossible: false,
          confirmedMaliciousContext: true,
          line,
        });
        if (resolved.value && resolved.value.length >= 6 && script.depth < 2 && scriptQueue.length < 24) {
          scriptQueue.push({
            source: `${script.source} [decoded ${callee}]`,
            code: resolved.value,
            depth: script.depth + 1,
          });
        }
      }
      // Note: plain eval() or new Function() with no obfuscation/exfil is NOT flagged malicious alone (Rule 4 / Section 4)
    }

    function visitNode(node: AstNode, parent: AstNode | null, grandparent: AstNode | null): void {
      if (!node || typeof node.type !== 'string') return;

      // Track function scope & call-graph triggers
      if (
        node.type === 'FunctionDeclaration' ||
        node.type === 'FunctionExpression' ||
        node.type === 'ArrowFunctionExpression'
      ) {
        const fnName =
          node.id?.name ||
          (parent?.type === 'VariableDeclarator' && parent.id?.type === 'Identifier' ? parent.id.name : '') ||
          '(anonymous)';
        ctx.currentFnStack.push(fnName);
        const mappedTrig = fnName !== '(anonymous)' ? fnCallTriggers.get(fnName) : undefined;
        if (mappedTrig) ctx.triggerStack.push(mappedTrig);
        walkChildren(node, (c) => visitNode(c, node, parent));
        if (mappedTrig) ctx.triggerStack.pop();
        ctx.currentFnStack.pop();
        return;
      }

      // Track consent conditionals (e.g. if (hasConsent) { ... })
      let pushedConsent = false;
      if (node.type === 'IfStatement' && node.test) {
        const testSrc = safeSlice(code, node.test, 120);
        if (CONSENT_IDENTIFIERS_RE.test(testSrc) && !/!\s*/.test(testSrc)) {
          hasConsentApiOrGate = true;
          ctx.consentBranchDepth++;
          pushedConsent = true;
        }
      }

      // Variable tracking: var x = expr;
      if (node.type === 'VariableDeclarator' && node.id?.type === 'Identifier' && node.init) {
        const res = resolveStringExpr(node.init, ctx);
        if (res.value !== undefined) ctx.varStrings.set(node.id.name, res);

        const tInfo = collectExprTaints(node.init, ctx);
        if (tInfo.taints.size > 0) ctx.varTaints.set(node.id.name, tInfo.taints);

        if (node.init.type === 'NewExpression' && getCalleePath(node.init.callee) === 'XMLHttpRequest') {
          ctx.xhrVars.set(node.id.name, {});
        }
      }

      // Assignment tracking: x = expr; or f.action = '...'; or img.src = '...';
      if (node.type === 'AssignmentExpression') {
        if (node.left?.type === 'Identifier') {
          const res = resolveStringExpr(node.right, ctx);
          if (res.value !== undefined) ctx.varStrings.set(node.left.name, res);
          const tInfo = collectExprTaints(node.right, ctx);
          if (tInfo.taints.size > 0) {
            const existing = ctx.varTaints.get(node.left.name) || new Set<TaintSourceTag>();
            tInfo.taints.forEach((t) => existing.add(t));
            ctx.varTaints.set(node.left.name, existing);
          }
        } else if (node.left?.type === 'MemberExpression') {
          const leftPath = getCalleePath(node.left);
          const rightStr = resolveStringExpr(node.right, ctx);
          const rawSnippet = safeSlice(code, node);

          if (/\.action$/i.test(leftPath) && rightStr.value && /^https?:\/\//i.test(rightStr.value)) {
            behavioralSignals.push({
              id: `form-rewrite-${behavioralSignals.length + 1}`,
              sourceScript: script.source,
              sourceFunction: currentFnName(),
              category: 'form_rewrite',
              indicator: `Dynamic form action rewrite -> ${rightStr.value}`,
              excerpt: rawSnippet,
              benignContextPossible: false,
              confirmedMaliciousContext: true,
              line: node.loc?.start.line || 1,
            });
          } else if (/(?:\.innerHTML|\.outerHTML)$/i.test(leftPath) && /<(?:form|input|iframe|script)\b/i.test(rightStr.value || rawSnippet)) {
            domMutationExcerpts.push(rawSnippet);
            behavioralSignals.push({
              id: `dom-mut-${behavioralSignals.length + 1}`,
              sourceScript: script.source,
              sourceFunction: currentFnName(),
              category: 'dom_injection',
              indicator: 'Dynamic HTML form/script/iframe injection via innerHTML/outerHTML',
              excerpt: rawSnippet,
              benignContextPossible: true,
              confirmedMaliciousContext: /<form\b|type=['"]password/i.test(rightStr.value || rawSnippet),
              line: node.loc?.start.line || 1,
            });
          } else if (/\.src$/i.test(leftPath)) {
            const tInfo = collectExprTaints(node.right, ctx);
            if (rightStr.value && (tInfo.taints.size > 0 || /^https?:\/\//i.test(rightStr.value)) && /(?:img|beacon|pixel|track)/i.test(leftPath)) {
              recordTx('dynamic_beacon', node.right, node.right, 'GET', node);
            }
          } else if (/^(?:window\.|document\.)?location(?:\.href)?$/i.test(leftPath) && rightStr.value) {
            if (activeTrigger() === 'timer_interval' || activeTrigger() === 'immediate_load') {
              // Redirect only flagged if inside timer/auto or popunder context or pointing to external url via atob
              if (rightStr.obfuscated || activeTrigger() === 'timer_interval') {
                behavioralSignals.push({
                  id: `auto-redir-${behavioralSignals.length + 1}`,
                  sourceScript: script.source,
                  sourceFunction: currentFnName(),
                  category: 'redirect',
                  indicator: `Scripted redirect -> ${rightStr.value.slice(0, 80)}`,
                  excerpt: rawSnippet,
                  benignContextPossible: true,
                  confirmedMaliciousContext: Boolean(rightStr.obfuscated),
                  line: node.loc?.start.line || 1,
                });
              }
            }
          } else if (/(?:^|\.)(?:onclick|onsubmit|onload|onbeforeunload)$/i.test(leftPath)) {
            const evtTrig: AstTriggerKind = leftPath.endsWith('onclick')
              ? 'user_click'
              : leftPath.endsWith('onsubmit')
                ? 'form_submit'
                : leftPath.endsWith('onbeforeunload')
                  ? 'page_exit'
                  : 'dom_ready';
            ctx.triggerStack.push(evtTrig);
            walkChildren(node, (child) => visitNode(child, node, parent));
            ctx.triggerStack.pop();
            if (pushedConsent) ctx.consentBranchDepth--;
            return;
          }
        }
      }

      // document.cookie access
      if (node.type === 'MemberExpression' && getCalleePath(node) === 'document.cookie' && parent) {
        inspectCookieAstNode(node, parent, grandparent || undefined);
      }

      // Debugger trap inside AST
      if (node.type === 'DebuggerStatement') {
        behavioralSignals.push({
          id: `anti-debug-${behavioralSignals.length + 1}`,
          sourceScript: script.source,
          sourceFunction: currentFnName(),
          category: 'anti_debug',
          indicator: 'Anti-debugging debugger; trap statement',
          excerpt: 'debugger;',
          benignContextPossible: false,
          confirmedMaliciousContext: true,
          line: node.loc?.start.line || 1,
        });
      }

      // NewExpression (WebSocket, EventSource, Worker, Function)
      if (node.type === 'NewExpression') {
        const callee = getCalleePath(node.callee);
        if (callee === 'WebSocket' || callee === 'window.WebSocket') {
          recordTx('websocket', node.arguments?.[0], undefined, 'WS', node);
        } else if (callee === 'EventSource' || callee === 'window.EventSource') {
          recordTx('eventsource', node.arguments?.[0], undefined, 'GET', node);
        } else if (callee === 'Worker' || callee === 'window.Worker' || callee === 'SharedWorker') {
          const wUrl = resolveStringExpr(node.arguments?.[0], ctx).value;
          if (wUrl && !webWorkerUrls.includes(wUrl)) webWorkerUrls.push(wUrl);
        } else if (callee === 'Function') {
          checkEvalAndDynamicExecution(node, 'new Function');
        } else if (/(?:AudioContext|webkitAudioContext)$/i.test(callee)) {
          backgroundCollections.push({
            category: 'browser_fingerprinting',
            apisUsed: ['AudioContext'],
            triggers: [activeTrigger()],
            sourceScript: script.source,
            sourceFunction: currentFnName(),
            excerpt: safeSlice(code, node),
            transmittedExternally: false,
            consentGated: ctx.consentBranchDepth > 0,
            isBenignStandalone: true,
          });
        }
      }

      // CallExpression sinks, collection APIs, workers, permissions & event listeners
      if (node.type === 'CallExpression') {
        const callee = getCalleePath(node.callee);
        const line = node.loc?.start.line || 1;
        const snippet = safeSlice(code, node);

        // Consent API detection (e.g., gtag('consent', ...))
        if (callee === 'gtag' && resolveStringExpr(node.arguments?.[0], ctx).value === 'consent') {
          hasConsentApiOrGate = true;
          consentEvidence.push(`${script.source}: Google Consent Mode API`);
        }

        // Event listeners & timer context wrappers (handle chained CallExpressions like document.getElementById('x').addEventListener)
        if ((callee === 'addEventListener' || callee.endsWith('.addEventListener')) && node.arguments?.length >= 2) {
          const evName = (resolveStringExpr(node.arguments[0], ctx).value || '').toLowerCase();
          const cb = node.arguments[1];
          const trig: AstTriggerKind =
            evName === 'click' || evName === 'pointerdown' || evName === 'mousedown' || evName === 'touchstart'
              ? 'user_click'
              : evName === 'submit'
                ? 'form_submit'
                : evName === 'keydown' || evName === 'keyup' || evName === 'keypress'
                  ? 'keystroke_event'
                  : evName === 'beforeunload' || evName === 'pagehide' || evName === 'unload'
                    ? 'page_exit'
                    : evName === 'domcontentloaded' || evName === 'load'
                      ? 'dom_ready'
                      : 'unknown';

          // Check inline password event hooking
          if (/\b(?:password|pwd|pass)\b/i.test(getCalleePath(node.callee)) || /password/i.test(safeSlice(code, node.callee))) {
            behavioralSignals.push({
              id: `pw-hook-${behavioralSignals.length + 1}`,
              sourceScript: script.source,
              sourceFunction: currentFnName(),
              category: 'password_hook',
              indicator: `Password field ${evName || 'input'} event listener`,
              excerpt: snippet,
              benignContextPossible: true,
              confirmedMaliciousContext: false,
              line,
            });
          }

          // Detect unvalidated postMessage 'message' listener without origin check (skip ephemeral dev bundler runtimes)
          if (
            evName === 'message' &&
            !DEV_BUILD_ENDPOINT_RE.test(script.source) &&
            (cb?.type === 'FunctionExpression' || cb?.type === 'ArrowFunctionExpression')
          ) {
            const handlerSrc = code.slice(cb.start, Math.min(cb.end, cb.start + 1500));
            const checksOrigin = /\.(?:origin)\b|origin\s*[!=]==?|\.source\s*[!=]==?\s*(?:window|self|parent|top)/i.test(handlerSrc);
            if (!checksOrigin && /\.(?:data)\b/.test(handlerSrc)) {
              pushBackdoor({
                kind: 'unvalidated_message_listener',
                severity: /(?:innerHTML|outerHTML|eval\s*\(|Function\s*\(|document\.write)/i.test(handlerSrc) ? 'high' : 'medium',
                evidence: `${script.source} line ${line}: message listener reads event.data without verifying event.origin`,
                detail: {
                  en: `Cross-window "message" listener in ${script.source} consumes incoming data without verifying event.origin.`,
                  ar: `مستمع رسائل النافذة "message" في ${script.source} يقرأ البيانات الواردة دون التحقق من event.origin.`,
                },
              });
            }
          }

          ctx.triggerStack.push(trig);
          visitNode(node.callee, node, parent);
          visitNode(node.arguments[0], node, parent);
          visitNode(cb, node, parent);
          ctx.triggerStack.pop();
          return;
        }

        if (callee === 'setInterval' || callee === 'setTimeout' || callee === 'window.setInterval' || callee === 'window.setTimeout') {
          ctx.triggerStack.push('timer_interval');
          for (const a of node.arguments || []) visitNode(a, node, parent);
          ctx.triggerStack.pop();
          return;
        }

        // Unsafe postMessage wildcard targetOrigin ('*')
        if ((callee === 'postMessage' || callee.endsWith('.postMessage')) && !DEV_BUILD_ENDPOINT_RE.test(script.source) && node.arguments?.length >= 2) {
          const targetOrigin = resolveStringExpr(node.arguments[1], ctx).value;
          if (targetOrigin === '*') {
            pushBackdoor({
              kind: 'unsafe_postmessage_wildcard',
              severity: 'medium',
              evidence: `${script.source} line ${line}: ${snippet}`,
              detail: {
                en: `postMessage(..., '*') broadcasts data to any origin without targetOrigin restriction.`,
                ar: `استدعاء postMessage(..., '*') يرسل البيانات لأي أصل خارجي دون تقييد targetOrigin.`,
              },
            });
          }
        }

        // FormData.append / URLSearchParams.append taint propagation
        if (callee.endsWith('.append') && node.callee?.object?.type === 'Identifier' && node.arguments?.length >= 2) {
          const containerVar = node.callee.object.name;
          const fieldKey = (resolveStringExpr(node.arguments[0], ctx).value || '').toLowerCase();
          const valTaint = collectExprTaints(node.arguments[1], ctx);
          const merged = ctx.varTaints.get(containerVar) || new Set<TaintSourceTag>();
          valTaint.taints.forEach((t) => merged.add(t));
          if (/photo|video|audio|camera|mic|snap|frame|record/.test(fieldKey)) merged.add('camera_mic');
          if (/^(?:document|media|file|image|blob)$/.test(fieldKey) && ctx.fnTaints.get(currentFnName())?.has('camera_mic')) {
            merged.add('camera_mic');
          }
          if (/geo|lat|lng|loc|coords/.test(fieldKey)) merged.add('geolocation');
          if (/clip|paste|key/.test(fieldKey)) merged.add('keystrokes_clipboard');
          if (merged.size > 0) ctx.varTaints.set(containerVar, merged);
        }

        // Hidden control / admin / debug query parameter backdoor hook
        if ((callee.endsWith('.get') || callee.endsWith('.has')) && node.arguments?.length >= 1) {
          const paramKey = (resolveStringExpr(node.arguments[0], ctx).value || '').toLowerCase();
          const objName = getCalleePath(node.callee?.object);
          if (
            /^(?:admin|cmd|exec|shell|backdoor|debug_?exec|eval_?code|override|secret_?key|sudo)$/.test(paramKey) &&
            (ctx.varTaints.get(objName)?.has('url_params') || /params|searchParams|query/i.test(objName))
          ) {
            pushBackdoor({
              kind: 'hidden_control_param',
              severity: 'high',
              evidence: `${script.source} line ${line}: checks query parameter "${paramKey}"`,
              detail: {
                en: `Hidden control/backdoor URL query parameter ("${paramKey}") inspected by script logic.`,
                ar: `يفحص السكربت معامل رابط تحكمي مخفي أو باب خلفي ("${paramKey}").`,
              },
            });
          }
        }

        // Service worker registration
        if (callee === 'navigator.serviceWorker.register') {
          const swUrl = resolveStringExpr(node.arguments?.[0], ctx).value;
          if (swUrl && !serviceWorkerUrls.includes(swUrl)) serviceWorkerUrls.push(swUrl);
        }

        // Permission call sites (for AST Call-Graph check in contentAnalyzer)
        if (
          callee === 'Notification.requestPermission' ||
          callee === 'subscribe' ||
          callee.endsWith('.pushManager.subscribe') ||
          callee === 'navigator.geolocation.getCurrentPosition' ||
          callee === 'navigator.geolocation.watchPosition' ||
          callee === 'navigator.mediaDevices.getUserMedia' ||
          callee === 'navigator.mediaDevices.getDisplayMedia' ||
          callee === 'navigator.clipboard.readText' ||
          callee === 'navigator.clipboard.read' ||
          callee === 'navigator.clipboard.writeText' ||
          callee === 'navigator.clipboard.write' ||
          callee === 'navigator.usb.requestDevice' ||
          callee === 'navigator.bluetooth.requestDevice' ||
          callee === 'navigator.hid.requestDevice' ||
          callee === 'navigator.serial.requestPort' ||
          callee === 'navigator.requestMIDIAccess'
        ) {
          const trig = activeTrigger();
          const onEntry = trig === 'immediate_load' || trig === 'dom_ready' || trig === 'timer_interval';
          const fnBucket = ctx.fnTaints.get(currentFnName()) || new Set<TaintSourceTag>();
          if (callee.includes('getUserMedia') || callee.includes('getDisplayMedia')) fnBucket.add('camera_mic');
          else if (callee.includes('geolocation')) fnBucket.add('geolocation');
          else if (callee.includes('clipboard.read')) fnBucket.add('keystrokes_clipboard');
          if (fnBucket.size > 0) ctx.fnTaints.set(currentFnName(), fnBucket);
          permissionSites.push({
            api: callee,
            sourceScript: script.source,
            sourceFunction: currentFnName(),
            triggeredOnEntry: onEntry,
            triggerKind: trig,
            triggerDescription: onEntry
              ? `${script.source} (${currentFnName()}): ${trig}`
              : `${script.source} (${currentFnName()}): bound to ${trig}`,
          });

          if (callee === 'navigator.clipboard.writeText' && node.arguments?.[0]) {
            const clipVal = resolveStringExpr(node.arguments[0], ctx).value || safeSlice(code, node.arguments[0]);
            if (/\b0x[a-fA-F0-9]{40}\b|\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b/.test(clipVal)) {
              behavioralSignals.push({
                id: `wallet-clip-${behavioralSignals.length + 1}`,
                sourceScript: script.source,
                sourceFunction: currentFnName(),
                category: 'wallet_drainer',
                indicator: 'Cryptocurrency wallet address clipboard hijacking',
                excerpt: snippet,
                benignContextPossible: false,
                confirmedMaliciousContext: true,
                line,
              });
            }
          }
        }

        // Dynamic eval
        if (callee === 'eval' || callee === 'window.eval') {
          checkEvalAndDynamicExecution(node, 'eval');
        }

        // Network Sinks
        if (callee === 'fetch' || callee === 'window.fetch') {
          const initArg = node.arguments?.[1];
          let httpMethod = 'GET';
          let bodyNode: AstNode | undefined;
          if (initArg?.type === 'ObjectExpression') {
            for (const p of initArg.properties || []) {
              const k = p.key?.name || p.key?.value;
              if (k === 'method') httpMethod = (resolveStringExpr(p.value, ctx).value || 'GET').toUpperCase();
              if (k === 'body') bodyNode = p.value;
            }
          }
          recordTx('fetch', node.arguments?.[0], bodyNode, httpMethod, node);
        } else if (callee === 'navigator.sendBeacon') {
          recordTx('sendBeacon', node.arguments?.[0], node.arguments?.[1], 'POST', node);
        } else if (callee.endsWith('.open') && node.callee?.object?.type === 'Identifier') {
          const objName = node.callee.object.name;
          if (ctx.xhrVars.has(objName)) {
            const methodStr = (resolveStringExpr(node.arguments?.[0], ctx).value || 'GET').toUpperCase();
            const urlRes = resolveStringExpr(node.arguments?.[1], ctx);
            ctx.xhrVars.set(objName, {
              url: urlRes.value,
              httpMethod: methodStr,
              obfuscatedUrl: urlRes.obfuscated,
              decodedFrom: urlRes.decodedFrom,
            });
          }
        } else if (callee.endsWith('.send') && node.callee?.object?.type === 'Identifier') {
          const objName = node.callee.object.name;
          const xhrMeta = ctx.xhrVars.get(objName);
          if (xhrMeta?.url) {
            recordTx(
              'xhr',
              { type: 'Literal', value: xhrMeta.url, start: node.start, end: node.end },
              node.arguments?.[0],
              xhrMeta.httpMethod || 'GET',
              node
            );
          }
        }

        // Forced redirect APIs
        if (
          (callee === 'window.location.replace' || callee === 'location.replace' || callee === 'location.assign') &&
          activeTrigger() === 'timer_interval'
        ) {
          const redirTarget = resolveStringExpr(node.arguments?.[0], ctx).value || '';
          behavioralSignals.push({
            id: `forced-redir-${behavioralSignals.length + 1}`,
            sourceScript: script.source,
            sourceFunction: currentFnName(),
            category: 'redirect',
            indicator: `Timed JS redirect (${callee} -> ${redirTarget.slice(0, 70)})`,
            excerpt: snippet,
            benignContextPossible: true,
            confirmedMaliciousContext: /atob|evil/i.test(snippet),
            line,
          });
        }

        // Popunder / aggressive window.open
        if (callee === 'window.open' || callee === 'open') {
          const targetUrl = resolveStringExpr(node.arguments?.[0], ctx).value || '';
          const features = resolveStringExpr(node.arguments?.[2], ctx).value || '';
          const isPopunder = /blur\s*\(\s*\)|width\s*=\s*\d+.*height\s*=\s*\d+/i.test(code.slice(Math.max(0, node.start - 80), Math.min(code.length, node.end + 120)));
          if (isPopunder || AD_OR_MINER_DOMAINS_RE.test(targetUrl) || /popunder|under/i.test(features)) {
            behavioralSignals.push({
              id: `popunder-${behavioralSignals.length + 1}`,
              sourceScript: script.source,
              sourceFunction: currentFnName(),
              category: 'popunder',
              indicator: 'Popunder / deceptive popup window trigger',
              excerpt: snippet,
              benignContextPossible: false,
              confirmedMaliciousContext: true,
              line,
            });
          }
        }

        // Fingerprinting APIs
        if ((callee === 'toDataURL' || callee.endsWith('.toDataURL')) && /canvas/i.test(safeSlice(code, node.callee))) {
          backgroundCollections.push({
            category: 'browser_fingerprinting',
            apisUsed: ['canvas.toDataURL'],
            triggers: [activeTrigger()],
            sourceScript: script.source,
            sourceFunction: currentFnName(),
            excerpt: snippet,
            transmittedExternally: false,
            consentGated: ctx.consentBranchDepth > 0,
            isBenignStandalone: true,
          });
        }

        // Storage write with tainted cookie
        if (/^(?:window\.)?(?:localStorage|sessionStorage)\.setItem$/.test(callee)) {
          const valTaint = collectExprTaints(node.arguments?.[1], ctx);
          if (valTaint.taints.has('cookies')) {
            for (const ckEv of cookieEvents) {
              if (ckEv.sourceScript === script.source && !ckEv.flowsToStorage) {
                ckEv.flowsToStorage = true;
                if (!ckEv.operations.includes('store')) ckEv.operations.push('store');
              }
            }
          }
        }

        // Cryptominer detection
        if (AD_OR_MINER_DOMAINS_RE.test(snippet) && /miner|hash|cryptonight|wasm/i.test(snippet)) {
          behavioralSignals.push({
            id: `miner-${behavioralSignals.length + 1}`,
            sourceScript: script.source,
            sourceFunction: currentFnName(),
            category: 'cryptominer',
            indicator: 'Client-side cryptocurrency miner script detected',
            excerpt: snippet,
            benignContextPossible: false,
            confirmedMaliciousContext: true,
            line,
          });
        }
      }

      walkChildren(node, (child) => visitNode(child, node, parent));
      if (pushedConsent) ctx.consentBranchDepth--;
    }

    visitNode(ast, null, null);
  }

  // Correlate background collection with actual transmissions (exclude benign standalone or unconfirmed same-origin form posts)
  const isSuspiciousExternalUrl = (destUrl: string, obf: boolean): boolean => {
    if (obf) return true;
    const clean = destUrl.trim().toLowerCase();
    if (!clean || clean.startsWith('/') && !clean.startsWith('//')) return false;
    if (/^https?:\/\/(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(?:[:/]|$)/i.test(clean)) return false;
    if (/^wss?:\/\/(?:localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(?:[:/]|$)/i.test(clean)) return false;
    return /^https?:\/\/|^wss?:\/\/|^\/\//i.test(clean);
  };

  const cookieTxOccurred = transmissions.some((tx) => tx.taintTags.includes('cookies') && isSuspiciousExternalUrl(tx.destinationUrl, tx.obfuscatedUrl));
  const credentialTxOccurred = transmissions.some(
    (tx) =>
      (tx.taintTags.includes('credentials') || tx.taintTags.includes('financial_pii')) &&
      isSuspiciousExternalUrl(tx.destinationUrl, tx.obfuscatedUrl)
  );
  const fingerprintTxOccurred = transmissions.some((tx) => tx.taintTags.includes('device_fingerprint'));
  const keystrokeTxOccurred = transmissions.some(
    (tx) => tx.taintTags.includes('keystrokes_clipboard') && isSuspiciousExternalUrl(tx.destinationUrl, tx.obfuscatedUrl)
  );

  for (const bg of backgroundCollections) {
    if (bg.category === 'browser_fingerprinting' && fingerprintTxOccurred) {
      bg.transmittedExternally = true;
      bg.isBenignStandalone = false;
    }
  }

  // Only emit background collections for cookies/storage/credentials/keystrokes if genuinely flowing to external/obfuscated transmission
  if (cookieTxOccurred) {
    const cookieTx = transmissions.find((t) => t.taintTags.includes('cookies') && isSuspiciousExternalUrl(t.destinationUrl, t.obfuscatedUrl))!;
    backgroundCollections.push({
      category: 'cookies_storage',
      apisUsed: ['document.cookie'],
      triggers: [cookieTx.trigger],
      sourceScript: cookieTx.sourceScript,
      sourceFunction: cookieTx.sourceFunction,
      excerpt: cookieTx.excerpt,
      transmittedExternally: true,
      consentGated: cookieTx.consentGated,
      isBenignStandalone: false,
    });
  }
  if (credentialTxOccurred) {
    const credTx = transmissions.find(
      (t) => (t.taintTags.includes('credentials') || t.taintTags.includes('financial_pii')) && isSuspiciousExternalUrl(t.destinationUrl, t.obfuscatedUrl)
    )!;
    backgroundCollections.push({
      category: 'credentials_inputs',
      apisUsed: ['input[type="password"] -> network'],
      triggers: [credTx.trigger],
      sourceScript: credTx.sourceScript,
      sourceFunction: credTx.sourceFunction,
      excerpt: credTx.excerpt,
      transmittedExternally: true,
      consentGated: credTx.consentGated,
      isBenignStandalone: false,
    });
  }
  if (keystrokeTxOccurred) {
    const ksTx = transmissions.find((t) => t.taintTags.includes('keystrokes_clipboard'))!;
    backgroundCollections.push({
      category: 'keystrokes_clipboard',
      apisUsed: ['keydown/clipboard -> network sink'],
      triggers: [ksTx.trigger],
      sourceScript: ksTx.sourceScript,
      sourceFunction: ksTx.sourceFunction,
      excerpt: ksTx.excerpt,
      transmittedExternally: true,
      consentGated: ksTx.consentGated,
      isBenignStandalone: false,
    });
  }

  // Anti-debug or periodic exfil timer
  const periodicSensitiveTx = transmissions.find(
    (t) =>
      t.trigger === 'timer_interval' &&
      isSuspiciousExternalUrl(t.destinationUrl, t.obfuscatedUrl) &&
      t.taintTags.some((tag) => ['cookies', 'credentials', 'financial_pii', 'keystrokes_clipboard'].includes(tag))
  );
  if (periodicSensitiveTx) {
    backgroundCollections.push({
      category: 'background_polling',
      apisUsed: ['setInterval', periodicSensitiveTx.method],
      triggers: ['timer_interval'],
      sourceScript: periodicSensitiveTx.sourceScript,
      sourceFunction: periodicSensitiveTx.sourceFunction,
      excerpt: periodicSensitiveTx.excerpt,
      transmittedExternally: true,
      consentGated: periodicSensitiveTx.consentGated,
      isBenignStandalone: false,
    });
  }

  // Build Static AST Data-Flow Taint records linking capture/sensitive sources to external sinks
  const sensitiveTaintSet = new Set<TaintSourceTag>([
    'camera_mic',
    'geolocation',
    'keystrokes_clipboard',
    'ip_profiling',
    'url_params',
    'credentials',
    'financial_pii',
    'cookies',
    'storage',
  ]);
  for (const tx of transmissions) {
    const isRelativeLocal = tx.destinationUrl.startsWith('/') && !tx.destinationUrl.startsWith('//');
    const urlForClassifier = isRelativeLocal
      ? `https://same-origin.local${tx.destinationUrl}`
      : tx.destinationUrl.startsWith('//')
        ? `https:${tx.destinationUrl}`
        : tx.destinationUrl;
    const channelInfo = classifyNetworkChannel(
      urlForClassifier,
      isRelativeLocal ? 'same-origin.local' : '',
      tx.httpMethod
    );
    const matchedSens = tx.taintTags.filter((t) => sensitiveTaintSet.has(t));
    if (
      matchedSens.length > 0 ||
      channelInfo.category === 'HIGH_RISK_EXFILTRATION_CHANNEL' ||
      channelInfo.category === 'WEBHOOK_OR_BOT_SINK'
    ) {
      const primary = matchedSens[0];
      const sourceKind: StaticDataFlowTaintItem['sourceKind'] =
        primary === 'camera_mic'
          ? 'camera_mic'
          : primary === 'geolocation'
            ? 'geolocation'
            : primary === 'keystrokes_clipboard'
              ? 'clipboard'
              : primary === 'ip_profiling'
                ? 'ip_profiling'
                : primary === 'url_params'
                  ? 'url_params'
                  : primary === 'cookies' || primary === 'storage'
                    ? 'storage_cookies'
                    : 'credentials_form';
      const triggerContext: StaticDataFlowTaintItem['triggerContext'] =
        tx.trigger === 'immediate_load' || tx.trigger === 'dom_ready' || tx.trigger === 'timer_interval'
          ? 'STATIC_AUTO_TRIGGER_ON_LOAD'
          : tx.trigger === 'user_click' || tx.trigger === 'form_submit'
            ? 'user_click'
            : 'unknown';
      const confirmedStaticFlow =
        matchedSens.length > 0 &&
        (!isRelativeLocal || tx.obfuscatedUrl) &&
        (channelInfo.category === 'HIGH_RISK_EXFILTRATION_CHANNEL' ||
          channelInfo.category === 'WEBHOOK_OR_BOT_SINK' ||
          isSuspiciousExternalUrl(tx.destinationUrl, tx.obfuscatedUrl));

      dataFlowTaints.push({
        id: `taint-${dataFlowTaints.length + 1}`,
        source: matchedSens.join(', ') || tx.sourceFunction,
        sourceKind,
        sink: `${tx.method}(${channelInfo.domain || tx.destinationUrl.slice(0, 60)})`,
        sinkChannel: channelInfo.category,
        triggerContext,
        confirmedStaticFlow,
        detail: {
          en: `CONFIRMED_DATA_EXFILTRATION_FLOW (Static AST): [${matchedSens.join(', ') || 'sensitive payload'}] from ${tx.sourceFunction} flows into ${tx.method} -> ${channelInfo.domain} (${channelInfo.category}).`,
          ar: `تدفق تسريب بيانات مؤكد (تحليل ساكن AST): تتدفق بيانات [${matchedSens.join('، ') || 'حساسة'}] من ${tx.sourceFunction} إلى ${tx.method} -> ${channelInfo.domain}.`,
        },
        excerpt: tx.excerpt,
      });
    }
  }

  return {
    scriptsParsed,
    scriptsFallback,
    transmissions,
    cookieEvents,
    behavioralSignals,
    backgroundCollections,
    serviceWorkerUrls,
    webWorkerUrls,
    permissionSites,
    dataFlowTaints,
    plantedBackdoors,
    consentMechanismInJs: {
      hasConsentApiOrGate,
      hasRejectOrWithdrawHandler,
      hasConsentUiTextInJs,
      evidence: consentEvidence.slice(0, 6),
    },
    obfuscationMarkerCount,
    isMinifiedBundlePresent,
    domMutationExcerpts: domMutationExcerpts.slice(0, 6),
  };
}
