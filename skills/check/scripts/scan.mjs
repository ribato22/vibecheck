#!/usr/bin/env node
// vibecheck scanner: the fast, deterministic first pass of the vibecheck audit. vibecheck-ignore-file
// Read-only. Zero dependencies. No network. It never runs your project's code.
//
//   node scan.mjs [path] [--json] [--fail-on critical|high|medium|low] [--strict]
//
// --fail-on exits 1 when a high-confidence finding at or above that severity exists (for CI).
// --strict  makes --fail-on count "verify" leads too.

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative, basename, extname, resolve, sep, posix } from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  SEVERITIES, SEVERITY_RANK, CODE_RULES, PUBLIC_ENV_RE,
  findSecrets, mask, redact, classifyEnvName,
} from './rules.mjs';

const VERSION = '1.1.1';
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_FILES = 20000;
const MAX_PER_RULE = { text: 25, json: 200 }; // agents read --json and need the full picture

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', '.next', '.nuxt', '.svelte-kit', '.output', '.vercel',
  '.netlify', 'coverage', 'vendor', 'venv', '.venv', '__pycache__', '.turbo', '.cache', 'Pods', '.expo',
  '.gradle', 'target', '.vibecheck', 'bower_components', '.parcel-cache', 'storybook-static', '.terraform',
]);
const SKIP_EXT = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.avif', '.ico', '.bmp', '.tiff', '.psd', '.svg', '.pdf',
  '.zip', '.gz', '.tgz', '.rar', '.7z', '.jar', '.woff', '.woff2', '.ttf', '.otf', '.eot', '.mp3', '.mp4',
  '.mov', '.avi', '.webm', '.wav', '.ogg', '.flac', '.so', '.dylib', '.dll', '.exe', '.bin', '.wasm',
  '.pyc', '.class', '.db', '.sqlite', '.sqlite3', '.map', '.lockb',
]);
const SKIP_NAMES = new Set([
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'Cargo.lock', 'poetry.lock',
  'Pipfile.lock', 'composer.lock', 'Gemfile.lock', 'go.sum', 'uv.lock',
]);

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const argv = process.argv.slice(2);
const opts = { json: false, strict: false, failOn: null, path: '.' };
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--json') opts.json = true;
  else if (a === '--strict') opts.strict = true;
  else if (a === '--fail-on') opts.failOn = argv[++i];
  else if (a === '--version') { console.log(VERSION); process.exit(0); }
  else if (a === '--help' || a === '-h') {
    console.log('usage: node scan.mjs [path] [--json] [--fail-on critical|high|medium|low] [--strict]');
    process.exit(0);
  } else opts.path = a;
}
if (opts.failOn && !(opts.failOn in SEVERITY_RANK)) {
  console.error(`--fail-on must be one of: ${SEVERITIES.join(', ')}`);
  process.exit(2);
}

const root = resolve(opts.path);
if (!existsSync(root) || !statSync(root).isDirectory()) {
  console.error(`vibecheck: not a directory: ${root}`);
  process.exit(2);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const toPosix = (p) => p.split(sep).join('/');

function git(args) {
  const r = spawnSync('git', args, { cwd: root, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
  return r.status === 0 ? r.stdout : null;
}

function walk(dir, depth, out, filter) {
  if (out.length >= MAX_FILES || depth < 0) return;
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (e.isDirectory()) {
      if (!SKIP_DIRS.has(e.name)) walk(join(dir, e.name), depth - 1, out, filter);
    } else if (e.isFile() && (!filter || filter(e.name))) {
      out.push(toPosix(relative(root, join(dir, e.name))));
    }
  }
}

const ENV_NAME = /^\.env(?:\..+)?$|\.env$|^\.dev\.vars$/;
const ENV_EXAMPLE = /(?:example|sample|template|dist|defaults?)$/i;
const isEnvFile = (rel) => ENV_NAME.test(basename(rel));
const isRealEnvFile = (rel) => isEnvFile(rel) && !ENV_EXAMPLE.test(basename(rel));
const isTestPath = (rel) => /(?:^|\/)(?:__tests__|tests?|spec|fixtures?|mocks?|__mocks__|e2e)\/|\.(?:test|spec)\.[cm]?[jt]sx?$/.test(rel);
// Code that doesn't ship: backups, archives and QA tooling. Secrets are still scanned there.
const isArchivePath = (rel) =>
  /(?:^|\/)(?:backups?|archives?|archived|old|deprecated|qa)(?:[-_.][^/]*)?\/|(?:^|\/)(?:playwright|cypress)\/|[-_.](?:backup|bak|old|orig|copy)\.(?:[cm]?[jt]sx?|py)$/i.test(rel);
const isNonShipping = (rel) => isTestPath(rel) || isArchivePath(rel);
const inSkippedDir = (rel) => rel.split('/').slice(0, -1).some((d) => SKIP_DIRS.has(d));

function langOf(rel) {
  const ext = extname(rel).toLowerCase();
  if (['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte', '.astro'].includes(ext)) return 'js';
  if (ext === '.py') return 'py';
  if (['.rb', '.php', '.go', '.java', '.kt', '.cs', '.rs', '.dart', '.swift', '.ex', '.exs'].includes(ext)) return 'other';
  return null;
}

function lineStarts(content) {
  const idx = [0];
  for (let i = 0; i < content.length; i++) if (content.charCodeAt(i) === 10) idx.push(i + 1);
  return idx;
}

function lineAt(starts, pos) {
  let lo = 0, hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= pos) lo = mid; else hi = mid - 1;
  }
  return lo + 1;
}

const snippet = (line) => redact(line.trim()).slice(0, 140);

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

const findings = [];
const perRule = new Map();
const hidden = new Map(); // rule id -> Map(file -> matches not shown)
const seen = new Set();

function add(f) {
  const key = `${f.id}|${f.file}|${f.line}|${f.title}`;
  if (seen.has(key)) return;
  seen.add(key);
  const n = (perRule.get(f.id) || 0) + 1;
  perRule.set(f.id, n);
  if (n > MAX_PER_RULE[opts.json ? 'json' : 'text']) {
    const files = hidden.get(f.id) || new Map();
    const where = f.file || '(project)';
    files.set(where, (files.get(where) || 0) + 1);
    hidden.set(f.id, files);
    return;
  }
  findings.push({ confidence: 'high', file: null, line: null, evidence: null, fix: null, ...f });
}

// ---------------------------------------------------------------------------
// 1. Files and stack
// ---------------------------------------------------------------------------

const notes = [];
const gitList = git(['ls-files', '-co', '--exclude-standard', '-z']);
const isGit = gitList !== null;
let files;
if (isGit) {
  files = gitList.split('\0').filter(Boolean).filter((f) => !inSkippedDir(f));
} else {
  files = [];
  walk(root, 30, files);
}
if (files.length > MAX_FILES) {
  notes.push(`Only the first ${MAX_FILES} files were scanned.`);
  files = files.slice(0, MAX_FILES);
}
const fileSet = new Set(files);

const stack = new Set();
const deps = new Set();
let rootDeps = 0;

const DEP_STACK = {
  next: 'nextjs', vite: 'vite', 'react-scripts': 'create-react-app', react: 'react', vue: 'vue', nuxt: 'nuxt',
  '@sveltejs/kit': 'sveltekit', astro: 'astro', '@remix-run/react': 'remix', expo: 'expo', 'react-native': 'react-native',
  express: 'express', hono: 'hono', fastify: 'fastify', '@nestjs/core': 'nestjs', koa: 'koa',
  '@supabase/supabase-js': 'supabase', '@supabase/ssr': 'supabase', firebase: 'firebase', 'firebase-admin': 'firebase',
  convex: 'convex', '@prisma/client': 'prisma', 'drizzle-orm': 'drizzle', mongoose: 'mongodb', mongodb: 'mongodb',
  stripe: 'stripe', '@stripe/stripe-js': 'stripe', '@lemonsqueezy/lemonsqueezy.js': 'lemonsqueezy',
  '@paddle/paddle-node-sdk': 'paddle', 'midtrans-client': 'midtrans', 'xendit-node': 'xendit',
  '@clerk/nextjs': 'clerk', '@clerk/clerk-react': 'clerk', 'next-auth': 'authjs', '@auth/core': 'authjs',
  'better-auth': 'better-auth', openai: 'openai', '@anthropic-ai/sdk': 'anthropic', ai: 'vercel-ai-sdk',
  '@google/generative-ai': 'gemini', '@google/genai': 'gemini', 'groq-sdk': 'groq', langchain: 'langchain',
  '@langchain/core': 'langchain', replicate: 'replicate', resend: 'resend', nodemailer: 'email',
  '@sendgrid/mail': 'email', postmark: 'email', twilio: 'sms',
};
const PY_STACK = {
  fastapi: 'fastapi', flask: 'flask', django: 'django', streamlit: 'streamlit', gradio: 'gradio',
  openai: 'openai', anthropic: 'anthropic', stripe: 'stripe', supabase: 'supabase', 'firebase-admin': 'firebase',
  'google-generativeai': 'gemini', 'google-genai': 'gemini', langchain: 'langchain', twilio: 'sms',
  midtransclient: 'midtrans', xendit: 'xendit', 'xendit-python': 'xendit', sqlalchemy: 'sqlalchemy',
};
const AI_STACK = ['openai', 'anthropic', 'vercel-ai-sdk', 'gemini', 'groq', 'langchain', 'replicate'];
const COSTLY_STACK = [...AI_STACK, 'email', 'resend', 'sms'];
const WEB_STACK = ['nextjs', 'vite', 'react', 'vue', 'nuxt', 'sveltekit', 'astro', 'remix', 'create-react-app'];

const readText = (rel) => {
  try { return readFileSync(join(root, rel), 'utf8'); } catch { return null; }
};

for (const rel of files) {
  const name = basename(rel);
  if (name === 'package.json') {
    try {
      const pkg = JSON.parse(readText(rel));
      const names = Object.keys({ ...pkg.dependencies, ...pkg.devDependencies });
      if (rel === 'package.json') rootDeps = names.length;
      for (const d of names) {
        deps.add(d);
        if (DEP_STACK[d]) stack.add(DEP_STACK[d]);
        if (d.startsWith('@ai-sdk/')) stack.add('vercel-ai-sdk');
      }
    } catch { /* unreadable package.json: ignore */ }
  } else if (/^requirements.*\.txt$|^pyproject\.toml$|^Pipfile$/.test(name)) {
    const text = (readText(rel) || '').toLowerCase();
    for (const [d, s] of Object.entries(PY_STACK)) {
      if (new RegExp(`(^|[\\s"'\\[])${d.replace(/[-]/g, '[-_]')}([\\s"'=<>~!\\[;,]|$)`, 'm').test(text)) {
        deps.add(d);
        stack.add(s);
      }
    }
    for (const d of ['slowapi', 'flask-limiter', 'django-ratelimit', 'fastapi-limiter', 'sentry-sdk']) {
      if (text.includes(d)) deps.add(d);
    }
  }
  if (/(?:^|\/)supabase\/(?:config\.toml|migrations\/)/.test(rel)) stack.add('supabase');
  if (/(?:^|\/)(?:firebase\.json|firestore\.rules|storage\.rules|database\.rules\.json)$/.test(rel)) stack.add('firebase');
  if (/(?:^|\/)vercel\.json$/.test(rel)) stack.add('vercel');
  if (/(?:^|\/)netlify\.toml$/.test(rel)) stack.add('netlify');
  if (/(?:^|\/)wrangler\.(?:toml|jsonc?)$/.test(rel)) stack.add('cloudflare');
}

const has = (...names) => names.some((n) => stack.has(n));

function isLikelyClient(rel, content) {
  if (/^\s*["']use client["']/m.test(content)) return true;
  if (/^\s*["']use server["']/m.test(content)) return false;
  if (/(?:^|\/)(?:api|server|backend|functions|lambda|scripts|supabase|migrations|prisma|convex|workers?)\//.test(rel)) return false;
  if (/\.server\.|\+server\.|\+api\.|(?:^|\/)(?:route|middleware|proxy|instrumentation)\.[cm]?[jt]s$|\.config\.[cm]?[jt]s$/.test(rel)) return false;
  if (langOf(rel) !== 'js' || /\.astro$/.test(rel)) return false;
  if (/\.(?:vue|svelte)$/.test(rel)) return true;
  if (/(?:^|\/)(?:components|hooks|ui|client)\//.test(rel)) return true;
  if (has('expo', 'react-native')) return true;
  const spa = has('vite', 'create-react-app') && !has('nextjs', 'remix', 'sveltekit', 'nuxt', 'astro');
  return spa && /(?:^|\/)src\//.test(rel);
}

// A file under test/backup/QA folders still ships when app code imports it (say, a shared helper kept in
// qa-scripts/). Follow relative imports from app code, transitively, and check those files like app code.
const IMPORT_RE = /(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)["'`](\.{1,2}\/[^"'`\n]+)["'`]/g;
const RESOLVE_EXT = ['', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.mts', '.cts', '.vue', '.svelte'];

function resolveImport(from, spec) {
  const base = posix.normalize(posix.join(posix.dirname(from), spec));
  const stems = [base];
  if (/\.[cm]?js$/.test(base)) stems.push(base.replace(/\.([cm]?)js$/, '.$1ts'), base.replace(/\.js$/, '.tsx')); // TS: './x.js' is x.ts
  for (const stem of stems) {
    for (const ext of RESOLVE_EXT) if (fileSet.has(stem + ext)) return stem + ext;
    for (const ext of RESOLVE_EXT.slice(1)) if (fileSet.has(`${stem}/index${ext}`)) return `${stem}/index${ext}`;
  }
  return null;
}

function findImportedNonShipping() {
  const imported = new Set();
  const queue = files.filter((rel) => langOf(rel) === 'js' && !isNonShipping(rel));
  const visited = new Set(queue);
  while (queue.length) {
    const rel = queue.pop();
    let st;
    try { st = statSync(join(root, rel)); } catch { continue; }
    if (!st.isFile() || st.size > MAX_FILE_BYTES) continue;
    for (const m of (readText(rel) || '').matchAll(IMPORT_RE)) {
      const target = resolveImport(rel, m[1]);
      if (!target || visited.has(target)) continue;
      visited.add(target);
      if (isNonShipping(target)) imported.add(target);
      queue.push(target);
    }
  }
  return imported;
}

const shippedAnyway = findImportedNonShipping();

// ---------------------------------------------------------------------------
// 2. Per-file checks
// ---------------------------------------------------------------------------

const signals = { rateLimit: false, monitoring: false, analytics: false, og: false, privacy: false, terms: false, envUsage: false };
const SIGNAL_RE = {
  rateLimit: /rate.?limit|ratelimit|throttl/i,
  monitoring: /@sentry\/|sentry_sdk|logrocket|bugsnag|@highlight-run|rollbar|honeybadger|@axiomhq|@logtail|dd-trace|newrelic|posthog/i,
  analytics: /@vercel\/analytics|posthog|plausible|umami|gtag\(|googletagmanager|mixpanel|amplitude|@segment|usefathom|simpleanalytics|cloudflareinsights|clarity\.ms/i,
  og: /og:image|openGraph|twitter:card/,
  privacy: /href=["'`][^"'`]*privacy|privacy[ -]policy|kebijakan privasi/i,
  terms: /href=["'`][^"'`]*terms|terms of (?:service|use)|syarat (?:dan|&) ketentuan/i,
  envUsage: /process\.env|import\.meta\.env|os\.environ|os\.getenv|Deno\.env/,
};

const sqlFiles = [];
const publicEnvSeen = new Map();
const skippedDirs = new Map();
let scanned = 0;

function notePublicEnv(fullName, suffix, rel, line) {
  const level = classifyEnvName(suffix);
  if (!level) return;
  const prev = publicEnvSeen.get(fullName);
  if (prev) { prev.count++; return; }
  const f = {
    id: 'VC-ENV-PUBLIC-SECRET', category: 'secrets', severity: level,
    confidence: level === 'critical' ? 'high' : 'verify',
    title: `${fullName} is shipped to every visitor's browser`,
    file: rel, line, evidence: fullName,
    fix: `Variables starting with ${fullName.slice(0, fullName.length - suffix.length)} are bundled into the front-end. Rename it without the public prefix, use it only in server code, and rotate the key if it was ever deployed.`,
    count: 1,
  };
  publicEnvSeen.set(fullName, f);
}

for (const rel of files) {
  const name = basename(rel);
  const ext = extname(rel).toLowerCase();
  if (SKIP_NAMES.has(name) || SKIP_EXT.has(ext) || /\.min\.[cm]?(?:js|css)$/.test(name)) continue;
  let st;
  try { st = statSync(join(root, rel)); } catch { continue; }
  if (!st.isFile() || st.size > MAX_FILE_BYTES) continue;
  const content = readText(rel);
  if (content === null || content.includes('\u0000')) continue;
  if (content.slice(0, 300).includes('vibecheck-ignore-file')) continue;
  scanned++;

  const lang = langOf(rel);
  const lines = content.split('\n');
  const envFile = isEnvFile(rel);

  // Secrets. Outside git we can't tell an ignored .env from a committed one, so we leave real .env files alone.
  if (isGit || !isRealEnvFile(rel)) {
    lines.forEach((line, i) => {
      for (const { rule, value } of findSecrets(line)) {
        if (rule.id === 'VC-KEY-GENERIC' && isTestPath(rel)) continue; // tests are full of fake "secret" values
        add({ id: rule.id, category: 'secrets', severity: rule.severity, confidence: rule.confidence,
          title: rule.title, file: rel, line: i + 1, evidence: mask(value), fix: rule.fix });
      }
    });
  }

  // Public env names (only meaningful for JS projects and env files).
  if (lang === 'js' || envFile) {
    lines.forEach((line, i) => {
      if (line.includes('vibecheck-ignore')) return;
      for (const m of line.matchAll(PUBLIC_ENV_RE)) notePublicEnv(m[0], m[2], rel, i + 1);
    });
  }

  for (const [k, re] of Object.entries(SIGNAL_RE)) if (!signals[k] && re.test(content)) signals[k] = true;

  const rulesFile = /(?:^|\/)(?:[\w.-]+\.rules|database\.rules\.json)$/.test(rel);
  if ((lang || ext === '.sql' || rulesFile) && isNonShipping(rel) && !shippedAnyway.has(rel)) {
    const dir = rel.includes('/') ? rel.slice(0, rel.lastIndexOf('/') + 1) : './';
    skippedDirs.set(dir, (skippedDirs.get(dir) || 0) + 1);
    continue;
  }
  if (ext === '.sql') sqlFiles.push({ rel, content });
  if (rulesFile) analyzeFirebaseRules(rel, content);
  if (!lang) continue;

  const starts = lineStarts(content);
  const at = (pos) => lineAt(starts, pos);

  for (const rule of CODE_RULES) {
    if (!rule.langs.includes(lang)) continue;
    if (rule.path && !rule.path.test(rel)) continue;
    if (rule.requires && !rule.requires.test(content)) continue;
    rule.re.lastIndex = 0;
    for (const m of content.matchAll(rule.re)) {
      const line = at(m.index);
      if (lines[line - 1].includes('vibecheck-ignore')) continue;
      let severity = rule.severity;
      if (rule.id === 'VC-CFG-CORS' && /credentials\s*:\s*true|allow_credentials\s*=\s*True|Allow-Credentials["']?\s*[,:]\s*["']?true/i.test(content)) severity = 'high';
      add({ id: rule.id, category: rule.category, severity, confidence: rule.confidence, title: rule.title,
        file: rel, line, evidence: snippet(lines[line - 1]), fix: rule.fix });
    }
  }

  if (lang !== 'js') continue;

  // Supabase admin key used where the browser can see it.
  const svc = /SERVICE_ROLE|service_role|sb_secret_|SUPABASE_SECRET_KEY/.exec(content);
  if (svc && isLikelyClient(rel, content)) {
    const line = at(svc.index);
    add({ id: 'VC-DB-SERVICE-KEY-CLIENT', category: 'database', severity: 'critical', confidence: 'verify',
      title: 'Supabase admin (service_role) key used in browser code',
      file: rel, line, evidence: snippet(lines[line - 1]),
      fix: 'The service_role key skips every RLS policy. Use it only in server code (API routes, server actions, edge functions); the browser gets the anon/publishable key.' });
  }

  // Webhook handler that never checks the Stripe signature.
  if (/webhook/i.test(rel + content) && /stripe/i.test(content) &&
      /(?:event|body|payload)\.type\b|checkout\.session\.completed|customer\.subscription/.test(content) &&
      !/constructEvent/.test(content)) {
    add({ id: 'VC-PAY-WEBHOOK-UNVERIFIED', category: 'money', severity: 'high', confidence: 'verify',
      title: 'Stripe webhook handler without signature verification', file: rel, line: 1,
      fix: 'Anyone can POST a fake "payment succeeded" event and unlock paid features. Verify with stripe.webhooks.constructEvent(rawBody, signature, STRIPE_WEBHOOK_SECRET).' });
  }

  // next.config.js `env: {}` inlines values into the client bundle.
  if (/(?:^|\/)next\.config\.[cm]?[jt]s$/.test(rel)) {
    const block = /\benv\s*:\s*\{([\s\S]*?)\}/.exec(content);
    if (block) {
      for (const m of block[1].matchAll(/([A-Z][A-Z0-9_]{2,})\s*:/g)) {
        if (classifyEnvName(m[1]) !== 'critical') continue;
        const line = at(block.index + block[0].indexOf(m[0]));
        add({ id: 'VC-ENV-NEXT-CONFIG', category: 'secrets', severity: 'critical', confidence: 'verify',
          title: `next.config.js "env" ships ${m[1]} to the browser`, file: rel, line, evidence: m[1],
          fix: 'Values in next.config "env" are inlined into client JavaScript. Remove it there and read process.env on the server only.' });
      }
    }
  }
}

// Ignored .env files aren't in the git listing, but their variable *names* still decide what ships to the browser.
const envFiles = [];
walk(root, 4, envFiles, (n) => ENV_NAME.test(n));
for (const rel of envFiles) {
  if (fileSet.has(rel)) continue;
  (readText(rel) || '').split('\n').forEach((line, i) => {
    const m = /^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=/.exec(line);
    if (!m || line.includes('vibecheck-ignore')) return;
    for (const p of m[1].matchAll(PUBLIC_ENV_RE)) if (p.index === 0) notePublicEnv(p[0], p[2], rel, i + 1);
  });
}
for (const f of publicEnvSeen.values()) {
  if (f.count > 1) f.title += ` (${f.count} places)`;
  delete f.count;
  add(f);
}

// ---------------------------------------------------------------------------
// 3. Database rules
// ---------------------------------------------------------------------------

function blankComments(text, lineComment) {
  const blank = (m) => m.replace(/[^\n]/g, ' ');
  return text.replace(/\/\*[\s\S]*?\*\//g, blank).replace(lineComment, blank);
}

function analyzeFirebaseRules(rel, content) {
  const text = blankComments(content, /\/\/[^\n]*/g);
  const starts = lineStarts(text);
  const push = (pos, severity, title, fix) =>
    add({ id: 'VC-DB-FIREBASE-OPEN', category: 'database', severity, confidence: severity === 'critical' ? 'high' : 'verify',
      title, file: rel, line: lineAt(starts, pos), evidence: snippet(content.split('\n')[lineAt(starts, pos) - 1]), fix });
  const OWNER_FIX = 'Allow access only to the owner, e.g. `allow read, write: if request.auth != null && request.auth.uid == userId;`';

  for (const m of text.matchAll(/allow\s+([a-z, ]+?)\s*(?::\s*if\s+(true|request\.auth\s*!=\s*null)\s*)?;/gi)) {
    const ops = m[1].toLowerCase();
    const writes = /write|create|update|delete/.test(ops);
    if (m[2] === undefined || m[2] === 'true') {
      push(m.index, writes ? 'critical' : 'high',
        writes ? 'Security rule lets anyone write or delete data' : 'Security rule lets anyone read data', OWNER_FIX);
    } else {
      push(m.index, writes ? 'high' : 'medium',
        writes ? 'Any signed-in user can change everyone\'s data' : 'Any signed-in user can read everyone\'s data',
        `"Signed in" isn't "owner": anyone can sign up. ${OWNER_FIX}`);
    }
  }
  for (const m of text.matchAll(/request\.time\s*<\s*timestamp\.date\(/g)) {
    push(m.index, 'critical', 'Firebase "test mode" rules: wide open until the expiry date',
      'Test-mode rules let anyone read and write everything, then lock everyone out on the date. Replace with real owner-based rules.');
  }
  for (const m of text.matchAll(/"\.(read|write)"\s*:\s*(true|"true"|"auth\s*!=\s*null")/g)) {
    const writes = m[1] === 'write';
    const anyone = m[2] !== '"auth != null"';
    push(m.index, anyone ? (writes ? 'critical' : 'high') : (writes ? 'high' : 'medium'),
      `Realtime Database lets ${anyone ? 'anyone' : 'any signed-in user'} ${m[1]} this path`,
      'Scope rules to the owner, e.g. ".write": "auth != null && auth.uid === $uid".');
  }
}

function analyzeSupabaseSql() {
  sqlFiles.sort((a, b) => a.rel.localeCompare(b.rel));
  const NAME = '((?:"?\\w+"?\\.)?"?\\w+"?)';
  const norm = (n) => n.replace(/"/g, '').toLowerCase().replace(/^public\./, '');
  const isPublic = (n) => !n.replace(/"/g, '').includes('.') || /^"?public"?\./i.test(n);
  const tables = new Map(); // name -> { rel, line, rls }

  for (const { rel, content } of sqlFiles) {
    const text = blankComments(content, /--[^\n]*/g);
    const starts = lineStarts(text);
    const at = (pos) => lineAt(starts, pos);
    const loc = (pos) => ({ file: rel, line: at(pos), evidence: snippet(content.split('\n')[at(pos) - 1]) });

    for (const m of text.matchAll(new RegExp(`create\\s+table\\s+(?:if\\s+not\\s+exists\\s+)?${NAME}`, 'gi'))) {
      if (isPublic(m[1]) && !tables.has(norm(m[1]))) tables.set(norm(m[1]), { ...loc(m.index), rls: false });
    }
    for (const m of text.matchAll(new RegExp(`alter\\s+table\\s+(?:only\\s+)?(?:if\\s+exists\\s+)?${NAME}\\s+(enable|disable)\\s+row\\s+level\\s+security`, 'gi'))) {
      const t = tables.get(norm(m[1]));
      const enable = m[2].toLowerCase() === 'enable';
      if (t) t.rls = enable;
      if (!enable) {
        add({ id: 'VC-DB-RLS-DISABLED', category: 'database', severity: 'critical', title: `RLS explicitly disabled on "${norm(m[1])}"`,
          ...loc(m.index), fix: 'With RLS off, anyone holding your public anon key can read and change every row. Enable RLS and add owner policies.' });
      }
    }
    for (const m of text.matchAll(new RegExp(`drop\\s+table\\s+(?:if\\s+exists\\s+)?${NAME}`, 'gi'))) tables.delete(norm(m[1]));

    for (const m of text.matchAll(new RegExp(`create\\s+policy\\s+("[^"]+"|\\w+)\\s+on\\s+${NAME}([\\s\\S]*?);`, 'gi'))) {
      const [, policy, table, body] = m;
      if (/user_metadata|raw_user_meta_data/i.test(body)) {
        add({ id: 'VC-DB-POLICY-USER-METADATA', category: 'database', severity: 'high', title: `Policy ${policy} trusts user_metadata`,
          ...loc(m.index), fix: 'Users can edit their own user_metadata, so they can give themselves any role. Use app_metadata or a roles table instead.' });
      }
      if (!/using\s*\(\s*true\s*\)|with\s+check\s*\(\s*true\s*\)/i.test(body)) continue;
      const cmd = (/\bfor\s+(select|insert|update|delete|all)\b/i.exec(body)?.[1] ?? 'all').toLowerCase();
      const verb = { select: 'read', insert: 'insert into', update: 'update', delete: 'delete from', all: 'read and write' }[cmd];
      add({ id: 'VC-DB-POLICY-OPEN', category: 'database', severity: cmd === 'select' ? 'medium' : 'high', confidence: 'verify',
        title: `Policy ${policy} lets everyone ${verb} "${norm(table)}"`, ...loc(m.index),
        fix: '`true` matches every request ("to authenticated" only means "anyone who signed up"). Scope it: using ((select auth.uid()) = user_id). Fine only for truly public data like published blog posts.' });
    }

    for (const m of text.matchAll(new RegExp(`create\\s+(?:or\\s+replace\\s+)?view\\s+${NAME}([\\s\\S]*?)\\bas\\b`, 'gi'))) {
      if (!isPublic(m[1]) || /security_invoker\s*=\s*(?:true|on)/i.test(m[2])) continue;
      add({ id: 'VC-DB-VIEW-BYPASS', category: 'database', severity: 'medium', confidence: 'verify',
        title: `View "${norm(m[1])}" ignores the RLS of the tables it reads`, ...loc(m.index),
        fix: 'Views run with their owner\'s rights by default. Create it `with (security_invoker = true)` or move it out of the public schema.' });
    }

    const fnStarts = [...text.matchAll(new RegExp(`create\\s+(?:or\\s+replace\\s+)?function\\s+${NAME}`, 'gi'))];
    for (const m of text.matchAll(/security\s+definer/gi)) {
      const fn = fnStarts.filter((f) => f.index < m.index).pop();
      if (!fn || !isPublic(fn[1]) || /returns\s+trigger/i.test(text.slice(fn.index, m.index))) continue;
      add({ id: 'VC-DB-SECURITY-DEFINER', category: 'database', severity: 'medium', confidence: 'verify',
        title: `Function "${norm(fn[1])}" is SECURITY DEFINER and callable from the API`, ...loc(fn.index),
        fix: 'It runs with admin rights and skips RLS. Check auth.uid() inside it, `set search_path = \'\'`, and `revoke execute on function ... from anon, public` if the browser should not call it.' });
    }
  }

  for (const [t, info] of tables) {
    if (info.rls) continue;
    add({ id: 'VC-DB-NO-RLS', category: 'database', severity: 'critical', confidence: 'verify',
      title: `Table "${t}" has no Row Level Security in your migrations`, file: info.file, line: info.line, evidence: info.evidence,
      fix: 'Without RLS, anyone with your public anon key can read and change every row (this is how Moltbook and many Lovable apps leaked). `alter table public.' + t + ' enable row level security;` plus owner policies. If you enabled it in the dashboard instead, confirm in Database → Advisors.' });
  }
}

if (has('supabase')) analyzeSupabaseSql();

// ---------------------------------------------------------------------------
// 4. Project-level checks
// ---------------------------------------------------------------------------

if (!isGit) {
  add({ id: 'VC-REL-NO-GIT', category: 'reliability', severity: 'medium', title: 'No git history: no undo button and no backup',
    fix: 'Run `git init`, commit, and push to a private GitHub repo. It is the single best safety net when an AI edit goes wrong.' });
} else {
  const tracked = (git(['ls-files', '-z']) || '').split('\0').filter(Boolean);
  const trackedEnv = tracked.filter(isRealEnvFile);
  for (const rel of trackedEnv) {
    add({ id: 'VC-ENV-TRACKED', category: 'secrets', severity: 'critical', title: `${rel} is committed to git`, file: rel,
      fix: 'Everyone with repo access has these secrets. `git rm --cached ' + rel + '`, add it to .gitignore, and rotate every key inside it.' });
  }
  const history = git(['log', '--all', '--diff-filter=A', '--name-only', '--pretty=format:', '--', '*.env', '*.env.*', '*.dev.vars']);
  const past = [...new Set((history || '').split('\n').map((s) => s.trim()).filter(Boolean))]
    .filter((rel) => isRealEnvFile(rel) && !trackedEnv.includes(rel));
  for (const rel of past) {
    add({ id: 'VC-ENV-HISTORY', category: 'secrets', severity: 'critical', title: `${rel} was committed in the past (still in git history)`, file: rel,
      fix: 'Deleting the file does not remove it from history. Rotate every key it contained; optionally purge it with git filter-repo.' });
  }
  const usesEnv = signals.envUsage || envFiles.length > 0;
  if (usesEnv && git(['check-ignore', '-q', '.env']) === null && git(['check-ignore', '-q', '.env.local']) === null) {
    add({ id: 'VC-ENV-GITIGNORE', category: 'secrets', severity: 'high', title: '.env is not in .gitignore',
      file: fileSet.has('.gitignore') ? '.gitignore' : null,
      fix: 'Add `.env*` (and `!.env.example`) to .gitignore before your next `git add .`.' });
  }
}

const usesCostly = COSTLY_STACK.some((s) => stack.has(s));
const RATE_LIMIT_DEPS = ['@upstash/ratelimit', 'express-rate-limit', 'rate-limiter-flexible', '@arcjet/next', '@arcjet/node',
  'hono-rate-limiter', '@fastify/rate-limit', '@nestjs/throttler', 'next-rate-limit', 'limiter', '@unkey/ratelimit',
  'express-slow-down', 'slowapi', 'flask-limiter', 'django-ratelimit', 'fastapi-limiter'];
if (usesCostly && !signals.rateLimit && !RATE_LIMIT_DEPS.some((d) => deps.has(d))) {
  const what = [...stack].filter((s) => COSTLY_STACK.includes(s)).join(', ');
  add({ id: 'VC-MONEY-NO-RATE-LIMIT', category: 'money', severity: 'high', confidence: 'verify',
    title: `Paid APIs (${what}) with no rate limiting anywhere`,
    fix: 'One script can call your AI/email/SMS endpoints thousands of times and run up your bill ("denial of wallet"). Require login, add a per-user rate limit, and set a hard spend cap in the provider dashboard.' });
}

const isWeb = WEB_STACK.some((s) => stack.has(s)) || files.some((f) => /(?:^|\/)index\.html$/.test(f));
const isApp = isWeb || has('expo', 'react-native');
const anyPath = (re) => files.some((f) => re.test(f));

if (isApp && !signals.monitoring && !deps.has('sentry-sdk')) {
  add({ id: 'VC-REL-NO-MONITORING', category: 'reliability', severity: 'low', title: 'No error monitoring',
    fix: 'You will not know when users hit errors. Add Sentry (free tier) or PostHog error tracking.' });
}
if (rootDeps > 0 && !['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb'].some((f) => fileSet.has(f))) {
  add({ id: 'VC-REL-NO-LOCKFILE', category: 'reliability', severity: 'low', title: 'No lockfile committed', file: 'package.json',
    fix: 'Without a lockfile every deploy can pull different (or compromised) package versions. Commit package-lock.json / pnpm-lock.yaml.' });
}

if (isApp) {
  const launch = [
    [!anyPath(/privacy/i) && !signals.privacy, 'VC-LAUNCH-PRIVACY', 'No privacy policy',
      'Required by law (GDPR, UU PDP, CCPA) as soon as you collect emails or personal data, and by the app stores.'],
    [!anyPath(/terms|(?:^|\/)tos\b|syarat/i) && !signals.terms, 'VC-LAUNCH-TERMS', 'No terms of service',
      'Terms limit your liability and let you ban abusers. Generate a starter and adapt it.'],
  ];
  if (isWeb) {
    launch.push(
      [!signals.og, 'VC-LAUNCH-OG', 'No Open Graph / social preview tags', 'Links shared on X, WhatsApp, LinkedIn show a blank card. Add og:title, og:description and og:image.'],
      [!anyPath(/(?:^|\/)robots\.(?:txt|[cm]?[jt]s)$/), 'VC-LAUNCH-ROBOTS', 'No robots.txt', 'Add robots.txt so search engines know what to crawl.'],
      [!anyPath(/sitemap/i) && !deps.has('next-sitemap') && !deps.has('@astrojs/sitemap'), 'VC-LAUNCH-SITEMAP', 'No sitemap', 'Add a sitemap so Google indexes all your pages.'],
      [!anyPath(/favicon|(?:^|\/)(?:apple-)?icon\.(?:png|ico|svg|jpe?g|[cm]?[jt]sx?)$/i), 'VC-LAUNCH-FAVICON', 'No favicon', 'Browser tabs and bookmarks show a generic icon.'],
      [!anyPath(/(?:^|\/)(?:not-found|404|\+error|_error)\.(?:[cm]?[jt]sx?|vue|svelte|astro|html|md)$/), 'VC-LAUNCH-404', 'No custom 404 page', 'Lost visitors hit a blank framework error page. Add a friendly 404 with a link home.'],
      [!signals.analytics, 'VC-LAUNCH-ANALYTICS', 'No analytics', 'You will not know if anyone uses your launch. Add privacy-friendly analytics (Vercel, Plausible, PostHog, Umami).'],
    );
  }
  for (const [missing, id, title, fix] of launch) {
    if (missing) add({ id, category: 'launch', severity: 'low', confidence: 'verify', title, fix });
  }
}

// ---------------------------------------------------------------------------
// 5. Output
// ---------------------------------------------------------------------------

findings.sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
  (a.confidence === 'high' ? -1 : 1) - (b.confidence === 'high' ? -1 : 1) || String(a.file).localeCompare(String(b.file)));

for (const [id, files] of hidden) {
  const total = [...files.values()].reduce((a, b) => a + b, 0);
  const byCount = [...files].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const list = byCount.slice(0, 8).map(([file, n]) => `${file} (${n})`).join(', ');
  const more = byCount.length > 8 ? ` and ${byCount.length - 8} more files` : '';
  notes.push(`${id}: ${total} more matches not shown, in ${list}${more}. Check those files before treating this rule as fully covered.`);
}
if (skippedDirs.size) {
  const total = [...skippedDirs.values()].reduce((a, b) => a + b, 0);
  const dirs = [...skippedDirs.keys()].sort();
  notes.push(`Code patterns not checked in ${total} test/backup/QA files (secrets were): ${dirs.slice(0, 8).join(', ')}${dirs.length > 8 ? ` and ${dirs.length - 8} more` : ''}. Imports through path aliases (like @/) aren't followed, so if any of these ship to users, check them by hand.`);
}
if (shippedAnyway.size) {
  const list = [...shippedAnyway].sort();
  notes.push(`${list.length} files in test/backup/QA folders are imported by app code, so they were checked like app code: ${list.slice(0, 8).join(', ')}${list.length > 8 ? ` and ${list.length - 8} more` : ''}.`);
}

const counts = Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length]));
const report = {
  tool: 'vibecheck-scan', version: VERSION, root, git: isGit, stack: [...stack].sort(),
  files_scanned: scanned, counts, findings, notes,
  hidden: Object.fromEntries([...hidden].map(([id, files]) => [id, Object.fromEntries(files)])),
};

if (opts.json) {
  console.log(JSON.stringify(report, null, 2));
} else {
  const color = process.stdout.isTTY && !process.env.NO_COLOR;
  const paint = (code, s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const SEV_STYLE = { critical: '1;31', high: '31', medium: '33', low: '36', info: '2' };
  console.log(`${paint('1', 'vibecheck scan')} ${VERSION} · ${root}`);
  console.log(`stack: ${report.stack.join(', ') || 'unknown'} · ${scanned} files scanned${isGit ? '' : ' · not a git repo'}\n`);
  for (const sev of SEVERITIES) {
    const group = findings.filter((f) => f.severity === sev);
    if (!group.length) continue;
    console.log(paint(SEV_STYLE[sev], `${sev.toUpperCase()}  ${group.length}`));
    for (const f of group) {
      const where = f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : '(project)';
      const mark = f.confidence === 'verify' ? '?' : '•';
      console.log(`  ${mark} ${f.id.padEnd(26)} ${where}`);
      console.log(`      ${f.title}${f.evidence ? `  [${f.evidence}]` : ''}`);
    }
    console.log('');
  }
  for (const n of notes) console.log(paint('2', `note: ${n}`));
  const summary = SEVERITIES.slice(0, 4).map((s) => `${counts[s]} ${s}`).join(' · ');
  console.log(`${summary}   (? = lead to verify by reading the code)`);
  console.log(paint('2', 'This is the quick deterministic pass. Run /vibecheck:check in your AI agent for the full audit, score and fixes.'));
}

if (opts.failOn) {
  const limit = SEVERITY_RANK[opts.failOn];
  const failing = findings.filter((f) => SEVERITY_RANK[f.severity] <= limit && (opts.strict || f.confidence === 'high'));
  process.exit(failing.length ? 1 : 0);
}
