#!/usr/bin/env node
// vibecheck deploy preflight: what works on your machine but breaks in production. vibecheck-ignore-file
// Read-only. Zero dependencies. No network. It never runs your project's code, and never reads env values.
//
//   node preflight.mjs [path] [--json] [--host <name>] [--host-env <file>]
//
// --host      where the app deploys: vercel, netlify, cloudflare, amplify, railway, render, fly, heroku, docker.
//             Detected from config files when omitted.
// --host-env  a file with the env var NAMES set on the host: one per line, or the pasted output of
//             `vercel env ls production`, `fly secrets list` or `wrangler secret list`.

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative, basename, extname, resolve, sep, posix } from 'node:path';
import { spawnSync } from 'node:child_process';
import { builtinModules } from 'node:module';

const VERSION = '1.1.0';
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_FILES = 20000;
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));
const SERVERLESS = new Set(['vercel', 'netlify', 'cloudflare', 'amplify']);
const CONTAINER = new Set(['railway', 'render', 'fly', 'heroku', 'docker']);
const HOSTS = [...SERVERLESS, ...CONTAINER];

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const argv = process.argv.slice(2);
const opts = { json: false, host: null, hostEnv: null, path: '.' };
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--json') opts.json = true;
  else if (a === '--host') opts.host = (argv[++i] || '').toLowerCase();
  else if (a === '--host-env') opts.hostEnv = argv[++i];
  else if (a === '--version') { console.log(VERSION); process.exit(0); }
  else if (a === '--help' || a === '-h') {
    console.log('usage: node preflight.mjs [path] [--json] [--host <name>] [--host-env <file>]');
    process.exit(0);
  } else opts.path = a;
}
if (opts.host && !HOSTS.includes(opts.host)) {
  console.error(`--host must be one of: ${HOSTS.join(', ')}`);
  process.exit(2);
}
const root = resolve(opts.path);
if (!existsSync(root) || !statSync(root).isDirectory()) {
  console.error(`vibecheck: not a directory: ${root}`);
  process.exit(2);
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', '.next', '.nuxt', '.svelte-kit', '.output', '.vercel',
  '.netlify', 'coverage', 'vendor', 'venv', '.venv', '__pycache__', '.turbo', '.cache', 'Pods', '.expo',
  '.gradle', 'target', '.vibecheck', 'bower_components', '.parcel-cache', 'storybook-static', '.terraform',
]);
const toPosix = (p) => p.split(sep).join('/');
const inSkippedDir = (rel) => rel.split('/').slice(0, -1).some((d) => SKIP_DIRS.has(d));
const isTestPath = (rel) => /(?:^|\/)(?:__tests__|tests?|spec|fixtures?|mocks?|__mocks__|e2e)\/|\.(?:test|spec)\.[cm]?[jt]sx?$/.test(rel);
const isArchivePath = (rel) =>
  /(?:^|\/)(?:backups?|archives?|archived|old|deprecated|qa)(?:[-_.][^/]*)?\/|(?:^|\/)(?:playwright|cypress)\/|[-_.](?:backup|bak|old|orig|copy)\.(?:[cm]?[jt]sx?|py)$/i.test(rel);
const isNonShipping = (rel) => isTestPath(rel) || isArchivePath(rel);
const isDevConfig = (rel) => /(?:^|\/)(?:vite|vitest|jest|playwright|cypress|webpack|rollup|eslint|prettier|tailwind|postcss)\.config\.|(?:^|\/)docker-compose[^/]*\.ya?ml$/.test(rel);

function langOf(rel) {
  const ext = extname(rel).toLowerCase();
  if (['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.mts', '.cts', '.vue', '.svelte', '.astro'].includes(ext)) return 'js';
  if (ext === '.py') return 'py';
  return null;
}

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

const gitList = git(['ls-files', '-co', '--exclude-standard', '-z']);
const isGit = gitList !== null;
let files = [];
if (isGit) files = gitList.split('\0').filter(Boolean).filter((f) => !inSkippedDir(f));
else walk(root, 30, files);
files = files.slice(0, MAX_FILES);
const fileSet = new Set(files);
const lowerMap = new Map(files.map((f) => [f.toLowerCase(), f]));

const cache = new Map();
function readText(rel) {
  if (cache.has(rel)) return cache.get(rel);
  let text = null;
  try {
    const p = join(root, rel);
    if (statSync(p).size <= MAX_FILE_BYTES) {
      text = readFileSync(p, 'utf8');
      if (text.includes('\u0000')) text = null;
    }
  } catch { /* unreadable */ }
  cache.set(rel, text);
  return text;
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
const tryJSON = (text) => { try { return JSON.parse(text); } catch { return null; } };

// ---------------------------------------------------------------------------
// Project facts
// ---------------------------------------------------------------------------

const pkgs = files.filter((f) => basename(f) === 'package.json').map((rel) => ({ rel, json: tryJSON(readText(rel)) })).filter((p) => p.json);
const rootPkg = pkgs.find((p) => p.rel === 'package.json')?.json || null;
const declared = new Set();
const workspaceNames = new Set();
for (const { json } of pkgs) {
  for (const d of Object.keys({ ...json.dependencies, ...json.devDependencies, ...json.peerDependencies, ...json.optionalDependencies })) declared.add(d);
  if (json.name) workspaceNames.add(json.name);
}
const allScripts = pkgs.flatMap((p) => Object.values(p.json.scripts || {})).join('\n');
const hasDep = (...names) => names.some((n) => declared.has(n));
const pyReqs = files.filter((f) => /(?:^|\/)(?:requirements[^/]*\.txt|pyproject\.toml|Pipfile)$/.test(f)).map(readText).join('\n').toLowerCase();

const hosts = new Set();
if (opts.host) hosts.add(opts.host);
else {
  const HOST_FILES = [
    [/^vercel\.json$/, 'vercel'], [/^netlify\.toml$/, 'netlify'], [/^wrangler\.(?:toml|jsonc?)$/, 'cloudflare'],
    [/^amplify\.ya?ml$/, 'amplify'], [/^railway\.(?:json|toml)$/, 'railway'], [/^render\.ya?ml$/, 'render'],
    [/^fly\.toml$/, 'fly'], [/^Procfile$/, 'heroku'], [/^(?:Dockerfile|Containerfile)$/, 'docker'],
  ];
  for (const rel of files) for (const [re, host] of HOST_FILES) if (re.test(basename(rel))) hosts.add(host);
  if (existsSync(join(root, '.vercel/project.json'))) hosts.add('vercel');
  if (existsSync(join(root, '.netlify/state.json'))) hosts.add('netlify');
}
const serverless = [...hosts].some((h) => SERVERLESS.has(h));
const container = [...hosts].some((h) => CONTAINER.has(h));
const assignsPort = ['railway', 'render', 'fly', 'heroku'].some((h) => hosts.has(h)); // these pass the port in $PORT

const ignoredFile = (rel) => (readText(rel) || '').slice(0, 300).includes('vibecheck-ignore-file');
const shippingCode = files.filter((f) => langOf(f) && !isNonShipping(f) && !ignoredFile(f));

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

const findings = [];
const notes = [];
const seen = new Set();
function add(f) {
  const key = `${f.id}|${f.file}|${f.line}|${f.title}`;
  if (seen.has(key)) return;
  seen.add(key);
  findings.push({ confidence: 'verify', file: null, line: null, evidence: null, ...f });
}
const snippet = (line) => line.trim().slice(0, 140);

// 1. Imports: case mismatches (fine on Mac/Windows, broken on Linux build servers) and undeclared packages.

const RESOLVE_EXT = ['', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.mts', '.cts', '.vue', '.svelte', '.json'];
// Real import/export statements only (a "from" inside a string must not count).
const SPEC_RE = /^\s*import\s+(?:type\s+)?[\w*${}\s,]+?\s+from\s*["']([^"'\n]+)["']|^\s*export\s+(?:type\s+)?(?:\*(?:\s+as\s+\w+)?|\{[^}]*\})\s+from\s*["']([^"'\n]+)["']|\bimport\s*\(\s*["']([^"'\n]+)["']\s*\)|\brequire\s*\(\s*["']([^"'\n]+)["']\s*\)|^\s*import\s*["']([^"'\n]+)["']/gm;
const BUILTINS = new Set(builtinModules.map((m) => m.replace(/^node:/, '')));

const aliasPrefixes = ['@/', '~/', '~', '#', '$'];
for (const rel of files.filter((f) => /(?:^|\/)(?:[tj]sconfig[^/]*\.json|vite\.config\.[cm]?[jt]s)$/.test(f))) {
  const text = readText(rel) || '';
  const block = /"paths"\s*:\s*\{([\s\S]*?)\}/.exec(text)?.[1] || /\balias\s*:\s*\{([\s\S]*?)\}/.exec(text)?.[1] || '';
  for (const m of block.matchAll(/["']?([@~\w$#/.-]+?)\*?["']?\s*:/g)) if (m[1]) aliasPrefixes.push(m[1]);
}

function packageName(spec) {
  if (/^[./]/.test(spec) || /^[a-z]+:/i.test(spec)) return null; // relative, absolute, node:, virtual:, astro:…
  if (aliasPrefixes.some((p) => spec === p.replace(/\/$/, '') || spec.startsWith(p))) return null;
  const parts = spec.split('/');
  const name = spec.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
  return BUILTINS.has(name) || workspaceNames.has(name) ? null : name;
}

function caseMismatch(from, spec) {
  const base = posix.normalize(posix.join(posix.dirname(from), spec));
  if (base.startsWith('..')) return null;
  const stems = [base];
  if (/\.[cm]?js$/.test(base)) stems.push(base.replace(/\.([cm]?)js$/, '.$1ts'), base.replace(/\.js$/, '.tsx'));
  const candidates = stems.flatMap((s) => [...RESOLVE_EXT.map((e) => s + e), ...RESOLVE_EXT.slice(1).map((e) => `${s}/index${e}`)]);
  if (candidates.some((c) => fileSet.has(c))) return null;
  for (const c of candidates) {
    const actual = lowerMap.get(c.toLowerCase());
    if (actual) return actual;
  }
  return null;
}

const undeclared = new Map();
const importedPackages = new Set();
for (const rel of shippingCode.filter((f) => langOf(f) === 'js')) {
  const text = readText(rel);
  if (!text) continue;
  const starts = lineStarts(text);
  const lines = text.split('\n');
  for (const m of text.matchAll(SPEC_RE)) {
    const spec = m[1] || m[2] || m[3] || m[4] || m[5];
    const line = lineAt(starts, m.index + m[0].length - 1);
    const src = lines[line - 1] || '';
    if (src.includes('vibecheck-ignore')) continue;
    if (spec.startsWith('.')) {
      const actual = caseMismatch(rel, spec);
      if (actual) {
        add({ id: 'VC-DEPLOY-IMPORT-CASE', severity: 'high', confidence: 'high', file: rel, line, evidence: snippet(src),
          title: `Import "${spec}" only matches "${actual}" if letter case is ignored`,
          fix: 'Mac and Windows ignore letter case in file names; Linux build servers (Vercel, Netlify, Docker…) do not, so this import fails there. Make the import and the file name match exactly. If you renamed the file only by case, also run `git mv` so git records the new name.' });
      }
      continue;
    }
    if (/^\s*(?:import|export)\s+type\b/.test(m[0])) continue;
    const name = packageName(spec);
    if (name) importedPackages.add(name);
    if (!name || declared.has(name) || declared.has(`@types/${name}`)) continue;
    if (!rootPkg && pkgs.length === 0) continue;
    const prev = undeclared.get(name);
    if (prev) prev.count++;
    else undeclared.set(name, { file: rel, line, evidence: snippet(src), count: 1 });
  }
}
for (const [name, u] of undeclared) {
  add({ id: 'VC-DEPLOY-DEP-UNDECLARED', severity: 'high', file: u.file, line: u.line, evidence: u.evidence,
    title: `"${name}" is imported but not in package.json${u.count > 1 ? ` (${u.count} places)` : ''}`,
    fix: `It works locally because the package happens to be in node_modules (installed by hand, or pulled in by another package). The host installs only what package.json lists, so the build fails. Run \`npm install ${name}\` (or your package manager's equivalent) and commit package.json and the lockfile.` });
}

// 2. Environment variables: names only, never values.

// [pattern, a comma right after it means a default value (Python's os.getenv("X", default))]
const ENV_USE = [
  [/\bprocess\.env\.([A-Z_][A-Z0-9_]*)/g, false],
  [/\bprocess\.env\[\s*["'`]([A-Z_][A-Z0-9_]*)["'`]\s*\]/g, false],
  [/\bimport\.meta\.env\.([A-Z_][A-Z0-9_]*)/g, false],
  [/\bDeno\.env\.get\(\s*["'`]([A-Z_][A-Z0-9_]*)["'`]/g, false],
  [/\bBun\.env\.([A-Z_][A-Z0-9_]*)/g, false],
  [/\bos\.environ\[\s*["']([A-Z_][A-Z0-9_]*)["']\s*\]/g, false],
  [/\bos\.(?:environ\.get|getenv)\(\s*["']([A-Z_][A-Z0-9_]*)["']/g, true],
];
const PROVIDED = /^(?:NODE_ENV|PORT|HOST|HOSTNAME|PWD|HOME|PATH|TZ|CI|DEBUG|NEXT_RUNTIME|NEXT_PHASE|VERCEL|VERCEL_\w+|NEXT_PUBLIC_VERCEL_\w+|NETLIFY|NETLIFY_\w+|URL|DEPLOY_URL|DEPLOY_PRIME_URL|CONTEXT|RAILWAY_\w+|RENDER|RENDER_\w+|IS_PULL_REQUEST|FLY_\w+|PRIMARY_REGION|DYNO|K_SERVICE|K_REVISION|AWS_REGION|AWS_LAMBDA_\w+|LAMBDA_TASK_ROOT|CF_PAGES\w*|GITHUB_\w+|MODE|DEV|PROD|SSR|BASE_URL)$/;
const PUBLIC_PREFIX = /^(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|VUE_APP_|GATSBY_|PUBLIC_)/;

const used = new Map(); // name -> { file, line, fallback }
for (const rel of shippingCode.filter((f) => !/\.config\.[cm]?[jt]s$/.test(f))) {
  const text = readText(rel);
  if (!text) continue;
  const starts = lineStarts(text);
  const lines = text.split('\n');
  // Optional if followed by a default (?? / ||), compared like a feature flag (=== 'true'), or given a Python default.
  const record = (name, index, end, commaDefault) => {
    if (PROVIDED.test(name)) return;
    const line = lineAt(starts, index);
    if ((lines[line - 1] || '').includes('vibecheck-ignore')) return;
    const after = text.slice(end, end + 8);
    const fallback = /^\s*(?:\?\?|\|\||[!=]==?)/.test(after) || (commaDefault && /^\s*,/.test(after));
    const prev = used.get(name);
    if (!prev) used.set(name, { file: rel, line, fallback });
    else if (!fallback) prev.fallback = false;
  };
  for (const [re, commaDefault] of ENV_USE) for (const m of text.matchAll(re)) record(m[1], m.index, m.index + m[0].length, commaDefault);
  for (const m of text.matchAll(/import\s*\{([^}]+)\}\s*from\s*["']\$env\/(?:static|dynamic)\/(?:private|public)["']/g)) {
    for (const n of m[1].split(',').map((s) => s.trim().split(/\s+as\s+/)[0])) if (/^[A-Z_][A-Z0-9_]*$/.test(n)) record(n, m.index, m.index, false);
  }
}

const envNamesIn = (text) => [...(text || '').matchAll(/^\s*(?:export\s+)?([A-Z_][A-Z0-9_]*)\s*=/gm)].map((m) => m[1]);
const envFiles = [];
walk(root, 4, envFiles, (n) => /^\.env(?:\..+)?$|^\.dev\.vars$/.test(n));
const exampleFile = (rel) => /(?:example|sample|template|dist|defaults?)$/i.test(basename(rel));
const local = new Set(envFiles.filter((f) => !exampleFile(f)).flatMap((f) => envNamesIn(readText(f))));
const examples = envFiles.filter(exampleFile);
const documented = new Set(examples.flatMap((f) => envNamesIn(readText(f))));

// Env set in host config files counts as "on the host".
const hostConfigNames = new Set();
for (const rel of files.filter((f) => /(?:^|\/)(?:vercel\.json|netlify\.toml|wrangler\.(?:toml|jsonc?)|fly\.toml|render\.ya?ml|railway\.(?:json|toml)|Dockerfile|Containerfile|app\.ya?ml)$/.test(f))) {
  const text = readText(rel) || '';
  for (const re of [/^\s*([A-Z_][A-Z0-9_]*)\s*=/gm, /"([A-Z_][A-Z0-9_]*)"\s*:/g, /\bkey:\s*([A-Z_][A-Z0-9_]*)/g, /^\s*(?:ENV|ARG)\s+([A-Z_][A-Z0-9_]*)/gm]) {
    for (const m of text.matchAll(re)) hostConfigNames.add(m[1]);
  }
}

let hostNames = null;
if (opts.hostEnv) {
  const text = readFileSync(resolve(opts.hostEnv), 'utf8');
  hostNames = new Set(hostConfigNames);
  for (const line of text.split('\n')) {
    const first = line.trim().split(/[\s=:|,]+/).find((t) => /^[A-Z_][A-Z0-9_]*$/.test(t) && t.length > 1);
    if (first) hostNames.add(first);
  }
}

const needed = [...used.keys()].sort();
if (hostNames) {
  for (const name of needed) {
    if (hostNames.has(name)) continue;
    const u = used.get(name);
    const pub = PUBLIC_PREFIX.test(name);
    add({ id: 'VC-DEPLOY-ENV-NOT-ON-HOST', severity: u.fallback ? 'low' : 'high', file: u.file, line: u.line, evidence: name,
      title: `${name} is used but not set on the host${u.fallback ? ' (the code has a fallback)' : ''}`,
      fix: pub
        ? `Add ${name} to the host's production environment, then redeploy: public variables are baked in at build time, so the current build has it as undefined.`
        : `Add ${name} to the host's production environment (and preview, if you use preview deploys), then redeploy.` });
  }
}
const undocumented = needed.filter((n) => !documented.has(n));
if (needed.length && undocumented.length) {
  const list = undocumented.slice(0, 15).join(', ') + (undocumented.length > 15 ? ` and ${undocumented.length - 15} more` : '');
  add({ id: 'VC-DEPLOY-ENV-UNDOCUMENTED', severity: 'low', confidence: 'high', file: examples[0] || null,
    title: examples.length ? `${undocumented.length} env vars the code uses are missing from ${examples[0]}` : `No .env.example for the ${needed.length} env vars the code uses`,
    evidence: list,
    fix: 'List every variable name the app needs in .env.example (names only, no real values), so nobody forgets to set one on the host.' });
}

// 3. URLs that only work on your machine.

const LOCALHOST_RE = /\b(?:https?|wss?):\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?[^\s"'`)]*/g;
for (const rel of shippingCode.filter((f) => !isDevConfig(f) && !/(?:^|\/)(?:scripts?|seed|seeds)\//.test(f))) {
  const text = readText(rel);
  if (!text) continue;
  const starts = lineStarts(text);
  const lines = text.split('\n');
  for (const m of text.matchAll(LOCALHOST_RE)) {
    const line = lineAt(starts, m.index);
    const src = lines[line - 1] || '';
    if (src.includes('vibecheck-ignore') || /console\.|\blog\(|\bprint\(|development|isDev|import\.meta\.env\.DEV|NODE_ENV/.test(src)) continue;
    const before = src.slice(0, src.indexOf(m[0]));
    const fallback = /(?:process\.env|import\.meta\.env|os\.environ|getenv)[^;]*(?:\?\?|\|\||,)\s*["'`]?$/.test(before);
    add({ id: 'VC-DEPLOY-LOCALHOST', severity: fallback ? 'medium' : 'high', file: rel, line, evidence: snippet(src),
      title: fallback ? `Falls back to ${m[0]} when an env var is missing` : `Hardcoded ${m[0]}`,
      fix: fallback
        ? 'If that env var is missing on the host, production silently calls localhost and fails. Set it on the host, or fail loudly instead of falling back.'
        : 'In production, "localhost" is the visitor\'s own computer or the server itself, so this breaks. Read the URL from an env var (and add the production origin to CORS and auth redirect allowlists).' });
  }
}

// 4. Runtime: Node version, lockfiles, ports, start command.

const major = (s) => { const m = /(\d+)/.exec(String(s ?? '')); return m ? Number(m[1]) : null; };
const pins = [];
for (const f of ['.nvmrc', '.node-version']) if (fileSet.has(f) || existsSync(join(root, f))) {
  const v = major(readText(f)); if (v) pins.push({ source: f, v });
}
const netlifyNode = /NODE_VERSION\s*=\s*["']?(\d+)/.exec(readText('netlify.toml') || '')?.[1];
if (netlifyNode) pins.push({ source: 'netlify.toml', v: Number(netlifyNode) });
for (const rel of files.filter((f) => /(?:^|\/)(?:Dockerfile|Containerfile)$/.test(f))) {
  const v = /^\s*FROM\s+(?:[\w./-]+\/)?node:(\d+)/im.exec(readText(rel) || '')?.[1];
  if (v) pins.push({ source: rel, v: Number(v) });
}
const engines = rootPkg?.engines?.node;
if (engines && !/>/.test(engines)) { const v = major(engines); if (v) pins.push({ source: 'package.json engines', v }); }
const engineMin = engines && />=?\s*(\d+)/.exec(engines)?.[1];
const distinct = [...new Set(pins.map((p) => p.v))];
const tooLow = engineMin ? pins.filter((p) => p.v < Number(engineMin)) : [];
if (distinct.length > 1 || tooLow.length) {
  add({ id: 'VC-DEPLOY-NODE-MISMATCH', severity: 'medium', confidence: 'high',
    title: 'Node version differs between your files',
    evidence: [...pins.map((p) => `${p.source}: ${p.v}`), ...(engineMin ? [`package.json engines: >=${engineMin}`] : [])].join(' · '),
    fix: 'Pick one Node major version and use it everywhere (.nvmrc, package.json "engines", the host setting, the Dockerfile), so the host builds with the same Node you tested on.' });
} else if (rootPkg && Object.keys({ ...rootPkg.dependencies, ...rootPkg.devDependencies }).length && !pins.length && !engines) {
  add({ id: 'VC-DEPLOY-NODE-UNPINNED', severity: 'low', confidence: 'high', file: 'package.json',
    title: 'Node version is not pinned',
    fix: 'The host picks its default Node version, which may not be the one you develop on. Add `"engines": { "node": "22.x" }` (your version) to package.json, or a .nvmrc file.' });
}

const LOCKFILES = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb'];
const locks = LOCKFILES.filter((f) => fileSet.has(f));
const pm = /^(npm|yarn|pnpm|bun)@/.exec(rootPkg?.packageManager || '')?.[1];
const lockOf = { npm: ['package-lock.json'], yarn: ['yarn.lock'], pnpm: ['pnpm-lock.yaml'], bun: ['bun.lock', 'bun.lockb'] };
if (locks.length > 1) {
  add({ id: 'VC-DEPLOY-MULTI-LOCKFILE', severity: 'medium', confidence: 'high', evidence: locks.join(', '),
    title: 'More than one lockfile', fix: 'The host picks one package manager based on which lockfile it finds, and may install different versions than you have. Keep only the lockfile of the package manager you use.' });
} else if (pm && locks.length === 1 && !lockOf[pm].includes(locks[0])) {
  add({ id: 'VC-DEPLOY-MULTI-LOCKFILE', severity: 'medium', confidence: 'high', file: 'package.json', evidence: `packageManager: ${rootPkg.packageManager} · lockfile: ${locks[0]}`,
    title: 'packageManager and lockfile disagree', fix: 'Install with the package manager named in "packageManager" and commit its lockfile, or update the field.' });
}

const serverDeps = ['express', 'fastify', 'hono', 'koa', '@nestjs/core', '@hapi/hapi', 'polka'];
for (const rel of shippingCode) {
  const text = readText(rel);
  if (!text) continue;
  const starts = lineStarts(text);
  const lines = text.split('\n');
  const readsPort = /process\.env\.PORT|process\.env\[["']PORT["']\]|environ(?:\.get)?\(?\[?\s*["']PORT["']|getenv\(\s*["']PORT["']/.test(text);
  const portRe = langOf(rel) === 'py'
    ? /\b(?:app|uvicorn)\.run\([^)]*\bport\s*=\s*(\d{2,5})/g
    : /\.listen\(\s*(\d{2,5})\b/g;
  if (!readsPort && !serverless) {
    for (const m of text.matchAll(portRe)) {
      const line = lineAt(starts, m.index);
      if ((lines[line - 1] || '').includes('vibecheck-ignore')) continue;
      add({ id: 'VC-DEPLOY-PORT-HARDCODED', severity: assignsPort ? 'high' : 'low', file: rel, line, evidence: snippet(lines[line - 1]),
        title: `Server listens on fixed port ${m[1]}`,
        fix: 'Hosts like Railway, Render, Fly and Heroku tell your app which port to use through the PORT env var, and mark the deploy as failed if nothing answers there. Use `process.env.PORT || ' + m[1] + '` (Python: `int(os.environ.get("PORT", ' + m[1] + '))`).' });
    }
  }
  if (container) {
    const bindRe = langOf(rel) === 'py' ? /\bhost\s*=\s*["'](?:127\.0\.0\.1|localhost)["']/g : /\.listen\([^)\n]*,\s*["'](?:127\.0\.0\.1|localhost)["']/g;
    for (const m of text.matchAll(bindRe)) {
      const line = lineAt(starts, m.index);
      add({ id: 'VC-DEPLOY-BIND-LOCALHOST', severity: 'high', file: rel, line, evidence: snippet(lines[line - 1]),
        title: 'Server only accepts connections from inside its own container',
        fix: 'Binding to 127.0.0.1/localhost is right for a local-only app, but inside a container the host\'s router cannot reach it. Bind to 0.0.0.0 in production (for example from a HOST env var), and keep 127.0.0.1 for local use.' });
    }
  }
}
const hasStart = !!rootPkg?.scripts?.start || fileSet.has('Procfile') || hosts.has('docker');
if (assignsPort && rootPkg && !hasStart && (serverDeps.some((d) => declared.has(d)) || declared.has('next') || declared.has('nuxt'))) {
  add({ id: 'VC-DEPLOY-NO-START', severity: 'medium', confidence: 'high', file: 'package.json',
    title: 'No "start" script for the host to run',
    fix: 'Railway, Render and Heroku run `npm start` after building. Add a start script (for example `"start": "node server.js"` or `"start": "next start"`), or set the start command in the host settings.' });
}

// 5. Data that won't survive serverless, and generated clients.

const prismaSchema = files.filter((f) => /(?:^|\/)schema\.prisma$/.test(f)).map(readText).join('\n');
const drizzleConfig = files.filter((f) => /(?:^|\/)drizzle\.config\.[cm]?[jt]s$/.test(f)).map(readText).join('\n');
const usesSqlite = ['better-sqlite3', 'sqlite3', 'sqlite'].some((p) => importedPackages.has(p)) || // imported, not just listed
  /provider\s*=\s*"sqlite"/.test(prismaSchema) || /dialect\s*:\s*["']sqlite["']/.test(drizzleConfig);
if (serverless && usesSqlite) {
  add({ id: 'VC-DEPLOY-SQLITE-SERVERLESS', severity: 'high',
    title: `SQLite file database on a serverless host (${[...hosts].filter((h) => SERVERLESS.has(h)).join(', ')})`,
    fix: 'Serverless functions get a fresh, mostly read-only disk, so a local .db file loses its data on every deploy or cold start (or can\'t be written at all). Move to a hosted database: Turso/libSQL keeps SQLite syntax; Supabase, Neon or another Postgres also works.' });
}
if (serverless) {
  for (const rel of shippingCode.filter((f) => !/(?:^|\/)(?:scripts?|components)\//.test(f) && !isDevConfig(f))) {
    const text = readText(rel);
    if (!text || !/\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\s*\(/.test(text)) continue;
    const starts = lineStarts(text);
    const lines = text.split('\n');
    for (const m of text.matchAll(/\b(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\s*\(/g)) {
      const line = lineAt(starts, m.index);
      const src = lines[line - 1] || '';
      if (/tmp|tmpdir|vibecheck-ignore/i.test(src)) continue;
      add({ id: 'VC-DEPLOY-FS-WRITE', severity: 'medium', file: rel, line, evidence: snippet(src),
        title: 'Writes files to disk on a serverless host',
        fix: 'Serverless disks are read-only except /tmp, and /tmp is wiped between requests. Store uploads and data in object storage (S3, R2, Supabase Storage) or a database.' });
    }
  }
}
if (hasDep('prisma', '@prisma/client') && !/prisma\s+generate/.test(allScripts) &&
    !files.filter((f) => /(?:^|\/)(?:Dockerfile|Containerfile)$/.test(f)).some((f) => /prisma\s+generate/.test(readText(f) || ''))) {
  add({ id: 'VC-DEPLOY-PRISMA-GENERATE', severity: serverless ? 'high' : 'medium', file: 'package.json',
    title: 'Prisma Client is never generated during the build',
    fix: 'Hosts that cache node_modules (Vercel, Netlify) can build with a stale or missing Prisma Client ("PrismaClient is unable to run" / missing models). Add `"postinstall": "prisma generate"` or put `prisma generate &&` in front of the build script.' });
}

// ---------------------------------------------------------------------------
// Reminders: host-side steps the code can't show
// ---------------------------------------------------------------------------

const reminders = [];
const anyFile = (re) => files.some((f) => re.test(f));
if ([...used.keys()].some((n) => PUBLIC_PREFIX.test(n))) reminders.push('Public env vars (NEXT_PUBLIC_, VITE_, EXPO_PUBLIC_…) are baked in when the app is built: after adding or changing one on the host, redeploy.');
if (anyFile(/(?:^|\/)prisma\/migrations\//)) reminders.push('Apply database migrations to the production database: `npx prisma migrate deploy`.');
if (anyFile(/(?:^|\/)supabase\/migrations\//)) reminders.push('Apply Supabase migrations to the production project: `supabase link` to it, then `supabase db push`.');
if (anyFile(/(?:^|\/)drizzle\.config\.[cm]?[jt]s$/)) reminders.push('Apply Drizzle migrations to the production database: `npx drizzle-kit migrate`.');
if (anyFile(/(?:^|\/)alembic\.ini$/)) reminders.push('Apply migrations to the production database: `alembic upgrade head`.');
if (anyFile(/(?:^|\/)manage\.py$/)) reminders.push('Run `python manage.py migrate` against the production database, and set DEBUG=False and ALLOWED_HOSTS.');
if (hasDep('@supabase/supabase-js', '@supabase/ssr') || anyFile(/(?:^|\/)supabase\/config\.toml$/)) reminders.push('Supabase → Authentication → URL Configuration: set the Site URL and add the production redirect URLs, or logins and magic links send people to localhost.');
if (hasDep('next-auth', '@auth/core', '@auth/nextjs', 'better-auth')) reminders.push('Auth: set the auth secret and production URL env vars on the host, and add the production callback URL to every OAuth provider (Google, GitHub…).');
if (hasDep('@clerk/nextjs', '@clerk/clerk-react', '@clerk/express')) reminders.push('Clerk: use the production instance keys and add your domain in the Clerk dashboard.');
if (hasDep('firebase') || anyFile(/(?:^|\/)firebase\.json$/)) reminders.push('Firebase → Authentication → Settings → Authorized domains: add the production domain.');
if (hasDep('stripe', '@stripe/stripe-js') || pyReqs.includes('stripe')) reminders.push('Stripe: create a live-mode webhook endpoint for the production URL and set its signing secret on the host. Test-mode keys and webhook secrets do not work in live mode.');
if (hasDep('midtrans-client', 'xendit-node') || /midtrans|xendit/.test(pyReqs)) reminders.push('Midtrans/Xendit: switch to production keys and set the production notification/callback URL in the dashboard.');
if (serverless && hasDep('pg', 'postgres', '@prisma/client', 'drizzle-orm') && (hasDep('@supabase/supabase-js') || anyFile(/(?:^|\/)supabase\//))) reminders.push('Serverless + Postgres: connect through a pooler (Supabase: the transaction pooler on port 6543) so functions don\'t run the database out of connections.');
if (hasDep('cors') || /CORSMiddleware|flask_cors|corsheaders/.test(files.filter((f) => langOf(f) === 'py').map(readText).join('\n'))) reminders.push('CORS: add the production front-end origin to the allowlist.');
reminders.push('After deploying: open the production logs and click through signup → core feature → payment once.');

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

if (!hosts.size) notes.push('No hosting config found. Pass --host (vercel, netlify, cloudflare, railway, render, fly, heroku, docker) for host-specific checks.');
if (!hostNames) notes.push('Env vars were not compared with the host. List the names set on the host (never the values) and pass them with --host-env <file>.');

findings.sort((a, b) => RANK[a.severity] - RANK[b.severity] || String(a.file).localeCompare(String(b.file)));
const counts = Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length]));
const report = {
  tool: 'vibecheck-deploy', version: VERSION, root, git: isGit, hosts: [...hosts].sort(), serverless,
  env: {
    used: needed.map((n) => ({ name: n, ...used.get(n) })),
    defined_locally: [...local].sort(),
    documented: [...documented].sort(),
    on_host: hostNames ? [...hostNames].sort() : null,
    set_on_host: needed.filter((n) => local.has(n)),
  },
  counts, findings, reminders, notes,
};

if (opts.json) {
  console.log(JSON.stringify(report, null, 2));
} else {
  const color = process.stdout.isTTY && !process.env.NO_COLOR;
  const paint = (code, s) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
  const STYLE = { critical: '1;31', high: '31', medium: '33', low: '36', info: '2' };
  console.log(`${paint('1', 'vibecheck deploy preflight')} ${VERSION} · ${root}`);
  console.log(`host: ${report.hosts.join(', ') || 'unknown'} · ${needed.length} env vars used\n`);
  for (const sev of SEVERITIES) {
    const group = findings.filter((f) => f.severity === sev);
    if (!group.length) continue;
    console.log(paint(STYLE[sev], `${sev.toUpperCase()}  ${group.length}`));
    for (const f of group) {
      const where = f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : '(project)';
      console.log(`  ${f.confidence === 'verify' ? '?' : '•'} ${f.id.padEnd(28)} ${where}`);
      console.log(`      ${f.title}${f.evidence ? `  [${f.evidence}]` : ''}`);
    }
    console.log('');
  }
  if (report.env.set_on_host.length) console.log(`Set on the host: ${report.env.set_on_host.join(', ')}\n`);
  console.log(paint('1', 'Before you deploy:'));
  for (const r of reminders) console.log(`  - ${r}`);
  for (const n of notes) console.log(paint('2', `note: ${n}`));
  console.log(`\n${SEVERITIES.slice(0, 4).map((s) => `${counts[s]} ${s}`).join(' · ')}   (? = lead to verify by reading the code)`);
}
