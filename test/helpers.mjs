// Test helpers. vibecheck-ignore-file
// Fake credentials are assembled at runtime so this repo never contains a string that looks like a real key.

import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { isPlaceholder } from '../skills/check/scripts/rules.mjs';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
export const SCAN = join(ROOT, 'skills/check/scripts/scan.mjs');
export const GUARD = join(ROOT, 'hooks/guard.mjs');
export const PREFLIGHT = join(ROOT, 'skills/deploy/scripts/preflight.mjs');

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/** Deterministic random-looking string that never trips the placeholder filter. */
export function rand(n, seed = 1, alphabet = ALNUM) {
  for (let s = seed; ; s += 7919) {
    let x = s;
    let out = '';
    for (let i = 0; i < n; i++) {
      x = (x * 1103515245 + 12345) % 2147483648;
      out += alphabet[Math.floor(x / 65536) % alphabet.length];
    }
    if (!isPlaceholder(out)) return out;
  }
}

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

export const keys = {
  openai: 'sk-' + 'proj-' + rand(48, 11, ALNUM + '_-'),
  anthropic: 'sk-' + 'ant-' + 'api03-' + rand(80, 12, ALNUM + '_-'),
  stripeLive: 'sk_' + 'live_' + rand(32, 13),
  aws: 'AK' + 'IA' + rand(16, 14, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'),
  serviceRole: [b64({ alg: 'HS256', typ: 'JWT' }), b64({ iss: 'supabase', ref: rand(20, 15).toLowerCase(), role: 'service_role', iat: 1700000000 }), rand(43, 16, ALNUM + '_-')].join('.'),
  anon: [b64({ alg: 'HS256', typ: 'JWT' }), b64({ iss: 'supabase', ref: rand(20, 17).toLowerCase(), role: 'anon', iat: 1700000000 }), rand(43, 18, ALNUM + '_-')].join('.'),
  dbUrl: 'postgres' + 'ql://postgres.' + rand(12, 19).toLowerCase() + ':' + rand(20, 20) + '@aws-0-ap-southeast-1.pooler.supabase.com:6543/postgres',
};

export function makeProject(files) {
  const dir = mkdtempSync(join(tmpdir(), 'vibecheck-'));
  for (const [rel, content] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), content);
  }
  return dir;
}

export const removeProject = (dir) => rmSync(dir, { recursive: true, force: true });

const GIT_ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: 'test', GIT_AUTHOR_EMAIL: 'test@example.com',
  GIT_COMMITTER_NAME: 'test', GIT_COMMITTER_EMAIL: 'test@example.com',
  GIT_CONFIG_NOSYSTEM: '1', HOME: tmpdir(),
};

export function git(dir, ...args) {
  const r = spawnSync('git', ['-c', 'commit.gpgsign=false', '-c', 'init.defaultBranch=main', ...args], { cwd: dir, encoding: 'utf8', env: GIT_ENV });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')} failed: ${r.stderr}`);
  return r.stdout;
}

export function scan(dir, ...flags) {
  const r = spawnSync(process.execPath, [SCAN, dir, '--json', ...flags], { encoding: 'utf8' });
  if (r.status !== 0 && !flags.includes('--fail-on')) throw new Error(`scan failed: ${r.stderr}`);
  return { ...JSON.parse(r.stdout), exitCode: r.status };
}

export function preflight(dir, ...flags) {
  const r = spawnSync(process.execPath, [PREFLIGHT, dir, '--json', ...flags], { encoding: 'utf8' });
  if (r.status !== 0) throw new Error(`preflight failed: ${r.stderr}`);
  return JSON.parse(r.stdout);
}

export function guard(event, env = {}) {
  const r = spawnSync(process.execPath, [GUARD], {
    input: typeof event === 'string' ? event : JSON.stringify(event),
    encoding: 'utf8',
    env: { ...GIT_ENV, ...env },
  });
  return { code: r.status, stderr: r.stderr };
}

export const ids = (report) => new Set(report.findings.map((f) => f.id));
