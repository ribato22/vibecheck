#!/usr/bin/env node
// vibecheck guard: a Claude Code PreToolUse hook. vibecheck-ignore-file
//
// Blocks the action (exit 2, reason on stderr for the agent to fix) when the agent is about to:
//   - write a real API key / private key into a code file, or a secret env var with a browser-public prefix
//   - `git commit` or `git push` changes that contain a secret or a .env file
//
// Fails open: on any internal error the action goes ahead. Turn it off with VIBECHECK_GUARD=off.

import { readFileSync, statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { basename, extname, join } from 'node:path';
import { findSecrets, mask, PUBLIC_ENV_RE, classifyEnvName } from '../skills/check/scripts/rules.mjs';

const ENV_FILE = /^\.env(?:\..+)?$|\.env$|^\.dev\.vars$/;
const ENV_EXAMPLE = /(?:example|sample|template|dist|defaults?)$/i;
const SECRET_HOME = /^(?:\.dev\.vars|secrets\.toml)$|\.(?:pem|key|p12|pfx)$/; // files whose whole job is to hold a secret
const CODE_EXT = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte', '.astro', '.json']);
const MAX_UNTRACKED = 2000;

const isRealEnv = (name) => ENV_FILE.test(name) && !ENV_EXAMPLE.test(name);

function publicEnvProblems(line) {
  const out = [];
  for (const m of line.matchAll(PUBLIC_ENV_RE)) {
    if (classifyEnvName(m[2]) === 'critical') out.push(`${m[0]} has a browser-public prefix, so its value ships to every visitor`);
  }
  return out;
}

function checkWrite(tool, input) {
  const file = input.file_path || input.path || '';
  const name = basename(file);
  const text = tool === 'Write' ? input.content
    : tool === 'MultiEdit' ? (input.edits || []).map((e) => e.new_string).join('\n')
    : input.new_string;
  if (typeof text !== 'string') return [];
  const realEnv = isRealEnv(name);
  const checkSecrets = !realEnv && !SECRET_HOME.test(name);
  const checkPublic = realEnv || ENV_FILE.test(name) || CODE_EXT.has(extname(name).toLowerCase());
  const problems = [];
  text.split('\n').forEach((line, i) => {
    if (line.includes('vibecheck-ignore')) return;
    const where = tool === 'Write' ? `${name}:${i + 1}` : name;
    if (checkSecrets) {
      for (const { rule, value } of findSecrets(line, { guardOnly: true })) problems.push(`${rule.title} ${mask(value)} in ${where}`);
    }
    if (checkPublic) for (const p of publicEnvProblems(line)) problems.push(`${p} (${where})`);
  });
  return problems;
}

function git(args, cwd) {
  const r = spawnSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  return r.status === 0 ? r.stdout : null;
}

/** Secrets on the added lines of a unified diff / `git log -p` output. */
function patchProblems(patch) {
  const problems = [];
  let file = '';
  for (const line of patch.split('\n')) {
    if (line.startsWith('+++ ')) {
      file = line.slice(4).replace(/^b\//, '');
      if (file !== '/dev/null' && isRealEnv(basename(file))) problems.push(`${file} would be committed (env files hold your secrets)`);
      continue;
    }
    if (!line.startsWith('+') || line.includes('vibecheck-ignore')) continue;
    for (const { rule, value } of findSecrets(line.slice(1), { guardOnly: true })) problems.push(`${rule.title} ${mask(value)} in ${file}`);
  }
  return problems;
}

function untrackedProblems(cwd) {
  const list = (git(['ls-files', '-o', '--exclude-standard', '-z'], cwd) || '').split('\0').filter(Boolean).slice(0, MAX_UNTRACKED);
  const problems = [];
  for (const rel of list) {
    if (isRealEnv(basename(rel))) { problems.push(`${rel} would be committed (env files hold your secrets)`); continue; }
    try {
      if (statSync(join(cwd, rel)).size > 1024 * 1024) continue;
      const content = readFileSync(join(cwd, rel), 'utf8');
      if (content.includes('\u0000') || content.slice(0, 300).includes('vibecheck-ignore-file')) continue;
      for (const line of content.split('\n')) {
        if (line.includes('vibecheck-ignore')) continue;
        for (const { rule, value } of findSecrets(line, { guardOnly: true })) problems.push(`${rule.title} ${mask(value)} in ${rel}`);
      }
    } catch { /* unreadable: skip */ }
  }
  return problems;
}

function checkGit(command, cwd) {
  const commit = /\bgit\b[^;&|\n]*\bcommit\b/.test(command);
  const push = /\bgit\b[^;&|\n]*\bpush\b/.test(command);
  if (!commit && !push) return [];
  if (git(['rev-parse', '--is-inside-work-tree'], cwd) === null) return [];
  const problems = [];
  const diffArgs = ['-U0', '--no-color', '--no-ext-diff'];

  if (commit) {
    problems.push(...patchProblems(git(['diff', '--cached', ...diffArgs], cwd) || ''));
    const addsFiles = /\bgit\b[^;&|\n]*\badd\b/.test(command);
    if (addsFiles || /\bcommit\b[^;&|\n]*\s(?:-[a-zA-Z]*a[a-zA-Z]*|--all)\b/.test(command)) {
      problems.push(...patchProblems(git(['diff', ...diffArgs], cwd) || ''));
    }
    if (addsFiles) problems.push(...untrackedProblems(cwd));
  }
  if (push) {
    const range = git(['rev-parse', '--abbrev-ref', '--symbolic-full-name', '@{u}'], cwd) !== null
      ? ['@{u}..HEAD'] : ['HEAD', '--not', '--remotes'];
    problems.push(...patchProblems(git(['log', '-p', '--format=', ...diffArgs, ...range], cwd) || ''));
  }
  return problems;
}

function main() {
  if ((process.env.VIBECHECK_GUARD || '').toLowerCase() === 'off') return;
  const event = JSON.parse(readFileSync(0, 'utf8'));
  const tool = event.tool_name;
  const input = event.tool_input || {};
  const cwd = event.cwd || process.cwd();

  let problems = [];
  let advice;
  if (tool === 'Bash') {
    problems = checkGit(String(input.command || ''), cwd);
    advice = [
      'Move the value into .env (make sure .env is in .gitignore) and read it from server-only code.',
      'Unstage the file (git restore --staged <file>) or amend the commit before pushing.',
      'If the key was ever pushed or deployed, rotate it in the provider dashboard.',
    ];
  } else if (tool === 'Write' || tool === 'Edit' || tool === 'MultiEdit') {
    problems = checkWrite(tool, input);
    advice = [
      'Put the secret in .env (gitignored) and read it with process.env.NAME in server-only code.',
      'Keep browser-public prefixes (NEXT_PUBLIC_, VITE_, EXPO_PUBLIC_...) for values that are safe to publish.',
    ];
  }
  if (!problems.length) return;

  const unique = [...new Set(problems)].slice(0, 15);
  process.stderr.write([
    'vibecheck guard blocked this: it would put secrets where they do not belong.',
    '',
    ...unique.map((p) => `  - ${p}`),
    '',
    'Fix:',
    ...advice.map((a, i) => `  ${i + 1}. ${a}`),
    '',
    'False positive? Add a `vibecheck-ignore` comment on that line, or start Claude Code with VIBECHECK_GUARD=off.',
    '',
  ].join('\n'));
  process.exit(2);
}

try {
  main();
} catch {
  // Never block work because the guard itself failed.
}
process.exit(0);
