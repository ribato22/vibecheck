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
import { basename, extname, isAbsolute, join } from 'node:path';
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

// Keep substitutions opaque: finding their boundary must never evaluate their body.
function shellExpansionEnd(command, start) {
  if (command[start] === '`') {
    for (let i = start + 1; i < command.length; i++) {
      if (command[i] === '\\') i++;
      else if (command[i] === '`') return i;
    }
    return -1;
  }
  let quote = '', depth = 1;
  for (let i = start + 2; i < command.length; i++) {
    const ch = command[i];
    if (ch === '\\' && quote !== "'") { i++; continue; }
    if (quote !== "'" && (ch === '`' || (ch === '$' && command[i + 1] === '('))) {
      i = shellExpansionEnd(command, i);
      if (i === -1) return -1;
    } else if (quote) {
      if (ch === quote) quote = '';
    } else if (ch === '"' || ch === "'") quote = ch;
    else if (ch === '#' && /[\s;|&()]/.test(command[i - 1])) {
      i = command.indexOf('\n', i);
      if (i === -1) return -1;
    }
    else if (ch === '(') depth++;
    else if (ch === ')' && --depth === 0) return i;
  }
  return -1;
}

// shortcut: inspect literal words only; reject Git writes with an unresolved repo context.
function shellCommands(command) {
  const commands = [];
  let words = [], expansions = new Set(), word = '', quote = '', started = false, expands = false;
  const finishWord = () => {
    if (started) {
      if (expands) expansions.add(words.length);
      words.push(word);
    }
    word = ''; started = false; expands = false;
  };
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (ch === '\\' && quote !== "'") {
      const next = command[i + 1];
      if (next === undefined) return [];
      if (!quote || /["\\$`\n]/.test(next)) {
        if (next !== '\n') { word += next; started = true; }
        i++; continue;
      }
    }
    if (quote !== "'" && (ch === '`' || (ch === '$' && command[i + 1] === '('))) {
      const end = shellExpansionEnd(command, i);
      if (end === -1) return [];
      word += command.slice(i, end + 1);
      expands = true; started = true; i = end;
      continue;
    }
    if (quote !== "'" && ch === '$') expands = true;
    if (quote) {
      if (ch === quote) quote = '';
      else word += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch; started = true;
    } else if (ch === '#' && !started) {
      const newline = command.indexOf('\n', i);
      if (newline === -1) break;
      i = newline - 1;
    } else if (/[;&|\n()]/.test(ch)) {
      finishWord();
      if (words.length) commands.push({ words, expansions });
      words = []; expansions = new Set();
    } else if (/\s/.test(ch)) finishWord();
    else { word += ch; started = true; }
  }
  if (quote) return [];
  finishWord();
  if (words.length) commands.push({ words, expansions });
  return commands;
}

function gitCommands(command, cwd) {
  const commands = [];
  let changedCwd = false, unknownAdd = false;
  for (const { words, expansions } of shellCommands(command)) {
    let first = 0;
    while (/^[A-Za-z_]\w*=/.test(words[first] || '')) first++;
    while (['command', 'builtin'].includes(words[first])) {
      first++;
      if (words[first] === '--') first++;
    }
    if (['cd', 'pushd', 'popd'].includes(words[first])) changedCwd = true;
    if (!/^(?:.*[\\/])?git(?:\.exe)?$/.test(words[first] || '')) continue;
    const dirs = [];
    let dynamicRepo = false;
    let i = first + 1;
    for (; i < words.length; i++) {
      const arg = words[i];
      if (arg === '-C') {
        if (++i === words.length) break;
        dynamicRepo ||= expansions.has(i);
        dirs.push('-C', words[i]);
      } else if (arg.startsWith('-C')) {
        dynamicRepo ||= expansions.has(i);
        dirs.push('-C', arg.slice(2));
      }
      else if (arg === '--bare') dirs.push(arg);
      else if (arg === '-c') i++;
      else if (arg.startsWith('-c') || arg.startsWith('--config-env=') || [
        '-p', '-P', '--paginate', '--no-pager', '--no-optional-locks', '--no-replace-objects',
        '--no-lazy-fetch', '--no-advice', '--literal-pathspecs', '--glob-pathspecs', '--noglob-pathspecs', '--icase-pathspecs',
      ].includes(arg)) continue;
      else break;
    }
    const verb = words[i];
    if (!['add', 'commit', 'push'].includes(verb)) continue;
    const firstDir = dirs.find((arg, j) => dirs[j - 1] === '-C' && arg !== '');
    if (dynamicRepo || (changedCwd && !isAbsolute(firstDir || '')) || (verb === 'commit' && unknownAdd)) {
      if (verb === 'add') unknownAdd = true;
      else commands.push({ problem: `Cannot inspect git ${verb}: a repository path needs shell expansion, depends on a shell directory change, or follows an unresolved git add. Use git -C with a literal absolute repository path.` });
      continue;
    }
    // Let Git apply repeated -C options, including empty paths and symlink/.. traversal.
    let root = git([...dirs, 'rev-parse', '--show-toplevel'], cwd);
    if (!root && verb === 'push') root = git([...dirs, 'rev-parse', '--absolute-git-dir'], cwd);
    if (root) commands.push({ verb, cwd: root.replace(/\r?\n$/, ''), args: words.slice(i + 1) });
  }
  return commands;
}

function commitsAll(args) {
  for (let i = 0; i < args.length && args[i] !== '--'; i++) {
    const arg = args[i];
    if (['-m', '--message', '-F', '--file', '-C', '--reuse-message', '-c', '--reedit-message', '--author', '--date', '-t', '--template', '--trailer', '--fixup', '--squash', '--pathspec-from-file'].includes(arg)) i++;
    else if (arg === '--all') return true;
    else if (/^-[^-]/.test(arg)) {
      for (let j = 1; j < arg.length; j++) {
        const option = arg[j];
        if (option === 'a') return true;
        if ('mFCctSu'.includes(option)) {
          if ('mFCct'.includes(option) && j === arg.length - 1) i++;
          break; // Remaining characters are an option value.
        }
      }
    }
  }
  return false;
}

function checkGit(command, cwd) {
  const problems = [];
  const diffArgs = ['-U0', '--no-color', '--no-ext-diff'];
  const addsFiles = new Set();
  for (const cmd of gitCommands(command, cwd)) {
    if (cmd.problem) { problems.push(cmd.problem); continue; }
    const target = cmd.cwd;
    if (cmd.verb === 'add') addsFiles.add(target);
    if (cmd.verb === 'commit') {
      problems.push(...patchProblems(git(['diff', '--cached', ...diffArgs], target) || ''));
      if (addsFiles.has(target) || commitsAll(cmd.args)) {
        problems.push(...patchProblems(git(['diff', ...diffArgs], target) || ''));
      }
      if (addsFiles.has(target)) problems.push(...untrackedProblems(target));
    }
    if (cmd.verb === 'push') {
      const range = git(['rev-parse', '--abbrev-ref', '--symbolic-full-name', '@{u}'], target) !== null
        ? ['@{u}..HEAD'] : ['HEAD', '--not', '--remotes'];
      problems.push(...patchProblems(git(['log', '-p', '--format=', ...diffArgs, ...range], target) || ''));
    }
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

  const uncertainRepo = problems.some((p) => p.startsWith('Cannot inspect git '));
  if (uncertainRepo) advice = ['Use git -C with a literal absolute repository path and run directory changes separately.'];
  const unique = [...new Set(problems)].slice(0, 15);
  process.stderr.write([
    uncertainRepo ? 'vibecheck guard blocked this: the Git repository cannot be inspected safely.'
      : 'vibecheck guard blocked this: it would put secrets where they do not belong.',
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
