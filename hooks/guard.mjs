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

function git(args, cwd, options = {}) {
  const { requireQuiet = false, ...spawnOptions } = options;
  const r = spawnSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, ...spawnOptions });
  return r.status === 0 && (!requireQuiet || !r.stderr) ? r.stdout : null;
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
function shellExpansionEnd(command, start, openingLength = 2, pair = '()', parameterDoubleQuoted = false, nesting = 0) {
  if (nesting > 16) return -1;
  if (command[start] === '`') {
    for (let i = start + 1; i < command.length; i++) {
      if (command[i] === '\\') i++;
      else if (command[i] === '`') return i;
    }
    return -1;
  }
  let quote = '', depth = 1;
  for (let i = start + openingLength; i < command.length; i++) {
    const ch = command[i];
    if (ch === '\\' && quote !== "'") { i++; continue; }
    if (quote !== "'" && (ch === '`' || (ch === '$' && command[i + 1] === '('))) {
      i = shellExpansionEnd(command, i, 2, '()', false, nesting + 1);
      if (i === -1) return -1;
    } else if (quote) {
      if (ch === quote) quote = '';
    } else if (ch === '"' || (ch === "'" && !parameterDoubleQuoted)) quote = ch;
    else if (pair === '()' && openingLength === 2 && ch === '#' && /[\s;|&()]/.test(command[i - 1])) {
      i = command.indexOf('\n', i);
      if (i === -1) return -1;
    }
    else if (ch === pair[0] && (pair !== '{}' || command[i - 1] === '$')) depth++;
    else if (ch === pair[1] && --depth === 0) return i;
  }
  return -1;
}

const shellProblem = (reason) => ({ problem: `Cannot inspect shell command: ${reason}. Use separate literal commands.` });

// Heredoc text has no shell quote syntax; only escapes suppress its substitutions.
function substitutionCommands(text, deadline, depth, ignoreQuotes = false) {
  if (depth > 8 || Date.now() >= deadline) return [shellProblem('the parsing budget is exhausted')];
  const commands = [];
  let quote = '';
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '\\' && (ignoreQuotes || quote !== "'")) { i++; continue; }
    if ((ignoreQuotes || quote !== "'") && (ch === '`' || (ch === '$' && ['(', '{'].includes(text[i + 1])))) {
      const parameter = text[i + 1] === '{';
      const end = shellExpansionEnd(text, i, 2, parameter ? '{}' : '()', parameter && (ignoreQuotes || quote === '"'));
      if (end === -1) return [shellProblem('an expansion is incomplete or too deeply nested')];
      const body = text.slice(i + (ch === '`' ? 1 : 2), end);
      if (ch === '`' && /\\[$`\\]/.test(body)) return [shellProblem('legacy backtick escapes are unsupported')];
      commands.push(...(parameter || text[i + 2] === '('
        ? substitutionCommands(body, deadline, depth + 1, ignoreQuotes || quote === '"')
        : shellCommands(body, deadline, depth + 1)));
      i = end;
    } else if (!ignoreQuotes) {
      if (quote) { if (ch === quote) quote = ''; }
      else if (ch === '"' || ch === "'") quote = ch;
    }
  }
  return commands;
}

// shortcut: literal shell syntax only; use a full parser if more interpreters must be supported.
function shellCommands(command, deadline, depth = 0) {
  if (depth > 8 || command.length > 131072 || Date.now() >= deadline) return [shellProblem('the parsing budget is exhausted')];
  const commands = [];
  let words = [], expansions = new Set(), word = '', quote = '', started = false, expands = false;
  let heredoc = null, heredocs = [], quotedWord = false, lineStart = 0;
  const finishWord = () => {
    if (started) {
      if (heredoc !== null) {
        heredocs.push({ delimiter: word, stripTabs: heredoc, quoted: quotedWord });
        heredoc = null;
      } else {
        if (expands) expansions.add(words.length);
        words.push(word);
      }
    }
    word = ''; started = false; expands = false; quotedWord = false;
  };
  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (!quote && ch === '(' && command[i + 1] === ')' && /^[A-Za-z_]\w*$/.test(started && !words.length ? word : !started && words.length === 1 ? words[0] : '')) {
      return [...commands, shellProblem('shell function definitions are not supported')];
    }
    // Keep shifts opaque to heredoc parsing, but inspect executable substitutions inside them.
    if (!quote && heredoc === null && ch === '(' && command[i + 1] === '(') {
      const end = shellExpansionEnd(command, i, 1);
      if (end !== -1) {
        commands.push(...substitutionCommands(command.slice(i, end + 1), deadline, depth));
        finishWord(); word = command.slice(i, end + 1); started = true; i = end;
        continue;
      }
    }
    if (!quote && heredoc === null && ch === '[' && /^[A-Za-z_]\w*$/.test(word) && words.every((w) => /^[A-Za-z_]\w*=/.test(w))) {
      const end = shellExpansionEnd(command, i, 1, '[]');
      if (end !== -1 && /^\+?=/.test(command.slice(end + 1))) {
        commands.push(...substitutionCommands(command.slice(i + 1, end), deadline, depth));
        word += command.slice(i, end + 1); i = end;
        continue;
      }
    }
    if (ch === '\\' && quote !== "'") {
      const next = command[i + 1];
      if (next === undefined) return [...commands, shellProblem('a trailing escape is incomplete')];
      if (!quote || /["\\$`\n]/.test(next)) {
        quotedWord = true;
        if (next !== '\n') { word += next; started = true; }
        i++; continue;
      }
    }
    if (quote !== "'" && (ch === '`' || (ch === '$' && ['(', '{'].includes(command[i + 1])))) {
      const parameter = command[i + 1] === '{';
      const end = shellExpansionEnd(command, i, 2, parameter ? '{}' : '()', parameter && quote === '"');
      if (end === -1) return [...commands, shellProblem('an expansion is incomplete or too deeply nested')];
      if (heredoc === null) commands.push(...substitutionCommands(command.slice(i, end + 1), deadline, depth, parameter && quote === '"'));
      word += command.slice(i, end + 1);
      expands = true; started = true; i = end;
      continue;
    }
    if (quote !== "'" && ch === '$') expands = true;
    if (quote) {
      if (ch === quote) quote = '';
      else word += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch; started = true; quotedWord = true;
    } else if (ch === '<' && command[i + 1] === '<' && command[i - 1] !== '<' && command[i + 2] !== '<') {
      finishWord(); heredoc = command[i + 2] === '-'; i += heredoc ? 2 : 1;
    } else if (ch === '#' && !started) {
      const newline = command.indexOf('\n', i);
      if (newline === -1) break;
      i = newline - 1;
    } else if (/[;&|\n()]/.test(ch)) {
      finishWord();
      if (words.length) commands.push({ words, expansions, depth });
      words = []; expansions = new Set();
      if (ch === '\n' && heredocs.length) {
        let cursor = i + 1;
        const nested = [];
        for (const doc of heredocs) {
          let closed = false, body = '';
          while (cursor <= command.length) {
            const end = command.indexOf('\n', cursor);
            const line = command.slice(cursor, end === -1 ? command.length : end);
            cursor = end === -1 ? command.length + 1 : end + 1;
            if ((doc.stripTabs ? line.replace(/^\t+/, '') : line) === doc.delimiter) { closed = true; break; }
            body += line + '\n';
          }
          if (!closed) return [...commands, shellProblem('a heredoc is incomplete')];
          if (!doc.quoted) nested.push(...substitutionCommands(body, deadline, depth, true));
        }
        commands.splice(lineStart, 0, ...nested);
        heredocs = []; i = cursor - 1;
      }
      if (ch === '\n') lineStart = commands.length;
    } else if (/\s/.test(ch)) finishWord();
    else { word += ch; started = true; }
  }
  if (quote || heredoc !== null || heredocs.length) return [...commands, shellProblem('a quote or heredoc is incomplete')];
  finishWord();
  if (words.length) commands.push({ words, expansions, depth });
  return commands;
}

function gitCommands(command, cwd, deadline) {
  const commands = [];
  let changedCwd = false, unknownAdd = false, persistentRepoOverride = false, aliasSettingsChanged = false, builtins = null, parsedSize = command.length;
  const parsedCommands = shellCommands(command, deadline);
  for (let at = 0; at < parsedCommands.length; at++) {
    if (at >= 1024 || Date.now() >= deadline) { commands.push(shellProblem('the parsing budget is exhausted')); break; }
    const parsed = parsedCommands[at];
    if (parsed.problem) { commands.push(parsed); continue; }
    const { words, expansions } = parsed;
    let first = 0, envOverride = false;
    while (first < words.length) {
      if (/^[A-Za-z_]\w*=/.test(words[first])) { first++; continue; }
      if (['command', 'builtin', 'if', 'elif', 'then', 'else', 'while', 'until', 'do', '!', '{'].includes(words[first])) {
        first++;
        if (words[first] === '--') first++;
        continue;
      }
      if (!/^(?:.*[\\/])?env(?:\.exe)?$/.test(words[first])) break;
      first++;
      while (words[first]?.startsWith('-') && words[first] !== '--') {
        const option = words[first++];
        let name;
        if (option === '-u' || option === '--unset') name = words[first++];
        else if (option.startsWith('--unset=')) name = option.slice(8);
        else { commands.push(shellProblem('this env option is unsupported')); break; }
        envOverride ||= expansions.has(first - 1) || /^(?:GIT_|HOME$|XDG_CONFIG_HOME$|PATH$)/.test(name || '');
      }
      if (words[first] === '--') first++;
    }
    if (first === words.length || ['export', 'declare', 'typeset', 'readonly'].includes(words[first])) {
      persistentRepoOverride ||= words.some((word) => /^GIT_(?:DIR|WORK_TREE|COMMON_DIR|INDEX_FILE)=/.test(word));
    }
    if (['cd', 'pushd', 'popd'].includes(words[first])) changedCwd = true;
    if (expansions.has(first)) {
      commands.push({ problem: 'Cannot inspect shell command: the executable requires expansion. Use a literal executable and separate commands.' });
      continue;
    }
    if (words[first] === 'function') { commands.push(shellProblem('shell function definitions are not supported')); continue; }
    const inlineRepoOverride = envOverride || words.slice(0, first).some((word) => /^GIT_(?:DIR|WORK_TREE|COMMON_DIR|INDEX_FILE)=/.test(word));
    if (/^(?:.*[\\/])?(?:sh|bash|dash|zsh|ksh)(?:\.exe)?$/.test(words[first] || '')) {
      persistentRepoOverride ||= inlineRepoOverride;
      let bodyAt = first + 1;
      while (/^-[^-]/.test(words[bodyAt] || '') && !words[bodyAt].includes('c')) bodyAt++;
      if (!/^-[^-]*c/.test(words[bodyAt] || '') || expansions.has(bodyAt + 1) || words[bodyAt + 1] === undefined) {
        commands.push(shellProblem('the shell body is not a literal -c command'));
      } else {
        const body = words[bodyAt + 1];
        parsedSize += body.length;
        if (parsedSize > 131072) commands.push(shellProblem('the parsing budget is exhausted'));
        else parsedCommands.splice(at + 1, 0, ...shellCommands(body, deadline, parsed.depth + 1));
      }
      continue;
    }
    if (!/^(?:.*[\\/])?git(?:\.exe)?$/.test(words[first] || '')) continue;
    const dirs = [], config = [];
    let dynamicRepo = false;
    let repoOverride = persistentRepoOverride || inlineRepoOverride;
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
      else if (['--git-dir', '--work-tree'].includes(arg)) { repoOverride = true; i++; }
      else if (arg.startsWith('--git-dir=') || arg.startsWith('--work-tree=')) repoOverride = true;
      else if (arg === '-c') { config.push(arg, words[++i] || ''); dynamicRepo ||= expansions.has(i); }
      else if (arg.startsWith('-c')) { config.push(arg); dynamicRepo ||= expansions.has(i); }
      else if (arg.startsWith('--config-env=')) repoOverride = true;
      else if ([
        '-p', '-P', '--paginate', '--no-pager', '--no-optional-locks', '--no-replace-objects',
        '--no-lazy-fetch', '--no-advice', '--literal-pathspecs', '--glob-pathspecs', '--noglob-pathspecs', '--icase-pathspecs',
      ].includes(arg)) continue;
      else break;
    }
    const verb = words[i];
    if (expansions.has(i)) {
      commands.push({ problem: 'Cannot inspect git command: the subcommand requires expansion. Use a literal Git subcommand.' });
      continue;
    }
    if (!['add', 'commit', 'push'].includes(verb)) {
      if (verb === 'config' && words.slice(i + 1).some((arg) => /^alias\./i.test(arg))) aliasSettingsChanged = true;
      if (verb && !verb.startsWith('-')) {
        builtins ??= git(['--list-cmds=builtins'], cwd, { timeout: Math.max(1, deadline - Date.now()) })?.trim().split(/\s+/);
        if (builtins?.includes(verb)) continue;
        const alias = aliasSettingsChanged || changedCwd || dynamicRepo || repoOverride || Date.now() >= deadline ? null
          : git([...dirs, ...config, 'config', '--default', '', '--get', `alias.${verb}`], cwd, { timeout: Math.max(1, deadline - Date.now()), requireQuiet: true });
        if (alias === null || alias.trim()) commands.push(shellProblem('Git alias execution cannot be inspected'));
      }
      continue;
    }
    const firstDir = dirs.find((arg, j) => dirs[j - 1] === '-C' && arg !== '');
    if (repoOverride || dynamicRepo || (changedCwd && !isAbsolute(firstDir || '')) || (verb === 'commit' && unknownAdd)) {
      if (verb === 'add') unknownAdd = true;
      else if (repoOverride) commands.push({ problem: `Cannot inspect git ${verb}: repository or index overrides are not supported. Use direct git -C with a literal absolute repository path and no Git overrides.` });
      else commands.push({ problem: `Cannot inspect git ${verb}: a repository path needs shell expansion, depends on a shell directory change, or follows an unresolved git add. Use git -C with a literal absolute repository path.` });
      continue;
    }
    // Let Git apply repeated -C options, including empty paths and symlink/.. traversal.
    if (Date.now() >= deadline) {
      commands.push({ problem: `Cannot inspect git ${verb}: the shared inspection budget is exhausted.` });
      break;
    }
    const inspect = (argv) => Date.now() >= deadline ? null : git(argv, cwd, { timeout: Math.max(1, deadline - Date.now()) });
    let root = inspect([...dirs, 'rev-parse', '--show-toplevel']);
    if (!root && verb === 'push') root = inspect([...dirs, 'rev-parse', '--absolute-git-dir']);
    if (!root && (verb === 'push' || Date.now() >= deadline)) {
      commands.push({ problem: `Cannot inspect git ${verb}: repository discovery failed or exceeded the shared inspection budget.` });
      break;
    }
    if (root) commands.push({ verb, cwd: root.replace(/\r?\n$/, ''), args: words.slice(i + 1), dynamicArgs: words.slice(i + 1).some((_, j) => expansions.has(i + 1 + j)) });
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

function pushProblems(args, cwd, dynamicArgs, deadline) {
  const deny = (reason) => [`Cannot inspect git push: ${reason}. Use explicit literal local commit source refs and supported push options.`];
  if (dynamicArgs) return deny('push arguments require shell expansion');
  const read = (argv) => Date.now() >= deadline ? null : git(['--no-lazy-fetch', '--no-replace-objects', ...argv], cwd, { timeout: Math.max(1, deadline - Date.now()), requireQuiet: true });
  const config = (key) => read(['config', '--get', key])?.trim();
  const enabled = (key) => read(['config', '--bool', '--get', key])?.trim() === 'true';
  const positionals = [];
  let options = true, all = false, deleting = false, followTags;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (options && arg === '--') { options = false; continue; }
    if (options && arg.startsWith('-')) {
      if (arg === '--all' || arg === '--branches') all = true;
      else if (arg === '--delete' || arg === '-d') deleting = true;
      else if (arg === '--follow-tags') followTags = true;
      else if (arg === '--no-follow-tags') followTags = false;
      else if (['-o', '--push-option', '--receive-pack', '--exec'].includes(arg)) {
        if (++i === args.length) return deny('a push option has no value');
      } else if (/^--(?:push-option|receive-pack|exec|force-with-lease|signed)=/.test(arg) || /^-[qvfun]+$/.test(arg) || [
        '--set-upstream', '--force', '--force-with-lease', '--force-if-includes', '--no-force-if-includes',
        '--atomic', '--no-atomic', '--porcelain', '--verbose', '--quiet', '--progress', '--no-progress',
        '--dry-run', '--no-verify', '--verify', '--thin', '--no-thin', '--signed', '--no-signed', '--prune',
      ].includes(arg)) continue;
      else return deny('this push option is not supported for source inspection');
    } else positionals.push(arg);
  }
  if (deleting) return [];
  let [remote, ...specs] = positionals;
  const branch = read(['symbolic-ref', '--quiet', '--short', 'HEAD'])?.trim();
  remote ||= (branch && config(`branch.${branch}.pushRemote`)) || config('remote.pushDefault') || (branch && config(`branch.${branch}.remote`)) || 'origin';
  if (read(['config', '--get-all', `remotes.${remote}`]) !== null) return deny('remote group selection is not supported');
  if (enabled(`remote.${remote}.mirror`) || (followTags ?? enabled('push.followTags'))) return deny('implicit mirror or annotated-tag sources are not supported');
  const recursion = config('push.recurseSubmodules')?.toLowerCase();
  if (recursion && !['no', 'false', 'off', '0', 'check'].includes(recursion)) return deny('implicit submodule pushes are not supported');
  if (read(['rev-parse', '--is-shallow-repository'])?.trim() !== 'false') return deny('complete local history is unavailable');
  if (all) {
    if (specs.length) return deny('branch selection is ambiguous');
    const refs = read(['for-each-ref', '--format=%(refname)', 'refs/heads/']);
    if (refs === null) return deny('local branches could not be listed');
    specs = refs.trim().split('\n').filter(Boolean);
  } else if (!specs.length) {
    if (!config(`remote.${remote}.url`)) return deny('default sources require a configured named remote');
    const configured = read(['config', '--get-all', `remote.${remote}.push`]);
    if (configured !== null) {
      specs = configured.trim().split('\n').filter(Boolean);
      if (!specs.length) return deny('configured source selection is empty');
    }
    else {
      const mode = config('push.default') || 'simple';
      if (mode === 'nothing') return [];
      if (!['simple', 'current', 'upstream', 'tracking'].includes(mode)) return deny('the default push source selection is not supported');
      specs = ['HEAD'];
    }
  }
  const tips = new Set();
  for (const spec of specs) {
    const parts = spec.replace(/^\+/, '').split(':');
    if (parts.length > 2 || /[*?\[\]\s]/.test(spec) || spec === ':' || spec === '+:') return deny('a refspec is not a literal commit source');
    const source = parts[0];
    if (!source) {
      if (parts.length === 2 && parts[1]) continue; // A deletion transfers no source history.
      return deny('a source ref is missing');
    }
    const oid = read(['rev-parse', '--verify', '--end-of-options', source])?.trim();
    if (!oid || !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(oid) || read(['cat-file', '-t', oid])?.trim() !== 'commit') return deny('a source is unresolved, ambiguous, or not a commit');
    tips.add(oid);
  }
  if (!tips.size) return [];
  // No receiver exclusions: remote tracking refs may be stale or belong to another receiver.
  const patch = read(['log', '-p', '--root', '--diff-merges=separate', '--no-renames', '--format=', '-U0', '--no-color', '--no-ext-diff', '--no-textconv', '--no-show-signature', '--no-notes', ...tips, '--']);
  return patch === null ? deny('source history inspection failed or exceeded its limits') : patchProblems(patch);
}

function checkGit(command, cwd) {
  const problems = [];
  const deadline = Date.now() + 8000;
  const diffArgs = ['-U0', '--no-color', '--no-ext-diff'];
  const addsFiles = new Set();
  for (const cmd of gitCommands(command, cwd, deadline)) {
    if (cmd.problem) { problems.push(cmd.problem); continue; }
    if (Date.now() >= deadline) { problems.push(`Cannot inspect git ${cmd.verb}: the shared inspection budget is exhausted.`); break; }
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
      problems.push(...pushProblems(cmd.args, target, cmd.dynamicArgs, deadline));
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

  const uncertainRepo = problems.some((p) => p.startsWith('Cannot inspect '));
  if (problems.some((p) => p.startsWith('Cannot inspect git push:'))) advice = ['Use a literal repository path and explicit local commit source refs; verify complete local history and simplify push options.'];
  else if (uncertainRepo) advice = ['Use literal executable/subcommand names and git -C with a literal absolute repository path; separate shell indirection and directory changes.'];
  const unique = [...new Set(problems)].slice(0, 15);
  process.stderr.write([
    uncertainRepo ? 'vibecheck guard blocked this: the command cannot be inspected safely.'
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
