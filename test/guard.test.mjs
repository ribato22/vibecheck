// vibecheck-ignore-file
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { keys, makeProject, removeProject, git, guard } from './helpers.mjs';

const write = (file_path, content) => ({ tool_name: 'Write', tool_input: { file_path, content }, cwd: '/tmp' });
const bash = (command, cwd) => ({ tool_name: 'Bash', tool_input: { command }, cwd });

const quoted = (path) => `'${path.replaceAll("'", "'\\''")}'`;
function gitFixture() {
  const dir = makeProject({ 'session/README.md': 'safe\n', 'target repo/README.md': 'safe\n' });
  const cwd = join(dir, 'session');
  const target = join(dir, 'target repo');
  for (const repo of [cwd, target]) {
    git(repo, 'init', '-q');
    git(repo, 'add', '.');
    git(repo, 'commit', '-qm', 'baseline');
  }
  return { dir, cwd, target };
}

function pushFixture() {
  const fixture = gitFixture();
  const { dir, target } = fixture;
  const remote = join(dir, 'origin.git');
  git(dir, 'init', '--bare', '-q', remote);
  git(target, 'remote', 'add', 'origin', remote);
  git(target, '-c', 'protocol.file.allow=always', 'push', '-qu', 'origin', 'main');
  const main = git(target, 'rev-parse', 'HEAD').trim();
  git(target, 'checkout', '-qb', 'secret-history');
  writeFileSync(join(target, 'key.ts'), `const key = "${keys.openai}";\n`);
  git(target, 'add', 'key.ts');
  git(target, 'commit', '-qm', 'synthetic secret');
  const secret = git(target, 'rev-parse', 'HEAD').trim();
  git(target, 'rm', '-q', 'key.ts');
  git(target, 'commit', '-qm', 'remove synthetic secret');
  git(target, 'checkout', '-q', 'main');
  return { ...fixture, remote, main, secret };
}

test('blocks hardcoding a key into source code', () => {
  const r = guard(write('/app/src/lib/ai.ts', `const key = "${keys.openai}";`));
  assert.equal(r.code, 2);
  assert.match(r.stderr, /OpenAI API key sk-p…/);
  assert.ok(!r.stderr.includes(keys.openai), 'guard must not echo the full secret');
});

test('blocks Edit and MultiEdit too', () => {
  assert.equal(guard({ tool_name: 'Edit', tool_input: { file_path: '/a/pay.ts', old_string: 'x', new_string: `"${keys.stripeLive}"` } }).code, 2);
  assert.equal(guard({ tool_name: 'MultiEdit', tool_input: { file_path: '/a/s.py', edits: [{ old_string: 'a', new_string: keys.serviceRole }] } }).code, 2);
});

test('allows secrets in .env, blocks them in .env.example', () => {
  assert.equal(guard(write('/app/.env', `OPENAI_API_KEY=${keys.openai}`)).code, 0);
  assert.equal(guard(write('/app/.env.local', `DATABASE_URL=${keys.dbUrl}`)).code, 0);
  assert.equal(guard(write('/app/.env.example', `OPENAI_API_KEY=${keys.openai}`)).code, 2);
});

test('blocks secret env vars with a browser-public prefix', () => {
  const r = guard(write('/app/.env', 'NEXT_PUBLIC_OPENAI_API_KEY=abc'));
  assert.equal(r.code, 2);
  assert.match(r.stderr, /NEXT_PUBLIC_OPENAI_API_KEY has a browser-public prefix/);
  assert.equal(guard(write('/app/src/x.ts', 'const k = import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY;')).code, 2);
  assert.equal(guard(write('/app/.env', 'NEXT_PUBLIC_SUPABASE_ANON_KEY=abc\nVITE_STRIPE_PUBLISHABLE_KEY=pk')).code, 0);
  assert.equal(guard(write('/app/README.md', 'Never name it NEXT_PUBLIC_OPENAI_API_KEY')).code, 0);
});

test('public Supabase values are allowed but secret values still block under public-looking names', () => {
  for (const value of [keys.publishable, keys.anon]) {
    assert.equal(guard(write('/app/src/client.ts', `const apiKey = "${value}";`)).code, 0);
  }
  for (const value of [keys.supabaseSecret, keys.serviceRole, keys.openai]) {
    const result = guard(write('/app/src/client.ts', `const SUPABASE_PUBLISHABLE_KEY = "${value}";`));
    assert.equal(result.code, 2);
    assert.ok(!result.stderr.includes(value), 'blocked secrets must remain masked');
  }
});

test('respects vibecheck-ignore, VIBECHECK_GUARD=off and fails open on bad input', () => {
  assert.equal(guard(write('/a/t.ts', `const k = "${keys.openai}"; // vibecheck-ignore`)).code, 0);
  assert.equal(guard(write('/a/t.ts', `const k = "${keys.openai}";`), { VIBECHECK_GUARD: 'off' }).code, 0);
  assert.equal(guard('not json').code, 0);
  assert.equal(guard(bash('ls -la', '/tmp')).code, 0);
});

test('blocks a commit that contains a secret or a .env file', () => {
  const dir = makeProject({ 'README.md': 'hi\n', '.gitignore': 'node_modules\n' });
  try {
    git(dir, 'init', '-q');
    git(dir, 'add', '-A');
    git(dir, 'commit', '-qm', 'init');

    assert.equal(guard(bash('git commit -m "nothing staged"', dir)).code, 0);

    writeFileSync(join(dir, 'aws.js'), `export const id = "${keys.aws}";\n`);
    git(dir, 'add', 'aws.js');
    const staged = guard(bash('git commit -m "add aws"', dir));
    assert.equal(staged.code, 2);
    assert.match(staged.stderr, /AWS access key AKIA… ?|AWS access key AKIA/);
    git(dir, 'rm', '-q', '--cached', 'aws.js');

    writeFileSync(join(dir, '.env'), 'OPENAI_API_KEY=whatever\n');
    const addAll = guard(bash('git add . && git commit -m "wip"', dir));
    assert.equal(addAll.code, 2);
    assert.match(addAll.stderr, /\.env would be committed/);
  } finally {
    removeProject(dir);
  }
});

test('blocks a push whose unpushed commits contain a secret', () => {
  const dir = makeProject({ 'README.md': 'hi\n' });
  try {
    git(dir, 'init', '-q');
    writeFileSync(join(dir, 'key.ts'), `const k = "${keys.anthropic}";\n`);
    git(dir, 'add', '-A');
    git(dir, 'commit', '-qm', 'add key');
    writeFileSync(join(dir, 'key.ts'), 'const k = process.env.ANTHROPIC_API_KEY;\n');
    git(dir, 'commit', '-qam', 'remove key');
    const r = guard(bash('git push -u origin main', dir));
    assert.equal(r.code, 2, 'secret is still in an unpushed commit even though HEAD no longer has it');
    assert.match(r.stderr, /Anthropic API key/);
  } finally {
    removeProject(dir);
  }
});

test('git -C commits inspect the target index instead of the clean session repo', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    writeFileSync(join(target, '.env'), 'OPENAI_API_KEY=synthetic\n');
    git(target, 'add', '.env');
    for (const origin of [cwd, dir]) {
      const result = guard(bash(`git -C ${quoted(target)} commit -m fixture`, origin));
      assert.equal(result.code, 2, 'must block from both another repo and a non-Git cwd');
      assert.match(result.stderr, /\.env would be committed/);
    }
  } finally { removeProject(dir); }
});

test('git -C pushes inspect all target commits ahead of a local remote', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    const remote = join(dir, 'remote.git');
    git(dir, 'init', '--bare', '-q', remote);
    git(target, 'remote', 'add', 'origin', remote);
    git(target, '-c', 'protocol.file.allow=always', 'push', '-qu', 'origin', 'main');
    const before = git(remote, 'rev-parse', 'main');
    writeFileSync(join(target, 'key.ts'), `const key = "${keys.openai}";\n`);
    git(target, 'add', 'key.ts');
    git(target, 'commit', '-qm', 'synthetic secret');
    git(target, 'rm', '-q', 'key.ts');
    git(target, 'commit', '-qm', 'remove synthetic secret');
    const result = guard(bash(`git -C ${quoted(target)} push origin main`, cwd));
    assert.equal(result.code, 2);
    assert.match(result.stderr, /OpenAI API key/);
    assert.ok(!result.stderr.includes(keys.openai));
    assert.equal(git(remote, 'rev-parse', 'main'), before, 'inspection must not execute the push');
  } finally { removeProject(dir); }
});

test('safe git -C targets ignore secrets staged in the session repo', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    writeFileSync(join(cwd, '.env'), 'SECRET=synthetic\n');
    git(cwd, 'add', '.env');
    assert.equal(guard(bash(`git -C ${quoted(target)} commit -m safe`, cwd)).code, 0);
    git(cwd, 'commit', '-qm', 'env in unrelated history');
    assert.equal(guard(bash(`git -C ${quoted(target)} push origin main`, cwd)).code, 0);
  } finally { removeProject(dir); }
});

test('git -C handles quoted, attached, repeated, relative and empty paths', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    writeFileSync(join(target, '.env'), 'SECRET=synthetic\n');
    git(target, 'add', '.env');
    const prefixes = [
      `-C ${quoted(target)}`,
      `-C "${target}"`,
      `-C${quoted(target)}`,
      `-C ${quoted(dir)} -C 'target repo' -C ""`,
      `-c test.note='commit push -C elsewhere' -C ${quoted(target)} --no-pager`,
    ];
    for (const prefix of prefixes) {
      assert.equal(guard(bash(`git ${prefix} commit -m fixture`, cwd)).code, 2, prefix);
    }
  } finally { removeProject(dir); }
});

test('repeated git -C follows native Git directory traversal through symlinks', (t) => {
  const { dir, cwd, target } = gitFixture();
  try {
    git(dir, 'init', '-q');
    writeFileSync(join(dir, 'README.md'), 'outer repo\n');
    git(dir, 'add', 'README.md');
    git(dir, 'commit', '-qm', 'outer baseline');
    mkdirSync(join(target, 'child'));
    const link = join(dir, 'link');
    symlinkSync(join(target, 'child'), link, process.platform === 'win32' ? 'junction' : 'dir');
    // Native Git may resolve junction/.. differently from POSIX symlink/.. traversal.
    for (const repo of [dir, target]) {
      writeFileSync(join(repo, '.env'), 'SECRET=synthetic\n');
      git(repo, 'add', '.env');
    }
    const selected = git(cwd, '-C', link, '-C', '..', 'rev-parse', '--show-toplevel').replace(/\r?\n$/, '');
    assert.match(git(selected, 'diff', '--cached', '--name-only'), /^\.env$/m);
    t.diagnostic(`native Git selected ${selected}`);
    assert.equal(guard(bash(`git -C ${quoted(link)} -C .. commit -m fixture`, cwd)).code, 2);
  } finally { removeProject(dir); }
});

test('separate Git commands keep their target repos and add checks isolated', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    writeFileSync(join(target, '.env'), 'SECRET=synthetic\n');
    assert.equal(guard(bash(`git -C ${quoted(target)} add . && git -C ${quoted(target)} commit -m fixture`, cwd)).code, 2);
    assert.equal(guard(bash(`git -C ${quoted(cwd)} add . && git -C ${quoted(target)} commit -m fixture`, cwd)).code, 0);
    git(target, 'add', '.env');
    assert.equal(guard(bash(`git -C ${quoted(target)} commit -m fixture; git -C ${quoted(cwd)} push`, cwd)).code, 2);
  } finally { removeProject(dir); }
});

test('quoted Git words and option values are not Git subcommands or flags', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    writeFileSync(join(target, '.env'), 'SECRET=synthetic\n');
    git(target, 'add', '.env');
    assert.equal(guard(bash(`echo "git -C ${target} commit"`, target)).code, 0);
    assert.equal(guard(bash('git -c test.note="commit push" status', target)).code, 0);
    git(target, 'rm', '-q', '--cached', '.env');
    writeFileSync(join(target, 'README.md'), keys.openai);
    assert.equal(guard(bash(`git -C ${quoted(target)} commit -m 'message --all push'`, cwd)).code, 0);
    assert.equal(guard(bash(`git -C ${quoted(target)} commit -am fixture`, cwd)).code, 2);
  } finally { removeProject(dir); }
});

test('Git global flags and shell comments do not hide a real commit', () => {
  const { dir, cwd } = gitFixture();
  try {
    writeFileSync(join(cwd, '.env'), 'SECRET=synthetic\n');
    git(cwd, 'add', '.env');
    for (const command of [
      'git --no-replace-objects --literal-pathspecs commit -m fixture',
      "# don't interpret quotes in this comment\ngit commit -m fixture",
    ]) assert.equal(guard(bash(command, cwd)).code, 2, command);
  } finally { removeProject(dir); }
});

test('git -C preserves trailing whitespace in literal repo paths', { skip: process.platform === 'win32' }, () => {
  const dir = makeProject({ 'target /README.md': 'safe\n' });
  const target = join(dir, 'target ');
  try {
    git(target, 'init', '-q');
    git(target, 'add', '.');
    git(target, 'commit', '-qm', 'baseline');
    writeFileSync(join(target, '.env'), 'SECRET=synthetic\n');
    git(target, 'add', '.env');
    assert.equal(guard(bash(`git -C ${quoted(target)} commit -m fixture`, dir)).code, 2);
  } finally { removeProject(dir); }
});

test('attached commit message values are not --all options', () => {
  const { dir, cwd } = gitFixture();
  try {
    writeFileSync(join(cwd, 'README.md'), keys.openai);
    for (const flags of ['-mdata', '-qma', '-qm "--all"', '-Sdata -m fixture']) {
      assert.equal(guard(bash(`git commit ${flags}`, cwd)).code, 0, flags);
    }
    assert.equal(guard(bash('git commit -qam fixture', cwd)).code, 2);
  } finally { removeProject(dir); }
});

test('push checks still cover bare repos with and without git -C', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    writeFileSync(join(target, 'key.ts'), `const key = "${keys.openai}";\n`);
    git(target, 'add', 'key.ts');
    git(target, 'commit', '-qm', 'synthetic secret');
    const bare = join(dir, 'bare.git');
    git(dir, '-c', 'protocol.file.allow=always', 'clone', '--bare', '-q', target, bare);
    assert.equal(guard(bash('git push origin main', bare)).code, 2);
    assert.equal(guard(bash(`git -C ${quoted(bare)} push origin main`, cwd)).code, 2);
    assert.equal(guard(bash(`git -C ${quoted(bare)} --bare push origin main`, cwd)).code, 2);
  } finally { removeProject(dir); }
});

test('rejects unresolved shell variable repo paths before a commit', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    writeFileSync(join(target, '.env'), `OPENAI_API_KEY=${keys.openai}\n`);
    git(target, 'add', '.env');
    const before = git(target, 'rev-parse', 'HEAD');
    const result = guard(bash(`VIBECHECK_REPO=${quoted(target)}; git -C "$VIBECHECK_REPO" commit -m fixture`, cwd));
    assert.equal(result.code, 2, 'must not silently inspect a different repo or skip the write');
    assert.match(result.stderr, /literal.*git -C|git -C.*literal/i);
    assert.ok(!result.stderr.includes(keys.openai));
    assert.equal(git(target, 'rev-parse', 'HEAD'), before);
    assert.match(git(target, 'diff', '--cached', '--name-only'), /^\.env$/m);
  } finally { removeProject(dir); }
});

test('rejects a push after shell directory changes instead of inspecting the session repo', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    writeFileSync(join(target, 'key.ts'), `const key = "${keys.openai}";\n`);
    git(target, 'add', 'key.ts');
    git(target, 'commit', '-qm', 'synthetic secret');
    git(target, 'rm', '-q', 'key.ts');
    git(target, 'commit', '-qm', 'remove synthetic secret');
    for (const command of [
      `cd ${quoted(target)} && git push origin main`,
      `(cd ${quoted(target)} && git push origin main)`,
    ]) {
      const result = guard(bash(command, cwd));
      assert.equal(result.code, 2, command);
      assert.match(result.stderr, /literal.*git -C|git -C.*literal/i);
      assert.ok(!result.stderr.includes(keys.openai));
    }
  } finally { removeProject(dir); }
});

test('rejects command substitutions in repo paths without executing them', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    const marker = join(dir, 'must-not-exist');
    const body = `touch ${quoted(marker)}; printf '%s' ${quoted(target)}`;
    for (const path of [`"$(${body})"`, `$(${body})`, `\`${body}\``, `"$(printf '%s' \"$(printf '%s' ${quoted(target)})\")"`, `"$(printf '%s' ${quoted(target)} # don't parse ) here\n)"`]) {
      const result = guard(bash(`git -C ${path} push origin main`, cwd));
      assert.equal(result.code, 2, path);
      assert.match(result.stderr, /Cannot inspect git push/);
      assert.equal(existsSync(marker), false, 'inspection must never execute shell text');
    }
  } finally { removeProject(dir); }
});

test('an unresolved git add cannot hide files from a later literal commit', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    writeFileSync(join(target, '.env'), `OPENAI_API_KEY=${keys.openai}\n`);
    const command = `VIBECHECK_REPO=${quoted(target)}; git -C "$VIBECHECK_REPO" add . && git -C ${quoted(target)} commit -m fixture`;
    const result = guard(bash(command, cwd));
    assert.equal(result.code, 2);
    assert.match(result.stderr, /Cannot inspect git commit/);
    assert.equal(git(target, 'diff', '--cached', '--name-only'), '', 'inspection must not stage the file');
  } finally { removeProject(dir); }
});

test('assignments and shell builtins do not hide the Git command or directory change', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    writeFileSync(join(target, '.env'), 'SECRET=synthetic\n');
    git(target, 'add', '.env');
    for (const command of [
      `VIBECHECK_CASE=fixture git -C ${quoted(target)} commit -m fixture`,
      `command git -C ${quoted(target)} commit -m fixture`,
      `builtin cd ${quoted(target)} && git commit -m fixture`,
    ]) assert.equal(guard(bash(command, cwd)).code, 2, command);
  } finally { removeProject(dir); }
});

test('env assignment wrappers keep Git commit and push inspection on the literal target', () => {
  const { dir, cwd, target, remote, main } = pushFixture();
  try {
    writeFileSync(join(target, '.env'), `OPENAI_API_KEY=${keys.openai}\n`);
    git(target, 'add', '.env');
    for (const prefix of ['env VIBECHECK_FIXTURE=1', '/usr/bin/env FIRST=one SECOND="two words"', 'command env -- VIBECHECK_FIXTURE=1', 'OUTER=one env INNER=two']) {
      const commit = guard(bash(`${prefix} git -C ${quoted(target)} commit -m fixture`, cwd));
      assert.equal(commit.code, 2, prefix);
      assert.match(commit.stderr, /\.env would be committed/);
      assert.ok(!commit.stderr.includes(keys.openai));
      const push = guard(bash(`${prefix} git -C ${quoted(target)} push origin secret-history`, cwd));
      assert.equal(push.code, 2, prefix);
      assert.match(push.stderr, /OpenAI API key/);
      assert.ok(!push.stderr.includes(keys.openai));
    }
    assert.equal(git(target, 'rev-parse', 'HEAD').trim(), main);
    assert.equal(git(remote, 'rev-parse', 'main').trim(), main);
    assert.match(git(target, 'diff', '--cached', '--name-only'), /^\.env$/m);
  } finally { removeProject(dir); }
});

test('env unset options do not hide literal Git commits or pushes', () => {
  const { dir, cwd, target, remote, main } = pushFixture();
  try {
    writeFileSync(join(target, '.env'), `OPENAI_API_KEY=${keys.openai}\n`);
    git(target, 'add', '.env');
    for (const prefix of ['env -u VIBECHECK_UNUSED', 'env --unset=VIBECHECK_UNUSED', 'command env -u VIBECHECK_UNUSED', 'env -u VIBECHECK_UNUSED --']) {
      for (const verb of ['commit -m fixture', 'push origin secret-history']) {
        const result = guard(bash(`${prefix} git -C ${quoted(target)} ${verb}`, cwd));
        assert.equal(result.code, 2, `${prefix} ${verb}`);
        assert.ok(!result.stderr.includes(keys.openai));
      }
    }
    assert.equal(git(target, 'rev-parse', 'HEAD').trim(), main);
    assert.equal(git(remote, 'rev-parse', 'main').trim(), main);
    assert.match(git(target, 'diff', '--cached', '--name-only'), /^\.env$/m);
  } finally { removeProject(dir); }
});

test('inline shell branches keep literal Git writes visible', () => {
  const { dir, cwd, target } = pushFixture();
  try {
    writeFileSync(join(target, '.env'), `OPENAI_API_KEY=${keys.openai}\n`);
    git(target, 'add', '.env');
    for (const verb of ['commit -m fixture', 'push origin secret-history']) {
      const write = `git -C ${quoted(target)} ${verb}`;
      for (const command of [`if true; then ${write}; fi`, `if false; then :; else ${write}; fi`, `if false; then :; elif true; then ${write}; fi`]) {
        const result = guard(bash(command, cwd));
        assert.equal(result.code, 2, command);
        assert.ok(!result.stderr.includes(keys.openai));
      }
    }
  } finally { removeProject(dir); }
});

test('exported Git repository variables keep later writes uncertain', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    for (const setup of [
      `export GIT_DIR=${quoted(join(target, '.git'))} GIT_WORK_TREE=${quoted(target)}`,
      `GIT_DIR=${quoted(join(target, '.git'))}`,
      `declare GIT_INDEX_FILE=${quoted(join(target, '.git', 'index'))}`,
      `if true; then export GIT_DIR=${quoted(join(target, '.git'))} GIT_WORK_TREE=${quoted(target)}; fi`,
    ]) {
      for (const verb of ['commit -m fixture', 'push origin main']) {
        const result = guard(bash(`(${setup}; git -C ${quoted(cwd)} ${verb})`, cwd));
        assert.equal(result.code, 2, `${setup} ${verb}`);
        assert.match(result.stderr, /Cannot inspect git (commit|push).*overrides/);
      }
      assert.equal(guard(bash(`${setup}; git status --short`, cwd)).code, 0);
    }
    assert.equal(guard(bash(`export VIBECHECK_FIXTURE=1; git -C ${quoted(cwd)} commit -m safe`, cwd)).code, 0);
  } finally { removeProject(dir); }
});

test('unresolved executable and Git verb expansions refuse execution', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    const marker = join(dir, 'must-not-exist');
    for (const verb of ['commit -m fixture', 'push origin main']) {
      const result = guard(bash(`(fixture_git=git; "$fixture_git" -C ${quoted(target)} ${verb})`, cwd));
      assert.equal(result.code, 2);
      assert.match(result.stderr, /Cannot inspect.*executable/);
    }
    const dynamicVerb = guard(bash(`fixture_verb=commit; git -C ${quoted(target)} "$fixture_verb" -m fixture`, cwd));
    assert.equal(dynamicVerb.code, 2);
    assert.match(dynamicVerb.stderr, /Cannot inspect.*subcommand/);
    assert.equal(guard(bash(`"$(touch ${quoted(marker)}; printf git)" status`, cwd)).code, 2);
    assert.equal(existsSync(marker), false);
  } finally { removeProject(dir); }
});

test('Git aliases and shell function definitions refuse indirection without running it', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    const marker = join(dir, 'must-not-exist');
    for (const verb of ['commit', 'push']) {
      for (const option of [`-c alias.fixture=${verb}`, `-calias.fixture=${verb}`]) {
        const result = guard(bash(`git -C ${quoted(target)} ${option} fixture -m fixture`, cwd));
        assert.equal(result.code, 2);
        assert.match(result.stderr, /Cannot inspect.*alias/);
      }
      git(target, 'config', 'alias.fixture', verb);
      assert.equal(guard(bash(`git -C ${quoted(target)} fixture`, cwd)).code, 2);
    }
    git(target, 'config', 'alias.fixture', `!touch ${quoted(marker)}`);
    assert.equal(guard(bash(`git -C ${quoted(target)} fixture`, cwd)).code, 2);
    git(target, 'config', '--unset', 'alias.fixture');
    assert.equal(guard(bash(`git -C ${quoted(target)} config alias.fixture commit; git -C ${quoted(target)} fixture`, cwd)).code, 2);
    for (const command of [
      `(fixture_git(){ git "$@"; }; fixture_git -C ${quoted(target)} commit -m fixture)`,
      `function fixture_git { touch ${quoted(marker)}; }; fixture_git`,
    ]) {
      const result = guard(bash(command, cwd));
      assert.equal(result.code, 2);
      assert.match(result.stderr, /Cannot inspect.*function/);
    }
    assert.equal(guard(bash(`printf '%s' 'fixture_git(){ git commit; }'`, cwd)).code, 0);
    assert.equal(guard(bash(`git -C ${quoted(target)} status`, cwd)).code, 0);
    assert.equal(existsSync(marker), false);
  } finally { removeProject(dir); }
});

test('literal shell bodies and executable substitutions inspect nested Git writes without evaluation', () => {
  const { dir, cwd, target, remote, main } = pushFixture();
  try {
    writeFileSync(join(target, '.env'), `OPENAI_API_KEY=${keys.openai}\n`);
    git(target, 'add', '.env');
    const marker = join(dir, 'must-not-exist');
    for (const verb of ['commit -m fixture', 'push origin secret-history']) {
      const write = `touch ${quoted(marker)}; git -C ${quoted(target)} ${verb}`;
      for (const command of [
        `/bin/sh -c ${quoted(write)}`,
        `env -u UNUSED bash -lc ${quoted(`/bin/sh -c ${quoted(write)}`)}`,
        `printf '%s\\n' "$(${write})"`,
        `printf '%s\\n' \`${write}\``,
        `printf '%s' "\${UNSET:-$(${write})}"`,
        `printf '%s' "\${UNSET:-'$(${write})'}"`,
        `cat <<EXPANDING\n'$(${write})'\nEXPANDING\n`,
        `cat <<EXPANDING\n\`${write}\`\nEXPANDING\n`,
      ]) {
        const result = guard(bash(command, cwd));
        assert.equal(result.code, 2, command);
        assert.match(result.stderr, /\.env would be committed|OpenAI API key/);
        assert.ok(!result.stderr.includes(keys.openai));
      }
    }
    for (const command of [
      `/bin/sh -c ${quoted(`git -C ${quoted(cwd)} commit -m safe`)}`,
      `cat <<'LITERAL'\n$(git -C ${quoted(target)} commit -m fixture)\nLITERAL\n`,
      `cat <<\\LITERAL\n$(git -C ${quoted(target)} commit -m fixture)\nLITERAL\n`,
      `cat <<EXPANDING\n\\$(git -C ${quoted(target)} commit -m fixture)\nEXPANDING\n`,
    ]) assert.equal(guard(bash(command, cwd)).code, 0, command);
    assert.equal(guard(bash('sh -c "$BODY"', cwd)).code, 2);
    const legacy = 'printf \'%s\\n\' "`printf \'%s\' \\`git -C ' + quoted(target) + ' commit -m fixture\\``"';
    const legacyResult = guard(bash(legacy, cwd));
    assert.equal(legacyResult.code, 2);
    assert.match(legacyResult.stderr, /Cannot inspect.*legacy backtick/);
    assert.equal(existsSync(marker), false, 'inspection must never execute nested bodies');
    assert.equal(git(target, 'rev-parse', 'HEAD').trim(), main);
    assert.equal(git(remote, 'rev-parse', 'main').trim(), main);
    assert.match(git(target, 'diff', '--cached', '--name-only'), /^\.env$/m);
  } finally { removeProject(dir); }
});

test('nested git add preserves commit scope and incomplete or excessive parsing refuses execution', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    writeFileSync(join(target, '.env'), 'SECRET=synthetic\n');
    const add = `git -C ${quoted(target)} add .`;
    const commit = `git -C ${quoted(target)} commit -m fixture`;
    for (const command of [
      `/bin/sh -c ${quoted(`${add}; ${commit}`)}`,
      `printf '%s' "$(${add})"; ${commit}`,
      `${commit} <<EXPANDING\n$(${add})\nEXPANDING\n`,
    ]) {
      const result = guard(bash(command, cwd));
      assert.equal(result.code, 2, command);
      assert.match(result.stderr, /\.env would be committed/);
    }
    for (const command of ["printf 'unfinished", 'echo $(unfinished', 'cat <<END\nunfinished', `printf '%s' ${'x'.repeat(131073)}`, 'true;'.repeat(1025)]) {
      const result = guard(bash(command, cwd));
      assert.equal(result.code, 2);
      assert.match(result.stderr, /Cannot inspect shell command/);
    }
    let nested = 'printf safe';
    for (let i = 0; i < 10; i++) nested = `sh -c ${quoted(nested)}`;
    assert.equal(guard(bash(nested, cwd)).code, 2);
    assert.equal(git(target, 'diff', '--cached', '--name-only'), '', 'inspection must not stage the fixture');
  } finally { removeProject(dir); }
});

test('literal shell wrappers retain inherited repository override uncertainty', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    for (const prefix of [
      `GIT_DIR=${quoted(join(target, '.git'))} GIT_WORK_TREE=${quoted(target)}`,
      'env -u GIT_INDEX_FILE',
    ]) {
      for (const verb of ['commit -m fixture', 'push origin main']) {
        const command = `${prefix} sh -c ${quoted(`sh -c ${quoted(`git -C ${quoted(cwd)} ${verb}`)}`)}`;
        const result = guard(bash(command, cwd));
        assert.equal(result.code, 2, command);
        assert.match(result.stderr, /Cannot inspect git (commit|push).*overrides/);
      }
    }
  } finally { removeProject(dir); }
});

test('explicit repository overrides refuse writes even with an absolute git -C', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    const overrides = [
      `--git-dir=${quoted(join(target, '.git'))} --work-tree=${quoted(target)}`,
      `--git-dir ${quoted(join(target, '.git'))} --work-tree ${quoted(target)}`,
      `-C ${quoted(cwd)} --git-dir=${quoted(join(target, '.git'))}`,
      `--work-tree=${quoted(target)} -C ${quoted(cwd)}`,
    ];
    for (const options of overrides) {
      for (const verb of ['commit -m fixture', 'push origin main']) {
        const result = guard(bash(`git ${options} ${verb}`, cwd));
        assert.equal(result.code, 2, `${options} ${verb}`);
        assert.match(result.stderr, /Cannot inspect git (commit|push).*overrides/);
      }
      assert.equal(guard(bash(`git ${options} status --short`, cwd)).code, 0, options);
    }
  } finally { removeProject(dir); }
});

test('inline repository and index environment overrides refuse writes without evaluating values', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    const marker = join(dir, 'must-not-exist');
    for (const prefix of [
      `GIT_DIR=${quoted(join(target, '.git'))} GIT_WORK_TREE=${quoted(target)}`,
      `GIT_WORK_TREE=${quoted(target)}`,
      `GIT_INDEX_FILE=${quoted(join(target, '.git', 'index'))}`,
      `GIT_COMMON_DIR=${quoted(join(target, '.git'))}`,
      `env LABEL=fixture GIT_DIR=${quoted(join(target, '.git'))}`,
      `GIT_DIR="$(touch ${quoted(marker)})"`,
    ]) {
      for (const verb of ['commit -m fixture', 'push origin main']) {
        const result = guard(bash(`${prefix} git -C ${quoted(cwd)} ${verb}`, cwd));
        assert.equal(result.code, 2, `${prefix} ${verb}`);
        assert.match(result.stderr, /Cannot inspect git (commit|push).*overrides/);
      }
      assert.equal(guard(bash(`${prefix} git status --short`, cwd)).code, 0, prefix);
    }
    assert.equal(existsSync(marker), false, 'inspection must not run assignment substitutions');
  } finally { removeProject(dir); }
});

test('override-selected git add keeps a later literal commit uncertain', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    writeFileSync(join(target, '.env'), `OPENAI_API_KEY=${keys.openai}\n`);
    for (const prefix of [
      `git --git-dir=${quoted(join(target, '.git'))} --work-tree=${quoted(target)}`,
      `GIT_DIR=${quoted(join(target, '.git'))} GIT_WORK_TREE=${quoted(target)} git`,
      `env GIT_INDEX_FILE=${quoted(join(target, '.git', 'index'))} git -C ${quoted(target)}`,
    ]) {
      const result = guard(bash(`${prefix} add . && git -C ${quoted(target)} commit -m fixture`, cwd));
      assert.equal(result.code, 2, prefix);
      assert.match(result.stderr, /Cannot inspect git commit.*unresolved git add/);
      assert.ok(!result.stderr.includes(keys.openai));
    }
    assert.equal(git(target, 'diff', '--cached', '--name-only'), '', 'the guard must not stage the file');
  } finally { removeProject(dir); }
});

test('safe env-wrapped Git writes and non-repository assignments remain inspectable', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    writeFileSync(join(cwd, '.env'), 'SECRET=synthetic\n');
    git(cwd, 'add', '.env');
    writeFileSync(join(target, 'safe.txt'), 'safe\n');
    git(target, 'add', 'safe.txt');
    const before = git(target, 'rev-parse', 'HEAD');
    for (const prefix of ['env', 'env LABEL="two words"', 'command env -- LABEL=fixture', 'GIT_AUTHOR_NAME=fixture', 'GIT_TERMINAL_PROMPT=0 env LABEL=fixture']) {
      assert.equal(guard(bash(`${prefix} git -C ${quoted(target)} commit -m 'GIT_DIR=x --git-dir=elsewhere'`, cwd)).code, 0, prefix);
      assert.equal(guard(bash(`${prefix} git -C ${quoted(target)} push origin main`, cwd)).code, 0, prefix);
    }
    assert.equal(guard(bash('echo "GIT_DIR=x git commit --git-dir=elsewhere"', cwd)).code, 0);
    assert.equal(git(target, 'rev-parse', 'HEAD'), before);
    assert.match(git(target, 'diff', '--cached', '--name-only'), /^safe.txt$/m);
  } finally { removeProject(dir); }
});

test('literal dollar paths are inspected rather than treated as shell expansion', () => {
  const { dir, cwd } = gitFixture();
  try {
    const target = join(dir, 'literal $VIBECHECK_REPO');
    mkdirSync(target);
    git(target, 'init', '-q');
    writeFileSync(join(target, '.env'), 'SECRET=synthetic\n');
    git(target, 'add', '.env');
    const escaped = `"${target.replaceAll('\\', '\\\\').replaceAll('$', '\\$').replaceAll('"', '\\"')}"`;
    for (const path of [quoted(target), escaped]) {
      const result = guard(bash(`git -C ${path} commit -m fixture`, cwd));
      assert.equal(result.code, 2);
      assert.match(result.stderr, /\.env would be committed/);
      assert.doesNotMatch(result.stderr, /Cannot inspect git/);
    }
  } finally { removeProject(dir); }
});

test('read-only shell commands and message-only expansion remain allowed', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    writeFileSync(join(target, 'safe.txt'), 'safe\n');
    git(target, 'add', 'safe.txt');
    const marker = join(dir, 'must-not-exist');
    for (const command of [
      `cd ${quoted(target)} && git status`,
      `git -C "$VIBECHECK_REPO" status`,
      `echo 'git -C "$VIBECHECK_REPO" commit'`,
      `git -C ${quoted(target)} commit -m "$MESSAGE"`,
      `git -C ${quoted(target)} commit -m "$(touch ${quoted(marker)}; printf '%s' push)"`,
    ]) assert.equal(guard(bash(command, cwd)).code, 0, command);
    assert.equal(existsSync(marker), false);
    assert.match(git(target, 'diff', '--cached', '--name-only'), /^safe.txt$/m);
  } finally { removeProject(dir); }
});

test('heredoc payloads are text rather than top-level Git commands', () => {
  const { dir, cwd } = gitFixture();
  try {
    const example = `git -C ${quoted(join(dir, 'not-a-repo'))} push origin main`;
    for (const command of [
      `cat <<'EXAMPLE'\n${example}\nEXAMPLE`,
      `cat <<EXAMPLE\n${example}\nEXAMPLE\n`,
      `cat <<\\EXAMPLE\n${example}\nEXAMPLE\n`,
      `cat <<-"EXAMPLE"\n\t${example}\n\tEXAMPLE\n`,
      `cat <<FIRST <<'SECOND'\n${example}\nFIRST\n${example}\nSECOND\n`,
    ]) assert.equal(guard(bash(command, cwd)).code, 0, command);
  } finally { removeProject(dir); }
});

test('heredocs do not hide real Git writes before or after their payloads', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    writeFileSync(join(target, '.env'), 'SECRET=synthetic\n');
    git(target, 'add', '.env');
    const commit = `env LABEL=fixture git -C ${quoted(target)} commit -m fixture`;
    const example = `git -C ${quoted(join(dir, 'not-a-repo'))} push origin main`;
    for (const command of [
      `cat <<'EXAMPLE'\n${example}\nEXAMPLE\n${commit}`,
      `${commit}; cat <<EXAMPLE\n${example}\nEXAMPLE`,
      `cat <<EXAMPLE; ${commit}\n${example}\nEXAMPLE`,
      `cat <<FIRST <<-SECOND\n${example}\nFIRST\n\t${example}\n\tSECOND\n${commit}`,
    ]) {
      const result = guard(bash(command, cwd));
      assert.equal(result.code, 2, command);
      assert.match(result.stderr, /\.env would be committed/);
      assert.doesNotMatch(result.stderr, /Cannot inspect git/);
    }
  } finally { removeProject(dir); }
});

test('arithmetic and array indexes inspect nested commit and push substitutions without execution', () => {
  const { dir, cwd, target, remote, main } = pushFixture();
  try {
    writeFileSync(join(target, '.env'), `OPENAI_API_KEY=${keys.openai}\n`);
    git(target, 'add', '.env');
    const staged = git(target, 'diff', '--cached', '--binary');
    const marker = join(dir, 'must-not-exist');
    for (const verb of ['commit -qm fixture', 'push -q origin secret-history']) {
      const body = `touch ${quoted(marker)}; git -C ${quoted(target)} ${verb}`;
      const arithmetic = `(( fixture_n = $(${body})1 ))`;
      const index = `fixture_values[$(${body})0]=safe`;
      for (const command of [
        arithmetic,
        index,
        `/bin/bash -c ${quoted(arithmetic)}`,
        `/bin/bash -c ${quoted(index)}`,
        `fixture_values[$(${body})0]+=safe`,
        `(( fixture_n = \`${body}\`1 ))`,
        `for ((fixture_n=$(${body})1;fixture_n<2;fixture_n++)); do :; done`,
      ]) {
        const result = guard(bash(command, cwd));
        assert.equal(result.code, 2, command);
        assert.match(result.stderr, /\.env would be committed|OpenAI API key/);
        assert.ok(!result.stderr.includes(keys.openai));
      }
    }
    assert.equal(existsSync(marker), false, 'inspection must not execute substitution bodies');
    assert.equal(git(target, 'rev-parse', 'HEAD').trim(), main);
    assert.equal(git(remote, 'rev-parse', 'main').trim(), main);
    assert.equal(git(target, 'diff', '--cached', '--binary'), staged);
  } finally { removeProject(dir); }
});

test('arithmetic and index substitutions retain nested add scope for later commits', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    writeFileSync(join(target, '.env'), `OPENAI_API_KEY=${keys.openai}\n`);
    const commit = `git -C ${quoted(target)} commit -m fixture`;
    for (const add of [`git -C ${quoted(target)} add .`, 'git -C "$UNRESOLVED_REPO" add .']) {
      for (const setup of [`(( fixture_n=$(${add})1 ))`, `fixture_values[$(${add})0]=safe`]) {
        const result = guard(bash(`${setup}; ${commit}`, cwd));
        assert.equal(result.code, 2, setup);
        assert.match(result.stderr, /\.env would be committed|Cannot inspect git commit/);
        assert.ok(!result.stderr.includes(keys.openai));
      }
    }
    assert.equal(git(target, 'diff', '--cached', '--name-only'), '', 'inspection must not stage files');
  } finally { removeProject(dir); }
});

test('arithmetic and index parsing preserves safe syntax, quote boundaries and nesting limits', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    writeFileSync(join(target, 'safe.txt'), 'safe\n');
    git(target, 'add', 'safe.txt');
    const marker = join(dir, 'must-not-exist');
    const commit = `git -C ${quoted(target)} commit -m safe`;
    const harmless = `touch ${quoted(marker)}; printf 1`;
    for (const command of [
      `(( fixture_n=1<<2 )); ${commit}`,
      `fixture_values[1 << 2]=safe; ${commit}`,
      `(( fixture_n=$(${harmless}) )); ${commit}`,
      `fixture_values[$(${harmless})]=safe; ${commit}`,
      `printf '%s' ${quoted('((fixture_n=$(git -C "$UNRESOLVED_REPO" push origin main)1))')}`,
      `printf '%s' ${quoted('fixture_values[$(git -C "$UNRESOLVED_REPO" push origin main)0]=safe')}`,
    ]) assert.equal(guard(bash(command, cwd)).code, 0, command);
    let nested = 'printf 0';
    for (let i = 0; i < 10; i++) nested = `printf "$(${nested})"`;
    for (const command of [`((fixture_n=$(${nested})1))`, `fixture_values[$(${nested})0]=safe`]) {
      const result = guard(bash(command, cwd));
      assert.equal(result.code, 2);
      assert.match(result.stderr, /Cannot inspect shell command.*budget/);
    }
    assert.equal(existsSync(marker), false);
    assert.match(git(target, 'diff', '--cached', '--name-only'), /^safe.txt$/m);
  } finally { removeProject(dir); }
});

test('arithmetic and word expansions containing shifts cannot hide a later Git write', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    writeFileSync(join(target, '.env'), 'SECRET=synthetic\n');
    git(target, 'add', '.env');
    const commit = `git -C ${quoted(target)} commit -m fixture`;
    for (const command of [
      `((value=1<<2));\n${commit}\n2`,
      `echo \${LABEL:-1<<EXAMPLE}\n${commit}\nEXAMPLE}`,
      `printf '%s\\n' "\${LABEL:- # default}"\n${commit}`,
      `printf '%s\\n' "\${LABEL:-can't}"\n${commit}`,
      `values[1<<2]=safe\n${commit}\n2]=safe`,
      `values[1 << 2]=safe\n${commit}\n2]=safe`,
    ]) {
      const result = guard(bash(command, cwd));
      assert.equal(result.code, 2, command);
      assert.match(result.stderr, /\.env would be committed/);
    }
  } finally { removeProject(dir); }
});

test('an absolute literal git -C restores an inspectable target after cd', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    writeFileSync(join(target, '.env'), 'SECRET=synthetic\n');
    git(target, 'add', '.env');
    writeFileSync(join(cwd, 'safe.txt'), 'safe\n');
    git(cwd, 'add', 'safe.txt');
    assert.equal(guard(bash(`cd ${quoted(target)} && git -C ${quoted(cwd)} commit -m safe`, cwd)).code, 0);
    const result = guard(bash(`cd ${quoted(cwd)} && git -C ${quoted(target)} commit -m fixture`, cwd));
    assert.equal(result.code, 2);
    assert.match(result.stderr, /\.env would be committed/);
    assert.doesNotMatch(result.stderr, /Cannot inspect git/);
    assert.equal(guard(bash(`cd ${quoted(target)} && git -C "" commit -m fixture`, cwd)).code, 2);
  } finally { removeProject(dir); }
});

test('push inspects a named source branch even when HEAD is clean and synced', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    const remote = join(dir, 'origin.git');
    git(dir, 'init', '--bare', '-q', remote);
    git(target, 'remote', 'add', 'origin', remote);
    git(target, '-c', 'protocol.file.allow=always', 'push', '-qu', 'origin', 'main');
    const main = git(target, 'rev-parse', 'HEAD');
    git(target, 'checkout', '-qb', 'secret-history');
    writeFileSync(join(target, 'key.ts'), `const key = "${keys.openai}";\n`);
    git(target, 'add', 'key.ts');
    git(target, 'commit', '-qm', 'synthetic secret');
    git(target, 'rm', '-q', 'key.ts');
    git(target, 'commit', '-qm', 'remove synthetic secret');
    git(target, 'checkout', '-q', 'main');
    assert.equal(git(target, 'rev-list', '--count', '@{u}..HEAD').trim(), '0');
    const result = guard(bash(`git -C ${quoted(target)} push origin secret-history:refs/heads/secret-history`, cwd));
    assert.equal(result.code, 2);
    assert.match(result.stderr, /OpenAI API key/);
    assert.ok(!result.stderr.includes(keys.openai));
    assert.equal(git(target, 'rev-parse', 'HEAD'), main);
    assert.equal(git(remote, 'for-each-ref', '--format=%(refname)', 'refs/heads/secret-history'), '');
  } finally { removeProject(dir); }
});

test('push to another remote checks history already present in the upstream', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    const origin = join(dir, 'origin.git');
    const archive = join(dir, 'archive.git');
    for (const [name, remote] of [['origin', origin], ['archive', archive]]) {
      git(dir, 'init', '--bare', '-q', remote);
      git(target, 'remote', 'add', name, remote);
      git(target, '-c', 'protocol.file.allow=always', 'push', '-q', name, 'main');
    }
    git(target, 'branch', '--set-upstream-to=origin/main', 'main');
    const archiveBefore = git(archive, 'rev-parse', 'main');
    writeFileSync(join(target, 'key.ts'), `const key = "${keys.openai}";\n`);
    git(target, 'add', 'key.ts');
    git(target, 'commit', '-qm', 'synthetic secret');
    git(target, 'rm', '-q', 'key.ts');
    git(target, 'commit', '-qm', 'remove synthetic secret');
    git(target, '-c', 'protocol.file.allow=always', 'push', '-q', 'origin', 'main');
    assert.equal(git(target, 'rev-list', '--count', '@{u}..HEAD').trim(), '0');
    const result = guard(bash(`git -C ${quoted(target)} push archive main`, cwd));
    assert.equal(result.code, 2);
    assert.match(result.stderr, /OpenAI API key/);
    assert.equal(git(archive, 'rev-parse', 'main'), archiveBefore);
  } finally { removeProject(dir); }
});

test('push selection separates safe refs, option values, deletes and multiple sources', () => {
  const { dir, cwd, target } = pushFixture();
  try {
    for (const args of ['--push-option secret-history origin main', 'origin HEAD:refs/heads/safe', '--delete origin secret-history', 'origin :refs/heads/secret-history']) {
      assert.equal(guard(bash(`git -C ${quoted(target)} push ${args}`, cwd)).code, 0, args);
    }
    for (const args of ['origin main secret-history:refs/heads/feature', '--force-with-lease origin +secret-history:refs/heads/feature', '--all origin']) {
      const result = guard(bash(`git -C ${quoted(target)} push ${args}`, cwd));
      assert.equal(result.code, 2, args);
      assert.match(result.stderr, /OpenAI API key/);
    }
  } finally { removeProject(dir); }
});

test('push defaults honor remote mappings and push-remote precedence', () => {
  const { dir, cwd, target } = pushFixture();
  try {
    git(target, 'config', 'remote.origin.push', 'secret-history:refs/heads/feature');
    for (const command of ['git push origin', 'git push']) {
      const result = guard(bash(command, target));
      assert.equal(result.code, 2, command);
      assert.match(result.stderr, /OpenAI API key/);
    }
    git(target, 'remote', 'add', 'archive', join(dir, 'receiver-not-contacted.git'));
    git(target, 'config', 'remote.archive.push', 'secret-history:refs/heads/feature');
    git(target, 'config', 'remote.origin.push', 'main');
    git(target, 'config', 'remote.pushDefault', 'archive');
    assert.match(guard(bash('git push', target)).stderr, /OpenAI API key/);
    assert.equal(guard(bash(`git -C ${quoted(target)} push origin`, cwd)).code, 0);
    git(target, 'config', 'branch.main.pushRemote', 'origin');
    assert.equal(guard(bash('git push', target)).code, 0);
    assert.equal(existsSync(join(dir, 'receiver-not-contacted.git')), false);
  } finally { removeProject(dir); }
});

test('unresolved, dynamic, annotated-tag and unsupported push selections are refused', () => {
  const { dir, cwd, target } = pushFixture();
  try {
    git(target, 'tag', '-a', 'annotated', '-m', 'safe annotation');
    for (const args of ['origin missing-ref', 'origin "$SOURCE"', 'origin annotated', '--tags origin', '--mirror origin', '--follow-tags origin main', 'origin :', '--unknown origin main']) {
      const result = guard(bash(`git -C ${quoted(target)} push ${args}`, cwd));
      assert.equal(result.code, 2, args);
      assert.match(result.stderr, /Cannot inspect git push/);
    }
    git(target, 'config', 'push.followTags', 'true');
    assert.match(guard(bash('git push origin main', target)).stderr, /Cannot inspect git push/);
    git(target, 'config', 'push.followTags', 'yes');
    assert.match(guard(bash('git push origin main', target)).stderr, /Cannot inspect git push/);
    assert.equal(guard(bash('git push --no-follow-tags origin main', target)).code, 0);
    git(target, 'config', '--unset', 'push.followTags');
    git(target, 'config', 'remote.origin.mirror', 'true');
    assert.match(guard(bash('git push origin main', target)).stderr, /Cannot inspect git push/);
    git(target, 'config', 'remote.origin.mirror', '1');
    assert.match(guard(bash('git push origin main', target)).stderr, /Cannot inspect git push/);
    git(target, 'config', '--unset', 'remote.origin.mirror');
    git(target, 'config', 'push.recurseSubmodules', 'on-demand');
    assert.match(guard(bash('git push origin main', target)).stderr, /Cannot inspect git push/);
    git(target, 'config', '--unset', 'push.recurseSubmodules');
    git(target, 'config', 'push.default', 'matching');
    assert.match(guard(bash('git push origin', target)).stderr, /Cannot inspect git push/);
    git(target, 'tag', 'main');
    assert.match(guard(bash('git push origin main', target)).stderr, /Cannot inspect git push/);
  } finally { removeProject(dir); }
});

test('shallow and unreadable push histories are refused rather than treated as clean', () => {
  const { dir, target, main, secret } = pushFixture();
  try {
    writeFileSync(join(target, '.git', 'shallow'), `${main}\n`);
    assert.match(guard(bash('git push origin main', target)).stderr, /Cannot inspect git push/);
    unlinkSync(join(target, '.git', 'shallow'));
    const object = join(target, '.git', 'objects', secret.slice(0, 2), secret.slice(2));
    assert.equal(existsSync(object), true);
    unlinkSync(object);
    const result = guard(bash('git push origin secret-history', target));
    assert.equal(result.code, 2);
    assert.match(result.stderr, /source history inspection failed/);
  } finally { removeProject(dir); }
});

test('push history includes secrets introduced only by a merge commit', () => {
  const { dir, target } = gitFixture();
  try {
    git(target, 'checkout', '-qb', 'feature');
    writeFileSync(join(target, 'feature.txt'), 'safe feature\n');
    git(target, 'add', 'feature.txt');
    git(target, 'commit', '-qm', 'safe feature');
    git(target, 'checkout', '-q', 'main');
    writeFileSync(join(target, 'main.txt'), 'safe main\n');
    git(target, 'add', 'main.txt');
    git(target, 'commit', '-qm', 'safe main');
    git(target, 'merge', '--no-ff', '--no-commit', 'feature');
    writeFileSync(join(target, 'key.ts'), `const key = "${keys.openai}";\n`);
    git(target, 'add', 'key.ts');
    git(target, 'commit', '-qm', 'merge introduces synthetic secret');
    const result = guard(bash('git push origin main', target));
    assert.equal(result.code, 2);
    assert.match(result.stderr, /OpenAI API key/);
    git(target, 'config', 'log.diffMerges', 'off');
    const configured = guard(bash('git push origin main', target));
    assert.equal(configured.code, 2);
    assert.match(configured.stderr, /OpenAI API key/);
  } finally { removeProject(dir); }
});

test('push inspection never runs a configured textconv program', () => {
  const { dir, target } = gitFixture();
  try {
    const marker = join(dir, 'converter-ran');
    const converter = join(dir, 'converter.mjs');
    writeFileSync(converter, `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(marker)}, 'ran'); process.stdout.write('clean');\n`);
    git(target, 'config', 'diff.fixture.textconv', `"${process.execPath}" "${converter}"`);
    writeFileSync(join(target, '.gitattributes'), 'key.ts diff=fixture\n');
    writeFileSync(join(target, 'key.ts'), `const key = "${keys.openai}";\n`);
    git(target, 'add', '.gitattributes', 'key.ts');
    git(target, 'commit', '-qm', 'synthetic secret with textconv');
    const result = guard(bash('git push origin main', target));
    assert.equal(result.code, 2);
    assert.match(result.stderr, /OpenAI API key/);
    assert.equal(existsSync(marker), false);
  } finally { removeProject(dir); }
});

test('replacement objects cannot hide the history a push will send', () => {
  const { dir, target, main, secret } = pushFixture();
  try {
    git(target, 'replace', secret, main);
    const result = guard(bash('git push origin secret-history', target));
    assert.equal(result.code, 2);
    assert.match(result.stderr, /OpenAI API key/);
  } finally { removeProject(dir); }
});

test('multiple pushes share one inspection budget for the whole Bash call', () => {
  const { dir, target } = gitFixture();
  try {
    const command = Array(1000).fill(`git -C ${quoted(target)} push origin main`).join('; ');
    const started = Date.now();
    const result = guard(bash(command, target));
    assert.equal(result.code, 2);
    assert.match(result.stderr, /Cannot inspect git push/);
    assert.ok(Date.now() - started < 15000, 'must refuse within one budget, not grant a budget per push');
  } finally { removeProject(dir); }
});

test('root source commits are inspected even when log.showRoot is disabled', () => {
  const dir = makeProject({ 'key.ts': `const key = "${keys.openai}";\n` });
  try {
    git(dir, 'init', '-q');
    git(dir, 'add', 'key.ts');
    git(dir, 'commit', '-qm', 'root synthetic secret');
    git(dir, 'rm', '-q', 'key.ts');
    git(dir, 'commit', '-qm', 'remove synthetic secret');
    git(dir, 'config', 'log.showRoot', 'false');
    const result = guard(bash('git push unused HEAD:main', dir));
    assert.equal(result.code, 2);
    assert.match(result.stderr, /OpenAI API key/);
  } finally { removeProject(dir); }
});

test('push history detects env files created by rename-only commits', () => {
  const dir = makeProject({ 'settings.txt': 'SECRET=synthetic\n' });
  try {
    git(dir, 'init', '-q');
    git(dir, 'add', 'settings.txt');
    git(dir, 'commit', '-qm', 'safe initial filename');
    git(dir, 'mv', 'settings.txt', '.env');
    git(dir, 'commit', '-qm', 'rename to env');
    git(dir, 'config', 'diff.renames', 'true');
    const result = guard(bash('git push unused HEAD:main', dir));
    assert.equal(result.code, 2);
    assert.match(result.stderr, /\.env would be committed/);
  } finally { removeProject(dir); }
});

test('shell policy regressions: eval refuses commit and push bodies without evaluating them', () => {
  const { dir, cwd, target, remote, main } = pushFixture();
  try {
    const marker = join(dir, 'eval-must-not-run');
    const index = git(target, 'diff', '--cached', '--binary');
    for (const verb of ['commit -m fixture', 'push origin secret-history']) {
      const body = `touch ${quoted(marker)}; git -C ${quoted(target)} ${verb}`;
      for (const command of [
        `eval ${quoted(body)}`,
        `command eval ${quoted(body)}`,
        `command -p eval ${quoted(body)}`,
        `env LABEL=fixture sh -c ${quoted(`eval ${quoted(body)}`)}`,
      ]) {
        const result = guard(bash(command, cwd));
        assert.equal(result.code, 2, command);
        assert.match(result.stderr, /Cannot inspect shell command/);
      }
    }
    assert.equal(guard(bash("eval 'printf safe'", cwd)).code, 2, 'eval is refused even for a harmless body');
    assert.equal(guard(bash(`printf '%s' ${quoted('eval git commit; eval git push')}`, cwd)).code, 0);
    assert.equal(existsSync(marker), false);
    assert.equal(git(target, 'rev-parse', 'HEAD').trim(), main);
    assert.equal(git(target, 'diff', '--cached', '--binary'), index);
    assert.equal(git(remote, 'rev-parse', 'main').trim(), main);
  } finally { removeProject(dir); }
});

test('shell policy regressions: exec and time inspect literal Git targets and allow safe targets', () => {
  const { dir, cwd, target, remote, main } = pushFixture();
  try {
    writeFileSync(join(target, '.env'), `OPENAI_API_KEY=${keys.openai}\n`);
    git(target, 'add', '.env');
    const prefixes = ['exec', 'exec --', 'time', 'time -p', 'time --', '/usr/bin/time', '/usr/bin/time -p', 'exec env LABEL=fixture', 'time env LABEL=fixture', 'command -p exec --', 'command -p /usr/bin/time -p'];
    const index = git(target, 'diff', '--cached', '--binary');
    for (const prefix of prefixes) {
      for (const verb of ['commit -m fixture', 'push origin secret-history']) {
        const result = guard(bash(`${prefix} git -C ${quoted(target)} ${verb}`, cwd));
        assert.equal(result.code, 2, `${prefix} ${verb}`);
        assert.match(result.stderr, /\.env would be committed|OpenAI API key/);
        assert.ok(!result.stderr.includes(keys.openai));
      }
    }
    const nested = guard(bash(`env LABEL=fixture sh -c ${quoted(`exec -- git -C ${quoted(target)} commit -m fixture`)}`, cwd));
    assert.equal(nested.code, 2);
    assert.match(nested.stderr, /\.env would be committed/);
    assert.equal(git(target, 'diff', '--cached', '--binary'), index);

    git(target, 'rm', '--cached', '-q', '.env');
    writeFileSync(join(target, 'safe.txt'), 'safe\n');
    git(target, 'add', 'safe.txt');
    writeFileSync(join(cwd, '.env'), 'SECRET=synthetic\n');
    git(cwd, 'add', '.env');
    const safeIndex = git(target, 'diff', '--cached', '--binary');
    for (const prefix of prefixes) {
      assert.equal(guard(bash(`${prefix} git -C ${quoted(target)} commit -m safe`, cwd)).code, 0, prefix);
      assert.equal(guard(bash(`${prefix} git -C ${quoted(target)} push origin main`, cwd)).code, 0, prefix);
    }
    assert.equal(git(target, 'rev-parse', 'HEAD').trim(), main);
    assert.equal(git(target, 'diff', '--cached', '--binary'), safeIndex);
    assert.equal(git(remote, 'rev-parse', 'main').trim(), main);
  } finally { removeProject(dir); }
});

test('shell policy regressions: unsupported exec and time options or redirections refuse inspection', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    const marker = join(dir, 'wrapper-must-not-run');
    for (const verb of ['commit -m fixture', 'push origin main']) {
      const literal = `git -C ${quoted(target)} ${verb}`;
      for (const command of [
        `exec -a fixture ${literal}`,
        `exec -c ${literal}`,
        `exec -l ${literal}`,
        `time --output=${quoted(marker)} ${literal}`,
        `exec >/dev/null ${literal}`,
        `exec &>${quoted(marker)} ${literal}`,
        `time 2>/dev/null ${literal}`,
        `exec -- "$fixture_executable" -C ${quoted(target)} ${verb}`,
        `time -p "$fixture_executable" -C ${quoted(target)} ${verb}`,
      ]) {
        const result = guard(bash(command, cwd));
        assert.equal(result.code, 2, command);
        assert.match(result.stderr, /Cannot inspect shell command/);
      }
    }
    assert.equal(guard(bash(`printf '%s' ${quoted('exec -a fixture git commit; time --output=fixture git push')}`, cwd)).code, 0);
    assert.equal(existsSync(marker), false);
  } finally { removeProject(dir); }
});

test('shell policy regressions: xargs refuses commit and push commands without reading or running input', () => {
  const { dir, cwd, target, remote, main } = pushFixture();
  try {
    const marker = join(dir, 'xargs-must-not-run');
    const index = git(target, 'diff', '--cached', '--binary');
    for (const verb of ['commit -m fixture', 'push origin secret-history']) {
      for (const command of [
        `printf '%s\\n' ${quoted(target)} | xargs -I REPO git -C REPO ${verb}`,
        `printf '%s\\n' ${quoted(target)} | /usr/bin/xargs -I{} git -C '{}' ${verb}`,
        `printf '%s\\n' ${quoted(target)} | command -p xargs -I REPO git -C REPO ${verb}`,
      ]) {
        const result = guard(bash(command, cwd));
        assert.equal(result.code, 2, command);
        assert.match(result.stderr, /Cannot inspect shell command/);
      }
    }
    for (const command of [
      `xargs touch ${quoted(marker)}`,
      `env LABEL=fixture sh -c ${quoted('xargs printf safe')}`,
      `xargs git status < ${quoted(join(dir, 'missing-stdin'))}`,
    ]) {
      const result = guard(bash(command, cwd));
      assert.equal(result.code, 2, command);
      assert.match(result.stderr, /Cannot inspect shell command/);
    }
    assert.equal(guard(bash("printf '%s' 'xargs git commit; xargs git push'", cwd)).code, 0);
    assert.equal(existsSync(marker), false);
    assert.equal(git(target, 'rev-parse', 'HEAD').trim(), main);
    assert.equal(git(target, 'diff', '--cached', '--binary'), index);
    assert.equal(git(remote, 'rev-parse', 'main').trim(), main);
  } finally { removeProject(dir); }
});

test('shell policy regressions: source and dot refuse external scripts without executing them', () => {
  const { dir, cwd, target, remote, main } = pushFixture();
  try {
    const marker = join(dir, 'source-must-not-run');
    const script = join(dir, 'external script.sh');
    const index = git(target, 'diff', '--cached', '--binary');
    for (const verb of ['commit -m fixture', 'push origin secret-history']) {
      writeFileSync(script, `touch ${quoted(marker)}; git -C ${quoted(target)} ${verb}\n`);
      for (const command of [`source ${quoted(script)}`, `. ${quoted(script)}`, `command -p . ${quoted(script)}`, `sh -c ${quoted(`. ${quoted(script)}`)}`]) {
        const result = guard(bash(command, cwd));
        assert.equal(result.code, 2, command);
        assert.match(result.stderr, /Cannot inspect shell command/);
      }
    }
    for (const command of [`source ${quoted(join(dir, 'missing-source'))}`, `. "$fixture_source"`]) {
      const result = guard(bash(command, cwd));
      assert.equal(result.code, 2, command);
      assert.match(result.stderr, /Cannot inspect shell command/);
    }
    assert.equal(guard(bash("printf '%s' 'source fixture.sh; . fixture.sh; git commit'", cwd)).code, 0);
    assert.equal(existsSync(marker), false);
    assert.equal(git(target, 'rev-parse', 'HEAD').trim(), main);
    assert.equal(git(target, 'diff', '--cached', '--binary'), index);
    assert.equal(git(remote, 'rev-parse', 'main').trim(), main);
  } finally { removeProject(dir); }
});

test('shell policy regressions: Git config environment keeps direct and nested writes uncertain', () => {
  const { dir, cwd, target, remote, main } = pushFixture();
  try {
    const config = join(dir, 'alternate gitconfig');
    writeFileSync(config, '[alias]\n fixture = commit\n');
    const index = git(target, 'diff', '--cached', '--binary');
    for (const prefix of [
      `GIT_CONFIG_GLOBAL=${quoted(config)}`,
      `GIT_CONFIG_SYSTEM=${quoted(config)}`,
      'GIT_CONFIG_NOSYSTEM=1',
      'GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.fixture GIT_CONFIG_VALUE_0=commit',
      `GIT_CONFIG_PARAMETERS=${quoted("'alias.fixture=commit'")}`,
      `HOME=${quoted(dir)}`,
      `XDG_CONFIG_HOME=${quoted(dir)}`,
      `env LABEL=fixture GIT_CONFIG_GLOBAL=${quoted(config)}`,
    ]) {
      for (const verb of ['commit -m fixture', 'push origin main']) {
        const result = guard(bash(`${prefix} git -C ${quoted(target)} ${verb}`, cwd));
        assert.equal(result.code, 2, `${prefix} ${verb}`);
        assert.match(result.stderr, /Cannot inspect git (commit|push)/);
      }
      assert.equal(guard(bash(`${prefix} git -C ${quoted(target)} status --short`, cwd)).code, 0, prefix);
    }
    const nested = guard(bash(`env GIT_CONFIG_GLOBAL=${quoted(config)} sh -c ${quoted(`exec -- git -C ${quoted(target)} commit -m fixture`)}`, cwd));
    assert.equal(nested.code, 2);
    assert.match(nested.stderr, /Cannot inspect/);
    assert.equal(git(target, 'rev-parse', 'HEAD').trim(), main);
    assert.equal(git(target, 'diff', '--cached', '--binary'), index);
    assert.equal(git(remote, 'rev-parse', 'main').trim(), main);
  } finally { removeProject(dir); }
});

test('shell policy regressions: persistent Git config assignments cannot hide alias execution', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    const marker = join(dir, 'config-alias-must-not-run');
    const config = join(dir, 'external gitconfig');
    writeFileSync(config, `[alias]\n fixture = commit\n marker = !touch ${quoted(marker)}\n`);
    const head = git(target, 'rev-parse', 'HEAD');
    const index = git(target, 'diff', '--cached', '--binary');
    for (const setup of [
      `GIT_CONFIG_GLOBAL=${quoted(config)}`,
      `export GIT_CONFIG_GLOBAL=${quoted(config)}`,
      `declare GIT_CONFIG_GLOBAL=${quoted(config)}`,
      'export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.fixture GIT_CONFIG_VALUE_0=commit',
      `if true; then export GIT_CONFIG_GLOBAL=${quoted(config)}; fi`,
    ]) {
      for (const verb of ['commit -m fixture', 'push origin main', 'fixture -m fixture', 'marker']) {
        const result = guard(bash(`${setup}; git -C ${quoted(target)} ${verb}`, cwd));
        assert.equal(result.code, 2, `${setup}; ${verb}`);
        assert.match(result.stderr, /Cannot inspect/);
      }
      assert.equal(guard(bash(`${setup}; git -C ${quoted(target)} status --short`, cwd)).code, 0, setup);
    }
    const inlineAlias = guard(bash('GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.fixture GIT_CONFIG_VALUE_0=commit git fixture -m fixture', cwd));
    assert.equal(inlineAlias.code, 2);
    assert.match(inlineAlias.stderr, /Cannot inspect/);
    const markerAlias = `GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.fixture GIT_CONFIG_VALUE_0=${quoted(`!touch ${quoted(marker)}`)}`;
    for (const prefix of [markerAlias, `env ${markerAlias}`]) {
      const result = guard(bash(`${prefix} git -C ${quoted(target)} fixture`, cwd));
      assert.equal(result.code, 2, prefix);
      assert.match(result.stderr, /Cannot inspect/);
      assert.equal(guard(bash(`${prefix} git -C ${quoted(target)} status --short`, cwd)).code, 0);
    }
    const configEnv = `VIBECHECK_ALIAS=commit git -C ${quoted(target)} --config-env=alias.fixture=VIBECHECK_ALIAS`;
    for (const verb of ['commit -m fixture', 'push origin main', 'fixture -m fixture']) {
      const result = guard(bash(`${configEnv} ${verb}`, cwd));
      assert.equal(result.code, 2, verb);
      assert.match(result.stderr, /Cannot inspect/);
    }
    assert.equal(guard(bash(`${configEnv} status --short`, cwd)).code, 0);
    assert.equal(guard(bash("printf '%s' 'export GIT_CONFIG_GLOBAL=fixture; git fixture'", cwd)).code, 0);
    assert.equal(existsSync(marker), false);
    assert.equal(git(target, 'rev-parse', 'HEAD'), head);
    assert.equal(git(target, 'diff', '--cached', '--binary'), index);
  } finally { removeProject(dir); }
});

test('shell policy regressions: exec and time add preserve untracked files for a later commit check', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    writeFileSync(join(target, '.env'), `OPENAI_API_KEY=${keys.openai}\n`);
    const head = git(target, 'rev-parse', 'HEAD');
    for (const prefix of ['exec --', 'time -p', '/usr/bin/time']) {
      const command = `(${prefix} git -C ${quoted(target)} add .) && git -C ${quoted(target)} commit -m fixture`;
      const result = guard(bash(command, cwd));
      assert.equal(result.code, 2, prefix);
      assert.match(result.stderr, /\.env would be committed/);
      assert.ok(!result.stderr.includes(keys.openai));
    }
    assert.equal(git(target, 'rev-parse', 'HEAD'), head);
    assert.equal(git(target, 'diff', '--cached', '--name-only'), '', 'inspection must not stage the fixture');
  } finally { removeProject(dir); }
});

test('shell context regressions: literal redirections do not hide Git commit or push inspection', () => {
  const { dir, cwd, target, remote, main } = pushFixture();
  try {
    const output = join(dir, 'must-not-be-created.log');
    const input = join(dir, 'input.txt');
    writeFileSync(input, 'safe input\n');
    writeFileSync(join(target, '.env'), `OPENAI_API_KEY=${keys.openai}\n`);
    git(target, 'add', '.env');
    const index = git(target, 'diff', '--cached', '--binary');
    for (const verb of ['commit -m fixture', 'push origin secret-history']) {
      for (const command of [
        `>${quoted(output)} git -C ${quoted(target)} ${verb}`,
        `git >${quoted(output)} -C ${quoted(target)} ${verb}`,
        `git -C ${quoted(target)} ${verb} >>${quoted(output)}`,
        `<${quoted(input)} git -C ${quoted(target)} ${verb}`,
        `git -C ${quoted(target)} <${quoted(input)} ${verb}`,
        `git -C ${quoted(target)} ${verb} 2>&1`,
        `git -C ${quoted(target)} ${verb} >${quoted(output)}<${quoted(input)}`,
        `git &>${quoted(output)} -C ${quoted(target)} ${verb}`,
        `git -C ${quoted(target)} ${verb} &>>${quoted(output)}`,
        `git -C ${quoted(target)} ${verb} >|${quoted(output)}`,
        `git -C ${quoted(target)} ${verb} <>${quoted(input)}`,
        `git -C ${quoted(target)} ${verb} <&0`,
      ]) {
        const result = guard(bash(command, cwd));
        assert.equal(result.code, 2, command);
        assert.match(result.stderr, /\.env would be committed|OpenAI API key/);
        assert.doesNotMatch(result.stderr, /Cannot inspect/);
        assert.ok(!result.stderr.includes(keys.openai));
      }
    }
    assert.equal(existsSync(output), false, 'inspection must not apply a redirection');
    assert.equal(git(target, 'rev-parse', 'HEAD').trim(), main);
    assert.equal(git(target, 'diff', '--cached', '--binary'), index);
    assert.equal(git(remote, 'rev-parse', 'main').trim(), main);
  } finally { removeProject(dir); }
});

test('shell context regressions: safe redirection and quoted operator text stay literal', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    const output = join(dir, 'must-not-be-created.log');
    const input = join(dir, 'input.txt');
    writeFileSync(input, 'safe\n');
    writeFileSync(join(target, 'safe.txt'), 'safe\n');
    git(target, 'add', 'safe.txt');
    const head = git(target, 'rev-parse', 'HEAD');
    const index = git(target, 'diff', '--cached', '--binary');
    for (const command of [
      `exec -- git -C ${quoted(target)} commit -m '<quoted > message>'`,
      `time -p git -C ${quoted(target)} commit -m '<quoted > message>'`,
      `>${quoted(output)} git -C ${quoted(target)} commit -m safe`,
      `git >${quoted(output)} -C ${quoted(target)} commit -m safe`,
      `git -C ${quoted(target)} commit -m safe <${quoted(input)} 2>&1`,
      `echo safe >${quoted(output)}`,
      `printf '%s' 'git commit <input >output 2>&1'`,
      `cat <<'TEXT'\ngit -C missing commit >output\nTEXT\n`,
      `cat <<< 'git commit >output'`,
      `printf '%s' "$(printf '%s' '<literal > text')"`,
      `printf -- '-v GIT_DIR fixture'; git -C ${quoted(target)} commit -m safe`,
    ]) assert.equal(guard(bash(command, cwd)).code, 0, command);
    for (const prefix of ['exec --', 'time -p']) {
      const result = guard(bash(`${prefix} git -C ${quoted(target)} commit -m safe >${quoted(output)}`, cwd));
      assert.equal(result.code, 2, prefix);
      assert.match(result.stderr, /Cannot inspect shell command/);
    }
    assert.equal(existsSync(output), false);
    assert.equal(git(target, 'rev-parse', 'HEAD'), head);
    assert.equal(git(target, 'diff', '--cached', '--binary'), index);
  } finally { removeProject(dir); }
});

test('shell context regressions: unsupported redirects refuse while process substitutions stay inspected', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    const output = join(dir, 'must-not-be-created.log');
    const marker = join(dir, 'substitution-must-not-run');
    writeFileSync(join(target, '.env'), `OPENAI_API_KEY=${keys.openai}\n`);
    git(target, 'add', '.env');
    const head = git(target, 'rev-parse', 'HEAD');
    const index = git(target, 'diff', '--cached', '--binary');
    const commit = `git -C ${quoted(target)} commit -m fixture`;
    for (const command of [
      `{fixture_fd}>${quoted(output)} ${commit}`,
      `>${quoted(output)} ${commit} <`,
      `${commit} >`,
    ]) {
      const result = guard(bash(command, cwd));
      assert.equal(result.code, 2, command);
      assert.match(result.stderr, /Cannot inspect shell command/);
    }
    for (const command of [
      `cat <(touch ${quoted(marker)}; ${commit})`,
      `cat >(${commit})`,
      `cat <<< "$(${commit})"`,
      `cat >"$(touch ${quoted(marker)}; ${commit})"`,
      `cat < <(touch ${quoted(marker)}; ${commit})`,
    ]) {
      const result = guard(bash(command, cwd));
      assert.equal(result.code, 2, command);
      assert.match(result.stderr, /\.env would be committed/);
      assert.ok(!result.stderr.includes(keys.openai));
    }
    assert.equal(guard(bash('cat <(printf safe)', cwd)).code, 0);
    assert.equal(existsSync(output), false);
    assert.equal(existsSync(marker), false);
    assert.equal(git(target, 'rev-parse', 'HEAD'), head);
    assert.equal(git(target, 'diff', '--cached', '--binary'), index);
  } finally { removeProject(dir); }
});

test('shell context regressions: printf variable writes retain Git context uncertainty', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    const head = git(cwd, 'rev-parse', 'HEAD');
    const index = git(cwd, 'diff', '--cached', '--binary');
    for (const setup of [
      `export GIT_DIR GIT_WORK_TREE; printf -v GIT_DIR %s ${quoted(join(target, '.git'))}; printf -v GIT_WORK_TREE %s ${quoted(target)}`,
      `printf -v GIT_DIR %s ${quoted(join(target, '.git'))}`,
      `printf -vGIT_DIR %s ${quoted(join(target, '.git'))}`,
      'printf -v GIT_CONFIG_COUNT %s 1',
      'fixture_name=GIT_DIR; printf -v "$fixture_name" %s fixture',
    ]) {
      for (const verb of ['commit -m fixture', 'push origin main', 'fixture -m fixture']) {
        const result = guard(bash(`/bin/bash -c ${quoted(`${setup}; git -C ${quoted(cwd)} ${verb}`)}`, cwd));
        assert.equal(result.code, 2, `${setup}; ${verb}`);
        assert.match(result.stderr, /Cannot inspect/);
      }
      assert.equal(guard(bash(`${setup}; git -C ${quoted(cwd)} status --short`, cwd)).code, 0, setup);
    }
    for (const setup of ['printf -v LABEL %s GIT_DIR', 'printf -vLABEL %s "GIT_CONFIG_COUNT=1"']) {
      assert.equal(guard(bash(`${setup}; git -C ${quoted(cwd)} commit -m safe`, cwd)).code, 0, setup);
    }
    assert.equal(guard(bash("printf '%s' 'printf -v GIT_DIR value; export GIT_DIR'", cwd)).code, 0);
    assert.equal(git(cwd, 'rev-parse', 'HEAD'), head);
    assert.equal(git(cwd, 'diff', '--cached', '--binary'), index);
  } finally { removeProject(dir); }
});

test('shell context regressions: read destinations retain Git configuration and alias uncertainty', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    const head = git(target, 'rev-parse', 'HEAD');
    const index = git(target, 'diff', '--cached', '--binary');
    for (const setup of [
      "export GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0; read -r GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0 <<'CONFIG'\n1 alias.fixture commit\nCONFIG\n",
      `read -r GIT_DIR <<< ${quoted(join(target, '.git'))}`,
      'fixture_name=GIT_CONFIG_COUNT; read -r "$fixture_name" <<< 1',
    ]) {
      for (const verb of ['commit -m fixture', 'push origin main', 'fixture -m fixture']) {
        const body = `${setup}\ngit -C ${quoted(target)} ${verb}`;
        const result = guard(bash(`/bin/bash -c ${quoted(body)}`, cwd));
        assert.equal(result.code, 2, `${setup}; ${verb}`);
        assert.match(result.stderr, /Cannot inspect/);
      }
      assert.equal(guard(bash(`/bin/bash -c ${quoted(`${setup}\ngit -C ${quoted(target)} status --short`)}`, cwd)).code, 0, setup);
    }
    assert.equal(guard(bash(`read -r LABEL <<< GIT_DIR; git -C ${quoted(target)} commit -m safe`, cwd)).code, 0);
    assert.equal(guard(bash("printf '%s' 'read -r GIT_DIR <<< fixture'", cwd)).code, 0);
    assert.equal(git(target, 'rev-parse', 'HEAD'), head);
    assert.equal(git(target, 'diff', '--cached', '--binary'), index);
  } finally { removeProject(dir); }
});

test('shell context regressions: trap and hash indirection refuse without executing callbacks', () => {
  const { dir, cwd, target, remote, main } = pushFixture();
  try {
    const marker = join(dir, 'callback-must-not-run');
    const index = git(target, 'diff', '--cached', '--binary');
    for (const verb of ['commit -m fixture', 'push origin secret-history']) {
      for (const body of [
        `trap ${quoted(`touch ${quoted(marker)}; git -C ${quoted(target)} ${verb}`)} EXIT; :`,
        `hash -p git fixture_git; fixture_git -C ${quoted(target)} ${verb}`,
      ]) {
        const result = guard(bash(`/bin/bash -c ${quoted(body)}`, cwd));
        assert.equal(result.code, 2, body);
        assert.match(result.stderr, /Cannot inspect shell command/);
      }
    }
    for (const command of ["trap 'printf safe' EXIT; :", 'hash -p git fixture_git', 'hash -t fixture_git']) {
      assert.equal(guard(bash(command, cwd)).code, 2, command);
    }
    for (const command of ["printf '%s' 'trap git EXIT; hash -p git fixture_git'", 'command -v git', 'command -v trap', 'command -v hash']) {
      assert.equal(guard(bash(command, cwd)).code, 0, command);
    }
    assert.equal(existsSync(marker), false);
    assert.equal(git(target, 'rev-parse', 'HEAD').trim(), main);
    assert.equal(git(target, 'diff', '--cached', '--binary'), index);
    assert.equal(git(remote, 'rev-parse', 'main').trim(), main);
  } finally { removeProject(dir); }
});

test('shell context regressions: inline Git configuration refuses every push before source selection', () => {
  const { dir, cwd, target, remote, main } = pushFixture();
  try {
    const marker = join(dir, 'config-must-not-run');
    const index = git(target, 'diff', '--cached', '--binary');
    for (const setting of ['remote.origin.push=secret-history:refs/heads/feature', 'color.ui=false', `alias.unused=!touch ${quoted(marker)}`]) {
      for (const options of [`-c ${quoted(setting)}`, `-c${quoted(setting)}`]) {
        const result = guard(bash(`git -C ${quoted(target)} ${options} push origin`, cwd));
        assert.equal(result.code, 2, options);
        assert.match(result.stderr, /Cannot inspect git push/);
      }
    }
    assert.equal(guard(bash(`sh -c ${quoted(`git -C ${quoted(target)} -c color.ui=false push origin main`)}`, cwd)).code, 2);
    assert.equal(guard(bash(`git -C ${quoted(target)} -c color.ui=false commit -m safe`, cwd)).code, 0);
    assert.equal(guard(bash(`git -C ${quoted(target)} -c remote.origin.push=secret-history status --short`, cwd)).code, 0);
    assert.equal(existsSync(marker), false);
    assert.equal(git(target, 'rev-parse', 'HEAD').trim(), main);
    assert.equal(git(target, 'diff', '--cached', '--binary'), index);
    assert.equal(git(remote, 'rev-parse', 'main').trim(), main);
  } finally { removeProject(dir); }
});

test('shell context regressions: unknown Git global options refuse while terminal information stays allowed', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    const execPath = git(target, '--exec-path').trim();
    const head = git(target, 'rev-parse', 'HEAD');
    const index = git(target, 'diff', '--cached', '--binary');
    for (const verb of ['commit -m fixture', 'push origin main', 'status --short']) {
      for (const command of [
        `git --exec-path=${quoted(execPath)} -C ${quoted(target)} ${verb}`,
        `git -C ${quoted(target)} --exec-path=${quoted(execPath)} ${verb}`,
        `git --unknown-global-option -C ${quoted(target)} ${verb}`,
      ]) {
        const result = guard(bash(command, cwd));
        assert.equal(result.code, 2, command);
        assert.match(result.stderr, /Cannot inspect/);
      }
    }
    for (const option of ['--version', '-v', '--help', '--html-path', '--man-path', '--info-path', '--exec-path']) {
      assert.equal(guard(bash(`git ${option}`, cwd)).code, 0, option);
    }
    writeFileSync(join(target, '.env'), `OPENAI_API_KEY=${keys.openai}\n`);
    git(target, 'add', '.env');
    assert.equal(guard(bash(`git --version; git -C ${quoted(target)} commit -m fixture`, cwd)).code, 2);
    git(target, 'reset', '-q', '--', '.env');
    assert.equal(guard(bash('git help -a', cwd)).code, 0);
    assert.equal(git(target, 'rev-parse', 'HEAD'), head);
    assert.equal(git(target, 'diff', '--cached', '--binary'), index);
  } finally { removeProject(dir); }
});

test('additional shell regressions: unquoted globs refuse unresolved execution but quoted patterns stay literal', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    for (const verb of ['commit -m fixture', 'push origin main']) {
      for (const command of [
        `/usr/bin/g[i]t -C ${quoted(target)} ${verb}`,
        `g?t -C ${quoted(target)} ${verb}`,
        `git -C ${quoted(dir)}/target* ${verb}`,
        `git -C ${quoted(dir)}/target? ${verb}`,
        `git -C ${quoted(dir)}/target[ab] ${verb}`,
      ]) {
        const result = guard(bash(command, cwd));
        assert.equal(result.code, 2, command);
        assert.match(result.stderr, /Cannot inspect/);
      }
    }
    const dynamicVerb = guard(bash(`git -C ${quoted(target)} comm?t`, cwd));
    assert.equal(dynamicVerb.code, 2);
    assert.match(dynamicVerb.stderr, /Cannot inspect/);

    const literal = join(dir, 'literal[repo]');
    mkdirSync(literal);
    writeFileSync(join(literal, 'README.md'), 'safe\n');
    git(literal, 'init', '-q'); git(literal, 'add', '.'); git(literal, 'commit', '-qm', 'baseline');
    writeFileSync(join(literal, '.env'), `OPENAI_API_KEY=${keys.openai}\n`);
    git(literal, 'add', '.env');
    const head = git(literal, 'rev-parse', 'HEAD');
    const index = git(literal, 'diff', '--cached', '--binary');
    for (const path of [quoted(literal), `${quoted(dir)}/literal\\[repo\\]`]) {
      const result = guard(bash(`git -C ${path} commit -m '*? [literal message]'`, cwd));
      assert.equal(result.code, 2, path);
      assert.match(result.stderr, /\.env would be committed/);
      assert.doesNotMatch(result.stderr, /Cannot inspect/);
      assert.ok(!result.stderr.includes(keys.openai));
    }
    for (const command of [
      `'g[i]t' status`, `g\\[i\\]t status`, `printf '%s' 'git -C target* comm?t'`,
      '[ -n safe ]', '[[ safe == s* ]]',
      `cat <<'DOC'\ng[i]t -C target* comm?t\nDOC\n`,
    ]) assert.equal(guard(bash(command, cwd)).code, 0, command);
    assert.equal(git(literal, 'rev-parse', 'HEAD'), head);
    assert.equal(git(literal, 'diff', '--cached', '--binary'), index);
  } finally { removeProject(dir); }
});

test('additional shell regressions: alias execution and queries refuse without running definitions', () => {
  const { dir, cwd, target, remote, main } = pushFixture();
  try {
    const marker = join(dir, 'alias-must-not-run');
    const index = git(target, 'diff', '--cached', '--binary');
    for (const verb of ['commit -m fixture', 'push origin secret-history']) {
      const body = `shopt -s expand_aliases\nalias fixture_git=${quoted(`touch ${quoted(marker)}; git -C ${quoted(target)}`)}\nfixture_git ${verb}`;
      const result = guard(bash(`/bin/bash -c ${quoted(body)}`, cwd));
      assert.equal(result.code, 2, verb);
      assert.match(result.stderr, /Cannot inspect shell command/);
    }
    for (const command of ['alias', 'alias -p', 'alias fixture_git', 'alias fixture_printf=printf']) {
      const result = guard(bash(command, cwd));
      assert.equal(result.code, 2, command);
      assert.match(result.stderr, /Cannot inspect shell command/);
    }
    assert.equal(guard(bash('command -v alias', cwd)).code, 0);
    assert.equal(guard(bash("printf '%s' 'alias fixture_git=git; fixture_git commit'", cwd)).code, 0);
    assert.equal(existsSync(marker), false);
    assert.equal(git(target, 'rev-parse', 'HEAD').trim(), main);
    assert.equal(git(target, 'diff', '--cached', '--binary'), index);
    assert.equal(git(remote, 'rev-parse', 'main').trim(), main);
  } finally { removeProject(dir); }
});

for (const modifier of ['noglob', 'nocorrect']) {
  test(`additional shell regressions: ${modifier} keeps literal Git writes visible`, () => {
    const { dir, cwd, target, remote, main } = pushFixture();
    try {
      writeFileSync(join(target, '.env'), `OPENAI_API_KEY=${keys.openai}\n`);
      git(target, 'add', '.env');
      const index = git(target, 'diff', '--cached', '--binary');
      for (const verb of ['commit -m fixture', 'push origin secret-history']) {
        const result = guard(bash(`/bin/zsh -c ${quoted(`${modifier} git -C ${quoted(target)} ${verb}`)}`, cwd));
        assert.equal(result.code, 2, verb);
        assert.match(result.stderr, /\.env would be committed|OpenAI API key/);
        assert.ok(!result.stderr.includes(keys.openai));
      }
      assert.equal(git(target, 'diff', '--cached', '--binary'), index);
      git(target, 'rm', '--cached', '-q', '.env');
      writeFileSync(join(target, 'safe.txt'), 'safe\n');
      git(target, 'add', 'safe.txt');
      const safeIndex = git(target, 'diff', '--cached', '--binary');
      for (const verb of ['commit -m safe', 'push origin main', 'status --short']) {
        assert.equal(guard(bash(`/bin/zsh -c ${quoted(`${modifier} git -C ${quoted(target)} ${verb}`)}`, cwd)).code, 0, verb);
      }
      assert.equal(guard(bash(`printf '%s' ${quoted(`${modifier} git commit`)}`, cwd)).code, 0);
      assert.equal(git(target, 'rev-parse', 'HEAD').trim(), main);
      assert.equal(git(target, 'diff', '--cached', '--binary'), safeIndex);
      assert.equal(git(remote, 'rev-parse', 'main').trim(), main);
    } finally { removeProject(dir); }
  });
}

test('additional shell regressions: repeat inspects literal decimal commands without evaluating counts', () => {
  const { dir, cwd, target, remote, main } = pushFixture();
  try {
    const marker = join(dir, 'repeat-count-must-not-run');
    writeFileSync(join(target, '.env'), `OPENAI_API_KEY=${keys.openai}\n`);
    git(target, 'add', '.env');
    const index = git(target, 'diff', '--cached', '--binary');
    for (const count of ['1', '2', '0', '000']) {
      for (const verb of ['commit -m fixture', 'push origin secret-history']) {
        const body = `repeat ${count} git -C ${quoted(target)} ${verb}`;
        const result = guard(bash(`/bin/zsh -c ${quoted(body)}`, cwd));
        assert.equal(result.code, 2, body);
        assert.match(result.stderr, /\.env would be committed|OpenAI API key/);
        assert.ok(!result.stderr.includes(keys.openai));
      }
    }
    for (const command of [
      `repeat "$COUNT" git -C ${quoted(target)} commit -m fixture`,
      `repeat -1 git -C ${quoted(target)} commit -m fixture`,
      `repeat 1+1 git -C ${quoted(target)} commit -m fixture`,
      `repeat "$(touch ${quoted(marker)}; printf 1)" printf safe`,
      'repeat', 'repeat 2',
    ]) {
      const result = guard(bash(command, cwd));
      assert.equal(result.code, 2, command);
      assert.match(result.stderr, /Cannot inspect shell command/);
    }
    assert.equal(guard(bash('repeat 2 printf safe', cwd)).code, 0);
    assert.equal(guard(bash(`repeat 0 git -C ${quoted(cwd)} commit -m safe`, cwd)).code, 0);
    assert.equal(guard(bash("printf '%s' 'repeat $COUNT git commit'", cwd)).code, 0);
    assert.equal(existsSync(marker), false);
    assert.equal(git(target, 'rev-parse', 'HEAD').trim(), main);
    assert.equal(git(target, 'diff', '--cached', '--binary'), index);
    assert.equal(git(remote, 'rev-parse', 'main').trim(), main);
  } finally { removeProject(dir); }
});

test('additional shell regressions: BASH_ENV and ENV selection refuse implicit shell startup', () => {
  const { dir, cwd, target, remote, main } = pushFixture();
  try {
    const marker = join(dir, 'startup-must-not-run');
    const script = join(dir, 'synthetic startup.sh');
    const index = git(target, 'diff', '--cached', '--binary');
    for (const verb of ['commit -m fixture', 'push origin secret-history']) {
      writeFileSync(script, `touch ${quoted(marker)}; git -C ${quoted(target)} ${verb}\n`);
      for (const [name, shell] of [['BASH_ENV', '/bin/bash'], ['ENV', '/bin/sh']]) {
        for (const command of [
          `${name}=${quoted(script)} ${shell} -c ':'`,
          `env LABEL=fixture ${name}=${quoted(script)} ${shell} -c ':'`,
          `export ${name}=${quoted(script)}; ${shell} -c ':'`,
          `${name}=${quoted(script)}; ${shell} -c ':'`,
          `export ${name}; ${shell} -c ':'`,
          `${name}+=${quoted(script)} ${shell} -c ':'`,
          `fixture_name=${name}; export "$fixture_name"; ${shell} -c ':'`,
          `printf -v ${name} %s ${quoted(script)}; ${shell} -c ':'`,
          `read -r ${name} <<< ${quoted(script)}; ${shell} -c ':'`,
          `fixture_name=${name}; printf -v "$fixture_name" %s fixture; ${shell} -c ':'`,
        ]) {
          const result = guard(bash(command, cwd));
          assert.equal(result.code, 2, command);
          assert.match(result.stderr, /Cannot inspect shell command/);
        }
      }
    }
    assert.equal(guard(bash(`BASH_ENV=${quoted(join(dir, 'missing-startup'))} /bin/bash -c ':'`, cwd)).code, 2);
    assert.equal(guard(bash(`BASH_ENV=${quoted(script)} git -C ${quoted(cwd)} commit -m safe`, cwd)).code, 0);
    assert.equal(guard(bash(`export BASH_ENV; git -C ${quoted(cwd)} status --short`, cwd)).code, 0);
    assert.equal(guard(bash(`STARTUP_LABEL=${quoted(script)} /bin/bash -c ':'`, cwd)).code, 0);
    assert.equal(guard(bash('export STARTUP_LABEL="$LABEL"; /bin/bash -c ":"', cwd)).code, 0);
    assert.equal(guard(bash('env -u BASH_ENV /bin/bash -c ":"', cwd)).code, 0);
    assert.equal(guard(bash("printf '%s' 'BASH_ENV=fixture /bin/bash -c git'", cwd)).code, 0);
    assert.equal(existsSync(marker), false);
    assert.equal(git(target, 'rev-parse', 'HEAD').trim(), main);
    assert.equal(git(target, 'diff', '--cached', '--binary'), index);
    assert.equal(git(remote, 'rev-parse', 'main').trim(), main);
  } finally { removeProject(dir); }
});

test('additional shell regressions: ZDOTDIR declarations and mutations refuse implicit zsh startup', () => {
  const { dir, cwd, target, remote, main } = pushFixture();
  try {
    const dotdir = join(dir, 'synthetic zdotdir');
    mkdirSync(dotdir);
    const marker = join(dir, 'zsh-startup-must-not-run');
    const index = git(target, 'diff', '--cached', '--binary');
    for (const verb of ['commit -m fixture', 'push origin secret-history']) {
      writeFileSync(join(dotdir, '.zshenv'), `touch ${quoted(marker)}; git -C ${quoted(target)} ${verb}\n`);
      for (const command of [
        `ZDOTDIR=${quoted(dotdir)} /bin/zsh -c ':'`,
        `env ZDOTDIR=${quoted(dotdir)} /bin/zsh -c ':'`,
        `export ZDOTDIR=${quoted(dotdir)}; /bin/zsh -c ':'`,
        `declare ZDOTDIR; /bin/zsh -c ':'`,
        `printf -vZDOTDIR %s ${quoted(dotdir)}; /bin/zsh -c ':'`,
        `read -r ZDOTDIR <<< ${quoted(dotdir)}; /bin/zsh -c ':'`,
        'fixture_name=ZDOTDIR; read -r "$fixture_name" <<< fixture; /bin/zsh -c ":"',
      ]) {
        const result = guard(bash(command, cwd));
        assert.equal(result.code, 2, command);
        assert.match(result.stderr, /Cannot inspect shell command/);
      }
    }
    assert.equal(guard(bash(`ZDOTDIR=${quoted(dotdir)} git -C ${quoted(cwd)} commit -m safe`, cwd)).code, 0);
    assert.equal(guard(bash(`export ZDOTDIR; git -C ${quoted(cwd)} status --short`, cwd)).code, 0);
    assert.equal(guard(bash(`cat <<'DOC'\nZDOTDIR=${dotdir} /bin/zsh -c ':'\nDOC\n`, cwd)).code, 0);
    assert.equal(existsSync(marker), false);
    assert.equal(git(target, 'rev-parse', 'HEAD').trim(), main);
    assert.equal(git(target, 'diff', '--cached', '--binary'), index);
    assert.equal(git(remote, 'rev-parse', 'main').trim(), main);
  } finally { removeProject(dir); }
});

test('additional shell regressions: any Git config invocation taints only later writes and alias lookup', () => {
  const { dir, cwd, target, remote, main } = pushFixture();
  try {
    const marker = join(dir, 'config-replay-must-not-run');
    const index = git(target, 'diff', '--cached', '--binary');
    const config = git(target, 'config', '--local', '--list');
    const query = `git -C ${quoted(target)} config --get core.bare`;
    for (const first of [
      query,
      `git -C ${quoted(target)} config remote.origin.push secret-history:refs/heads/feature`,
      `sh -c ${quoted(query)}`,
    ]) {
      for (const later of [
        `git -C ${quoted(target)} commit -m fixture`,
        `git -C ${quoted(target)} push origin`,
        `git -C ${quoted(target)} fixture -m fixture`,
        `git -C ${quoted(cwd)} commit -m fixture`,
      ]) {
        const result = guard(bash(`${first}; ${later}`, cwd));
        assert.equal(result.code, 2, `${first}; ${later}`);
        assert.match(result.stderr, /Cannot inspect/);
      }
      assert.equal(guard(bash(`${first}; git -C ${quoted(target)} status --short`, cwd)).code, 0, first);
    }
    const substitution = guard(bash(`git -C ${quoted(cwd)} commit -m "$(${query})"`, cwd));
    assert.equal(substitution.code, 2);
    assert.match(substitution.stderr, /Cannot inspect/);
    const callback = guard(bash(`git -C ${quoted(target)} config alias.marker ${quoted(`!touch ${quoted(marker)}`)}; git -C ${quoted(target)} marker`, cwd));
    assert.equal(callback.code, 2);
    assert.match(callback.stderr, /Cannot inspect/);
    assert.equal(guard(bash(query, cwd)).code, 0);
    assert.equal(guard(bash(`git -C ${quoted(cwd)} commit -m safe; ${query}`, cwd)).code, 0, 'a later config query must not taint an earlier write');
    assert.equal(guard(bash(`printf '%s' ${quoted(query + '; git push')}`, cwd)).code, 0);
    assert.equal(existsSync(marker), false);
    assert.equal(git(target, 'rev-parse', 'HEAD').trim(), main);
    assert.equal(git(target, 'diff', '--cached', '--binary'), index);
    assert.equal(git(target, 'config', '--local', '--list'), config, 'inspection must not replay configuration commands');
    assert.equal(git(remote, 'rev-parse', 'main').trim(), main);
  } finally { removeProject(dir); }
});
