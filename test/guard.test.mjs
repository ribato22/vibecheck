// vibecheck-ignore-file
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, symlinkSync, writeFileSync } from 'node:fs';
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

test('repeated git -C follows physical directories through symlinks', () => {
  const { dir, cwd, target } = gitFixture();
  try {
    mkdirSync(join(target, 'child'));
    symlinkSync(join(target, 'child'), join(cwd, 'link'), process.platform === 'win32' ? 'junction' : 'dir');
    writeFileSync(join(target, '.env'), 'SECRET=synthetic\n');
    git(target, 'add', '.env');
    assert.equal(guard(bash(`git -C ${quoted(join(cwd, 'link'))} -C .. commit -m fixture`, cwd)).code, 2);
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
