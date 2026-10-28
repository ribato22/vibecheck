// vibecheck-ignore-file
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { keys, makeProject, removeProject, git, guard } from './helpers.mjs';

const write = (file_path, content) => ({ tool_name: 'Write', tool_input: { file_path, content }, cwd: '/tmp' });
const bash = (command, cwd) => ({ tool_name: 'Bash', tool_input: { command }, cwd });

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
