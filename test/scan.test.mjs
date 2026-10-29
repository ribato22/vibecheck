// vibecheck-ignore-file
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { keys, makeProject, removeProject, git, scan, ids, SCAN } from './helpers.mjs';

const vulnerableNextApp = () => ({
  'package.json': JSON.stringify({
    name: 'my-saas',
    dependencies: { next: '15.3.0', react: '19.0.0', '@supabase/supabase-js': '2.45.0', stripe: '17.0.0', openai: '5.0.0' },
  }),
  'package-lock.json': '{}',
  '.gitignore': 'node_modules\n',
  '.env': `NEXT_PUBLIC_SUPABASE_URL=https://abc.supabase.co\nNEXT_PUBLIC_OPENAI_API_KEY=${keys.openai}\nSUPABASE_SERVICE_ROLE_KEY=${keys.serviceRole}\n`,
  'src/lib/ai.ts': `import OpenAI from 'openai';\nexport const openai = new OpenAI({\n  apiKey: "${keys.openai}",\n  dangerouslyAllowBrowser: true,\n});\n`,
  'src/components/AdminPanel.tsx': `'use client';\nimport { createClient } from '@supabase/supabase-js';\nconst supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!);\nexport default function AdminPanel({ html }) { return <div dangerouslySetInnerHTML={{ __html: html }} />; }\n`,
  'src/app/api/webhook/route.ts': `import Stripe from 'stripe';\nexport async function POST(req: Request) {\n  const event = await req.json();\n  if (event.type === 'checkout.session.completed') { /* grant premium */ }\n  return Response.json({ ok: true });\n}\n`,
  'src/app/api/checkout/route.ts': `import Stripe from 'stripe';\nconst stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);\nexport async function POST(req: Request) {\n  const body = await req.json();\n  return stripe.checkout.sessions.create({ line_items: [{ price_data: { currency: 'usd', unit_amount: body.price, product_data: { name: 'Pro' } }, quantity: 1 }], mode: 'payment' });\n}\n`,
  'src/app/api/profile/route.ts': `import { db } from '@/lib/db';\nexport async function PATCH(req: Request) {\n  return Response.json(await db.user.update({ data: await req.json() }));\n}\nexport async function GET(req: Request) {\n  const email = new URL(req.url).searchParams.get('email');\n  return Response.json(await db.query(\`SELECT * FROM users WHERE email = '\${email}'\`));\n}\n`,
  'src/lib/stripe.ts': `export const stripeKey = "${keys.stripeLive}";\n`,
  'scripts/seed.ts': `const url = "${keys.dbUrl}";\n`,
  'supabase/migrations/20260101000000_init.sql': [
    'create table public.profiles (id uuid primary key references auth.users, is_admin boolean default false);',
    'alter table public.profiles enable row level security;',
    'create policy "anyone can update profiles" on public.profiles for update to authenticated using (true);',
    'create policy "admins" on public.profiles for select using ((auth.jwt() -> \'user_metadata\' ->> \'role\') = \'admin\');',
    '-- messages are private!',
    'create table if not exists messages (id bigint generated always as identity primary key, body text, user_id uuid);',
    'create view public.leaderboard as select id from public.profiles;',
    'create or replace function public.add_credits(n int) returns void language sql security definer as $$ update profiles set is_admin = true $$;',
  ].join('\n'),
});

test('flags the classic vibe-coding leaks in a vulnerable Next.js + Supabase + Stripe app', () => {
  const dir = makeProject(vulnerableNextApp());
  try {
    git(dir, 'init', '-q');
    git(dir, 'add', 'package.json');
    git(dir, 'commit', '-qm', 'init');
    const report = scan(dir);
    const found = ids(report);
    for (const id of [
      'VC-KEY-OPENAI', 'VC-KEY-STRIPE', 'VC-KEY-SUPABASE-SERVICE', 'VC-KEY-DB-URL', 'VC-ENV-PUBLIC-SECRET',
      'VC-ENV-GITIGNORE', 'VC-AI-BROWSER', 'VC-DB-SERVICE-KEY-CLIENT', 'VC-DB-NO-RLS', 'VC-DB-POLICY-OPEN',
      'VC-DB-POLICY-USER-METADATA', 'VC-DB-VIEW-BYPASS', 'VC-DB-SECURITY-DEFINER', 'VC-PAY-WEBHOOK-UNVERIFIED',
      'VC-PAY-CLIENT-PRICE', 'VC-INJ-MASS-ASSIGN', 'VC-INJ-SQL', 'VC-XSS-HTML', 'VC-MONEY-NO-RATE-LIMIT',
      'VC-LAUNCH-PRIVACY',
    ]) assert.ok(found.has(id), `expected ${id}; got ${[...found].join(', ')}`);

    assert.deepEqual(report.stack, ['nextjs', 'openai', 'react', 'stripe', 'supabase']);
    const noRls = report.findings.filter((f) => f.id === 'VC-DB-NO-RLS');
    assert.deepEqual(noRls.map((f) => f.title), ['Table "messages" has no Row Level Security in your migrations']);
    assert.equal(noRls[0].line, 6, 'line numbers survive blanked SQL comments');
    const pub = report.findings.find((f) => f.evidence === 'NEXT_PUBLIC_OPENAI_API_KEY');
    assert.equal(pub.severity, 'critical');
  } finally {
    removeProject(dir);
  }
});

test('never prints a secret in full', () => {
  const dir = makeProject(vulnerableNextApp());
  try {
    const raw = JSON.stringify(scan(dir));
    for (const k of [keys.openai, keys.stripeLive, keys.serviceRole, keys.dbUrl]) assert.ok(!raw.includes(k), 'secret leaked into output');
    assert.ok(raw.includes(keys.openai.slice(0, 4) + '…' + keys.openai.slice(-4)));
  } finally {
    removeProject(dir);
  }
});

test('catches .env files committed now or in the past', () => {
  const dir = makeProject({ 'index.js': 'console.log(process.env.X)\n', '.env.production': `OPENAI_API_KEY=${keys.openai}\n`, '.env.old': 'A=1\n' });
  try {
    git(dir, 'init', '-q');
    git(dir, 'add', '-A');
    git(dir, 'commit', '-qm', 'oops');
    git(dir, 'rm', '-q', '--cached', '.env.old');
    git(dir, 'commit', '-qm', 'remove');
    const report = scan(dir);
    const titles = report.findings.map((f) => f.title);
    assert.ok(titles.includes('.env.production is committed to git'));
    assert.ok(titles.includes('.env.old was committed in the past (still in git history)'));
  } finally {
    removeProject(dir);
  }
});

test('flags open Firebase rules, Flask debug and Python SQL injection outside git', () => {
  const dir = makeProject({
    'requirements.txt': 'flask==3.0.0\nopenai>=1.0\n',
    'app.py': 'from flask import Flask\napp = Flask(__name__)\ndef q(cur, name):\n    cur.execute(f"SELECT * FROM users WHERE name = \'{name}\'")\napp.run(debug=True)\n',
    'firestore.rules': "rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /{document=**} {\n      allow read, write: if request.time < timestamp.date(2026, 1, 1);\n    }\n    match /posts/{id} {\n      allow read, write: if true;\n    }\n    match /users/{uid} {\n      allow read: if request.auth != null && request.auth.uid == uid;\n    }\n  }\n}\n",
    'database.rules.json': '{ "rules": { ".read": true, ".write": "auth != null" } }',
  });
  try {
    const report = scan(dir);
    const found = ids(report);
    for (const id of ['VC-DB-FIREBASE-OPEN', 'VC-CFG-DEBUG', 'VC-INJ-SQL', 'VC-REL-NO-GIT', 'VC-MONEY-NO-RATE-LIMIT']) {
      assert.ok(found.has(id), `expected ${id}`);
    }
    const fb = report.findings.filter((f) => f.id === 'VC-DB-FIREBASE-OPEN').map((f) => `${f.file}:${f.line}:${f.severity}`);
    assert.deepEqual(fb.sort(), [
      'database.rules.json:1:high', 'database.rules.json:1:high',
      'firestore.rules:5:critical', 'firestore.rules:8:critical',
    ].sort());
    assert.ok(!fb.some((f) => f.startsWith('firestore.rules:11')), 'owner-scoped rule must not be flagged');
  } finally {
    removeProject(dir);
  }
});

test('a well-secured app comes back clean', () => {
  const dir = makeProject({
    'package.json': JSON.stringify({
      dependencies: { next: '15.3.0', react: '19.0.0', '@supabase/supabase-js': '2.45.0', '@supabase/ssr': '0.5.0', openai: '5.0.0',
        '@upstash/ratelimit': '2.0.0', '@sentry/nextjs': '9.0.0', '@vercel/analytics': '1.0.0' },
    }),
    'package-lock.json': '{}',
    '.gitignore': 'node_modules\n.env*\n!.env.example\n',
    '.env': `OPENAI_API_KEY=${keys.openai}\nNEXT_PUBLIC_SUPABASE_ANON_KEY=${keys.anon}\nNEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_${'x'.repeat(4)}\n`,
    '.env.example': 'OPENAI_API_KEY=\nNEXT_PUBLIC_SUPABASE_URL=\nNEXT_PUBLIC_SUPABASE_ANON_KEY=\n',
    'src/app/layout.tsx': "export const metadata = { title: 'App', openGraph: { images: ['/og.png'] } };\n",
    'src/app/privacy/page.tsx': 'export default () => <p>Privacy</p>;\n',
    'src/app/terms/page.tsx': 'export default () => <p>Terms</p>;\n',
    'src/app/not-found.tsx': 'export default () => <p>404</p>;\n',
    'src/app/robots.ts': 'export default () => ({ rules: { userAgent: "*" } });\n',
    'src/app/sitemap.ts': 'export default () => [];\n',
    'src/app/favicon.ico': '',
    'src/app/api/chat/route.ts': "import 'server-only';\nimport OpenAI from 'openai';\nconst openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });\n",
    'src/components/Chat.tsx': "'use client';\nimport { createBrowserClient } from '@supabase/ssr';\nexport const sb = createBrowserClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);\n",
    'supabase/migrations/001.sql': [
      'create table public.todos (id bigint primary key, user_id uuid not null, task text);',
      'alter table public.todos enable row level security;',
      'create policy "own todos" on public.todos for all to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);',
      'create view public.todo_counts with (security_invoker = true) as select user_id, count(*) from public.todos group by 1;',
      'create function public.handle_new_user() returns trigger language plpgsql security definer set search_path = \'\' as $$ begin return new; end $$;',
    ].join('\n'),
  });
  try {
    git(dir, 'init', '-q');
    git(dir, 'add', '-A');
    git(dir, 'commit', '-qm', 'init');
    const report = scan(dir);
    assert.deepEqual(report.findings, [], JSON.stringify(report.findings, null, 2));
    assert.equal(scan(dir, '--fail-on', 'low', '--strict').exitCode, 0);
  } finally {
    removeProject(dir);
  }
});

test('--fail-on exits non-zero only for high-confidence findings unless --strict', () => {
  const dir = makeProject({ 'a.js': `const k = "${keys.anthropic}";\n`, 'b.js': 'el.innerHTML = x;\n' });
  try {
    assert.equal(scan(dir, '--fail-on', 'critical').exitCode, 1);
    const xssOnly = makeProject({ 'b.js': 'el.innerHTML = x;\n' });
    try {
      git(xssOnly, 'init', '-q');
      assert.equal(scan(xssOnly, '--fail-on', 'medium').exitCode, 0);
      assert.equal(scan(xssOnly, '--fail-on', 'medium', '--strict').exitCode, 1);
    } finally {
      removeProject(xssOnly);
    }
  } finally {
    removeProject(dir);
  }
});

test('placeholders and ignore markers are not reported', () => {
  const dir = makeProject({
    'README.md': `Set OPENAI_API_KEY=${'sk-' + 'proj-your-key-here'} and STRIPE_SECRET_KEY=${'sk_' + 'live_' + 'x'.repeat(24)}\n`,
    'config.js': `const legacy = "${keys.aws}"; // vibecheck-ignore\n`,
    'docker.js': 'const url = "postgres://postgres:postgres@localhost:5432/app";\n',
  });
  try {
    assert.deepEqual(scan(dir).findings.filter((f) => f.category === 'secrets'), []);
  } finally {
    removeProject(dir);
  }
});

test('Playwright $eval / $$eval are not flagged as eval()', () => {
  const dir = makeProject({
    'src/report.js': 'export const go = (page) => page.$$eval("tr", (rows) => rows.length);\nexport const one = (page) => page.$eval("#a", (e) => e.textContent);\n',
    'src/danger.js': 'export const run = (input) => eval(input);\n',
  });
  try {
    const evals = scan(dir).findings.filter((f) => f.id === 'VC-INJ-EVAL').map((f) => f.file);
    assert.deepEqual(evals, ['src/danger.js']);
  } finally {
    removeProject(dir);
  }
});

test('backup, archive and QA folders skip code patterns but still get secret scans', () => {
  const dir = makeProject({
    'package.json': JSON.stringify({ dependencies: { '@supabase/supabase-js': '2.45.0' } }),
    'package-lock.json': '{}',
    'public/app.js': 'el.innerHTML = userInput;\n',
    'handoff/backup-pra-A0-L/app.js': `el.innerHTML = userInput;\nconst key = "${keys.openai}";\n`,
    'handoff/qa-scripts/browser/qa-batch3.js': 'el.innerHTML = x;\n',
    'old/server.py': 'cur.execute(f"SELECT * FROM t WHERE id = {i}")\n',
    'src/app.backup.js': 'eval(x);\n',
    'archive/2025/schema.sql': 'create table public.legacy (id int);\n',
  });
  try {
    const report = scan(dir);
    const code = report.findings.filter((f) => f.category !== 'secrets' && f.file).map((f) => `${f.id} ${f.file}`);
    assert.deepEqual(code, ['VC-XSS-HTML public/app.js'], 'only shipping code is pattern-checked');
    assert.ok(report.findings.some((f) => f.id === 'VC-KEY-OPENAI' && f.file === 'handoff/backup-pra-A0-L/app.js'), 'secrets in backups are still found');
    const note = report.notes.find((n) => n.startsWith('Code patterns not checked in 5 '));
    assert.ok(note, JSON.stringify(report.notes));
    assert.match(note, /handoff\/backup-pra-A0-L\//);
  } finally {
    removeProject(dir);
  }
});

test('test files skip the generic secret guess but not real key formats', () => {
  const dir = makeProject({
    'test/contract.test.mjs': `const headers = { apiKey: "raha8f3kQ9z2x8765" };\nconst real = "${keys.anthropic}";\n`,
    'src/config.js': 'export const apiKey = "raha8f3kQ9z2x8765";\n',
  });
  try {
    const found = scan(dir).findings.filter((f) => f.category === 'secrets').map((f) => `${f.id} ${f.file}`);
    assert.deepEqual(found.sort(), ['VC-KEY-ANTHROPIC test/contract.test.mjs', 'VC-KEY-GENERIC src/config.js'].sort());
  } finally {
    removeProject(dir);
  }
});

test('agents get every match in --json; the text view caps per rule and says where the rest are', () => {
  const xss = (n) => 'el.innerHTML = x;\n'.repeat(n);
  const dir = makeProject({ 'a.js': xss(30), 'b.js': xss(5) });
  try {
    const report = scan(dir);
    assert.equal(report.findings.filter((f) => f.id === 'VC-XSS-HTML').length, 35);
    assert.deepEqual(report.hidden, {});

    const text = spawnSync(process.execPath, [SCAN, dir], { encoding: 'utf8' }).stdout;
    assert.match(text, /VC-XSS-HTML: 10 more matches not shown, in a\.js \(5\), b\.js \(5\)\./);
  } finally {
    removeProject(dir);
  }
});

test('--json still has a ceiling and reports the overflow per file', () => {
  const dir = makeProject({ 'big.js': 'el.innerHTML = x;\n'.repeat(210) });
  try {
    const report = scan(dir);
    assert.equal(report.findings.filter((f) => f.id === 'VC-XSS-HTML').length, 200);
    assert.deepEqual(report.hidden, { 'VC-XSS-HTML': { 'big.js': 10 } });
    assert.ok(report.notes.some((n) => n.startsWith('VC-XSS-HTML: 10 more matches not shown, in big.js (10).')));
  } finally {
    removeProject(dir);
  }
});

test('files in skipped folders that app code imports are checked like app code', () => {
  const dir = makeProject({
    'api-v1.mjs': "import { parseYaml } from './handoff/qa-scripts/openapi/yaml.mjs';\nexport const load = (s) => parseYaml(s);\n",
    'handoff/qa-scripts/openapi/yaml.mjs': "import { lex } from './lexer.mjs';\nexport const parseYaml = (s) => lex(s);\n",
    'handoff/qa-scripts/openapi/lexer.mjs': 'export const lex = (src) => eval(src);\n',
    'handoff/qa-scripts/browser/qa-batch3.js': 'eval(y);\n',
    'src/app.ts': "import { h } from '../old/legacy.js';\nexport default h;\n",
    'old/legacy.ts': 'export const h = (el, x) => { el.innerHTML = x; };\n',
    'src/cjs.js': "const helper = require('./backup-v1/helper');\nmodule.exports = helper;\n",
    'src/backup-v1/helper/index.js': "const { execSync } = require('child_process');\nmodule.exports = (dir) => execSync(`ls ${dir}`);\n",
  });
  try {
    const report = scan(dir);
    const code = report.findings.filter((f) => f.file && f.category !== 'secrets').map((f) => `${f.id} ${f.file}`).sort();
    assert.deepEqual(code, [
      'VC-INJ-CMD src/backup-v1/helper/index.js',
      'VC-INJ-EVAL handoff/qa-scripts/openapi/lexer.mjs',
      'VC-XSS-HTML old/legacy.ts',
    ], 'imported helpers (even transitively) are checked; the unused QA script is not');
    assert.ok(report.notes.includes('4 files in test/backup/QA folders are imported by app code, so they were checked like app code: handoff/qa-scripts/openapi/lexer.mjs, handoff/qa-scripts/openapi/yaml.mjs, old/legacy.ts, src/backup-v1/helper/index.js.'), JSON.stringify(report.notes));
    assert.ok(report.notes.some((n) => n.startsWith('Code patterns not checked in 1 test/backup/QA files') && n.includes('handoff/qa-scripts/browser/')));
  } finally {
    removeProject(dir);
  }
});
