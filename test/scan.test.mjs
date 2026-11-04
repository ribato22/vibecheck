// vibecheck-ignore-file
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { keys, rand, makeProject, removeProject, git, scan, ids, SCAN } from './helpers.mjs';

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

test('public Supabase values are not generic secrets under apiKey assignments', () => {
  const dir = makeProject({
    'src/clients.js': `const apiKey = "${keys.publishable}";\nconst client = { apiKey: "${keys.anon}" };\n`,
  });
  try {
    assert.deepEqual(scan(dir).findings.filter((f) => f.category === 'secrets'), []);
  } finally {
    removeProject(dir);
  }
});

test('unrelated and malformed public-looking values remain generic secrets to verify', () => {
  const [header, , signature] = keys.anon.split('.');
  const jwt = (claims) => [header, Buffer.from(claims).toString('base64url'), signature].join('.');
  const values = [
    jwt(JSON.stringify({ iss: 'other-app', role: 'anon' })),
    jwt(JSON.stringify({ iss: 'supabase', role: 'authenticated' })),
    jwt('{"iss":"supabase","role":"anon"'),
    ['eyJmalformedheader123', keys.anon.split('.')[1], signature].join('.'),
    [Buffer.from(JSON.stringify({ typ: 'JWT' })).toString('base64url'), keys.anon.split('.')[1], signature].join('.'),
    [Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url'), keys.anon.split('.')[1], signature].join('.'),
    ...[16, 17, 42].map((length) => [header, keys.anon.split('.')[1], signature.slice(0, length)].join('.')),
    [header, keys.anon.split('.')[1], signature + 'A'].join('.'),
    keys.anon + '.extra',
    keys.publishable + '!',
  ];
  const dir = makeProject({ 'src/keys.js': values.map((value) => `const apiKey = "${value}";`).join('\n') });
  try {
    const found = scan(dir).findings.filter((f) => f.category === 'secrets');
    assert.deepEqual(found.map((f) => [f.id, f.line]), values.map((_, i) => ['VC-KEY-GENERIC', i + 1]));
    assert.ok(found.every((f) => f.confidence === 'verify'));
  } finally {
    removeProject(dir);
  }
});

test('skipping a public Supabase key does not hide generic secrets later on the same line', () => {
  const secret = rand(32, 23);
  const dir = makeProject({ 'src/keys.js': `const apiKey = "${keys.publishable}"; const accessToken = "${secret}";\n` });
  try {
    const found = scan(dir).findings.filter((f) => f.category === 'secrets');
    assert.equal(found.length, 1);
    assert.equal(found[0].id, 'VC-KEY-GENERIC');
    assert.equal(found[0].evidence, `${secret.slice(0, 4)}…${secret.slice(-4)}`);
    assert.ok(!JSON.stringify(found).includes(secret), 'the actual secret must be masked');
  } finally {
    removeProject(dir);
  }
});

test('Supabase secret values remain critical and masked under public-looking variable names', () => {
  const dir = makeProject({
    'src/keys.js': `const SUPABASE_PUBLISHABLE_KEY = "${keys.supabaseSecret}";\nconst SUPABASE_ANON_KEY = "${keys.serviceRole}";\nconst apiKey = "${keys.openai}";\n`,
  });
  try {
    const found = scan(dir).findings.filter((f) => f.category === 'secrets');
    assert.deepEqual(found.map((f) => f.id).sort(), ['VC-KEY-SUPABASE-SECRET', 'VC-KEY-SUPABASE-SERVICE', 'VC-KEY-OPENAI'].sort());
    assert.ok(found.every((f) => f.severity === 'critical' && f.confidence === 'high'));
    for (const value of [keys.supabaseSecret, keys.serviceRole, keys.openai]) assert.ok(!JSON.stringify(found).includes(value));
    assert.equal(scan(dir, '--fail-on', 'critical').exitCode, 1);
  } finally {
    removeProject(dir);
  }
});

test('RLS-disabled migrations retain critical leads but require exposure and grants verification', () => {
  const dir = makeProject({
    'package.json': JSON.stringify({ dependencies: { '@supabase/supabase-js': '2.45.0' } }),
    'supabase/migrations/001.sql': [
      'create schema private;',
      'create table private.payroll (id int);',
      'alter table private.payroll disable row level security;',
      'create table public.internal_notes (id int);',
      'revoke all on public.internal_notes from public, anon, authenticated;',
      'alter table public.internal_notes disable row level security;',
      'create table public.messages (id int);',
      'grant select, update on public.messages to anon, authenticated;',
      'alter table public.messages disable row level security;',
    ].join('\n'),
  });
  try {
    const found = scan(dir).findings.filter((f) => f.id === 'VC-DB-RLS-DISABLED');
    assert.equal(found.length, 3, 'private, revoked and granted cases must all remain visible for review');
    assert.deepEqual(found.map((f) => f.line).sort((a, b) => a - b), [3, 6, 9]);
    assert.ok(found.every((f) => f.severity === 'critical'));
    assert.ok(found.every((f) => f.confidence === 'verify'), 'migrations alone do not confirm the deployed API exposure and effective grants');
  } finally {
    removeProject(dir);
  }
});

test('RLS leads do not fail default CI before verification but still fail strict CI', () => {
  const dir = makeProject({
    'package.json': JSON.stringify({ dependencies: { '@supabase/supabase-js': '2.45.0' } }),
    'supabase/migrations/001.sql': 'create table public.notes (id int);\nalter table public.notes disable row level security;\n',
  });
  try {
    assert.equal(scan(dir, '--fail-on', 'critical').exitCode, 0);
    assert.equal(scan(dir, '--fail-on', 'critical', '--strict').exitCode, 1);
  } finally {
    removeProject(dir);
  }
});

const privateNotesSql = 'create table public.notes (id int, body text);\nalter table public.notes enable row level security;\n';

test('Supabase views stop warning after ALTER VIEW enables invoker mode', () => {
  const dir = makeProject({
    'supabase/migrations/001.sql': privateNotesSql + 'create view public.note_view as select * from public.notes;\n',
    'supabase/migrations/002.sql': 'alter view public.note_view set (security_invoker = true);\n',
  });
  try {
    assert.deepEqual(scan(dir).findings.filter((f) => f.id === 'VC-DB-VIEW-BYPASS'), []);
  } finally {
    removeProject(dir);
  }
});

test('Supabase views warn after ALTER VIEW disables invoker mode', () => {
  const dir = makeProject({
    'supabase/migrations/001.sql': privateNotesSql + 'create view public.note_view with (security_invoker = true) as select * from public.notes;\n',
    'supabase/migrations/002.sql': 'alter view public.note_view set (security_invoker = false);\n',
  });
  try {
    const found = scan(dir).findings.filter((f) => f.id === 'VC-DB-VIEW-BYPASS');
    assert.deepEqual(found.map((f) => [f.file, f.line, f.confidence]), [['supabase/migrations/002.sql', 1, 'verify']]);
    assert.match(found[0].title, /note_view/);
  } finally {
    removeProject(dir);
  }
});

test('Supabase views warn when ALTER VIEW resets invoker mode', () => {
  const dir = makeProject({
    'supabase/migrations/001.sql': privateNotesSql + 'create view public.note_view with (security_invoker = true) as select * from public.notes;\n',
    'supabase/migrations/002.sql': 'alter view public.note_view reset (security_invoker);\n',
  });
  try {
    const found = scan(dir).findings.filter((f) => f.id === 'VC-DB-VIEW-BYPASS');
    assert.deepEqual(found.map((f) => [f.file, f.line, f.confidence]), [['supabase/migrations/002.sql', 1, 'verify']]);
  } finally {
    removeProject(dir);
  }
});

test('Supabase views preserve invoker mode when CREATE OR REPLACE omits options', () => {
  const dir = makeProject({
    'supabase/migrations/001.sql': privateNotesSql + 'create view public.note_view with (security_invoker = true) as select * from public.notes;\n',
    'supabase/migrations/002.sql': 'create or replace view public.note_view as select * from public.notes where id > 0;\n',
  });
  try {
    assert.deepEqual(scan(dir).findings.filter((f) => f.id === 'VC-DB-VIEW-BYPASS'), []);
  } finally {
    removeProject(dir);
  }
});

test('Supabase views follow explicit invoker options in CREATE OR REPLACE', () => {
  const dir = makeProject({
    'supabase/migrations/001.sql': privateNotesSql + 'create view public.note_view as select * from public.notes;\n',
    'supabase/migrations/002.sql': 'create or replace view public.note_view with (security_invoker = true) as select * from public.notes;\n',
  });
  try {
    assert.deepEqual(scan(dir).findings.filter((f) => f.id === 'VC-DB-VIEW-BYPASS'), []);
  } finally {
    removeProject(dir);
  }
});

test('Supabase functions stop warning after ALTER FUNCTION switches to invoker', () => {
  const dir = makeProject({
    'supabase/migrations/001.sql': privateNotesSql + 'create function public.read_notes() returns setof public.notes language sql security definer set search_path = \'\' as $$ select * from public.notes $$;\n',
    'supabase/migrations/002.sql': 'alter function public.read_notes() security invoker;\n',
  });
  try {
    assert.deepEqual(scan(dir).findings.filter((f) => f.id === 'VC-DB-SECURITY-DEFINER'), []);
  } finally {
    removeProject(dir);
  }
});

test('Supabase functions warn after ALTER FUNCTION switches to definer', () => {
  const dir = makeProject({
    'supabase/migrations/001.sql': privateNotesSql + 'create function public.read_notes() returns setof public.notes language sql security invoker set search_path = \'\' as $$ select * from public.notes $$;\n',
    'supabase/migrations/002.sql': 'alter function public.read_notes() security definer;\n',
  });
  try {
    const found = scan(dir).findings.filter((f) => f.id === 'VC-DB-SECURITY-DEFINER');
    assert.deepEqual(found.map((f) => [f.file, f.line, f.confidence]), [['supabase/migrations/002.sql', 1, 'verify']]);
    assert.match(found[0].title, /read_notes/);
  } finally {
    removeProject(dir);
  }
});

test('Supabase functions default to invoker when CREATE OR REPLACE omits SECURITY', () => {
  const dir = makeProject({
    'supabase/migrations/001.sql': privateNotesSql + 'create function public.read_notes() returns setof public.notes language sql security definer as $$ select * from public.notes $$;\n',
    'supabase/migrations/002.sql': 'create or replace function public.read_notes() returns setof public.notes language sql as $$ select * from public.notes $$;\n',
  });
  try {
    assert.deepEqual(scan(dir).findings.filter((f) => f.id === 'VC-DB-SECURITY-DEFINER'), []);
  } finally {
    removeProject(dir);
  }
});

test('Supabase function overloads keep separate declared security modes', () => {
  const dir = makeProject({
    'supabase/migrations/001.sql': [
      'create function public.read_notes(note_id integer) returns integer language sql security definer as $$ select note_id $$;',
      'create function public.read_notes(note_key text) returns text language sql security definer as $$ select note_key $$;',
    ].join('\n'),
    'supabase/migrations/002.sql': 'alter function public.read_notes(integer) security invoker;\n',
  });
  try {
    const found = scan(dir).findings.filter((f) => f.id === 'VC-DB-SECURITY-DEFINER');
    assert.deepEqual(found.map((f) => [f.file, f.line, f.confidence]), [['supabase/migrations/001.sql', 2, 'verify']]);
    assert.match(found[0].title, /read_notes/);
  } finally {
    removeProject(dir);
  }
});

test('Supabase function bodies cannot change top-level view or function security state', () => {
  const dir = makeProject({
    'supabase/migrations/001.sql': privateNotesSql + [
      'create function public.read_notes() returns integer language sql security invoker as $$ select 1 $$;',
      'create function public.describe_sql() returns text language plpgsql security invoker as $body$',
      'begin',
      '  perform \'alter function public.read_notes() security definer;\';',
      '  return $example$create view public.fake_view as select * from public.notes;$example$;',
      'end;',
      '$body$;',
    ].join('\n'),
  });
  try {
    assert.deepEqual(scan(dir).findings.filter((f) => ['VC-DB-VIEW-BYPASS', 'VC-DB-SECURITY-DEFINER'].includes(f.id)), []);
  } finally {
    removeProject(dir);
  }
});

test('Supabase same-file security transitions keep source order and final ALTER locations', () => {
  const dir = makeProject({
    'supabase/migrations/001.sql': privateNotesSql + [
      'create view public.note_view with (security_invoker = true) as select * from public.notes;',
      'alter view public.note_view set (security_invoker = false);',
      'alter view public.note_view set (security_invoker = true);',
      'alter view public.note_view set (security_invoker = false);',
      'create function public.read_notes() returns integer language sql security invoker as $$ select 1 $$;',
      'alter function public.read_notes() security definer;',
      'alter function public.read_notes() security invoker;',
      'alter function public.read_notes() security definer;',
    ].join('\n'),
  });
  try {
    const found = scan(dir).findings;
    const views = found.filter((f) => f.id === 'VC-DB-VIEW-BYPASS');
    const functions = found.filter((f) => f.id === 'VC-DB-SECURITY-DEFINER');
    assert.deepEqual(views.map((f) => [f.file, f.line, f.confidence]), [['supabase/migrations/001.sql', 6, 'verify']]);
    assert.deepEqual(functions.map((f) => [f.file, f.line, f.confidence]), [['supabase/migrations/001.sql', 10, 'verify']]);
  } finally {
    removeProject(dir);
  }
});

test('Supabase views reset omitted options on a fresh CREATE after DROP', () => {
  const dir = makeProject({ 'supabase/migrations/001.sql': [
    'create view public.note_view with (security_invoker = true) as select 1;',
    'drop view public.note_view;',
    'create view public.note_view as select 1;',
  ].join('\n') });
  try {
    const found = scan(dir).findings.filter((f) => f.id === 'VC-DB-VIEW-BYPASS');
    assert.deepEqual(found.map((f) => [f.line, f.confidence]), [[3, 'verify']]);
  } finally { removeProject(dir); }
});

test('Supabase views recognize quoted and numeric invoker booleans', () => {
  const dir = makeProject({ 'supabase/migrations/001.sql': [
    'create view public.quoted_value with (security_invoker = true) as select 1;',
    "alter view public.quoted_value set (security_invoker = 'false');",
    'create view public.numeric_value with (security_invoker = true) as select 1;',
    'alter view public.numeric_value set (security_invoker = 0);',
    'create view public.enabled_value as select 1;',
    "alter view public.enabled_value set (security_invoker = 'true');",
  ].join('\n') });
  try {
    const found = scan(dir).findings.filter((f) => f.id === 'VC-DB-VIEW-BYPASS');
    assert.deepEqual(found.map((f) => [f.line, f.confidence]), [[2, 'verify'], [4, 'verify']]);
  } finally { removeProject(dir); }
});

test('Supabase function overloads preserve quoted input type identity', () => {
  const dir = makeProject({ 'supabase/migrations/001.sql': [
    'create type public."CaseType" as enum (\'a\');',
    'create type public."casetype" as enum (\'a\');',
    'create function public.read_notes(value public."CaseType") returns integer language sql security definer as $$ select 1 $$;',
    'create function public.read_notes(value public."casetype") returns integer language sql security definer as $$ select 1 $$;',
    'alter function public.read_notes(public."casetype") security invoker;',
  ].join('\n') });
  try {
    const found = scan(dir).findings.filter((f) => f.id === 'VC-DB-SECURITY-DEFINER');
    assert.deepEqual(found.map((f) => [f.line, f.confidence]), [[3, 'verify']]);
  } finally { removeProject(dir); }
});

test('Supabase functions ignore quoted result-column names when reading security mode', () => {
  const dir = makeProject({ 'supabase/migrations/001.sql':
    'create function public.note_values() returns table ("security invoker" text) language sql security definer as $$ select \'x\' $$;' });
  try {
    const found = scan(dir).findings.filter((f) => f.id === 'VC-DB-SECURITY-DEFINER');
    assert.deepEqual(found.map((f) => [f.line, f.confidence]), [[1, 'verify']]);
  } finally { removeProject(dir); }
});

test('Supabase functions remain visible after nested SQL block comments', () => {
  const dir = makeProject({ 'supabase/migrations/001.sql': [
    '/* outer comment',
    ' /* nested comment */',
    ' still outer */',
    'create function public.read_label() returns integer language sql security definer as $$ select 1 $$;',
  ].join('\n') });
  try {
    const found = scan(dir).findings.filter((f) => f.id === 'VC-DB-SECURITY-DEFINER');
    assert.deepEqual(found.map((f) => [f.line, f.confidence]), [[4, 'verify']]);
  } finally { removeProject(dir); }
});

test('Supabase view and definer leads stay conditional despite revokes and a non-admin owner', () => {
  const dir = makeProject({
    'supabase/migrations/001.sql': privateNotesSql + [
      'create role app_reader nologin nosuperuser nobypassrls;',
      'grant usage on schema public to app_reader;',
      'grant select on public.notes to app_reader;',
      'create view public.note_view as select * from public.notes;',
      'revoke all on public.note_view from public, anon, authenticated;',
      'create function public.read_notes() returns setof public.notes language sql security definer set search_path = \'\' as $$ select * from public.notes $$;',
      'alter function public.read_notes() owner to app_reader;',
      'revoke all on function public.read_notes() from public, anon, authenticated;',
    ].join('\n'),
  });
  try {
    const found = scan(dir).findings.filter((f) => ['VC-DB-VIEW-BYPASS', 'VC-DB-SECURITY-DEFINER'].includes(f.id));
    assert.equal(found.length, 2, 'review leads remain without claiming effective exposure or elevated owner privileges');
    assert.ok(found.every((f) => f.severity === 'medium' && f.confidence === 'verify'));
    const view = found.find((f) => f.id === 'VC-DB-VIEW-BYPASS');
    const fn = found.find((f) => f.id === 'VC-DB-SECURITY-DEFINER');
    assert.doesNotMatch(view.title, /ignores (?:the )?RLS/i);
    assert.doesNotMatch(fn.title, /callable from (?:the )?API/i);
    assert.doesNotMatch(fn.fix, /runs with admin rights|and skips RLS/i);
    for (const finding of found) {
      const message = `${finding.title} ${finding.fix}`;
      assert.match(message, /\b(?:verify|confirm|check)\b/i);
      assert.match(message, /\b(?:expos\w*|API)\b/i);
      assert.match(message, /\b(?:grant\w*|privilege\w*)\b/i);
      assert.match(message, /\bowner(?:'s)?\b/i);
    }
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

const schemaLeadIds = ['VC-DB-NO-RLS', 'VC-DB-VIEW-BYPASS', 'VC-DB-SECURITY-DEFINER'];

test('Supabase configured schemas include mixed-quote multiline API entries', () => {
  const dir = makeProject({
    'supabase/config.toml': '[api]\nschemas = [\n  \'api\', # application API\n  "reporting", # read models\n]\n',
    'supabase/migrations/001.sql': [
      'create table api.notes (id int);',
      'create view api.note_view as select * from api.notes;',
      'create function api.read_notes() returns setof api.notes language sql security definer as $$ select * from api.notes $$;',
      'create table reporting.events (id int);',
    ].join('\n'),
  });
  try {
    const found = scan(dir).findings.filter((f) => schemaLeadIds.includes(f.id)).sort((a, b) => a.line - b.line);
    assert.deepEqual(found.map((f) => [f.id, f.line, f.confidence]), [
      ['VC-DB-NO-RLS', 1, 'verify'],
      ['VC-DB-VIEW-BYPASS', 2, 'verify'],
      ['VC-DB-SECURITY-DEFINER', 3, 'verify'],
      ['VC-DB-NO-RLS', 4, 'verify'],
    ]);
  } finally {
    removeProject(dir);
  }
});

test('Supabase configured schemas keep table RLS state and fixes qualified', () => {
  const dir = makeProject({
    'supabase/config.toml': '[api]\nschemas = ["api"]\n',
    'supabase/migrations/001.sql': [
      'create table api.notes (id int);',
      'create table private.notes (id int);',
      'alter table private.notes enable row level security;',
    ].join('\n'),
  });
  try {
    const found = scan(dir).findings.filter((f) => f.id === 'VC-DB-NO-RLS');
    assert.deepEqual(found.map((f) => [f.file, f.line, f.confidence]), [['supabase/migrations/001.sql', 1, 'verify']]);
    assert.match(found[0].fix, /alter\s+table\s+(?:"api"|api)\.(?:"notes"|notes)\s+enable\s+row\s+level\s+security/i);
  } finally {
    removeProject(dir);
  }
});

test('Supabase configured schemas preserve custom view and function ALTER modes', () => {
  const dir = makeProject({
    'supabase/config.toml': '[api]\nschemas = ["api"]\n',
    'supabase/migrations/001.sql': [
      'create view api.safe_view as select 1 as value;',
      'create view api.review_view with (security_invoker = true) as select 1 as value;',
      'create function api.safe_fn() returns integer language sql security definer as $$ select 1 $$;',
      'create function api.review_fn() returns integer language sql security invoker as $$ select 1 $$;',
    ].join('\n'),
    'supabase/migrations/002.sql': [
      'alter view api.safe_view set (security_invoker = true);',
      'alter view api.review_view set (security_invoker = false);',
      'alter function api.safe_fn() security invoker;',
      'alter function api.review_fn() security definer;',
    ].join('\n'),
  });
  try {
    const found = scan(dir).findings.filter((f) => schemaLeadIds.includes(f.id)).sort((a, b) => a.line - b.line);
    assert.deepEqual(found.map((f) => [f.id, f.file, f.line, f.confidence]), [
      ['VC-DB-VIEW-BYPASS', 'supabase/migrations/002.sql', 2, 'verify'],
      ['VC-DB-SECURITY-DEFINER', 'supabase/migrations/002.sql', 4, 'verify'],
    ]);
  } finally {
    removeProject(dir);
  }
});

test('Supabase configured schemas retain public and ignore unrelated config fields', () => {
  const dir = makeProject({
    'supabase/config.toml': '[api]\nschemas = ["api"]\nextra_search_path = ["extra"]\n[other]\nschemas = ["private"]\n',
    'supabase/migrations/001.sql': ['public', 'private', 'extra'].flatMap((schema) => [
      `create table ${schema}.notes (id int);`,
      `create view ${schema}.note_view as select * from ${schema}.notes;`,
      `create function ${schema}.read_notes() returns setof ${schema}.notes language sql security definer as $$ select * from ${schema}.notes $$;`,
    ]).join('\n'),
  });
  try {
    const found = scan(dir).findings.filter((f) => schemaLeadIds.includes(f.id)).sort((a, b) => a.line - b.line);
    assert.deepEqual(found.map((f) => [f.id, f.line, f.confidence]), [
      ['VC-DB-NO-RLS', 1, 'verify'],
      ['VC-DB-VIEW-BYPASS', 2, 'verify'],
      ['VC-DB-SECURITY-DEFINER', 3, 'verify'],
    ]);
  } finally {
    removeProject(dir);
  }
});

test('Supabase configured schemas report manual coverage for malformed or dynamic arrays', () => {
  for (const config of ['[api]\nschemas = ["api"\n', '[api]\nschemas = env("API_SCHEMAS")\n']) {
    const dir = makeProject({
      'supabase/config.toml': config,
      'supabase/migrations/001.sql': 'create table public.notes (id int);\ncreate table api.notes (id int);\n',
    });
    try {
      const report = scan(dir);
      assert.equal(report.exitCode, 0);
      assert.deepEqual(report.findings.filter((f) => f.id === 'VC-DB-NO-RLS').map((f) => f.line), [1]);
      assert.ok(report.notes.some((note) => /config\.toml/.test(note) && /manual|unverified/i.test(note)), JSON.stringify(report.notes));
    } finally {
      removeProject(dir);
    }
  }
});

test('Supabase configured schemas use the closest project config and root fallback', () => {
  const dir = makeProject({
    'supabase/config.toml': '[api]\nschemas = ["root_api"]\n',
    'supabase/migrations/001.sql': 'create table root_api.root_notes (id int);\ncreate table a_api.root_hidden (id int);\n',
    'apps/a/supabase/config.toml': '[api]\nschemas = ["a_api"]\n',
    'apps/a/supabase/migrations/001.sql': 'create table a_api.a_notes (id int);\ncreate table root_api.a_hidden (id int);\n',
    'apps/b/supabase/migrations/001.sql': 'create table root_api.b_notes (id int);\ncreate table a_api.b_hidden (id int);\n',
  });
  try {
    const found = scan(dir).findings.filter((f) => f.id === 'VC-DB-NO-RLS').sort((a, b) => a.file.localeCompare(b.file));
    assert.deepEqual(found.map((f) => [f.file, f.line, f.confidence]), [
      ['apps/a/supabase/migrations/001.sql', 1, 'verify'],
      ['apps/b/supabase/migrations/001.sql', 1, 'verify'],
      ['supabase/migrations/001.sql', 1, 'verify'],
    ]);
  } finally {
    removeProject(dir);
  }
});

test('Supabase configured schemas preserve quoted schema case', () => {
  const dir = makeProject({
    'supabase/config.toml': '[api]\nschemas = ["CamelCase", "Api.Space", "select"]\n',
    'supabase/migrations/001.sql': [
      'create table "CamelCase".notes (id int);',
      'create table camelcase.hidden_notes (id int);',
      'create view "CamelCase".note_view as select * from "CamelCase".notes;',
      'create view camelcase.hidden_view as select 1 as value;',
      'create function "CamelCase".read_notes() returns integer language sql security definer as $$ select 1 $$;',
      'create function camelcase.hidden_fn() returns integer language sql security definer as $$ select 1 $$;',
      'create table "Api.Space".dot_notes (id int);',
      'create view "Api.Space".dot_view as select * from "Api.Space".dot_notes;',
      'create function "Api.Space".read_dot_notes() returns integer language sql security definer as $$ select 1 $$;',
      'create table "select".reserved_notes (id int);',
    ].join('\n'),
  });
  try {
    const found = scan(dir).findings.filter((f) => schemaLeadIds.includes(f.id)).sort((a, b) => a.line - b.line);
    assert.deepEqual(found.map((f) => [f.id, f.line, f.confidence]), [
      ['VC-DB-NO-RLS', 1, 'verify'],
      ['VC-DB-VIEW-BYPASS', 3, 'verify'],
      ['VC-DB-SECURITY-DEFINER', 5, 'verify'],
      ['VC-DB-NO-RLS', 7, 'verify'],
      ['VC-DB-VIEW-BYPASS', 8, 'verify'],
      ['VC-DB-SECURITY-DEFINER', 9, 'verify'],
      ['VC-DB-NO-RLS', 10, 'verify'],
    ]);
    assert.match(found[0].fix, /"CamelCase"\.(?:"notes"|notes)/);
    assert.match(found[1].title, /CamelCase.*note_view/);
    assert.match(found[2].title, /CamelCase.*read_notes/);
    assert.match(found[3].fix, /"Api\.Space"\.(?:"dot_notes"|dot_notes)/);
    assert.match(found[4].title, /Api\.Space.*dot_view/);
    assert.match(found[5].title, /Api\.Space.*read_dot_notes/);
    assert.match(found[6].fix, /"select"\.(?:"reserved_notes"|reserved_notes)/);
  } finally {
    removeProject(dir);
  }
});

test('Supabase configured schemas accept root dotted api.schemas without other sections', () => {
  const dir = makeProject({
    'supabase/config.toml': 'api.schemas = [\'api\']\n[other]\nschemas = ["private"]\n',
    'supabase/migrations/001.sql': 'create table api.notes (id int);\ncreate table private.notes (id int);\n',
  });
  try {
    const found = scan(dir).findings.filter((f) => f.id === 'VC-DB-NO-RLS');
    assert.deepEqual(found.map((f) => [f.line, f.confidence]), [[1, 'verify']]);
  } finally {
    removeProject(dir);
  }
});

test('Supabase configured schemas reject long malformed arrays within a bounded time', () => {
  const dir = makeProject({
    'supabase/config.toml': '[api]\nschemas = ["api"' + ' '.repeat(300000) + '\n',
    'supabase/migrations/001.sql': 'create table public.notes (id int);\n',
  });
  try {
    const result = spawnSync(process.execPath, [SCAN, dir, '--json'], {
      encoding: 'utf8', timeout: 5000, killSignal: 'SIGKILL',
    });
    assert.equal(result.error?.code, undefined, 'malformed config must finish within the generous scanner timeout');
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.ok(report.notes.some((note) => /config\.toml/.test(note) && /manual|unverified/i.test(note)), JSON.stringify(report.notes));
  } finally {
    removeProject(dir);
  }
});

test('Supabase configured schemas stop API scope at array-table headers', () => {
  const dir = makeProject({
    'supabase/config.toml': '[api]\nenabled = true\n[[other]]\nschemas = ["private"]\n',
    'supabase/migrations/001.sql': 'create table public.notes (id int);\ncreate table private.notes (id int);\n',
  });
  try {
    const found = scan(dir).findings.filter((f) => f.id === 'VC-DB-NO-RLS');
    assert.deepEqual(found.map((f) => [f.line, f.confidence]), [[1, 'verify']]);
  } finally {
    removeProject(dir);
  }
});

test('Supabase configured schemas accept quoted and spaced root dotted keys', () => {
  const observed = [];
  for (const key of ['"api" . "schemas"', 'api . schemas', "'api' . 'schemas'"]) {
    const dir = makeProject({
      'supabase/config.toml': key + ' = ["api"]\n[other]\nschemas = ["private"]\n',
      'supabase/migrations/001.sql': 'create table api.notes (id int);\ncreate table private.notes (id int);\n',
    });
    try {
      observed.push(scan(dir).findings.filter((f) => f.id === 'VC-DB-NO-RLS').map((f) => [f.line, f.confidence]));
    } finally {
      removeProject(dir);
    }
  }
  assert.deepEqual(observed, [[[1, 'verify']], [[1, 'verify']], [[1, 'verify']]]);
});
