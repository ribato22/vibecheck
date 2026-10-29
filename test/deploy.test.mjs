// vibecheck-ignore-file
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { keys, makeProject, removeProject, git, preflight, ids } from './helpers.mjs';

const brokenVercelApp = () => ({
  'package.json': JSON.stringify({
    name: 'shop', engines: { node: '18.x' }, scripts: { build: 'next build' },
    dependencies: { next: '15.3.0', react: '19.0.0', '@prisma/client': '6.0.0', stripe: '17.0.0', '@supabase/supabase-js': '2.45.0', 'better-sqlite3': '11.0.0' },
    devDependencies: { prisma: '6.0.0', typescript: '5.6.0', '@types/node': '22.0.0' },
  }),
  'package-lock.json': '{}',
  'pnpm-lock.yaml': '',
  '.nvmrc': '20\n',
  '.gitignore': 'node_modules\n.env*\n!.env.example\n',
  '.env.local': `OPENAI_API_KEY=${keys.openai}\nSTRIPE_SECRET_KEY=${keys.stripeLive}\nDATABASE_URL=${keys.dbUrl}\n`,
  '.env.example': 'OPENAI_API_KEY=\n',
  'tsconfig.json': '{ "compilerOptions": { "paths": { "@/*": ["./src/*"] } } }',
  'prisma/schema.prisma': 'datasource db {\n  provider = "postgresql"\n  url = env("DATABASE_URL")\n}\n',
  'prisma/migrations/0001_init/migration.sql': 'create table "User" (id text primary key);\n',
  'src/components/Button.tsx': 'export default function Button() { return null; }\n',
  'src/app/page.tsx': "import Button from '../components/button';\nimport dayjs from 'dayjs';\nimport { z } from 'zod';\nimport type { Metadata } from 'next';\nimport fs from 'node:fs';\nimport { db } from '@/lib/db';\nconst label = 'delete from', other = 1;\nexport default function Page() { return Button; }\n",
  'src/lib/api.ts': "export const API = 'http://localhost:4000/api';\nexport const base = process.env.NEXT_PUBLIC_API_URL || \"http://localhost:3000\";\nconsole.log('ready on http://localhost:3000');\n",
  'src/lib/cache.ts': "import Database from 'better-sqlite3';\nexport const cache = new Database('cache.db');\n",
  'src/lib/db.ts': "import { PrismaClient } from '@prisma/client';\nexport const db = new PrismaClient({ datasourceUrl: process.env.DATABASE_URL ?? '' });\n",
  'src/app/api/chat/route.ts': "import Stripe from 'stripe';\nimport fs from 'node:fs';\nconst stripe = new Stripe(process.env.STRIPE_SECRET_KEY);\nconst key = process.env.OPENAI_API_KEY;\nconst beta = process.env.ENABLE_BETA === 'true';\nexport async function POST() { fs.writeFileSync('./uploads/log.txt', 'x'); return Response.json({}); }\n",
});

test('finds what breaks a Next.js app on Vercel', () => {
  const dir = makeProject(brokenVercelApp());
  try {
    git(dir, 'init', '-q');
    writeFileSync(join(dir, 'host-env.txt'), [
      'Vercel CLI 39.0.0',
      '> Environment Variables found for acme/shop',
      ' name              value        environments   created',
      ' OPENAI_API_KEY    Encrypted    Production     3d ago',
    ].join('\n'));
    const r = preflight(dir, '--host', 'vercel', '--host-env', join(dir, 'host-env.txt'));
    const found = ids(r);
    for (const id of ['VC-DEPLOY-IMPORT-CASE', 'VC-DEPLOY-DEP-UNDECLARED', 'VC-DEPLOY-ENV-NOT-ON-HOST', 'VC-DEPLOY-ENV-UNDOCUMENTED',
      'VC-DEPLOY-LOCALHOST', 'VC-DEPLOY-NODE-MISMATCH', 'VC-DEPLOY-MULTI-LOCKFILE', 'VC-DEPLOY-PRISMA-GENERATE',
      'VC-DEPLOY-SQLITE-SERVERLESS', 'VC-DEPLOY-FS-WRITE']) assert.ok(found.has(id), `expected ${id}; got ${[...found].join(', ')}`);

    const titles = (id) => r.findings.filter((f) => f.id === id).map((f) => `${f.severity}: ${f.title}`).sort();
    assert.deepEqual(titles('VC-DEPLOY-DEP-UNDECLARED'), ['high: "dayjs" is imported but not in package.json', 'high: "zod" is imported but not in package.json'],
      'node:, type-only, @/ aliases and the word "from" inside a string are not packages');
    assert.deepEqual(titles('VC-DEPLOY-ENV-NOT-ON-HOST'), [
      'high: STRIPE_SECRET_KEY is used but not set on the host',
      'low: DATABASE_URL is used but not set on the host (the code has a fallback)',
      'low: ENABLE_BETA is used but not set on the host (the code has a fallback)',
      'low: NEXT_PUBLIC_API_URL is used but not set on the host (the code has a fallback)',
    ], 'a fallback (?? / || / === flag) makes a missing var low; the localhost fallback itself is flagged separately');
    assert.deepEqual(titles('VC-DEPLOY-LOCALHOST'), ['high: Hardcoded http://localhost:4000/api', 'medium: Falls back to http://localhost:3000 when an env var is missing'],
      'console.log URLs are ignored');
    assert.equal(r.findings.find((f) => f.id === 'VC-DEPLOY-IMPORT-CASE').title, 'Import "../components/button" only matches "src/components/Button.tsx" if letter case is ignored');
    assert.equal(r.findings.find((f) => f.id === 'VC-DEPLOY-PRISMA-GENERATE').severity, 'high');

    assert.deepEqual(r.hosts, ['vercel']);
    assert.deepEqual(r.env.set_on_host, ['DATABASE_URL', 'OPENAI_API_KEY', 'STRIPE_SECRET_KEY']);
    assert.ok(r.reminders.some((x) => x.includes('prisma migrate deploy')));
    assert.ok(r.reminders.some((x) => x.startsWith('Supabase → Authentication')));
    assert.ok(r.reminders.some((x) => x.startsWith('Stripe: create a live-mode webhook')));
    assert.ok(r.reminders.some((x) => x.startsWith('Public env vars')));

    const raw = JSON.stringify(r);
    for (const k of [keys.openai, keys.stripeLive, keys.dbUrl]) assert.ok(!raw.includes(k), 'env values must never be read into the output');
  } finally {
    removeProject(dir);
  }
});

test('finds port, bind and start-command problems for container hosts', () => {
  const dir = makeProject({
    'package.json': JSON.stringify({ name: 'api', engines: { node: '>=20' }, dependencies: { express: '4.19.0' } }),
    'package-lock.json': '{}',
    'railway.json': '{ "build": {} }',
    'server.js': "const express = require('express');\nconst app = express();\napp.listen(3000, '127.0.0.1');\n",
  });
  try {
    const r = preflight(dir);
    assert.deepEqual(r.hosts, ['railway']);
    const got = r.findings.map((f) => `${f.id} ${f.severity}`).sort();
    assert.deepEqual(got, ['VC-DEPLOY-BIND-LOCALHOST high', 'VC-DEPLOY-NO-START medium', 'VC-DEPLOY-PORT-HARDCODED high']);
  } finally {
    removeProject(dir);
  }
});

test('a deploy-ready app comes back clean', () => {
  const dir = makeProject({
    'package.json': JSON.stringify({
      name: 'ok', engines: { node: '22.x' }, scripts: { build: 'prisma generate && next build', start: 'next start' },
      dependencies: { next: '15.3.0', react: '19.0.0', '@prisma/client': '6.0.0', dayjs: '1.11.0' }, devDependencies: { prisma: '6.0.0' },
    }),
    'package-lock.json': '{}',
    '.nvmrc': '22\n',
    'vercel.json': '{}',
    '.env.example': 'DATABASE_URL=\nNEXT_PUBLIC_API_URL=\n',
    'src/components/Button.tsx': 'export default function Button() { return null; }\n',
    'src/app/page.tsx': "import Button from '../components/Button';\nimport dayjs from 'dayjs';\nexport default function Page() { return Button; }\n",
    'src/lib/api.ts': 'export const base = process.env.NEXT_PUBLIC_API_URL;\nexport const db = process.env.DATABASE_URL;\n',
    'host-env.txt': 'DATABASE_URL\nNEXT_PUBLIC_API_URL\n',
  });
  try {
    const r = preflight(dir, '--host-env', join(dir, 'host-env.txt'));
    assert.deepEqual(r.findings, [], JSON.stringify(r.findings, null, 2));
    assert.deepEqual(r.notes, []);
  } finally {
    removeProject(dir);
  }
});

test('a SQLite package that is listed but never imported is not flagged', () => {
  const dir = makeProject({
    'package.json': JSON.stringify({ name: 'x', engines: { node: '22.x' }, dependencies: { next: '15.3.0', 'better-sqlite3': '11.0.0' } }),
    'package-lock.json': '{}',
    'src/app/page.tsx': 'export default function Page() { return null; }\n',
  });
  try {
    assert.ok(!ids(preflight(dir, '--host', 'vercel')).has('VC-DEPLOY-SQLITE-SERVERLESS'));
  } finally {
    removeProject(dir);
  }
});

const localDemo = () => ({
  'package.json': JSON.stringify({ name: 'demo', engines: { node: '>=22.15' }, scripts: { start: 'node server.mjs' } }),
  'server.mjs': [
    "import http from 'node:http';",
    "import { scale } from './demo-data.mjs';",
    "const ALLOWED = new Set(['http://localhost:4173', 'http://127.0.0.1:4173']);",
    'const server = http.createServer((req, res) => res.end(String(scale)));',
    "server.listen(Number(process.env.PORT) || 4173, '127.0.0.1');",
  ].join('\n'),
  'demo-data.mjs': "const parseScale = (v) => Number(v) || 1;\nexport const scale = parseScale(process.env.DEMO_SCALE);\n",
  'handoff/blueprint/live-study/probe.js': "await fetch('http://localhost:4173/api/health');\n",
  'handoff/blueprint/live-study/scripts/analyze.mjs': 'const terms = process.env.MASK_TERMS;\nconst stage = process.env.STAGE;\n',
});

test('--host local: localhost, loopback binds and fixed ports are correct, not findings', () => {
  const dir = makeProject(localDemo());
  try {
    const r = preflight(dir, '--host', 'local');
    assert.deepEqual(r.hosts, ['local']);
    assert.deepEqual(r.findings.map((f) => `${f.id} ${f.severity} ${f.evidence}`), ['VC-DEPLOY-ENV-UNDOCUMENTED low DEMO_SCALE']);
    assert.ok(r.notes.some((n) => n.startsWith('Target is local')));
    assert.ok(!r.notes.some((n) => n.startsWith('No hosting config') || n.startsWith('Env vars were not compared')));
    assert.ok(r.reminders.at(-1).startsWith('Restart the running app'));
  } finally {
    removeProject(dir);
  }
});

test('dev tooling folders are not production requirements, whatever the host', () => {
  const dir = makeProject(localDemo());
  try {
    const r = preflight(dir);
    assert.deepEqual(r.env.used.map((u) => u.name), ['DEMO_SCALE'], 'MASK_TERMS and STAGE live in scripts/');
    const localhost = r.findings.filter((f) => f.id === 'VC-DEPLOY-LOCALHOST').map((f) => f.file).sort();
    assert.deepEqual(localhost, ['handoff/blueprint/live-study/probe.js', 'server.mjs', 'server.mjs'], 'without --host local, localhost is still flagged outside tooling folders');
  } finally {
    removeProject(dir);
  }
});
