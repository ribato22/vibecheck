// vibecheck-ignore-file
// Release hygiene: skills load in every agent, their links resolve, and all version numbers agree.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { spawnSync } from 'node:child_process';
import { ROOT, SCAN } from './helpers.mjs';

const read = (rel) => readFileSync(join(ROOT, rel), 'utf8');
const skills = readdirSync(join(ROOT, 'skills'), { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name);

function frontmatter(text) {
  const m = /^---\n([\s\S]*?)\n---\n/.exec(text);
  assert.ok(m, 'SKILL.md must start with YAML frontmatter on line 1');
  return Object.fromEntries(m[1].split('\n').map((l) => /^([\w-]+):\s*(.*)$/.exec(l)).filter(Boolean).map((x) => [x[1], x[2]]));
}

function markdownFiles(dir) {
  return readdirSync(join(ROOT, dir), { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? markdownFiles(`${dir}/${e.name}`) : e.name.endsWith('.md') ? [`${dir}/${e.name}`] : []);
}

test('every skill has Agent Skills-compliant frontmatter', () => {
  assert.deepEqual(skills.sort(), ['check', 'fix', 'unstuck']);
  for (const name of skills) {
    const fm = frontmatter(read(`skills/${name}/SKILL.md`));
    assert.equal(fm.name, name, `${name}: name must match its folder`);
    assert.match(fm.name, /^[a-z0-9]+(?:-[a-z0-9]+)*$/);
    assert.ok(fm.description && fm.description.length <= 1024, `${name}: description is required and at most 1024 characters`);
  }
});

test('every relative link in the skills points to a file that exists', () => {
  const missing = [];
  for (const file of markdownFiles('skills')) {
    for (const m of read(file).matchAll(/\]\(([^)\s#]+)(?:#[^)]*)?\)/g)) {
      if (/^[a-z]+:/i.test(m[1])) continue;
      if (!existsSync(join(ROOT, dirname(file), m[1]))) missing.push(`${file} -> ${m[1]}`);
    }
  }
  assert.deepEqual(missing, []);
});

test('the hook points at a script that exists', () => {
  const hooks = JSON.parse(read('hooks/hooks.json'));
  const commands = Object.values(hooks.hooks).flat().flatMap((h) => h.hooks.map((x) => x.command));
  assert.ok(commands.length > 0);
  for (const cmd of commands) {
    const path = /\$\{CLAUDE_PLUGIN_ROOT\}\/([^"\s]+)/.exec(cmd)?.[1];
    assert.ok(path && existsSync(join(ROOT, path)), `missing hook script in: ${cmd}`);
  }
});

test('plugin, package, scanner and changelog versions agree', () => {
  const plugin = JSON.parse(read('.claude-plugin/plugin.json')).version;
  const pkg = JSON.parse(read('package.json')).version;
  const scanner = spawnSync(process.execPath, [SCAN, '--version'], { encoding: 'utf8' }).stdout.trim();
  const changelog = /^## (\d+\.\d+\.\d+)/m.exec(read('CHANGELOG.md'))?.[1];
  assert.deepEqual({ pkg, scanner, changelog }, { pkg: plugin, scanner: plugin, changelog: plugin });
});
