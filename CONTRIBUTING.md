# Contributing to vibecheck

Thanks for making AI-built apps safer. The best contributions are small and come with a test.

## Layout

```
.claude-plugin/          plugin + marketplace manifests (Claude Code)
skills/check/            the audit skill
  SKILL.md               workflow, scoring, report format
  scripts/rules.mjs      every regex rule (secrets, env names, code patterns)
  scripts/scan.mjs       the scanner: files, stack detection, SQL/Firebase analysis, output
  references/            the manual checklist and per-stack guides
  templates/report.md    report skeleton
skills/fix/              guided fixing
skills/unstuck/          the debugging protocol for AI fix loops
hooks/                   the guard (PreToolUse hook)
test/                    node:test suites, no dependencies
```

## Adding a rule

1. Add it to `CODE_RULES` or `SECRET_RULES` in `rules.mjs` (or to an analyzer in `scan.mjs` if it needs more than a regex).
   - `id`: `VC-<AREA>-<NAME>`. Areas: `KEY`, `ENV`, `DB`, `AUTH`, `MONEY`/`PAY`/`AI`, `INJ`/`XSS`, `CFG`, `REL`, `LAUNCH`.
   - `severity`: the realistic impact (see the guide at the top of `references/checklist.md`).
   - `confidence`: `high` only if a match is almost always a real problem. Everything else is `verify`, and the agent confirms it by reading the code.
   - `fix`: one or two plain sentences: what can happen, and what to do instead.
   - Secret rules: set `guard: true` only for precise key formats. The guard blocks on them, so false positives hurt.
2. Add a test in `test/scan.test.mjs`: one fixture that must trigger the rule, and make sure the "well-secured app" test stays clean.
3. Add the check to `references/checklist.md` (mark it ⚙) and, if it's stack-specific, to the right stack guide.
4. `npm test`.

**Never commit real or realistic-looking secrets**, not even revoked ones. GitHub push protection will block them, and they teach scanners bad habits. Build fake keys at runtime the way `test/helpers.mjs` does.

## Writing for the skills

The readers are AI agents *and* first-time founders. Keep instructions short, imperative and concrete. Lead findings with the consequence ("anyone can read every message"), then the mechanism. Accuracy matters more than coverage: if you aren't sure a claim about a provider is current, link the docs or leave it out.
