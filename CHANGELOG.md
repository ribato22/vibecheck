# Changelog

## 1.1.0 (2026-10-29)

New skill: **`/vibecheck:deploy`**, a pre-deploy check for "works on my machine, broken in production".

- A new self-contained, read-only scanner (`skills/deploy/scripts/preflight.mjs`) finds:
  - env vars the code uses that aren't set on the host (pass the host's variable *names* with `--host-env`; values are never read), or that are missing from `.env.example`
  - hardcoded `localhost` URLs, and env var fallbacks to localhost
  - imports whose letter case only matches on Mac/Windows (`'./button'` vs `Button.tsx`), which break on Linux build servers
  - packages imported but not listed in package.json
  - servers on a fixed port or bound to `127.0.0.1` on Railway, Render, Fly, Heroku and Docker, and a missing `start` script
  - SQLite and disk writes on serverless hosts, Prisma Client never generated, multiple lockfiles, Node version mismatches
- It detects the host from config files, or takes `--host`, and turns the stack into a checklist of host-side steps: migrations, auth redirect URLs, live webhooks, rebuilding after public env changes.
- `references/hosts.md` has checklists for Vercel, Netlify, Cloudflare, Railway, Render, Fly, Heroku, Docker and Python apps.
- `/vibecheck:fix` now handles `VC-DEPLOY-*` findings from `.vibecheck/deploy.md`.

## 1.0.4 (2026-10-29)

From the first full check → fix → re-check cycle on a real app.

- **Reports stay private outside git too.** `.vibecheck/.gitignore` only protects git. The audit now checks how else the project leaves the machine (no git, zip or handoff archives, Docker `COPY . .`, public npm packages, upload scripts) and tells you where to exclude `.vibecheck/`. It offers the edit instead of making it.
- **`fix` stays inside the finding.** It asks before touching files the fix doesn't need (docs, build, QA or packaging scripts).
- **`fix` doesn't restart your processes.** It tells you which running servers still have the old code and that unsaved demo state may be lost.
- **`fix` without git:** if you'd rather not use git, it backs up each file to `.vibecheck/backup-<finding-id>/` before editing.
- New `test/skills.test.mjs` checks every skill's frontmatter, that every linked reference file exists, and that all version numbers match.

## 1.0.3 (2026-10-29)

- **Skipped folders no longer hide code that ships.** A file under a test, backup or QA folder is checked like app code when app code imports it, directly or through other imports (`import`, `export … from`, `import()`, `require()`, including `./x.js` → `x.ts` and folder `index` files). In a real audit, two OpenAPI helpers kept in `qa-scripts/` were used at runtime and had been skipped.
- `notes` lists those files. Imports through path aliases (like `@/`) aren't followed yet, and the note says so.

## 1.0.2 (2026-10-29)

- **Agents see every match.** `--json` now returns up to 200 matches per rule (was 25). In a real audit, the old limit was used up by one noisy folder and hid the app's own code.
- **Overflow is reported per file**, in `notes` and in a new `hidden` field (`{ rule: { file: count } }`), so the agent knows exactly which files still need a look. The text view for humans still shows 25 per rule.
- The audit skill tells the agent to check `hidden` files and skipped folders before calling a rule fully covered.

## 1.0.1 (2026-10-29)

Fixes from the first real-world audit outside Claude Code (Codex, on a local Node.js app).

- **Exposure-aware verdicts.** The audit now decides whether an app is `public`, `internal` or `local` and judges findings for that exposure. A local demo can get "🟢 GO (local only)", and the report lists what must change before it's exposed more widely. When the exposure is unclear, the audit assumes `public`.
- **Fewer false positives from code that doesn't ship.** Code patterns are no longer checked in backup, archive and QA folders (`backup*/`, `archive*/`, `old/`, `qa*/`, `playwright/`, `cypress/`, `*.backup.js`…). Secrets are still scanned there, and the scanner lists the skipped folders so the agent can check them if they do ship.
- **`VC-INJ-EVAL` no longer flags Playwright's `page.$eval()` / `page.$$eval()`.**
- **No generic "possible hardcoded secret" guesses in test files.** Real key formats (OpenAI, Anthropic, Stripe, AWS…) are still reported there.
- The README badge is offered only for a full-mode GO of a public app.

## 1.0.0 (2026-10-28)

First public release: `/vibecheck:check`, `/vibecheck:fix`, `/vibecheck:unstuck`, the guard hook, and the zero-dependency scanner.
