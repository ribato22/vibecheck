<p align="center">
  <img src="assets/banner.png" alt="vibecheck: ship your vibe-coded app without leaking your users' data, or your wallet" width="100%">
</p>

<p align="center">
  <b>Your AI wrote the app. vibecheck makes sure it doesn't leak your users' data, or your wallet.</b>
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#what-it-catches">What it catches</a> ·
  <a href="#commands">Commands</a> ·
  <a href="#the-guard-always-on">Guard</a> ·
  <a href="#use-it-in-ci">CI</a> ·
  <a href="README.id.md">🇮🇩 Bahasa Indonesia</a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/Claude%20Code-plugin-d97757" alt="Claude Code plugin">
  <img src="https://img.shields.io/badge/works%20with-Cursor%20·%20Codex%20·%20Gemini%20CLI%20·%20OpenCode-555" alt="Works with Cursor, Codex, Gemini CLI, OpenCode">
  <img src="https://img.shields.io/badge/dependencies-0-brightgreen" alt="Zero dependencies">
  <a href="https://github.com/ribato22/vibecheck/actions"><img src="https://github.com/ribato22/vibecheck/actions/workflows/test.yml/badge.svg" alt="tests"></a>
</p>

---

In January 2026, a vibe-coded social network exposed **1.5 million API tokens and 35,000 email addresses**. One Supabase key sat in the front-end, and Row Level Security was off ([Wiz](https://www.wiz.io/blog/common-security-risks-in-vibe-coded-apps), [Infosecurity](https://www.infosecurity-magazine.com/news/moltbook-exposes-user-data-api/)). In 2025, **170+ Lovable apps** shipped with the same hole ([CVE-2025-48757](https://nvd.nist.gov/vuln/detail/CVE-2025-48757)). Every week, someone finds out their OpenAI key was in the JavaScript bundle by reading their bill.

AI tools write code that **works**. Nobody checks that it's **safe**. vibecheck is the senior engineer who reviews your app before you hit deploy, in plain language, with the fixes ready to paste.

<p align="center"><img src="assets/demo.png" alt="vibecheck finds 3 critical issues, scores the app 31/100 NO-GO, then /vibecheck:fix takes it to 92/100 GO" width="90%"></p>

<p align="center"><a href="examples/sample-report.md">📄 See a full sample report</a></p>

## What you get

- 🚦 **A Launch Score and a verdict.** 0 to 100, plus 🔴 NO-GO, 🟡 FIX FIRST or 🟢 GO, so you know if you can ship today.
- 🔍 **A real audit, not regex soup.** A zero-dependency scanner (60+ checks) finds the leads fast. Your AI agent then reads the code to verify each one, traces attack flows like "can user A read user B's data?", and drops the false positives.
- 🗣️ **Plain language.** Every finding starts with *what can happen* ("anyone can read every private message"), then the technical detail. Reports come in the language you write in.
- 📋 **Copy-paste fix prompts.** Every finding has a ready prompt for Claude Code, Cursor, Lovable, Bolt, v0 or Replit, so it helps even if your app lives in a no-code builder.
- 🛠️ **`/vibecheck:fix`.** Fixes issues one at a time, criticals first, verifies each one, and never "fixes" by weakening security.
- 🛡️ **An always-on guard.** A hook stops your agent from hardcoding API keys or committing `.env` *before* it happens.
- 🧭 **`/vibecheck:unstuck`.** Breaks the "AI fix loop" when the same bug keeps coming back.

## What it catches

| Area | Examples |
|---|---|
| 🔑 **Secrets** | OpenAI / Anthropic / Stripe / AWS / Supabase keys in code; secrets behind `NEXT_PUBLIC_` / `VITE_` / `EXPO_PUBLIC_`; `.env` committed now or in git history |
| 🗄️ **Database** | Supabase tables without RLS, `using (true)` policies, users editing their own `is_admin`, policies trusting `user_metadata`; Firebase "test mode" and open rules; the service-role key in browser code |
| 🔐 **Auth** | API routes and server actions without a server-side check, IDOR (reading other people's records), admin by client flag, middleware-only auth, `jwt.decode` without verify |
| 💸 **Money** | AI calls from the browser (`dangerouslyAllowBrowser`), paid APIs with no rate limit ("denial of wallet"), prices taken from the request, unverified Stripe / Midtrans / Xendit webhooks, premium unlocked from a success URL |
| 🧱 **Input** | SQL injection, mass assignment, XSS via `dangerouslySetInnerHTML` and AI output, SSRF, shell injection, prompt injection through tools |
| 🚀 **Config** | `CORS *` with credentials, debug mode, public source maps, disabled TLS checks, missing security headers, hallucinated npm packages |
| 🛟 **Reliability** | No git, no backups, no error monitoring, schema not in migrations, no lockfile |
| 🌍 **Launch** | Privacy policy and terms, account deletion (App Store), OG tags, sitemap, robots, 404, favicon, analytics, email DNS |

Deepest coverage: **Next.js, React/Vite, Supabase, Firebase, Stripe, OpenAI/Anthropic/Gemini, Express, FastAPI/Flask/Django, Expo**, with **Midtrans and Xendit** for Indonesian payments. The generic checks work on any stack.

## Install

### Claude Code (recommended: includes the guard hook)

```text
/plugin marketplace add ribato22/vibecheck
/plugin install vibecheck@vibecheck
```

### Cursor, Codex, Gemini CLI, OpenCode, Windsurf and other agents (skills only)

```bash
npx skills add ribato22/vibecheck
```

### Manual

Copy the folders in `skills/` into `~/.claude/skills/` (or your agent's skills folder).

## Commands

| Command | What it does |
|---|---|
| `/vibecheck:check` | Full audit → score, verdict and `.vibecheck/report.md` with fix prompts |
| `/vibecheck:check quick` | 2-minute pre-deploy check: secrets, database access and criticals |
| `/vibecheck:check security` | Security areas only |
| `/vibecheck:check launch` | Launch checklist (legal, SEO, monitoring) plus any critical |
| `/vibecheck:fix` | Fix criticals, then highs, one at a time, with before → after score |
| `/vibecheck:fix VC-DB-NO-RLS` | Fix one specific finding |
| `/vibecheck:unstuck` | Stop the fix loop: reproduce, find the root cause, revert the pile |

You don't have to remember them. Ask *"is my app ready to launch?"* or say *"it's still broken, you keep going in circles"* and the right skill kicks in. In other agents, call the skill by name (`check`, `fix`, `unstuck`).

## The guard (always on)

With the Claude Code plugin, vibecheck watches every file write and every `git commit` / `git push` your agent makes:

```text
vibecheck guard blocked this: it would put secrets where they do not belong.

  - OpenAI API key sk-p…9xQz in src/lib/ai.ts:3
  - NEXT_PUBLIC_OPENAI_API_KEY has a browser-public prefix, so its value ships to every visitor (.env:2)

Fix:
  1. Put the secret in .env (gitignored) and read it with process.env.NAME in server-only code.
  2. Keep browser-public prefixes (NEXT_PUBLIC_, VITE_, EXPO_PUBLIC_...) for values that are safe to publish.
```

The agent reads that message and fixes it itself. The guard blocks only high-confidence key formats, allows secrets in `.env`, and checks every unpushed commit (not just the last one). Silence a false positive with a `vibecheck-ignore` comment on the line, or turn the guard off with `VIBECHECK_GUARD=off`.

## Use it in CI

The scanner is a single Node file with no dependencies:

```bash
node skills/check/scripts/scan.mjs ./my-app                     # human-readable
node skills/check/scripts/scan.mjs ./my-app --json              # for tools and agents
node skills/check/scripts/scan.mjs . --fail-on critical         # exit 1 on high-confidence criticals
```

```yaml
# .github/workflows/vibecheck.yml
name: vibecheck
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }   # full history, so .env files committed in the past are caught
      - uses: actions/checkout@v4
        with: { repository: ribato22/vibecheck, path: .vibecheck-tool }
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: node .vibecheck-tool/skills/check/scripts/scan.mjs . --fail-on critical
```

## Passed? Show it

Got a 🟢 GO? Add the badge to your README:

```markdown
[![vibecheck: GO 92/100](https://img.shields.io/badge/vibecheck-GO%2092%2F100-brightgreen)](https://github.com/ribato22/vibecheck)
```

[![vibecheck: GO 92/100](https://img.shields.io/badge/vibecheck-GO%2092%2F100-brightgreen)](https://github.com/ribato22/vibecheck)

Only GO apps get a badge. A public "NO-GO" badge would tell attackers where to look.

## Safe by design

A security tool should never be the security problem.

- **The audit is read-only.** It writes only to `.vibecheck/`, which ignores itself in git. Fixes happen only in `/vibecheck:fix`, after you agree.
- **Zero dependencies, zero network calls**, and it never runs your project's code. About 1,000 lines of plain JavaScript you can read in 15 minutes: [`rules.mjs`](skills/check/scripts/rules.mjs), [`scan.mjs`](skills/check/scripts/scan.mjs), [`guard.mjs`](hooks/guard.mjs).
- **Secrets are always masked** (`sk-p…9xQz`) in output, reports and guard messages.
- **The guard fails open.** If it crashes, your work continues.

## FAQ

**Does this replace a penetration test?**
No. It catches the mistakes AI tools make most often, and that's most real-world vibe-coding breaches. If you handle health, financial or children's data, get a professional review too.

**Does it send my code anywhere?**
The scanner doesn't touch the network. The skills run inside the AI agent you already use, like any other prompt.

**It flagged something that's fine.**
Add `// vibecheck-ignore` (or `# vibecheck-ignore`) on that line. Put `vibecheck-ignore-file` in the first lines to skip a whole file, such as test fixtures. Then open an issue so the rule gets better.

**My app was built in Lovable / Bolt / v0 / Replit.**
Export or sync it to GitHub, open it with any supported agent, and run the check. Paste the fix prompts back into your builder.

## Contributing

New rules, stack guides and false-positive reports are very welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Each rule ships with a test. Run them with `npm test` (Node 18+, no install needed).

## Roadmap

- [ ] Official GitHub Action
- [ ] More stack guides: Convex, Clerk, Auth.js, Better Auth, Laravel, Rails
- [ ] Live checks (security headers, open Supabase tables) behind an explicit opt-in

---

<p align="center">
  If vibecheck caught something before your users did, a ⭐ helps other builders find it.<br>
  <sub>MIT © vibecheck contributors · Not affiliated with Anthropic, Supabase, Firebase, Stripe or any other vendor named here.</sub>
</p>
