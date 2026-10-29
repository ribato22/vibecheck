# Changelog

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
