# Security policy

vibecheck is a security tool, so a flaw in vibecheck itself can put its users at risk. Thank you for reporting responsibly.

## Report a vulnerability privately

Use GitHub's private reporting: **[Report a vulnerability](https://github.com/ribato22/vibecheck/security/advisories/new)** (repo → Security → Advisories → Report a vulnerability).

Please **don't open a public issue** for a vulnerability, and **never include real secrets** in a report. Use fake values that match the format.

Useful details:
- vibecheck version (`node skills/check/scripts/scan.mjs --version`) and how you installed it
- the agent and version (Claude Code, Cursor, Codex…), OS and Node version
- the smallest file or repo layout that reproduces the problem, and what happens vs. what you expected

## What counts

| In scope | Examples |
|---|---|
| Secret exposure | The scanner, report or guard prints a secret unmasked; a report lands somewhere git will commit it |
| Unsafe actions | Scanning a repo causes vibecheck to execute that repo's code, make network requests, or write outside `.vibecheck/` during an audit |
| Prompt injection through scanned content | Text inside a scanned project makes the skills take destructive or outward-facing actions (pushing, deleting, sending data) without the user's approval |
| Denial of service | A crafted file makes the scanner or guard hang or crash in a way that blocks the user's work (the guard is designed to fail open) |
| Guard bypass that silently commits a secret | A high-confidence key format slips past the guard on `git commit` / `git push` because of a logic bug, not a missing pattern |

| Not a vulnerability (open a normal issue instead) |
|---|
| A missed detection or a false positive. Use the "False positive / missed issue" template |
| Vulnerabilities in *your own app* that vibecheck found. Fix those in your project |
| Problems in Claude Code, the agents, or third-party services themselves. Report those to their vendors |

## What to expect

This is a small open-source project maintained by volunteers, so timelines are best effort:

- acknowledgement within **7 days**
- a fix or mitigation plan for confirmed issues within **30 days**, sooner for anything that leaks secrets
- credit in the release notes and the advisory, if you'd like it

## Supported versions

Only the latest release receives security fixes. Update with `claude plugin update vibecheck` (Claude Code), or reinstall the skills in other agents.
