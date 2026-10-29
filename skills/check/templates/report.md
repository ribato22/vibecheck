# vibecheck report: {{app name}}

> {{date}} · mode: {{quick|full|security|launch}} · exposure: {{public|internal|local}} · scanner {{version or "not run"}} · stack: {{stack}}
> Keep this file private: it lists weaknesses. (`.vibecheck/` ignores itself in git.)

## 🚦 Verdict: {{🔴 NO-GO | 🟡 FIX FIRST | 🟢 GO}}{{ (local only) | (internal only)}} · {{score}}/100 ({{grade}})

| 🔴 Critical | 🟠 High | 🟡 Medium | 🔵 Low | ❔ To verify |
|:-:|:-:|:-:|:-:|:-:|
| {{n}} | {{n}} | {{n}} | {{n}} | {{n}} |

{{Two or three plain sentences: the biggest risk, what an attacker or a bad day could do, and what to fix first.}}
{{If there was a previous report: "Last time: 31/100 (F) → now: 86/100 (B). Fixed: VC-…, VC-…"}}

## Fix these first

{{Numbered list of critical + high findings, one line each, linking to the details below.}}

---

## Findings

### 🔴 VC-KEY-OPENAI · Your OpenAI key is visible to every visitor

- **Where:** `src/lib/ai.ts:4` (`sk-p…9xQz`)
- **What can happen:** anyone can copy the key from the browser and run up your OpenAI bill, or use your account for abuse.
- **Why:** the key sits in client-side code and ships in the JavaScript bundle.
- **Fix:**
  1. Revoke the key at platform.openai.com → API keys and create a new one. Removing it from the code is not enough.
  2. Store the new key as `OPENAI_API_KEY` (no `NEXT_PUBLIC_` prefix) in `.env` and in your host's environment settings.
  3. Move the OpenAI call into a server route (`app/api/chat/route.ts`) that checks the user is logged in and is rate-limited.
- **Fix prompt** (paste into Claude Code / Cursor / Lovable / Bolt):
  ```text
  Security fix: my OpenAI API key is exposed in browser code in src/lib/ai.ts.
  Move every OpenAI call to a server-only API route at app/api/chat/route.ts that
  reads process.env.OPENAI_API_KEY, rejects requests from users who aren't logged in,
  limits each user to 20 requests per hour, and sets a max output token limit.
  Update the frontend to call /api/chat instead. Remove the key and
  dangerouslyAllowBrowser from all client code. Don't change any other behaviour.
  When done, show me where the key is now read and confirm no client file references it.
  ```

{{…one block per finding, ordered critical → low. Group low-severity launch items into a single checklist block.}}

---

## 🔓 Before exposing it more widely

{{Only for `local` or `internal` apps. Everything that doesn't deduct today but must change before more people can reach the app (auth, ownership checks, rate limits, launch basics), each with a fix prompt. Remove this section for public apps.}}

## ❔ Check these yourself (outside the code)

- [ ] {{e.g. Supabase → Database → Advisors shows no "RLS disabled" warnings}}
- [ ] {{e.g. Spend limit set at OpenAI (Settings → Limits) and Vercel (Spend Management)}}
- [ ] {{e.g. Database backups enabled, and you know how to restore one}}
- [ ] {{e.g. Revoked keys: list each leaked key that must be rotated}}

## ✅ What's already good

{{Short list of things done right. Owners deserve to know what not to break.}}

## Not covered

{{What this audit didn't look at (mode limits, folders skipped, no access to dashboards). vibecheck is a strong first line, not a penetration test.}}
