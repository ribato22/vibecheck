# vibecheck report: my-saas

> 2026-10-28 · mode: full · scanner 1.0.0 · stack: Next.js 15, Supabase, Stripe, OpenAI, Vercel
> Keep this file private: it lists weaknesses. (`.vibecheck/` ignores itself in git.)
>
> *This is an example report for a fictional app, to show what vibecheck produces.*

## 🚦 Verdict: 🔴 NO-GO · 31/100 (F)

| 🔴 Critical | 🟠 High | 🟡 Medium | 🔵 Low | ❔ To verify |
|:-:|:-:|:-:|:-:|:-:|
| 3 | 2 | 4 | 6 | 2 |

Right now, anyone can read every private message in your app and spend your OpenAI credit, and a fake "payment succeeded" request unlocks Pro for free. None of this needs hacking skills: a browser's DevTools is enough. Fix the three criticals before anything else. Each takes under 30 minutes with the fix prompts below.

## Fix these first

1. 🔴 [VC-KEY-OPENAI: your OpenAI key is visible to every visitor](#-vc-key-openai--your-openai-key-is-visible-to-every-visitor)
2. 🔴 [VC-DB-NO-RLS: anyone can read and edit all messages](#-vc-db-no-rls--anyone-can-read-and-edit-all-messages)
3. 🔴 [VC-PAY-WEBHOOK-UNVERIFIED: anyone can fake a payment](#-vc-pay-webhook-unverified--anyone-can-fake-a-payment)
4. 🟠 [VC-MONEY-NO-RATE-LIMIT: /api/chat can be called without limits](#-vc-money-no-rate-limit--apichat-can-be-called-without-limits)
5. 🟠 [VC-DB-PRIV-COLUMNS: users can make themselves admin](#-vc-db-priv-columns--users-can-make-themselves-admin)

---

## Findings

### 🔴 VC-KEY-OPENAI · Your OpenAI key is visible to every visitor

- **Where:** `src/lib/ai.ts:4` (`sk-p…9xQz`), plus `NEXT_PUBLIC_OPENAI_API_KEY` in `.env:2`
- **What can happen:** anyone can copy the key from the browser and run up your OpenAI bill, or use your account for spam and abuse.
- **Why:** the key is read through a `NEXT_PUBLIC_` variable and the SDK runs with `dangerouslyAllowBrowser: true`, so it ships in the JavaScript bundle.
- **Fix:**
  1. Revoke the key at platform.openai.com → API keys and create a new one. Removing it from the code is not enough: it was deployed.
  2. Save the new key as `OPENAI_API_KEY` (no `NEXT_PUBLIC_`) in `.env` and in Vercel → Settings → Environment Variables.
  3. Move the OpenAI call into `app/api/chat/route.ts` with a login check and a rate limit (see VC-MONEY-NO-RATE-LIMIT).
- **Fix prompt:**
  ```text
  Security fix: my OpenAI API key is exposed in browser code (src/lib/ai.ts uses
  NEXT_PUBLIC_OPENAI_API_KEY with dangerouslyAllowBrowser). Move every OpenAI call
  into a server-only route at app/api/chat/route.ts that reads process.env.OPENAI_API_KEY,
  returns 401 for users who aren't logged in, and sets max_tokens to 1000. Update the
  frontend to call /api/chat. Remove NEXT_PUBLIC_OPENAI_API_KEY and dangerouslyAllowBrowser
  everywhere. Don't change any other behaviour. When done, show me that no client
  file references the key.
  ```

### 🔴 VC-DB-NO-RLS · Anyone can read and edit all messages

- **Where:** `supabase/migrations/20260101000000_init.sql:6`, table `messages`
- **What can happen:** anyone with your public anon key (it's in your front-end, which is normal) can download every message from every user, change them, or delete them all.
- **Why:** the table is in the `public` schema without Row Level Security. Supabase's API exposes it fully.
- **Fix:** a new migration that enables RLS **and** adds owner policies in the same file (RLS without policies makes the app show empty lists).
- **Fix prompt:**
  ```text
  Create a Supabase migration supabase/migrations/<timestamp>_messages_rls.sql that
  enables row level security on public.messages and adds policies so authenticated
  users can select, insert, update and delete only rows where user_id = (select auth.uid()).
  Insert must use "with check". Don't change other tables. Then tell me how to apply it
  and how to test as two different users that user A can't see user B's messages.
  ```
- **Check yourself:** Supabase → Database → Advisors → Security should show no "RLS disabled in public" items after you apply it.

### 🔴 VC-PAY-WEBHOOK-UNVERIFIED · Anyone can fake a payment

- **Where:** `app/api/stripe/webhook/route.ts`
- **What can happen:** anyone can send a fake `checkout.session.completed` event and get Pro for free, for any account.
- **Why:** the handler reads `req.json()` and trusts it, without checking Stripe's signature.
- **Fix prompt:**
  ```text
  In app/api/stripe/webhook/route.ts, verify the Stripe signature: read the raw body
  with await req.text(), call stripe.webhooks.constructEvent(body, stripe-signature
  header, process.env.STRIPE_WEBHOOK_SECRET), and return 400 if it throws. Store
  processed event IDs so duplicate events are ignored. Keep the existing fulfilment
  logic. Explain how to test it with `stripe listen --forward-to localhost:3000/api/stripe/webhook`.
  ```

### 🟠 VC-MONEY-NO-RATE-LIMIT · /api/chat can be called without limits

- **Where:** `app/api/chat/route.ts`
- **What can happen:** one script calling this endpoint in a loop can spend hundreds of dollars overnight.
- **Fix prompt:**
  ```text
  Add rate limiting to app/api/chat/route.ts with @upstash/ratelimit (sliding window,
  20 requests per hour per user ID). Return 429 when exceeded. Reject messages longer
  than 4000 characters. Ask me before installing packages, and list the env vars I
  need to add.
  ```
- **Check yourself:** set a monthly budget at OpenAI → Settings → Limits.

### 🟠 VC-DB-PRIV-COLUMNS · Users can make themselves admin

- **Where:** `supabase/migrations/20260101000000_init.sql:3`, policy "anyone can update profiles"
- **What can happen:** any signed-up user can run `update profiles set is_admin = true` from the browser console and open your admin panel.
- **Fix prompt:**
  ```text
  Users must not be able to change is_admin on public.profiles. Write a migration that
  replaces the "anyone can update profiles" policy with one limited to the user's own
  row (using and with check on (select auth.uid()) = id), and restricts updatable columns:
  revoke update on public.profiles from authenticated; then grant update only on
  display_name and avatar_url. Don't touch other policies.
  ```

### 🟡 Medium (4)

| ID | What | Where |
|---|---|---|
| VC-XSS-HTML | Admin panel renders HTML without sanitizing it | `src/components/AdminPanel.tsx:4` |
| VC-DB-VIEW-BYPASS | View `leaderboard` ignores RLS | `supabase/migrations/…_init.sql:7` |
| VC-CFG-HEADERS | No security headers | `next.config.js` |
| VC-AUTH-MIDDLEWARE-ONLY | `/dashboard` is protected only in middleware | `middleware.ts:12` |

### 🔵 Launch checklist (6)

- [ ] Privacy policy (you collect emails: required by GDPR / UU PDP)
- [ ] Terms of service
- [ ] Open Graph image and description
- [ ] robots.txt and sitemap
- [ ] Custom 404 page
- [ ] Error monitoring (Sentry free tier)

---

## ❔ Check these yourself (outside the code)

- [ ] Rotate the OpenAI key (see VC-KEY-OPENAI)
- [ ] OpenAI and Vercel spend limits are set
- [ ] Supabase backups: Pro plan or a regular `supabase db dump`

## ✅ What's already good

- Supabase Auth with `@supabase/ssr`, so sessions live in httpOnly cookies
- `.env.example` documents every variable
- Stripe Checkout Sessions use price IDs, not amounts from the client

## Not covered

Dashboard-only settings (Auth redirect URLs, storage buckets) and a live test of the deployed site. vibecheck is a strong first line of defence, not a penetration test.
