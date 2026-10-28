# vibecheck checklist

Eight areas, ordered by how badly they hurt. The severity column is the default: adjust it to the real impact in this app. IDs marked ⚙ are also checked by the scanner. Everything else needs you to read code or ask the user about a dashboard setting.

Severity guide:
- **critical**: an attacker can, today, steal or change other users' data, take over accounts, or spend the owner's money. Launch blocker.
- **high**: a realistic attack, or a likely incident within weeks of launch. Fix before launch.
- **medium**: needs extra conditions, or limited impact. Fix soon.
- **low**: hygiene and polish.

---

## 1. Secrets & keys

| ID | Check | Sev | How to verify / fix |
|---|---|---|---|
| ⚙ VC-KEY-* | No real API keys, private keys or DB passwords in tracked files | critical | Scanner. Fix: move to server env vars and **rotate the key** (deleting it from code doesn't help once it was pushed or deployed). |
| ⚙ VC-ENV-PUBLIC-SECRET | No secret behind a browser-public prefix (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`, `PUBLIC_`, `NUXT_PUBLIC_`) | critical | These are inlined into the JS bundle at build time. Rename, use server-side only, rotate. |
| ⚙ VC-ENV-TRACKED / VC-ENV-HISTORY | `.env` files never committed, now or in history | critical | `git log --all -- .env` shows history. Rotate everything that was in it. |
| ⚙ VC-ENV-GITIGNORE | `.gitignore` covers `.env*` (with `!.env.example`) | high | |
| VC-SEC-CLIENT-IMPORT | Client components don't import modules that read secrets | high | Follow imports from `'use client'` files and `src/` SPA code. In Next.js, add `import 'server-only'` to secret-reading modules. |
| ⚙ VC-ENV-BUNDLED / VC-ENV-NEXT-CONFIG | Build config doesn't inline all env vars (Vite `define: {'process.env': process.env}`, Next `env: {}` with secrets) | critical | |
| VC-SEC-LOGS | Logs and error messages don't print tokens, passwords, full request bodies or PII | medium | Search `console.log(` / `print(` near auth, payment and user objects. |
| VC-SEC-MCP-CONFIG | Agent/MCP config files (`.mcp.json`, `.cursor/mcp.json`, `.claude/settings.json`) don't contain tokens | high | Scanner covers known formats. Check `env` blocks by eye. |

## 2. Database access

| ID | Check | Sev | How to verify / fix |
|---|---|---|---|
| ⚙ VC-DB-NO-RLS / VC-DB-RLS-DISABLED | Supabase: RLS enabled on **every** table in `public` | critical | Tables made in the dashboard won't be in migrations: ask the user to run the SQL in `stacks/supabase.md` or open Database → Advisors. |
| ⚙ VC-DB-POLICY-OPEN | Policies are scoped to the owner, not `using (true)` | high | `to authenticated` only means "anyone who signed up". Public read is OK only for truly public content. |
| VC-DB-OWNER-WRITE | Insert/update policies have `with check` so users can't write rows as someone else | high | |
| VC-DB-PRIV-COLUMNS | Users can't update their own `role`, `is_admin`, `plan`, `credits`, `balance`, `verified` | critical | Column grants or a separate table only the server writes. See `stacks/supabase.md`. |
| ⚙ VC-DB-POLICY-USER-METADATA | Authorization never trusts `user_metadata` (users can edit it) | high | Use `app_metadata` or a roles table. |
| ⚙ VC-DB-VIEW-BYPASS / VC-DB-SECURITY-DEFINER | Views use `security_invoker`; `security definer` functions check `auth.uid()` and aren't executable by `anon` | medium | |
| VC-DB-STORAGE | Storage buckets with private files are private, with per-user folder policies | high | Public bucket = anyone with the URL pattern can list or guess files. |
| ⚙ VC-DB-FIREBASE-OPEN | Firestore/Storage/RTDB rules aren't open, aren't "test mode", and are owner-scoped | critical | |
| ⚙ VC-DB-SERVICE-KEY-CLIENT | The admin/service key is only used server-side | critical | |
| VC-DB-NOSQL-INJECTION | Mongo queries don't take raw objects from `req.body` (`{ "$ne": null }` logs in as anyone) | high | Validate types with zod, or cast to string. |

## 3. Authentication & authorization

| ID | Check | Sev | How to verify / fix |
|---|---|---|---|
| VC-AUTH-SERVER-CHECK | Every API route, server action and function that reads or writes user data verifies the session **on the server** | critical | Hiding a button in the UI is not protection. List every entry point and tick each one. |
| VC-AUTH-IDOR | Handlers check that the record belongs to the caller (`where id = :id and user_id = :me`) | critical | Classic: `/api/invoices/[id]` returns any invoice for any id. |
| VC-AUTH-ADMIN | Admin pages and APIs check a server-side role, never a client flag, localStorage, query param or hidden route | critical | |
| VC-AUTH-MIDDLEWARE-ONLY | Auth isn't enforced *only* in middleware or a layout | high | Next.js middleware can be bypassed (CVE-2025-29927) and layouts don't protect server actions. Check close to the data. |
| ⚙ VC-AUTH-JWT-DECODE | JWTs are verified, not just decoded | high | |
| VC-AUTH-ROLL-YOUR-OWN | No home-made password hashing, sessions or reset tokens | high | Prefer Supabase Auth, Clerk, Auth.js, Better Auth, Firebase Auth. If custom: bcrypt/argon2, single-use expiring reset tokens. |
| VC-AUTH-REDIRECTS | OAuth/magic-link redirect URLs are an exact allowlist; ⚙ app redirects only go to relative paths | medium | Supabase: Auth → URL Configuration. |
| VC-AUTH-SIGNUP-ABUSE | Signup/login/OTP have rate limits; CAPTCHA if signup grants free credits | medium | |
| ⚙ VC-AUTH-TOKEN-STORAGE | Session tokens live in httpOnly cookies, not localStorage | low | |

## 4. Money & abuse ("denial of wallet")

| ID | Check | Sev | How to verify / fix |
|---|---|---|---|
| ⚙ VC-AI-BROWSER | LLM / paid APIs are never called directly from the browser | critical | Proxy through a server route with auth + rate limit. |
| ⚙ VC-MONEY-NO-RATE-LIMIT | AI, email, SMS, upload and auth endpoints have per-user/IP rate limits | high | One `for` loop can cost thousands. See `stacks/ai-apis.md`. |
| VC-MONEY-SPEND-CAP | Hard spend limits / budget alerts are set at every provider (OpenAI, Anthropic, Google Cloud, Vercel, Supabase, Firebase, Twilio) | high | UNVERIFIED unless the user confirms. Firebase/GCP budget alerts notify but **don't stop** spending. |
| VC-MONEY-MAX-TOKENS | LLM calls set max output tokens, cap input size and cap tool/agent loop steps | medium | |
| ⚙ VC-PAY-CLIENT-PRICE | Prices and amounts come from the server (price IDs), never from the request | critical | |
| ⚙ VC-PAY-WEBHOOK-UNVERIFIED | Payment webhooks verify signatures on the raw body | critical | Unverified webhook = free premium for anyone. |
| VC-PAY-SUCCESS-URL | Paid access is granted from the webhook, not from visiting `/success?session_id=…` | critical | Anyone can open the success URL. |
| VC-PAY-IDEMPOTENT | Webhook handlers tolerate duplicate and out-of-order events | medium | Store processed event IDs. |
| VC-PAY-ENTITLEMENT | Premium features check subscription status on the server, from the database | high | |
| ⚙ VC-CFG-IMAGES-WILDCARD | Image optimizer / proxy endpoints only accept known hosts | low | |

## 5. Input & output

| ID | Check | Sev | How to verify / fix |
|---|---|---|---|
| VC-IN-VALIDATE | Every server entry point validates input with a schema (zod, valibot, pydantic) | medium | |
| ⚙ VC-INJ-SQL | No SQL built with string interpolation | critical | Parameters or the ORM. |
| ⚙ VC-INJ-MASS-ASSIGN | Request bodies aren't written straight into the DB | high | Pick allowed fields. |
| ⚙ VC-XSS-HTML | User- or AI-generated HTML/markdown is sanitized (DOMPurify) or rendered as text | high | Markdown renderers: keep raw HTML off. |
| VC-IN-UPLOADS | Uploads limit type and size, are stored privately, and are never served as HTML from your domain | medium | |
| ⚙ VC-INJ-SSRF | Server-side fetches of user URLs use a host allowlist | medium | |
| ⚙ VC-INJ-CMD / VC-INJ-EVAL | No shell commands or eval built from input | critical | |
| VC-AI-PROMPT-INJECTION | LLM tools/actions re-check authorization in code; no secrets in system prompts; model output is treated as untrusted | high | See `stacks/ai-apis.md`. |

## 6. Deployment & config

| ID | Check | Sev | How to verify / fix |
|---|---|---|---|
| VC-CFG-HEADERS | Security headers set: CSP (even a basic one), `frame-ancestors`/X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HSTS | medium | |
| ⚙ VC-CFG-CORS | CORS lists real origins; never `*` together with credentials | high | |
| ⚙ VC-CFG-DEBUG | Debug mode off in production; errors don't show stack traces to users | medium | |
| VC-CFG-EXPOSED-FILES | Nothing public that shouldn't be: `.git/`, `.env`, backups, admin panels, API docs with "try it" | high | Check `public/` and `static/` folders. |
| ⚙ VC-CFG-SOURCEMAPS | No public production source maps | low | |
| VC-CFG-DEPS | Dependencies exist, are the intended packages, and have no known critical CVEs | high | AI tools sometimes invent package names that attackers then register ("slopsquatting"). Check unfamiliar names on npm/PyPI: real downloads, real repo, not brand new. Suggest the user run `npm audit --omit=dev`. Check the framework version against advisories. |
| VC-CFG-ENV-SEPARATION | Dev and prod use different keys and databases; test keys aren't in prod and live keys aren't in dev | medium | |
| ⚙ VC-CFG-TLS-OFF | TLS verification isn't disabled | medium | |

## 7. Reliability & data safety

| ID | Check | Sev | How to verify / fix |
|---|---|---|---|
| ⚙ VC-REL-NO-GIT | Code is in git and pushed to a private remote | medium | The undo button for bad AI edits. |
| VC-REL-BACKUPS | Database backups on (Supabase PITR / daily backups, Firebase scheduled exports, Neon branching) and a restore has been tried once | high | UNVERIFIED unless the user confirms. |
| VC-REL-MIGRATIONS | Schema changes live in migration files, not only dashboard clicks | medium | Otherwise prod can't be rebuilt. |
| ⚙ VC-REL-NO-MONITORING | Error tracking (Sentry, PostHog) and uptime monitoring | low | |
| VC-REL-ERROR-STATES | API routes return proper status codes; the UI shows friendly error, empty and loading states; no unhandled promise rejections in critical flows | low | |
| VC-REL-ENV-DOCS | `.env.example` lists every required variable (names only) | low | Saves the next deploy. |
| VC-REL-SMOKE-TEST | At least a manual or automated smoke test of signup, login, the core feature and payment | low | |
| ⚙ VC-REL-NO-LOCKFILE | Lockfile committed | low | |

## 8. Launch basics

| ID | Check | Sev | How to verify / fix |
|---|---|---|---|
| ⚙ VC-LAUNCH-PRIVACY | Privacy policy if you collect any personal data (GDPR, UU PDP Indonesia, CCPA; required by app stores) | low → medium if collecting data from EU/ID users | |
| ⚙ VC-LAUNCH-TERMS | Terms of service | low | |
| VC-LAUNCH-ACCOUNT-DELETION | Users can delete their account and data | low → high for iOS apps (App Store requirement) | |
| VC-LAUNCH-COOKIES | Cookie consent if using non-essential cookies for EU visitors | low | |
| ⚙ VC-LAUNCH-OG / ROBOTS / SITEMAP / FAVICON / 404 | Title + meta description, OG image, robots.txt, sitemap, favicon, custom 404 | low | |
| ⚙ VC-LAUNCH-ANALYTICS | Some analytics, to know whether the launch worked | low | |
| VC-LAUNCH-EMAIL-DNS | Transactional email from your own domain with SPF, DKIM and DMARC | low → medium if login depends on email | Otherwise magic links land in spam. |
| VC-LAUNCH-SUPPORT | A visible contact or support channel | low | |
| VC-LAUNCH-MOBILE | Key pages work on a phone; basic accessibility (alt text, labels, contrast) | low | |
