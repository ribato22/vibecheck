# Supabase

## The one thing to understand

The browser talks to your database directly with the **anon / publishable key**, and that key is public by design. Row Level Security (RLS) policies are the *only* thing between that key and every row of every table in the `public` schema. No RLS means a public table. This is how Moltbook (Jan 2026) and 170+ Lovable apps (CVE-2025-48757) leaked.

| Key | Where it may live |
|---|---|
| `anon` JWT / `sb_publishable_…` | Browser is fine, **if** RLS is on everywhere |
| `service_role` JWT / `sb_secret_…` | Server only. It bypasses all RLS. Never in client code, never behind `NEXT_PUBLIC_`/`VITE_`/`EXPO_PUBLIC_` |

## Verify (give these to the user; you don't run them)

Tables without RLS. Paste into the dashboard's SQL Editor:

```sql
select c.relname as table_name, c.relrowsecurity as rls_enabled
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind in ('r', 'p')
order by rls_enabled, table_name;
```

Every policy, to read through:

```sql
select tablename, policyname, cmd, roles, qual as using_expr, with_check
from pg_policies where schemaname = 'public' order by tablename;
```

Also: Dashboard → **Database → Advisors → Security Advisor** flags `rls_disabled_in_public`, `security_definer_view`, `function_search_path_mutable`, exposed auth users and more.

Exposure test, only against the user's own project and with their OK:

```bash
curl "https://<project-ref>.supabase.co/rest/v1/<table>?select=*&limit=1" \
  -H "apikey: <anon-key>" -H "Authorization: Bearer <anon-key>"
```

Rows returned while logged out means the table is readable by the whole internet.

## Owner-only policies (the default you want)

```sql
alter table public.notes enable row level security;

create policy "read own notes" on public.notes
  for select to authenticated using ((select auth.uid()) = user_id);
create policy "insert own notes" on public.notes
  for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "update own notes" on public.notes
  for update to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "delete own notes" on public.notes
  for delete to authenticated using ((select auth.uid()) = user_id);
```

- Wrapping it as `(select auth.uid())` is the recommended form: the same check, cached per query.
- Enabling RLS **without** policies makes the table return `[]` to clients. That's safe but looks like "my app broke". Ship the policies in the same migration.
- Public content (published posts, a product catalog): `for select to anon, authenticated using (published = true)`. Never `using (true)` on anything private.

## Privilege escalation: the bug AI writes most

A `profiles` table with `role`, `is_admin`, `plan`, `credits` or `is_pro`, plus an "update own profile" policy, means users can set `is_admin = true` on themselves. Restrict columns:

```sql
revoke update on public.profiles from authenticated;
grant update (display_name, avatar_url, bio) on public.profiles to authenticated;
```

Or keep entitlements in a separate table that only the server (service role, or a webhook) writes.

`auth.jwt() -> 'user_metadata'` (and `raw_user_meta_data`) can be **edited by the user** through `supabase.auth.updateUser()`. Never authorize on it. Use `app_metadata` (server-set) or a roles table.

## Other checks

- **Views** run with their owner's rights and skip RLS: `create view … with (security_invoker = true)` (Postgres 15+).
- **Functions** in `public` are callable via `/rest/v1/rpc/` by `anon` by default. For `security definer` functions: check `auth.uid()` inside, add `set search_path = ''`, and `revoke execute on function public.fn from anon, public;` unless anonymous use is intended.
- **Storage**: private buckets for private files. Per-user folders:
  `create policy "own files" on storage.objects for all to authenticated using (bucket_id = 'docs' and (storage.foldername(name))[1] = (select auth.uid())::text);`
- **Edge Functions**: keep JWT verification on unless the function is a public webhook (then verify the webhook signature). Store secrets with `supabase secrets set`, not in code.
- **Auth settings**: email confirmation on, redirect URLs as an exact allowlist, CAPTCHA if signup grants free credits, leaked-password protection.
- **Realtime**: broadcast/presence channels and Postgres Changes respect RLS only if configured. Check for private channels.
- **Backups**: daily backups come with paid plans; add PITR for anything with paying users. Free projects pause when idle and don't include backups, so export regularly with `supabase db dump`.
- **Spend cap**: keep it on, or set billing alerts, before a launch spike.

## Server code

- Next.js / SSR: `@supabase/ssr` with cookies. On the server, check the user with `supabase.auth.getUser()` (verified by the Auth server) or `getClaims()`, not `getSession()` alone, which reads unverified cookie data.
- Server code that uses the service role must do its own authorization checks: RLS no longer protects you there.
