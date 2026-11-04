# Supabase

## The one thing to understand

The browser uses the **anon / publishable key**, which is public by design. Data access depends on the schemas exposed through the Data API, the effective grants for the request's role, and Row Level Security (RLS) policies. The `public` schema name or an RLS flag alone doesn't prove that anyone can read or change data. Private data exposed to API roles needs effective RLS and scoped grants.

| Key | Where it may live |
|---|---|
| `anon` JWT / `sb_publishable_…` | Browser is expected; restrict data access with API exposure, grants and RLS policies |
| `service_role` JWT / `sb_secret_…` | Server only. It bypasses all RLS. Never in client code, never behind `NEXT_PUBLIC_`/`VITE_`/`EXPO_PUBLIC_` |

## Verify (give these to the user; you don't run them)

First confirm which schemas the Data API exposes and the effective privileges of `anon` and `authenticated` for each operation. Migrations can show intended grants and policies; dashboard-only changes remain `UNVERIFIED` until the owner supplies evidence.

Inventory table RLS flags. Paste into the dashboard's SQL Editor:

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

## Owner-run access checks

Give these steps to the owner for their own project, using synthetic records. The audit does not run them. Record deployed results as `UNVERIFIED` until the owner provides the tested role, resource, operation, expected/actual result and time, with credentials redacted.

1. Create test accounts A and B and a private synthetic record owned by A. Confirm A can perform the intended operations on it.
2. Without a user session, use the public publishable/anon key to request the private record. It must not be returned. For example:

   ```bash
   curl "https://<project-ref>.supabase.co/rest/v1/<table>?id=eq.<record-A-id>&select=*&limit=1" \
     -H "apikey: <publishable-or-anon-key>"
   ```

3. Sign in as B and replace a record ID with A's known private record ID. Test read, update and delete separately through the relevant app/API paths. No private data should be returned and A's record must remain unchanged. Repeat with the accounts swapped where applicable.
4. Confirm intentionally public data is still readable by the intended roles, while private data and unauthorized writes remain blocked.

Use public/user credentials for these checks. The SQL Editor, a table owner or service-role/secret key can have privileges that normal API users lack. A returned row proves access to that row; an empty response alone doesn't establish that every resource and operation is protected.

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
- For roles subject to RLS, no applicable policy denies row access: SELECT may return `[]`, while writes may fail or affect no rows. Ship the intended policies in the same migration.
- Public content (published posts, a product catalog): `for select to anon, authenticated using (published = true)`. Never `using (true)` on anything private.

## Privilege escalation: the bug AI writes most

If users have UPDATE privileges on `role`, `is_admin`, `plan`, `credits` or `is_pro`, an "update own profile" policy alone lets them change those values on themselves. Restrict columns:

```sql
revoke update on public.profiles from authenticated;
grant update (display_name, avatar_url, bio) on public.profiles to authenticated;
```

Or keep entitlements in a separate table that only the server (service role, or a webhook) writes.

`auth.jwt() -> 'user_metadata'` (and `raw_user_meta_data`) can be **edited by the user** through `supabase.auth.updateUser()`. Never authorize on it. Use `app_metadata` (server-set) or a roles table.

## Other checks

- **Views** normally run with their owner's rights and may bypass underlying RLS. Check API exposure and grants; use `create view … with (security_invoker = true)` (Postgres 15+) when callers should use their own privileges.
- **Functions** in exposed schemas are callable via `/rest/v1/rpc/` when the API role has EXECUTE privilege, including grants inherited from `PUBLIC`. For `security definer` functions: check `auth.uid()` inside, add `set search_path = ''`, and `revoke execute on function public.fn from anon, public;` unless anonymous use is intended.
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
