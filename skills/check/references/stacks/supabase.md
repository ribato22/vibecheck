# Supabase

## The one thing to understand

The browser uses the **anon / publishable key**, which is public by design. Data access depends on the schemas exposed through the Data API, the effective grants for the request's role, and Row Level Security (RLS) policies. The `public` schema name or an RLS flag alone doesn't prove that anyone can read or change data. Private data exposed to API roles needs effective RLS and scoped grants.

| Key | Where it may live |
|---|---|
| `anon` JWT / `sb_publishable_…` | Browser is expected; restrict data access with API exposure, grants and RLS policies |
| `service_role` JWT / `sb_secret_…` | Server only. It bypasses all RLS. Never in client code, never behind `NEXT_PUBLIC_`/`VITE_`/`EXPO_PUBLIC_` |

## Verify (give these to the user; you don't run them)

First confirm which schemas the Data API exposes and the effective privileges of `anon` and `authenticated` for each operation. Migrations can show intended grants and policies; dashboard-only changes remain `UNVERIFIED` until the owner supplies evidence.

The scanner's missing-RLS, view and definer checks retain `public` coverage and add schema names from literal `api.schemas` arrays in the closest enclosing project's `supabase/config.toml`, written as `schemas = [...]` under `[api]` or as a top-level dotted `api.schemas = [...]` key. Explicit RLS-disable and policy leads can appear outside that configured scope. Local config describes intended scope, not the deployed API. Compare it with the deployment's exposed-schema settings; review dynamic or otherwise unrecognized declarations manually. Unreadable or unsupported config retains `public` coverage.

Inventory table RLS flags. Replace `('public', 'api')` in both queries below with the schemas the owner needs to inspect, including every deployed exposed schema:

```sql
select n.nspname as schemaname, c.relname as table_name,
       c.relrowsecurity as rls_enabled
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname in ('public', 'api') and c.relkind in ('r', 'p')
order by schemaname, rls_enabled, table_name;
```

Every policy, to read through:

```sql
select schemaname, tablename, policyname, cmd, roles,
       qual as using_expr, with_check
from pg_policies
where schemaname in ('public', 'api')
order by schemaname, tablename, policyname;
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

   For a custom exposed schema such as `api`, add `Accept-Profile: api` for GET/HEAD. For POST/PATCH/PUT/DELETE checks use `Content-Profile: api`. Repeat for each relevant exposed schema; an error caused by selecting the wrong schema doesn't establish authorization.

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

- **Views** normally use their owner's privileges and RLS context for underlying tables. Verify the owner's RLS privileges, API exposure and effective SELECT grants before concluding that a view bypasses RLS or exposes private rows. Use `create view … with (security_invoker = true)` (Postgres 15+) when callers should use their own privileges.
- **Functions** eligible for RPC in exposed schemas may be callable via `/rest/v1/rpc/` when the API role has the required schema and EXECUTE privileges, including PUBLIC/inherited grants. `security definer` uses the function owner's privileges; RLS bypass depends on that owner and the tables accessed. For private data, verify authorization inside the function, such as ownership checks using `auth.uid()`. Pin `search_path = ''`, schema-qualify references and limit EXECUTE to intended roles, allowing anonymous use only when intended.
- **Storage**: review bucket visibility and operation-specific policies using the [manual Storage checks](#storage-manual-vc-db-storage) below.
- **Edge Functions**: keep JWT verification on unless the function is a public webhook (then verify the webhook signature). Store secrets with `supabase secrets set`, not in code.
- **Auth settings**: email confirmation on, redirect URLs as an exact allowlist, CAPTCHA if signup grants free credits, leaked-password protection.
- **Realtime**: broadcast/presence channels and Postgres Changes respect RLS only if configured. Check for private channels.
- **Backups**: daily backups come with paid plans; add PITR for anything with paying users. Free projects pause when idle and don't include backups, so export regularly with `supabase db dump`.
- **Spend cap**: keep it on, or set billing alerts, before a launch spike.

The scanner follows straightforward static CREATE/ALTER security-mode declarations in lexical SQL-file and statement order, keeping function input signatures separate. It reads the declared source state, not an execution log: dynamic SQL, unusual signatures/type aliases, name resolution and dashboard-only changes still require manual review. Both view and definer findings remain `verify` leads until effective access is checked. A grant revocation alone does not establish that no inherited access remains.

## Storage (manual: VC-DB-STORAGE)

`VC-DB-STORAGE` requires manual review; it is not an automated bucket-access verdict. In a **public bucket**, anyone with the public object URL can retrieve its bytes without an RLS check. That flag doesn't automatically allow listing, uploads, overwrites or deletes. **Private buckets** apply access policies to retrieval too; private visibility still requires correct policies. A valid signed URL delegates access to its holder until expiry, so signed-out access through an intentionally issued URL is expected. Keep signed URLs out of public reports.

Give the owner these read-only inventory queries; the audit does not execute them:

```sql
select id, name, public from storage.buckets order by id;

select schemaname, tablename, policyname, roles, cmd, qual, with_check
from pg_policies
where schemaname = 'storage' and tablename = 'objects'
order by policyname;
```

Review each policy's bucket/path scope and operations, including other permissive policies that may broaden access. Upload needs an INSERT policy; upsert additionally needs SELECT and UPDATE access. If each user should manage only their own folder in a private `docs` bucket, a proposed migration could use this scope:

```sql
create policy "own docs folder" on storage.objects
for all to authenticated
using (
  bucket_id = 'docs'
  and (storage.foldername(name))[1] = (select auth.uid())::text
)
with check (
  bucket_id = 'docs'
  and (storage.foldername(name))[1] = (select auth.uid())::text
);
```

This example allows all four row operations within that folder; choose separate policies when intended permissions differ. It doesn't change bucket visibility or cancel broader existing policies. Review it as a migration proposal, not a command to run during the audit.

Have the owner test their own project with synthetic files and accounts A/B, using normal public/user credentials rather than a service key:

1. Put a known synthetic private file under A's intended folder, record its contents/path, and confirm A can perform the intended operations.
2. While signed out and as B, test listing A's prefix, authenticated download of A's file, and its direct public URL separately. Private metadata/bytes must remain inaccessible to unauthorized callers. A public bucket's intended public asset should remain retrievable by URL; test listing separately against the intended policy.
3. Swap B's target path to A's folder for a new upload, an update/upsert of the known file, and deletion. Unauthorized operations must create no object and leave A's existing path and contents unchanged. Check the state as A afterward; a status code alone is insufficient.
4. Check who can create a signed URL for A's private file. Unauthorized B/signed-out requests must fail. Deliberately share an authorized URL for the synthetic file, verify intended access while valid, then check a fresh request after expiry. Expiry doesn't erase bytes a recipient already downloaded.

Record visibility, actor, operation/path, expected/actual result and time without credentials or signed tokens. Effective Storage access and deployed schema settings remain `UNVERIFIED` until evidence is supplied. Sources: [bucket access models](https://supabase.com/docs/guides/storage/buckets/fundamentals), [Storage access policies](https://supabase.com/docs/guides/storage/security/access-control), [custom schemas](https://supabase.com/docs/guides/api/using-custom-schemas), [schema profile headers](https://docs.postgrest.org/en/stable/references/api/schemas.html).

## Server code

- Next.js / SSR: `@supabase/ssr` with cookies. On the server, check the user with `supabase.auth.getUser()` (verified by the Auth server) or `getClaims()`, not `getSession()` alone, which reads unverified cookie data.
- Server code that uses the service role must do its own authorization checks: RLS no longer protects you there.
