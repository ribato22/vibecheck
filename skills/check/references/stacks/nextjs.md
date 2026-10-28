# Next.js

## Secrets

- Only `NEXT_PUBLIC_*` vars reach the browser, and they're **inlined at build time**. Changing one needs a rebuild, and any secret with that prefix is public.
- Values listed under `env:` in `next.config.js` are inlined too.
- Add `import 'server-only'` at the top of modules that read secrets or use the DB/admin SDKs. A client import then fails the build instead of leaking.
- Props passed from Server to Client Components are serialized into the page. Don't pass whole DB rows (password hashes, emails, internal flags). Map to the fields the UI needs.

## Server Actions and Route Handlers are public endpoints

- Every exported function in a `'use server'` file can be called by anyone with a POST request, whether or not your UI shows a button for it. Each one needs: auth check, ownership check, input validation.
- `app/**/route.ts` handlers likewise. Check them one by one.

```ts
'use server';
import { z } from 'zod';
const Input = z.object({ noteId: z.string().uuid(), text: z.string().max(5000) });

export async function updateNote(raw: unknown) {
  const user = await getUser();                 // verified on the server
  if (!user) throw new Error('Unauthorized');
  const { noteId, text } = Input.parse(raw);
  await db.note.update({ where: { id: noteId, userId: user.id }, data: { text } }); // ownership in the query
}
```

## Middleware isn't enough

- Middleware (`middleware.ts`, renamed `proxy.ts` in Next 16) is fine for redirects, but **don't make it the only auth check**. CVE-2025-29927 let attackers skip it with an `x-middleware-subrequest` header (fixed in 15.2.3 / 14.2.25 / 13.5.9 / 12.3.5), and matcher gaps are common. Check auth in the data layer, route handler or server action too.
- Layouts don't re-run on every navigation and don't protect server actions. Check in the page, action or data function.
- Check the installed `next` version in `node_modules/next/package.json` against current security advisories.

## Caching leaks

User-specific data inside `unstable_cache`, `'use cache'`, `fetch(..., { cache: 'force-cache' })`, ISR, or a CDN-cached route can be served to **other** users. Anything that depends on cookies or the session must be dynamic or cached per user.

## Config

```js
// next.config.js: baseline security headers
const securityHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
];
module.exports = { async headers() { return [{ source: '/(.*)', headers: securityHeaders }]; } };
```

- `images.remotePatterns` with `hostname: '**'` turns your optimizer into a free image proxy on your bill.
- `productionBrowserSourceMaps: true` publishes your source.
- Redirect after login (`?next=`, `callbackUrl`): accept only relative paths starting with a single `/`.
- `dangerouslySetInnerHTML` with markdown or AI output: sanitize first.
