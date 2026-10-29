# Host checklists

Check the section for the app's host. Items marked ⚙ are also checked by the preflight. Everything else needs the code, the host dashboard, or the user.

## Every host

- Production env vars set with production values: live payment keys, the production database, the production site URL ⚙
- Build reproduces locally from a clean install: `npm ci && npm run build`. Suggest it to the user; don't run it during the audit.
- Same Node major version locally and on the host ⚙
- One lockfile, committed ⚙
- Database migrations applied to the production database ⚙ (reminder)
- Auth: production domain in the provider's redirect/callback allowlist; production auth secret set ⚙ (reminder)
- Webhooks (Stripe, Midtrans, Xendit, GitHub…) point at the production URL and use the production signing secret ⚙ (reminder)
- CORS allowlist and cookie domains include the production origin ⚙ (reminder)
- A custom domain has DNS pointing at the host, and HTTPS is active
- You know where the production logs are, and you check them after the first deploy

## Vercel

- Env vars are per environment (Production, Preview, Development). A variable set only for Preview is `undefined` in Production.
- List names: `vercel env ls production`. Don't use `vercel env pull` in an audit, because it downloads values.
- Monorepo: set the project's Root Directory to the app folder.
- Node version: Project Settings → Build and Deployment, or `"engines"` in package.json.
- Functions have no persistent disk: no SQLite file, no uploads to local folders ⚙
- Functions have a maximum duration: long jobs need a queue or a background worker, and scheduled jobs need Vercel Cron.
- Edge runtime (`export const runtime = 'edge'`, middleware) has no Node APIs such as `fs` or native modules.
- Prisma: generate during the build ⚙. With Supabase Postgres, use the pooled connection for queries and a direct URL for migrations ⚙ (reminder).
- Logs: the project's Logs tab, or `vercel logs <deployment-url>`.

## Netlify

- Env vars: Site configuration → Environment variables. Check the scopes (Builds, Functions, Runtime) and deploy contexts (Production, Deploy Previews).
- Node version: `NODE_VERSION` env var, `.nvmrc` or `"engines"` ⚙
- Next.js and other frameworks run through Netlify's adapters: check the framework version is supported.
- Functions have a timeout and no persistent disk ⚙
- Redirects and SPA fallback: `_redirects` or `[[redirects]]` in netlify.toml (`/* /index.html 200` for single-page apps), or deep links give 404.
- Logs: the dashboard's Logs section (Functions and Deploys).

## Cloudflare (Workers / Pages)

- Secrets: `wrangler secret list`. Plain vars go in `[vars]` in wrangler.toml, or in the Pages project settings.
- Workers aren't Node: Node built-ins need the `nodejs_compat` flag, and there is no filesystem ⚙
- Local secrets live in `.dev.vars`, which must never be committed.
- Logs: `wrangler tail`.

## Railway

- Variables are per service (Variables tab). Shared variables must be referenced in each service.
- The app must listen on `$PORT` ⚙ and bind 0.0.0.0 ⚙
- Start command: `npm start` or a custom start command ⚙
- The disk resets on redeploy unless you attach a Volume (needed for SQLite or uploads).
- Logs: the service's Deployments → Logs, or `railway logs`.

## Render

- Env vars: the service's Environment tab. Render sets `PORT` for web services ⚙
- Build and start commands in the service settings ⚙
- Free instances sleep when idle and wake slowly on the first request: expect a slow first load.
- The disk is ephemeral unless you add a persistent disk (paid).
- Logs: the service's Logs tab.

## Fly.io

- Secrets: `fly secrets list` (names only). Non-secret env goes in `[env]` in fly.toml.
- `internal_port` in fly.toml must match the port the app listens on; bind 0.0.0.0 ⚙
- SQLite needs a Fly Volume, or move to a hosted database.
- Logs: `fly logs`.

## Heroku

- Config Vars in Settings, or `heroku config` (prints values: avoid it in an audit).
- `Procfile` with a `web:` process, listening on `$PORT` ⚙
- The filesystem is ephemeral: it resets at least daily and on every deploy ⚙
- Logs: `heroku logs --tail`.

## Docker (any host)

- `.dockerignore` excludes `.env*`, `node_modules`, `.git` and `.vibecheck` (see `/vibecheck:check`).
- Don't `COPY .env` or bake secrets into the image: pass env vars at runtime.
- Bind 0.0.0.0 inside the container ⚙; `EXPOSE` and the published port match the app's port.
- Node version in `FROM node:XX` matches local ⚙
- Logs: `docker logs <container>`, or the platform's log view.

## Python apps

- Pin dependencies in requirements.txt or pyproject.toml, and the Python version (`.python-version` or the host setting).
- Start with a production server: `gunicorn app:app` or `uvicorn main:app --host 0.0.0.0 --port $PORT`, not `app.run()` / `debug=True`.
- Django: `DEBUG=False`, `ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS`, static files collected (`collectstatic`, WhiteNoise or a CDN), `python manage.py migrate` on the production database.
