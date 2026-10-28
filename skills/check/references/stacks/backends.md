# Backends: Express, Hono, Fastify, NestJS, FastAPI, Flask, Django

## Node (Express / Hono / Fastify / Nest)

- **Auth on every route that touches user data**: a middleware that sets `req.user`, *and* an ownership check in the handler (`where: { id, userId: req.user.id }`).
- **Validate input** with zod/valibot (Nest: `ValidationPipe` with `whitelist: true, forbidNonWhitelisted: true`).
- **No mass assignment**: `User.update(req.body)` lets users send `{ "role": "admin" }`. Pick fields explicitly.
- **Mongo operator injection**: `User.findOne({ email: req.body.email, password: req.body.password })` with `{ "$ne": null }` logs in as anyone. Validate that values are strings. Never compare plaintext passwords.
- **SQL**: parameters (`$1`, `?`), or the ORM. `$queryRawUnsafe` and `knex.raw` with template strings are injection.
- **JWT**: `jwt.verify(token, secret, { algorithms: ['HS256'] })`, never `jwt.decode()` for auth. Secrets come from env and are long and random.
- **Baseline hardening**:
  ```js
  app.disable('x-powered-by');
  app.use(helmet());
  app.use(cors({ origin: ['https://myapp.com'], credentials: true }));
  app.use(express.json({ limit: '100kb' }));
  app.use('/api/', rateLimit({ windowMs: 60_000, limit: 100 }));
  ```
  Stricter limits on `/login`, `/signup`, `/forgot-password`, OTP and any AI/email/SMS endpoint.
- **Errors**: a final error handler that logs the details and returns a generic message. Run with `NODE_ENV=production`. No stack traces in responses.
- **Uploads** (multer / busboy): size limits, a type allowlist, random filenames, stored outside the web root or in private object storage.
- **Shell**: `execFile`/`spawn` with an args array; never `exec` with template strings.

## Python

- **FastAPI**: protect routers with `dependencies=[Depends(get_current_user)]`; pydantic models for all bodies; `CORSMiddleware(allow_origins=[...])`, never `["*"]` with `allow_credentials=True`; `slowapi` for rate limits; hide `/docs` in production if the API isn't public (`docs_url=None`).
- **Flask**: `debug=False` in production (the debugger allows remote code execution); `SECRET_KEY` from env; `flask-limiter`; `flask-cors` with explicit origins (bare `CORS(app)` allows every origin); CSRF protection for cookie sessions (Flask-WTF).
- **Django**: `DEBUG = False`, `ALLOWED_HOSTS` set, `SECRET_KEY` from env, `SECURE_*` and `SESSION_COOKIE_SECURE` on. Run `python manage.py check --deploy` (the user runs it). Use the ORM; with `raw()`/`extra()` always pass params.
- **SQL**: `cursor.execute("... WHERE id = %s", (user_id,))`, never f-strings, `%` or `+`. SQLAlchemy: `text("... :id")` with params.
- **Subprocess**: no `shell=True`, no `os.system(f"...")`.
- **Pickle / yaml.load** on untrusted input means remote code execution. Use `json` or `yaml.safe_load`.
- **Streamlit / Gradio**: `share=True` and public Spaces expose the app to everyone. Add auth, and keep keys in `st.secrets` or env (`.streamlit/secrets.toml` gitignored).
