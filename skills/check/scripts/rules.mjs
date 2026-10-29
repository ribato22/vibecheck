// vibecheck rule library, shared by scan.mjs (the audit) and hooks/guard.mjs (the live guard). vibecheck-ignore-file
// Every rule is a plain regex on purpose: anyone can read and audit all of them in a few minutes.

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
export const SEVERITY_RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));

// Values that look like docs placeholders rather than real credentials.
const PLACEHOLDER =
  /x{4,}|\*{4,}|\.{3}|…|<[^>]*>|your|example|sample|dummy|placeholder|changeme|replace.?me|redacted|fake|test123|0{8,}|1234567890|abcdefghij/i;

export function isPlaceholder(value) {
  return PLACEHOLDER.test(value);
}

// ---------------------------------------------------------------------------
// Secrets. `guard: true` = precise enough to block a commit or a file write.
// ---------------------------------------------------------------------------

const ROTATE = 'Revoke/rotate this key in the provider dashboard, then load it from a server-only env var.';

export const SECRET_RULES = [
  { id: 'VC-KEY-PRIVATE', title: 'Private key', severity: 'critical', guard: true,
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/ },
  { id: 'VC-KEY-AWS', title: 'AWS access key', severity: 'critical', guard: true,
    re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { id: 'VC-KEY-STRIPE', title: 'Stripe/Clerk live secret key', severity: 'critical', guard: true,
    re: /\b(?:sk|rk)_live_[0-9A-Za-z]{20,}/ },
  { id: 'VC-KEY-STRIPE-TEST', title: 'Stripe/Clerk test secret key', severity: 'medium',
    re: /\b(?:sk|rk)_test_[0-9A-Za-z]{20,}/ },
  { id: 'VC-KEY-WEBHOOK-SECRET', title: 'Stripe webhook signing secret', severity: 'high', guard: true,
    re: /\bwhsec_[0-9A-Za-z+/=]{24,}/ },
  { id: 'VC-KEY-OPENAI', title: 'OpenAI API key', severity: 'critical', guard: true,
    re: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/ },
  { id: 'VC-KEY-ANTHROPIC', title: 'Anthropic API key', severity: 'critical', guard: true,
    re: /\bsk-ant-[A-Za-z0-9_-]{32,}/ },
  { id: 'VC-KEY-OPENROUTER', title: 'OpenRouter API key', severity: 'critical', guard: true,
    re: /\bsk-or-v1-[a-f0-9]{48,}/ },
  { id: 'VC-KEY-GROQ', title: 'Groq API key', severity: 'critical', guard: true,
    re: /\bgsk_[A-Za-z0-9]{40,}/ },
  { id: 'VC-KEY-XAI', title: 'xAI API key', severity: 'critical', guard: true,
    re: /\bxai-[A-Za-z0-9]{40,}/ },
  { id: 'VC-KEY-HUGGINGFACE', title: 'Hugging Face token', severity: 'high', guard: true,
    re: /\bhf_[A-Za-z0-9]{30,}/ },
  { id: 'VC-KEY-REPLICATE', title: 'Replicate API token', severity: 'high', guard: true,
    re: /\br8_[A-Za-z0-9]{37}\b/ },
  { id: 'VC-KEY-GITHUB', title: 'GitHub token', severity: 'critical', guard: true,
    re: /\bgh[pousr]_[A-Za-z0-9]{36,}|\bgithub_pat_[A-Za-z0-9_]{50,}/ },
  { id: 'VC-KEY-SLACK', title: 'Slack token', severity: 'high', guard: true,
    re: /\bxox[abposr]-[A-Za-z0-9-]{10,}/ },
  { id: 'VC-KEY-SENDGRID', title: 'SendGrid API key', severity: 'critical', guard: true,
    re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/ },
  { id: 'VC-KEY-SUPABASE-SECRET', title: 'Supabase secret key', severity: 'critical', guard: true,
    re: /\bsb_secret_[A-Za-z0-9_-]{20,}/ },
  { id: 'VC-KEY-GOOGLE-OAUTH', title: 'Google OAuth client secret', severity: 'high', guard: true,
    re: /\bGOCSPX-[A-Za-z0-9_-]{28}/ },
  { id: 'VC-KEY-MAILGUN', title: 'Mailgun API key', severity: 'high',
    re: /\bkey-[0-9a-f]{32}\b/ },
  { id: 'VC-KEY-SLACK-WEBHOOK', title: 'Slack webhook URL', severity: 'medium',
    re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{12,}/ },
  { id: 'VC-KEY-DISCORD-WEBHOOK', title: 'Discord webhook URL', severity: 'medium',
    re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]{20,}/ },
  { id: 'VC-KEY-GOOGLE', title: 'Google API key (Firebase / Maps / Gemini)', severity: 'medium', confidence: 'verify',
    re: /\bAIza[0-9A-Za-z_-]{35}\b/,
    fix: 'Firebase web config keys are public by design. If this is a Gemini or Maps key, anyone can use it: restrict it in Google Cloud Console (API + referrer restrictions) or move the call server-side.' },
];

export const SERVICE_ROLE_RULE = {
  id: 'VC-KEY-SUPABASE-SERVICE', title: 'Supabase service_role key (bypasses all RLS)', severity: 'critical', guard: true,
};
export const DB_URL_RULE = {
  id: 'VC-KEY-DB-URL', title: 'Database connection string with password', severity: 'high', guard: true,
};
export const GENERIC_RULE = {
  id: 'VC-KEY-GENERIC', title: 'Possible hardcoded secret', severity: 'medium', confidence: 'verify',
};

for (const rule of [...SECRET_RULES, SERVICE_ROLE_RULE, DB_URL_RULE, GENERIC_RULE]) {
  rule.category = 'secrets';
  rule.confidence ??= 'high';
  rule.fix ??= ROTATE;
}

const JWT_RE = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}/g;
const DB_URL_RE =
  /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?):\/\/([^\s:@/'"`]+):([^\s@'"`]+)@([^\s/'"`:?#]+)/g;
const DUMMY_PASSWORD = /^(?:pass(?:word)?|postgres|root|secret|admin|test|user|mysql|redis|guest|\$\{.*\}|\$\w+|%.*%|\{\{.*\}\})$/i;
const GENERIC_RE =
  /[\w-]*(?:secret|password|passwd|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret)[\w-]*["']?\s*[:=]\s*["'`]([^"'`\s]{12,})["'`]/i;

export function jwtRole(token) {
  try {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'))?.role ?? null;
  } catch {
    return null;
  }
}

function entropy(s) {
  const freq = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let h = 0;
  for (const n of Object.values(freq)) h -= (n / s.length) * Math.log2(n / s.length);
  return h;
}

function looksRandom(value) {
  return /\d/.test(value) && /[a-z]/i.test(value) && !/^https?:|\$\{|^process\.env|\//.test(value) && entropy(value) >= 3.3;
}

/** Secrets on one line of text. `guardOnly` keeps only rules precise enough to block on. */
export function findSecrets(line, { guardOnly = false } = {}) {
  if (line.length > 20000 || line.includes('vibecheck-ignore')) return [];
  const hits = [];
  for (const rule of SECRET_RULES) {
    if (guardOnly && !rule.guard) continue;
    const m = rule.re.exec(line);
    if (m && !isPlaceholder(m[0])) hits.push({ rule, value: m[0] });
  }
  for (const m of line.matchAll(JWT_RE)) {
    if (jwtRole(m[0]) === 'service_role') {
      hits.push({ rule: SERVICE_ROLE_RULE, value: m[0] });
      break;
    }
  }
  for (const m of line.matchAll(DB_URL_RE)) {
    const [url, , password, host] = m;
    const local = !host.includes('.') || /^(?:127\.|0\.0\.0\.0)/.test(host);
    if (local || isPlaceholder(url) || DUMMY_PASSWORD.test(password)) continue;
    hits.push({ rule: DB_URL_RULE, value: url });
    break;
  }
  if (!guardOnly && hits.length === 0) {
    const m = GENERIC_RE.exec(line);
    if (m && looksRandom(m[1]) && !isPlaceholder(m[1])) hits.push({ rule: GENERIC_RULE, value: m[1] });
  }
  return hits;
}

/** Show enough of a secret to recognise it, never enough to use it. */
export function mask(value) {
  const db = value.match(/^([a-z+]+:\/\/[^:]+:)[^@]+(@.*)$/i);
  if (db) return `${db[1]}****${db[2]}`;
  if (value.startsWith('-----BEGIN')) return value;
  if (value.length <= 12) return `${value.slice(0, 2)}…`;
  return `${value.slice(0, 4)}…${value.slice(-4)}`;
}

/** Mask every secret on a line so code snippets are safe to print. */
export function redact(line) {
  let out = line;
  for (const { value } of findSecrets(line)) out = out.split(value).join(mask(value));
  return out;
}

// ---------------------------------------------------------------------------
// Env var names that ship to the browser.
// ---------------------------------------------------------------------------

export const PUBLIC_ENV_RE = /\b(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|VUE_APP_|GATSBY_|PUBLIC_)([A-Z0-9_]+)/g;

const ALWAYS_SECRET =
  /SECRET|SERVICE_ROLE|SERVICE_KEY|PRIVATE|PASSWORD|PASSWD|DATABASE_URL|DB_URL|POSTGRES|MONGO|REDIS_URL|ADMIN_KEY|SK_LIVE/;
const PAID_PROVIDER =
  /OPENAI|ANTHROPIC|CLAUDE|GROQ|GEMINI|GOOGLE_AI|GOOGLE_GENERATIVE|MISTRAL|DEEPSEEK|OPENROUTER|REPLICATE|ELEVENLABS|PERPLEXITY|COHERE|TOGETHER|FIREWORKS|XAI|HUGGING|HF_|RESEND|SENDGRID|MAILGUN|POSTMARK|TWILIO|AWS|GITHUB|PINECONE|FIRECRAWL|TAVILY|SERPAPI|LEMON|PADDLE/;
const HAS_PUBLISHABLE_VARIANT = /STRIPE|CLERK/;
const KEYISH = /KEY|TOKEN|SECRET/;
const SAFE_PUBLIC =
  /ANON|PUBLISHABLE|PUBLIC_KEY|SITE_KEY|SITEKEY|MEASUREMENT|DSN|POSTHOG|MAPBOX|FIREBASE|MAPS|GA_|GTM|ONESIGNAL|ALGOLIA_(?:APP_ID|SEARCH)|PUSHER_(?:KEY|CLUSTER)|CLIENT_ID|APP_ID|PROJECT_ID|VAPID_PUBLIC/;

/** 'critical' | 'high' | null for an env var name (without its public prefix). */
export function classifyEnvName(name) {
  if (ALWAYS_SECRET.test(name)) return 'critical';
  if (SAFE_PUBLIC.test(name)) return null;
  if (PAID_PROVIDER.test(name) && KEYISH.test(name)) return 'critical';
  if (HAS_PUBLISHABLE_VARIANT.test(name) && KEYISH.test(name)) return 'high';
  if (/API_KEY|APIKEY|TOKEN|ACCESS_KEY|AUTH_KEY/.test(name)) return 'high';
  return null;
}

// ---------------------------------------------------------------------------
// Code patterns. These are leads: the agent must read the code and confirm.
// ---------------------------------------------------------------------------

const JS = ['js'];
const PY = ['py'];
const ANY = ['js', 'py', 'other'];

export const CODE_RULES = [
  { id: 'VC-AI-BROWSER', category: 'money', severity: 'critical', langs: JS,
    title: 'AI SDK is allowed to run in the browser',
    re: /dangerouslyAllowBrowser\s*:\s*true/g,
    fix: 'Anyone can copy the key from the page and bill you. Call the model from a server route with auth + rate limiting.' },
  { id: 'VC-AUTH-JWT-DECODE', category: 'auth', severity: 'high', langs: JS,
    title: 'JWT decoded without checking its signature',
    re: /\bjwt\.decode\s*\(/g,
    fix: 'jwt.decode() trusts whatever the user sends. On the server use jwt.verify(token, secret, { algorithms: [...] }).' },
  { id: 'VC-AUTH-JWT-DECODE', category: 'auth', severity: 'high', langs: PY,
    title: 'JWT signature verification turned off',
    re: /verify_signature["']?\s*:\s*False/g,
    fix: 'Remove verify_signature: False and pass the key + algorithms to jwt.decode().' },
  { id: 'VC-INJ-SQL', category: 'input', severity: 'high', langs: JS,
    title: 'SQL built from user-controlled string',
    re: /\.(?:query|execute|raw|exec|unsafe|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(\s*`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{/gi,
    fix: 'Use parameters ($1, ?) or a tagged sql`` template from your DB library instead of string interpolation.' },
  { id: 'VC-INJ-SQL', category: 'input', severity: 'high', langs: PY,
    title: 'SQL built with f-string / % / +',
    re: /\.execute(?:many)?\(\s*f["']|\btext\(\s*f["']|\.execute\(\s*["'][^"'\n]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"'\n]*["']\s*(?:%|\+|\.format\()/gi,
    fix: 'Pass values as parameters: cursor.execute("... WHERE id = %s", (user_id,)).' },
  { id: 'VC-INJ-MASS-ASSIGN', category: 'input', severity: 'high', langs: JS,
    title: 'Request body written straight to the database',
    re: /\.(?:update|insert|create|upsert)\s*\(\s*(?:\{\s*data\s*:\s*)?(?:req\.body|request\.body|await\s+req\.json\(\)|await\s+request\.json\(\))\s*[,)}]|(?:findByIdAndUpdate|findOneAndUpdate|updateOne|updateMany)\s*\([^,]+,\s*(?:req\.body|request\.body)\s*[,)]/g,
    fix: 'A user can add fields like role: "admin" or credits: 99999. Pick allowed fields explicitly (or validate with a zod schema) before writing.' },
  { id: 'VC-XSS-HTML', category: 'input', severity: 'medium', langs: JS,
    title: 'Raw HTML rendered',
    re: /dangerouslySetInnerHTML|v-html=|\{@html\s|\.innerHTML\s*=(?!=)/g,
    fix: 'If any part comes from users or an AI model, sanitize with DOMPurify first, or render as text.' },
  { id: 'VC-INJ-EVAL', category: 'input', severity: 'medium', langs: JS,
    title: 'eval / new Function',
    re: /(?<![$.\w])eval\s*\(|\bnew\s+Function\s*\(/g, // not Playwright's page.$eval / $$eval
    fix: 'Never evaluate strings that users or models can influence. Replace with JSON.parse or explicit logic.' },
  { id: 'VC-INJ-EVAL', category: 'input', severity: 'medium', langs: PY,
    title: 'eval / exec',
    re: /(?<![.\w])(?:eval|exec)\s*\(/g,
    fix: 'Never evaluate strings that users or models can influence. Use ast.literal_eval or explicit parsing.' },
  { id: 'VC-INJ-CMD', category: 'input', severity: 'high', langs: JS,
    title: 'Shell command built from a string',
    re: /\b(?:exec|execSync)\s*\(\s*`[^`]*\$\{/g,
    fix: 'Use execFile/spawn with an argument array and validate inputs against an allowlist.' },
  { id: 'VC-INJ-CMD', category: 'input', severity: 'high', langs: PY,
    title: 'Shell command built from a string',
    re: /\bos\.system\s*\(\s*f["']|subprocess\.\w+\([^)]*shell\s*=\s*True/g,
    fix: 'Use subprocess.run([...args]) without shell=True and validate inputs.' },
  { id: 'VC-CFG-CORS', category: 'config', severity: 'medium', langs: ANY,
    title: 'CORS allows every website',
    re: /Access-Control-Allow-Origin["']?\s*[,:]\s*["']\*["']|\borigin\s*:\s*["']\*["']|allow_origins\s*=\s*\[\s*["']\*["']\s*\]|CORS_(?:ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True|\bcors\(\s*\)|\bCORS\(\s*app\s*\)/g,
    fix: 'List your real front-end origins. A wildcard plus cookies/credentials lets any site act as your logged-in users.' },
  { id: 'VC-PAY-CLIENT-PRICE', category: 'money', severity: 'high', langs: ['js', 'py'],
    title: 'Payment amount taken from the request',
    re: /\b(?:unit_amount|amount|price)\s*:\s*(?:req\.body|request\.body|body|input|params|searchParams)(?:\.|\[)/g,
    requires: /stripe|checkout|payment|lemonsqueezy|paddle|midtrans|xendit/i,
    fix: 'Users can edit the request and pay Rp1 / $0.01. Look the price up on the server from a product/price ID.' },
  { id: 'VC-CFG-DEBUG', category: 'config', severity: 'medium', langs: PY,
    title: 'Debug mode on',
    re: /app\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True/gm,
    fix: 'Debug pages leak source code and secrets. Read DEBUG from an env var and keep it False in production.' },
  { id: 'VC-CFG-TLS-OFF', category: 'config', severity: 'medium', langs: ANY,
    title: 'TLS certificate checks disabled',
    re: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|\bverify\s*=\s*False/g,
    fix: 'Turning off certificate checks lets anyone on the network read and change the traffic. Remove it.' },
  { id: 'VC-AUTH-TOKEN-STORAGE', category: 'auth', severity: 'low', langs: JS,
    title: 'Auth token stored in localStorage',
    re: /localStorage\.setItem\(\s*["'`][^"'`]*(?:token|jwt|session|auth)/gi,
    fix: 'Any XSS bug can steal it. Prefer httpOnly cookies (most auth libraries do this for you).' },
  { id: 'VC-INJ-SSRF', category: 'input', severity: 'medium', langs: JS,
    title: 'Server fetches a URL chosen by the user',
    re: /\b(?:fetch|axios\.(?:get|post)|got)\(\s*(?:req\.(?:body|query)|request\.(?:body|query)|searchParams\.get\()/g,
    fix: 'Attackers can make your server call internal addresses. Allowlist hosts before fetching.' },
  { id: 'VC-AUTH-OPEN-REDIRECT', category: 'auth', severity: 'medium', langs: JS,
    title: 'Redirect target comes from the URL',
    re: /\bredirect\(\s*(?:req\.query\.\w+|searchParams\.get\(|request\.nextUrl\.searchParams\.get\()/g,
    fix: 'Phishers can send people through your login to their site. Only allow relative paths that start with a single "/".' },
  { id: 'VC-CFG-SOURCEMAPS', category: 'config', severity: 'low', langs: JS,
    title: 'Production source maps published',
    re: /productionBrowserSourceMaps\s*:\s*true|\bsourcemap\s*:\s*true/g,
    path: /(?:^|\/)(?:next|vite|nuxt|astro|svelte)\.config\.[cm]?[jt]s$/,
    fix: 'Source maps hand your full front-end source to anyone. Disable them or upload them privately to your error tracker.' },
  { id: 'VC-CFG-IMAGES-WILDCARD', category: 'money', severity: 'low', langs: JS,
    title: 'Image optimizer accepts any host',
    re: /hostname\s*:\s*["']\*\*["']/g,
    path: /(?:^|\/)next\.config\.[cm]?[jt]s$/,
    fix: 'Anyone can use your image optimizer (and your bandwidth bill) for any image on the internet. List the hosts you use.' },
  { id: 'VC-ENV-BUNDLED', category: 'secrets', severity: 'critical', langs: JS,
    title: 'All env vars bundled into the front-end',
    re: /["']process\.env["']\s*:\s*(?:JSON\.stringify\()?process\.env\b|envPrefix\s*:\s*(?:["']["']|\[[^\]]*["']["'])/g,
    path: /(?:^|\/)vite\.config\.[cm]?[jt]s$/,
    fix: 'Every secret in your environment ships to the browser. Only expose the specific public VITE_ vars you need.' },
];

for (const rule of CODE_RULES) rule.confidence ??= 'verify';
