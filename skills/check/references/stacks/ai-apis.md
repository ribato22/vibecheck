# AI / LLM APIs: OpenAI, Anthropic, Gemini, Groq, OpenRouter, Vercel AI SDK

## Denial of wallet: your bill is the attack surface

An AI endpoint without limits is a credit card anyone can swipe. Typical incidents: a key in the JS bundle, `dangerouslyAllowBrowser: true`, a public `/api/chat` with no auth, or a free tier with no per-user quota.

1. **Server only.** The browser calls *your* route; your route calls the provider. Never ship provider keys to the client, and never use `dangerouslyAllowBrowser: true` in production.
2. **Require auth** on AI routes, or for anonymous demos use a strict IP limit plus CAPTCHA/Turnstile.
3. **Rate limit per user and per IP**, plus a daily per-user quota stored in your DB.
4. **Cap the cost of each request**: set max output tokens, cap input length, cap conversation history, cap agent/tool steps (`maxSteps` / `stopWhen` in the AI SDK), and pick the model on the server (don't accept a model name from the client).
5. **Hard spend limits at the provider**: OpenAI project budgets and usage limits, Anthropic workspace spend limits, Google Cloud budgets **plus quotas** (budgets alone don't stop spending), OpenRouter key credit limits. Separate keys per environment and per app.

```ts
// Upstash rate limit: works on Vercel / serverless
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const ratelimit = new Ratelimit({ redis: Redis.fromEnv(), limiter: Ratelimit.slidingWindow(20, '1 h') });

export async function POST(req: Request) {
  const user = await getUser();
  if (!user) return new Response('Unauthorized', { status: 401 });
  const { success } = await ratelimit.limit(`chat:${user.id}`);
  if (!success) return new Response('Too many requests', { status: 429 });
  const { message } = await req.json();
  if (typeof message !== 'string' || message.length > 4000) return new Response('Bad request', { status: 400 });
  // ... call the model with maxOutputTokens / max_tokens set
}
```

Long-running Node servers: `express-rate-limit` or `rate-limiter-flexible`. Python: `slowapi` (FastAPI), `flask-limiter`.

## Prompt injection

Treat everything the model reads (user messages, web pages, PDFs, emails, tool results) as untrusted input that may contain instructions.

- **Tools re-check authorization in code.** If the model can call `deleteDocument(id)`, the tool implementation must confirm the *current user* owns `id`. Never rely on the prompt to enforce permissions.
- Don't give the model credentials, a DB admin client or a shell it can steer. Least-privilege tools, scoped to the user.
- Ask a human to confirm before sending email, spending money or deleting data.
- **System prompts leak.** Put no secrets, keys, internal URLs or "hidden rules you'd hate to see on Twitter" in them.
- Render model output as text or sanitized markdown. Never `dangerouslySetInnerHTML` raw output. Don't auto-load image URLs from model output in sensitive contexts: that can exfiltrate data through the query string.

## Data

- Don't log full prompts or responses with personal data. If you do, set retention.
- Tell users in the privacy policy which AI providers process their data.
- BYO-key apps: store user keys encrypted, never log them, and send them only to the provider.

## Version gotchas (useful for `unstuck` too)

- AI tools often write code for a different SDK version (OpenAI v3 `Configuration` vs v4+ client, AI SDK v4 vs v5 renames) or invent model names. Check the installed version and the provider's current model list.
