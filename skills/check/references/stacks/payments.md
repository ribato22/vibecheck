# Payments: Stripe, Lemon Squeezy, Paddle, Midtrans, Xendit

## The rules

1. **The server decides the price.** The client sends a product or price ID; the server looks up the amount. Never `unit_amount: body.price`.
2. **The webhook decides who paid.** Grant access in the webhook handler after verifying the signature, never on the success/redirect page (anyone can open `/success?session_id=…` or `?status=paid`).
3. **Verify every webhook signature on the raw body.**
4. **Check entitlements on the server**, from your database, on every paid action, not from a client flag.
5. **Handle duplicates and order**: store processed event IDs and ignore repeats; also handle cancellations, refunds, failed renewals and chargebacks.

## Stripe

```ts
// app/api/stripe/webhook/route.ts (Next.js App Router)
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(req: Request) {
  const body = await req.text();                       // raw body: don't use req.json() first
  const sig = req.headers.get('stripe-signature')!;
  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET!);
  } catch {
    return new Response('Invalid signature', { status: 400 });
  }
  if (await alreadyProcessed(event.id)) return new Response('ok');
  switch (event.type) {
    case 'checkout.session.completed': /* grant access for session.client_reference_id */ break;
    case 'customer.subscription.updated':
    case 'customer.subscription.deleted': /* sync status */ break;
    case 'invoice.payment_failed': /* notify, downgrade later */ break;
  }
  return new Response('ok');
}
```

- Express: mount `express.raw({ type: 'application/json' })` on the webhook route **before** `express.json()`.
- Create Checkout Sessions on the server with `line_items: [{ price: 'price_…', quantity: 1 }]`, and pass your user ID as `client_reference_id` or `metadata`.
- `sk_live_` / `rk_live_` server only; `pk_live_` is fine in the browser. Prefer restricted keys (`rk_`) with only the permissions you need.
- Test and live mode have different keys **and different webhook secrets**. Production must use live ones.
- Offer the Customer Portal so users can cancel without emailing you.

## Lemon Squeezy / Paddle

- Lemon Squeezy: verify `X-Signature` = HMAC-SHA256 of the raw body with your signing secret, using a constant-time compare.
- Paddle Billing: verify the `Paddle-Signature` header (`ts` + `h1`) with the SDK's `webhooks.unmarshal()`, or compute HMAC-SHA256 over `ts:rawBody`.
- In both cases, look up which user paid from data you set server-side (custom data or passthrough), not from the redirect.

## Midtrans (Indonesia)

- Never trust the Snap `onSuccess` callback or the `finish` redirect URL. Fulfil from the **HTTP notification** (webhook).
- Verify `signature_key` = `SHA512(order_id + status_code + gross_amount + ServerKey)`, or better, call the Get Status API with your server key and act on the returned `transaction_status` (`settlement`/`capture` with `fraud_status: accept`).
- The **Server Key** is server only. The Client Key is fine in the browser.
- Check that `gross_amount` matches the order amount stored in your DB.

## Xendit (Indonesia)

- Verify the `x-callback-token` header equals your Callback Verification Token (from the dashboard) before trusting any callback.
- Confirm status and amount against your own invoice record (or fetch the invoice via API) before granting access.
- The Secret API key is server only. Separate test and live keys.

## Checklist

- [ ] Amount and currency computed server-side
- [ ] Webhook signature verified on the raw body
- [ ] Access granted only from the webhook (or a server-side status check)
- [ ] Idempotent handler (event or order ID stored)
- [ ] Cancellation, refund, failed payment and chargeback handled
- [ ] Secret keys server-only; test and live separated
- [ ] Paid features check entitlement on the server
