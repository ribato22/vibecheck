# Mobile: Expo / React Native / Flutter

## Everything in the app is public

The JS bundle (or Dart snapshot) can be pulled out of the APK/IPA in minutes. Treat every value in the app, including `EXPO_PUBLIC_*`, `app.json` `extra`, `--dart-define`, `google-services.json` and hardcoded strings, as published.

- Only publishable keys belong in the app (Supabase anon/publishable, Firebase config, Stripe `pk_`, RevenueCat public SDK key).
- Anything secret (OpenAI, Stripe `sk_`, Supabase `service_role`, SendGrid, admin tokens) goes behind your backend or an edge function with auth and rate limits.
- Over-the-air updates (EAS Update, CodePush) ship JS to every user: the same rule applies.

## Storage

- Tokens: `expo-secure-store`, Keychain/Keystore, or `flutter_secure_storage`. Not `AsyncStorage` / `SharedPreferences`, which are plain files.
- Don't cache sensitive data unencrypted. Clear it on logout.

## Deep links & WebViews

- Deep-link parameters are attacker-controlled: validate them and never auto-perform actions (payments, account changes) from a link.
- Use verified universal links / app links for auth callbacks. Custom schemes can be hijacked by other apps.
- WebViews: restrict `originWhitelist`, don't inject tokens into pages you don't control, and keep `javaScriptEnabled` only where needed.

## Backend still decides

Your RLS, rules and API checks matter *more* in mobile, because anyone can call your backend without the app. Everything in `supabase.md` / `firebase.md` / `backends.md` applies.

## Store requirements that block launches

- **Account deletion**: Apple requires in-app account deletion for apps that support account creation; Google Play requires a deletion path and a web link.
- Privacy policy URL, plus the privacy "nutrition label" / Data safety form, filled in truthfully (including AI providers and analytics SDKs).
- Apple Guideline 4.8: if you offer third-party social login, you may also need a privacy-focused login option such as Sign in with Apple.
- In-app purchases: digital goods generally must use store billing (rules vary by region). Verify purchases on the server (RevenueCat, or App Store Server API / Play Developer API), never trust the client receipt alone.
