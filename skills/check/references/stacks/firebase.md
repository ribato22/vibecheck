# Firebase

## The one thing to understand

The web config (`apiKey`, `projectId`, …) is public by design. **Security Rules** are the only thing protecting Firestore, Realtime Database and Storage from anyone who opens DevTools. The Admin SDK (`firebase-admin`, service-account JSON with `private_key`) bypasses all rules, so it's server only.

## Red flags in rules

| Rule | Meaning | Severity |
|---|---|---|
| `allow read, write;` or `allow read, write: if true;` | Anyone can read, change, delete everything | critical |
| `allow read, write: if request.time < timestamp.date(…)` | "Test mode": wide open until the date, then broken | critical |
| `allow read, write: if request.auth != null;` | Any signed-up stranger can read and change everyone's data | high |
| `".read": true` / `".write": true` (Realtime DB) | Public | critical / high |
| Rules that never mention `request.auth.uid` | Probably not owner-scoped | review |

## Owner-scoped rules

```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
    match /posts/{postId} {
      allow read: if resource.data.published == true;
      allow create: if request.auth != null
        && request.resource.data.authorId == request.auth.uid;
      allow update, delete: if request.auth != null
        && resource.data.authorId == request.auth.uid;
    }
  }
}
```

**Stop self-upgrades**: users editing their own `role` / `isPremium` / `credits`:

```
allow update: if request.auth.uid == userId
  && request.resource.data.diff(resource.data).affectedKeys()
       .hasOnly(['displayName', 'photoURL']);
```

Keep entitlements in docs only the server (Admin SDK, e.g. from a payment webhook) writes, or in custom claims.

Storage rules: the same idea, with paths like `match /users/{uid}/{file=**} { allow read, write: if request.auth.uid == uid; }`, plus size and type limits (`request.resource.size < 5 * 1024 * 1024`, `request.resource.contentType.matches('image/.*')`).

## Other checks

- **API key restrictions**: in Google Cloud Console → Credentials, restrict the browser key to your domains and to only the APIs it needs. If the Gemini (Generative Language) API or Maps is enabled on the same project, an unrestricted browser key may be usable for those paid APIs.
- **App Check** on Firestore, Storage and Functions cuts scripted abuse.
- **Cloud Functions**: callable functions must check `request.auth` (v2) / `context.auth` (v1). HTTP functions must verify the ID token (`admin.auth().verifyIdToken`) or a webhook signature. Never trust a `uid` from the request body.
- **Service-account JSON** in the repo or bundle → critical. Rotate it in IAM.
- **Billing**: budget alerts only notify, they **don't cap** spending. For hard limits use quotas, App Check and rate limits. Blaze plan plus an open endpoint is a real risk.
- **Backups**: enable Firestore scheduled backups or point-in-time recovery.
- **Test**: the Rules Playground in the console, or `@firebase/rules-unit-testing` with the emulator.
- Deploy rules with `firebase deploy --only firestore:rules,storage` (the user runs it).
