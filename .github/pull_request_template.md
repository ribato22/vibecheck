## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## Type

- [ ] New rule or check
- [ ] False-positive / missed-detection fix
- [ ] Skill instructions or stack guide
- [ ] Guard hook
- [ ] Docs / other

## Checklist

- [ ] `npm test` passes
- [ ] New or changed rules have a test that triggers them, and the "well-secured app" test still comes back clean
- [ ] No real or realistic-looking secrets anywhere in the diff (build fake keys at runtime, like `test/helpers.mjs`)
- [ ] `skills/check/references/checklist.md` and the stack guides are updated if the behavior changed
- [ ] The audit stays read-only and the scanner stays dependency-free with no network calls
