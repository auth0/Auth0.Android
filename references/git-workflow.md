# Git Workflow Reference — Auth0.Android

## Branch naming

| Type | Pattern | Example |
|------|---------|---------|
| Feature | `feat/{name}` | `feat/passkey-enrollment` |
| Fix | `fix/{issue-id}-{name}` | `fix/992-dpop-nonce-retry` |
| Chore | `chore/{name}` | `chore/bump-okhttp` |
| Release | `release/{version}` | `release/4.1.0` |
| Docs | `docs/{name}` | `docs/update-dpop-examples` |

## Commit messages

Format: `{type}({scope}): {description}` — under 70 chars, imperative mood.

Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `perf`, `ci`

Scope (optional): `dpop`, `storage`, `mfa`, `provider`, `credentials`, `myaccount`

## Pull requests

Template: `.github/PULL_REQUEST_TEMPLATE.md` — describe what changed and why, list methods/classes added/removed, add testing instructions, check the three-item checklist.

Required before merge: `test.yml` + `codeql.yml` + `sca_scan.yml` pass, at least one reviewer approval.

Merge strategy: squash or rebase for linear history.

## Pre-commit checklist

```bash
./gradlew testReleaseUnitTest jacocoTestReleaseUnitTestReport lintRelease --continue --console=plain
```

Then: confirm coverage >= 80% for the patch, update `README.md`/`EXAMPLES.md` if public API changed, scan staged diff for secrets before pushing.
