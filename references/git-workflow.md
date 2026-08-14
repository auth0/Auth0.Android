# Git Workflow Reference — Auth0.Android

## Branch Naming

| Type | Pattern | Example |
|------|---------|---------|
| Feature | `feature/{name}` or `feat/{name}` | `feat/passkey-enrollment` |
| Bug fix | `fix/{issue-id}-{name}` | `fix/992-dpop-nonce-retry` |
| Hotfix | `hotfix/{name}` | `hotfix/token-expiry-race` |
| Chore | `chore/{name}` | `chore/bump-okhttp` |
| Refactor | `refactor/{name}` | `refactor/request-factory` |
| Release | `release/{version}` | `release/3.3.0` |
| Port / backport | `port/{issue-id}-{name}` | `port/992-mfa-dpop` |
| Docs | `docs/{name}` | `docs/update-dpop-examples` |

## Commit Messages

Format: `{type}({scope}): {short description}` — keep under 70 characters total.

**Types:** `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `perf`, `ci`

**Scope (optional):** package or feature name — `dpop`, `storage`, `mfa`, `provider`, `credentials`

**Examples:**
```
feat(dpop): support DPoP for MFA requests
fix(storage): address session expiry race condition
test(provider): add redirect URI mismatch test
docs: update EXAMPLES.md with passkey enrollment
chore: bump okhttp to 4.12.0
```

Use imperative mood ("add", "fix", not "adds", "fixed").

## Pull Requests

**Title:** same format as commit message (under 70 chars).

**Description:** see `.github/PULL_REQUEST_TEMPLATE.md` — describe what changed and why, list endpoints/classes/methods added/removed, include testing instructions, check the three-item checklist.

**Required before merge:**
- CI must pass: `test.yml` (unit tests + lint + coverage), `codeql.yml`, `sca_scan.yml`
- At least one reviewer approval
- No unresolved comments

**Merge strategy:** squash or rebase to maintain linear history (project preference).

## Pre-Commit Checklist

```bash
# 1. Run the full CI pipeline locally
./gradlew clean test jacocoTestReport lint --continue --console=plain --max-workers=1 --no-daemon

# 2. Confirm all tests pass and coverage hasn't dropped below 80% for the patch
# 3. Update README.md / EXAMPLES.md if public API changed (see Boundaries → Always Do)
# 4. Add CHANGELOG.md entry for user-facing changes
# 5. Never commit secrets — scan with `git diff --staged` before pushing
```
