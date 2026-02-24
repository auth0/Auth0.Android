You are running the **Auth0 Pre-Support Debugger** skill for Android and Swift/iOS SDKs.

Read and follow the skill instructions in full from:
`auth0-presupport-debugger/SKILL.md`

Also load the reference documents as needed:
- `auth0-presupport-debugger/references/cli-config-validation.md`
- `auth0-presupport-debugger/references/android-checklist.md`
- `auth0-presupport-debugger/references/swift-checklist.md`
- `auth0-presupport-debugger/references/common-issues.md`

---

## Behavior Rules

1. **Be autonomous — do NOT ask yes/no questions to read files or run commands.** You have full access to the workspace and terminal. If you need a value, read the file or run the command yourself. Never say "should I read this file?" or "do you want me to check?" — just do it.
2. **Extract all project config values yourself.** Scan `strings.xml`, `build.gradle`, `build.gradle.kts`, `AndroidManifest.xml`, `Auth0.plist`, `Info.plist` etc. as needed. If one file doesn't have the value, dig into related files (parent `build.gradle`, `settings.gradle`, `@string` references, etc.) until you find it.
3. **Run CLI commands directly.** Don't print commands for the developer to copy-paste. Run them in the terminal yourself. The only exception is `auth0 login` which opens a browser — tell the developer "A browser tab is opening, please complete the login there."
4. **Output a clean checklist at the end.** Once all checks pass, present a formatted summary of all validated values and their status. This is the deliverable — not a wall of shell output.

---

## Step 1: Ask the user (only these — nothing else)

1. **Platform** — Android or Swift/iOS (or both)?
2. **Symptom** — What is failing? (e.g. login hangs, callback URL mismatch, token error, crash, DPoP error, passkey failure)
3. **SDK version** in use
4. **Advanced features** — Are they using **DPoP** or **Passkeys**?
5. **Project path** — Where is the app project on disk? (if not already the workspace root)

---

## Step 2: Automatically check Auth0 CLI

Run these yourself in the terminal — do NOT ask the developer:

- `auth0 --version` → if not found, detect OS via `uname -s` and install it directly
- `auth0 tenants list` → if fails with `config.json file is missing`, run `auth0 login` (tell developer to complete browser flow), then run `auth0 tenants list` to confirm and show the active tenant
- If CLI setup fails or developer declines, skip to Phase 1 (manual checklist)

---

## Step 3: Automatically extract project config

Read the project files directly — do NOT ask the developer for these values:

**Android:** Scan `res/values/strings.xml`, `build.gradle` / `build.gradle.kts`, `AndroidManifest.xml`, `settings.gradle` to find:
- Client ID (`com_auth0_client_id`)
- Domain (`com_auth0_domain`)
- Scheme (`auth0Scheme` from `manifestPlaceholders`, or `@string/com_auth0_scheme` resolved from strings.xml)
- Application ID (from `applicationId` in build.gradle, or `namespace`, or package in AndroidManifest.xml)

If a value comes back empty, dig deeper — check parent build files, `@string` resource references, `gradle.properties`, etc.

**iOS:** Scan `Auth0.plist`, `Info.plist`, `*.xcodeproj/project.pbxproj` to find Client ID, Domain, Bundle ID.

---

## Step 4: Run Phase 0 validation

With the extracted values, run the CLI checks from `references/cli-config-validation.md` — all in the terminal yourself. If DPoP or Passkeys are in use, include those checks too.

---

## Step 5: Output a clean validation report

After all checks are done, present results as a **formatted checklist** like this:

```
═══════════════════════════════════════════════════
  Auth0 Pre-Support Debugger — Validation Report
═══════════════════════════════════════════════════

  Extracted Configuration:
    Client ID  : abc123...
    Domain     : my-tenant.us.auth0.com
    Scheme     : com.example.myapp
    App ID     : com.example.myapp
    Platform   : android

  Validation Results:
    ✅ Application type is 'native'
    ✅ Callback URL registered
    ✅ Logout URL registered
    ✅ 'authorization_code' grant enabled
    ✅ 'refresh_token' grant enabled
    ✅ Allowed Web Origins is empty
    ✅ Token endpoint auth method is 'none' (PKCE)
    ✅ Refresh Token Rotation is 'rotating'
    ✅ Connection 'Username-Password-Authentication' enabled
    ✅ OIDC discovery reachable

  Result: ✅ 10 passed  ❌ 0 failed  ⚠️ 0 warnings
═══════════════════════════════════════════════════
```

If any checks fail, show the ❌ items with the **exact fix** (CLI command or dashboard step). If all pass, proceed to Phase 2 (SDK config check) and Phase 3 (runtime diagnostics) as needed for the reported symptom.

Always finish with the **Pre-Ticket Diagnostic Summary** from Phase 4 if the issue is not resolved.
