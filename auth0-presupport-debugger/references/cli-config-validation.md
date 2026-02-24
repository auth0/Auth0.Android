# Auth0 CLI — Automated Configuration Validation

Use the Auth0 CLI (`auth0`) to programmatically validate that the developer's Auth0 dashboard settings match their local SDK configuration. This eliminates manual dashboard inspection and catches mismatches instantly.

---

## Prerequisites

### 1. Install the Auth0 CLI

```bash
# macOS (Homebrew)
brew tap auth0/auth0-cli && brew install auth0

# Windows (Scoop)
scoop bucket add auth0 https://github.com/auth0/scoop-auth0-cli.git
scoop install auth0

# Linux / manual
curl -sSfL https://raw.githubusercontent.com/auth0/auth0-cli/main/install.sh | sh -s -- -b /usr/local/bin

# Verify installation
auth0 --version
```

### 2. Authenticate the CLI

```bash
# Interactive login — opens a browser to authorize the CLI against the tenant
auth0 login

# Verify the active tenant
auth0 tenants list
```

> **Important:** The CLI must be authenticated against the **same tenant** the developer's app is configured to use. If the developer works with multiple tenants, confirm the active one with `auth0 tenants list`.

### 2a. Pre-Flight: Verify CLI Is Authenticated

A common issue is the CLI being **installed but not authenticated** (never ran `auth0 login`). Always verify before running any validation:

```bash
# Check CLI is installed
auth0 --version || { echo "❌ Auth0 CLI not installed — see install steps above"; exit 1; }

# Check CLI is authenticated (this is the step people miss)
auth0 tenants list 2>/dev/null || {
  echo "❌ Auth0 CLI is installed but NOT authenticated."
  echo "   Error: 'config.json file is missing' means you need to log in first."
  echo ""
  echo "   Run:  auth0 login"
  echo "   This opens your browser to complete the Auth0 authorization flow."
  echo ""
  echo "   For a specific tenant:  auth0 login --domain your-tenant.auth0.com"
  exit 1
}

echo "✅ CLI is installed and authenticated"
```

> **Common pitfall:** The developer says "CLI is installed" after running `auth0 --version` but has never run `auth0 login`. The first `auth0 apps show` command then fails with `Failed to load tenants: config.json file is missing`. Always run `auth0 tenants list` to confirm authentication before proceeding.

### 3. Extract Local App Configuration

Before running CLI checks, gather these values from the developer's project source files:

| Value | Android Location | iOS/Swift Location |
|-------|------------------|--------------------|
| **Client ID** | `res/values/strings.xml` → `com_auth0_client_id` | `Auth0.plist` → `ClientId` |
| **Domain** | `res/values/strings.xml` → `com_auth0_domain` | `Auth0.plist` → `Domain` |
| **Scheme** | `build.gradle` → `manifestPlaceholders.auth0Scheme` | `Info.plist` → `CFBundleURLSchemes` (= bundle ID) |
| **Package / Bundle ID** | `build.gradle` → `applicationId` | Xcode → target → Bundle Identifier |

---

## Phase 0 — Validation Commands

### Step 1: Fetch Application Details from Dashboard

```bash
# Replace <CLIENT_ID> with the value from the developer's app
auth0 apps show <CLIENT_ID> --json
```

This returns the full application configuration as JSON. Save it for comparison:

```bash
auth0 apps show <CLIENT_ID> --json > /tmp/auth0-app-config.json
```

**Key fields to extract:**

```bash
# Application type (must be "native" for mobile SDKs)
auth0 apps show <CLIENT_ID> --json | jq -r '.app_type'

# Allowed Callback URLs
auth0 apps show <CLIENT_ID> --json | jq -r '.callbacks[]'

# Allowed Logout URLs
auth0 apps show <CLIENT_ID> --json | jq -r '.allowed_logout_urls[]'

# Allowed Web Origins (should be empty/null for native apps)
auth0 apps show <CLIENT_ID> --json | jq -r '.web_origins // empty'

# Grant Types
auth0 apps show <CLIENT_ID> --json | jq -r '.grant_types[]'

# Token Endpoint Auth Method
auth0 apps show <CLIENT_ID> --json | jq -r '.token_endpoint_auth_method'
```

---

### Step 2: Validate Application Type

```bash
APP_TYPE=$(auth0 apps show <CLIENT_ID> --json | jq -r '.app_type')

if [ "$APP_TYPE" != "native" ]; then
  echo "❌ FAIL: Application type is '$APP_TYPE' — must be 'native' for mobile SDKs"
  echo "   Fix: Dashboard → Application → Settings → Application Type → Native"
else
  echo "✅ PASS: Application type is 'native'"
fi
```

> **Why this matters:** SPA and Regular Web App types use different OAuth flows. Native apps require PKCE which is automatically enforced when the type is set to Native.

---

### Step 3: Validate Callback URLs

#### Android Expected Callback URL Format

```
{scheme}://{auth0Domain}/android/{packageName}/callback
```

#### iOS Expected Callback URL Format

```
{bundleId}://{auth0Domain}/ios/{bundleId}/callback
```

#### Automated Check

```bash
# --- Set these from the developer's project config ---
CLIENT_ID="YOUR_CLIENT_ID"
AUTH0_DOMAIN="your-tenant.auth0.com"
PLATFORM="android"                        # or "ios"
APP_IDENTIFIER="com.example.myapp"        # packageName (Android) or bundleId (iOS)
SCHEME="com.example.myapp"                # auth0Scheme (Android) or bundleId (iOS)

# --- Build expected callback URL ---
EXPECTED_CALLBACK="${SCHEME}://${AUTH0_DOMAIN}/${PLATFORM}/${APP_IDENTIFIER}/callback"

echo "Expected callback URL: $EXPECTED_CALLBACK"

# --- Fetch actual callback URLs from dashboard ---
CALLBACKS=$(auth0 apps show "$CLIENT_ID" --json | jq -r '.callbacks[]? // empty')

if echo "$CALLBACKS" | grep -qxF "$EXPECTED_CALLBACK"; then
  echo "✅ PASS: Callback URL is registered in the dashboard"
else
  echo "❌ FAIL: Callback URL NOT found in Allowed Callback URLs"
  echo "   Expected : $EXPECTED_CALLBACK"
  echo "   Dashboard: $CALLBACKS"
  echo ""
  echo "   Fix: Add the expected URL to Dashboard → Application → Allowed Callback URLs"
fi
```

#### Common Callback URL Mistakes Caught by This Check

| Mistake | Example |
|---------|---------|
| Wrong scheme (used `https` instead of app scheme) | `https://tenant.auth0.com/...` vs `com.app://tenant.auth0.com/...` |
| Case mismatch | `com.Example.App` vs `com.example.app` |
| Trailing slash | `…/callback/` vs `…/callback` |
| Invisible trailing space | `…/callback ` (space at end) |
| Wrong platform path segment | `/ios/` instead of `/android/` |
| Wrong domain | `tenant.us.auth0.com` vs `tenant.auth0.com` |

---

### Step 4: Validate Logout URLs

```bash
# --- Build expected logout URL (same format as callback URL) ---
EXPECTED_LOGOUT="${SCHEME}://${AUTH0_DOMAIN}/${PLATFORM}/${APP_IDENTIFIER}/callback"

# --- Fetch actual logout URLs from dashboard ---
LOGOUT_URLS=$(auth0 apps show "$CLIENT_ID" --json | jq -r '.allowed_logout_urls[]? // empty')

if echo "$LOGOUT_URLS" | grep -qxF "$EXPECTED_LOGOUT"; then
  echo "✅ PASS: Logout URL is registered in the dashboard"
else
  echo "❌ FAIL: Logout URL NOT found in Allowed Logout URLs"
  echo "   Expected : $EXPECTED_LOGOUT"
  echo "   Dashboard: $LOGOUT_URLS"
  echo ""
  echo "   Fix: Add the expected URL to Dashboard → Application → Allowed Logout URLs"
fi
```

---

### Step 5: Validate Grant Types

```bash
GRANT_TYPES=$(auth0 apps show "$CLIENT_ID" --json | jq -r '.grant_types[]')

# Check for Authorization Code
if echo "$GRANT_TYPES" | grep -qx "authorization_code"; then
  echo "✅ PASS: 'authorization_code' grant type is enabled"
else
  echo "❌ FAIL: 'authorization_code' grant type is MISSING"
  echo "   Fix: Dashboard → Application → Advanced Settings → Grant Types → enable Authorization Code"
fi

# Check for Refresh Token
if echo "$GRANT_TYPES" | grep -qx "refresh_token"; then
  echo "✅ PASS: 'refresh_token' grant type is enabled"
else
  echo "⚠️  WARN: 'refresh_token' grant type is MISSING"
  echo "   This is required if the app uses offline_access scope or CredentialsManager"
  echo "   Fix: Dashboard → Application → Advanced Settings → Grant Types → enable Refresh Token"
fi
```

---

### Step 6: Validate Allowed Web Origins (Should Be Empty for Native)

```bash
WEB_ORIGINS=$(auth0 apps show "$CLIENT_ID" --json | jq -r '.web_origins[]? // empty')

if [ -z "$WEB_ORIGINS" ]; then
  echo "✅ PASS: Allowed Web Origins is empty (correct for native apps)"
else
  echo "⚠️  WARN: Allowed Web Origins is set — this is unusual for native apps"
  echo "   Values: $WEB_ORIGINS"
  echo "   Native apps do not need Allowed Web Origins. If this is intentional (e.g., companion web app), ignore this warning."
fi
```

---

### Step 7: Validate Token Endpoint Auth Method

```bash
TOKEN_AUTH=$(auth0 apps show "$CLIENT_ID" --json | jq -r '.token_endpoint_auth_method')

if [ "$TOKEN_AUTH" = "none" ]; then
  echo "✅ PASS: Token endpoint auth method is 'none' (correct for native + PKCE)"
else
  echo "⚠️  WARN: Token endpoint auth method is '$TOKEN_AUTH'"
  echo "   Native apps using PKCE should have 'none' — the client secret is not used."
  echo "   Fix: Dashboard → Application → Settings → Credentials → Authentication Method → None"
fi
```

---

### Step 8: Validate Connections Enabled for the Application

```bash
echo "--- Connections enabled for this application ---"
auth0 apps show "$CLIENT_ID" --json | jq -r '
  if .connections then
    .connections[] | "\(.name) (\(.strategy))"
  else
    "No connection data returned — check manually in Dashboard → Application → Connections"
  end
'
```

> **Manual fallback:** If the CLI does not return connection data for the app, verify in the dashboard under **Application → Connections** that at least one connection (e.g., `Username-Password-Authentication`, `google-oauth2`) is toggled **ON**.

**Common connection issues:**
- No connections enabled → user sees "No connections available" on Universal Login
- Social connection enabled but not configured → OAuth error from the social provider
- Database connection enabled but sign-up disabled → `access_denied` for new users

---

### Step 9: Validate Refresh Token Rotation Settings

```bash
# Check if Refresh Token Rotation is enabled
ROTATION=$(auth0 apps show "$CLIENT_ID" --json | jq -r '.refresh_token.rotation_type // "not_set"')
EXPIRATION_TYPE=$(auth0 apps show "$CLIENT_ID" --json | jq -r '.refresh_token.expiration_type // "not_set"')
IDLE_LIFETIME=$(auth0 apps show "$CLIENT_ID" --json | jq -r '.refresh_token.idle_token_lifetime // "not_set"')
TOKEN_LIFETIME=$(auth0 apps show "$CLIENT_ID" --json | jq -r '.refresh_token.token_lifetime // "not_set"')

echo "Refresh Token Configuration:"
echo "  Rotation type     : $ROTATION"
echo "  Expiration type   : $EXPIRATION_TYPE"
echo "  Idle lifetime (s) : $IDLE_LIFETIME"
echo "  Absolute lifetime : $TOKEN_LIFETIME"

if [ "$ROTATION" = "rotating" ]; then
  echo "✅ Refresh Token Rotation is enabled (recommended for native apps)"
else
  echo "⚠️  Refresh Token Rotation is '$ROTATION' — Auth0 recommends 'rotating' for native apps"
fi
```

---

### Step 10: Validate DPoP (Demonstrating Proof of Possession) Configuration

DPoP binds access tokens to a client-generated key pair, preventing token theft. It is an **Early Access** feature — the tenant must have DPoP enabled by Auth0 support before the SDK can use it.

> **When to run this check:** Only if the developer's code calls `WebAuthProvider.useDPoP()` or `AuthenticationAPIClient.useDPoP(context)`. If DPoP is not used, skip this step.

#### Check 10a: Verify DPoP Is Enabled at the Tenant / API Level

DPoP is configured on the **API (Resource Server)** level in Auth0. The API must accept DPoP-bound tokens.

```bash
# List all APIs and check their token_dialect (DPoP-aware APIs use 'access_token_authz' or support DPoP)
auth0 apis list --json | jq -r '.[] | "\(.name) — identifier: \(.identifier) — signing_alg: \(.signing_alg) — token_dialect: \(.token_dialect // \"not_set\")"'
```

#### Check 10b: Verify the Application Grant Types Support DPoP

DPoP works with the `authorization_code` grant. Confirm it is enabled (already covered in Step 5), and that the token endpoint auth method is `none` (PKCE, covered in Step 7).

```bash
# DPoP requires PKCE — token_endpoint_auth_method must be 'none'
TOKEN_AUTH=$(auth0 apps show "$CLIENT_ID" --json | jq -r '.token_endpoint_auth_method')

if [ "$TOKEN_AUTH" = "none" ]; then
  echo "✅ PASS: Token endpoint auth method is 'none' (required for DPoP + PKCE)"
else
  echo "❌ FAIL: Token endpoint auth method is '$TOKEN_AUTH' — DPoP requires 'none' (PKCE)"
  echo "   Fix: Dashboard → Application → Credentials → Authentication Method → None"
fi
```

#### Check 10c: Verify OIDC Discovery Advertises DPoP Support

```bash
# The well-known endpoint should include dpop_signing_alg_values_supported
DPOP_ALGS=$(curl -s "https://${AUTH0_DOMAIN}/.well-known/openid-configuration" | jq -r '.dpop_signing_alg_values_supported // empty')

if [ -n "$DPOP_ALGS" ]; then
  echo "✅ PASS: Tenant advertises DPoP support — algorithms: $DPOP_ALGS"
else
  echo "❌ FAIL: Tenant does NOT advertise DPoP support in OIDC discovery"
  echo "   This means DPoP is not enabled for this tenant."
  echo "   Fix: Contact Auth0 support to enable DPoP (Early Access feature)"
fi
```

#### Check 10d: Verify Android SDK DPoP Requirements

```bash
# DPoP in auth0-android requires API level 23+ (Android 6.0)
# Check the app's minSdk
MIN_SDK=$(grep -oP '(?<=minSdk\s)\d+' app/build.gradle 2>/dev/null || grep -oP '(?<=minSdkVersion\s)\d+' app/build.gradle 2>/dev/null || echo "NOT_FOUND")

if [ "$MIN_SDK" != "NOT_FOUND" ] && [ "$MIN_SDK" -ge 23 ]; then
  echo "✅ PASS: minSdk is $MIN_SDK (≥ 23, DPoP supported)"
else
  echo "❌ FAIL: minSdk is $MIN_SDK — DPoP requires API level 23+ (Android 6.0)"
  echo "   Fix: Set minSdk to 23 or higher in build.gradle"
fi
```

#### DPoP Configuration Gotchas

| Issue | Cause | Fix |
|-------|-------|-----|
| `DPoPException: UNSUPPORTED_ERROR` | Device running Android < 6.0 (API 23) | Set `minSdk 23` or guard DPoP usage with API level check |
| `DPoPException: KEY_GENERATION_ERROR` | StrongBox and non-StrongBox key generation both failed | Check device Keystore health; may occur on some emulators |
| Tokens not DPoP-bound after login | DPoP not enabled at tenant level | Contact Auth0 support to enable DPoP (Early Access) |
| Old sessions still use Bearer tokens | DPoP only applies to **new** login sessions | Force re-login for existing users |
| `use_dpop_nonce` error from resource server | Server requires a nonce for replay protection | Implement retry logic: call `DPoP.isNonceRequiredError(response)`, extract nonce from `DPoP-Nonce` header, retry |
| Key pair persists after logout | `DPoP.clearKeyPair()` not called on logout | Always call `DPoP.clearKeyPair()` in your logout flow |

#### DPoP SDK Usage Reference

**Android — Enable DPoP for browser login:**
```kotlin
WebAuthProvider
    .useDPoP()
    .login(account)
    .start(context, callback)
```

**Android — Enable DPoP for direct API calls:**
```kotlin
val client = AuthenticationAPIClient(account).useDPoP(context)
```

**Android — Making DPoP-protected API calls to your resource server:**
```kotlin
val headerData = DPoP.getHeaderData(httpMethod, url, accessToken, tokenType, nonce)
request.addHeader("Authorization", headerData.authorizationHeader)  // "DPoP <token>"
headerData.dpopProof?.let { request.addHeader("DPoP", it) }
```

**Android — Cleanup on logout (REQUIRED):**
```kotlin
DPoP.clearKeyPair()
```

---

### Step 11: Validate Passkeys Configuration

Passkeys provide phishing-resistant, passwordless authentication using WebAuthn / FIDO2 credentials managed by the device's Credential Manager.

> **When to run this check:** Only if the developer's code calls `signupWithPasskey()`, `passkeyChallenge()`, or `signinWithPasskey()`. If passkeys are not used, skip this step.

#### Check 11a: Verify Custom Domain Is Configured (REQUIRED for Passkeys)

Passkeys require a **custom domain** — the Credential Manager uses the domain as the WebAuthn Relying Party (RP) ID. Without a custom domain, passkey registration and login will fail.

```bash
CUSTOM_DOMAINS=$(auth0 domains list --json 2>/dev/null | jq -r '.[] | "\(.domain) — status: \(.status) — type: \(.type)"' || echo "NONE")

if [ "$CUSTOM_DOMAINS" = "NONE" ] || [ -z "$CUSTOM_DOMAINS" ]; then
  echo "❌ FAIL: No custom domain configured — passkeys REQUIRE a custom domain"
  echo "   Fix: Dashboard → Settings → Custom Domains → configure and verify a domain"
  echo "   See: https://auth0.com/docs/customize/custom-domains"
else
  echo "✅ PASS: Custom domain(s) found:"
  echo "$CUSTOM_DOMAINS" | sed 's/^/     /'
  
  # Check domain status
  VERIFIED=$(auth0 domains list --json 2>/dev/null | jq -r '.[] | select(.status == "ready") | .domain')
  if [ -n "$VERIFIED" ]; then
    echo "  ✅ At least one domain is verified and ready"
  else
    echo "  ❌ No custom domain has status 'ready' — verify domain DNS configuration"
  fi
fi
```

#### Check 11b: Verify Passkey Grant Type Is Enabled

Passkeys use the `urn:okta:params:oauth:grant-type:webauthn` grant type.

```bash
GRANT_TYPES=$(auth0 apps show "$CLIENT_ID" --json | jq -r '.grant_types[]')

# Check for the passkey (WebAuthn) grant type
if echo "$GRANT_TYPES" | grep -q "webauthn"; then
  echo "✅ PASS: Passkey (WebAuthn) grant type is enabled"
else
  echo "❌ FAIL: Passkey (WebAuthn) grant type is NOT enabled"
  echo "   The grant type 'urn:okta:params:oauth:grant-type:webauthn' must be enabled."
  echo "   Fix: Dashboard → Application → Advanced Settings → Grant Types → enable Passkey"
fi
```

#### Check 11c: Verify a Database Connection with Passkeys Support Exists

Passkeys are tied to a **database connection**. The connection must have passkey authentication enabled.

```bash
# List database connections and check for authentication_methods or passkey indicators
auth0 connections list --json | jq -r '
  .[] | select(.strategy == "auth0") | 
  "\(.name) — enabled_clients: \(.enabled_clients | length) — authentication_methods: \(.options.authentication_methods // "not_configured")"
'
```

> **Manual verification required:** Check the database connection settings in Auth0 Dashboard → Authentication → Database → [Connection] → Authentication Methods → confirm **Passkey** is enabled.

#### Check 11d: Verify Android SDK Passkey Requirements

```bash
# Passkeys in auth0-android require API level 28+ (Android 9)
MIN_SDK=$(grep -oP '(?<=minSdk\s)\d+' app/build.gradle 2>/dev/null || grep -oP '(?<=minSdkVersion\s)\d+' app/build.gradle 2>/dev/null || echo "NOT_FOUND")

if [ "$MIN_SDK" != "NOT_FOUND" ] && [ "$MIN_SDK" -ge 28 ]; then
  echo "✅ PASS: minSdk is $MIN_SDK (≥ 28, Passkeys supported)"
else
  echo "❌ FAIL: minSdk is $MIN_SDK — Passkeys require API level 28+ (Android 9)"
  echo "   Fix: Set minSdk to 28 or higher, or guard passkey usage with API level check"
fi

# Check for Credential Manager dependency in build.gradle
CRED_MGR=$(grep -r 'androidx.credentials' app/build.gradle 2>/dev/null || echo "NOT_FOUND")

if [ "$CRED_MGR" != "NOT_FOUND" ]; then
  echo "✅ PASS: Credential Manager dependency found in build.gradle"
else
  echo "❌ FAIL: Credential Manager dependency (androidx.credentials) NOT found"
  echo "   Passkeys require Google Credential Manager. Add to build.gradle:"
  echo '   implementation "androidx.credentials:credentials:<version>"'
  echo '   implementation "androidx.credentials:credentials-play-services-auth:<version>"'
fi
```

#### Check 11e: Verify Android Asset Links (Digital Asset Links) for Passkeys

For Credential Manager to associate your app with the Auth0 domain, the domain must serve a valid `.well-known/assetlinks.json` file containing your app's signing certificate fingerprint.

```bash
# Check if assetlinks.json is reachable on the custom domain
CUSTOM_DOMAIN=$(auth0 domains list --json 2>/dev/null | jq -r '.[] | select(.status == "ready") | .domain' | head -1)

if [ -n "$CUSTOM_DOMAIN" ]; then
  ASSET_LINKS=$(curl -s "https://${CUSTOM_DOMAIN}/.well-known/assetlinks.json")
  
  if echo "$ASSET_LINKS" | jq -e '.' >/dev/null 2>&1; then
    echo "✅ PASS: assetlinks.json is reachable at https://${CUSTOM_DOMAIN}/.well-known/assetlinks.json"
    
    # Check if the app's package name is listed
    if echo "$ASSET_LINKS" | jq -e --arg pkg "$APP_IDENTIFIER" '.[].target | select(.package_name == $pkg)' >/dev/null 2>&1; then
      echo "  ✅ App package '$APP_IDENTIFIER' is listed in assetlinks.json"
    else
      echo "  ❌ App package '$APP_IDENTIFIER' NOT found in assetlinks.json"
      echo "     Fix: Add your app's package name and SHA-256 fingerprint to the Auth0 dashboard"
      echo "     Dashboard → Applications → [App] → Device Settings → Android"
    fi
  else
    echo "❌ FAIL: assetlinks.json is NOT valid JSON or not reachable"
    echo "   URL: https://${CUSTOM_DOMAIN}/.well-known/assetlinks.json"
  fi
else
  echo "⚠️  SKIP: No verified custom domain — cannot check assetlinks.json"
fi
```

#### Passkeys Configuration Gotchas

| Issue | Cause | Fix |
|-------|-------|-----|
| `Credential Manager` throws "No credentials available" | No passkeys registered for this RP ID, or custom domain misconfigured | Verify custom domain is set and verified; ensure user has registered a passkey |
| Passkey registration returns error | Custom domain not configured or not verified | Dashboard → Settings → Custom Domains → verify status is "ready" |
| `urn:okta:params:oauth:grant-type:webauthn` not recognized | Passkey grant type not enabled for the application | Dashboard → Application → Advanced Settings → Grant Types → enable Passkey |
| `assetlinks.json` not found | Android Device Settings not configured for the app | Dashboard → Applications → [App] → Device Settings → Android → add package + SHA-256 fingerprint |
| Wrong RP ID in Credential Manager prompt | Custom domain doesn't match what the SDK sends | Ensure the Auth0 domain in SDK config matches the custom domain |
| Passkeys work on web but not mobile | Missing Android asset links or Credential Manager dependency | Add `androidx.credentials` dependency; configure Device Settings in dashboard |
| `access_denied` on `signinWithPasskey()` | Database connection doesn't have passkeys enabled | Dashboard → Authentication → Database → [Connection] → Authentication Methods → enable Passkey |
| Passkeys not working on emulator | Some emulators lack Credential Manager / FIDO2 support | Test on a physical device with Google Play Services |
| Two passkey flows confused | Registration (`signupWithPasskey`) vs post-login enrollment (`MyAccountAPIClient`) are distinct | Registration = new user signup; Enrollment = existing user adds a passkey via My Account API |

#### Passkeys SDK Usage Reference

**Android — Passkey Signup (new user):**
```kotlin
val challenge = authClient.signupWithPasskey(userData, realm).await()
// Pass challenge.authParamsPublicKey to Credential Manager
val credentialRequest = CreatePublicKeyCredentialRequest(challenge.authParamsPublicKey)
val result = credentialManager.createCredential(context, credentialRequest)
// Complete sign-in
val credentials = authClient.signinWithPasskey(challenge.authSession, publicKeyCredentials, realm).await()
```

**Android — Passkey Login (existing user):**
```kotlin
val challenge = authClient.passkeyChallenge(realm).await()
// Pass challenge.authParamsPublicKey to Credential Manager
val option = GetPublicKeyCredentialOption(challenge.authParamsPublicKey)
val result = credentialManager.getCredential(context, GetCredentialRequest(listOf(option)))
// Complete sign-in
val credentials = authClient.signinWithPasskey(challenge.authSession, publicKeyCredentials, realm).await()
```

**Android — Passkey Enrollment (existing user, post-login):**
```kotlin
val myAccountClient = MyAccountAPIClient(account, accessToken)
val challenge = myAccountClient.passkeyEnrollmentChallenge().await()
// Use Credential Manager to create the credential
val enrolled = myAccountClient.enroll(passkeyCredential, challenge).await()
```

---

## Full Automated Validation Script

Copy and run this end-to-end script. Fill in the five variables at the top.

```bash
#!/usr/bin/env bash
set -euo pipefail

# ╔══════════════════════════════════════════════════════════════════╗
# ║  Auth0 Pre-Support Debugger — CLI Configuration Validator       ║
# ║  Fill in the 5 values below from the developer's project files  ║
# ╚══════════════════════════════════════════════════════════════════╝

CLIENT_ID=""                    # From strings.xml / Auth0.plist
AUTH0_DOMAIN=""                 # From strings.xml / Auth0.plist
PLATFORM=""                     # "android" or "ios"
APP_IDENTIFIER=""               # packageName (Android) or bundleId (iOS)
SCHEME=""                       # auth0Scheme (Android) or bundleId (iOS)

# ── Optional: DPoP & Passkeys (set to "true" to validate) ──────
VALIDATE_DPOP="false"           # Set to "true" if the app uses DPoP
VALIDATE_PASSKEYS="false"       # Set to "true" if the app uses Passkeys

# ── Validation ────────────────────────────────────────────────────

if [ -z "$CLIENT_ID" ] || [ -z "$AUTH0_DOMAIN" ] || [ -z "$PLATFORM" ] || [ -z "$APP_IDENTIFIER" ] || [ -z "$SCHEME" ]; then
  echo "ERROR: All 5 variables must be filled in before running this script."
  exit 1
fi

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Auth0 CLI Configuration Validation"
echo "  Client ID : $CLIENT_ID"
echo "  Domain    : $AUTH0_DOMAIN"
echo "  Platform  : $PLATFORM"
echo "  App ID    : $APP_IDENTIFIER"
echo "  Scheme    : $SCHEME"
echo "═══════════════════════════════════════════════════════════"
echo ""

PASS=0
FAIL=0
WARN=0

pass() { echo "  ✅ $1"; ((PASS++)); }
fail() { echo "  ❌ $1"; ((FAIL++)); }
warn() { echo "  ⚠️  $1"; ((WARN++)); }

# Pre-flight: verify CLI is authenticated
auth0 tenants list >/dev/null 2>&1 || {
  echo "❌ FATAL: Auth0 CLI is not authenticated."
  echo "   Run 'auth0 login' first, then re-run this script."
  exit 1
}
echo "✅ CLI authenticated"
echo ""

# Fetch app config once
APP_JSON=$(auth0 apps show "$CLIENT_ID" --json 2>/dev/null) || {
  echo "❌ FATAL: Could not fetch application '$CLIENT_ID' from Auth0."
  echo "   Possible causes:"
  echo "   - Client ID is wrong"
  echo "   - CLI is not authenticated (run: auth0 login)"
  echo "   - CLI is authenticated against a different tenant"
  exit 1
}

echo "1. Application Type"
APP_TYPE=$(echo "$APP_JSON" | jq -r '.app_type // "unknown"')
if [ "$APP_TYPE" = "native" ]; then
  pass "Application type is 'native'"
else
  fail "Application type is '$APP_TYPE' — must be 'native'"
fi
echo ""

echo "2. Callback URL"
EXPECTED_CALLBACK="${SCHEME}://${AUTH0_DOMAIN}/${PLATFORM}/${APP_IDENTIFIER}/callback"
CALLBACKS=$(echo "$APP_JSON" | jq -r '.callbacks[]? // empty')
if echo "$CALLBACKS" | grep -qxF "$EXPECTED_CALLBACK"; then
  pass "Callback URL found: $EXPECTED_CALLBACK"
else
  fail "Callback URL NOT found in dashboard"
  echo "       Expected : $EXPECTED_CALLBACK"
  if [ -n "$CALLBACKS" ]; then
    echo "       Registered:"
    echo "$CALLBACKS" | sed 's/^/         /'
  else
    echo "       Registered: (none)"
  fi
fi
echo ""

echo "3. Logout URL"
EXPECTED_LOGOUT="${SCHEME}://${AUTH0_DOMAIN}/${PLATFORM}/${APP_IDENTIFIER}/callback"
LOGOUT_URLS=$(echo "$APP_JSON" | jq -r '.allowed_logout_urls[]? // empty')
if echo "$LOGOUT_URLS" | grep -qxF "$EXPECTED_LOGOUT"; then
  pass "Logout URL found: $EXPECTED_LOGOUT"
else
  fail "Logout URL NOT found in dashboard"
  echo "       Expected : $EXPECTED_LOGOUT"
  if [ -n "$LOGOUT_URLS" ]; then
    echo "       Registered:"
    echo "$LOGOUT_URLS" | sed 's/^/         /'
  else
    echo "       Registered: (none)"
  fi
fi
echo ""

echo "4. Grant Types"
GRANT_TYPES=$(echo "$APP_JSON" | jq -r '.grant_types[]? // empty')
if echo "$GRANT_TYPES" | grep -qx "authorization_code"; then
  pass "'authorization_code' grant enabled"
else
  fail "'authorization_code' grant MISSING"
fi
if echo "$GRANT_TYPES" | grep -qx "refresh_token"; then
  pass "'refresh_token' grant enabled"
else
  warn "'refresh_token' grant MISSING (required for offline_access / CredentialsManager)"
fi
echo ""

echo "5. Allowed Web Origins"
WEB_ORIGINS=$(echo "$APP_JSON" | jq -r '.web_origins[]? // empty')
if [ -z "$WEB_ORIGINS" ]; then
  pass "Allowed Web Origins is empty (correct for native)"
else
  warn "Allowed Web Origins has values — unusual for native apps"
fi
echo ""

echo "6. Token Endpoint Auth Method"
TOKEN_AUTH=$(echo "$APP_JSON" | jq -r '.token_endpoint_auth_method // "unknown"')
if [ "$TOKEN_AUTH" = "none" ]; then
  pass "Token endpoint auth method is 'none' (PKCE)"
else
  warn "Token endpoint auth method is '$TOKEN_AUTH' — expected 'none' for native PKCE"
fi
echo ""

echo "7. Refresh Token Configuration"
RT_ROTATION=$(echo "$APP_JSON" | jq -r '.refresh_token.rotation_type // "not_set"')
RT_EXPIRATION=$(echo "$APP_JSON" | jq -r '.refresh_token.expiration_type // "not_set"')
RT_IDLE=$(echo "$APP_JSON" | jq -r '.refresh_token.idle_token_lifetime // "not_set"')
RT_ABSOLUTE=$(echo "$APP_JSON" | jq -r '.refresh_token.token_lifetime // "not_set"')
echo "    Rotation     : $RT_ROTATION"
echo "    Expiration   : $RT_EXPIRATION"
echo "    Idle lifetime: ${RT_IDLE}s"
echo "    Abs lifetime : ${RT_ABSOLUTE}s"
if [ "$RT_ROTATION" = "rotating" ]; then
  pass "Refresh Token Rotation is enabled"
else
  warn "Refresh Token Rotation is '$RT_ROTATION' — 'rotating' recommended for native"
fi
echo ""

# ── DPoP Validation (optional) ───────────────────────────────
if [ "$VALIDATE_DPOP" = "true" ]; then
  echo "8. DPoP Configuration"
  
  # Check OIDC discovery for DPoP support
  DPOP_ALGS=$(curl -s "https://${AUTH0_DOMAIN}/.well-known/openid-configuration" | jq -r '.dpop_signing_alg_values_supported // empty' 2>/dev/null)
  if [ -n "$DPOP_ALGS" ]; then
    pass "Tenant advertises DPoP support (algorithms: $DPOP_ALGS)"
  else
    fail "Tenant does NOT advertise DPoP in OIDC discovery — contact Auth0 support to enable (Early Access)"
  fi
  
  # DPoP requires PKCE (token_endpoint_auth_method = none) — already checked above
  if [ "$TOKEN_AUTH" != "none" ]; then
    fail "DPoP requires token_endpoint_auth_method='none' but found '$TOKEN_AUTH'"
  fi
  echo ""
fi

# ── Passkeys Validation (optional) ───────────────────────────
if [ "$VALIDATE_PASSKEYS" = "true" ]; then
  echo "9. Passkeys Configuration"
  
  # Check custom domain (required)
  CUSTOM_DOMAIN=$(auth0 domains list --json 2>/dev/null | jq -r '.[] | select(.status == "ready") | .domain' 2>/dev/null | head -1)
  if [ -n "$CUSTOM_DOMAIN" ]; then
    pass "Custom domain verified: $CUSTOM_DOMAIN (required for passkeys)"
  else
    fail "No verified custom domain — passkeys REQUIRE a custom domain"
  fi
  
  # Check passkey (WebAuthn) grant type
  if echo "$GRANT_TYPES" | grep -q "webauthn"; then
    pass "Passkey (WebAuthn) grant type is enabled"
  else
    fail "Passkey (WebAuthn) grant type is NOT enabled"
  fi
  
  # Check assetlinks.json (Android only)
  if [ "$PLATFORM" = "android" ] && [ -n "$CUSTOM_DOMAIN" ]; then
    ASSET_LINKS=$(curl -s "https://${CUSTOM_DOMAIN}/.well-known/assetlinks.json" 2>/dev/null)
    if echo "$ASSET_LINKS" | jq -e '.' >/dev/null 2>&1; then
      pass "assetlinks.json reachable at https://${CUSTOM_DOMAIN}/.well-known/assetlinks.json"
      if echo "$ASSET_LINKS" | jq -e --arg pkg "$APP_IDENTIFIER" '.[].target | select(.package_name == $pkg)' >/dev/null 2>&1; then
        pass "App package '$APP_IDENTIFIER' found in assetlinks.json"
      else
        fail "App package '$APP_IDENTIFIER' NOT in assetlinks.json — configure in Dashboard → App → Device Settings"
      fi
    else
      fail "assetlinks.json not valid or not reachable at https://${CUSTOM_DOMAIN}/.well-known/assetlinks.json"
    fi
  fi
  echo ""
fi

echo "═══════════════════════════════════════════════════════════"
echo "  RESULTS:  ✅ $PASS passed   ❌ $FAIL failed   ⚠️  $WARN warnings"
echo "═══════════════════════════════════════════════════════════"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "⛔ There are configuration errors. Fix the ❌ items above before proceeding."
  echo "   After fixing, re-run this script to confirm."
  exit 1
elif [ "$WARN" -gt 0 ]; then
  echo "⚠️  No hard failures, but review the warnings above."
  exit 0
else
  echo "🎉 All checks passed. Configuration looks correct."
  exit 0
fi
```

---

## Automated Config Extraction from Project Files

### Android — Extract Config from Source

```bash
# Run from the Android project root

# Extract Client ID from strings.xml
ANDROID_CLIENT_ID=$(grep -oP '(?<=name="com_auth0_client_id">)[^<]+' app/src/main/res/values/strings.xml 2>/dev/null || echo "NOT_FOUND")

# Extract Domain from strings.xml
ANDROID_DOMAIN=$(grep -oP '(?<=name="com_auth0_domain">)[^<]+' app/src/main/res/values/strings.xml 2>/dev/null || echo "NOT_FOUND")

# Extract applicationId from build.gradle
ANDROID_APP_ID=$(grep -oP '(?<=applicationId\s")[^"]+' app/build.gradle 2>/dev/null || echo "NOT_FOUND")

# Extract auth0Scheme from manifestPlaceholders
ANDROID_SCHEME=$(grep -oP '(?<=auth0Scheme:\s")[^"]+' app/build.gradle 2>/dev/null || echo "NOT_FOUND")

echo "Extracted Android Config:"
echo "  Client ID : $ANDROID_CLIENT_ID"
echo "  Domain    : $ANDROID_DOMAIN"
echo "  App ID    : $ANDROID_APP_ID"
echo "  Scheme    : $ANDROID_SCHEME"
```

### iOS — Extract Config from Source

```bash
# Run from the iOS project root

# Extract Client ID from Auth0.plist
IOS_CLIENT_ID=$(/usr/libexec/PlistBuddy -c "Print :ClientId" Auth0.plist 2>/dev/null || echo "NOT_FOUND")

# Extract Domain from Auth0.plist
IOS_DOMAIN=$(/usr/libexec/PlistBuddy -c "Print :Domain" Auth0.plist 2>/dev/null || echo "NOT_FOUND")

# Extract Bundle ID from project.pbxproj (rough extraction)
IOS_BUNDLE_ID=$(grep -oP '(?<=PRODUCT_BUNDLE_IDENTIFIER = )[^;]+' *.xcodeproj/project.pbxproj 2>/dev/null | head -1 | tr -d ' "' || echo "NOT_FOUND")

echo "Extracted iOS Config:"
echo "  Client ID : $IOS_CLIENT_ID"
echo "  Domain    : $IOS_DOMAIN"
echo "  Bundle ID : $IOS_BUNDLE_ID"
```

---

## CLI Quick-Fix Commands

If the validation script finds issues, use these CLI commands to fix them directly (instead of going to the dashboard):

### Fix: Add Missing Callback URL

```bash
# Fetch current callbacks, append the new one, and update
CURRENT=$(auth0 apps show <CLIENT_ID> --json | jq -r '[.callbacks[]?] | join(",")')
NEW_CALLBACK="${SCHEME}://${AUTH0_DOMAIN}/${PLATFORM}/${APP_IDENTIFIER}/callback"

auth0 apps update <CLIENT_ID> \
  --callbacks "${CURRENT},${NEW_CALLBACK}"
```

### Fix: Add Missing Logout URL

```bash
CURRENT_LOGOUT=$(auth0 apps show <CLIENT_ID> --json | jq -r '[.allowed_logout_urls[]?] | join(",")')
NEW_LOGOUT="${SCHEME}://${AUTH0_DOMAIN}/${PLATFORM}/${APP_IDENTIFIER}/callback"

auth0 apps update <CLIENT_ID> \
  --logout-urls "${CURRENT_LOGOUT},${NEW_LOGOUT}"
```

### Fix: Change Application Type to Native

```bash
auth0 apps update <CLIENT_ID> --type native
```

### Fix: Enable Required Grant Types

```bash
auth0 apps update <CLIENT_ID> \
  --grants "authorization_code,refresh_token,implicit"
```

### Fix: Set Token Endpoint Auth Method to None (PKCE)

```bash
auth0 apps update <CLIENT_ID> \
  --auth-method none
```

---

## Validating Tenant-Level Settings

Beyond app-level settings, certain tenant-level configurations can cause issues:

### Check Enabled Connections

```bash
# List all connections in the tenant
auth0 connections list --json | jq -r '.[] | "\(.name) — \(.strategy) — enabled_clients: \(.enabled_clients | length)"'
```

### Verify a Specific Connection Is Enabled for the App

```bash
# Check if a connection includes this Client ID in its enabled_clients
CONNECTION_NAME="Username-Password-Authentication"
ENABLED=$(auth0 connections list --json | jq -r --arg name "$CONNECTION_NAME" --arg cid "$CLIENT_ID" '
  .[] | select(.name == $name) | .enabled_clients | index($cid) // empty
')

if [ -n "$ENABLED" ]; then
  echo "✅ Connection '$CONNECTION_NAME' is enabled for this app"
else
  echo "❌ Connection '$CONNECTION_NAME' is NOT enabled for this app"
  echo "   Fix: Dashboard → Application → Connections → toggle ON"
fi
```

### Check Custom Domain (if applicable)

```bash
auth0 domains list --json 2>/dev/null | jq -r '.[] | "\(.domain) — status: \(.status)"' || echo "No custom domains configured"
```

### Verify OIDC Discovery Endpoint

```bash
# Should return a valid JSON with authorization_endpoint, token_endpoint, etc.
curl -s "https://${AUTH0_DOMAIN}/.well-known/openid-configuration" | jq '.authorization_endpoint, .token_endpoint, .issuer'
```

---

## Validation Checklist Summary

| # | Check | CLI Command | Pass Criteria |
|---|-------|-------------|---------------|
| 1 | Application exists | `auth0 apps show <CID>` | Returns JSON, no error |
| 2 | App type = native | `.app_type` | `"native"` |
| 3 | Callback URL registered | `.callbacks[]` | Contains expected URL |
| 4 | Logout URL registered | `.allowed_logout_urls[]` | Contains expected URL |
| 5 | Authorization Code grant | `.grant_types[]` | Contains `"authorization_code"` |
| 6 | Refresh Token grant | `.grant_types[]` | Contains `"refresh_token"` |
| 7 | Web Origins empty | `.web_origins[]` | Empty or null |
| 8 | Token auth = none | `.token_endpoint_auth_method` | `"none"` |
| 9 | RT rotation enabled | `.refresh_token.rotation_type` | `"rotating"` |
| 10 | Connection enabled | `connections list` | App's CID in `enabled_clients` |
| 11 | OIDC discovery reachable | `curl .well-known/openid-configuration` | Valid JSON, 200 OK |
| | **DPoP (if used)** | | |
| 12 | DPoP advertised in OIDC discovery | `.dpop_signing_alg_values_supported` | Non-empty array (e.g. `["ES256"]`) |
| 13 | Token auth = none (PKCE for DPoP) | `.token_endpoint_auth_method` | `"none"` |
| 14 | Android minSdk ≥ 23 for DPoP | `build.gradle` → `minSdk` | `≥ 23` |
| | **Passkeys (if used)** | | |
| 15 | Custom domain configured & verified | `auth0 domains list` | At least one domain with status `"ready"` |
| 16 | Passkey (WebAuthn) grant type | `.grant_types[]` | Contains `webauthn` |
| 17 | `assetlinks.json` reachable (Android) | `curl .well-known/assetlinks.json` | Valid JSON with app's package name |
| 18 | Credential Manager dependency (Android) | `build.gradle` | `androidx.credentials` present |
| 19 | Android minSdk ≥ 28 for Passkeys | `build.gradle` → `minSdk` | `≥ 28` |
| 11 | OIDC discovery reachable | `curl .well-known/openid-configuration` | Valid JSON, 200 OK |

---

## Troubleshooting the CLI Itself

| Problem | Fix |
|---------|-----|
| `auth0: command not found` | Install the CLI — see Prerequisites above |
| `Failed to load tenants: config.json file is missing` | CLI is installed but **never authenticated**. Run `auth0 login` first |
| `Unauthorized` or `Login required` | Auth session expired. Run `auth0 login` to re-authenticate |
| Wrong tenant data | Run `auth0 tenants list` and switch with `auth0 tenants use <tenant>` |
| `jq: command not found` | Install jq: `brew install jq` (macOS) or `apt-get install jq` (Linux) |
| `grep -oP` fails on macOS | macOS grep doesn't support `-P`. Install GNU grep: `brew install grep`, then use `ggrep -oP` |
| CLI returns empty for callbacks | The app may have no callbacks set — this is itself the bug |
| Rate limiting | Auth0 Management API has rate limits; avoid running the script in a tight loop |
