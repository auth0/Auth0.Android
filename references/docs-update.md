# Docs Update Rules — Auth0.Android

## Tracked Docs Inventory

| Doc | What it covers |
|-----|---------------|
| `README.md` | Installation (Gradle coordinates, AAR), requirements (minSdk, Java), Auth0 dashboard config, `AndroidManifest.xml` setup, quick-start login/logout code, ProGuard rules |
| `EXAMPLES.md` | Full Kotlin + Java usage for all major features: WebAuthProvider, CredentialsManager, SecureCredentialsManager, AuthenticationAPIClient, MFA, DPoP, My Account API, passkeys, bot protection, PAR, SSO |

Migration guides (`V2_MIGRATION_GUIDE.md`, `V3_MIGRATION_GUIDE.md`) are **not tracked** as fixed docs — their filename is version-specific and is inferred from the target branch at breaking-change time, not baked here.

## Code-to-Docs Mapping (Library shape)

When you change code in these areas, update these docs **in the same PR**:

| When this changes | Update |
|-------------------|--------|
| Public API entry point (`Auth0.kt`, `WebAuthProvider`, `AuthenticationAPIClient`, `CredentialsManager`, `SecureCredentialsManager`, `MyAccountAPIClient`) | `README.md` (usage/quick-start), `EXAMPLES.md` (affected samples) |
| Configuration options or constructor parameters on public classes | `README.md` (configuration section) |
| `AndroidManifest.xml` changes (new activity, intent filter, permission) | `README.md` (setup/configuration section) |
| New authentication flow or major feature (passkey, DPoP, MFA factor, PAR) | `EXAMPLES.md` (new section or subsection) |
| Any new public method or exported function added | `EXAMPLES.md` (add a Kotlin + Java usage sample) |
| Any public method, property, or class removed or renamed | `README.md` (remove/update references), `EXAMPLES.md` (remove/update affected samples) |
| SDK installation coordinates or minSdk / Java requirements | `README.md` (installation + requirements sections) |
| New integration pattern (new credential type, new provider, new grant type) | `EXAMPLES.md` (add integration example) |
| ProGuard / R8 rules changed | `README.md` (ProGuard section), `FAQ.md` if relevant |

> **Never defer docs to a follow-up PR.** A PR that ships a new public method without an `EXAMPLES.md` entry is incomplete. The review checklist in `.github/PULL_REQUEST_TEMPLATE.md` confirms this.
