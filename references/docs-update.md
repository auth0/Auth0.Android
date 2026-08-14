# Docs Update Rules — Auth0.Android

## Tracked docs

| Doc | What it covers |
|-----|---------------|
| `README.md` | Installation (Gradle coords), requirements (minSdk 26, Java 17), Auth0 dashboard config, `AndroidManifest.xml` setup, quick-start login/logout, ProGuard rules |
| `EXAMPLES.md` | Full Kotlin + Java usage for all features: WebAuthProvider, CredentialsManager, SecureCredentialsManager, AuthenticationAPIClient, MFA, DPoP, My Account API, passkeys, bot protection, PAR, SSO |

Migration guides (`V4_MIGRATION_GUIDE.md`) are not tracked as fixed docs — filename is version-specific, inferred from the target branch at breaking-change time.

## Code-to-docs mapping (library shape)

| When this changes | Update |
|-------------------|--------|
| Public API entry point (`Auth0`, `WebAuthProvider`, `AuthenticationAPIClient`, `CredentialsManager`, `SecureCredentialsManager`, `MyAccountAPIClient`) | `README.md` quick-start, `EXAMPLES.md` affected samples |
| Constructor params or config options on public classes | `README.md` configuration section |
| `AndroidManifest.xml` changes (new activity, intent filter, permission) | `README.md` setup section |
| New authentication flow or major feature | `EXAMPLES.md` new section with Kotlin + Java sample |
| Public method or class added | `EXAMPLES.md` usage sample |
| Public method, property, or class removed or renamed | `README.md` + `EXAMPLES.md` remove/update references |
| SDK installation coordinates or minSdk/Java requirements changed | `README.md` installation + requirements |
| ProGuard/R8 rules changed | `README.md` ProGuard section |

> Never defer docs to a follow-up PR. A PR that ships a new public method without an `EXAMPLES.md` entry is incomplete.
