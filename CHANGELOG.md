# Change Log

## [3.12.0](https://github.com/auth0/Auth0.Android/tree/3.12.0) (2025-12-11)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/3.11.0...3.12.0)

**Added**
- feat: Add support for `organization` to custom token exchange [\#885](https://github.com/auth0/Auth0.Android/pull/885) ([pmathew92](https://github.com/pmathew92))

**Changed**
- refactor: Updating MRRT token store logic [\#884](https://github.com/auth0/Auth0.Android/pull/884) ([pmathew92](https://github.com/pmathew92))

## [3.11.0](https://github.com/auth0/Auth0.Android/tree/3.11.0) (2025-11-24)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/3.10.0...3.11.0)

**Added**
- feat: Added option to pass AuthenticationAPIClient to SecureCredentialsManager class  [\#879](https://github.com/auth0/Auth0.Android/pull/879) ([pmathew92](https://github.com/pmathew92))
- feat: add configurable biometric authentication policies for SecureCredentialsManager [\#867](https://github.com/auth0/Auth0.Android/pull/867) ([subhankarmaiti](https://github.com/subhankarmaiti))

**Fixed**
- fix: Fixes the IV overwrite when trying to encrypt multiple credentials  [\#882](https://github.com/auth0/Auth0.Android/pull/882) ([pmathew92](https://github.com/pmathew92))

## [3.10.0](https://github.com/auth0/Auth0.Android/tree/3.10.0) (2025-09-12)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/3.9.1...3.10.0)

**Added**
- SDK-6103 Added support for My Account API. [\#847](https://github.com/auth0/Auth0.Android/pull/847) ([utkrishtsahu](https://github.com/utkrishtsahu))

## [3.9.1](https://github.com/auth0/Auth0.Android/tree/3.9.1) (2025-08-12)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/3.9.0...3.9.1)

**Fixed**
- fix: Fixed the transitive dependency issue on generated aar file [\#858](https://github.com/auth0/Auth0.Android/pull/858) ([pmathew92](https://github.com/pmathew92))

## [3.9.0](https://github.com/auth0/Auth0.Android/tree/3.9.0) (2025-08-11)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/3.8.0...3.9.0)

**Added**
- feat: Add support for DPoP [\#850](https://github.com/auth0/Auth0.Android/pull/850) ([pmathew92](https://github.com/pmathew92))
- feat : support to pass organisation while signing-up and signing-in with passkeys [\#843](https://github.com/auth0/Auth0.Android/pull/843) ([pmathew92](https://github.com/pmathew92))
- Exposes UserProfile to return contents of id token without refreshing credentials [\#840](https://github.com/auth0/Auth0.Android/pull/840) ([NandanPrabhu](https://github.com/NandanPrabhu))

**Updated**
- `userInfo` api in the `AuthenticationAPIClient` class now takes a tokenType parameter with a default value of `Bearer`. 

## [3.8.0](https://github.com/auth0/Auth0.Android/tree/3.8.0) (2025-06-04)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/3.7.0...3.8.0)

**Added**
- Added support to enroll passkeys with My Account API  [\#837](https://github.com/auth0/Auth0.Android/pull/837) ([pmathew92](https://github.com/pmathew92))

## [3.7.0](https://github.com/auth0/Auth0.Android/tree/3.7.0) (2025-05-09)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/3.6.0...3.7.0)

**Added**
- Add support for Multi-Resource Refresh Token (MRRT) [\#811](https://github.com/auth0/Auth0.Android/pull/811) ([pmathew92](https://github.com/pmathew92))
- Allow updating the logout and authorize url [\#822](https://github.com/auth0/Auth0.Android/pull/822) ([utkrishtsahu](https://github.com/utkrishtsahu))

## [3.6.0](https://github.com/auth0/Auth0.Android/tree/3.6.0) (2025-04-28)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/3.5.0...3.6.0)

**Added**
- Added new error type to CredentialsManagerException class [\#821](https://github.com/auth0/Auth0.Android/pull/821) ([pmathew92](https://github.com/pmathew92))
- Added  Native to Web support [\#803](https://github.com/auth0/Auth0.Android/pull/803) ([pmathew92](https://github.com/pmathew92))

**Changed**
- Removed experimental tag from TWA [\#818](https://github.com/auth0/Auth0.Android/pull/818) ([pmathew92](https://github.com/pmathew92))

## [3.5.0](https://github.com/auth0/Auth0.Android/tree/3.5.0) (2025-03-17)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/3.4.0...3.5.0)

**Added**
- Updated documentation to pass an activity context for login and logout [\#808](https://github.com/auth0/Auth0.Android/pull/808) ([pmathew92](https://github.com/pmathew92))
- Add to CustomTabsOptions ability to disable opening auth in custom tab [\#806](https://github.com/auth0/Auth0.Android/pull/806) ([bennycao](https://github.com/bennycao))

**Changed**
- Fixed the java samples in the Example.md file [\#807](https://github.com/auth0/Auth0.Android/pull/807) ([pmathew92](https://github.com/pmathew92))

## [3.4.0](https://github.com/auth0/Auth0.Android/tree/3.4.0) (2025-02-13)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/3.3.0...3.4.0)

**Added**
- Support Process Death in WebAuthProvider [\#784](https://github.com/auth0/Auth0.Android/pull/784) ([ahibrahimleague](https://github.com/ahibrahimleague))

**Changed**
- Updated compile and target sdk version to 35 [\#799](https://github.com/auth0/Auth0.Android/pull/799) ([pmathew92](https://github.com/pmathew92))

## [3.3.0](https://github.com/auth0/Auth0.Android/tree/3.3.0) (2025-02-03)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/3.2.1...3.3.0)

**Added**
- Add support for custom token exchange [\#789](https://github.com/auth0/Auth0.Android/pull/789) ([pmathew92](https://github.com/pmathew92))

## [3.2.1](https://github.com/auth0/Auth0.Android/tree/3.2.1) (2024-12-06)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/3.2.0...3.2.1)

**Added**
- Added new error types for CredentialsManagerException [\#783](https://github.com/auth0/Auth0.Android/pull/783) ([pmathew92](https://github.com/pmathew92))
- Making realm parameter optional for passkeys [\#776](https://github.com/auth0/Auth0.Android/pull/776) ([pmathew92](https://github.com/pmathew92))

## [3.2.0](https://github.com/auth0/Auth0.Android/tree/3.2.0) (2024-11-07)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/3.1.0...3.2.0)

**Added**
- Supporting passkey via AuthenticationAPIClient [\#773](https://github.com/auth0/Auth0.Android/pull/773) ([pmathew92](https://github.com/pmathew92))

## [3.1.0](https://github.com/auth0/Auth0.Android/tree/3.1.0) (2024-10-31)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/3.0.0...3.1.0)

**Added**
- Support for Passkey Authentication [\#770](https://github.com/auth0/Auth0.Android/pull/770) ([pmathew92](https://github.com/pmathew92))

## [3.0.0](https://github.com/auth0/Auth0.Android/tree/3.0.0) (2024-10-30)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/2.11.0...3.0.0)

Check the [Migration Guide](https://github.com/auth0/Auth0.Android/blob/main/V3_MIGRATION_GUIDE.md) to understand the changes required to migrate your application to v3
Check the [3.0.0.beta.0][https://github.com/auth0/Auth0.Android/releases/tag/3.0.0-beta.0] to understand other major changes

**⚠️ BREAKING CHANGES**
- BREAKING CHANGE: updated description of AuthenticationException in case of empty description [\#756](https://github.com/auth0/Auth0.Android/pull/756) ([desusai7](https://github.com/desusai7))
- feat: implemented biometrics authentication for SecureCredentialsManager using androidx.biometrics package [\#745](https://github.com/auth0/Auth0.Android/pull/745) ([desusai7](https://github.com/desusai7))

**Added**
- Handled NPE in the AuthenticationActivity  [\#759](https://github.com/auth0/Auth0.Android/pull/759) ([pmathew92](https://github.com/pmathew92))

## [3.0.0-beta.0](https://github.com/auth0/Auth0.Android/tree/3.0.0-beta.0) (2024-08-01)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/2.11.0...3.0.0-beta.0)

**⚠️ BREAKING CHANGES**
- feat: implemented biometrics authentication for SecureCredentialsManager using androidx.biometrics package [\#745](https://github.com/auth0/Auth0.Android/pull/745) ([desusai7](https://github.com/desusai7))

## [2.11.0](https://github.com/auth0/Auth0.Android/tree/2.11.0) (2024-05-08)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/2.10.2...2.11.0)

**Added**
- Implement headers support in getCredentials and awaitCredentials [\#699](https://github.com/auth0/Auth0.Android/pull/699) ([poovamraj](https://github.com/poovamraj))

**Fixed**
- Guard against NullPointerException when getting Credentials from Json [\#701](https://github.com/auth0/Auth0.Android/pull/701) ([bennycao](https://github.com/bennycao))

**Security**
- Bump codecov/codecov-action from 3.1.4 to 4.0.1 [\#714](https://github.com/auth0/Auth0.Android/pull/714) ([dependabot[bot]](https://github.com/apps/dependabot))
- Bump github/codeql-action from 2 to 3 [\#705](https://github.com/auth0/Auth0.Android/pull/705) ([dependabot[bot]](https://github.com/apps/dependabot))
- chore(dependencies): Update OkHttp to 4.12.0 [\#696](https://github.com/auth0/Auth0.Android/pull/696) ([evansims](https://github.com/evansims))

## [2.10.2](https://github.com/auth0/Auth0.Android/tree/2.10.2) (2023-10-04)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/2.10.1...2.10.2)

**Fixed**
- Destroy TWA Launcher at unbind [\#690](https://github.com/auth0/Auth0.Android/pull/690) ([poovamraj](https://github.com/poovamraj))
- Use ThreadPool to launch browser for authentication [\#689](https://github.com/auth0/Auth0.Android/pull/689) ([poovamraj](https://github.com/poovamraj))

**Security**
- Update Okio to resolve CVE-2023-3635 [\#687](https://github.com/auth0/Auth0.Android/pull/687) ([jimmyjames](https://github.com/jimmyjames))
- build(dependencies): Update OkHttp to 4.11.0 [SDK-4501] [\#684](https://github.com/auth0/Auth0.Android/pull/684) ([evansims](https://github.com/evansims))

## [2.10.1](https://github.com/auth0/Auth0.Android/tree/2.10.1) (2023-08-01)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/2.10.0...2.10.1)

**Fixed**
- Handle SecurityException thrown while launching the browser [\#677](https://github.com/auth0/Auth0.Android/pull/677) ([poovamraj](https://github.com/poovamraj))

## [2.10.0](https://github.com/auth0/Auth0.Android/tree/2.10.0) (2023-07-18)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/2.9.3...2.10.0)

**Added**
- Return refreshed Credentials in CredentialsManagerException to avoid logout [\#666](https://github.com/auth0/Auth0.Android/pull/666) ([poovamraj](https://github.com/poovamraj))
- [SDK-4413] Support Organization Name [\#669](https://github.com/auth0/Auth0.Android/pull/669) ([poovamraj](https://github.com/poovamraj))
- Add more error pairs to isMultifactorCodeInvalid [SDK-4194] [\#664](https://github.com/auth0/Auth0.Android/pull/664) ([poovamraj](https://github.com/poovamraj))

**Fixed**
- Avoid null pointer exception because of error description [\#667](https://github.com/auth0/Auth0.Android/pull/667) ([poovamraj](https://github.com/poovamraj))
- Revert changes from #654. Fix renew Credentials logic [\#670](https://github.com/auth0/Auth0.Android/pull/670) ([poovamraj](https://github.com/poovamraj))

**Security**
- chore(security): Update and pin Graddle workflow actions [\#671](https://github.com/auth0/Auth0.Android/pull/671) ([evansims](https://github.com/evansims))

## [2.9.3](https://github.com/auth0/Auth0.Android/tree/2.9.3) (2023-05-19)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/2.9.2...2.9.3)

**Fixed**
- Consider SocketException as network error [\#659](https://github.com/auth0/Auth0.Android/pull/659) ([poovamraj](https://github.com/poovamraj))
- [ESD-28245] Fix not propagating error values from server [\#658](https://github.com/auth0/Auth0.Android/pull/658) ([poovamraj](https://github.com/poovamraj))

## [2.9.2](https://github.com/auth0/Auth0.Android/tree/2.9.2) (2023-05-05)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/2.9.1...2.9.2)

**Fixed**
- Add required scopes to token and renewAuth requests [\#654](https://github.com/auth0/Auth0.Android/pull/654) ([poovamraj](https://github.com/poovamraj))
- Added rule to support Proguard in full mode [\#652](https://github.com/auth0/Auth0.Android/pull/652) ([poovamraj](https://github.com/poovamraj))

## [2.9.1](https://github.com/auth0/Auth0.Android/tree/2.9.1) (2023-04-18)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/2.9.0...2.9.1)

**Fixed**
- Update dependencies [\#641](https://github.com/auth0/Auth0.Android/pull/641) ([poovamraj](https://github.com/poovamraj))

## [2.9.0](https://github.com/auth0/Auth0.Android/tree/2.9.0) (2023-03-16)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/2.8.1...2.9.0)

**Added**
- Added forceRefresh option to getCredentials [\#637](https://github.com/auth0/Auth0.Android/pull/637) ([poovamraj](https://github.com/poovamraj))
- Add Invalid refresh token flag [\#635](https://github.com/auth0/Auth0.Android/pull/635) ([poovamraj](https://github.com/poovamraj))
- [SDK-3348] Implement trusted web activity support [\#631](https://github.com/auth0/Auth0.Android/pull/631) ([poovamraj](https://github.com/poovamraj))
- Allow `authorizeUrl` and `logoutUrl` customisation [\#622](https://github.com/auth0/Auth0.Android/pull/622) ([poovamraj](https://github.com/poovamraj))
- Add AuthenticationException.isTooManyAttempts error [\#615](https://github.com/auth0/Auth0.Android/pull/615) ([tomhusson-toast](https://github.com/tomhusson-toast))

**Fixed**
- Gson crashes when minified with R8 strict mode [\#634](https://github.com/auth0/Auth0.Android/pull/634) ([wiyarmir](https://github.com/wiyarmir))

## [2.8.1](https://github.com/auth0/Auth0.Android/tree/2.8.1) (2023-01-11)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/2.8.0...2.8.1)

This patch release does not contain any functional changes, but is being released using an updated signing key for verification as part of our commitment to best security practices.
Please review [the README note for additional details.](https://github.com/auth0/Auth0.Android/blob/main/README.md)

## [2.8.0](https://github.com/auth0/Auth0.Android/tree/2.8.0) (2022-07-05)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/2.7.0...2.8.0)

**Added**
- [SDK-3329] Improved ID token exception API [\#577](https://github.com/auth0/Auth0.Android/pull/577) ([poovamraj](https://github.com/poovamraj))
- [SDK-3144] Add user property to Credentials [\#569](https://github.com/auth0/Auth0.Android/pull/569) ([adamjmcgrath](https://github.com/adamjmcgrath))
- [SDK-3353] Validate claims for ID Token received in Authentication API Client [\#575](https://github.com/auth0/Auth0.Android/pull/575) ([poovamraj](https://github.com/poovamraj))
- [SDK-3346] Implemented coroutine support [\#563](https://github.com/auth0/Auth0.Android/pull/563) ([poovamraj](https://github.com/poovamraj))

**Changed**
- [SDK-3358] Improve Android README [\#579](https://github.com/auth0/Auth0.Android/pull/579) ([adamjmcgrath](https://github.com/adamjmcgrath))
- [SDK-3352] Expire credentials based on access token alone [\#572](https://github.com/auth0/Auth0.Android/pull/572) ([adamjmcgrath](https://github.com/adamjmcgrath))

**Deprecated**
- Remove `user_metadata` use case from `addSignUpParameters` [\#567](https://github.com/auth0/Auth0.Android/pull/567) ([adamjmcgrath](https://github.com/adamjmcgrath))

**Fixed**
- [SDK-3452] Network Exception Issue Fix [\#580](https://github.com/auth0/Auth0.Android/pull/580) ([poovamraj](https://github.com/poovamraj))
- [SDK-3350] Empty credentials before continuing should throw CredentialsManagerException [\#576](https://github.com/auth0/Auth0.Android/pull/576) ([poovamraj](https://github.com/poovamraj))
- [SDK-3354] Deserialize UserProfile.createdAt as ISO8601 [\#571](https://github.com/auth0/Auth0.Android/pull/571) ([adamjmcgrath](https://github.com/adamjmcgrath))
- [SDK-3082] Avoid config change to handle authentication [\#566](https://github.com/auth0/Auth0.Android/pull/566) ([poovamraj](https://github.com/poovamraj))
- createdAt should be deserialized as ISO8601 UTC (not local time) [\#564](https://github.com/auth0/Auth0.Android/pull/564) ([adamjmcgrath](https://github.com/adamjmcgrath))

**Security**
- Security: Update OkHttp to 4.10.0 [\#574](https://github.com/auth0/Auth0.Android/pull/574) ([evansims](https://github.com/evansims))
- Security: Bump Kotlin Stdlib to 1.6.20 to address CVE-2022-24329 [\#552](https://github.com/auth0/Auth0.Android/pull/552) ([evansims](https://github.com/evansims))
- Bump OkHttp version [\#551](https://github.com/auth0/Auth0.Android/pull/551) ([lbalmaceda](https://github.com/lbalmaceda))

## [2.7.0](https://github.com/auth0/Auth0.Android/tree/2.7.0) (2022-02-25)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/2.6.0...2.7.0)

**Changed**
- Implement Thread Safe Credential Manager [\#542](https://github.com/auth0/Auth0.Android/pull/542) ([poovamraj](https://github.com/poovamraj))

## [2.6.0](https://github.com/auth0/Auth0.Android/tree/2.6.0) (2021-12-07)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/2.5.1...2.6.0)

**Changed**
- Improve authenticated flow of the Credentials Manager [\#519](https://github.com/auth0/Auth0.Android/pull/519) ([lbalmaceda](https://github.com/lbalmaceda))

## [2.5.1](https://github.com/auth0/Auth0.Android/tree/2.5.1) (2021-11-08)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/2.5.0...2.5.1)

**Security**
- Bump GSON dependency to 2.8.9 [\#526](https://github.com/auth0/Auth0.Android/pull/526) ([evansims](https://github.com/evansims))

## [2.5.0](https://github.com/auth0/Auth0.Android/tree/2.5.0) (2021-10-11)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/2.4.0...2.5.0)

**Added**
- Credentials Managers: renew tokens with extra parameters [\#514](https://github.com/auth0/Auth0.Android/pull/514) ([lustikuss](https://github.com/lustikuss))

**Changed**
- Update Configuration URL (CDN URL) [SDK-2710] [\#520](https://github.com/auth0/Auth0.Android/pull/520) ([lbalmaceda](https://github.com/lbalmaceda))

**Fixed**
- Fix memory leak in CustomTabsService [\#517](https://github.com/auth0/Auth0.Android/pull/517) ([lbalmaceda](https://github.com/lbalmaceda))
- Prevent NPE when parsing email_verified boolean [\#516](https://github.com/auth0/Auth0.Android/pull/516) ([lbalmaceda](https://github.com/lbalmaceda))
- Proper migration for the new key sets was applied [\#512](https://github.com/auth0/Auth0.Android/pull/512) ([lbalmaceda](https://github.com/lbalmaceda))
- Always close request body InputStream when exception occurs [\#492](https://github.com/auth0/Auth0.Android/pull/492) ([Marcono1234](https://github.com/Marcono1234))

## [2.4.0](https://github.com/auth0/Auth0.Android/tree/2.4.0) (2021-07-20)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/2.3.0...2.4.0)

**Added**
- Add federated option to the Web Auth Logout [SDK-2165] [\#501](https://github.com/auth0/Auth0.Android/pull/501) ([lbalmaceda](https://github.com/lbalmaceda))
- Add support for Recovery Code multi-factor authentication [\#500](https://github.com/auth0/Auth0.Android/pull/500) ([lbalmaceda](https://github.com/lbalmaceda))
- Add support for OOB multi-factor authentication [SDK-2657] [\#498](https://github.com/auth0/Auth0.Android/pull/498) ([lbalmaceda](https://github.com/lbalmaceda))

**Fixed**
- Fix MFA Challenge authentication and prevent sending the scope again [\#504](https://github.com/auth0/Auth0.Android/pull/504) ([lbalmaceda](https://github.com/lbalmaceda))
- Fix bug parsing content type headers [\#503](https://github.com/auth0/Auth0.Android/pull/503) ([lbalmaceda](https://github.com/lbalmaceda))
- Catch IOExceptions from response body InputStream [\#486](https://github.com/auth0/Auth0.Android/pull/486) ([jeffdgr8](https://github.com/jeffdgr8))

## [2.3.0](https://github.com/auth0/Auth0.Android/tree/2.3.0) (2021-07-02)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/2.2.0...2.3.0)

**Changed**
- Explicitly specify charset, don't rely on default charset [\#491](https://github.com/auth0/Auth0.Android/pull/491) ([Marcono1234](https://github.com/Marcono1234))
- Disable share button in Chrome custom tabs [\#489](https://github.com/auth0/Auth0.Android/pull/489) ([latsson](https://github.com/latsson))
- Rewrite ThreadSwitcher class so that it is not tied to Looper [\#482](https://github.com/auth0/Auth0.Android/pull/482) ([alvindizon](https://github.com/alvindizon))

**Fixed**
- Improve access_denied error handling by using the description [\#494](https://github.com/auth0/Auth0.Android/pull/494) ([lbalmaceda](https://github.com/lbalmaceda))

## [2.2.0](https://github.com/auth0/Auth0.Android/tree/2.2.0) (2021-04-21)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/2.1.0...2.2.0)

**Added**
- Accept UserMetadata for creating users [SDK-2429] [\#475](https://github.com/auth0/Auth0.Android/pull/475) ([lbalmaceda](https://github.com/lbalmaceda))

**Fixed**
- Let dokka plugin pull dependencies from JCenter [\#471](https://github.com/auth0/Auth0.Android/pull/471) ([lbalmaceda](https://github.com/lbalmaceda))

## [2.1.0](https://github.com/auth0/Auth0.Android/tree/2.1.0) (2021-03-26)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/2.0.0...2.1.0)

**Added**
- Add support for Organizations [SDK-2396] [\#467](https://github.com/auth0/Auth0.Android/pull/467) ([lbalmaceda](https://github.com/lbalmaceda))

**Changed**
- Migrate to newer OSS Plugin with support for Sonatype [\#469](https://github.com/auth0/Auth0.Android/pull/469) ([lbalmaceda](https://github.com/lbalmaceda))

**Fixed**
- Add Java's R8 Proguard rules for Gson [\#465](https://github.com/auth0/Auth0.Android/pull/465) ([lbalmaceda](https://github.com/lbalmaceda))

## [2.0.0](https://github.com/auth0/Auth0.Android/tree/2.0.0) (2021-02-10)

**This is a major release and contains breaking changes!** 

Please see the [migration guide](V2_MIGRATION_GUIDE.md) document. The full changelog from version 1 to version 2 is [here](https://github.com/auth0/Auth0.Android/compare/1.30.0...2.0.0).

### New requirements
v2 requires Android API version 21 or later and Java 8+. Update your `build.gradle` file with the following:

```groovy
android {
    compileOptions {
        sourceCompatibility JavaVersion.VERSION_1_8
        targetCompatibility JavaVersion.VERSION_1_8
    }

    kotlinOptions {
        jvmTarget = '1.8'
    }
}
```

### Main features
- Supports exclusively the **OpenID Connect** authentication pipeline from Auth0.
- Uses **AndroidX** dependencies, and drops the use of the Jetifier plugin.
- Reworked networking stack. Offers a **customizable Networking Client**. 

See the changelog entries below for additional details.

What follows is the summary of changes made from `2.0.0-beta.0`.

[Full Changelog](https://github.com/auth0/Auth0.Android/compare/2.0.0-beta.0...2.0.0)

**Changed**
- Improve Credentials class nullability [\#457](https://github.com/auth0/Auth0.Android/pull/457) ([lbalmaceda](https://github.com/lbalmaceda))
- Enforce openid scope on the AuthenticationAPIClient [\#455](https://github.com/auth0/Auth0.Android/pull/455) ([lbalmaceda](https://github.com/lbalmaceda))
- Make JsonRequired annotation internal  [\#452](https://github.com/auth0/Auth0.Android/pull/452) ([lbalmaceda](https://github.com/lbalmaceda))
- Make requests that return Void have an optional type [\#447](https://github.com/auth0/Auth0.Android/pull/447) ([lbalmaceda](https://github.com/lbalmaceda))

## [2.0.0-beta.0](https://github.com/auth0/Auth0.Android/tree/2.0.0-beta.0) (2021-01-19)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.30.0...2.0.0-beta.0)

**Changed**
- Refactor JWT decoding logic [\#443](https://github.com/auth0/Auth0.Android/pull/443) ([lbalmaceda](https://github.com/lbalmaceda))
- Explicitly reject "none" signing algorithm [\#442](https://github.com/auth0/Auth0.Android/pull/442) ([lbalmaceda](https://github.com/lbalmaceda))
- Receive NetworkingClient through the Auth0 instance [\#440](https://github.com/auth0/Auth0.Android/pull/440) ([lbalmaceda](https://github.com/lbalmaceda))
- Update the Credentials class [\#435](https://github.com/auth0/Auth0.Android/pull/435) ([lbalmaceda](https://github.com/lbalmaceda))
- Move to a JSON client singleton [\#433](https://github.com/auth0/Auth0.Android/pull/433) ([lbalmaceda](https://github.com/lbalmaceda))
- Migrate default NetworkingClient implementation to use OkHttp [\#428](https://github.com/auth0/Auth0.Android/pull/428) ([lbalmaceda](https://github.com/lbalmaceda))
- Enforce the "openid" scope for the WebAuthProvider [\#422](https://github.com/auth0/Auth0.Android/pull/422) ([lbalmaceda](https://github.com/lbalmaceda))
- Update WebAuthProvider#start required Context [\#421](https://github.com/auth0/Auth0.Android/pull/421) ([lbalmaceda](https://github.com/lbalmaceda))
- Stop using kotlin.Unit in public APIs [\#414](https://github.com/auth0/Auth0.Android/pull/414) ([lbalmaceda](https://github.com/lbalmaceda))
- Migrate Public API to Kotlin [\#410](https://github.com/auth0/Auth0.Android/pull/410) ([lbalmaceda](https://github.com/lbalmaceda))

**Deprecated**
- Deprecate isAuthenticationCanceled in favor of isCanceled [\#425](https://github.com/auth0/Auth0.Android/pull/425) ([lbalmaceda](https://github.com/lbalmaceda))
- Merge BaseCallback into Callback [\#416](https://github.com/auth0/Auth0.Android/pull/416) ([jimmyjames](https://github.com/jimmyjames))

**Removed**
- Remove setUserAgent methods from API clients [\#444](https://github.com/auth0/Auth0.Android/pull/444) ([lbalmaceda](https://github.com/lbalmaceda))
- Remove timeouts and logging setters from Auth0 class [\#441](https://github.com/auth0/Auth0.Android/pull/441) ([lbalmaceda](https://github.com/lbalmaceda))
- Run and fix inspections, remove unused classes [\#439](https://github.com/auth0/Auth0.Android/pull/439) ([lbalmaceda](https://github.com/lbalmaceda))
- Remove obsolete config properties [\#432](https://github.com/auth0/Auth0.Android/pull/432) ([jimmyjames](https://github.com/jimmyjames))
- Remove DatabaseConnectionRequest class [\#417](https://github.com/auth0/Auth0.Android/pull/417) ([lbalmaceda](https://github.com/lbalmaceda))

**Fixed**
- Fix request to patch user metadata [\#429](https://github.com/auth0/Auth0.Android/pull/429) ([lbalmaceda](https://github.com/lbalmaceda))

**Breaking changes**
- Stop using VoidCallback on WebAuth Logout  [\#424](https://github.com/auth0/Auth0.Android/pull/424) ([lbalmaceda](https://github.com/lbalmaceda))
- Change WebAuthProvider (Login) callback type [\#415](https://github.com/auth0/Auth0.Android/pull/415) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.30.0](https://github.com/auth0/Auth0.Android/tree/1.30.0) (2020-12-18)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.29.2...1.30.0)

**Added**
- Add custom headers to social token request [\#351](https://github.com/auth0/Auth0.Android/pull/351) ([TLFilip](https://github.com/TLFilip))

**Deprecated**
- Deprecate API client constructors that take Context [\#393](https://github.com/auth0/Auth0.Android/pull/393) ([lbalmaceda](https://github.com/lbalmaceda))
- Deprecate Legacy Authentication APIs [\#391](https://github.com/auth0/Auth0.Android/pull/391) ([jimmyjames](https://github.com/jimmyjames))

## [1.29.2](https://github.com/auth0/Auth0.Android/tree/1.29.2) (2020-11-11)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.29.1...1.29.2)

**Fixed**
- Refactor: Move passwordless "invalid credentials" errors [\#373](https://github.com/auth0/Auth0.Android/pull/373) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.29.1](https://github.com/auth0/Auth0.Android/tree/1.29.1) (2020-11-10)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.29.0...1.29.1)

**Fixed**
- Handle API response for mobile OTP code incorrect. [\#371](https://github.com/auth0/Auth0.Android/pull/371) ([nicbell](https://github.com/nicbell))

## [1.29.0](https://github.com/auth0/Auth0.Android/tree/1.29.0) (2020-11-04)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.28.0...1.29.0)

**Added**
- SecureCredentialsManager: Allow to pass scope and minTTL [\#369](https://github.com/auth0/Auth0.Android/pull/369) ([lbalmaceda](https://github.com/lbalmaceda))
- CredentialsManager: Allow to pass scope and minTTL [\#363](https://github.com/auth0/Auth0.Android/pull/363) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.28.0](https://github.com/auth0/Auth0.Android/tree/1.28.0) (2020-10-13)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.27.0...1.28.0)

**Added**
- Accept a custom clock instance in both Credentials Managers [SDK-1973] [\#358](https://github.com/auth0/Auth0.Android/pull/358) ([lbalmaceda](https://github.com/lbalmaceda))

**Fixed**
- Catch a gson JsonIOException when parsing SimpleRequest response [SDK-1981] [\#355](https://github.com/auth0/Auth0.Android/pull/355) ([quibi-jlk](https://github.com/quibi-jlk))

## [1.27.0](https://github.com/auth0/Auth0.Android/tree/1.27.0) (2020-09-25)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.26.0...1.27.0)

**Added**
- Feat: Filter allowed CustomTabs browsers [\#353](https://github.com/auth0/Auth0.Android/pull/353) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.26.1](https://github.com/auth0/Auth0.Android/tree/1.26.1) (2020-09-16)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.26.0...1.26.1)

**Fixed**
- Fix NPE on Kotlin when callbacks returned a nullable value [\#344](https://github.com/auth0/Auth0.Android/pull/344) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.26.0](https://github.com/auth0/Auth0.Android/tree/1.26.0) (2020-09-11)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.25.0...1.26.0)

**Having project sync issues after upgrading?**
This release defines a "queries" element in the Android Manifest file to make the SDK compatible with Android 11 new privacy changes. If you run into a build compile issue when importing this version, make sure that you are using the latest patch version of the Android Gradle Plugin. Check the table in the [announcement blogpost](https://android-developers.googleblog.com/2020/07/preparing-your-build-for-package-visibility-in-android-11.html) to learn to what version you should update.



**Changed**
- Improve compatibility with Kotlin and run Lint on CI [\#337](https://github.com/auth0/Auth0.Android/pull/337) ([lbalmaceda](https://github.com/lbalmaceda))

**Fixed**
- Add support for Android 11 new privacy settings [\#335](https://github.com/auth0/Auth0.Android/pull/335) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.25.0](https://github.com/auth0/Auth0.Android/tree/1.25.0) (2020-08-21)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.24.1...1.25.0)

**Added**
- Add Bot Protection support [\#329](https://github.com/auth0/Auth0.Android/pull/329) ([lbalmaceda](https://github.com/lbalmaceda))
- Support use of Custom Issuer for ID Token verification [SDK-1910] [\#328](https://github.com/auth0/Auth0.Android/pull/328) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.24.1](https://github.com/auth0/Auth0.Android/tree/1.24.1) (2020-08-04)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.24.0...1.24.1)

**Fixed**
- Patch Key alias migration for Secure Credentials Manager [\#325](https://github.com/auth0/Auth0.Android/pull/325) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.24.0](https://github.com/auth0/Auth0.Android/tree/1.24.0) (2020-07-16)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.23.0...1.24.0)

### Read if using the SecureCredentialsManager
Starting from this version, the alias used to store the key pair in the Android Keystore is prefixed to avoid collisions between other Auth0 enabled apps. Your users will be facing a "credentials not found" scenario, requiring them to log in again **once**. Double check that you are not ignoring the errors being returned in the callback and documented [here](https://github.com/auth0/Auth0.Android#handling-exceptions).

**Changed**
- Allow to set headers and parameters in all requests [\#318](https://github.com/auth0/Auth0.Android/pull/318) ([lbalmaceda](https://github.com/lbalmaceda))

**Fixed**
- Use of a unique keystore key alias across apps [\#315](https://github.com/auth0/Auth0.Android/pull/315) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.23.0](https://github.com/auth0/Auth0.Android/tree/1.23.0) (2020-03-30)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.22.1...1.23.0)

**Added**
- Support Refresh Token Rotation [\#294](https://github.com/auth0/Auth0.Android/pull/294) ([lbalmaceda](https://github.com/lbalmaceda))

**Fixed**
- Improve consistency around Expires At in CredentialsManager [\#295](https://github.com/auth0/Auth0.Android/pull/295) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.22.1](https://github.com/auth0/Auth0.Android/tree/1.22.1) (2020-03-04)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.22.0...1.22.1)

**Fixed**
- Handle weird SecureCredentialsManager exceptions [\#288](https://github.com/auth0/Auth0.Android/pull/288) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.22.0](https://github.com/auth0/Auth0.Android/tree/1.22.0) (2020-02-06)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.21.0...1.22.0)

**Added**
- Add support for Social Native Token Exchange endpoint [\#281](https://github.com/auth0/Auth0.Android/pull/281) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.21.0](https://github.com/auth0/Auth0.Android/tree/1.21.0) (2020-01-29)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.20.1...1.21.0)

**Added**
- Allow to customize the redirect URI / return to URL [\#279](https://github.com/auth0/Auth0.Android/pull/279) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.20.1](https://github.com/auth0/Auth0.Android/tree/1.20.1) (2020-01-10)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.20.0...1.20.1)

**Changed**
- Update OSS Gradle plugin version [\#275](https://github.com/auth0/Auth0.Android/pull/275) ([lbalmaceda](https://github.com/lbalmaceda))

**Removed**
- Remove issued_at value check [\#274](https://github.com/auth0/Auth0.Android/pull/274) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.20.0](https://github.com/auth0/Auth0.Android/tree/1.20.0) (2019-12-23)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.19.1...1.20.0)

**Added**
- Add OIDC passwordless  [\#271](https://github.com/auth0/Auth0.Android/pull/271) ([lbalmaceda](https://github.com/lbalmaceda))
- Support fetching the JWKS [\#260](https://github.com/auth0/Auth0.Android/pull/260) ([lbalmaceda](https://github.com/lbalmaceda))

**Fixed**
- Use closeTo to still match with small differences [part 2] [\#272](https://github.com/auth0/Auth0.Android/pull/272) ([lbalmaceda](https://github.com/lbalmaceda))

**Security**
- Improve OIDC compliance [\#265](https://github.com/auth0/Auth0.Android/pull/265) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.19.1](https://github.com/auth0/Auth0.Android/tree/1.19.1) (2019-11-29)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.19.0...1.19.1)

**Fixed**
- Fix CredentialsManager migration scenario [\#266](https://github.com/auth0/Auth0.Android/pull/266) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.19.0](https://github.com/auth0/Auth0.Android/tree/1.19.0) (2019-09-10)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.18.0...1.19.0)

**Changed**
- Update CredentialManager classes to include IDToken expiration [\#254](https://github.com/auth0/Auth0.Android/pull/254) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.18.0](https://github.com/auth0/Auth0.Android/tree/1.18.0) (2019-07-26)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.17.0...1.18.0)

**Changed**
- Update gradle android plugin and wrapper version [\#250](https://github.com/auth0/Auth0.Android/pull/250) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.17.0](https://github.com/auth0/Auth0.Android/tree/1.17.0) (2019-06-28)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.16.0...1.17.0)

**Added**
- Add WebAuth Logout feature [\#245](https://github.com/auth0/Auth0.Android/pull/245) ([lbalmaceda](https://github.com/lbalmaceda))

**Deprecated**
- Deprecate WebAuthProvider.init() [\#247](https://github.com/auth0/Auth0.Android/pull/247) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.16.0](https://github.com/auth0/Auth0.Android/tree/1.16.0) (2019-06-18)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.15.2...1.16.0)

**Added**
- Support Web authentication cancel scenario [\#240](https://github.com/auth0/Auth0.Android/pull/240) ([lbalmaceda](https://github.com/lbalmaceda))
- Expose NetworkErrorException when request fails due to networking [\#235](https://github.com/auth0/Auth0.Android/pull/235) ([lbalmaceda](https://github.com/lbalmaceda))

**Fixed**
- Update PKCE usage requirements and errors [\#239](https://github.com/auth0/Auth0.Android/pull/239) ([lbalmaceda](https://github.com/lbalmaceda))
- Make connection_scope separate values with comma [\#236](https://github.com/auth0/Auth0.Android/pull/236) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.15.2](https://github.com/auth0/Auth0.Android/tree/1.15.2) (2019-04-17)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.15.1...1.15.2)

**Fixed**
- Update telemetry format [\#228](https://github.com/auth0/Auth0.Android/pull/228) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.15.1](https://github.com/auth0/Auth0.Android/tree/1.15.1) (2019-01-28)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.15.0...1.15.1)

**Fixed**
- Delete keys and stored Credentials on unrecoverable use cases [\#218](https://github.com/auth0/Auth0.Android/pull/218) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.15.0](https://github.com/auth0/Auth0.Android/tree/1.15.0) (2019-01-10)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.14.1...1.15.0)

**Added**
- Allow to override default timeouts for Http Client [\#206](https://github.com/auth0/Auth0.Android/pull/206) ([nolivermke](https://github.com/nolivermke))

**Changed**
- Update Telemetry format [\#209](https://github.com/auth0/Auth0.Android/pull/209) ([lbalmaceda](https://github.com/lbalmaceda))

**Fixed**
- Add Android P support for SecureCredentialsManager [\#203](https://github.com/auth0/Auth0.Android/pull/203) ([TheGamer007](https://github.com/TheGamer007))

## [1.14.1](https://github.com/auth0/Auth0.Android/tree/1.14.1) (2018-10-04)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.14.0...1.14.1)

**Fixed**
- Use latest patch of the OSS plugin [\#190](https://github.com/auth0/Auth0.Android/pull/190) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.14.0](https://github.com/auth0/Auth0.Android/tree/1.14.0) (2018-10-03)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.13.2...1.14.0)

**Fixed**
- Change target sdk to 28 and use latest Gradle plugin [\#186](https://github.com/auth0/Auth0.Android/pull/186) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.13.2](https://github.com/auth0/Auth0.Android/tree/1.13.2) (2018-07-20)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.13.1...1.13.2)

**Fixed**
- Fix service handling when custom tabs are not available [\#173](https://github.com/auth0/Auth0.Android/pull/173) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.13.1](https://github.com/auth0/Auth0.Android/tree/1.13.1) (2018-07-13)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.13.0...1.13.1)

**Fixed**
- Fix Web Authentication issues [\#169](https://github.com/auth0/Auth0.Android/pull/169) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.13.0](https://github.com/auth0/Auth0.Android/tree/1.13.0) (2018-06-05)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.12.2...1.13.0)

**Added**
- Allow SSO error to go through [\#161](https://github.com/auth0/Auth0.Android/pull/161) ([lbalmaceda](https://github.com/lbalmaceda))
- Add support for MFA using OIDC conformant endpoints [\#146](https://github.com/auth0/Auth0.Android/pull/146) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.12.2](https://github.com/auth0/Auth0.Android/tree/1.12.2) (2018-03-19)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.12.1...1.12.2)

**Fixed**
- Disable HTTP 2 protocol on OkHttp client [\#152](https://github.com/auth0/Auth0.Android/pull/152) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.12.1](https://github.com/auth0/Auth0.Android/tree/1.12.1) (2018-02-01)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.12.0...1.12.1)

**Fixed**
- Fix NPE when browser re-attempts a finished authentication [\#143](https://github.com/auth0/Auth0.Android/pull/143) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.12.0](https://github.com/auth0/Auth0.Android/tree/1.12.0) (2017-11-17)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.11.0...1.12.0)

**Added**
- Add support for TLS1.2 on pre-lollipop devices. [\#128](https://github.com/auth0/Auth0.Android/pull/128) ([dj-mal](https://github.com/dj-mal))

## [1.11.0](https://github.com/auth0/Auth0.Android/tree/1.11.0) (2017-10-17)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.10.1...1.11.0)

**Added**
- Add an encrypted version of the CredentialsManager [\#115](https://github.com/auth0/Auth0.Android/pull/115) ([lbalmaceda](https://github.com/lbalmaceda))
- Allow Custom Tabs UI to be customizable [\#111](https://github.com/auth0/Auth0.Android/pull/111) ([lbalmaceda](https://github.com/lbalmaceda))

**Changed**
- Make Credential Managers save the refreshed value [\#118](https://github.com/auth0/Auth0.Android/pull/118) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.10.1](https://github.com/auth0/Auth0.Android/tree/1.10.1) (2017-10-05)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.10.0...1.10.1)

**Fixed**
- Make CCT stay alive when activity is paused [\#121](https://github.com/auth0/Auth0.Android/pull/121) ([lbalmaceda](https://github.com/lbalmaceda))
- Fix bug when canceling WebAuth flow [\#120](https://github.com/auth0/Auth0.Android/pull/120) ([lbalmaceda](https://github.com/lbalmaceda))
- Capture invalid_credentials error for OIDC endpoints [\#114](https://github.com/auth0/Auth0.Android/pull/114) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.10.0](https://github.com/auth0/Auth0.Android/tree/1.10.0) (2017-07-19)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.9.0...1.10.0)

**Changed**
- Add a manifest placeholder for configuring the scheme [\#110](https://github.com/auth0/Auth0.Android/pull/110) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.9.0](https://github.com/auth0/Auth0.Android/tree/1.9.0) (2017-07-10)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.8.0...1.9.0)

**Added**
- Add hasValidCredentials and clearCredentials to CredentialsManager [\#102](https://github.com/auth0/Auth0.Android/pull/102) ([lbalmaceda](https://github.com/lbalmaceda))
- Add granted scope to the Credentials object [\#97](https://github.com/auth0/Auth0.Android/pull/97) ([lbalmaceda](https://github.com/lbalmaceda))
- Add CredentialsManager and generic Storage [\#96](https://github.com/auth0/Auth0.Android/pull/96) ([lbalmaceda](https://github.com/lbalmaceda))

**Changed**
- Use Chrome Custom Tabs when possible [\#95](https://github.com/auth0/Auth0.Android/pull/95) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.8.0](https://github.com/auth0/Auth0.Android/tree/1.8.0) (2017-04-27)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.7.0...1.8.0)

**Added**
- Add method to revoke a refresh_token [\#86](https://github.com/auth0/Auth0.Android/pull/86) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.7.0](https://github.com/auth0/Auth0.Android/tree/1.7.0) (2017-04-06)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.6.0...1.7.0)

**Added**
- Add WebAuthProvider Rule error message parsing [\#89](https://github.com/auth0/Auth0.Android/pull/89) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.6.0](https://github.com/auth0/Auth0.Android/tree/1.6.0) (2017-03-02)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.5.0...1.6.0)

**Added**
- Add expires_in field to the Credentials class [\#78](https://github.com/auth0/Auth0.Android/pull/78) ([lbalmaceda](https://github.com/lbalmaceda))
- Added: GET UserProfile endpoint for UsersAPIClient [\#76](https://github.com/auth0/Auth0.Android/pull/76) ([lbalmaceda](https://github.com/lbalmaceda))

**Changed**
- Extract the user id from the 'sub' claim if present [\#77](https://github.com/auth0/Auth0.Android/pull/77) ([lbalmaceda](https://github.com/lbalmaceda))
- Strictly compare the OIDC invalid_request message [\#75](https://github.com/auth0/Auth0.Android/pull/75) ([lbalmaceda](https://github.com/lbalmaceda))
- Credentials fields are not guaranteed to be present [\#74](https://github.com/auth0/Auth0.Android/pull/74) ([lbalmaceda](https://github.com/lbalmaceda))

**Fixed**
- Ensure closing the response body after it was parsed [\#79](https://github.com/auth0/Auth0.Android/pull/79) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.5.0](https://github.com/auth0/Auth0.Android/tree/1.5.0) (2017-01-31)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.4.0...1.5.0)

**Added**
- Log a warning message when using non-OIDC endpoints in OIDC mode [\#70](https://github.com/auth0/Auth0.Android/pull/70) ([lbalmaceda](https://github.com/lbalmaceda))
- Refresh auth using /oauth/token refresh_token grant (OIDC mode) [\#68](https://github.com/auth0/Auth0.Android/pull/68) ([lbalmaceda](https://github.com/lbalmaceda))

**Fixed**
- Fix JavaDoc errors and warnings [\#72](https://github.com/auth0/Auth0.Android/pull/72) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.4.0](https://github.com/auth0/Auth0.Android/tree/1.4.0) (2017-01-02)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.3.0...1.4.0)

**Added**
- Update Proguard rules and include them on the packaging [\#66](https://github.com/auth0/Auth0.Android/pull/66) ([lbalmaceda](https://github.com/lbalmaceda))
- Add base values getters for the Telemetry class [\#63](https://github.com/auth0/Auth0.Android/pull/63) ([lbalmaceda](https://github.com/lbalmaceda))
- Add warning log message when custom scheme is not lower case [\#58](https://github.com/auth0/Auth0.Android/pull/58) ([lbalmaceda](https://github.com/lbalmaceda))
- Add flag to authenticate with OIDC mode [\#57](https://github.com/auth0/Auth0.Android/pull/57) ([lbalmaceda](https://github.com/lbalmaceda))
- Customize the Scheme used in the redirect_uri parameter [\#54](https://github.com/auth0/Auth0.Android/pull/54) ([lbalmaceda](https://github.com/lbalmaceda))

**Changed**
- Remove required fields check on UserProfile deserializing [\#65](https://github.com/auth0/Auth0.Android/pull/65) ([lbalmaceda](https://github.com/lbalmaceda))
- Migrate OIDCConformant flag into Auth0 class [\#62](https://github.com/auth0/Auth0.Android/pull/62) ([lbalmaceda](https://github.com/lbalmaceda))
- Use password-realm grant for /oauth/token endpoint [\#56](https://github.com/auth0/Auth0.Android/pull/56) ([lbalmaceda](https://github.com/lbalmaceda))

**Fixed**
- Fix bug when parsing PasswordStrength errors into AuthenticationException [\#60](https://github.com/auth0/Auth0.Android/pull/60) ([lbalmaceda](https://github.com/lbalmaceda))

**Breaking changes**
- Migrate loggingEnabled flag to Auth0 class [\#64](https://github.com/auth0/Auth0.Android/pull/64) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.3.0](https://github.com/auth0/Auth0.Android/tree/1.3.0) (2016-12-12)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.2.0...1.3.0)

**Added**
- Allow to specify Audience parameter in the WebAuthProvider [\#49](https://github.com/auth0/Auth0.Android/pull/49) ([lbalmaceda](https://github.com/lbalmaceda))

**Fixed**
- Generate and save State and Nonce variables for WebAuthProvider [\#50](https://github.com/auth0/Auth0.Android/pull/50) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.2.0](https://github.com/auth0/Auth0.Android/tree/1.2.0) (2016-11-30)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.1.2...1.2.0)

**Added**
- Add userInfo method [\#44](https://github.com/auth0/Auth0.Android/pull/44) ([lbalmaceda](https://github.com/lbalmaceda))
- Get new Credentials using a Refresh Token [\#43](https://github.com/auth0/Auth0.Android/pull/43) ([lbalmaceda](https://github.com/lbalmaceda))
- Login with password grant using /oauth/token endpoint [\#42](https://github.com/auth0/Auth0.Android/pull/42) ([lbalmaceda](https://github.com/lbalmaceda))
- Add Logging for Requests/Responses and Uri's. [\#40](https://github.com/auth0/Auth0.Android/pull/40) ([lbalmaceda](https://github.com/lbalmaceda))
- Support multiple response_type values [\#38](https://github.com/auth0/Auth0.Android/pull/38) ([lbalmaceda](https://github.com/lbalmaceda))

**Deprecated**
- Deprecate useCodeGrant in the WebAuthProvider class [\#46](https://github.com/auth0/Auth0.Android/pull/46) ([lbalmaceda](https://github.com/lbalmaceda))
- Deprecate tokenInfo method in favor of userInfo [\#45](https://github.com/auth0/Auth0.Android/pull/45) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.1.2](https://github.com/auth0/Auth0.Android/tree/1.1.2) (2015-11-22)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.1.1...1.1.2)

**Fixed**
- Fix scope being overriden during WebAuth [\#37](https://github.com/auth0/Auth0.Android/pull/37) ([hzalaz](https://github.com/hzalaz))

## [1.1.1](https://github.com/auth0/Auth0.Android/tree/1.1.1) (2015-11-21)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.1.0...1.1.1)

**Deprecated**
- Deprecate WebView authentication flow [\#36](https://github.com/auth0/Auth0.Android/pull/36) ([lbalmaceda](https://github.com/lbalmaceda))

**Fixed**
- Avoid sending null parameters in the authorize URI [\#35](https://github.com/auth0/Auth0.Android/pull/35) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.1.0](https://github.com/auth0/Auth0.Android/tree/1.1.0) (2015-10-14)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.0.1...1.1.0)

**Added**
- Add connection_scope setter [\#31](https://github.com/auth0/Auth0.Android/pull/31) ([lbalmaceda](https://github.com/lbalmaceda))
- Allow to set additional Parameters. [\#29](https://github.com/auth0/Auth0.Android/pull/29) ([lbalmaceda](https://github.com/lbalmaceda))

**Deprecated**
- Remove Deprecated WebView/Fullscreen options [\#32](https://github.com/auth0/Auth0.Android/pull/32) ([lbalmaceda](https://github.com/lbalmaceda))

**Fixed**
- Change default WebAuthProvider connection to null [\#33](https://github.com/auth0/Auth0.Android/pull/33) ([lbalmaceda](https://github.com/lbalmaceda))


## [1.0.1](https://github.com/auth0/Auth0.Android/tree/1.0.1) (2015-09-27)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.0.0...1.0.1)

**Changed**
- Make AuthHandler callback protected again [\#27](https://github.com/auth0/Auth0.Android/pull/27) ([lbalmaceda](https://github.com/lbalmaceda))

## [1.0.0](https://github.com/auth0/Auth0.Android/tree/1.0.0) (2015-09-15)

Android java toolkit for Auth0 API

### Requirements

Android API version 15 or newer

### Installation

#### Gradle

Auth0.android is available through [Gradle](https://gradle.org/). To install it, simply add the following line to your `build.gradle` file:

```gradle
dependencies {
    compile "com.auth0.android:auth0:1.0.0"
}
```
