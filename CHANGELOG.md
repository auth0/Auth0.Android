# Change Log

## [1.30.0](https://github.com/auth0/Auth0.Android/tree/1.30.0) (2020-12-18)
[Full Changelog](https://github.com/auth0/Auth0.Android/compare/1.29.2...1.30.0)

**Added**
- Add custom headers to social token request [SDK-2080] [\#351](https://github.com/auth0/Auth0.Android/pull/351) ([TLFilip](https://github.com/TLFilip))

**Deprecated**
- Deprecate API client constructors that take Context [\#393](https://github.com/auth0/Auth0.Android/pull/393) ([lbalmaceda](https://github.com/lbalmaceda))
- Deprecate AuthorizableRequest [\#392](https://github.com/auth0/Auth0.Android/pull/392) ([lbalmaceda](https://github.com/lbalmaceda))
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
