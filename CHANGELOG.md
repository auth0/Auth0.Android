# Change Log

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
