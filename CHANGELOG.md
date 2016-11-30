# Change Log

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
