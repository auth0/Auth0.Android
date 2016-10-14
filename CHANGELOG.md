# Change Log

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