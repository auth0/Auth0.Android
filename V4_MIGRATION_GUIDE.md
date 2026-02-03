# Migration Guide from SDK v3 to v4

## Overview

v4 of the Auth0 Android SDK includes significant build toolchain updates to support the latest Android development environment. This guide documents the changes required when migrating from v3 to v4.

## Requirements Changes

### Java Version

v4 requires **Java 17** or later (previously Java 11).

Update your `build.gradle` to target Java 17:

```groovy
android {
    compileOptions {
        sourceCompatibility JavaVersion.VERSION_17
        targetCompatibility JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = '17'
    }
}
```

### Gradle and Android Gradle Plugin

v4 requires:

- **Gradle**: 8.10.2 or later
- **Android Gradle Plugin (AGP)**: 8.8.2 or later

Update your `gradle/wrapper/gradle-wrapper.properties`:

```properties
distributionUrl=https\://services.gradle.org/distributions/gradle-8.10.2-all.zip
```

Update your root `build.gradle`:

```groovy
buildscript {
    dependencies {
        classpath 'com.android.tools.build:gradle:8.8.2'
    }
}
```

### Kotlin Version

v4 uses **Kotlin 2.0.21** . If you're using Kotlin in your project, you may need to update your Kotlin version to ensure compatibility.

```groovy
buildscript {
    ext.kotlin_version = "2.0.21"
}
```

## Breaking Changes


## Getting Help

If you encounter issues during migration:

- [GitHub Issues](https://github.com/auth0/Auth0.Android/issues) - Report bugs or ask questions
- [Auth0 Community](https://community.auth0.com/) - Community support
- [Migration Examples](https://github.com/auth0/auth0.android/blob/main/EXAMPLES.md) - Updated code examples
