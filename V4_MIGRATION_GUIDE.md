# Migration Guide from SDK v3 to v4

## Overview

v4 of the Auth0 Android SDK includes significant build toolchain updates to support the latest Android development environment. This guide documents the changes required when migrating from v3 to v4.

## Requirements Changes

### Java Version

v4 requires **Java 17** or later (previously Java 8+).

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

v4 uses **Kotlin 2.0.21**. If you're using Kotlin in your project, you may need to update your Kotlin version to ensure compatibility.

```groovy
buildscript {
    ext.kotlin_version = "2.0.21"
}
```

## Breaking Changes

No breaking API changes have been identified in v4. This section will be updated if any are discovered.

## Dependency Changes

### ⚠️ Gson 2.8.9 → 2.11.0 (Transitive Dependency)

v4 updates the internal Gson dependency from **2.8.9** to **2.11.0**. While the SDK does not expose Gson types in its public API, Gson is included as a transitive runtime dependency. If your app also uses Gson, be aware of the following changes introduced in Gson 2.10+:

- **`TypeToken` with unresolved type variables is rejected at runtime.** Code like `object : TypeToken<List<T>>() {}` (where `T` is a generic parameter) will throw `IllegalArgumentException`. Use Kotlin `reified` type parameters or pass concrete types instead.
- **Strict type coercion is enforced.** Gson no longer silently coerces JSON objects or arrays to `String`. If your code relies on this behavior, you will see `JsonSyntaxException`.
- **Built-in ProGuard/R8 rules are included.** Gson 2.11.0 ships its own keep rules, so you may be able to remove custom Gson ProGuard rules from your project.

If you need to pin Gson to an older version, you can use Gradle's `resolutionStrategy`:

```groovy
configurations.all {
    resolutionStrategy.force 'com.google.code.gson:gson:2.8.9'
}
```

> **Note:** Pinning to an older version is not recommended long-term, as the SDK has been tested and validated against Gson 2.11.0.

## Getting Help

If you encounter issues during migration:

- [GitHub Issues](https://github.com/auth0/Auth0.Android/issues) - Report bugs or ask questions
- [Auth0 Community](https://community.auth0.com/) - Community support