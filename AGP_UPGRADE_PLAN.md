# AGP and Gradle Upgrade Plan: Version 7 to Version 8+

## Current State Analysis

### Current Versions
- **Gradle**: 7.5
- **AGP (Android Gradle Plugin)**: 7.4.0
- **Kotlin**: 1.8.22
- **Compile SDK**: 35
- **Target SDK**: 35
- **Min SDK**: 21 (library), 24 (sample)
- **Java Compatibility**: VERSION_11 (library), VERSION_1_8 (sample)

### Project Structure
- Multi-module project: `auth0` (library) + `sample` (application)
- Uses Groovy DSL for build scripts (no Kotlin DSL)
- Custom Gradle scripts: jacoco.gradle, maven-publish.gradle, versioning.gradle

### Key Dependencies Identified
**AndroidX Libraries:**
- androidx.core:core-ktx:1.6.0
- androidx.appcompat:appcompat:1.6.0 (library), 1.3.0 (sample)
- androidx.browser:browser:1.4.0
- androidx.biometric:biometric:1.1.0
- androidx.credentials:credentials:1.3.0

**Networking:**
- com.squareup.okhttp3:okhttp:4.12.0
- com.squareup.okhttp3:logging-interceptor:4.12.0
- com.google.code.gson:gson:2.8.9

**Coroutines:**
- org.jetbrains.kotlinx:kotlinx-coroutines-core:1.6.2

**Testing:**
- JUnit 4.13.2
- Robolectric 4.8.1
- PowerMock 2.0.9
- Mockito 3.12.4
- Espresso 3.5.1 (library), 3.4.0 (sample)

### Critical Issues Found

1. **gradle.properties Alert**: Contains temporary workaround
   ```
   # Adding this here temporarily to fix the build with compileSdKVersion 35. Remove this when migrate to gradle 8
   android.aapt2Version=8.6.1-11315950
   ```
   This indicates the project is already encountering issues with SDK 35 on AGP 7.

2. **Deprecated JCenter Repository**: Still using JCenter for specific dependencies
   - org.jetbrains.trove4j:trove4j
   - com.soywiz.korlibs.korte:korte-jvm
   - org.jetbrains.kotlinx:kotlinx-html-jvm

3. **Outdated Dependencies**: Several dependencies need updates for AGP 8 compatibility

4. **Jacoco Configuration**: Uses deprecated `xml.enabled` / `html.enabled` syntax

5. **Lint Options**: Uses deprecated `lintOptions` block (should be `lint`)

6. **CI/CD**: GitHub Actions setup uses older Gradle/Kotlin versions in CI config

## Recommended Target Versions

### Primary Recommendations
- **Gradle**: 8.10.2 (Latest stable with excellent AGP 8.x support)
- **AGP**: 8.7.3 (Latest stable for SDK 35 - removes need for AAPT2 workaround)
- **Kotlin**: 2.0.21 (Full compatibility with AGP 8.x, K2 compiler)
- **Java Target**: Remain at Java 11 (already compliant)
- **JaCoCo**: 0.8.5 → 0.8.12

## Critical Breaking Changes

### 1. PowerMock Incompatibility (SHOW STOPPER)
**Problem**: PowerMock 2.0.9 uses bytecode manipulation incompatible with Java Module System required by AGP 8.x

**Current Dependencies (auth0/build.gradle:102-104)**:
```groovy
testImplementation "org.powermock:powermock-module-junit4:$powermockVersion"
testImplementation "org.powermock:powermock-module-junit4-rule:$powermockVersion"
testImplementation "org.powermock:powermock-api-mockito2:$powermockVersion"
```

**Affected Test Files** (only 2 files!):
1. `auth0/src/test/java/com/auth0/android/authentication/storage/CryptoUtilTest.java`
   - Mocks: KeyGenerator, TextUtils, Build.VERSION, Base64, Cipher, Log, KeyStore
   - Purpose: Testing Android KeyStore cryptographic operations
   - Strategy: Use Robolectric's shadow classes for Android framework mocking

2. `auth0/src/test/java/com/auth0/android/dpop/DPoPKeyStoreTest.kt`
   - Mocks: KeyStore, KeyPairGenerator, KeyGenParameterSpec.Builder, Build.VERSION, Log
   - Purpose: Testing DPoP key storage and generation
   - Strategy: Use Robolectric + refactor to reduce static mocking needs

**Chosen Approach**: Remove PowerMock and refactor tests to use Robolectric + standard Mockito
- Robolectric already provides shadows for most Android framework classes (Build.VERSION, Log, TextUtils, Base64)
- KeyStore and Cipher operations can be tested with real Android KeyStore via Robolectric
- Reduces test complexity and improves compatibility

**Impact**: 2-3 hours of test refactoring (only 2 test files affected)

### 2. Deprecated DSL Syntax
Must update before AGP 8.x will work:
- `lintOptions` → `lint` (auth0/build.gradle:53)
- `xml.enabled` → `xml.required` (gradle/jacoco.gradle:48-49)
- `compileSdkVersion` → `compileSdk` (sample/build.gradle:7)

### 3. JCenter Deprecation Warning
Still using JCenter for specific Dokka dependencies (trove4j, kotlinx-html-jvm). These are now on Maven Central, so repositories will continue working.

## Step-by-Step Upgrade Sequence

### Phase 1: Pre-Upgrade Preparation
1. **Remove AAPT2 Workaround**
   - File: `gradle.properties`
   - Remove: `android.aapt2Version=8.6.1-11315950`
   - This was a temporary fix that AGP 8.7.3 resolves

2. **Validate Current Build**
   ```bash
   ./gradlew clean build test jacocoTestReport --stacktrace
   ```

3. **Update Gradle Wrapper**
   - File: `gradle/wrapper/gradle-wrapper.properties`
   - Change: `distributionUrl=https\://services.gradle.org/distributions/gradle-8.10.2-all.zip`
   - Run: `./gradlew wrapper --gradle-version=8.10.2 --distribution-type=all`

4. **Update AGP Version**
   - File: `build.gradle` (root)
   - Line 16: `classpath 'com.android.tools.build:gradle:8.7.3'`

### Phase 2: Fix Deprecated DSL Syntax

5. **Fix lintOptions** (auth0/build.gradle:53-56)
   ```groovy
   // OLD
   lintOptions {
       htmlReport true
       abortOnError true
   }

   // NEW
   lint {
       htmlReport = true
       abortOnError = true
   }
   ```

6. **Fix JaCoCo Reports** (gradle/jacoco.gradle:47-50)
   ```groovy
   // OLD
   reports {
       xml.enabled = true
       html.enabled = true
   }

   // NEW
   reports {
       xml.required = true
       html.required = true
   }
   ```

7. **Fix SDK Version Syntax** (sample/build.gradle:7-11)
   ```groovy
   // OLD
   compileSdkVersion 35
   minSdkVersion 24
   targetSdkVersion 35

   // NEW
   compileSdk 35
   minSdk 24
   targetSdk 35
   ```

### Phase 3: Kotlin Upgrade

8. **Update Kotlin Version**
   - File: `build.gradle` (root)
   - Line 3: `ext.kotlin_version = "2.0.21"`

9. **Update Kotlin Stdlib Reference**
   - File: `auth0/build.gradle`
   - Line 87: `"org.jetbrains.kotlin:kotlin-stdlib:$kotlin_version"`
   - (Remove `-jdk8` suffix - it's now implicit)

### Phase 4: Update Test Dependencies

10. **Handle PowerMock Removal** (auth0/build.gradle)
    - Remove lines 102-104 (PowerMock dependencies)
    - Refactor 2 affected test files:
      - CryptoUtilTest.java: Remove @RunWith(PowerMockRunner), @PrepareForTest, PowerMockito imports
      - DPoPKeyStoreTest.kt: Remove @RunWith(PowerMockRunner), @PrepareForTest, PowerMockito usage
    - Replace static mocking with Robolectric shadows and standard Mockito

11. **Update Mockito Ecosystem**
    - Line 105: `mockito-core: 3.12.4 → 5.7.0`
    - Line 107: `mockito-kotlin: 2.2.0 → org.mockito.kotlin:mockito-kotlin:5.1.0`

12. **Update Robolectric**
    - Line 111: `robolectric: 4.8.1 → 4.13.1`

13. **Update Testing Libraries**
    - `androidx.test.espresso:espresso-intents: 3.5.1 → 3.6.1`
    - `androidx.test.espresso:espresso-core: 3.4.0 → 3.6.1`
    - `androidx.test.ext:junit: 1.1.3 → 1.2.0`
    - `awaitility: 1.7.0 → 4.2.1`

### Phase 5: Update Runtime Dependencies

14. **Update AndroidX Libraries**
    - `androidx.core:core-ktx: 1.6.0 → 1.15.0`
    - `androidx.appcompat:appcompat: 1.6.0 → 1.7.0 (sample: 1.3.0 → 1.7.0)`
    - `androidx.browser:browser: 1.4.0 → 1.8.0`
    - `androidx.biometric:biometric: 1.1.0 → 1.2.0`
    - `androidx.constraintlayout: 2.0.4 → 2.1.4` (sample)
    - `androidx.navigation: 2.3.5 → 2.8.2` (sample)
    - `androidx.material: 1.4.0 → 1.12.0` (sample)

15. **Update Coroutines**
    - Line 80: `coroutinesVersion = '1.6.2' → '1.7.3'`

16. **Update Other Dependencies**
    - `gson: 2.8.9 → 2.10.1`
    - `okhttp: 4.12.0` (keep - already latest)

### Phase 6: Update gradle.properties

17. **Clean Up Properties** (gradle.properties)
    - Remove: `android.aapt2Version=8.6.1-11315950` (done in Phase 1)
    - Remove: `android.enableJetifier=false` (not needed with AGP 8.x)
    - Keep: `android.useAndroidX=true`
    - Keep: `kotlin.code.style=official`
    - Optional Add: `org.gradle.caching=true`

### Phase 7: Update CI/CD Configuration

18. **Update GitHub Actions** (.github/actions/setup/action.yml)
    - Line 12: Default Gradle: `6.7.1 → 8.10.2`
    - Line 16: Default Kotlin: `1.6.21 → 2.0.21`

### Phase 8: Update JaCoCo Version

19. **Update JaCoCo** (gradle/jacoco.gradle:4)
    - `toolVersion = "0.8.5" → "0.8.12"`

## Complete Dependency Update Matrix

```
GRADLE ECOSYSTEM:
├─ Gradle: 7.5 → 8.10.2
├─ AGP: 7.4.0 → 8.7.3
├─ Kotlin: 1.8.22 → 2.0.21
├─ Java: 11 (no change)
└─ JaCoCo: 0.8.5 → 0.8.12

KOTLIN ECOSYSTEM:
├─ kotlin-stdlib-jdk8 → kotlin-stdlib: 2.0.21
├─ kotlinx-coroutines: 1.6.2 → 1.7.3

ANDROIDX LIBRARIES:
├─ core-ktx: 1.6.0 → 1.15.0
├─ appcompat: 1.6.0/1.3.0 → 1.7.0
├─ browser: 1.4.0 → 1.8.0
├─ biometric: 1.1.0 → 1.2.0
├─ credentials: 1.3.0 (keep)
├─ constraintlayout: 2.0.4 → 2.1.4
├─ navigation: 2.3.5 → 2.8.2
└─ material: 1.4.0 → 1.12.0

TEST FRAMEWORKS:
├─ Robolectric: 4.8.1 → 4.13.1
├─ Mockito: 3.12.4 → 5.7.0
├─ mockito-kotlin: 2.2.0 → 5.1.0
├─ PowerMock: 2.0.9 → REMOVE
├─ MockK: NEW 1.13.14 (optional)
├─ espresso: 3.5.1/3.4.0 → 3.6.1
├─ awaitility: 1.7.0 → 4.2.1
└─ androidx.test.ext:junit: 1.1.3 → 1.2.0

NETWORK/JSON:
├─ okhttp: 4.12.0 (keep)
└─ gson: 2.8.9 → 2.10.1
```

## Testing Strategy

### Verification Steps
```bash
# 1. Basic compilation
./gradlew clean build -x test

# 2. Unit tests
./gradlew test --stacktrace

# 3. Coverage reports
./gradlew test jacocoTestReport --stacktrace

# 4. Lint checks
./gradlew lint --stacktrace

# 5. Sample app build
./gradlew :sample:build

# 6. Library packaging
./gradlew :auth0:assembleRelease

# 7. CI replication
./gradlew clean test jacocoTestReport lint --continue --console=plain --max-workers=1 --no-daemon

# 8. Maven publish dry-run
./gradlew publish -x signReleasePublication --dry-run
```

## Rollback Plan

### Full Revert (if critical issues arise)
```bash
git checkout build.gradle gradle.properties gradle/wrapper/gradle-wrapper.properties
./gradlew wrapper --gradle-version=7.5
```

### Partial Revert
- Upgrade only to Gradle 7.6 (without AGP 8.x)
- Provides some improvements while maintaining compatibility

## Estimated Effort
- **Total Time**: 7-9 hours
- **Critical Path**: 5 hours minimum
- **PowerMock Refactoring**: 2-4 hours (50% of total effort)
- **Risk Level**: Medium-High (PowerMock compatibility is main blocker)

## Recommended Implementation Order

Based on user preferences (latest stable versions, direct Kotlin 2.0.21 upgrade, PowerMock removal):

### Commit 1: Phase 1 - Pre-upgrade preparation
- Remove AAPT2 workaround from gradle.properties
- Validate current build passes
- Create feature branch: `git checkout -b gradle-agp-8-upgrade`

### Commit 2: Phase 1 - Gradle wrapper upgrade
- Update gradle-wrapper.properties to 8.10.2
- Run: `./gradlew wrapper --gradle-version=8.10.2 --distribution-type=all`
- Verify: `./gradlew --version`

### Commit 3: Phase 1 & 2 - AGP + DSL fixes
- Update AGP to 8.7.3 in root build.gradle
- Fix lintOptions → lint (auth0/build.gradle)
- Fix JaCoCo reports syntax (gradle/jacoco.gradle)
- Fix SDK version syntax (sample/build.gradle)
- Test: `./gradlew clean build -x test` (should compile)

### Commit 4: Phase 3 - Kotlin upgrade
- Update Kotlin to 2.0.21 in root build.gradle
- Update stdlib reference in auth0/build.gradle
- Test: `./gradlew clean build -x test`

### Commit 5: Phase 4 - PowerMock removal & test refactoring
- Remove PowerMock dependencies from auth0/build.gradle
- Refactor CryptoUtilTest.java to use Robolectric
- Refactor DPoPKeyStoreTest.kt to use Robolectric
- Update Mockito to 5.7.0
- Update mockito-kotlin to 5.1.0
- Test: `./gradlew test --stacktrace` (critical milestone)

### Commit 6: Phase 4 & 5 - Dependency updates
- Update Robolectric to 4.13.1
- Update all AndroidX libraries
- Update coroutines to 1.7.3
- Update espresso, awaitility, gson
- Test: `./gradlew test jacocoTestReport`

### Commit 7: Phase 6 & 8 - Properties and tooling
- Clean up gradle.properties
- Update JaCoCo to 0.8.12
- Update CI configuration (.github/actions/setup/action.yml)
- Test: Full CI command locally

### Commit 8: Final verification
- Run: `./gradlew clean test jacocoTestReport lint --continue --console=plain --max-workers=1 --no-daemon`
- Verify sample app builds
- Verify library packaging
- Maven publish dry-run
- Ready for PR

## Critical Files to Modify
- `/Users/prince.mathew/workspace/Auth0.Android/build.gradle` - AGP, Kotlin versions
- `/Users/prince.mathew/workspace/Auth0.Android/auth0/build.gradle` - DSL syntax, dependencies, PowerMock removal
- `/Users/prince.mathew/workspace/Auth0.Android/sample/build.gradle` - DSL syntax, dependencies
- `/Users/prince.mathew/workspace/Auth0.Android/gradle/wrapper/gradle-wrapper.properties` - Gradle version
- `/Users/prince.mathew/workspace/Auth0.Android/gradle/jacoco.gradle` - JaCoCo DSL syntax, version
- `/Users/prince.mathew/workspace/Auth0.Android/gradle.properties` - Property cleanup
- `/Users/prince.mathew/workspace/Auth0.Android/.github/actions/setup/action.yml` - CI configuration
- `/Users/prince.mathew/workspace/Auth0.Android/auth0/src/test/java/com/auth0/android/authentication/storage/CryptoUtilTest.java` - PowerMock refactoring
- `/Users/prince.mathew/workspace/Auth0.Android/auth0/src/test/java/com/auth0/android/dpop/DPoPKeyStoreTest.kt` - PowerMock refactoring
