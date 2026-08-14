# Commands Reference — Auth0.Android

Verified against `.github/workflows/test.yml` and `auth0/build.gradle`.

## CI pipeline (exact command from `test.yml`)

```bash
./gradlew testReleaseUnitTest jacocoTestReleaseUnitTestReport lintRelease --continue --console=plain
```

## Individual tasks

```bash
# Unit tests (release variant)
./gradlew testReleaseUnitTest

# Unit tests + JaCoCo coverage report
./gradlew testReleaseUnitTest jacocoTestReleaseUnitTestReport

# Lint (release variant, matches CI)
./gradlew lintRelease

# Build SDK (debug + release AARs)
./gradlew auth0:assemble

# Build release AAR only
./gradlew auth0:assembleRelease

# Build sample app
./gradlew sample:assembleDebug

# Check explicit-API compliance (fails on implicit visibility)
./gradlew auth0:compileReleaseKotlin

# Clean
./gradlew clean
```

## Coverage

JaCoCo reports land in `auth0/build/reports/jacoco/` after `jacocoTestReleaseUnitTestReport`. Codecov uploads automatically in CI. Thresholds: 80% patch target, 1% project degradation max (`codecov.yml`). `CryptoUtil.java` is excluded.
