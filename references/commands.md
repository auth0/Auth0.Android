# Commands Reference — Auth0.Android

All commands verified against `.github/workflows/test.yml` and `auth0/build.gradle`.

## Full CI pipeline (matches `test.yml` exactly)

```bash
./gradlew clean test jacocoTestReport lint --continue --console=plain --max-workers=1 --no-daemon
```

## Individual tasks

```bash
# Run unit tests only
./gradlew test

# Run unit tests + coverage report
./gradlew test jacocoTestReport

# Run lint only
./gradlew lint

# Build SDK library (debug + release AARs)
./gradlew auth0:assemble

# Build release AAR only
./gradlew auth0:assembleRelease

# Build sample app (debug)
./gradlew sample:assembleDebug

# Check Kotlin explicit-API compliance (fails if implicit visibility is used)
./gradlew auth0:compileReleaseKotlin

# Clean build artifacts
./gradlew clean

# List all available Gradle tasks
./gradlew tasks
```

## Coverage reports

JaCoCo HTML reports are written to `auth0/build/reports/jacoco/` after running `jacocoTestReport`. Codecov uploads happen automatically in CI via the `codecov/codecov-action` step. Coverage thresholds are in `codecov.yml` (80% patch target, 1% project degradation threshold).

## Publishing (CI only)

Maven Central publishing is triggered by CI via `java-release.yml`. It requires `MAVEN_USERNAME`, `MAVEN_PASSWORD`, and signing credentials. Do not run publishing tasks locally unless explicitly authorized.
