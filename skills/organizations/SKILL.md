---
name: organizations
description: >-
  Use when building a multi-tenant or B2B Auth0.Android app with Auth0
  Organizations: logging a user into a specific organization with
  WebAuthProvider.withOrganization, accepting an organization invitation link with
  withInvitationUrl and App Links, reading the org_id claim, or associating a
  password reset with an organization.
metadata:
  type: sub-skill
  library: Auth0.Android
  library_version: 4.3.1
requires:
  - auth0-android
---

# Auth0.Android - Organizations

Organizations are available on Enterprise and Startup plans. Reference: [`examples/organizations.md`](https://github.com/auth0/Auth0.Android/blob/main/examples/organizations.md). There is no dedicated organization accessor on `Credentials`.

## Log in to an organization

```kotlin
WebAuthProvider.login(account)
    .withOrganization("org_abc123") // organization id (starts with org_) or name
    .start(this, callback)
```

The SDK validates the ID token against the value you pass: an id starting with `org_` is compared to the `org_id` claim, anything else is compared (lowercased) to `org_name`. A mismatch fails the login with a token validation error.

## Accept an invitation

Invitation links are `https` only, so set up [Android App Links](https://auth0.com/docs/applications/enable-android-app-links-support) so the link opens your app, and set the application's Application Login URI in the Dashboard to that HTTPS URL so invitations point at it. In `onCreate` or `onNewIntent`, pass the full URL through as-is. The SDK extracts the `organization` and `invitation` parameters; do not parse them yourself.

```kotlin
intent?.data?.takeIf { it.isHierarchical }?.let { uri -> // opaque URIs (mailto:) make the SDK throw
    WebAuthProvider.login(account)
        .withInvitationUrl(uri.toString())
        .start(this, callback)
}
```

If the URL lacks the expected values the callback receives an error.

## Read the organization

`org_id` and `org_name` are ID token claims. `credentials.user` decodes the ID token, so non-standard claims are in `getExtraInfo()`:

```kotlin
val orgId = credentials.user.getExtraInfo()["org_id"] as? String
```

## Password reset for an organization user

```kotlin
authentication.resetPassword("user@example.com", "Username-Password-Authentication", "org_abc123")
    .start(voidCallback)
```

The third argument must be the organization id, not the name. Auth0 adds the organization details to the reset redirect URL and email templates.

## Notes

- Enable the organization and the connection on the Auth0 application, and set the application's organization behavior in the Dashboard.
- Keep the client ID and domain in `strings.xml`, read through `Auth0.getInstance(context)`. No client secret in the app.
- Store credentials with `SecureCredentialsManager`.
- Do not build the `/authorize` URL by hand to add `organization`; use the builder.
