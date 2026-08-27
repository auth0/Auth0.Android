## Organizations

[Organizations](https://auth0.com/docs/organizations) is a set of features that provide better support for developers who build and maintain SaaS and Business-to-Business (B2B) applications.
Note that Organizations is currently only available to customers on our Enterprise and Startup subscription plans.

### Log in to an organization

```kotlin
WebAuthProvider.login(account)
    .withOrganization(organizationIdOrName)
    .start(this, callback)
```

### Accept user invitations

Users can be invited to your organization via a link. Tapping on the invitation link should open your app. Since invitations links are `https` only, is recommended that your app supports [Android App Links](https://developer.android.com/training/app-links). In [Enable Android App Links Support](https://auth0.com/docs/applications/enable-android-app-links-support), you will find how to make the Auth0 server publish the Digital Asset Links file required by your application.

When your app gets opened by an invitation link, grab the invitation URL from the received Intent (e.g. in `onCreate` or `onNewIntent`) and pass it to `.withInvitationUrl()`:

```kotlin
getIntent()?.data?.let {
    WebAuthProvider.login(account)
        .withInvitationUrl(invitationUrl)
        .start(this, callback)
}
```

<details>
  <summary>Using Java</summary>

```java
if (getIntent() != null && getIntent().getData() != null) {
    WebAuthProvider.login(account)
        .withInvitationUrl(getIntent().getData())
        .start(this, callback);
}
```
</details>

If the URL doesn't contain the expected values, an error will be raised through the provided callback.
