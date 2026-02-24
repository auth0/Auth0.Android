# Swift / iOS SDK Validation Checklist

Use this checklist to verify every layer of an Auth0 Swift integration (Auth0.swift) before raising a support ticket. Work through each section in order.

---

## 1. Dependency Setup {#dependency-setup}

### Swift Package Manager (Recommended)

In Xcode: **File → Add Package Dependencies**

- Package URL: `https://github.com/auth0/Auth0.swift`
- Dependency Rule: Up to Next Major (current major: `2.x`)
- Target: your app target (not a test target only)

Verify in `Package.resolved` or **Xcode → Project → Package Dependencies** that `Auth0` is listed and resolved.

### CocoaPods

`Podfile`:

```ruby
platform :ios, '14.0'
use_frameworks!

target 'YourApp' do
  pod 'Auth0', '~> 2.0'
end
```

After any `Podfile` change, run:

```bash
pod install --repo-update
```

Open the `.xcworkspace` file (not `.xcodeproj`) after pod install.

**Checklist:**
- [ ] Auth0.swift is added to the **app target**, not only a test target
- [ ] Using version `2.x` (current major — `1.x` is legacy)
- [ ] CocoaPods users are opening `.xcworkspace`, not `.xcodeproj`
- [ ] `pod install` was re-run after any `Podfile` change

---

## 2. Auth0.plist Configuration {#auth0-plist}

The SDK looks for `Auth0.plist` at the **root of the app target** (not in a subdirectory). This is the most common iOS setup mistake.

Create `Auth0.plist` in the app target root:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>ClientId</key>
    <string>YOUR_CLIENT_ID</string>
    <key>Domain</key>
    <string>your-tenant.auth0.com</string>
</dict>
</plist>
```

**Checklist:**
- [ ] File is named exactly `Auth0.plist` (case-sensitive)
- [ ] File is added to the **app target** membership in Xcode (check File Inspector → Target Membership)
- [ ] File is **not** only in a test target
- [ ] `Domain` value does **not** include `https://` prefix
- [ ] `Domain` value does **not** have a trailing slash
- [ ] `ClientId` matches the **Client ID** from Auth0 Dashboard exactly
- [ ] Key names are `ClientId` and `Domain` (capital C, capital D) — these are case-sensitive

### Alternative: Programmatic Initialization

If you prefer not to use `Auth0.plist`:

```swift
// In AppDelegate or @main App struct
Auth0
    .webAuth(clientId: "YOUR_CLIENT_ID", domain: "your-tenant.auth0.com")
    .start { result in ... }
```

---

## 3. URL Scheme (Custom Scheme Callback) {#url-scheme}

The SDK uses a custom URL scheme to receive the callback from the browser after login.

Open `Info.plist` (or the **Info** tab in Xcode target settings) and add a URL Type:

```xml
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleTypeRole</key>
        <string>None</string>
        <key>CFBundleURLName</key>
        <string>auth0</string>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>$(PRODUCT_BUNDLE_IDENTIFIER)</string>
        </array>
    </dict>
</array>
```

**Checklist:**
- [ ] `CFBundleURLTypes` entry exists in `Info.plist` (or is set in Xcode target Info tab)
- [ ] `CFBundleURLSchemes` array contains `$(PRODUCT_BUNDLE_IDENTIFIER)` or the literal bundle ID
- [ ] The scheme matches the bundle identifier registered in Auth0 Dashboard callback URL
- [ ] There are no duplicate URL schemes conflicting with another SDK

### Constructing the Expected Callback URL

The URL the SDK sends to Auth0 is built as:

```
{bundleId}://{auth0Domain}/ios/{bundleId}/callback
```

Example: `com.example.myapp://your-tenant.auth0.com/ios/com.example.myapp/callback`

**This URL must be listed verbatim in Auth0 Dashboard → Application → Allowed Callback URLs.**

---

## 4. Universal Links (Optional but Recommended for Production) {#universal-links}

Universal Links are recommended over custom schemes for security (they cannot be hijacked by other apps).

### Steps to Verify

1. In Xcode, open target → **Signing & Capabilities** → confirm **Associated Domains** entitlement is added.
2. Confirm the domain entry format: `applinks:your-tenant.auth0.com`
3. Verify the `apple-app-site-association` (AASA) file is hosted at:
   ```
   https://your-tenant.auth0.com/.well-known/apple-app-site-association
   ```
4. The AASA file must include your app's Team ID and bundle identifier.

Fetch and verify the AASA file:

```bash
curl -s https://your-tenant.auth0.com/.well-known/apple-app-site-association | python3 -m json.tool
```

**Checklist:**
- [ ] Associated Domains entitlement is added in Xcode (not just the entitlements file — must be enabled in Developer Portal)
- [ ] Domain in entitlement is `applinks:your-tenant.auth0.com`
- [ ] App is provisioned with a profile that includes the Associated Domains entitlement
- [ ] AASA file is reachable without redirect and returns valid JSON
- [ ] App's Team ID + Bundle ID appears in the AASA `appID` field as `TEAMID.BUNDLEID`
- [ ] Testing on a physical device (Universal Links do **not** work on Simulator)

---

## 5. AppDelegate / SceneDelegate Integration {#appdelegate}

### UIKit (AppDelegate)

```swift
// AppDelegate.swift
import Auth0

func application(_ app: UIApplication,
                 open url: URL,
                 options: [UIApplication.OpenURLOptionsKey: Any]) -> Bool {
    return WebAuthentication.resume(with: url)
}
```

### SwiftUI

```swift
// YourApp.swift
import Auth0
import SwiftUI

@main
struct YourApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
                .onOpenURL { url in
                    WebAuthentication.resume(with: url)
                }
        }
    }
}
```

**Checklist:**
- [ ] `WebAuthentication.resume(with:)` is called in `application(_:open:options:)` (UIKit) or `.onOpenURL` (SwiftUI)
- [ ] For Universal Links, `application(_:continue:restorationHandler:)` also calls `WebAuthentication.resume(with:)`
- [ ] The method is actually reachable at runtime (e.g., not inside a conditional block that never executes)

---

## 6. Login and Logout Calls {#auth-calls}

### Login

```swift
Auth0
    .webAuth()
    .audience("https://your-tenant.auth0.com/userinfo")  // optional, for OIDC
    .scope("openid profile email offline_access")
    .start { result in
        switch result {
        case .success(let credentials):
            print("Access token: \(credentials.accessToken)")
        case .failure(let error):
            print("Login failed: \(error)")
        }
    }
```

### Logout

```swift
Auth0
    .webAuth()
    .clearSession { result in
        switch result {
        case .success:
            print("Logged out")
        case .failure(let error):
            print("Logout failed: \(error)")
        }
    }
```

**Checklist:**
- [ ] `offline_access` scope is included if you need refresh tokens
- [ ] The `audience` parameter is set correctly if you're calling a custom API
- [ ] Logout URL in Auth0 Dashboard matches the URL the SDK sends
- [ ] Error cases are handled and logged

---

## 7. Credentials Manager (Token Storage) {#credentials-manager}

```swift
import Auth0

let credentialsManager = CredentialsManager(authentication: Auth0.authentication())

// Store credentials after login
credentialsManager.store(credentials: credentials)

// Retrieve (auto-refreshes if expired and refresh token is available)
credentialsManager.credentials { result in
    switch result {
    case .success(let credentials):
        // Use credentials.accessToken
    case .failure(let error):
        // Re-authenticate
    }
}
```

**Checklist:**
- [ ] `offline_access` scope was included at login (required for refresh token)
- [ ] Refresh Token Rotation is consistently enabled/disabled between dashboard and SDK usage
- [ ] `credentialsManager.hasValid()` is used to check token status before API calls

---

## 8. Keychain Access {#keychain}

Auth0.swift stores tokens in the iOS Keychain by default.

**Checklist:**
- [ ] The app has proper entitlements to access the Keychain (this is standard but can fail in some enterprise provisioning setups)
- [ ] If using **Keychain Sharing**, the access group is consistent across extensions and the main app
- [ ] Testing on Simulator: Keychain works on Simulator but may have different behavior than a physical device in some edge cases

To enable Keychain Sharing in Xcode: **Target → Signing & Capabilities → + Capability → Keychain Sharing**

---

## 9. Simulator vs Physical Device {#simulator}

| Feature | Simulator | Physical Device |
|---------|-----------|-----------------|
| Custom URL scheme callback | Works | Works |
| Universal Links | Does **not** work | Works |
| Biometric (Face ID / Touch ID) | Limited (can simulate) | Full support |
| Keychain | Works | Works |

**Checklist:**
- [ ] If Universal Links are failing, confirm you are testing on a **physical device**
- [ ] Biometric tests require a physical device for accurate results

---

## 10. Version Compatibility

| Auth0.swift | iOS Minimum | Swift Minimum | Notes |
|-------------|-------------|---------------|-------|
| 2.x         | 14.0        | 5.7           | Current major version |
| 1.x         | 12.0        | 5.3           | Legacy, use 2.x for new projects |

**Checklist:**
- [ ] Using Auth0.swift `2.x`
- [ ] `IPHONEOS_DEPLOYMENT_TARGET` in Xcode is `14.0` or higher
- [ ] Swift version in Xcode build settings is `5.7` or higher

---

## Quick Callback URL Builder

Fill in the blanks and paste the result into Auth0 Dashboard → Allowed Callback URLs:

```
Scheme      : {bundleId}             e.g. com.example.myapp
Domain      : {auth0Domain}          e.g. your-tenant.auth0.com
Bundle ID   : {bundleId}             e.g. com.example.myapp

Callback URL: {scheme}://{domain}/ios/{bundleId}/callback
Example     : com.example.myapp://your-tenant.auth0.com/ios/com.example.myapp/callback
```

For **macOS** (Catalyst or native Mac app):

```
Callback URL: {bundleId}://{domain}/macos/{bundleId}/callback
```
