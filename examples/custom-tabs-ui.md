## Customize the Custom Tabs UI

If the device where the app is running has a Custom Tabs compatible Browser, a Custom Tab will be preferred for the logout flow. You can customize the Page Title visibility, the Toolbar color, and the supported Browser applications by using the `CustomTabsOptions` class.

```kotlin
val ctOptions = CustomTabsOptions.newBuilder()
    .withToolbarColor(R.color.ct_toolbar_color)
    .showTitle(true)
    .build()
 
WebAuthProvider.login(account)
    .withCustomTabsOptions(ctOptions)
    .start(this, callback)
```

<details>
  <summary>Using Java</summary>

```java
CustomTabsOptions options = CustomTabsOptions.newBuilder()
   .withToolbarColor(R.color.ct_toolbar_color)
   .showTitle(true)
   .build();

WebAuthProvider.login(account)
   .withCustomTabsOptions(options)
   .start(MainActivity.this, callback);
```
</details>

### Partial Custom Tabs (Bottom Sheet and Side Sheet)

You can present the authentication flow as a **bottom sheet** on compact screens or a **side sheet** on larger screens (e.g., tablets and foldables) instead of a full-screen browser tab. This is configured through `CustomTabsOptions`.

> **Browser compatibility:**
> - **Bottom sheet** (Partial Custom Tabs) requires **Chrome 107+** (or another Custom Tabs browser that supports the Partial Custom Tabs protocol).
> - **Side sheet** requires **Chrome 120+** (or another browser that supports side-sheet Custom Tabs).
>
> If the user's browser does not meet the minimum version requirement, the authentication flow automatically falls back to a standard full-screen Custom Tab (or a full-screen browser tab if Custom Tabs are unsupported). It is therefore safe to enable these options unconditionally — users on older browsers will simply see the full-screen experience.

#### Bottom sheet

```kotlin
val ctOptions = CustomTabsOptions.newBuilder()
    .withInitialHeight(700)          // initial height in dp
    .withResizable(true)             // allow the user to drag to resize (default)
    .withToolbarCornerRadius(16)     // rounded top corners (0–16 dp)
    .build()

WebAuthProvider.login(account)
    .withCustomTabsOptions(ctOptions)
    .start(this, callback)
```

#### Side sheet (with bottom-sheet fallback on narrow screens)

```kotlin
val ctOptions = CustomTabsOptions.newBuilder()
    .withInitialHeight(700)          // used when the screen is narrower than the breakpoint
    .withInitialWidth(500)           // initial side-sheet width in dp
    .withSideSheetBreakpoint(840)    // screens wider than this render as a side sheet
    .build()

WebAuthProvider.login(account)
    .withCustomTabsOptions(ctOptions)
    .start(this, callback)
```

If `withSideSheetBreakpoint` is not set, the browser's default breakpoint (typically 840 dp in Chrome) applies, so devices narrower than that will continue to render as a bottom sheet or full screen.

#### Allow interaction with the app behind the partial tab

By default, the app behind a Partial Custom Tab is non-interactive. Enable pass-through interaction with:

```kotlin
val ctOptions = CustomTabsOptions.newBuilder()
    .withInitialHeight(700)
    .withBackgroundInteractionEnabled(true)
    .build()
```

<details>
  <summary>Using Java</summary>

```java
CustomTabsOptions options = CustomTabsOptions.newBuilder()
    .withInitialHeight(700)
    .withInitialWidth(500)
    .withSideSheetBreakpoint(840)
    .withToolbarCornerRadius(16)
    .withBackgroundInteractionEnabled(true)
    .build();

WebAuthProvider.login(account)
    .withCustomTabsOptions(options)
    .start(MainActivity.this, callback);
```
</details>

### Allow the initial redirect to leave the browser (`https` scheme)

> **When you need this:** only if you use an `https` redirect scheme (Android App Links) **and** need to support **Chrome 119 or older**. On Chrome 120+ this is handled automatically, and the Auth Tab flow is unaffected. The option is disabled by default and is safe to leave off otherwise.

When the redirect scheme is `https`, a Custom Tab opened from a Custom Tabs session always targets the browser package explicitly. Chrome versions prior to 120 interpret that as a request to keep the *initial* navigation chain inside the browser. If the `/authorize` request redirects straight to the callback URL without any user interaction — for example because the user already has a session or `prompt=none` is used — those Chrome versions load the callback URL inside the Custom Tab instead of launching your app, and the user sees a `Not found.` page.

Enabling `withSendToExternalDefaultHandlerEnabled(true)` sets `CustomTabsIntent.EXTRA_SEND_TO_EXTERNAL_DEFAULT_HANDLER` on the intent, which lets that initial redirect launch your app instead:

```kotlin
val ctOptions = CustomTabsOptions.newBuilder()
    .withSendToExternalDefaultHandlerEnabled(true)
    .build()

WebAuthProvider.login(account)
    .withCustomTabsOptions(ctOptions)
    .start(this, callback)
```

<details>
  <summary>Using Java</summary>

```java
CustomTabsOptions options = CustomTabsOptions.newBuilder()
    .withSendToExternalDefaultHandlerEnabled(true)
    .build();

WebAuthProvider.login(account)
    .withCustomTabsOptions(options)
    .start(MainActivity.this, callback);
```
</details>
