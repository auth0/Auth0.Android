# 🧠 Prompt: Designing a Modular UI SDK for Auth0.Android Integration

You are tasked with designing a **new Android SDK/module** that provides reusable **UI components** on top of the existing `Auth0.Android` SDK. This new SDK should encapsulate common authentication flows through customizable UI elements, using either Jetpack Compose or XML-based views.

---

## 📚 Background: Existing SDK Summary (Auth0.Android)

- Offers OAuth 2.0/OpenID Connect support with WebAuthProvider, AuthenticationAPIClient, etc.
- Includes secure credential management with DPoP, PKCE, biometric auth.
- Java/Kotlin hybrid codebase targeting Android API 21+.
- Uses best practices like builder patterns, modular package structure, and Robolectric/Mockito for testing.

---

## ✅ New SDK Requirements

### 1. SDK Integration & Session Management

- New UI SDK must **depend on** and **interact with Auth0.Android** (not duplicate logic).
- Should manage or receive a shared instance of `Auth0` and `CredentialsManager`. Share the best way how this can be achieved

### 2. UI Toolkit Support

- Should **support both Jetpack Compose and XML-based UI**.
- Provide:
  - Complete UI components (`LoginScreen`, `SignUpScreen`)
  - Atomic UI elements (`LoginButton`, `InputField`, etc.)
- Consider modular separation for Compose and View-based components.

### 3. Customizability

- Support **theme overrides**, styleable attributes, customizable strings/icons.
- Developers should be able to:
  - Replace entire screens or override component behavior
  - Hook into lifecycle events (onLoginSuccess, onError, etc.)

### 4. Best Practices: Architecture, Testing, Security

- Use **MVVM** or **Unidirectional Data Flow (UDF)** pattern.
- UI separated from business logic (state handled in ViewModels or any other better option). Applicable for complete UI-components
- Token/session logic must use `Auth0.Android` SDK securely.
- Testable with **MockWebServer**, **Robolectric**, **UI tests for Compose and XML**.

---


## 📌 Deliverables for the LLM

Generate a architecture/design proposal for the above SDK. The Design should be a low-level design (LLD) with diagrams showcasing the control flow and dependency . No need to provide actual code implementaiton and make any code changes. Only share the design proposal. I will review it and reiterate on the same .  It should include:

1. Session/Auth0 instance management strategy
2. UI framework coexistence plan (Compose + XML)
3. Customization strategies (themes, styles, callback interfaces)
4. Security and testability considerations


