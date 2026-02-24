You are running the **Auth0 Pre-Support Debugger** skill for Android and Swift/iOS SDKs.

Read and follow the skill instructions in full from:
`auth0-presupport-debugger/SKILL.md`

Also load the reference documents as needed:
- `auth0-presupport-debugger/references/cli-config-validation.md`
- `auth0-presupport-debugger/references/android-checklist.md`
- `auth0-presupport-debugger/references/swift-checklist.md`
- `auth0-presupport-debugger/references/common-issues.md`

---

Start by asking the user:

1. **Platform** — Android or Swift/iOS (or both)?
2. **Symptom** — What is failing? (e.g. login hangs, callback URL mismatch, token error, crash, DPoP error, passkey failure)
3. **SDK version** in use
4. **Advanced features** — Are they using **DPoP** or **Passkeys**?
5. **Auth0 CLI available?** — Do they have the Auth0 CLI installed? (`auth0 --version`). If not, detect their OS first (`uname -s` or ask), then offer to install:
   - **macOS:** `brew tap auth0/auth0-cli && brew install auth0`
   - **Windows:** `scoop bucket add auth0 https://github.com/auth0/scoop-auth0-cli.git && scoop install auth0`
   - **Linux:** `curl -sSfL https://raw.githubusercontent.com/auth0/auth0-cli/main/install.sh | sh -s -- -b /usr/local/bin`
   
   If they accept, install and proceed to Phase 0. If they decline, skip to Phase 1.

> **Note:** All CLI validation commands in `references/cli-config-validation.md` use `grep -oP` (Perl regex) which works on Linux/Windows(WSL) but not macOS default grep. On macOS, use `ggrep -oP` (install via `brew install grep`) or the equivalent `sed`/`awk` alternatives shown in the reference doc.

Then walk through the diagnostic phases defined in the skill (Phase 0 if CLI is available, otherwise Phase 1), one at a time, asking targeted questions and checking their configuration against the checklists. At the end, generate the Pre-Ticket Diagnostic Summary from Phase 4 filled in with everything collected.
