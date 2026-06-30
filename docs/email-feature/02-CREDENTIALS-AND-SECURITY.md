# Credentials & Security

## The mailbox

| | |
|---|---|
| **Sender** | `reports@sounalhosn.ae` (dedicated cPanel mailbox, created for this) |
| **Recipient** | `Mohamed@sounalhosn.ae` |
| **SMTP host** | `sounalhosn.ae` |
| **Port** | `465` (implicit SSL) |
| **Auth** | the mailbox's own password (cPanel — no App Password needed) |

A **dedicated** `reports@` sender was chosen (not a personal mailbox) so the
credential that ships to client machines is low-value and revocable without
touching anyone's personal email.

## How the password travels: baked-in obfuscation

The credentials ship **inside the app**, XOR-scrambled with a fixed key and
base64-encoded, in `app/modules/emailer.py`:

```python
_OBF_KEY = b"sr-falcon-2026"
_DEFAULTS = {
    "HOST": "...", "PORT": "...", "USER": "...",
    "PASSWORD": "...",   # the reports@ mailbox password, obfuscated
    "TO": "...",
}
```

`_deobf()` reverses it at runtime. So a fresh client install (just `git pull` /
the `.exe`) can send email with **zero setup on-site**.

### ⚠️ This is obfuscation, NOT encryption

This is an explicit, accepted trade-off — **the user chose it knowingly**:

- The app must unscramble the password by itself, unattended, with no external
  key. So the key ships with the app. Anyone with the code/`.exe` who knows what
  to look for **can recover the password.**
- What obfuscation *does* buy: it's not plaintext, won't show in a casual `grep`,
  and won't trip GitHub/automated secret scanners.
- Why it's acceptable here: it's a **dedicated, low-value `reports@` mailbox**
  whose only ability is to *send* report emails, and it can be **rotated in
  cPanel in ~30 seconds**.

### Risk register

| Risk | Mitigation |
|------|-----------|
| Password recoverable from the app | Low-value send-only mailbox; rotatable instantly. |
| Repo is public | **Action item:** confirm `j0ons/soun-runner` is PRIVATE. If public, rotate + privatise. |
| Password was in the build chat transcript | Rotate when convenient (see below). |
| Mailbox abused to send spam | It's a normal mailbox — watch the Sent folder; rotate if anything looks off. |

## 🔁 How to rotate the password (do this if ever in doubt)

1. **cPanel** → Email Accounts → `reports@sounalhosn.ae` → **Manage** → set a new
   password. (≈30 seconds.)
2. Regenerate the obfuscated blob — run this from the project root:

   ```bash
   python3 -c "from app.modules.emailer import _obf; print(_obf('NEW-PASSWORD-HERE'))"
   ```

3. Paste the output into `_DEFAULTS["PASSWORD"]` in `app/modules/emailer.py`.
4. Commit + push. Every client install picks it up on next `git pull` / rebuild.

> The same `_obf()` trick regenerates HOST / USER / TO blobs if those ever change.

## Override without rebuilding (per machine)

You never *need* to, but you can override any field on a specific machine:

- **`config.local`** (git-ignored, persists across `git pull`) — copy
  `config.local.example` → `config.local`, fill in.
- **Environment variables** in the launcher (`SOUN_SMTP_*`).

Both win over the baked-in defaults.

## What is and isn't in git

| In git (safe) | NOT in git |
|---------------|-----------|
| Obfuscated blob in `emailer.py` (must ship) | The real `config.local` (git-ignored) |
| `config.local.example` (placeholder values) | Plaintext password anywhere |

Every commit in this feature was checked with
`git diff --cached | grep -i '<password>'` to confirm no plaintext leaked.
