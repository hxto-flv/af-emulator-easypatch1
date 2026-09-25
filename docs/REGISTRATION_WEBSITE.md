# Registration, login, recovery and admin website

The repository includes a local Flask website backed by the same SQLite account database used by `server/account_db.py`.

## Features

- Case-insensitive usernames with parameterized SQLite queries.
- PBKDF2-HMAC-SHA256 password hashing with per-account random salts.
- Invite-gated beta registration by default.
- High-entropy invite codes; only their SHA-256 hashes are stored.
- One login URL for normal users and administrators.
- `/admin` returns **404** unless the logged-in account is an administrator.
- Administrator invite creation and account ban/unban controls.
- Banned accounts cannot log in or use recovery.
- Three one-time recovery codes per issue; only their hashes are stored.
- Recovery failure lockout after repeated bad codes.
- CSRF validation on every POST.
- HTTPOnly / SameSite session cookies and browser security headers.
- Web access/IP logging using the direct request peer address.

## Install

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Configure an administrator

```powershell
$env:AF_ADMIN_USERNAME = "admin"
$env:AF_ADMIN_PASSWORD = "use-a-long-unique-password"
$env:AF_WEB_SECRET = "use-a-long-random-session-secret"
```

If the administrator username already exists, startup refuses to promote it unless the configured password matches that existing account.

## Run

```powershell
.\.venv\Scripts\python.exe .\web\app.py
```

Default local address: `http://127.0.0.1:8080/login`.

Routes:

```text
/register   beta/invite registration
/login      shared normal/admin login
/account    signed-in account page + recovery-code generation
/recover    one-time recovery-code password reset
/status     local-service status
/admin      admin-only; returns 404 for everyone else
```

## Environment variables

```text
AF_ACCOUNT_DB           SQLite database path
AF_WEB_HOST             bind host, default 127.0.0.1
AF_WEB_PORT             bind port, default 8080
AF_WEB_SECRET           persistent Flask session secret
AF_REQUIRE_INVITE       1 by default; set 0 only for open local testing
AF_ADMIN_USERNAME       optional admin bootstrap username
AF_ADMIN_PASSWORD       matching admin bootstrap password
AF_WEB_SECURE_COOKIE    set 1 when serving through HTTPS
```

For anything beyond localhost, use a persistent `AF_WEB_SECRET`, HTTPS, and `AF_WEB_SECURE_COOKIE=1`. Do not expose the development server directly to an untrusted public network.

## Recovery behavior

A signed-in player can generate three one-time recovery codes. Generating a new set invalidates earlier unused codes. A successful recovery consumes the supplied code. Repeated failed recovery attempts create a temporary durable lockout. Banned accounts are excluded from recovery.

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_account_db -v
.\.venv\Scripts\python.exe -m unittest tests.test_web_account_service -v
.\.venv\Scripts\python.exe -m unittest tests.test_web_app -v
```

The Flask route tests require dependencies from `requirements.txt`.

## Important game-login boundary

The website safely creates and manages local SQLite accounts, but it does **not** claim that the stock PH launcher username/password packet is fully wired to this database yet. The known-good TCLS/game login path remains separate until the exact AP cmd-3 credential fields are validated and connected without destabilizing the stable client handoff.

This separation is intentional: website/account work must not break VERSION/AUTH/DIR/ROLE/ZONE or the integrated v143b PvE/DS runtime.
