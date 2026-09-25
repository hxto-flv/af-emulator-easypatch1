# Easy Getting Started Guide

This guide is written for people who just want to get the **stable public v143b emulator** running without knowing the Assault Fire protocol first.

> Current limitation: use an **existing/local test profile path**. The unfinished first-time/new-account creation flow is intentionally not part of the stable public build.

## The short version

You will do the basic backend setup, then verify the client launch handoff:

```text
1. Clone the repo
2. Install the Python dependency
3. Generate a local RSA key pair
4. Redirect the old Assault Fire PH hostnames to 127.0.0.1
5. Start the v143b server
6. Launch client.exe / TCLS and log in until START is available
7. Choose ONE compatibility path:
   - normal launch: patch_tgame_datetime.py
   - suspended launch: patch_tcls_suspended_launch.py
8. Click START
9. Confirm TGame reaches ROLE and ZONE
```

Before your first test, also read **[Vital Launch Requirements](LAUNCH_REQUIREMENTS.md)**. It explains the TCLS → TGame shared-memory handoff and the build-specific launch patch that is easy to miss.

For PvE, v143b manages the lazy DS lifecycle: room creation reserves capacity, the stock room's selected map/settings are carried into that reservation, match start arms the bridge, and the first valid DS UDP packet starts the v48 AFDEV loader.

---

## 1. Clone the repository

Open PowerShell:

```powershell
git clone https://github.com/armangido/af-emulator.git
cd af-emulator
```

No Git? You can also use GitHub's **Code → Download ZIP**, extract it, and open PowerShell inside the extracted folder.

---

## 2. Install Python and the dependency

Python **3.12** is recommended.

Check that Python works:

```powershell
py -3.12 --version
```

Create a small virtual environment:

```powershell
py -3.12 -m venv .venv
```

Install the dependency:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

You can use `.venv\Scripts\python.exe` for every command in this guide if plain `python` points at a different Python installation.

---

## 3. Generate your local RSA key pair

This is the easiest method. **You do not need OpenSSL.**

The Assault Fire PH AUTH protocol used by this project expects a **1024-bit RSA key** for legacy client compatibility. The server receives a 128-byte RSA ciphertext and produces a 128-byte signature, so a different RSA size will not work with this protocol.

> RSA-1024 is obsolete for modern security. This helper uses it only because the legacy game protocol requires it. Do not reuse this key for websites, SSH, certificates, passwords, or anything security-sensitive.

### Easiest one-command setup

Replace the example path below with the folder that contains your client's existing `APClient.dat`.

Typical client layout:

```text
<YOUR ASSAULT FIRE FOLDER>
└── TCLS
    └── config
        └── APClient.dat
```

Example:

```powershell
.\.venv\Scripts\python.exe .\tools\setup\generate_local_rsa_keypair.py --client-config-dir "D:\AssaultFirePH\TCLS\config"
```

The helper will:

1. generate `server\PRIVATE.PEM`;
2. generate the matching public key as `generated\APClient.dat`;
3. back up your current client `APClient.dat` if one already exists;
4. copy the new matching public key into your client's `TCLS\config\APClient.dat`.

Expected output looks roughly like:

```text
[OK] Generated a matching Assault Fire PH local RSA-1024 key pair.

[PRIVATE - SERVER]
  ...\server\PRIVATE.PEM
  Keep this file private. Never commit or upload it.

[PUBLIC - CLIENT]
  ...\generated\APClient.dat

[BACKUP] ...\TCLS\config\APClient.dat
      -> ...\APClient.dat.backup_YYYYMMDD_HHMMSS

[OK] Installed matching public key:
  ...\TCLS\config\APClient.dat
```

### Important: PRIVATE.PEM and APClient.dat must match

Think of them as a pair:

```text
server\PRIVATE.PEM          <---- matching pair ---->   TCLS\config\APClient.dat
PRIVATE KEY                                            PUBLIC KEY
server keeps this                                     client uses this
NEVER upload it                                       safe to regenerate
```

If you generate a new `PRIVATE.PEM` but keep an old `APClient.dat`, AUTH will fail.

### Never upload PRIVATE.PEM

The repository's `.gitignore` blocks `PRIVATE.PEM`, `*.PEM`, and generated key files, but still check before every push:

```powershell
git status --short
```

You should **never** see `server\PRIVATE.PEM` staged for commit.

### If you only want to generate the files

Run:

```powershell
.\.venv\Scripts\python.exe .\tools\setup\generate_local_rsa_keypair.py
```

That creates:

```text
server\PRIVATE.PEM
generated\APClient.dat
```

Then copy `generated\APClient.dat` yourself to:

```text
<YOUR GAME FOLDER>\TCLS\config\APClient.dat
```

### Client compatibility note

The known working local setup uses `APClient.dat` as a raw PEM RSA-1024 public key. The original PH TCLS build required the already-known small local loader patch so it accepts that raw PEM file.

This repository does **not** distribute a modified `TCLS.dll`.

If VERSION works but AUTH fails immediately at the RSA step even though the two generated files match, check that your local TCLS setup is the version/configuration that reads the raw PEM `APClient.dat`.

---

## 4. Redirect the retired Assault Fire PH services to localhost

The local emulator needs the old PH service names to resolve to your own PC.

The three mappings are:

```text
127.0.0.1    tversion.levelupgames.ph
127.0.0.1    tauthproxy.levelupgames.ph
127.0.0.1    tdir.levelupgames.ph
```

### Easiest method

Open **PowerShell as Administrator**, go to the repository folder, then run:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\setup\setup_assaultfire_hosts.ps1
```

The helper:

- backs up your current Windows hosts file;
- removes conflicting entries only for these three Assault Fire PH names;
- adds the localhost mappings;
- flushes the Windows DNS cache.

A plain copy of the mappings is also available at:

```text
config\hosts.txt
```

### Manual method

Open Notepad as Administrator and edit:

```text
C:\Windows\System32\drivers\etc\hosts
```

Add the three lines, save, then run:

```powershell
ipconfig /flushdns
```

---

## 5. Start the stable v143b emulator

From the repository folder:

```powershell
.\.venv\Scripts\python.exe .\server\assaultfire_server_v143b.py
```

The server now automatically looks for:

```text
server\PRIVATE.PEM
```

A good sign is:

```text
[BOOT] Loaded RSA private key from ...
[VERSION] Listening on port 9060
[AUTH] Listening on port 8000
[DIR] Listening on port 9010
...
[MAIN] All listeners running.
```

If your private key is stored somewhere else, you can point the server to it:

```powershell
$env:AF_PRIVATE_KEY = "D:\MyPrivateFolder\PRIVATE.PEM"
.\.venv\Scripts\python.exe .\server\assaultfire_server_v143b.py
```

Optional log path:

```powershell
$env:AF_LOG_PATH = "D:\af-logs\server.log"
```

Keep the server window open while testing.

---

## Before launching: legacy security-driver compatibility

The original Assault Fire PH client includes a legacy kernel-level security / anti-cheat component designed for an older Windows environment.

On modern Windows, this old component can cause startup failures, crashes, driver initialization errors, or other instability even when the local emulator is responding correctly.

For preservation testing, some users may need a local test environment where that obsolete security-driver path is not active or is otherwise avoided.

This repository does **not** provide instructions or tooling for defeating active anti-cheat/security systems.

Any operating-system, driver, boot-policy, virtualization, or security configuration changes a user independently chooses to make are at that user's own risk. The project maintainers/contributors are not responsible for system instability, data loss, security problems, driver failures, or other consequences caused by third-party tools, original game drivers, or user-performed system changes.

See [Issue #4](https://github.com/armangido/af-emulator/issues/4), [Vital Setup Notes](VITAL_SETUP_NOTES.md), and [DISCLAIMER.md](../DISCLAIMER.md).

---

## 6. Choose one client compatibility path

The validated PH client needs the TGame datetime compatibility fix. There are now **two ways** to apply it. Use only one for a given launch.

### Path A — normal TCLS launch

If your TCLS already launches TGame reliably, start the standalone datetime patcher in a second PowerShell window:

```powershell
.\.venv\Scripts\python.exe .\tools\patches\patch_tgame_datetime.py
```

It waits for `TGame.exe`, verifies:

```text
TGame.exe + 0x010B9510
expected: 83 EC 24 53 8B 5C 24 2C
```

and applies the runtime-only datetime fix.

### Path B — debugger-free suspended TCLS launch

If your setup needs the proven TCLS handoff timing, first launch `client.exe / TCLS`, log in, and stop at the normal **START** screen.

Close/detach x32dbg, then run:

```powershell
.\.venv\Scripts\python.exe .\tools\patches\patch_tcls_suspended_launch.py
```

Wait for:

```text
TCLS ARMED
Click START in the Assault Fire launcher now.
```

Then click START.

The combined helper will:

1. locate the loaded `TCLS.dll`;
2. verify `TCLS.dll+0x584E0 == 8B 55 18 52`;
3. temporarily change those bytes to `6A 04 90 90` so TGame is created suspended;
4. detect the new child `TGame.exe`;
5. restore the original TCLS bytes immediately;
6. apply `patch_tgame_datetime.py` to the suspended child;
7. resume the primary TGame thread;
8. print a final success summary.

This is runtime-only. It does not modify `TCLS.dll` or `TGame.exe` on disk.

If either TCLS or TGame has a signature mismatch, the helper stops instead of forcing the patch. If the datetime patch fails after child creation, TGame is intentionally left suspended rather than resumed into a known failure path.

For manual inspection, you can keep TGame suspended after both runtime patches:

```powershell
.\.venv\Scripts\python.exe .\tools\patches\patch_tcls_suspended_launch.py --leave-suspended
```

**Do not run the standalone datetime patcher at the same time as the combined helper.**

More details: [Vital Launch Requirements](LAUNCH_REQUIREMENTS.md) and [Issue #3](https://github.com/armangido/af-emulator/issues/3).

---

## 7. Verify the TCLS → TGame launch handoff

Do **not** treat the launcher and TGame as the same program. The normal retail path is:

```text
client.exe / TCLS
  -> GetLoginInfo / selected server
  -> CreateProcessW(TGame.exe -q <uin>)
  -> TCLS_SHAREDMEMEMORY<child PID>
  -> TGame.exe
  -> ROLE
  -> ZONE
```

On the validated PH TCLS build, these locations were recovered:

```text
TCLS.dll + 0x5C150   CLaunchUI::GetLoginInfo
TCLS.dll + 0x5C230   selected game-server lookup
TCLS.dll + 0x5C236   "Get Game Server Info fail!" check
TCLS.dll + 0x5E7B3   shared-memory CreateFileMappingW path
TCLS.dll + 0x584F4   CreateProcessW area
```

### Optional suspended-launch compatibility path

Some preservation setups need enough time to let TCLS finish the handoff and apply TGame compatibility work before TGame initializes.

At the normal launcher START stage, the validated build can temporarily use:

```text
TCLS.dll + 0x584E0
expected: 8B 55 18 52
patch   : 6A 04 90 90
```

That changes the creation flags to `CREATE_SUSPENDED`.

Rules:

- verify the expected four bytes first;
- patch process memory only;
- never distribute a modified `TCLS.dll`;
- restore `8B 55 18 52` immediately after the child TGame is observed;
- apply the TGame runtime compatibility patch while the child is suspended;
- resume TGame afterward;
- do not leave a debugger attached to TGame during normal protected initialization.

If your setup already launches TGame reliably, do **not** apply this just because it is documented.

Full details and failure diagnosis: **[LAUNCH_REQUIREMENTS.md](LAUNCH_REQUIREMENTS.md)**.

---

## 8. Launch Assault Fire PH

Start the client using the same local client setup you normally use.

The hosts entries send VERSION/AUTH/DIR traffic to the emulator on your PC.

For the public **v143b** baseline, test an existing/local profile path. Do not use the unfinished new-account/nickname flow as your first test.

### First things to check

| Check | Expected |
|---|---|
| VERSION reaches local server | ✅ |
| Login AUTH handshake reaches local server | ✅ |
| Server list/DIR loads | ✅ |
| Existing local profile reaches zone/login path | ✅ baseline target |
| Basic profile/property state | ✅ baseline target |
| First-ever account creation | ❌ not supported in public v143b |
| PvE dedicated-server/gameplay handoff + room-selected map | ✅ integrated on main |

See [STATUS.md](STATUS.md) for the detailed working/partial/broken matrix.

---

## 9. PvE map setup

You do **not** need the DS components just to test VERSION/AUTH/DIR/login. For PvE, the current v143b server manages them as part of the match lifecycle.

Current files:

```text
server\assaultfire_ds_spawner.py
tools\server_spawner\AFDevLoader_v48_spawner_multi_instance.py
tools\bridge\af_ds_udp_bridge_v9_multi_peer_latch.py
```

Set `AF_GAME_DIR` to the `Binaries\\Win32` directory of your Assault Fire PH installation (the drive letter/install location can be different), then start v143b:

```powershell
$env:AF_GAME_DIR = "<full path to your Assault Fire PH Binaries\Win32 folder>"
$env:AF_DS_SPAWNER_ENABLED = "1"
.\.venv\Scripts\python.exe .\server\assaultfire_server_v143b.py
```

The lifecycle is lazy: A10A reserves capacity only and seeds the stock room's map/settings; A11E can update them before start; A3A0/A113 arms the bridge; the first valid DS UDP packet starts AFDEV; verified `SESSION_READY` releases the latched packet and the UE3 session goes live.

By default `AF_DS_USE_CLIENT_MAP=1`, so the selected stock-client `MapString` is used. Set it to `0` only if you intentionally want to force `AF_DS_DEFAULT_MAP`.

See **[Stable PvE bridge + server spawner guide](PVE_BRIDGE_AND_SPAWNER.md)** and **[PvE runtime and map selection](PVE_RUNTIME.md)**.

The older Issue #1 sample documents the pre-fix state.

## 10. Super-simple troubleshooting

### Launcher says "AP client initialization failed."

First look at the emulator window. If you see VERSION traffic but **no `[AUTH] Connected ...`**, TCLS failed to initialize the AP client locally before it even reached the emulator's AUTH protocol.

Reinstall a matching generated APClient file into the exact client copy you launch:

~~~powershell
.\.venv\Scripts\python.exe .\tools\setup\generate_local_rsa_keypair.py --client-config-dir "D:\Assault Fire PH\TCLS\config" --force
~~~

Then verify:

~~~powershell
Get-Item "D:\Assault Fire PH\TCLS\config\APClient.dat" | Select-Object FullName,Length
Get-Content "D:\Assault Fire PH\TCLS\config\APClient.dat" -TotalCount 1
~~~

The repository-generated file should be **272 bytes** and start with:

~~~text
-----BEGIN PUBLIC KEY-----
~~~

Important: the known PH setup needs the client-side TCLS configuration that accepts this raw PEM form. If VERSION succeeds but AUTH is never opened, repeatedly changing the server's AP response will not fix that stage.

Also, `TCLS.dll+0x584E0` is the **TGame suspended-launch patch**, not the APClient loader fix.

See **[Launcher / AP / TGame Error Reference](LAUNCHER_ERRORS.md#ap-client-initialization-failed)** for the full diagnosis.

### Server says it cannot load PRIVATE.PEM

Run the generator again:

```powershell
.\.venv\Scripts\python.exe .\tools\setup\generate_local_rsa_keypair.py
```

Then confirm this file exists:

```text
server\PRIVATE.PEM
```

### AUTH reaches the server but RSA decrypt fails

The most common thing to check first is that the client public key and server private key are from the **same generated pair**.

Regenerate/install both together:

```powershell
.\.venv\Scripts\python.exe .\tools\setup\generate_local_rsa_keypair.py --client-config-dir "D:\YourGameFolder\TCLS\config" --force
```

Then restart both the server and client.

If it still fails immediately at RSA, verify your TCLS setup reads the raw PEM `APClient.dat`.

### The client tries the old internet host instead of localhost

Run Administrator PowerShell:

```powershell
ipconfig /flushdns
```

Then check:

```powershell
ping tversion.levelupgames.ph
```

It should resolve to:

```text
127.0.0.1
```

### Port already in use

The stable backend uses several local ports including:

```text
9060   VERSION
8000   AUTH
9010   DIR
65005  ROLE
65006  ZONE in the stable configuration
```

Close an older copy of the emulator before starting another one.

---

## 11. How to report a useful bug

Please include:

```text
Client version:
Server commit:
What I clicked/did:
What I expected:
What happened instead:

Relevant server log:
...

Packet command/opcode if known:
...

Does it reproduce after restarting both client and server?
Yes / No
```

Before posting logs publicly, remove:

- passwords;
- private keys;
- access tokens;
- personal account information;
- unrelated local filesystem details.

Never attach `PRIVATE.PEM`.

---

## 12. Easy ways to contribute

You do not have to know assembly.

Helpful contributions include:

- making the setup guide clearer;
- adding tests;
- documenting packet IDs;
- reproducing an issue and reporting exact steps;
- comparing sanitized packet captures;
- improving Python error messages;
- documenting which client UI action produces which request;
- helping verify partial lobby/social/clan/PvE behavior.

Please read [../CONTRIBUTING.md](../CONTRIBUTING.md) before submitting code.

Small changes with clear evidence are better than large guessed protocol implementations.
