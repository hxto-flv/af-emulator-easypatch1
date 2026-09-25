# Frequently Asked Questions

This FAQ covers the most common setup and troubleshooting questions for the public **Assault Fire PH emulator v143b** baseline.

## I got an AP / launcher / TGame error code. Where do I look?

Use the dedicated **[Launcher / AP / TGame Error Reference](LAUNCHER_ERRORS.md)**.

It currently catalogs the errors we have actually observed or verified, including:

- AP cmd 4 / cmd 5 failure checkpoints;
- RSA/APClient mismatch symptoms;
- AP framing/padding diagnostics;
- `Get Game Server Info fail!`;
- `Get loginInfo fail!`;
- `Network is disconnected:Connection Closed!`;
- known legacy security warning tuples such as `(1, 81008, 4B)`;
- `0xC000071C STATUS_INVALID_THREAD`;
- `0xC0000005`;
- TGame datetime/signature errors.

Unknown codes are intentionally marked unknown instead of being guessed.

---

## Why does TGame.exe crash even though the server is running?

The known PH client build can enter a datetime conversion path with an invalid/pre-1900 year and crash.

This is a **client compatibility problem**, not necessarily a VERSION/AUTH/DIR server failure.

Before launching the client, start:

```powershell
.\.venv\Scripts\python.exe .\tools\patches\patch_tgame_datetime.py
```

You should see:

```text
Waiting for TGame.exe ...
You can launch the game now.
```

Launch Assault Fire. When TGame appears, the patcher should print:

```text
PATCHED
...
Datetime fix is active for this TGame process.
```

The known validated location is:

```text
TGame.exe + 0x010B9510
VA 0x014B9510 with image base 0x00400000
```

Expected original bytes:

```text
83 EC 24 53 8B 5C 24 2C
```

The helper checks those bytes first and refuses to patch a different build blindly.

The patch is **runtime-only**; it does not modify `TGame.exe` on disk.

See [Issue #3](https://github.com/armangido/af-emulator/issues/3).

---

## What about the old kernel anti-cheat / security driver?

The original PH client includes a legacy kernel-level security / anti-cheat component from an older Windows era.

On modern Windows, it may cause:

- startup failure;
- early TGame/client crashes;
- driver initialization errors;
- conflicts with current Windows security;
- instability that looks like an emulator/network problem.

For local preservation testing, some users may need an environment where that obsolete security-driver path is not active or is otherwise avoided.

This project does **not** provide instructions or tooling for defeating active anti-cheat/security systems. Any system/driver/security configuration changes a user independently chooses to make are at that user's own risk.

The maintainers and contributors are not responsible for damage, instability, data loss, security issues, or driver/system consequences caused by third-party tools, original game drivers, or user-performed system changes.

See [Issue #4](https://github.com/armangido/af-emulator/issues/4), [Vital Setup Notes](VITAL_SETUP_NOTES.md), and [DISCLAIMER.md](../DISCLAIMER.md).

---

## What version should I use?

Use the public **v143b stable baseline**.

Later branches contain experimental work, especially first-login/new-account behavior, and are intentionally not part of `main` yet.

See [Project Status](STATUS.md).

---

## Do I need to generate a private key?

Yes.

The local AUTH implementation uses a matching RSA-1024 key pair:

```text
server\PRIVATE.PEM            TCLS\config\APClient.dat
private key          <---->    matching public key
```

Generate both with:

```powershell
.\.venv\Scripts\python.exe .\tools\setup\generate_local_rsa_keypair.py --client-config-dir "D:\YourAssaultFireFolder\TCLS\config"
```

Never commit or upload `PRIVATE.PEM`.

---

## Why RSA-1024?

The legacy PH AUTH flow uses a 128-byte RSA ciphertext/signature operation, which corresponds to RSA-1024.

This is retained only for compatibility with the old client protocol. Do not reuse this key for modern security purposes.

---

## What is APClient.dat?

For the known local setup, `APClient.dat` contains the matching RSA-1024 public key in PEM form.

It must match the private key used by the emulator.

If the pair does not match, AUTH will fail.

The original PH TCLS build also needs the already-known local compatibility change that allows it to read the raw PEM `APClient.dat`. This repository does not distribute a modified `TCLS.dll`.

---

## Why does the client still try to contact the old servers?

Check your Windows hosts file.

The stable local mappings are:

```text
127.0.0.1    tversion.levelupgames.ph
127.0.0.1    tauthproxy.levelupgames.ph
127.0.0.1    tdir.levelupgames.ph
```

Use the included helper from Administrator PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\setup\setup_assaultfire_hosts.ps1
```

Then flush DNS:

```powershell
ipconfig /flushdns
```

---

## Which ports does the emulator use?

| Port | Service | Purpose |
|---:|---|---|
| 9060 | VERSION | Client version/start check |
| 8000 | AUTH | RSA/DH/AES login handshake |
| 9010 | DIR | Server/directory discovery |
| 65005 | ROLE | Stable role/game-side service path |
| 65006 | ZONE | Stable zone connection |
| 65008 | PvE bridge | Local v9 bridge entry used by the integrated PvE match path |
| 7777/UDP | AFDEV | Local v48 UE3/AFDEV listen-server endpoint used by the integrated PvE path |

Ports 65008 and 7777 are needed only when running PvE dedicated-server sessions; normal VERSION/AUTH/DIR/login testing does not use them.

---

## Does PvE map selection work?

**Yes for the local v143b dedicated-server/gameplay handoff integrated on `main`.**

The current path reserves DS capacity at room creation, carries the stock room's selected `MapString`/settings into the reservation, lets A11E replace them before start, arms the bridge at match start, lazily starts the v48 AFDEV loader on the first valid DS UDP packet, verifies the runtime/zero DS key, and releases the latched UE3 handshake through the v9 multi-peer bridge.

The current path is map-generic: supported PvE maps selected by the stock room UI use the same v48/v9 dedicated-server lifecycle. The selected map must exist in the local cooked map tree and be compatible with the PvE game class. Match-history/reward work and the PH-client difficulty-label mismatch are separate follow-up areas.

## Do I need the bridge and AFDEV spawner for normal login testing?

No.

VERSION/AUTH/DIR/basic existing-profile testing uses the main v143b emulator and does not need a DS instance. For PvE, v143b launches/manages the bridge and AFDEV loader lazily as part of the match path.

See [PvE Bridge and Spawner](PVE_BRIDGE_AND_SPAWNER.md).

---

## Why does the repo not include TGame.exe, TCLS.dll, maps, UPK files, or other game assets?

Those are original third-party game files.

This project publishes original emulator code, tools, and research documentation, but not proprietary game binaries/assets.

You need your own lawfully obtained client files.

---

## Can I create a brand-new account in the public build?

Not reliably.

The first-time nickname/new-account flow is experimental and intentionally excluded from the stable public v143b baseline.

Use the existing/local profile path when testing `main`.

---

## Is the lobby fully implemented?

Not yet.

The stable branch contains a lobby/room foundation, but some room behavior is synthetic/research-grade rather than a complete production-style dynamic lifecycle.

See [STATUS.md](STATUS.md).

---

## Are friends, private chat, and clans fully working?

They are **partial** in the stable baseline.

The repository contains useful protocol foundations, but real two-client behavior and complete stock UI integration still need verification before being called stable.

---

## What should I run first?

For a basic local test:

```text
1. v143b emulator
2. the appropriate TGame/TCLS compatibility helper for your launch path
3. Assault Fire PH client
```

For PvE, set `AF_GAME_DIR` and enable the DS spawner, then run the same v143b server. The stock room's selected map is used by default. Do not manually pre-start AFDEV for every lobby; the current path starts it lazily after the client sends the first valid DS UDP packet.

See the [Easy Getting Started Guide](GETTING_STARTED.md) for copy/paste commands.

## The server says a port is already in use. What do I do?

Make sure an older emulator/bridge/AFDEV process is not already running.

Useful Windows command:

```powershell
netstat -ano | findstr ":9060 :8000 :9010 :65005 :65006 :65008 :7777"
```

Then identify a PID:

```powershell
tasklist /FI "PID eq YOUR_PID"
```

Do not kill unrelated processes just because they appear in the output.

---

## Where should I report a bug?

Open a GitHub issue and include:

- client version;
- server commit;
- exact steps;
- expected behavior;
- actual behavior;
- smallest useful sanitized log;
- packet command/opcode if known.

Do **not** upload:

- `PRIVATE.PEM`;
- passwords/tokens;
- original proprietary game binaries/assets;
- unrelated personal data.

---

## I want to help but I do not know assembly. Can I still contribute?

Yes.

Good contribution areas include:

- documentation;
- setup testing;
- protocol packet parsing;
- unit tests;
- sanitized packet comparisons;
- reproducing issues;
- identifying which client UI action sends which command;
- Python cleanup that preserves verified behavior;
- error messages and diagnostics.

See [CONTRIBUTING.md](../CONTRIBUTING.md).

---

## What is the overall goal?

The project is a community preservation/server-emulation effort for the retired Assault Fire PH client.

The long-term target is a reproducible local environment where verified stock-client behavior can be preserved and studied without relying on the original online service.
