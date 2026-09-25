# Vital Setup Notes

Read this page before troubleshooting protocol bugs.

These are the compatibility requirements and known client-side blockers that can make Assault Fire PH fail even when the emulator itself is behaving correctly.

## 1. Use the stable public v143b baseline

Use:

```text
server/assaultfire_server_v143b.py
```

The public `main` branch uses the stable pre-new-account v143b server and intentionally excludes the unfinished first-login/new-account experiments.

## 2. The RSA key pair must match

The server private key:

```text
server/PRIVATE.PEM
```

must match the public key used by the client:

```text
TCLS/config/APClient.dat
```

Generate a matching pair with:

```powershell
.\.venv\Scripts\python.exe .\tools\setup\generate_local_rsa_keypair.py --client-config-dir "D:\YourAssaultFireFolder\TCLS\config"
```

Never upload or commit `PRIVATE.PEM`.

## 3. Redirect the retired PH hostnames to localhost

The required local mappings are:

```text
127.0.0.1    tversion.levelupgames.ph
127.0.0.1    tauthproxy.levelupgames.ph
127.0.0.1    tdir.levelupgames.ph
```

Use:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\setup\setup_assaultfire_hosts.ps1
```

from Administrator PowerShell.

## 4. TGame datetime compatibility patch

The known PH `TGame.exe` build can crash in a legacy datetime conversion path.

Before launching the client, run:

```powershell
.\.venv\Scripts\python.exe .\tools\patches\patch_tgame_datetime.py
```

The helper verifies the known byte signature first and patches memory only for the running process.

See [Issue #3](https://github.com/armangido/af-emulator/issues/3).

## 5. Legacy kernel anti-cheat compatibility warning

Assault Fire PH shipped with a legacy kernel-level anti-cheat/security component designed for an older Windows environment.

On modern Windows systems, that old kernel component can be a serious compatibility problem and may contribute to:

- client startup failure;
- crashes;
- driver initialization errors;
- security-product conflicts;
- instability unrelated to the emulator protocol;
- behavior that looks like a server/network bug even when it is not.

For preservation testing, some users may need a local environment in which that obsolete anti-cheat path is not active or is otherwise avoided.

### Important boundary

This repository does **not** provide:

- kernel anti-cheat bypass code;
- instructions for defeating active anti-cheat protections;
- driver tampering procedures;
- signing/security-control bypass instructions;
- methods intended for use against a live competitive service.

The project is for preservation/research of the retired Assault Fire PH client and local emulator.

Any operating-system, driver, boot-policy, virtualization, or security configuration changes a user independently chooses to make are their own responsibility and may carry system/security risk.

The project maintainers and contributors are not responsible for damage, instability, data loss, account/system consequences, or security problems caused by third-party tools or user-performed kernel/driver/security modifications.

If the legacy anti-cheat is the blocker, treat it as a **client compatibility issue**, not as proof that VERSION/AUTH/DIR/ROLE/ZONE emulation is incorrect.

## 6. Keep testing isolated

Recommended:

- use your own lawfully obtained game client;
- keep testing local;
- prefer an isolated test machine/VM or dedicated test environment;
- do not expose the emulator ports directly to the public internet;
- do not use the project against any live game/service;
- back up files before replacing client configuration.

## 7. PvE runtime and map selection

The current stock-selected PvE path is integrated with v143b and uses:

```text
server/assaultfire_ds_spawner.py
tools/bridge/af_ds_udp_bridge_v9_multi_peer_latch.py
tools/server_spawner/AFDevLoader_v48_spawner_multi_instance.py
```

The intended flow is reserve-only at A10A, arm the bridge at A3A0/A113, then lazy-start AFDEV on the first valid DS UDP packet. The v5 bridge and v26 loader are retained only as legacy rollback/reference files.

See [PVE_RUNTIME.md](PVE_RUNTIME.md).

See:

- [FAQ](FAQ.md)
- [Getting Started](GETTING_STARTED.md)
- [Architecture](ARCHITECTURE.md)
- [Status](STATUS.md)
- [Milestones](MILESTONES.md)
