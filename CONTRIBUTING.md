# Contributing to Assault Fire Emulator

Thanks for helping with the project.

## What we want

Useful contributions include:

- protocol documentation
- packet decoders/encoders
- clean-room server implementation
- reproducible tests
- sanitized logs/fixtures
- bug fixes
- UE3/TDR research notes
- documentation improvements

## Before opening a pull request

1. Keep changes focused.
2. Explain what behavior you observed and how you verified it.
3. Remove secrets, account identifiers, IPs that should stay private, and unrelated personal data.
4. Do not include original game binaries or assets.
5. Do not paste large amounts of decompiled or disassembled proprietary code.
6. Prefer documenting behavior and data structures in your own words.
7. Add or update tests when practical.

## Protocol research reports

Please include:

- client version/build
- service or subsystem
- packet direction
- opcode/command
- sequence/correlation field if known
- packet size
- sanitized hex or decoded fields
- expected behavior
- observed behavior
- reproduction steps

## Client / launcher errors and compatibility fixes

Client-side problems are welcome when they are documented in a way other users can reproduce.

For a new error report, use the repository's **Client / launcher error** issue form. It asks for the exact popup, the last confirmed launch stage, sanitized server logs, client build, environment, and APClient status.

For a fix, the pull-request template now asks contributors to show the failure stage and evidence before/after the change. This is especially important for build-specific runtime compatibility work.

Use this stage order when describing the problem:

```text
client.exe / TCLS
  -> VERSION
  -> AP / AUTH
  -> DIR
  -> ROLE / TACC
  -> TCLS -> TGame handoff
  -> TGame startup
  -> TGame ROLE
  -> TGame ZONE
  -> gameplay state
```

Examples of useful evidence from current research include:

- `AP client initialization failed.` with VERSION traffic but no `[AUTH] Connected ...` — report as a local TCLS/APClient initialization failure, not as a proven server AUTH-packet bug;
- `Get Game Server Info fail!` — include DIR/selected-server evidence;
- `Get loginInfo fail!` — include AP completion, selected server state, and TCLS handoff evidence;
- `Network is disconnected:Connection Closed!` after TGame starts — include ROLE ownership/connection and early socket-close evidence;
- `0xC000071C STATUS_INVALID_THREAD` or other startup exit codes — include Windows build and exact TGame/TCLS hashes;
- datetime compatibility failures — include the validated TGame signature result from the helper;
- legacy security/driver warning tuples — record the exact tuple and text, but do not submit bypass instructions for active security systems.

For any client runtime patch or helper:

1. identify the exact client build;
2. prefer an RVA plus expected byte signature instead of an absolute VA;
3. refuse to patch when the signature does not match;
4. prefer runtime-only changes when practical;
5. restore temporary launcher changes after use;
6. never distribute patched `TCLS.dll`, `TGame.exe`, or other original game binaries;
7. document what stage the change fixes and what stage comes next.

If an error is not understood yet, mark the interpretation **unknown** or **likely** instead of assigning a guessed meaning. Add verified findings to [docs/LAUNCHER_ERRORS.md](docs/LAUNCHER_ERRORS.md) so future users can diagnose the same failure without repeating the research.

## Branches

- `main`: stable, reviewable code and documentation
- feature/research branches: experimental work

Avoid committing unstable experiments directly to `main`.

## Pull requests

A good PR description explains:

- what changed
- why it changed
- how it was tested
- any protocol assumptions that are still uncertain

## Legal / redistribution

Only submit material you have the right to contribute.

Do not commit proprietary game executables, DLLs, maps, packages, textures, audio, leaked source code, private keys, credentials, or other restricted material.
