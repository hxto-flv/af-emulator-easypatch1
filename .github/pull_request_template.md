## What does this fix?

Describe the exact client/launcher problem this PR addresses.

Example:

```text
Popup: AP client initialization failed.
Last good stage: VERSION TX
Next expected stage: [AUTH] Connected
```

## Failure stage

Mark the last stage that worked:

- [ ] No VERSION connection
- [ ] VERSION
- [ ] AUTH / AP
- [ ] DIR / server list
- [ ] ROLE / TACC
- [ ] TCLS -> TGame handoff
- [ ] TGame startup
- [ ] TGame ROLE
- [ ] TGame ZONE
- [ ] Gameplay / post-login
- [ ] Documentation-only / not applicable

## Evidence

Please include reproducible evidence, not only a guessed fix.

- Exact popup/log text:
- Client version/build:
- Server version/commit:
- Before behavior:
- After behavior:
- Sanitized relevant log:
- TGame/TCLS SHA-256 if build-specific:
- Runtime address/RVA and expected bytes if a compatibility patch is build-specific:

Do not upload original game binaries or DLLs.

## How was this tested?

Describe the exact test sequence and expected result.

For launcher fixes, useful checkpoints include:

```text
VERSION -> AUTH -> DIR -> ROLE/TACC -> TCLS handoff -> TGame ROLE -> ZONE
```

If your change claims to fix AP/AUTH, show whether `[AUTH] Connected ...` appears and whether the AP exchange actually completes.

## Client compatibility / patch safety

For changes involving client runtime compatibility:

- [ ] The target client build is identified.
- [ ] Any RVA/offset is paired with a byte signature or another reliable validation.
- [ ] The helper refuses to patch on a signature mismatch.
- [ ] The change is runtime-only where practical.
- [ ] This PR does not distribute a modified `TCLS.dll` or `TGame.exe`.
- [ ] This change is not an anti-cheat/security bypass intended for a live service.

## Tests and regression checks

- [ ] Existing tests pass.
- [ ] I added/updated a test where practical.
- [ ] I verified this does not break an earlier working stage.
- [ ] Documentation was updated if users need new setup/troubleshooting steps.

## Privacy / redistribution checklist

- [ ] No `PRIVATE.PEM`, passwords, access tokens, or personal player data.
- [ ] No proprietary executables, DLLs, maps, packages, audio, textures, or full memory dumps.
- [ ] Decompiled/disassembled third-party code is not copied verbatim in bulk.
- [ ] Logs/fixtures are sanitized.

## Remaining uncertainty

List anything that is still inferred or unverified. If none, write `None`.
