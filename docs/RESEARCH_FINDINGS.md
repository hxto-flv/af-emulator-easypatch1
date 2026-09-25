# Verified Research Findings

This page collects reverse-engineering findings that are useful to preservation work but are too detailed for the project status page.

## Evidence labels

- **Verified** — observed in the validated PH build, recovered from shipped package/schema data, or exercised by the current working runtime.
- **Observed capture** — recorded from one accepted stock-client exchange; useful evidence, but not necessarily a universal constant.
- **Research lead** — a strong clue that still lacks enough protocol/runtime validation to be called implemented.

Unless stated otherwise, addresses and runtime details on this page are specific to the validated Assault Fire PH preservation build used by this repository.

## 1. Legacy PvE round-family finding: `PVEGame.TGSVGame`

**Status: Verified**

Static package/map analysis used by the current v48 loader found that a shipped PvE scripting package contains:

```text
PVEGame.TGSVSeqAct_ResetRound
```

and does not contain the investigated TGSV3 round-start/prepare/clear sequence-action instances.

The recovered `PVEGame.u` relationship for that reset path points to:

```text
PVEGame.TGSVGame
PVEGame.TGSVGameReplicationInfo
```

This established `PVEGame.TGSVGame` rather than `TGSVGame.TGSV3Game` as the validated game class used by the current generic PvE runtime.

This finding removed the need for the earlier experimental idea of reclassifying the live GRI or changing the spawned game type after map load.

Source implementation: `tools/server_spawner/AFDevLoader_v48_spawner_multi_instance.py`.

## 2. The working AFDEV process is a true server process

**Status: Verified**

The current v48 loader validates the process-level Unreal globals before declaring the AFDEV runtime usable:

```text
GIsClient = 0
GIsServer = 1
GIsEditor = 0
```

If the process does not enter this state, the loader treats that as a startup failure instead of continuing with a client/listen-hybrid configuration.

This matters because earlier experiments could load farther while still being in the wrong process mode, producing misleading PvE loading and movement behavior.

Source implementation: `tools/server_spawner/AFDevLoader_v48_spawner_multi_instance.py`.

## 3. Multiple AFDEV instances need unique TGame mutex identities

**Status: Verified**

The validated PH image has a normal single-instance path around `CreateMutexW`.

Recovered static details:

```text
call-site area : 0x01349D75
mutex string   : 0x01D12F98
GetLastError() : 183 -> multiple-running-instances path
```

The original mutex name is:

```text
TGAME_{D21F20CD-996C-4ae2-8BF8-F2A7B4CD20D5}
```

For AFDEV server processes, the v48 loader derives a deterministic per-instance `TGAME_{...}` mutex name using UUID5 and the DS `instance_id`. This lets multiple local AFDEV server processes coexist while preserving separate process identities.

Source implementation: `tools/server_spawner/AFDevLoader_v48_spawner_multi_instance.py`.

## 4. GEO protocol commands used before the ZONE handoff

**Status: Verified**

The recovered C2GEO/GEO2C command family used by the local TGame path is:

| Direction | Command | ID |
|---|---|---:|
| C2GEO | `REQ_ZONELIST` | `0x1000` |
| GEO2C | `RES_ZONELIST` | `0x2000` |
| C2GEO | `REQ_PINGLIST` | `0x1001` |
| GEO2C | `RES_PINGLIST` | `0x2001` |

The GEO packet magic is `0x8202`.

The recovered `C2GEOPkgHead` is four big-endian `u16` fields:

```text
Magic
Cmd
HeadLen
BodyLen
```

These messages sit in the TGame login path immediately before or around selection of the local ZONE endpoint.

Source implementation: `server/assaultfire_server_v94.py` (protocol foundation inherited by the stable line).

## 5. One accepted stock A10A room-creation capture

**Status: Observed capture**

An accepted PH client room-creation capture recorded on 2026-09-19 contained:

```text
ModeId    = 0x00002001
MapId     = 0x002F
SubModeId = 0x00001001
Flags     = 0x00003008
MapString = empty in this particular A10A request
```

These values are a known accepted reference, not universal constants for every room or map.

The current implementation preserves the stock room fields and allows the later A11E `SetGameSettings` update to replace the map/settings snapshot before lazy AFDEV startup. A later stock `MapString` can therefore become the actual map launched by v48.

Source implementation/comments: `server/assaultfire_server_v94.py`, `server/assaultfire_server_v143b.py`, and `server/assaultfire_ds_spawner.py`.

## 6. Tutorial completion has a recovered client request entry, but rewards are not solved

**Status: Research lead**

The recovered `UTGame.u` online-request catalog contains:

```text
TGOnlineClient.OnlineRequest_NotifyFinishNewGuidTask(Byte nTaskMode)
export index: 43269
```

This is a strong lead for the tutorial/basic-controls completion path and may explain why simply finishing the playable tutorial is not sufficient for rewards in the current emulator.

What is **not** yet verified:

- the numeric network command used by this request;
- the exact request/response wire structure;
- whether it gates starter rewards, progression, or another tutorial state;
- the stock client's expected completion acknowledgement.

Tutorial rewards therefore remain **unsolved** in the public baseline. This entry is a research target, not an implemented feature.

Source catalog: `V139_UTGAME_REQUEST_CATALOG` in `server/assaultfire_server_v143b.py`.

## Publication rule

Future additions should preserve the distinction between verified behavior, single captures, and research leads. A promising symbol or export name by itself is not enough to mark a feature as working.
