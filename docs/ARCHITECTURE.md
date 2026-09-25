# Architecture and Port Map

This page gives newcomers a quick mental model of the current stable local setup.

## Basic login path

```text
                    Windows hosts file
                          |
                          | old PH hostnames -> 127.0.0.1
                          v
+------------------ Assault Fire PH client ------------------+
|                                                           |
| TCLS / launcher                                           |
|   |                                                       |
|   +---- VERSION ------------------------------> :9060     |
|   |                                                       |
|   +---- AUTH ---------------------------------> :8000     |
|   |        RSA-1024 + DH + AES                           |
|   |                                                       |
|   +---- DIR ----------------------------------> :9010     |
|            discovers local role/zone endpoints            |
|                                                           |
| TCLS                                                      |
|   +---- GetLoginInfo / selected-server state              |
|   +---- CreateProcessW(TGame.exe -q <uin>)                |
|   +---- TCLS_SHAREDMEMEMORY<child PID> ----------------+  |
|                                                       |   |
| TGame.exe <-------------------------------------------+   |
|   |                                                       |
|   +---- ROLE ---------------------------------> :65005    |
|   |                                                       |
|   +---- ZONE ---------------------------------> :65006    |
+-----------------------------------------------------------+
                          |
                          v
               server/assaultfire_server_v143b.py
```

The client-side RSA public key and server-side private key must be a matching pair:

```text
TCLS\config\APClient.dat   <---- pair ---->   server\PRIVATE.PEM
       public key                                private key
```

## TCLS → TGame launch handoff

The launcher does more than spawn an executable. The verified PH build creates a shared-memory mapping named:

```text
TCLS_SHAREDMEMEMORY<decimal child PID>
```

and writes login/game-server handoff information for the new TGame process.

A validated runtime-only compatibility method can temporarily force `CREATE_SUSPENDED` at:

```text
TCLS.dll + 0x584E0
8B 55 18 52  ->  6A 04 90 90
```

Only use it when the original signature matches, and restore the original bytes immediately after TGame is created.

Full details: [Vital Launch Requirements](LAUNCH_REQUIREMENTS.md).

## Required TGame compatibility patch

The known PH TGame build can crash in a datetime conversion path.

Before launching the client, run:

```text
tools/patches/patch_tgame_datetime.py
```

The patch is runtime-only and verifies the known function signature before changing process memory.

Tracking: [Issue #3](https://github.com/armangido/af-emulator/issues/3).

## PvE dedicated-server path

The v143b server owns the room-to-DS lifecycle:

```text
TGame room / ZONE
      |
      | A10A reserve only
      | A11E room settings
      | A3A0/A113 start
      v
server/assaultfire_ds_spawner.py
      |
      | starts lightweight per-room bridge
      v
v9 multi-peer latch bridge :65008 + slot
      |
      | first valid client DS UDP triggers lazy spawn
      v
v48 AFDEV loader
      |
      | room-selected installed map / PVEGame.TGSVGame
      | native movement + zero-DSKey verification
      v
AFDEV / UE3 :7777 + slot
      |
      +-- SESSION_READY -> release first packet -> live relay
```

Files:

```text
tools/bridge/af_ds_udp_bridge_v9_multi_peer_latch.py
tools/server_spawner/AFDevLoader_v48_spawner_multi_instance.py
```

The older v5/v26 pair is retained as a historical rollback path.

## Port reference

| Port | Transport | Component | Notes |
|---:|---|---|---|
| 9060 | TCP | VERSION | Stable |
| 8000 | TCP | AUTH | Stable |
| 9010 | TCP | DIR | Stable |
| 65005 | TCP | ROLE | Stable baseline path |
| 65006 | TCP | ZONE | Stable baseline path |
| 65008 | UDP | PvE bridge | v9 per-room bridge entry used by the integrated PvE path |
| 7777 | UDP | AFDEV/UE3 | v48 AFDEV listen endpoint; additional slots increment per DS allocation |

## Source-of-truth rule

The project separates three levels of knowledge:

```text
VERIFIED
  observed in stock client / live test / recovered schema

PARTIAL
  useful implementation exists but complete retail behavior is not proven

EXPERIMENTAL
  research branch, inferred structure, or incomplete client verification
```

Only verified/reproducible behavior should be promoted into the stable public baseline.

See:

- [Project Status](STATUS.md)
- [Research Findings](RESEARCH_FINDINGS.md)
- [Milestones](MILESTONES.md)
- [FAQ](FAQ.md)
- [Getting Started](GETTING_STARTED.md)
