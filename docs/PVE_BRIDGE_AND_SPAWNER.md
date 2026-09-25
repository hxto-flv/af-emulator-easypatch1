# Stable PvE Bridge and Server Spawner

The current `main` branch carries the integrated local PvE handoff used by the stable **v143b** server. Supported installed PvE maps selected in the stock room UI flow through the same generic lazy DS path.

## Current components

```text
server/assaultfire_server_v143b.py
server/assaultfire_ds_spawner.py
tools/bridge/af_ds_udp_bridge_v9_multi_peer_latch.py
tools/server_spawner/AFDevLoader_v48_spawner_multi_instance.py
```

The repository does **not** redistribute `TGame_AFDEV.exe`, cooked maps, private keys, or runtime player/server state.

## Current lifecycle

```text
A10A CreateRoom
  -> reserve DS slot only
  -> do not start AFDEV

A11E SetGameSettings
  -> store ModeId / MapId / SubModeId / Flags for the room

A3A0 or A113 Start
  -> arm lightweight bridge
  -> return the A11A DS assignment

first valid client DS UDP
  -> v9 bridge latches the first packet
  -> start the room's v48 AFDEV loader

AFDEV ready
  -> load the room-selected map with PVEGame.TGSVGame
  -> enable the validated native movement/correction path
  -> apply the room map/settings
  -> verify the live zero DS key
  -> write SESSION_READY.json

bridge
  -> release the latched first packet
  -> wait for AFDEV's first reply
  -> normal multi-peer UE3 relay becomes live
```

This prevents the old behavior where merely creating a lobby could start a dedicated server.

## Multi-player lifetime

The DS spawner tracks room membership separately from active match membership.

- `A117 QuitMatch` removes only the sending player from the active match.
- A shared AFDEV instance remains alive while other match players remain.
- The final match player ends the round without destroying the logical room.
- `A107 LeaveRoom` removes room membership.
- Room ownership transfers to a remaining player when needed.
- The final room member releases the DS slot.
- A ZONE disconnect is handled per player instead of tearing down another player's session.

## Room map and difficulty/settings

`A10A` seeds the reserved DS allocation from the stock room selection. `A11E` is the authoritative pre-start settings update: its `MapString`, `MapId`, `SubModeId`/difficulty and flags replace the reservation snapshot before A113 starts the match. The loader resolves the selected map under the local cooked map tree. A PH-client Hard/Normal HUD label mismatch is tracked separately from the working authoritative room/AFDEV state.

## Configuration

Point `AF_GAME_DIR` to your own Assault Fire PH `Binaries\\Win32` directory (any drive/install location), then use the normal DS settings:

```powershell
$env:AF_GAME_DIR = "<full path to your Assault Fire PH Binaries\Win32 folder>"
$env:AF_DS_SPAWNER_ENABLED = "1"
$env:AF_DS_MAX_INSTANCES = "4"
.\.venv\Scripts\python.exe .\server\assaultfire_server_v143b.py
```

The default local slot layout uses public bridge ports beginning at UDP 65008 and AFDEV target ports beginning at UDP 7777. Keep these development listeners on a trusted/local network.

## Validation

The repository includes lifecycle/difficulty tests plus `tests/test_pve_map_selection.py` for stock-client map propagation invariants. Live Windows validation still depends on a lawfully supplied PH client and AFDEV executable.

## Legacy rollback files

These remain for historical comparison and rollback:

```text
server/assaultfire_server_v94.py
tools/bridge/af_ds_udp_bridge_v5_actor_dump.py
tools/server_spawner/AFDevLoader_v26_pve_natural_loading_completion.py
```

They are no longer the default PvE path.

See [PvE runtime and map selection](PVE_RUNTIME.md), [Project Status](STATUS.md), and [Architecture](ARCHITECTURE.md).
