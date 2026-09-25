#!/usr/bin/env python3
"""Assault Fire PH dedicated-server allocator - r10 multiplayer-safe lazy AFDEV lifecycle.

Lifecycle:
    A10A                 -> reserve_lobby()   (NO processes)
    A3A0/A113 handoff    -> arm_lobby()       (bridge only)
    first valid DS UDP   -> bridge spawns v48 AFDEV loader
    SESSION_READY        -> bridge sends ONLY latched first packet; first AFDEV reply -> live relay
    player A117/leave   -> remove only that player from match/room tracking
    last match player    -> bridge + loader + AFDEV are terminated; room survives as ROUND_ENDED
    last room player     -> full room release

The bridge is deliberately the only component allowed to trigger TGame_AFDEV.exe.
"""
from __future__ import annotations

import atexit
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
from typing import Dict, Optional


class SpawnerError(RuntimeError):
    pass


class DSCapacityError(SpawnerError):
    pass


class DSStartupError(SpawnerError):
    pass


@dataclass
class SpawnerConfig:
    enabled: bool = True
    max_instances: int = 4
    public_host: str = "127.0.0.1"
    public_port_base: int = 65008
    target_host: str = "127.0.0.1"
    target_port_base: int = 7777
    game_dir: str = r"D:\AssaultFirePH\Binaries\Win32"
    default_map: str = "SV-Maya_3_Main"
    game_class: str = "PVEGame.TGSVGame"
    ready_timeout: float = 90.0
    bridge_ready_timeout: float = 3.0
    create_cooldown: float = 1.5
    buffer_max_packets: int = 256
    buffer_max_bytes: int = 512 * 1024
    buffer_max_age: float = 45.0
    runtime_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parents[1] / "runtime" / "ds_runtime")
    loader_script: Path = field(default_factory=lambda: Path(__file__).resolve().parents[1] / "tools" / "server_spawner" / "AFDevLoader_v48_spawner_multi_instance.py")
    bridge_script: Path = field(default_factory=lambda: Path(__file__).resolve().parents[1] / "tools" / "bridge" / "af_ds_udp_bridge_v9_multi_peer_latch.py")
    python_exe: str = sys.executable

    @classmethod
    def from_env(cls) -> "SpawnerConfig":
        here = Path(__file__).resolve().parent
        repo_root = here.parent

        def env_bool(name: str, default: bool) -> bool:
            raw = os.environ.get(name)
            if raw is None:
                return default
            return raw.strip().lower() not in ("0", "false", "off", "no")

        def resolve_game_dir() -> str:
            raw = os.environ.get("AF_GAME_DIR")
            if raw and os.path.isdir(raw):
                return raw
            candidates = [
                r"C:\Users\Administrator\Desktop\af\Assault Fire 1.0.0.24\Binaries\Win32",
                r"D:\AssaultFirePH\Binaries\Win32",
                r".\game\Binaries\Win32",
            ]
            for c in candidates:
                if os.path.isdir(c):
                    return c
            return raw or r"D:\AssaultFirePH\Binaries\Win32"

        return cls(
            enabled=env_bool("AF_DS_SPAWNER_ENABLED", True),
            max_instances=max(1, int(os.environ.get("AF_DS_MAX_INSTANCES", "4"))),
            public_host=os.environ.get("AF_DS_PUBLIC_HOST", "127.0.0.1"),
            public_port_base=int(os.environ.get("AF_DS_PUBLIC_PORT_BASE", "65008")),
            target_host=os.environ.get("AF_DS_TARGET_HOST", "127.0.0.1"),
            target_port_base=int(os.environ.get("AF_DS_TARGET_PORT_BASE", "7777")),
            game_dir=resolve_game_dir(),
            default_map=os.environ.get("AF_DS_DEFAULT_MAP", "SV-Maya_3_Main"),
            game_class=os.environ.get("AF_DS_GAME_CLASS", "PVEGame.TGSVGame"),
            ready_timeout=max(5.0, float(os.environ.get("AF_DS_READY_TIMEOUT", "90"))),
            bridge_ready_timeout=max(0.25, float(os.environ.get("AF_DS_BRIDGE_READY_TIMEOUT", "3"))),
            create_cooldown=max(0.0, float(os.environ.get("AF_DS_CREATE_COOLDOWN", "1.5"))),
            buffer_max_packets=max(8, int(os.environ.get("AF_DS_BUFFER_MAX_PACKETS", "256"))),
            buffer_max_bytes=max(16 * 1024, int(os.environ.get("AF_DS_BUFFER_MAX_BYTES", str(512 * 1024)))),
            buffer_max_age=max(5.0, float(os.environ.get("AF_DS_BUFFER_MAX_AGE", "45"))),
            runtime_dir=Path(os.environ.get("AF_DS_RUNTIME_DIR", str(repo_root / "runtime" / "ds_runtime"))).resolve(),
            loader_script=Path(os.environ.get("AF_DS_LOADER", str(repo_root / "tools" / "server_spawner" / "AFDevLoader_v48_spawner_multi_instance.py"))).resolve(),
            bridge_script=Path(os.environ.get("AF_DS_BRIDGE", str(repo_root / "tools" / "bridge" / "af_ds_udp_bridge_v9_multi_peer_latch.py"))).resolve(),
            python_exe=os.environ.get("AF_DS_PYTHON", sys.executable),
        )


@dataclass
class DSAllocation:
    slot: int
    public_host: str
    public_port: int
    target_host: str
    target_port: int
    map_name: str
    max_players: int
    instance_id: str
    room_id: int
    owner_id: int
    mode_id: int = 0x00002001
    map_id: int = 0x002F
    sub_mode_id: int = 0x00001001
    room_flags: int = 0x00003008
    state: str = "RESERVED"  # RESERVED -> ARMED -> STARTING -> AFDEV_READY -> READY/FAILED -> RELEASED
    reserved_at: float = field(default_factory=time.time)
    armed_at: Optional[float] = None
    started_at: Optional[float] = None
    ready_at: Optional[float] = None
    last_error: Optional[str] = None
    bridge_pid: Optional[int] = None
    loader_pid: Optional[int] = None
    afdev_pid: Optional[int] = None
    trigger_client: Optional[str] = None
    buffered_packets: int = 0
    buffered_bytes: int = 0
    suppressed_startup_packets: int = 0
    replay_attempts: int = 0
    peer_count: int = 0
    live_peer_count: int = 0
    room_players: set[int] = field(default_factory=set)
    match_players: set[int] = field(default_factory=set)
    round_generation: int = 0

    bridge_proc: Optional[subprocess.Popen] = field(default=None, repr=False, compare=False)
    bridge_log_handle: object = field(default=None, repr=False, compare=False)

    def public_endpoint(self):
        return self.public_host, self.public_port


class DedicatedServerSpawner:
    def __init__(self, config: Optional[SpawnerConfig] = None, log_fn=None):
        self.config = config or SpawnerConfig.from_env()
        self._log_fn = log_fn
        self._lock = threading.RLock()
        self._allocations: Dict[int, DSAllocation] = {}
        self._owner_to_room: Dict[int, int] = {}
        self._last_create: Dict[int, float] = {}
        self._next_room_id = 1
        self._shutdown = False
        self.config.runtime_dir.mkdir(parents=True, exist_ok=True)
        atexit.register(self.shutdown_all)

    def _emit(self, label: str, message: str) -> None:
        if self._log_fn:
            try:
                self._log_fn(label, message)
                return
            except Exception:
                pass
        print(f"[{label}] {message}", flush=True)

    def _log(self, message: str) -> None:
        self._emit("DS-SPAWNER", message)

    @staticmethod
    def _udp_port_available(host: str, port: int) -> bool:
        bind_host = "0.0.0.0" if host in ("", "0.0.0.0") else host
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind((bind_host, int(port)))
            return True
        except OSError:
            return False
        finally:
            try:
                s.close()
            except Exception:
                pass

    def _slot_ports_free(self, slot: int) -> bool:
        return (
            self._udp_port_available("0.0.0.0", self.config.public_port_base + slot)
            and self._udp_port_available(self.config.target_host, self.config.target_port_base + slot)
        )

    def _choose_slot_locked(self) -> int:
        occupied = {
            a.slot for a in self._allocations.values()
            if a.state not in ("RELEASED", "ROUND_ENDED")
        }
        for slot in range(self.config.max_instances):
            if slot in occupied:
                continue
            if self._slot_ports_free(slot):
                return slot
            self._log(
                f"slot={slot} skipped because UDP {self.config.public_port_base + slot} "
                f"or {self.config.target_port_base + slot} is already in use"
            )
        raise DSCapacityError(f"no free DS slot (max_instances={self.config.max_instances})")

    # r10 intentionally has no standby/warm pool. Keep this API as a harmless
    # compatibility no-op so an old launcher/environment cannot accidentally
    # make AFDEV start at backend boot.
    def start_warm_pool(self) -> None:
        self._log("r10 lazy-latch mode: warm pool disabled; AFDEV=OFF until first valid bridge UDP packet")

    def reserve_lobby(
        self, *, owner_id: int, map_name: Optional[str] = None, max_players: int = 4,
        mode_id: int = 0x00002001, map_id: int = 0x002F,
        sub_mode_id: int = 0x00001001, room_flags: int = 0x00003008,
    ) -> DSAllocation:
        owner_id = int(owner_id)
        now = time.time()
        with self._lock:
            existing_room = self._owner_to_room.get(owner_id)
            if existing_room is not None:
                existing = self._allocations.get(existing_room)
                if existing and existing.state != "RELEASED":
                    self._log(
                        f"idempotent reserve owner={owner_id} -> existing room={existing.room_id} "
                        f"slot={existing.slot} state={existing.state}"
                    )
                    return existing

            last = self._last_create.get(owner_id)
            if last is not None and now - last < self.config.create_cooldown:
                raise DSCapacityError(
                    f"lobby-create cooldown active for owner={owner_id} "
                    f"({now - last:.2f}s < {self.config.create_cooldown:.2f}s)"
                )

            slot = self._choose_slot_locked()
            room_id = self._next_room_id
            self._next_room_id += 1
            desired_map = (map_name or self.config.default_map).strip() or self.config.default_map
            allocation = DSAllocation(
                slot=slot,
                public_host=self.config.public_host,
                public_port=self.config.public_port_base + slot,
                target_host=self.config.target_host,
                target_port=self.config.target_port_base + slot,
                map_name=desired_map,
                max_players=max(2, int(max_players)),
                instance_id=f"room-{room_id}-slot-{slot}",
                room_id=room_id,
                owner_id=owner_id,
                mode_id=int(mode_id) & 0xFFFFFFFF,
                map_id=int(map_id) & 0xFFFF,
                sub_mode_id=int(sub_mode_id) & 0xFFFFFFFF,
                room_flags=int(room_flags) & 0xFFFFFFFF,
                state="RESERVED",
                room_players={owner_id},
                match_players=set(),
            )
            self._allocations[room_id] = allocation
            self._owner_to_room[owner_id] = room_id
            self._last_create[owner_id] = now
            self._write_snapshot_locked()
            self._log(
                f"reserved room={room_id} owner={owner_id} slot={slot} "
                f"public={allocation.public_host}:{allocation.public_port} "
                f"afdev={allocation.target_host}:{allocation.target_port} map={allocation.map_name!r} "
                f"mode=0x{allocation.mode_id:08x} map_id=0x{allocation.map_id:04x} "
                f"submode=0x{allocation.sub_mode_id:08x} flags=0x{allocation.room_flags:08x}; "
                "AFDEV=OFF bridge=OFF"
            )
            return allocation

    def allocation_for_room(self, room_id: int) -> Optional[DSAllocation]:
        with self._lock:
            return self._allocations.get(int(room_id))

    def allocation_for_owner(self, owner_id: int) -> Optional[DSAllocation]:
        with self._lock:
            rid = self._owner_to_room.get(int(owner_id))
            return self._allocations.get(rid) if rid is not None else None

    def prepare_lobby_settings_update(self, room_id: int, requester_uin: int) -> DSAllocation:
        """Make A11E safe when the client has returned to the room UI.

        A live A11E cannot belong to an actively playing client: it is emitted by
        the room-settings UI.  If our lifecycle is still READY/AFDEV_READY for a
        solo room, treat that as a stale previous round, tear it down first, and
        leave the logical lobby in ROUND_ENDED so the new settings can be applied
        and A113 can allocate a fresh AFDEV instance.

        For multiplayer, never kill a shared DS while another player remains in
        match.  In that case reject the settings update and keep the active round.
        """
        room_id = int(room_id)
        requester_uin = int(requester_uin)
        should_end = False
        with self._lock:
            allocation = self._allocations.get(room_id)
            if allocation is None:
                raise SpawnerError(f"unknown room {room_id}")
            if allocation.state in ("READY", "AFDEV_READY"):
                other_match_players = set(allocation.match_players) - {requester_uin}
                if other_match_players:
                    raise SpawnerError(
                        f"cannot change room {room_id} settings while other match players are active: "
                        f"{sorted(other_match_players)}"
                    )
                should_end = True
            elif allocation.state in ("ARMED", "STARTING"):
                raise SpawnerError(
                    f"cannot change room {room_id} settings while DS startup is in progress "
                    f"(state={allocation.state})"
                )
            elif allocation.state == "FAILED":
                # A failed heavy round must be torn down before reuse.  Preserve the
                # logical lobby and transition it to ROUND_ENDED.
                should_end = True
            elif allocation.state == "RELEASED":
                raise SpawnerError(f"room {room_id} has been released")

        if should_end:
            self._log(
                f"A11E room-settings UI detected stale/finished round room={room_id} "
                f"requester={requester_uin}; tearing down old DS before settings update"
            )
            self.end_round(room_id, reason="A11E settings change / returned to room UI")

        current = self.allocation_for_room(room_id)
        if current is None:
            raise SpawnerError(f"unknown room {room_id}")
        return current

    def update_lobby_settings(
        self, room_id: int, *, mode_id: int, map_id: int,
        sub_mode_id: int, room_flags: int, map_name: Optional[str] = None,
    ) -> DSAllocation:
        """Update settings for a reserved logical room before AFDEV starts.

        The retail PH client creates the room with A10A, then can change its
        selected PVE map/settings with A11E before A113 StartMatch. The latest
        A11E settings must therefore replace the A10A snapshot that will be
        passed to the lazy AFDEV loader.
        """
        room_id = int(room_id)
        with self._lock:
            allocation = self._allocations.get(room_id)
            if allocation is None:
                raise SpawnerError(f"unknown room {room_id}")
            if allocation.state not in ("RESERVED", "ROUND_ENDED"):
                raise SpawnerError(
                    f"cannot change room {room_id} settings while state={allocation.state}"
                )
            desired_map = str(map_name or "").strip()
            if desired_map:
                allocation.map_name = desired_map
            allocation.mode_id = int(mode_id) & 0xFFFFFFFF
            allocation.map_id = int(map_id) & 0xFFFF
            allocation.sub_mode_id = int(sub_mode_id) & 0xFFFFFFFF
            allocation.room_flags = int(room_flags) & 0xFFFFFFFF
            self._write_snapshot_locked()
            self._log(
                f"settings updated room={room_id} state={allocation.state} "
                f"map_name={allocation.map_name!r} "
                f"mode=0x{allocation.mode_id:08x} map_id=0x{allocation.map_id:04x} "
                f"submode=0x{allocation.sub_mode_id:08x} flags=0x{allocation.room_flags:08x}"
            )
            return allocation

    def status(self):
        with self._lock:
            return [self._room_dict(a) for a in sorted(self._allocations.values(), key=lambda x: x.room_id)]

    def standby_status(self):
        return []

    def _instance_paths(self, allocation: DSAllocation):
        inst_dir = self.config.runtime_dir / allocation.instance_id
        return {
            "dir": inst_dir,
            "bridge_log": inst_dir / "bridge.log",
            "loader_log": inst_dir / "loader.log",
            "actor_log": inst_dir / "actor_payloads.log",
            "state_file": inst_dir / "BRIDGE_STATE.json",
            "ready_file": inst_dir / "SESSION_READY.json",
            "pid_file": inst_dir / "AFDEV_PID.txt",
            "loader_pid_file": inst_dir / "LOADER_PID.txt",
        }

    @staticmethod
    def _read_json(path: Path) -> dict:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    @staticmethod
    def _tail_file(path: Path, max_lines: int = 12, max_chars: int = 2600) -> str:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return ""
        tail = " | ".join(x.strip() for x in text.splitlines()[-max_lines:] if x.strip())
        return tail[-max_chars:] if len(tail) > max_chars else tail

    def arm_lobby(self, room_id: int) -> DSAllocation:
        """Start only the lightweight UDP bridge and wait until it is bound.

        This function NEVER starts AFDEV. The bridge receives the first valid
        client DS datagram and only then launches AFDevLoader_v48.
        """
        room_id = int(room_id)
        with self._lock:
            allocation = self._allocations.get(room_id)
            if allocation is None:
                raise SpawnerError(f"unknown room {room_id}")
            if allocation.state == "RELEASED":
                raise SpawnerError(f"room {room_id} has been fully released")
            if allocation.state == "ROUND_ENDED":
                # r10: a completed/abandoned round frees the heavy DS processes but
                # preserves the lobby.  A later A113 reuses only the logical room
                # membership and receives a fresh slot/process set.
                old = allocation
                slot = self._choose_slot_locked()
                allocation = DSAllocation(
                    slot=slot,
                    public_host=self.config.public_host,
                    public_port=self.config.public_port_base + slot,
                    target_host=self.config.target_host,
                    target_port=self.config.target_port_base + slot,
                    map_name=old.map_name,
                    max_players=old.max_players,
                    instance_id=f"room-{room_id}-slot-{slot}-round-{old.round_generation + 1}-{int(time.time() * 1000)}",
                    room_id=room_id,
                    owner_id=old.owner_id,
                    mode_id=old.mode_id,
                    map_id=old.map_id,
                    sub_mode_id=old.sub_mode_id,
                    room_flags=old.room_flags,
                    state="RESERVED",
                    room_players=set(old.room_players),
                    match_players=set(old.match_players),
                    round_generation=old.round_generation + 1,
                )
                self._allocations[room_id] = allocation
                self._owner_to_room[int(allocation.owner_id)] = room_id
                self._write_snapshot_locked()
                self._log(
                    f"re-armed ROUND_ENDED room={room_id} owner={allocation.owner_id} "
                    f"players={sorted(allocation.room_players)} match_players={sorted(allocation.match_players)} "
                    f"with fresh slot={slot} public={allocation.public_host}:{allocation.public_port} "
                    f"afdev={allocation.target_host}:{allocation.target_port}"
                )
            if allocation.state in ("ARMED", "STARTING", "READY") and allocation.bridge_proc is not None:
                return allocation
            if allocation.state == "FAILED":
                raise DSStartupError(allocation.last_error or "bridge/AFDEV startup failed")
            if not self.config.bridge_script.is_file():
                raise DSStartupError(f"missing bridge: {self.config.bridge_script}")
            if not self.config.loader_script.is_file():
                raise DSStartupError(f"missing loader: {self.config.loader_script}")

            p = self._instance_paths(allocation)
            p["dir"].mkdir(parents=True, exist_ok=True)
            for key in ("state_file", "ready_file", "pid_file", "loader_pid_file"):
                try:
                    p[key].unlink()
                except FileNotFoundError:
                    pass

            allocation.bridge_log_handle = p["bridge_log"].open("a", encoding="utf-8", buffering=1)
            child_env = os.environ.copy()
            child_env.setdefault("PYTHONUTF8", "1")
            child_env["PYTHONIOENCODING"] = "utf-8:backslashreplace"
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

            cmd = [
                self.config.python_exe, str(self.config.bridge_script),
                "--listen-ip", "0.0.0.0",
                "--listen-port", str(allocation.public_port),
                "--target-host", allocation.target_host,
                "--target-port", str(allocation.target_port),
                "--actor-dump", str(p["actor_log"]),
                "--lazy-spawn",
                "--python-exe", self.config.python_exe,
                "--loader-script", str(self.config.loader_script),
                "--game-dir", self.config.game_dir,
                "--map", allocation.map_name,
                "--game", self.config.game_class,
                "--max-players", str(allocation.max_players),
                "--mode-id", str(allocation.mode_id),
                "--map-id", str(allocation.map_id),
                "--sub-mode-id", str(allocation.sub_mode_id),
                "--room-flags", str(allocation.room_flags),
                "--instance-id", allocation.instance_id,
                "--pid-file", str(p["pid_file"]),
                "--ready-file", str(p["ready_file"]),
                "--loader-pid-file", str(p["loader_pid_file"]),
                "--loader-log", str(p["loader_log"]),
                "--state-file", str(p["state_file"]),
                "--startup-timeout", str(self.config.ready_timeout),
                "--buffer-max-packets", str(self.config.buffer_max_packets),
                "--buffer-max-bytes", str(self.config.buffer_max_bytes),
                "--buffer-max-age", str(self.config.buffer_max_age),
            ]
            allocation.bridge_proc = subprocess.Popen(
                cmd,
                cwd=str(self.config.bridge_script.parent),
                stdout=allocation.bridge_log_handle,
                stderr=subprocess.STDOUT,
                creationflags=creationflags,
                env=child_env,
            )
            allocation.bridge_pid = allocation.bridge_proc.pid
            allocation.armed_at = time.time()
            allocation.state = "ARMED"
            allocation.last_error = None
            self._write_snapshot_locked()

        # A11A must not race the bridge bind. Wait only for the tiny bridge,
        # never for AFDEV/SESSION_READY.
        deadline = time.time() + self.config.bridge_ready_timeout
        while time.time() < deadline:
            if allocation.bridge_proc is not None and allocation.bridge_proc.poll() is not None:
                detail = self._tail_file(p["bridge_log"])
                with self._lock:
                    allocation.state = "FAILED"
                    allocation.last_error = f"bridge exited rc={allocation.bridge_proc.returncode}" + (f"; log_tail={detail}" if detail else "")
                    self._write_snapshot_locked()
                raise DSStartupError(allocation.last_error)
            payload = self._read_json(p["state_file"])
            if payload.get("state") == "LISTENING":
                self._log(
                    f"armed room={allocation.room_id} slot={allocation.slot} bridge={allocation.public_host}:{allocation.public_port} "
                    f"AFDEV=OFF; first valid DS UDP packet will spawn v48 on {allocation.target_host}:{allocation.target_port}"
                )
                threading.Thread(
                    target=self._monitor_bridge,
                    args=(allocation,),
                    name=f"AF-DS-monitor-room-{allocation.room_id}",
                    daemon=True,
                ).start()
                return allocation
            time.sleep(0.02)

        detail = self._tail_file(p["bridge_log"])
        with self._lock:
            allocation.state = "FAILED"
            allocation.last_error = f"bridge did not reach LISTENING in {self.config.bridge_ready_timeout:.2f}s" + (f"; log_tail={detail}" if detail else "")
            self._write_snapshot_locked()
        self._stop_allocation(allocation)
        raise DSStartupError(allocation.last_error)

    # Compatibility alias: in r10 'prewarm' means bridge-arm only and never
    # starts AFDEV. The stable server no longer calls it from A10A.
    def prewarm(self, room_id: int) -> None:
        self.arm_lobby(room_id)

    def _monitor_bridge(self, allocation: DSAllocation) -> None:
        paths = self._instance_paths(allocation)
        last_state = None
        while True:
            with self._lock:
                current = self._allocations.get(allocation.room_id)
                if current is not allocation or allocation.state == "RELEASED" or self._shutdown:
                    return
                proc = allocation.bridge_proc
            if proc is not None and proc.poll() is not None:
                detail = self._tail_file(paths["bridge_log"])
                with self._lock:
                    if allocation.state != "RELEASED":
                        allocation.state = "FAILED"
                        allocation.last_error = f"bridge exited rc={proc.returncode}" + (f"; log_tail={detail}" if detail else "")
                        self._write_snapshot_locked()
                self._log(f"room={allocation.room_id} bridge FAILED: {allocation.last_error}")
                return

            payload = self._read_json(paths["state_file"])
            state = str(payload.get("state") or "")
            if state:
                with self._lock:
                    allocation.loader_pid = int(payload.get("loader_pid") or 0) or allocation.loader_pid
                    allocation.afdev_pid = int(payload.get("afdev_pid") or 0) or allocation.afdev_pid
                    allocation.trigger_client = payload.get("trigger_client") or allocation.trigger_client
                    allocation.buffered_packets = int(payload.get("buffered_packets") or 0)
                    allocation.buffered_bytes = int(payload.get("buffered_bytes") or 0)
                    allocation.suppressed_startup_packets = int(payload.get("suppressed_startup_packets") or 0)
                    allocation.replay_attempts = int(payload.get("replay_attempts") or 0)
                    allocation.peer_count = int(payload.get("peer_count") or allocation.peer_count or 0)
                    allocation.live_peer_count = int(payload.get("live_peer_count") or 0)
                    if state == "SPAWNING":
                        if allocation.state != "STARTING":
                            allocation.state = "STARTING"
                            allocation.started_at = float(payload.get("spawned_at") or time.time())
                    elif state == "AFDEV_READY":
                        allocation.state = "AFDEV_READY"
                    elif state == "READY":
                        allocation.state = "READY"
                        allocation.ready_at = float(payload.get("ready_at") or time.time())
                    elif state == "FAILED":
                        allocation.state = "FAILED"
                        allocation.last_error = str(payload.get("error") or "bridge lazy AFDEV startup failed")
                    self._write_snapshot_locked()

                if state != last_state:
                    if state == "SPAWNING":
                        self._log(
                            f"room={allocation.room_id} slot={allocation.slot} first valid DS UDP from {allocation.trigger_client} "
                            f"-> AFDEV STARTING loader_pid={allocation.loader_pid}; buffered={allocation.buffered_packets}"
                        )
                    elif state == "AFDEV_READY":
                        self._log(
                            f"SESSION_READY room={allocation.room_id} slot={allocation.slot} "
                            f"AFDEV={allocation.target_host}:{allocation.target_port} pid={allocation.afdev_pid}; "
                            f"zero_dskey={'VERIFIED' if payload.get('zero_dskey') else 'MISSING'} "
                            f"socket=0x{int(payload.get('zero_dskey_socket') or 0):08X}; "
                            f"difficulty={payload.get('pve_difficulty_name') or '?'} "
                            f"submode=0x{int(payload.get('sub_mode_id') or allocation.sub_mode_id):08X} "
                            f"flags=0x{int(payload.get('room_flags') or allocation.room_flags):08X}; "
                            "first packet latched/sent; waiting for first AFDEV UDP reply"
                        )
                    elif state == "READY":
                        self._log(
                            f"RELAY LIVE room={allocation.room_id} slot={allocation.slot} "
                            f"AFDEV={allocation.target_host}:{allocation.target_port} pid={allocation.afdev_pid}; "
                            f"first AFDEV reply observed retries={allocation.replay_attempts} "
                            f"suppressed_startup={allocation.suppressed_startup_packets} "
                            f"peers={allocation.peer_count} live_peers={allocation.live_peer_count}"
                        )
                    elif state == "FAILED":
                        detail = str(allocation.last_error or "lazy AFDEV startup failed")
                        # r16 diagnostics: if an older bridge or an early bridge
                        # failure did not embed loader_log_tail, surface it here.
                        if "loader_log_tail=" not in detail:
                            try:
                                lp = self._instance_paths(allocation)["loader_log"]
                                if lp.is_file():
                                    lines = lp.read_text(encoding="utf-8", errors="replace").splitlines()
                                    tail = " | ".join(x.strip() for x in lines[-18:] if x.strip())
                                    if tail:
                                        detail += "; loader_log_tail=" + tail[-4000:]
                            except Exception:
                                pass
                        allocation.last_error = detail
                        self._log(f"room={allocation.room_id} lazy AFDEV FAILED: {detail}")
                        return
                    last_state = state
            time.sleep(0.10)

    def register_room_player(self, room_id: int, uin: int) -> dict:
        room_id = int(room_id); uin = int(uin)
        with self._lock:
            a = self._allocations.get(room_id)
            if a is None or a.state == "RELEASED":
                raise SpawnerError(f"unknown/released room {room_id}")
            a.room_players.add(uin)
            self._write_snapshot_locked()
            result = {
                "room_id": room_id,
                "uin": uin,
                "room_players": sorted(a.room_players),
                "match_players": sorted(a.match_players),
                "owner_id": a.owner_id,
            }
        self._log(
            f"room-player join room={room_id} uin={uin} room_players={result['room_players']}"
        )
        return result

    def begin_match(self, room_id: int, starter_uin: Optional[int] = None) -> dict:
        """Mark players belonging to this lobby as active in the current DS round.

        First start of a round seeds the in-match set from all known room members.
        A later start/rejoin while the DS is already active only adds the requester.
        """
        room_id = int(room_id)
        starter = None if starter_uin is None else int(starter_uin)
        with self._lock:
            a = self._allocations.get(room_id)
            if a is None or a.state == "RELEASED":
                raise SpawnerError(f"unknown/released room {room_id}")
            if starter is not None:
                a.room_players.add(starter)
            new_round = a.state in ("RESERVED", "ROUND_ENDED") or not a.match_players
            if new_round:
                a.match_players = set(a.room_players)
            elif starter is not None:
                a.match_players.add(starter)
            self._write_snapshot_locked()
            result = {
                "room_id": room_id,
                "starter_uin": starter,
                "new_round": bool(new_round),
                "room_players": sorted(a.room_players),
                "match_players": sorted(a.match_players),
                "remaining_match_players": len(a.match_players),
                "state": a.state,
            }
        self._log(
            f"match-player begin room={room_id} starter={starter or 0} "
            f"new_round={result['new_round']} active={result['match_players']}"
        )
        return result

    def mark_player_in_match(self, room_id: int, uin: int) -> dict:
        room_id = int(room_id); uin = int(uin)
        with self._lock:
            a = self._allocations.get(room_id)
            if a is None or a.state == "RELEASED":
                raise SpawnerError(f"unknown/released room {room_id}")
            a.room_players.add(uin)
            a.match_players.add(uin)
            self._write_snapshot_locked()
            result = {
                "room_id": room_id,
                "uin": uin,
                "match_players": sorted(a.match_players),
                "remaining_match_players": len(a.match_players),
            }
        self._log(
            f"match-player in room={room_id} uin={uin} active={result['match_players']}"
        )
        return result

    def end_round(self, room_id: int, reason: str = "last match player left") -> bool:
        """Stop this room's DS processes without deleting the lobby membership."""
        room_id = int(room_id)
        with self._lock:
            a = self._allocations.get(room_id)
            if a is None or a.state == "RELEASED":
                return False
            if a.state == "ROUND_ENDED":
                return True
            a.state = "ROUND_ENDED"
            a.last_error = reason
            a.match_players.clear()
            self._write_snapshot_locked()
        self._log(
            f"round ended room={room_id} owner={a.owner_id} slot={a.slot}: {reason}; "
            f"lobby_players={sorted(a.room_players)}"
        )
        self._stop_allocation(a)
        return True

    def quit_match_player(self, room_id: int, uin: int, reason: str = "A117 QuitMatch") -> dict:
        """Remove one player from the running match; stop DS only when the last player leaves."""
        room_id = int(room_id); uin = int(uin)
        should_end = False
        with self._lock:
            a = self._allocations.get(room_id)
            if a is None or a.state == "RELEASED":
                return {"room_id": room_id, "uin": uin, "found": False, "remaining_match_players": 0, "ended_round": False}
            was_active = uin in a.match_players
            a.match_players.discard(uin)
            remaining = len(a.match_players)
            # Only an allocation that has actually entered/armed a round should be
            # converted to ROUND_ENDED. Duplicate A117 after cleanup is harmless.
            should_end = remaining == 0 and a.state not in ("RESERVED", "ROUND_ENDED")
            self._write_snapshot_locked()
            result = {
                "room_id": room_id,
                "uin": uin,
                "found": True,
                "was_active": was_active,
                "remaining_match_players": remaining,
                "match_players": sorted(a.match_players),
                "ended_round": bool(should_end),
                "state": a.state,
            }
        self._log(
            f"match-player quit room={room_id} uin={uin} was_active={was_active} "
            f"remaining={remaining} players={result['match_players']} reason={reason}"
        )
        if should_end:
            self.end_round(room_id, reason=f"{reason}; last match player left")
            result["ended_round"] = True
            result["state"] = "ROUND_ENDED"
        return result

    def remove_room_player(self, room_id: int, uin: int, reason: str = "player left room") -> dict:
        """Remove one lobby member. Shared AFDEV survives while any match player remains."""
        room_id = int(room_id); uin = int(uin)
        action = "KEEP"
        transfer = None
        with self._lock:
            a = self._allocations.get(room_id)
            if a is None or a.state == "RELEASED":
                return {"room_id": room_id, "uin": uin, "found": False, "action": "NONE"}
            a.match_players.discard(uin)
            a.room_players.discard(uin)
            if a.owner_id == uin and a.room_players:
                old_owner = a.owner_id
                new_owner = min(a.room_players)
                self._owner_to_room.pop(int(old_owner), None)
                a.owner_id = int(new_owner)
                self._owner_to_room[int(new_owner)] = room_id
                transfer = (old_owner, new_owner)
            room_remaining = len(a.room_players)
            match_remaining = len(a.match_players)
            if room_remaining == 0:
                action = "RELEASE_ROOM"
            elif match_remaining == 0 and a.state not in ("RESERVED", "ROUND_ENDED"):
                action = "END_ROUND"
            self._write_snapshot_locked()
            result = {
                "room_id": room_id,
                "uin": uin,
                "found": True,
                "action": action,
                "remaining_room_players": room_remaining,
                "remaining_match_players": match_remaining,
                "room_players": sorted(a.room_players),
                "match_players": sorted(a.match_players),
                "owner_id": a.owner_id,
                "owner_transfer": transfer,
            }
        self._log(
            f"room-player leave room={room_id} uin={uin} room_remaining={room_remaining} "
            f"match_remaining={match_remaining} action={action} reason={reason}"
        )
        if transfer:
            self._log(f"room owner transferred room={room_id} {transfer[0]} -> {transfer[1]}")
        if action == "RELEASE_ROOM":
            self.release_lobby(room_id, reason=f"{reason}; last room player left")
        elif action == "END_ROUND":
            self.end_round(room_id, reason=f"{reason}; no match players remain")
        return result

    def wait_ready(self, room_id: int, timeout: Optional[float] = None) -> DSAllocation:
        allocation = self.arm_lobby(int(room_id))
        deadline = time.time() + (self.config.ready_timeout if timeout is None else max(0.1, float(timeout)))
        while time.time() < deadline:
            with self._lock:
                current = self._allocations.get(int(room_id))
                if current is None:
                    raise SpawnerError(f"unknown room {room_id}")
                if current.state == "READY":
                    return current
                if current.state == "FAILED":
                    raise DSStartupError(current.last_error or "lazy AFDEV startup failed")
                if current.state == "RELEASED":
                    raise DSStartupError("DS allocation released")
            time.sleep(0.10)
        raise DSStartupError(f"room {room_id} is not ready before timeout")

    @staticmethod
    def _read_pid(path: Path) -> Optional[int]:
        try:
            return int(path.read_text(encoding="utf-8").strip())
        except Exception:
            return None

    @staticmethod
    def _kill_pid(pid: Optional[int]) -> None:
        if not pid:
            return
        try:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(int(pid)), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            else:
                os.kill(int(pid), 15)
        except Exception:
            pass

    def release_lobby(self, room_id: int, reason: str = "room released") -> bool:
        room_id = int(room_id)
        with self._lock:
            allocation = self._allocations.get(room_id)
            if allocation is None:
                return False
            if allocation.state == "RELEASED":
                return True
            allocation.state = "RELEASED"
            allocation.last_error = reason
            self._owner_to_room.pop(int(allocation.owner_id), None)
            allocation.room_players.clear()
            allocation.match_players.clear()
            self._write_snapshot_locked()
        self._log(f"release room={room_id} owner={allocation.owner_id} slot={allocation.slot}: {reason}")
        self._stop_allocation(allocation)
        return True

    def _stop_allocation(self, allocation: DSAllocation) -> None:
        p = self._instance_paths(allocation)
        afdev_pid = allocation.afdev_pid or self._read_pid(p["pid_file"])
        loader_pid = allocation.loader_pid or self._read_pid(p["loader_pid_file"])
        bridge_pid = allocation.bridge_pid or (allocation.bridge_proc.pid if allocation.bridge_proc is not None else None)

        self._log(
            f"teardown room={allocation.room_id} slot={allocation.slot} "
            f"afdev_pid={afdev_pid or 0} loader_pid={loader_pid or 0} bridge_pid={bridge_pid or 0}"
        )

        # Kill the heavy child first, then its Python monitor, then the bridge.
        self._kill_pid(afdev_pid)
        self._kill_pid(loader_pid)

        proc = allocation.bridge_proc
        if proc is not None:
            try:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2.0)
                    except subprocess.TimeoutExpired:
                        proc.kill()
            except Exception:
                pass

        try:
            if allocation.bridge_log_handle:
                allocation.bridge_log_handle.close()
        except Exception:
            pass

        # Give Windows a short moment to release both UDP sockets.  This is
        # diagnostic only; release_lobby has already made the slot logically
        # free and cleanup remains idempotent.
        deadline = time.time() + 2.0
        public_free = target_free = False
        while time.time() < deadline:
            public_free = self._udp_port_available("0.0.0.0", allocation.public_port)
            target_free = self._udp_port_available(allocation.target_host, allocation.target_port)
            if public_free and target_free:
                break
            time.sleep(0.05)

        self._log(
            f"teardown complete room={allocation.room_id} slot={allocation.slot} "
            f"public_udp_{allocation.public_port}_free={public_free} "
            f"afdev_udp_{allocation.target_port}_free={target_free}"
        )

        allocation.bridge_proc = None
        allocation.bridge_log_handle = None
        allocation.bridge_pid = None
        allocation.loader_pid = None
        allocation.afdev_pid = None
        with self._lock:
            self._write_snapshot_locked()

    def _room_dict(self, a: DSAllocation) -> dict:
        return {
            "room_id": a.room_id,
            "owner_id": a.owner_id,
            "slot": a.slot,
            "public_host": a.public_host,
            "public_port": a.public_port,
            "target_host": a.target_host,
            "target_port": a.target_port,
            "map_name": a.map_name,
            "max_players": a.max_players,
            "mode_id": a.mode_id,
            "map_id": a.map_id,
            "sub_mode_id": a.sub_mode_id,
            "room_flags": a.room_flags,
            "instance_id": a.instance_id,
            "state": a.state,
            "reserved_at": a.reserved_at,
            "armed_at": a.armed_at,
            "started_at": a.started_at,
            "ready_at": a.ready_at,
            "last_error": a.last_error,
            "bridge_pid": a.bridge_pid,
            "loader_pid": a.loader_pid,
            "afdev_pid": a.afdev_pid,
            "trigger_client": a.trigger_client,
            "buffered_packets": a.buffered_packets,
            "buffered_bytes": a.buffered_bytes,
            "suppressed_startup_packets": a.suppressed_startup_packets,
            "replay_attempts": a.replay_attempts,
            "peer_count": a.peer_count,
            "live_peer_count": a.live_peer_count,
            "room_players": sorted(a.room_players),
            "match_players": sorted(a.match_players),
            "round_generation": a.round_generation,
        }

    def _write_snapshot_locked(self) -> None:
        try:
            payload = {
                "updated_at": time.time(),
                "mode": "bridge_packet_lazy_first_packet_latch_multiplayer_cleanup",
                "max_instances": self.config.max_instances,
                "rooms": [self._room_dict(a) for a in self._allocations.values()],
                "standbys": [],
            }
            path = self.config.runtime_dir / "spawner_state.json"
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
            os.replace(tmp, path)
        except Exception as exc:
            self._log(f"state snapshot write failed: {exc}")

    def shutdown_all(self) -> None:
        with self._lock:
            if self._shutdown:
                return
            self._shutdown = True
            rows = list(self._allocations.values())
        for a in rows:
            prior = a.state
            if prior != "RELEASED":
                a.state = "RELEASED"
            if prior not in ("RELEASED", "ROUND_ENDED"):
                self._stop_allocation(a)
        with self._lock:
            self._owner_to_room.clear()
            self._write_snapshot_locked()
