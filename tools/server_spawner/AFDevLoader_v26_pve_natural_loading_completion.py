#!/usr/bin/env python3
# Stable Assault Fire PH AFDEV PVE listen-server spawner/launcher (v26)
#
# Known-good companion for the v5 transparent UDP bridge.
# This script does not include or redistribute TGame_AFDEV.exe or map assets.
# Supply your own lawful local game files via --game-dir or AF_GAME_DIR.
#
r"""
AFDevLoader v0.26
Assault Fire PH - PVE SYNTHETIC HOST OBSERVER FIX

Goal:
  Start the real PH TGame runtime without TCLS/network and execute the real
  UE3 console command:

      OPEN TR-Tutorial_Main

  on TGame's OWN PRIMARY/GAME THREAD.

Why v0.7 is different:
  - command-line map launching loses to Assault Fire's online startup UI
  - EXEC= also loses to that startup flow
  - calling UGameEngine::Exec from a foreign remote thread is unsafe
  - v0.7 briefly suspends TGame's primary thread, redirects it through a tiny
    one-shot trampoline, calls UTGameEngine::Exec there, then restores every
    register/flag and jumps back to the exact interrupted EIP

No game EXE is modified on disk.

Validated clean image:
  SHA256
  b4273f2658ca94eebc559a997fdfcd02d51e77ce75b892250c1db7fb80c70b51
"""

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import sys
import threading
import time


EXPECTED_SHA256 = (
    "b4273f2658ca94eebc559a997fdfcd02"
    "d51e77ce75b892250c1db7fb80c70b51"
)

DEFAULT_GAME_DIR = Path(os.environ.get("AF_GAME_DIR", r".\\game\\Binaries\\Win32"))
DEFAULT_MAP = "SV-Maya_3_Main"

# ---------------------------------------------------------------------------
# Validated addresses - clean PH TGame build
# ---------------------------------------------------------------------------

# Mandatory TCLS/GetLoginInfo failure path -> continue engine init.
LOGININFO_FAIL_VA = 0x014972F1
LOGININFO_EXPECT = bytes.fromhex("A1 20 D4 F9 01")
LOGININFO_PATCH  = bytes.fromhex("E9 17 01 00 00")  # jmp 0x0149740D

# TGTenio::DevLogin.
# Make it FAIL immediately instead of starting any Tencent/Tenio connection.
# Original function uses ret 14h.
DEVLOGIN_VA = 0x01494FF0
DEVLOGIN_EXPECT = bytes.fromhex("81 EC C8 01 00 00 A1 A0")
DEVLOGIN_OFFLINE_FAIL = bytes.fromhex(
    "31 C0"          # xor eax,eax
    "C2 14 00"      # ret 14h
    "90 90 90"      # padding
)

# Real UGameEngine::Exec-like handler.
# We statically verified this function parses the UTF-16 command "OPEN".
# UTGameEngine::Exec override. It falls through to UGameEngine::Exec.
TGAMEENGINE_EXEC_VA = 0x015B8980

# Global pointers.
GENGINE_PTR_VA = 0x02063820
GLOG_PTR_VA    = 0x01F9D420

# Live UE3 world pointer used directly by LoadMap/Tick in this build.
GWORLD_PTR_VA  = 0x02066BF8

# OPEN's vtable target stores the requested travel URL here.
# FString layout: Data*, Num, Max (12 bytes), then a separate byte/state flag.
PENDING_URL_OFFSET = 0x674
PENDING_FLAG_OFFSET = 0x680

# Fullscreen/loading movie stop wrapper used by TGame's LoadMap path.
#
# 0095B1C0:
#   if (arg != 0)
#       GFullScreenMovie->vfunc_38();
#   else
#       GFullScreenMovie->vfunc_1C(...);
#
# LoadMap calls this wrapper with arg=1 when stopping the loading movie.
STOP_LOADING_MOVIE_VA = 0x0095B1C0

# Assault Fire's separate LoadingMovie UI routine.
#
# Static reverse engineering:
#   0x01257FB0(... five stack args ...)
#
# Its first argument controls Show/Hide. With arg1=0 and arg5=0 it enters
# the LoadingMovie hide path at 0x01258099. Passing all five arguments as 0
# requests an immediate hide without the PostLoadPause/StreamByURL path.
AF_SHOW_LOADING_MOVIE_VA = 0x01257FB0

# UGameEngine layout confirmed by the same routine.
#
#   GEngine+0x47C = TArray<ULocalPlayer*>::Data
#   GEngine+0x480 = Count
#   GEngine+0x484 = Max
#
# It then checks:
#   LocalPlayer+0x40
# which is the player's PlayerController/Actor pointer in this build.
GAMEPLAYERS_OFFSET = 0x47C
LOCALPLAYER_PC_OFFSET = 0x40

# ---------------------------------------------------------------------------
# v24 PVE synthetic-listen-host fix
#
# TGSV3/PVE StartGame installs TimerCheckStartGame.  That timer fires on the
# FIRST PVEPlayerController for which:
#     !PC.bWaitingLoadingProcessComplete
#     PRI != None
#     !PRI.bAlwaysObserver
#
# AFDevLoader necessarily creates a synthetic GamePlayers[0] local controller
# inside TGame_AFDEV.exe.  In the broken runs that synthetic host was becoming
# the first eligible PVE player and consuming the one-shot GameStart event
# before the real network client finished loading.
#
# Neutralize ONLY GamePlayers[0]'s PRI by setting bAlwaysObserver.  The remote
# network client's PRI is never touched.
PVE_PC_VTABLE_V24 = 0x01E24C28
PVE_PC_PRI_OFFSET_V24 = 0x1DC
PVE_PRI_FLAGS_OFFSET_V24 = 0x3C0
PVE_PRI_ALWAYS_OBSERVER_MASK_V24 = 0x00000004

# Same-era UE3 controller layout. UPlayer+0x40 was already live-validated
# against Assault Fire in v0.12, so these are now used as READ-ONLY probes.
#
# AController:
#   +0x190 Pawn
#
# APlayerController:
#   +0x66C Player (UPlayer/ULocalPlayer)
#   +0x670 PlayerCamera
#   +0x688 AcknowledgedPawn
#
CONTROLLER_PAWN_OFFSET = 0x190
PC_PLAYER_OFFSET = 0x66C
PC_CAMERA_OFFSET = 0x670
PC_ACK_PAWN_OFFSET = 0x688

# ---------------------------------------------------------------------------
# Correct PH native class map + decoded tutorial defaults
# ---------------------------------------------------------------------------
#
# These were recovered from THIS exact clean TGame.exe:
#
#   TGGame:
#       ctor   0x013F9980
#       vtable 0x01D61948
#
#   TGTeamGame:
#       ctor   0x013F9A10
#       vtable 0x01D62530
#
#   TGPlayerController:
#       ctor   0x013F9BA0
#       vtable 0x01D64720
#       native size 0x9E0
#
#   TGPVPPlayerController:
#       ctor   0x013F9C00
#       vtable 0x01D651D8
#
#   TGTeamPlayerController:
#       ctor   0x013F9C30
#       vtable 0x01D65728
#       native size 0x9F8
#
#   TGPawn:
#       ctor   0x013EF8C0
#       vtable 0x01D5A830
#
#   TGTeamPawn:
#       ctor   0x013EF920
#       vtable 0x01D5B350
#       native size 0x1110
#
# The decoded PH UTGame.u package proves the intended tutorial classes:
#
#   TGTeamMatch_Tutorial extends TGTeamMatch
#
#   Default__TGTeamMatch_Tutorial.DefaultPawnClass
#       = TGTMPawn_Tutorial
#
#   Default__TGTeamMatch_Tutorial.PlayerControllerClass
#       = TGTMPlayerController_Tutorial
#
# TGTMPawn_Tutorial is a script subclass of TGTMPawn -> TGTeamPawn,
# therefore the expected native runtime vtable is TGTeamPawn's 0x01D5B350.
#
# TGTMPlayerController_Tutorial is a script subclass of
# TGTMPlayerController -> TGTeamPlayerController,
# therefore the expected native runtime vtable is 0x01D65728.
#
UTPLAYERCONTROLLER_VTABLE = 0x01D61428

TGGAME_VTABLE = 0x01D61948
TGTEAMGAME_VTABLE = 0x01D62530

TGPLAYERCONTROLLER_VTABLE = 0x01D64720
TGPVPPLAYERCONTROLLER_VTABLE = 0x01D651D8
TGTEAMPLAYERCONTROLLER_VTABLE = 0x01D65728

TGPLAYERCONTROLLER_SIZE = 0x9E0
TGTEAMPLAYERCONTROLLER_SIZE = 0x9F8

TGPAWN_VTABLE = 0x01D5A830
TGTEAMPAWN_VTABLE = 0x01D5B350
TGTEAMPAWN_NATIVE_SIZE = 0x1110

DEFAULT_GAME_CLASS = "TGSVGame.TGSV3Game"

# v21: isolate the AFDEV listen-server process from TGame's normal
# single-instance named mutex. Static call site in the validated PH image:
#   0x01349D75 -> push 0x01D12F98
#   CreateMutexW(...)
#   GetLastError()==183 -> "multiple running instances" popup.
# Change only the final GUID nibble for this suspended AFDEV process.
SINGLE_INSTANCE_MUTEX_VA = 0x01D12F98
SINGLE_INSTANCE_MUTEX_ORIGINAL = (
    "TGAME_{D21F20CD-996C-4ae2-8BF8-F2A7B4CD20D5}\0".encode("utf-16le")
)
SINGLE_INSTANCE_MUTEX_SERVER = (
    "TGAME_{D21F20CD-996C-4ae2-8BF8-F2A7B4CD20D6}\0".encode("utf-16le")
)

# Exact UE3 world helpers recovered from this clean PH TGame.exe.
#
# UWorld::GetWorldInfo-like helper:
#     ecx = UWorld*
#     push 0
#     call 0x00D9C1A0
#     ret 4
#
# UWorld::SetGameInfo (called by LoadMap):
#     0x00DA2760
#
# Inside SetGameInfo the returned WorldInfo is stored locally and the spawned
# authoritative GameInfo actor is written to:
#
#     WorldInfo + 0x414
#
UWORLD_GETWORLDINFO_VA = 0x00D9C1A0
WORLDINFO_GAME_OFFSET = 0x414

# TGame image and its .idata region. Most UE3 object vtables for this build
# live in .idata; this is only used as a READ-ONLY heuristic.
TGAME_IMAGE_MIN = 0x00400000
TGAME_IMAGE_MAX = 0x025BE000
TGAME_IDATA_MIN = 0x019F6000
TGAME_IDATA_MAX = 0x01F9C21F

# ---------------------------------------------------------------------------
# LoadMap milestone instrumentation
# ---------------------------------------------------------------------------
#
# These are existing 5-byte "push <timing-log-string>" instructions inside
# the real UE3 LoadMap routine. v0.11 replaces each push with a JMP to a tiny
# trampoline which:
#
#   1) writes the stage number to a private marker
#   2) executes the ORIGINAL push instruction
#   3) jumps straight back to address+5
#
# So the actual LoadMap logic is preserved.
#
LOADMAP_STAGES = [
    (
        1,
        "Before Load level",
        0x009C8A0C,
        bytes.fromhex("68 E0 BB B4 01"),
    ),
    (
        2,
        "After World Init",
        0x009C8B37,
        bytes.fromhex("68 88 BC B4 01"),
    ),
    (
        3,
        "Before Handle pending level",
        0x009C91D1,
        bytes.fromhex("68 28 C0 B4 01"),
    ),
    (
        4,
        "After SetGameInfo",
        0x009C966D,
        bytes.fromhex("68 D8 C1 B4 01"),
    ),
    (
        5,
        "After BeginPlay",
        0x009C99AA,
        bytes.fromhex("68 88 C2 B4 01"),
    ),
    (
        6,
        "After Client init",
        0x009C9E44,
        bytes.fromhex("68 70 C3 B4 01"),
    ),
    (
        7,
        "Finished loading level",
        0x009CAAAF,
        bytes.fromhex("68 F0 C6 B4 01"),
    ),
]

IS_BOOT_FROM_TCLS_VA = 0x020D4B80

# Win32 constants.
CREATE_SUSPENDED = 0x00000004
CREATE_UNICODE_ENVIRONMENT = 0x00000400

PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40

MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

# Commands we will try after the correct Tutorial controller exists.
# We stop as soon as a real TGTeamPawn-family object appears.
SPAWN_TRIGGER_COMMANDS = [
    "RESTARTPLAYER",
    "STARTMATCH",
    "QUICKRESTARTGAME",
    "RESTARTGAME",
    "STARTGAME",
    "SUMMON UTGame.TGTMPawn_Tutorial",
    "RESTARTLEVEL",
]

INFINITE = 0xFFFFFFFF
STILL_ACTIVE = 259

WOW64_CONTEXT_i386 = 0x00010000
WOW64_CONTEXT_CONTROL = WOW64_CONTEXT_i386 | 0x00000001
WOW64_CONTEXT_INTEGER = WOW64_CONTEXT_i386 | 0x00000002
WOW64_CONTEXT_SEGMENTS = WOW64_CONTEXT_i386 | 0x00000004
WOW64_CONTEXT_FULL = (
    WOW64_CONTEXT_CONTROL |
    WOW64_CONTEXT_INTEGER |
    WOW64_CONTEXT_SEGMENTS
)


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]



class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


class WOW64_FLOATING_SAVE_AREA(ctypes.Structure):
    _fields_ = [
        ("ControlWord", wintypes.DWORD),
        ("StatusWord", wintypes.DWORD),
        ("TagWord", wintypes.DWORD),
        ("ErrorOffset", wintypes.DWORD),
        ("ErrorSelector", wintypes.DWORD),
        ("DataOffset", wintypes.DWORD),
        ("DataSelector", wintypes.DWORD),
        ("RegisterArea", ctypes.c_ubyte * 80),
        ("Cr0NpxState", wintypes.DWORD),
    ]


class WOW64_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", wintypes.DWORD),

        ("Dr0", wintypes.DWORD),
        ("Dr1", wintypes.DWORD),
        ("Dr2", wintypes.DWORD),
        ("Dr3", wintypes.DWORD),
        ("Dr6", wintypes.DWORD),
        ("Dr7", wintypes.DWORD),

        ("FloatSave", WOW64_FLOATING_SAVE_AREA),

        ("SegGs", wintypes.DWORD),
        ("SegFs", wintypes.DWORD),
        ("SegEs", wintypes.DWORD),
        ("SegDs", wintypes.DWORD),

        ("Edi", wintypes.DWORD),
        ("Esi", wintypes.DWORD),
        ("Ebx", wintypes.DWORD),
        ("Edx", wintypes.DWORD),
        ("Ecx", wintypes.DWORD),
        ("Eax", wintypes.DWORD),

        ("Ebp", wintypes.DWORD),
        ("Eip", wintypes.DWORD),
        ("SegCs", wintypes.DWORD),
        ("EFlags", wintypes.DWORD),
        ("Esp", wintypes.DWORD),
        ("SegSs", wintypes.DWORD),

        ("ExtendedRegisters", ctypes.c_ubyte * 512),
    ]


# ---------------------------------------------------------------------------
# Win32 prototypes
# ---------------------------------------------------------------------------

kernel32.CreateProcessW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.BOOL,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.LPCWSTR,
    ctypes.POINTER(STARTUPINFOW),
    ctypes.POINTER(PROCESS_INFORMATION),
]
kernel32.CreateProcessW.restype = wintypes.BOOL

kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.WriteProcessMemory.restype = wintypes.BOOL

kernel32.VirtualProtectEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_size_t,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.VirtualProtectEx.restype = wintypes.BOOL

kernel32.VirtualAllocEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_size_t,
    wintypes.DWORD,
    wintypes.DWORD,
]
kernel32.VirtualAllocEx.restype = ctypes.c_void_p

kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t

kernel32.VirtualFreeEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_size_t,
    wintypes.DWORD,
]
kernel32.VirtualFreeEx.restype = wintypes.BOOL

kernel32.FlushInstructionCache.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_size_t,
]
kernel32.FlushInstructionCache.restype = wintypes.BOOL

kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
kernel32.ResumeThread.restype = wintypes.DWORD

kernel32.SuspendThread.argtypes = [wintypes.HANDLE]
kernel32.SuspendThread.restype = wintypes.DWORD

kernel32.Wow64GetThreadContext.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(WOW64_CONTEXT),
]
kernel32.Wow64GetThreadContext.restype = wintypes.BOOL

kernel32.Wow64SetThreadContext.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(WOW64_CONTEXT),
]
kernel32.Wow64SetThreadContext.restype = wintypes.BOOL

kernel32.GetExitCodeProcess.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.GetExitCodeProcess.restype = wintypes.BOOL

kernel32.TerminateProcess.argtypes = [
    wintypes.HANDLE,
    wintypes.UINT,
]
kernel32.TerminateProcess.restype = wintypes.BOOL

kernel32.WaitForSingleObject.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
]
kernel32.WaitForSingleObject.restype = wintypes.DWORD

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

shell32.IsUserAnAdmin.argtypes = []
shell32.IsUserAnAdmin.restype = wintypes.BOOL

shell32.ShellExecuteW.argtypes = [
    wintypes.HWND,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    ctypes.c_int,
]
shell32.ShellExecuteW.restype = ctypes.c_void_p


def winerr(prefix):
    e = ctypes.get_last_error()
    raise OSError(e, f"{prefix}: Win32 error {e}")


def ensure_admin():
    if shell32.IsUserAnAdmin():
        return

    params = subprocess.list2cmdline(
        [str(Path(__file__).resolve())] + sys.argv[1:]
    )

    print("[AFDEV] Requesting Administrator rights...")

    rc = shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        params,
        str(Path(__file__).resolve().parent),
        1,
    )

    value = int(ctypes.cast(rc, ctypes.c_void_p).value or 0)

    if value <= 32:
        raise SystemExit(
            f"UAC elevation failed/cancelled (ShellExecuteW={value})."
        )

    raise SystemExit(0)


def sha256_file(path):
    h = hashlib.sha256()

    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)

    return h.hexdigest()


def process_alive(hproc):
    code = wintypes.DWORD()

    if not kernel32.GetExitCodeProcess(
        hproc,
        ctypes.byref(code),
    ):
        return False

    return code.value == STILL_ACTIVE


def read_remote(hproc, address, size):
    buf = (ctypes.c_ubyte * size)()
    done = ctypes.c_size_t()

    if not kernel32.ReadProcessMemory(
        hproc,
        ctypes.c_void_p(address),
        ctypes.byref(buf),
        size,
        ctypes.byref(done),
    ):
        winerr(f"ReadProcessMemory(0x{address:08X})")

    if done.value != size:
        raise RuntimeError(
            f"short ReadProcessMemory at 0x{address:08X}: "
            f"{done.value}/{size}"
        )

    return bytes(buf)


def read_u32(hproc, address):
    return struct.unpack(
        "<I",
        read_remote(hproc, address, 4),
    )[0]


def write_remote(hproc, address, data):
    old = wintypes.DWORD()

    if not kernel32.VirtualProtectEx(
        hproc,
        ctypes.c_void_p(address),
        len(data),
        PAGE_EXECUTE_READWRITE,
        ctypes.byref(old),
    ):
        winerr(f"VirtualProtectEx(0x{address:08X})")

    try:
        src = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        done = ctypes.c_size_t()

        if not kernel32.WriteProcessMemory(
            hproc,
            ctypes.c_void_p(address),
            ctypes.byref(src),
            len(data),
            ctypes.byref(done),
        ):
            winerr(f"WriteProcessMemory(0x{address:08X})")

        if done.value != len(data):
            raise RuntimeError(
                f"short WriteProcessMemory at 0x{address:08X}: "
                f"{done.value}/{len(data)}"
            )

        kernel32.FlushInstructionCache(
            hproc,
            ctypes.c_void_p(address),
            len(data),
        )

    finally:
        dummy = wintypes.DWORD()

        kernel32.VirtualProtectEx(
            hproc,
            ctypes.c_void_p(address),
            len(data),
            old.value,
            ctypes.byref(dummy),
        )


def verify_and_patch(hproc, address, expected, replacement, label):
    current = read_remote(
        hproc,
        address,
        len(expected),
    )

    print(
        f"[AFDEV] {label} @0x{address:08X}\n"
        f"        current : {current.hex(' ').upper()}\n"
        f"        expected: {expected.hex(' ').upper()}"
    )

    if current != expected:
        raise RuntimeError(
            f"{label}: bytes do not match validated build."
        )

    write_remote(
        hproc,
        address,
        replacement,
    )

    after = read_remote(
        hproc,
        address,
        len(replacement),
    )

    if after != replacement:
        raise RuntimeError(
            f"{label}: patch verification failed."
        )

    print(
        f"        patched : {after.hex(' ').upper()}"
    )


def wait_for_engine(hproc, timeout):
    deadline = time.time() + timeout
    last_engine = 0
    last_log = 0

    while time.time() < deadline:
        if not process_alive(hproc):
            raise RuntimeError(
                "TGame exited before GEngine became ready."
            )

        try:
            last_engine = read_u32(
                hproc,
                GENGINE_PTR_VA,
            )
            last_log = read_u32(
                hproc,
                GLOG_PTR_VA,
            )
        except OSError:
            pass

        if last_engine and last_log:
            return last_engine, last_log

        time.sleep(0.10)

    raise RuntimeError(
        "Timed out waiting for UE3 globals. "
        f"GEngine=0x{last_engine:08X} "
        f"GLog=0x{last_log:08X}"
    )



def safe_read_u32(hproc, address):
    try:
        return read_u32(hproc, address)
    except Exception:
        return None



def arm_pve_synthetic_host_observer_v24(hproc, engine_ptr):
    """
    Background guard for AFDEV's synthetic GamePlayers[0] PVE controller.

    It polls the actual UGameEngine GamePlayers[0] pointer.  Only when that
    local PlayerController has the exact verified PVE PC vtable does it touch
    memory.  It then sets ONLY PRI.bAlwaysObserver (+0x3C0 mask 0x4).

    This is intentionally not a spawn/load/UI hack.  It prevents AFDEV's fake
    local frontend player from satisfying PVEGame.TimerCheckStartGame before
    the real remote player is ready.
    """
    state = {
        "first_patch": False,
        "patch_count": 0,
        "last_pc": 0,
        "last_pri": 0,
    }

    print(
        "[AFDEV-v24] Armed synthetic-host observer guard "
        "(GamePlayers[0] only)."
    )

    def worker():
        while process_alive(hproc):
            try:
                raw = read_remote(
                    hproc,
                    engine_ptr + GAMEPLAYERS_OFFSET,
                    12,
                )
                data_ptr, count, max_count = struct.unpack("<III", raw)

                if not (
                    data_ptr
                    and 1 <= count <= 32
                    and count <= max_count
                ):
                    time.sleep(0.005)
                    continue

                local_player = read_u32(hproc, data_ptr)
                if not local_player:
                    time.sleep(0.005)
                    continue

                pc = read_u32(
                    hproc,
                    local_player + LOCALPLAYER_PC_OFFSET,
                )
                if not pc:
                    time.sleep(0.005)
                    continue

                vt = read_u32(hproc, pc)
                if vt != PVE_PC_VTABLE_V24:
                    time.sleep(0.005)
                    continue

                pri = read_u32(
                    hproc,
                    pc + PVE_PC_PRI_OFFSET_V24,
                )
                if not pri:
                    time.sleep(0.005)
                    continue

                flags_addr = pri + PVE_PRI_FLAGS_OFFSET_V24
                old_flags = read_u32(hproc, flags_addr)
                new_flags = (
                    old_flags | PVE_PRI_ALWAYS_OBSERVER_MASK_V24
                )

                if new_flags != old_flags:
                    write_remote(
                        hproc,
                        flags_addr,
                        struct.pack("<I", new_flags),
                    )
                    verify = read_u32(hproc, flags_addr)
                    if not (
                        verify & PVE_PRI_ALWAYS_OBSERVER_MASK_V24
                    ):
                        raise RuntimeError(
                            "bAlwaysObserver verification failed"
                        )

                    state["patch_count"] += 1
                    state["last_pc"] = pc
                    state["last_pri"] = pri

                    if not state["first_patch"]:
                        state["first_patch"] = True
                        print(
                            "[AFDEV-v24] >>> PVE synthetic host neutralized "
                            f"BEFORE GameStart eligibility: "
                            f"PC=0x{pc:08X} PRI=0x{pri:08X} "
                            f"PRI+0x3C0 0x{old_flags:08X}"
                            f" -> 0x{verify:08X} "
                            "(bAlwaysObserver=TRUE)"
                        )
                    else:
                        print(
                            "[AFDEV-v24] Re-applied host bAlwaysObserver "
                            f"PC=0x{pc:08X} PRI=0x{pri:08X}"
                        )

                # Keep guarding.  Some lifecycle code can rewrite packed
                # PRI flag DWORDs; if bit 2 is ever cleared, restore it.
                time.sleep(0.010)

            except Exception:
                # Map/world swaps are expected while OPEN is travelling.
                time.sleep(0.010)

    t = threading.Thread(
        target=worker,
        name="AF-PVE-SyntheticHostObserver-v24",
        daemon=True,
    )
    t.start()
    return state, t


def read_remote_fstring(hproc, address, max_chars=512):
    """
    Read a UE3 FString/TArray<TCHAR>:
      +0 Data*
      +4 Num
      +8 Max
    """
    try:
        raw = read_remote(hproc, address, 12)
        ptr, num, cap = struct.unpack("<III", raw)

        if ptr == 0:
            return "", ptr, num, cap

        if num == 0:
            return "", ptr, num, cap

        # FString Num usually includes trailing NUL.
        if num > max_chars or cap > 0x100000 or num > cap:
            return f"<invalid FString ptr=0x{ptr:08X} num={num} max={cap}>", ptr, num, cap

        chars = read_remote(hproc, ptr, num * 2)
        text = chars.decode("utf-16le", errors="replace").rstrip("\x00")
        return text, ptr, num, cap

    except Exception as e:
        return f"<read error: {e}>", 0, 0, 0


def find_recent_log_files(game_root):
    """
    Assault Fire/UE3 builds vary in where -log writes.
    Probe likely locations and return existing .log files newest-first.
    """
    roots = [
        game_root / "TGame" / "Logs",
        game_root / "TGame" / "Log",
        game_root / "Binaries" / "Win32",
        game_root,
    ]

    found = []
    seen = set()

    for root in roots:
        if not root.is_dir():
            continue

        try:
            for p in root.glob("*.log"):
                rp = str(p.resolve()).lower()
                if rp in seen:
                    continue
                seen.add(rp)

                try:
                    found.append((p.stat().st_mtime, p))
                except OSError:
                    pass
        except OSError:
            pass

    found.sort(reverse=True)
    return [p for _, p in found]


def print_log_tail(path, max_lines=30):
    try:
        data = path.read_bytes()

        # UE3 logs can be ANSI or UTF-16.
        if data.startswith(b"\xff\xfe"):
            text = data.decode("utf-16le", errors="replace")
        else:
            # Detect likely UTF-16LE by NUL density.
            sample = data[:4096]
            nul_ratio = (sample.count(0) / max(1, len(sample)))
            if nul_ratio > 0.20:
                text = data.decode("utf-16le", errors="replace")
            else:
                text = data.decode("utf-8", errors="replace")

        lines = text.splitlines()
        print(f"[AFDEV] LOG TAIL: {path}")
        for line in lines[-max_lines:]:
            print(f"[TGLOG] {line}")

    except Exception as e:
        print(f"[AFDEV] Could not read log {path}: {e}")




def rel32(from_after_instruction, target):
    """
    x86 signed rel32 displacement encoded modulo 2^32.
    """
    return (target - from_after_instruction) & 0xFFFFFFFF


def install_loadmap_stage_hooks(hproc):
    """
    Install seven one-shot/non-destructive-in-behavior LoadMap milestone hooks.

    Returns:
        marker_ptr, instrumentation_base
    """
    # One page is enough for marker + 7 trampolines.
    remote = kernel32.VirtualAllocEx(
        hproc,
        None,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )

    if not remote:
        winerr("VirtualAllocEx(LoadMap instrumentation)")

    base = int(
        ctypes.cast(
            remote,
            ctypes.c_void_p,
        ).value
    )

    marker_ptr = base
    tramp_base = base + 0x100

    write_remote(
        hproc,
        marker_ptr,
        struct.pack("<I", 0),
    )

    print(
        f"[AFDEV] LoadMap stage marker @0x{marker_ptr:08X}"
    )

    for index, (stage, name, address, expected) in enumerate(
        LOADMAP_STAGES
    ):
        current = read_remote(
            hproc,
            address,
            5,
        )

        print(
            f"[AFDEV] Stage {stage} hook: {name}\n"
            f"        VA       : 0x{address:08X}\n"
            f"        current  : {current.hex(' ').upper()}\n"
            f"        expected : {expected.hex(' ').upper()}"
        )

        if current != expected:
            raise RuntimeError(
                f"LoadMap stage {stage} bytes do not match."
            )

        trampoline = tramp_base + index * 0x40

        # Original instruction is:
        #   push <imm32>
        original_imm = expected[1:5]

        code = bytearray()

        # mov dword ptr [marker_ptr], stage
        code += b"\xC7\x05"
        code += struct.pack("<I", marker_ptr)
        code += struct.pack("<I", stage)

        # Execute the exact original PUSH imm32.
        code += b"\x68" + original_imm

        # jmp address+5
        jump_back_from = trampoline + len(code) + 5
        code += b"\xE9" + struct.pack(
            "<I",
            rel32(
                jump_back_from,
                address + 5,
            ),
        )

        write_remote(
            hproc,
            trampoline,
            bytes(code),
        )

        # Replace original 5-byte PUSH with JMP trampoline.
        patch = (
            b"\xE9"
            + struct.pack(
                "<I",
                rel32(
                    address + 5,
                    trampoline,
                ),
            )
        )

        write_remote(
            hproc,
            address,
            patch,
        )

        after = read_remote(
            hproc,
            address,
            5,
        )

        if after != patch:
            raise RuntimeError(
                f"LoadMap stage {stage} hook verification failed."
            )

        print(
            f"        trampoline: 0x{trampoline:08X}"
        )

    print(
        "[AFDEV] All LoadMap milestone hooks installed."
    )

    return marker_ptr, base


def stage_name(stage):
    for number, name, _, _ in LOADMAP_STAGES:
        if number == stage:
            return name

    if stage == 0:
        return "LoadMap not entered"

    return "unknown"


def monitor_loadmap_stage(
    hproc,
    marker_ptr,
    seconds=30,
):
    print()
    print(
        "[AFDEV] ===== LOADMAP MILESTONE MONITOR ====="
    )

    previous = None
    highest = 0

    for i in range(seconds + 1):
        if not process_alive(hproc):
            print(
                "[AFDEV] TGame exited during LoadMap stage monitor."
            )
            return highest

        try:
            stage = read_u32(
                hproc,
                marker_ptr,
            )
        except Exception as e:
            print(
                f"[AFDEV] Stage marker read failed: {e}"
            )
            return highest

        if stage > highest:
            highest = stage

        if stage != previous:
            print(
                f"[MILESTONE +{i:02d}s] "
                f"stage={stage} -> {stage_name(stage)}"
            )
            previous = stage

        if stage >= 7:
            print(
                "[AFDEV] >>> LoadMap reached FINAL milestone 7."
            )
            break

        if i != seconds:
            time.sleep(1.0)

    print(
        f"[AFDEV] Highest LoadMap stage: "
        f"{highest} ({stage_name(highest)})"
    )
    print(
        "[AFDEV] ===== END MILESTONE MONITOR ====="
    )
    print()

    return highest


def sample_primary_thread(
    hproc,
    hthread,
    samples=12,
    interval=0.25,
):
    """
    If LoadMap does not reach stage 7, sample the primary/game thread EIP
    and a few stack dwords. This often exposes the exact wait/call where it
    is blocked.
    """
    print(
        "[AFDEV] ===== PRIMARY THREAD SAMPLES ====="
    )

    for i in range(samples):
        if not process_alive(hproc):
            break

        prev = kernel32.SuspendThread(
            hthread
        )

        if prev == 0xFFFFFFFF:
            print(
                "[AFDEV] SuspendThread failed during sampler."
            )
            break

        try:
            ctx = WOW64_CONTEXT()
            ctx.ContextFlags = WOW64_CONTEXT_FULL

            if not kernel32.Wow64GetThreadContext(
                hthread,
                ctypes.byref(ctx),
            ):
                print(
                    "[AFDEV] Wow64GetThreadContext failed during sampler."
                )
                break

            stack_words = []

            try:
                raw = read_remote(
                    hproc,
                    ctx.Esp,
                    8 * 4,
                )
                stack_words = list(
                    struct.unpack(
                        "<8I",
                        raw,
                    )
                )
            except Exception:
                stack_words = []

            stack_text = " ".join(
                f"{x:08X}"
                for x in stack_words
            )

            print(
                f"[THREAD {i:02d}] "
                f"EIP=0x{ctx.Eip:08X} "
                f"ESP=0x{ctx.Esp:08X} "
                f"stack={stack_text}"
            )

        finally:
            kernel32.ResumeThread(
                hthread
            )

        time.sleep(interval)

    print(
        "[AFDEV] ===== END THREAD SAMPLES ====="
    )
    print()




def scan_gameinfo_config(game_root, map_name):
    r"""
    Search the installed TGame\Config INI files for map-prefix/GameInfo clues.
    This is local/offline and avoids guessing the correct Tutorial GameInfo.
    """
    config_root = game_root / "TGame" / "Config"

    print()
    print("[AFDEV] ===== CONFIG / GAMETYPE SCAN =====")
    print(f"[AFDEV] Config root: {config_root}")

    if not config_root.is_dir():
        print("[AFDEV] Config directory not found.")
        print("[AFDEV] ===== END CONFIG SCAN =====")
        print()
        return

    prefix = map_name.split("-", 1)[0].strip().lower()
    needles = (
        "gamemapprefix",
        "defaultgametype",
        "gameinfo",
        "tutorial",
        f"{prefix}-",
        f"prefix={prefix}",
        f"prefix={prefix.upper()}",
    )

    hits = []

    for path in sorted(config_root.rglob("*.ini")):
        try:
            raw = path.read_bytes()

            # Most UE3 INIs here are ANSI/UTF-8; tolerate UTF-16 as well.
            if raw.startswith(b"\xff\xfe"):
                text = raw.decode("utf-16le", errors="replace")
            elif raw.startswith(b"\xfe\xff"):
                text = raw.decode("utf-16be", errors="replace")
            else:
                text = raw.decode("utf-8", errors="replace")

            for lineno, line in enumerate(text.splitlines(), 1):
                low = line.lower()

                if any(n.lower() in low for n in needles):
                    hits.append(
                        (path, lineno, line.strip())
                    )
        except Exception:
            continue

    if not hits:
        print(
            "[AFDEV] No matching GameInfo/map-prefix lines found "
            "in Config INIs."
        )
    else:
        # Avoid flooding: prefer lines containing tutorial/TR/game mapping.
        print(
            f"[AFDEV] Found {len(hits)} matching config lines "
            "(showing up to 80):"
        )

        for path, lineno, line in hits[:80]:
            try:
                rel = path.relative_to(config_root)
            except Exception:
                rel = path

            print(
                f"[CFG] {rel}:{lineno}: {line}"
            )

    print("[AFDEV] ===== END CONFIG SCAN =====")
    print()


def wait_for_player_controller(
    hproc,
    engine_ptr,
    timeout=15.0,
):
    """
    Wait for GamePlayers[0].Actor/PlayerController to become non-null.
    """
    deadline = time.time() + timeout
    last_lp = 0
    last_pc = 0

    while time.time() < deadline:
        try:
            raw = read_remote(
                hproc,
                engine_ptr + GAMEPLAYERS_OFFSET,
                12,
            )
            data_ptr, count, max_count = struct.unpack(
                "<III",
                raw,
            )

            if (
                data_ptr
                and 1 <= count <= 32
                and count <= max_count
            ):
                last_lp = read_u32(
                    hproc,
                    data_ptr,
                )

                if last_lp:
                    last_pc = read_u32(
                        hproc,
                        last_lp + LOCALPLAYER_PC_OFFSET,
                    )

                    if last_pc:
                        return last_lp, last_pc
        except Exception:
            pass

        time.sleep(0.25)

    return last_lp, last_pc



def wait_for_nonnull_gworld(hproc, timeout=15.0):
    """
    PendingURL can clear slightly before GWorld is swapped to the new world.
    v0.13 observed exactly that race. Wait for the final non-null pointer.
    """
    deadline = time.time() + timeout
    last = 0

    while time.time() < deadline:
        last = safe_read_u32(
            hproc,
            GWORLD_PTR_VA,
        ) or 0

        if last:
            return last

        time.sleep(0.10)

    return last


def is_probable_object_pointer(hproc, ptr):
    """
    Conservative read-only UE3 UObject heuristic:
      - pointer must be aligned and in plausible user address space
      - target must be readable
      - target's first DWORD (vtable) must land inside TGame .idata
    """
    if not ptr or (ptr & 3):
        return None

    if ptr < 0x00010000 or ptr >= 0x70000000:
        return None

    try:
        vtbl = read_u32(
            hproc,
            ptr,
        )
    except Exception:
        return None

    if TGAME_IDATA_MIN <= vtbl < TGAME_IDATA_MAX:
        return vtbl

    return None



def find_exact_vtable_targets_in_blob(
    hproc,
    object_base,
    object_size,
    target_vtable,
    target_name,
):
    """
    Scan an object's DWORD fields for pointers whose target begins with the
    exact requested native vtable.
    """
    hits = []

    try:
        blob = read_remote(
            hproc,
            object_base,
            object_size,
        )
    except Exception:
        return hits

    for off in range(
        0,
        object_size - 3,
        4,
    ):
        ptr = struct.unpack_from(
            "<I",
            blob,
            off,
        )[0]

        if (
            not ptr
            or (ptr & 3)
            or ptr < 0x00010000
            or ptr >= 0x70000000
        ):
            continue

        try:
            vtbl = read_u32(
                hproc,
                ptr,
            )
        except Exception:
            continue

        if vtbl == target_vtable:
            hits.append(
                (off, ptr)
            )

    if hits:
        print(
            f"[AFDEV] >>> Exact {target_name} pointer(s) found:"
        )
        for off, ptr in hits:
            print(
                f"[AFDEV]     object+0x{off:X} -> "
                f"0x{ptr:08X} "
                f"(vtable=0x{target_vtable:08X})"
            )
    else:
        print(
            f"[AFDEV] >>> No direct {target_name} pointer found "
            f"in object 0x{object_base:08X} size 0x{object_size:X}."
        )

    return hits



def scan_private_memory_for_vtable(
    hproc,
    target_vtable,
    label,
    max_hits=64,
):
    """
    Scan committed MEM_PRIVATE regions below 0x70000000 for allocations whose
    first DWORD at a 4-byte aligned address equals target_vtable.

    This is read-only. UObject instances live in private process memory, so
    this is much more decisive than only walking one or two UWorld pointers.
    """
    pattern = struct.pack("<I", target_vtable)
    hits = []

    address = 0x00010000
    max_address = 0x70000000
    mbi = MEMORY_BASIC_INFORMATION()
    mbi_size = ctypes.sizeof(mbi)

    while address < max_address and len(hits) < max_hits:
        got = kernel32.VirtualQueryEx(
            hproc,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            mbi_size,
        )

        if not got:
            # Move by one allocation granularity rather than getting stuck.
            address += 0x10000
            continue

        base = int(mbi.BaseAddress or 0)
        size = int(mbi.RegionSize or 0)

        if size <= 0:
            address += 0x10000
            continue

        next_address = base + size

        readable = (
            mbi.State == MEM_COMMIT
            and mbi.Type == MEM_PRIVATE
            and not (mbi.Protect & PAGE_NOACCESS)
            and not (mbi.Protect & PAGE_GUARD)
        )

        if readable:
            # Read in bounded chunks so a huge heap region does not require
            # one enormous temporary allocation.
            chunk_size = 1024 * 1024
            pos = base
            end = min(next_address, max_address)

            while pos < end and len(hits) < max_hits:
                want = min(chunk_size, end - pos)

                try:
                    blob = read_remote(
                        hproc,
                        pos,
                        want,
                    )
                except Exception:
                    pos += want
                    continue

                start = 0

                while len(hits) < max_hits:
                    idx = blob.find(pattern, start)

                    if idx < 0:
                        break

                    candidate = pos + idx

                    # UObject allocations are at least DWORD aligned.
                    if (candidate & 3) == 0:
                        # Basic sanity: inspect a few common object-header
                        # positions. We do NOT assume exact UE3 header layout;
                        # this simply filters obviously empty/random hits.
                        try:
                            head = read_remote(
                                hproc,
                                candidate,
                                0x40,
                            )
                            hdr28 = struct.unpack_from(
                                "<I",
                                head,
                                0x28,
                            )[0]
                            hdr2c = struct.unpack_from(
                                "<I",
                                head,
                                0x2C,
                            )[0]
                        except Exception:
                            hdr28 = hdr2c = 0

                        hits.append(
                            (
                                candidate,
                                hdr28,
                                hdr2c,
                            )
                        )

                    start = idx + 4

                pos += want

        if next_address <= address:
            address += 0x10000
        else:
            address = next_address

    print(
        f"[AFDEV] Global {label} exact-vtable hits: {len(hits)}"
    )

    for candidate, hdr28, hdr2c in hits[:20]:
        print(
            f"[GLOBAL] {label:26} "
            f"obj=0x{candidate:08X} "
            f"vtbl=0x{target_vtable:08X} "
            f"hdr28=0x{hdr28:08X} "
            f"hdr2C=0x{hdr2c:08X}"
        )

    return hits


def scan_tutorial_runtime_globally(hproc):
    """
    Return global exact-vtable hits for the tutorial native bases.
    """
    print()
    print(
        "[AFDEV] ===== GLOBAL TUTORIAL OBJECT SCAN ====="
    )

    game_hits = scan_private_memory_for_vtable(
        hproc,
        TGTEAMGAME_VTABLE,
        "TGTeamGame-family",
    )

    controller_hits = scan_private_memory_for_vtable(
        hproc,
        TGTEAMPLAYERCONTROLLER_VTABLE,
        "TGTeamPlayerController-family",
    )

    pawn_hits = scan_private_memory_for_vtable(
        hproc,
        TGTEAMPAWN_VTABLE,
        "TGTeamPawn-family",
    )

    print(
        "[AFDEV] ===== END GLOBAL TUTORIAL OBJECT SCAN ====="
    )
    print()

    return game_hits, controller_hits, pawn_hits



def profile_pawn_candidate(
    hproc,
    pawn,
    live_pc,
    local_player,
    gworld,
):
    """
    Read-only relationship probe for one TGTeamPawn-family candidate.

    We deliberately do NOT assume pawn/controller offsets. Instead we look
    for exact live-object pointers inside the candidate allocation.
    """
    result = {
        "pawn": pawn,
        "pc_offsets": [],
        "lp_offsets": [],
        "world_offsets": [],
    }

    try:
        blob = read_remote(
            hproc,
            pawn,
            0x1800,
        )
    except Exception as e:
        print(
            f"[PAWNREL] 0x{pawn:08X}: read failed: {e}"
        )
        return result

    for off in range(0, len(blob) - 3, 4):
        value = struct.unpack_from(
            "<I",
            blob,
            off,
        )[0]

        if live_pc and value == live_pc:
            result["pc_offsets"].append(off)

        if local_player and value == local_player:
            result["lp_offsets"].append(off)

        if gworld and value == gworld:
            result["world_offsets"].append(off)

    rels = []

    if result["pc_offsets"]:
        rels.append(
            "PC@" + ",".join(
                f"+0x{x:X}"
                for x in result["pc_offsets"]
            )
        )

    if result["lp_offsets"]:
        rels.append(
            "LP@" + ",".join(
                f"+0x{x:X}"
                for x in result["lp_offsets"]
            )
        )

    if result["world_offsets"]:
        rels.append(
            "WORLD@" + ",".join(
                f"+0x{x:X}"
                for x in result["world_offsets"]
            )
        )

    relation_text = (
        " ; ".join(rels)
        if rels
        else "no direct live PC/LP/GWorld refs"
    )

    print(
        f"[PAWNREL] pawn=0x{pawn:08X}: {relation_text}"
    )

    return result


def controller_pawn_pointer_hits(
    hproc,
    pc,
    pawn_addresses,
):
    """
    Scan a generous controller window for exact pointers to known
    TGTeamPawn-family candidates. This does not rely on a guessed Pawn offset.
    """
    hits = []

    if not pc or not pawn_addresses:
        return hits

    try:
        blob = read_remote(
            hproc,
            pc,
            0x1800,
        )
    except Exception as e:
        print(
            f"[AFDEV] Could not scan controller for pawn pointers: {e}"
        )
        return hits

    pawns = set(pawn_addresses)

    for off in range(0, len(blob) - 3, 4):
        value = struct.unpack_from(
            "<I",
            blob,
            off,
        )[0]

        if value in pawns:
            hits.append(
                (off, value)
            )

    if hits:
        print(
            "[AFDEV] >>> Live controller contains TGTeamPawn-family "
            "pointer(s):"
        )
        for off, pawn in hits:
            print(
                f"[REL] PC+0x{off:X} -> pawn 0x{pawn:08X}"
            )
    else:
        print(
            "[AFDEV] Live controller contains NO direct pointer to any "
            "known TGTeamPawn-family candidate."
        )

    return hits


def classify_pawn_set(
    hproc,
    pawn_hits,
    live_pc,
    local_player,
    gworld,
    label,
):
    """
    Profile a complete set of exact-vtable pawn candidates.
    """
    addresses = [
        x[0]
        for x in pawn_hits
    ]

    print()
    print(
        f"[AFDEV] ===== PAWN RELATIONSHIP PROFILE: {label} ====="
    )
    print(
        f"[AFDEV] Candidate count: {len(addresses)}"
    )

    profiles = []

    for pawn in addresses:
        profiles.append(
            profile_pawn_candidate(
                hproc,
                pawn,
                live_pc,
                local_player,
                gworld,
            )
        )

    controller_hits = controller_pawn_pointer_hits(
        hproc,
        live_pc,
        addresses,
    )

    strongly_related = [
        p
        for p in profiles
        if p["pc_offsets"]
    ]

    print(
        f"[AFDEV] Pawns with exact live-PC backref: "
        f"{len(strongly_related)}"
    )
    print(
        f"[AFDEV] Controller->pawn pointer hits: "
        f"{len(controller_hits)}"
    )
    print(
        f"[AFDEV] ===== END PAWN RELATIONSHIP PROFILE: {label} ====="
    )
    print()

    return {
        "addresses": set(addresses),
        "profiles": profiles,
        "controller_hits": controller_hits,
        "strongly_related": strongly_related,
    }



def inject_exec_on_localplayer_thread(
    hproc,
    hthread,
    local_player,
    log_ptr,
    command,
):
    """
    Execute a gameplay/player console command through the SAME FExec path
    that TGame itself uses for GamePlayers[0].

    Static proof from this exact TGame.exe, around 0x009B9936:

        mov eax,[GEngine+0x47C]  ; GamePlayers.Data
        mov edi,[eax]            ; ULocalPlayer*
        add edi,0x3C             ; embedded FExec subobject

        ...
        mov ebp,[edi]            ; FExec vtable
        push GLog
        push Cmd
        mov ecx,edi
        mov edx,[ebp+0]
        call edx                 ; FExec::Exec(Cmd, Ar)

    So:
        Exec this = ULocalPlayer + 0x3C
        function  = [ [ULocalPlayer+0x3C] + 0 ]
        args      = (TCHAR* Cmd, FOutputDevice* Ar)

    This is a much better route for gameplay commands than calling
    UTGameEngine::Exec directly.
    """
    command_bytes = (
        command.encode("utf-16le")
        + b"\x00\x00"
    )

    remote = kernel32.VirtualAllocEx(
        hproc,
        None,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )

    if not remote:
        winerr("VirtualAllocEx(LocalPlayer Exec)")

    remote = int(
        ctypes.cast(
            remote,
            ctypes.c_void_p,
        ).value
    )

    command_ptr = remote + 0x000
    result_ptr = remote + 0x400
    code_ptr = remote + 0x500

    write_remote(
        hproc,
        command_ptr,
        command_bytes,
    )

    write_remote(
        hproc,
        result_ptr,
        struct.pack("<I", 0xDEADC0DE),
    )

    prev = kernel32.SuspendThread(
        hthread
    )

    if prev == 0xFFFFFFFF:
        winerr("SuspendThread(LocalPlayer Exec)")

    suspended = True

    try:
        ctx = WOW64_CONTEXT()
        ctx.ContextFlags = WOW64_CONTEXT_FULL

        if not kernel32.Wow64GetThreadContext(
            hthread,
            ctypes.byref(ctx),
        ):
            winerr(
                "Wow64GetThreadContext(LocalPlayer Exec)"
            )

        original_eip = ctx.Eip

        print(
            f"[AFDEV] LocalPlayer Exec: game thread paused "
            f"at EIP=0x{original_eip:08X}"
        )

        exec_this = (
            local_player + 0x3C
        ) & 0xFFFFFFFF

        try:
            sub_vtable = read_u32(
                hproc,
                exec_this,
            )
            exec_fn = read_u32(
                hproc,
                sub_vtable,
            )
        except Exception as e:
            raise RuntimeError(
                f"Could not resolve LocalPlayer FExec vtable: {e}"
            )

        print(
            f"[AFDEV] LocalPlayer      = 0x{local_player:08X}"
        )
        print(
            f"[AFDEV] LocalPlayer FExec= 0x{exec_this:08X}"
        )
        print(
            f"[AFDEV] FExec vtable     = 0x{sub_vtable:08X}"
        )
        print(
            f"[AFDEV] FExec::Exec      = 0x{exec_fn:08X}"
        )
        print(
            f"[AFDEV] Player command   = {command}"
        )

        sc = bytearray()

        # Preserve exact interrupted CPU state.
        sc += b"\x9C"  # pushfd
        sc += b"\x60"  # pushad

        # ecx = LocalPlayer + 0x3C
        sc += b"\xB9" + struct.pack(
            "<I",
            exec_this,
        )

        # eax = [ecx]  (FExec sub-vtable)
        sc += b"\x8B\x01"

        # edx = [eax]  (slot 0 = Exec)
        sc += b"\x8B\x10"

        # push Ar = *GLog
        sc += b"\xA1" + struct.pack(
            "<I",
            GLOG_PTR_VA,
        )
        sc += b"\x50"

        # push Cmd
        sc += b"\x68" + struct.pack(
            "<I",
            command_ptr,
        )

        # call edx
        sc += b"\xFF\xD2"

        # Save returned UBOOL/EAX.
        sc += b"\xA3" + struct.pack(
            "<I",
            result_ptr,
        )

        sc += b"\x61"  # popad
        sc += b"\x9D"  # popfd

        # Return to exact interrupted EIP without clobbering regs.
        sc += b"\x68" + struct.pack(
            "<I",
            original_eip,
        )
        sc += b"\xC3"

        write_remote(
            hproc,
            code_ptr,
            bytes(sc),
        )

        ctx.Eip = code_ptr

        if not kernel32.Wow64SetThreadContext(
            hthread,
            ctypes.byref(ctx),
        ):
            winerr(
                "Wow64SetThreadContext(LocalPlayer Exec)"
            )

        resumed = kernel32.ResumeThread(
            hthread
        )

        if resumed == 0xFFFFFFFF:
            winerr(
                "ResumeThread(LocalPlayer Exec)"
            )

        suspended = False

        deadline = time.time() + 15.0

        while time.time() < deadline:
            if not process_alive(hproc):
                raise RuntimeError(
                    "TGame exited during LocalPlayer Exec."
                )

            result = read_u32(
                hproc,
                result_ptr,
            )

            if result != 0xDEADC0DE:
                print(
                    f"[AFDEV] LocalPlayer FExec::Exec returned: "
                    f"0x{result:08X}"
                )
                return result

            time.sleep(0.05)

        raise RuntimeError(
            "LocalPlayer Exec trampoline did not finish."
        )

    finally:
        if suspended:
            kernel32.ResumeThread(
                hthread
            )


def run_localplayer_exec_sanity_probe(
    hproc,
    hthread,
    local_player,
    log_ptr,
):
    """
    CAUSEEVENT is known to be sent through exactly this LocalPlayer FExec
    path by TGame's own engine tick code. Using a nonexistent event name
    is safe and tells us whether the command interface itself accepts the
    command.
    """
    print()
    print(
        "[AFDEV] ===== LOCALPLAYER FEXEC SANITY PROBE ====="
    )

    command = "CAUSEEVENT AFDEV_NONEXISTENT_EVENT"

    try:
        result = inject_exec_on_localplayer_thread(
            hproc,
            hthread,
            local_player,
            log_ptr,
            command,
        )
    except Exception as e:
        print(
            f"[AFDEV] LocalPlayer FExec sanity probe failed: {e}"
        )
        print(
            "[AFDEV] ===== END LOCALPLAYER FEXEC SANITY PROBE ====="
        )
        print()
        return None

    print(
        f"[AFDEV] Sanity command result: 0x{result:08X}"
    )

    if result:
        print(
            "[AFDEV] >>> LocalPlayer FExec path is LIVE and "
            "recognized CAUSEEVENT."
        )
    else:
        print(
            "[AFDEV] CAUSEEVENT returned 0. The FExec call itself "
            "completed, but this build did not report the command handled."
        )

    print(
        "[AFDEV] ===== END LOCALPLAYER FEXEC SANITY PROBE ====="
    )
    print()

    return result


def run_spawn_trigger_probes(
    hproc,
    hthread,
    engine_ptr,
    log_ptr,
    live_pc,
    local_player,
    gworld,
):
    """
    v0.18 behavior:
      - ALWAYS run the trigger probes, even if TGTeamPawn-family objects
        already exist globally.
      - Snapshot the exact pawn-object set before each command.
      - Diff the set afterward.
      - Check direct pawn->live-PC and live-PC->pawn relationships.
      - Stop only when we get strong evidence of a newly spawned/possessed
        pawn, not merely because class-default/archetype pawn objects exist.
    """
    print()
    print(
        "[AFDEV] ===== PAWN-SPAWN TRIGGER PROBES v0.19 / LOCALPLAYER FEXEC ====="
    )

    baseline_hits = scan_private_memory_for_vtable(
        hproc,
        TGTEAMPAWN_VTABLE,
        "TGTeamPawn-family BASELINE",
        max_hits=128,
    )

    baseline_profile = classify_pawn_set(
        hproc,
        baseline_hits,
        live_pc,
        local_player,
        gworld,
        "BASELINE",
    )

    previous_set = set(
        baseline_profile["addresses"]
    )

    if (
        baseline_profile["strongly_related"]
        or baseline_profile["controller_hits"]
    ):
        print(
            "[AFDEV] >>> A baseline TGTeamPawn-family object is already "
            "strongly related to the live controller."
        )
        print(
            "[AFDEV] We will still run commands to see if possession/state "
            "changes further."
        )

    for command in SPAWN_TRIGGER_COMMANDS:
        print()
        print(
            "=" * 72
        )
        print(
            f"[AFDEV] >>> Trying runtime command: {command}"
        )

        try:
            result = inject_exec_on_localplayer_thread(
                hproc,
                hthread,
                local_player,
                log_ptr,
                command,
            )
        except Exception as e:
            print(
                f"[AFDEV] Command injection failed: {e}"
            )
            continue

        print(
            f"[AFDEV] LocalPlayer Exec return: 0x{result:08X}"
        )

        # Let script/native game state tick.
        time.sleep(2.0)

        after_hits = scan_private_memory_for_vtable(
            hproc,
            TGTEAMPAWN_VTABLE,
            f"TGTeamPawn-family AFTER {command}",
            max_hits=128,
        )

        after_profile = classify_pawn_set(
            hproc,
            after_hits,
            live_pc,
            local_player,
            gworld,
            f"AFTER {command}",
        )

        after_set = set(
            after_profile["addresses"]
        )

        new_pawns = sorted(
            after_set - previous_set
        )

        vanished = sorted(
            previous_set - after_set
        )

        if new_pawns:
            print(
                f"[AFDEV] >>> NEW TGTeamPawn-family object(s) after "
                f"{command!r}:"
            )
            for pawn in new_pawns:
                print(
                    f"[NEWPAWN] 0x{pawn:08X}"
                )
        else:
            print(
                f"[AFDEV] No new TGTeamPawn-family allocation after "
                f"{command!r}."
            )

        if vanished:
            print(
                f"[AFDEV] Pawn candidate(s) disappeared after "
                f"{command!r}:"
            )
            for pawn in vanished:
                print(
                    f"[OLDPAWN-GONE] 0x{pawn:08X}"
                )

        # Re-read live LocalPlayer->PC in case a restart replaced controller.
        lp_now, pc_now = wait_for_player_controller(
            hproc,
            engine_ptr,
            timeout=2.0,
        )

        if pc_now and pc_now != live_pc:
            print(
                f"[AFDEV] >>> PlayerController changed: "
                f"0x{live_pc:08X} -> 0x{pc_now:08X}"
            )
            live_pc = pc_now
            local_player = lp_now

            # Re-classify current pawns against the new controller.
            after_profile = classify_pawn_set(
                hproc,
                after_hits,
                live_pc,
                local_player,
                gworld,
                f"AFTER {command} WITH NEW PC",
            )

        strong_relation = bool(
            after_profile["strongly_related"]
            or after_profile["controller_hits"]
        )

        # Strong success: actual possession/ownership-like pointer relation.
        if strong_relation:
            print()
            print(
                f"[AFDEV] >>> STRONG SUCCESS after {command!r}: "
                "a TGTeamPawn-family object is now directly related to "
                "the live PlayerController."
            )
            print(
                "[AFDEV] ===== END PAWN-SPAWN TRIGGER PROBES v0.19 / LOCALPLAYER FEXEC ====="
            )
            print()
            return {
                "command": command,
                "new_pawns": new_pawns,
                "pawn_hits": after_hits,
                "profile": after_profile,
                "live_pc": live_pc,
                "local_player": local_player,
                "strong": True,
            }

        # We still report allocation success even if not possessed.
        if new_pawns:
            print(
                f"[AFDEV] {command!r} created new pawn-family object(s), "
                "but no direct possession/controller relationship was "
                "detected yet."
            )

        previous_set = after_set

    print()
    print(
        "[AFDEV] All trigger probes finished without a strong "
        "controller<->pawn relationship."
    )
    print(
        "[AFDEV] ===== END PAWN-SPAWN TRIGGER PROBES v0.19 / LOCALPLAYER FEXEC ====="
    )
    print()

    return {
        "command": None,
        "new_pawns": [],
        "pawn_hits": after_hits if "after_hits" in locals() else baseline_hits,
        "profile": after_profile if "after_profile" in locals() else baseline_profile,
        "live_pc": live_pc,
        "local_player": local_player,
        "strong": False,
    }




def get_worldinfo_on_game_thread(
    hproc,
    hthread,
    gworld,
):
    """
    Call the exact UWorld::GetWorldInfo helper from this TGame build.

        ECX = GWorld
        push 0
        call 0x00D9C1A0

    Returns the live AWorldInfo*.
    """
    remote = kernel32.VirtualAllocEx(
        hproc,
        None,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )

    if not remote:
        winerr("VirtualAllocEx(GetWorldInfo)")

    remote = int(
        ctypes.cast(
            remote,
            ctypes.c_void_p,
        ).value
    )

    result_ptr = remote + 0x100
    code_ptr = remote + 0x200

    write_remote(
        hproc,
        result_ptr,
        struct.pack("<I", 0xDEADC0DE),
    )

    prev = kernel32.SuspendThread(
        hthread
    )

    if prev == 0xFFFFFFFF:
        winerr("SuspendThread(GetWorldInfo)")

    suspended = True

    try:
        ctx = WOW64_CONTEXT()
        ctx.ContextFlags = WOW64_CONTEXT_FULL

        if not kernel32.Wow64GetThreadContext(
            hthread,
            ctypes.byref(ctx),
        ):
            winerr(
                "Wow64GetThreadContext(GetWorldInfo)"
            )

        original_eip = ctx.Eip

        sc = bytearray()

        sc += b"\x9C"  # pushfd
        sc += b"\x60"  # pushad

        # ECX = GWorld
        sc += b"\xB9" + struct.pack(
            "<I",
            gworld,
        )

        # helper's single stack argument = 0
        sc += b"\x6A\x00"

        # EAX = UWorld::GetWorldInfo helper
        sc += b"\xB8" + struct.pack(
            "<I",
            UWORLD_GETWORLDINFO_VA,
        )

        # call eax
        sc += b"\xFF\xD0"

        # helper returns WorldInfo* in EAX
        sc += b"\xA3" + struct.pack(
            "<I",
            result_ptr,
        )

        sc += b"\x61"  # popad
        sc += b"\x9D"  # popfd

        # exact interrupted EIP
        sc += b"\x68" + struct.pack(
            "<I",
            original_eip,
        )
        sc += b"\xC3"

        write_remote(
            hproc,
            code_ptr,
            bytes(sc),
        )

        ctx.Eip = code_ptr

        if not kernel32.Wow64SetThreadContext(
            hthread,
            ctypes.byref(ctx),
        ):
            winerr(
                "Wow64SetThreadContext(GetWorldInfo)"
            )

        resumed = kernel32.ResumeThread(
            hthread
        )

        if resumed == 0xFFFFFFFF:
            winerr(
                "ResumeThread(GetWorldInfo)"
            )

        suspended = False

        deadline = time.time() + 10.0

        while time.time() < deadline:
            if not process_alive(hproc):
                raise RuntimeError(
                    "TGame exited while calling GetWorldInfo."
                )

            result = read_u32(
                hproc,
                result_ptr,
            )

            if result != 0xDEADC0DE:
                return result

            time.sleep(0.05)

        raise RuntimeError(
            "GetWorldInfo trampoline timed out."
        )

    finally:
        if suspended:
            kernel32.ResumeThread(
                hthread
            )


def inspect_authority_world(
    hproc,
    hthread,
    gworld,
):
    """
    Definitive authority/GameInfo probe.

    If WorldInfo+0x414 is NULL, there is no live authoritative GameInfo actor.
    If it is non-NULL, print its vtable and core UObject header words.
    """
    print()
    print(
        "[AFDEV] ===== AUTHORITY / WORLDINFO / GAMEINFO PROBE ====="
    )
    print(
        f"[AFDEV] GWorld = 0x{gworld:08X}"
    )

    try:
        world_info = get_worldinfo_on_game_thread(
            hproc,
            hthread,
            gworld,
        )
    except Exception as e:
        print(
            f"[AFDEV] GetWorldInfo failed: {e}"
        )
        print(
            "[AFDEV] ===== END AUTHORITY PROBE ====="
        )
        print()
        return {
            "world_info": 0,
            "game_info": 0,
        }

    print(
        f"[AFDEV] WorldInfo = 0x{world_info:08X}"
    )

    game_info = 0

    if world_info:
        try:
            game_info = read_u32(
                hproc,
                world_info + WORLDINFO_GAME_OFFSET,
            )
        except Exception as e:
            print(
                f"[AFDEV] Could not read WorldInfo+0x414: {e}"
            )

    print(
        f"[AFDEV] WorldInfo+0x414 (Game) = "
        f"0x{game_info:08X}"
    )

    if not game_info:
        print(
            "[AFDEV] >>> NO LIVE GameInfo actor exists in this world."
        )
        print(
            "[AFDEV] >>> That is the exact condition expected on a "
            "client/non-authority world."
        )
    else:
        try:
            vtbl = read_u32(
                hproc,
                game_info,
            )
            head = read_remote(
                hproc,
                game_info,
                0x40,
            )

            dwords = [
                struct.unpack_from("<I", head, x)[0]
                for x in range(0, 0x40, 4)
            ]

            print(
                f"[AFDEV] GameInfo vtable = 0x{vtbl:08X}"
            )
            print(
                "[AFDEV] GameInfo UObject header DWORDs:"
            )

            for off in range(0, 0x40, 0x10):
                vals = " ".join(
                    f"{dwords[(off // 4) + i]:08X}"
                    for i in range(4)
                )
                print(
                    f"[GI +0x{off:02X}] {vals}"
                )

            if vtbl == TGTEAMGAME_VTABLE:
                print(
                    "[AFDEV] >>> LIVE GameInfo matches the "
                    "TGTeamGame native family."
                )
            else:
                print(
                    "[AFDEV] >>> LIVE GameInfo exists, but its native "
                    "vtable is not the mapped TGTeamGame value."
                )

        except Exception as e:
            print(
                f"[AFDEV] Could not inspect GameInfo: {e}"
            )

    print(
        "[AFDEV] ===== END AUTHORITY PROBE ====="
    )
    print()

    return {
        "world_info": world_info,
        "game_info": game_info,
    }


def scan_world_for_tggame_and_tgpawn(
    hproc,
    gworld,
):
    """
    Targeted v0.16 scan for the tutorial's expected native bases.

    Expected:
      TGTeamMatch_Tutorial -> TGTeamGame native vtable 0x01D62530
      TGTMPawn_Tutorial    -> TGTeamPawn native vtable 0x01D5B350
    """
    print()
    print(
        "[AFDEV] ===== TUTORIAL GAMEINFO / PAWN EXACT-VTABLE SCAN ====="
    )

    if not gworld:
        print("[AFDEV] GWorld is NULL.")
        print(
            "[AFDEV] ===== END TUTORIAL EXACT-VTABLE SCAN ====="
        )
        print()
        return

    print(f"[AFDEV] GWorld                 = 0x{gworld:08X}")
    print(
        f"[AFDEV] Expected GameInfo VT   = "
        f"0x{TGTEAMGAME_VTABLE:08X} (TGTeamGame family)"
    )
    print(
        f"[AFDEV] Expected Pawn VT       = "
        f"0x{TGTEAMPAWN_VTABLE:08X} (TGTeamPawn family)"
    )

    # Direct fields in UWorld first.
    direct_game = find_exact_vtable_targets_in_blob(
        hproc,
        gworld,
        0x1400,
        TGTEAMGAME_VTABLE,
        "TGTeamGame/TGTeamMatch_Tutorial",
    )

    direct_pawn = find_exact_vtable_targets_in_blob(
        hproc,
        gworld,
        0x1400,
        TGTEAMPAWN_VTABLE,
        "TGTeamPawn/TGTMPawn_Tutorial",
    )

    try:
        world_blob = read_remote(
            hproc,
            gworld,
            0x1400,
        )
    except Exception as e:
        print(f"[AFDEV] Could not read UWorld: {e}")
        print(
            "[AFDEV] ===== END TUTORIAL EXACT-VTABLE SCAN ====="
        )
        print()
        return

    child_objects = []
    seen = set()

    for off in range(0, 0x1400 - 3, 4):
        ptr = struct.unpack_from("<I", world_blob, off)[0]

        if ptr in seen:
            continue

        vtbl = is_probable_object_pointer(
            hproc,
            ptr,
        )

        if vtbl is None:
            continue

        seen.add(ptr)
        child_objects.append(
            (off, ptr, vtbl)
        )

    print(
        f"[AFDEV] UWorld direct UObject-like children: "
        f"{len(child_objects)}"
    )

    game_hits = []
    pawn_hits = []

    # Follow one UObject level. This is enough to catch WorldInfo/GameInfo
    # style ownership without relying on version-specific UWorld offsets.
    for parent_off, child, child_vtbl in child_objects[:192]:
        try:
            blob = read_remote(
                hproc,
                child,
                0x1400,
            )
        except Exception:
            continue

        for off in range(0, 0x1400 - 3, 4):
            ptr = struct.unpack_from(
                "<I",
                blob,
                off,
            )[0]

            if (
                not ptr
                or (ptr & 3)
                or ptr < 0x00010000
                or ptr >= 0x70000000
            ):
                continue

            try:
                vtbl = read_u32(
                    hproc,
                    ptr,
                )
            except Exception:
                continue

            rec = (
                parent_off,
                child,
                child_vtbl,
                off,
                ptr,
            )

            if vtbl == TGTEAMGAME_VTABLE:
                game_hits.append(rec)

            if vtbl == TGTEAMPAWN_VTABLE:
                pawn_hits.append(rec)

    if direct_game or game_hits:
        print(
            "[AFDEV] >>> SUCCESS: tutorial TGTeamGame-family "
            "GameInfo object is present."
        )

        for poff, child, cvtbl, off, ptr in game_hits[:12]:
            print(
                f"[GAME] GWorld+0x{poff:X} -> "
                f"0x{child:08X}(vtbl=0x{cvtbl:08X}) "
                f"+0x{off:X} -> "
                f"0x{ptr:08X}(vtbl=0x{TGTEAMGAME_VTABLE:08X})"
            )
    else:
        print(
            "[AFDEV] >>> Tutorial TGTeamGame-family GameInfo "
            "was NOT found in the scanned graph."
        )

    if direct_pawn or pawn_hits:
        print(
            "[AFDEV] >>> SUCCESS: tutorial TGTeamPawn-family "
            "Pawn object is present."
        )

        for poff, child, cvtbl, off, ptr in pawn_hits[:12]:
            print(
                f"[PAWN] GWorld+0x{poff:X} -> "
                f"0x{child:08X}(vtbl=0x{cvtbl:08X}) "
                f"+0x{off:X} -> "
                f"0x{ptr:08X}(vtbl=0x{TGTEAMPAWN_VTABLE:08X})"
            )
    else:
        print(
            "[AFDEV] >>> Tutorial TGTeamPawn-family Pawn "
            "was NOT found in the scanned graph."
        )

    print(
        "[AFDEV] ===== END TUTORIAL EXACT-VTABLE SCAN ====="
    )
    print()



def scan_exact_tgplayercontroller(
    hproc,
    local_player,
    pc,
    gworld,
):
    """
    Targeted tutorial controller probe.

    Expected for TGTMPlayerController_Tutorial:
        native base TGTeamPlayerController
        vtable 0x01D65728

    We scan the inherited/native portion of the controller for a direct
    pointer to the expected TGTeamPawn-family pawn.
    """
    print()
    print(
        "[AFDEV] ===== EXACT TUTORIAL PLAYERCONTROLLER RUNTIME SCAN ====="
    )

    if not pc:
        print("[AFDEV] PlayerController is NULL.")
        print(
            "[AFDEV] ===== END TUTORIAL CONTROLLER SCAN ====="
        )
        print()
        return

    try:
        pc_vtbl = read_u32(
            hproc,
            pc,
        )
    except Exception:
        pc_vtbl = 0

    print(f"[AFDEV] PC              = 0x{pc:08X}")
    print(f"[AFDEV] PC VTable       = 0x{pc_vtbl:08X}")
    print(
        f"[AFDEV] Expected VT      = "
        f"0x{TGTEAMPLAYERCONTROLLER_VTABLE:08X}"
    )
    print(
        f"[AFDEV] LocalPlayer      = 0x{local_player:08X}"
    )
    print(f"[AFDEV] GWorld           = 0x{gworld:08X}")

    if pc_vtbl == TGTEAMPLAYERCONTROLLER_VTABLE:
        print(
            "[AFDEV] >>> SUCCESS: controller matches "
            "TGTeamPlayerController family."
        )
        print(
            "[AFDEV] >>> This is the expected native base for "
            "TGTMPlayerController_Tutorial."
        )
    elif pc_vtbl == TGPLAYERCONTROLLER_VTABLE:
        print(
            "[AFDEV] Controller is TGPlayerController family, "
            "not the tutorial team-controller family."
        )
    elif pc_vtbl == TGPVPPLAYERCONTROLLER_VTABLE:
        print(
            "[AFDEV] Controller is TGPVPPlayerController family."
        )
    elif pc_vtbl == UTPLAYERCONTROLLER_VTABLE:
        print(
            "[AFDEV] Controller fell back to the lower/base "
            "UT PlayerController family."
        )
    else:
        print(
            "[AFDEV] Controller vtable is not one of the mapped "
            "TG controller families."
        )

    try:
        blob = read_remote(
            hproc,
            pc,
            TGTEAMPLAYERCONTROLLER_SIZE,
        )
    except Exception as e:
        print(
            f"[AFDEV] Could not read controller object: {e}"
        )
        print(
            "[AFDEV] ===== END TUTORIAL CONTROLLER SCAN ====="
        )
        print()
        return

    # Known reverse direction:
    # ULocalPlayer+0x40 -> PlayerController.
    try:
        lp_actor = read_u32(
            hproc,
            local_player + LOCALPLAYER_PC_OFFSET,
        )
        print(
            f"[AFDEV] ULocalPlayer+0x40 = 0x{lp_actor:08X} "
            f"({'MATCH' if lp_actor == pc else 'MISMATCH'})"
        )
    except Exception as e:
        print(
            f"[AFDEV] ULocalPlayer+0x40 validation failed: {e}"
        )

    # Find the LocalPlayer pointer in the controller itself.
    lp_hits = []

    for off in range(
        0,
        TGTEAMPLAYERCONTROLLER_SIZE - 3,
        4,
    ):
        value = struct.unpack_from(
            "<I",
            blob,
            off,
        )[0]

        if value == local_player:
            lp_hits.append(off)

    if lp_hits:
        print(
            "[AFDEV] LocalPlayer pointer inside controller at: "
            + ", ".join(
                f"+0x{x:X}"
                for x in lp_hits
            )
        )

    # Exact tutorial pawn target.
    tutorial_pawn_hits = find_exact_vtable_targets_in_blob(
        hproc,
        pc,
        TGTEAMPLAYERCONTROLLER_SIZE,
        TGTEAMPAWN_VTABLE,
        "TGTeamPawn/TGTMPawn_Tutorial",
    )

    # Also show base-pawn hits as a fallback diagnostic.
    base_pawn_hits = find_exact_vtable_targets_in_blob(
        hproc,
        pc,
        TGTEAMPLAYERCONTROLLER_SIZE,
        TGPAWN_VTABLE,
        "base TGPawn",
    )

    if tutorial_pawn_hits:
        print(
            "[AFDEV] >>> SUCCESS: controller has a direct pointer "
            "to the expected tutorial pawn family."
        )
    elif base_pawn_hits:
        print(
            "[AFDEV] Controller has a base-TGPawn pointer, but not "
            "the expected tutorial team-pawn family."
        )
    else:
        print(
            "[AFDEV] >>> Controller has NO direct Pawn pointer "
            "matching either mapped TG pawn family."
        )

    # Print only high-value object pointers in the controller:
    # mapped pawn/controller families and LocalPlayer.
    print(
        "[AFDEV] High-value mapped object pointers in controller:"
    )

    mapped_vtables = {
        TGPAWN_VTABLE: "TGPawn-family",
        TGTEAMPAWN_VTABLE: "TGTeamPawn-family",
        TGPLAYERCONTROLLER_VTABLE: "TGPlayerController-family",
        TGPVPPLAYERCONTROLLER_VTABLE: "TGPVPPlayerController-family",
        TGTEAMPLAYERCONTROLLER_VTABLE: "TGTeamPlayerController-family",
    }

    printed = 0

    for off in range(
        0,
        TGTEAMPLAYERCONTROLLER_SIZE - 3,
        4,
    ):
        value = struct.unpack_from(
            "<I",
            blob,
            off,
        )[0]

        if value == local_player:
            print(
                f"[MAP] PC+0x{off:03X} = "
                f"0x{value:08X} LOCALPLAYER"
            )
            printed += 1
            continue

        if (
            not value
            or (value & 3)
            or value < 0x00010000
            or value >= 0x70000000
        ):
            continue

        try:
            vtbl = read_u32(
                hproc,
                value,
            )
        except Exception:
            continue

        label = mapped_vtables.get(vtbl)

        if label:
            print(
                f"[MAP] PC+0x{off:03X} = "
                f"0x{value:08X} "
                f"vtbl=0x{vtbl:08X} {label}"
            )
            printed += 1

    if printed == 0:
        print("[AFDEV]   <none>")

    print(
        "[AFDEV] ===== END TUTORIAL CONTROLLER SCAN ====="
    )
    print()



def inspect_player_controller_core(
    hproc,
    local_player,
    pc,
    label="",
):
    """
    Read-only probe of core same-era UE3 PlayerController fields.
    """
    print()
    print(
        f"[AFDEV] ===== PLAYERCONTROLLER CORE{label} ====="
    )

    if not pc:
        print("[AFDEV] PlayerController is NULL.")
        print("[AFDEV] ===== END PLAYERCONTROLLER CORE =====")
        print()
        return {}

    fields = {}

    probes = [
        ("Pawn", CONTROLLER_PAWN_OFFSET),
        ("Player", PC_PLAYER_OFFSET),
        ("PlayerCamera", PC_CAMERA_OFFSET),
        ("AcknowledgedPawn", PC_ACK_PAWN_OFFSET),
    ]

    for name, offset in probes:
        try:
            value = read_u32(
                hproc,
                pc + offset,
            )
        except Exception:
            value = 0

        fields[name] = value

        print(
            f"[AFDEV] PC+0x{offset:03X} "
            f"{name:16} = 0x{value:08X}"
        )

    player_ptr = fields.get("Player", 0)
    pawn = fields.get("Pawn", 0)
    ack = fields.get("AcknowledgedPawn", 0)
    camera = fields.get("PlayerCamera", 0)

    if player_ptr:
        relation = (
            "MATCHES LocalPlayer"
            if player_ptr == local_player
            else "DIFFERS from LocalPlayer"
        )
        print(
            f"[AFDEV] Player relation: {relation} "
            f"(LocalPlayer=0x{local_player:08X})"
        )

    if pawn:
        try:
            pawn_vtbl = read_u32(hproc, pawn)
        except Exception:
            pawn_vtbl = 0

        print(
            f"[AFDEV] >>> Controller already possesses a Pawn: "
            f"0x{pawn:08X} (VTable=0x{pawn_vtbl:08X})"
        )
    else:
        print(
            "[AFDEV] >>> Controller Pawn is NULL."
        )

    if ack:
        print(
            f"[AFDEV] >>> AcknowledgedPawn is 0x{ack:08X}"
        )
    else:
        print(
            "[AFDEV] >>> AcknowledgedPawn is NULL."
        )

    if camera:
        try:
            camera_vtbl = read_u32(
                hproc,
                camera,
            )
        except Exception:
            camera_vtbl = 0

        print(
            f"[AFDEV] >>> PlayerCamera exists: "
            f"0x{camera:08X} (VTable=0x{camera_vtbl:08X})"
        )
    else:
        print(
            "[AFDEV] >>> PlayerCamera is NULL."
        )

    print(
        "[AFDEV] ===== END PLAYERCONTROLLER CORE ====="
    )
    print()

    return fields


def inspect_local_players(hproc, engine_ptr, label=""):
    """
    Inspect the UGameEngine GamePlayers TArray and each LocalPlayer's
    PlayerController pointer.
    """
    try:
        raw = read_remote(
            hproc,
            engine_ptr + GAMEPLAYERS_OFFSET,
            12,
        )
        data_ptr, count, max_count = struct.unpack(
            "<III",
            raw,
        )
    except Exception as e:
        print(
            f"[AFDEV] GamePlayers{label}: read failed: {e}"
        )
        return {
            "data": 0,
            "count": 0,
            "max": 0,
            "players": [],
        }

    print()
    print(
        f"[AFDEV] GamePlayers{label}: "
        f"Data=0x{data_ptr:08X} Count={count} Max={max_count}"
    )

    result = {
        "data": data_ptr,
        "count": count,
        "max": max_count,
        "players": [],
    }

    # Sanity bounds.
    if count > 32 or max_count > 1024 or count > max_count:
        print(
            "[AFDEV] WARNING: GamePlayers TArray values look invalid."
        )
        return result

    for i in range(count):
        try:
            lp = read_u32(
                hproc,
                data_ptr + i * 4,
            ) if data_ptr else 0

            pc = (
                read_u32(
                    hproc,
                    lp + LOCALPLAYER_PC_OFFSET,
                )
                if lp
                else 0
            )

            lp_vtbl = (
                read_u32(hproc, lp)
                if lp
                else 0
            )

            pc_vtbl = (
                read_u32(hproc, pc)
                if pc
                else 0
            )

            print(
                f"[AFDEV]   Player[{i}] "
                f"ULocalPlayer=0x{lp:08X} "
                f"VTable=0x{lp_vtbl:08X} "
                f"PlayerController=0x{pc:08X} "
                f"PCVTable=0x{pc_vtbl:08X}"
            )

            result["players"].append(
                {
                    "local_player": lp,
                    "local_player_vtable": lp_vtbl,
                    "player_controller": pc,
                    "player_controller_vtable": pc_vtbl,
                }
            )

        except Exception as e:
            print(
                f"[AFDEV]   Player[{i}] read failed: {e}"
            )

    if count == 0:
        print(
            "[AFDEV] >>> No LocalPlayer exists."
        )
    elif not any(
        p.get("player_controller")
        for p in result["players"]
    ):
        print(
            "[AFDEV] >>> LocalPlayer exists, but no PlayerController is attached."
        )
    else:
        print(
            "[AFDEV] >>> At least one LocalPlayer + PlayerController exists."
        )

    print()

    return result


def hide_af_loading_ui_on_game_thread(hproc, hthread):
    """
    Call Assault Fire's own LoadingMovie hide routine:

        0x01257FB0(0, 0, 0.0f, 0.0f, 0)

    on the primary/game thread.

    The function uses stdcall-like stack cleanup:
        ret 0x14

    so it consumes all five arguments itself.
    """
    remote = kernel32.VirtualAllocEx(
        hproc,
        None,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )

    if not remote:
        winerr("VirtualAllocEx(AF LoadingMovie hide)")

    remote = int(
        ctypes.cast(
            remote,
            ctypes.c_void_p,
        ).value
    )

    result_ptr = remote + 0x100
    code_ptr = remote + 0x200

    write_remote(
        hproc,
        result_ptr,
        struct.pack("<I", 0xDEADC0DE),
    )

    prev = kernel32.SuspendThread(hthread)
    if prev == 0xFFFFFFFF:
        winerr("SuspendThread(AF LoadingMovie hide)")

    suspended = True

    try:
        ctx = WOW64_CONTEXT()
        ctx.ContextFlags = WOW64_CONTEXT_FULL

        if not kernel32.Wow64GetThreadContext(
            hthread,
            ctypes.byref(ctx),
        ):
            winerr(
                "Wow64GetThreadContext(AF LoadingMovie hide)"
            )

        original_eip = ctx.Eip

        print(
            f"[AFDEV] AF LoadingMovie hide: "
            f"game thread paused at EIP=0x{original_eip:08X}"
        )

        sc = bytearray()

        # Preserve exact interrupted CPU state.
        sc += b"\x9C"  # pushfd
        sc += b"\x60"  # pushad

        # Five arguments, right-to-left.
        # arg5 = 0
        # arg4 = 0.0f
        # arg3 = 0.0f
        # arg2 = 0
        # arg1 = 0  -> SHOW=FALSE
        sc += b"\x6A\x00" * 5

        # mov eax, AF_SHOW_LOADING_MOVIE_VA
        sc += b"\xB8" + struct.pack(
            "<I",
            AF_SHOW_LOADING_MOVIE_VA,
        )

        # call eax
        sc += b"\xFF\xD0"

        # Function returns with RET 14h, so ESP is back at pushad frame.

        # marker = 1
        sc += b"\xC7\x05"
        sc += struct.pack(
            "<I",
            result_ptr,
        )
        sc += struct.pack(
            "<I",
            1,
        )

        sc += b"\x61"  # popad
        sc += b"\x9D"  # popfd

        # Return to the exact interrupted instruction.
        sc += b"\x68" + struct.pack(
            "<I",
            original_eip,
        )
        sc += b"\xC3"

        write_remote(
            hproc,
            code_ptr,
            bytes(sc),
        )

        print(
            f"[AFDEV] AF LoadingMovie hide trampoline "
            f"@0x{code_ptr:08X}"
        )
        print(
            "[AFDEV] Calling "
            f"0x{AF_SHOW_LOADING_MOVIE_VA:08X}"
            "(Show=0, arg2=0, fade=0, pause=0, arg5=0)"
        )

        ctx.Eip = code_ptr

        if not kernel32.Wow64SetThreadContext(
            hthread,
            ctypes.byref(ctx),
        ):
            winerr(
                "Wow64SetThreadContext(AF LoadingMovie hide)"
            )

        resumed = kernel32.ResumeThread(hthread)

        if resumed == 0xFFFFFFFF:
            winerr("ResumeThread(AF LoadingMovie hide)")

        suspended = False

        deadline = time.time() + 10.0

        while time.time() < deadline:
            if not process_alive(hproc):
                raise RuntimeError(
                    "TGame exited while hiding AF LoadingMovie UI."
                )

            done = read_u32(
                hproc,
                result_ptr,
            )

            if done == 1:
                print(
                    "[AFDEV] Assault Fire LoadingMovie hide "
                    "routine returned successfully."
                )
                return True

            time.sleep(0.05)

        raise RuntimeError(
            "AF LoadingMovie hide trampoline did not finish."
        )

    finally:
        if suspended:
            kernel32.ResumeThread(hthread)


def stop_loading_movie_on_game_thread(hproc, hthread):
    """
    Execute TGame's own loading-movie stop wrapper (0x0095B1C0, arg=1)
    on the primary/game thread.

    This uses the same one-shot thread-hijack method as the OPEN command:
      - suspend primary thread
      - preserve flags + registers
      - call wrapper with push 1
      - set completion sentinel
      - restore state
      - jump back to exact interrupted EIP
    """
    remote = kernel32.VirtualAllocEx(
        hproc,
        None,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )

    if not remote:
        winerr("VirtualAllocEx(stop movie)")

    remote = int(ctypes.cast(remote, ctypes.c_void_p).value)

    result_ptr = remote + 0x100
    code_ptr = remote + 0x200

    write_remote(
        hproc,
        result_ptr,
        struct.pack("<I", 0xDEADC0DE),
    )

    prev = kernel32.SuspendThread(hthread)
    if prev == 0xFFFFFFFF:
        winerr("SuspendThread(stop movie)")

    suspended = True

    try:
        ctx = WOW64_CONTEXT()
        ctx.ContextFlags = WOW64_CONTEXT_FULL

        if not kernel32.Wow64GetThreadContext(
            hthread,
            ctypes.byref(ctx),
        ):
            winerr("Wow64GetThreadContext(stop movie)")

        original_eip = ctx.Eip

        print(
            f"[AFDEV] StopMovie: game thread paused at "
            f"EIP=0x{original_eip:08X}"
        )

        sc = bytearray()

        sc += b"\x9C"  # pushfd
        sc += b"\x60"  # pushad

        # push 1
        sc += b"\x6A\x01"

        # mov eax, STOP_LOADING_MOVIE_VA
        sc += b"\xB8" + struct.pack(
            "<I",
            STOP_LOADING_MOVIE_VA,
        )

        # call eax
        # 0x95B1C0 returns with ret 4, cleaning the argument.
        sc += b"\xFF\xD0"

        # completion sentinel = 1
        sc += b"\xC7\x05" + struct.pack(
            "<I",
            result_ptr,
        ) + struct.pack(
            "<I",
            1,
        )

        sc += b"\x61"      # popad
        sc += b"\x9D"      # popfd

        # Return to exact interrupted EIP without clobbering registers.
        sc += b"\x68" + struct.pack(
            "<I",
            original_eip,
        )
        sc += b"\xC3"

        write_remote(
            hproc,
            code_ptr,
            bytes(sc),
        )

        print(
            f"[AFDEV] StopMovie trampoline @0x{code_ptr:08X}"
        )
        print(
            f"[AFDEV] Calling 0x{STOP_LOADING_MOVIE_VA:08X}(1)"
        )

        ctx.Eip = code_ptr

        if not kernel32.Wow64SetThreadContext(
            hthread,
            ctypes.byref(ctx),
        ):
            winerr("Wow64SetThreadContext(stop movie)")

        resumed = kernel32.ResumeThread(hthread)
        if resumed == 0xFFFFFFFF:
            winerr("ResumeThread(stop movie)")

        suspended = False

        deadline = time.time() + 10.0

        while time.time() < deadline:
            if not process_alive(hproc):
                raise RuntimeError(
                    "TGame exited while stopping loading movie."
                )

            done = read_u32(
                hproc,
                result_ptr,
            )

            if done == 1:
                print(
                    "[AFDEV] StopMovie wrapper executed successfully."
                )
                return True

            time.sleep(0.05)

        raise RuntimeError(
            "StopMovie game-thread trampoline did not finish."
        )

    finally:
        if suspended:
            kernel32.ResumeThread(hthread)


def wait_for_pending_url_clear(
    hproc,
    engine_ptr,
    timeout=20.0,
):
    """
    Wait until the OPEN request has been consumed.
    Returns True when PendingURL Num becomes zero.
    """
    deadline = time.time() + timeout

    while time.time() < deadline:
        if not process_alive(hproc):
            return False

        text, ptr, num, cap = read_remote_fstring(
            hproc,
            engine_ptr + PENDING_URL_OFFSET,
        )

        print(
            f"[AFDEV] Travel wait: PendingURL={text!r} "
            f"(Num={num} Max={cap})"
        )

        if num == 0:
            return True

        time.sleep(0.5)

    return False


def monitor_travel_state(hproc, engine_ptr, game_root, seconds=30):
    print()
    print("[AFDEV] ===== LIVE TRAVEL / LOADMAP STATE =====")
    print(
        f"[AFDEV] Monitoring for {seconds}s: "
        "GWorld, PendingURL, PendingFlag"
    )

    previous = None
    world_first_seen = None

    for i in range(seconds + 1):
        if not process_alive(hproc):
            print("[AFDEV] TGame exited during state monitor.")
            return

        gworld = safe_read_u32(hproc, GWORLD_PTR_VA)
        pending, pptr, pnum, pmax = read_remote_fstring(
            hproc,
            engine_ptr + PENDING_URL_OFFSET,
        )

        try:
            pflag = read_remote(
                hproc,
                engine_ptr + PENDING_FLAG_OFFSET,
                1,
            )[0]
        except Exception:
            pflag = None

        state = (gworld, pending, pflag, pnum, pmax)

        # Print every 2 sec, plus immediately when state changes.
        if state != previous or i % 2 == 0:
            gworld_text = (
                f"0x{gworld:08X}"
                if gworld is not None
                else "<read-fail>"
            )
            flag_text = (
                f"0x{pflag:02X}"
                if pflag is not None
                else "<read-fail>"
            )

            print(
                f"[STATE +{i:02d}s] "
                f"GWorld={gworld_text} "
                f"PendingFlag={flag_text} "
                f"PendingURL={pending!r} "
                f"(Num={pnum} Max={pmax})"
            )

        if gworld and world_first_seen is None:
            world_first_seen = i
            print(
                f"[AFDEV] >>> GWorld became non-null at +{i}s: "
                f"0x{gworld:08X}"
            )

        previous = state

        if i != seconds:
            time.sleep(1.0)

    print("[AFDEV] ===== END LIVE STATE =====")
    print()

    logs = find_recent_log_files(game_root)
    if logs:
        print_log_tail(logs[0], max_lines=40)
    else:
        print("[AFDEV] No .log file found in common game log locations.")


def inject_exec_on_game_thread(
    hproc,
    hthread,
    engine_ptr,
    log_ptr,
    command,
):
    """
    Run UTGameEngine::Exec(command, *GLog) on the primary TGame thread.

    The trampoline:
      pushfd
      pushad
      mov eax,[GEngine]
      lea ecx,[eax+3Ch]   ; FExec/Exec adjusted this
      mov eax,[GLog]
      push eax             ; second arg: FOutputDevice*
      push command_ptr     ; first arg: TCHAR*
      mov eax,UTGameEngine::Exec
      call eax             ; callee RET 8
      mov [result_ptr],eax
      popad
      popfd
      jmp original_EIP

    Registers/flags and the interrupted EIP are restored afterward.
    """

    command_bytes = (
        command.encode("utf-16le")
        + b"\x00\x00"
    )

    # 4 KB is plenty for command + result + trampoline.
    remote = kernel32.VirtualAllocEx(
        hproc,
        None,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )

    if not remote:
        winerr("VirtualAllocEx")

    remote = int(ctypes.cast(
        remote,
        ctypes.c_void_p,
    ).value)

    command_ptr = remote + 0x000
    result_ptr  = remote + 0x400
    code_ptr    = remote + 0x500

    write_remote(
        hproc,
        command_ptr,
        command_bytes,
    )

    # Sentinel = not executed yet.
    write_remote(
        hproc,
        result_ptr,
        struct.pack("<I", 0xDEADC0DE),
    )

    prev = kernel32.SuspendThread(hthread)

    if prev == 0xFFFFFFFF:
        winerr("SuspendThread")

    suspended = True

    try:
        ctx = WOW64_CONTEXT()
        ctx.ContextFlags = WOW64_CONTEXT_FULL

        if not kernel32.Wow64GetThreadContext(
            hthread,
            ctypes.byref(ctx),
        ):
            winerr("Wow64GetThreadContext")

        original_eip = ctx.Eip

        print(
            f"[AFDEV] Primary/game thread paused at "
            f"EIP=0x{original_eip:08X}"
        )

        # x86 trampoline.
        sc = bytearray()

        sc += b"\x9C"              # pushfd
        sc += b"\x60"              # pushad

        # mov eax,[GENGINE_PTR_VA]
        sc += b"\xA1" + struct.pack(
            "<I",
            GENGINE_PTR_VA,
        )

        # test eax,eax
        sc += b"\x85\xC0"

        # jz -> restore (patched below)
        jz_pos = len(sc)
        sc += b"\x74\x00"

        # IMPORTANT:
        # UEngine/UTGameEngine's Exec implementation is reached through the
        # FExec multiple-inheritance subobject. Static code proves the Exec
        # body dereferences [this-0x3C] to get the real engine/vtable.
        #
        # Therefore:
        #     Exec this = GEngine + 0x3C
        #
        # v0.7 incorrectly used GEngine directly, causing the crash at
        # 0x009C0FF9 after:
        #     mov eax,[esi-3C]
        #
        # lea ecx,[eax+3Ch]
        sc += b"\x8D\x48\x3C"

        # mov eax,[GLOG_PTR_VA]
        sc += b"\xA1" + struct.pack(
            "<I",
            GLOG_PTR_VA,
        )

        # push eax (FOutputDevice*)
        sc += b"\x50"

        # push command_ptr
        sc += b"\x68" + struct.pack(
            "<I",
            command_ptr,
        )

        # mov eax, TGAMEENGINE_EXEC_VA
        # Call the Assault Fire UTGameEngine::Exec override. Unknown/base
        # commands such as OPEN fall through to UGameEngine::Exec.
        sc += b"\xB8" + struct.pack(
            "<I",
            TGAMEENGINE_EXEC_VA,
        )

        # call eax
        sc += b"\xFF\xD0"

        # mov [result_ptr],eax
        sc += b"\xA3" + struct.pack(
            "<I",
            result_ptr,
        )

        restore_pos = len(sc)

        # popad / popfd
        sc += b"\x61\x9D"

        # mov eax,original_eip ; jmp eax
        # EAX was restored by popad, so use push original; ret
        # to avoid clobbering any register.
        sc += b"\x68" + struct.pack(
            "<I",
            original_eip,
        )
        sc += b"\xC3"

        # Fix short JZ displacement.
        disp = restore_pos - (jz_pos + 2)

        if not -128 <= disp <= 127:
            raise RuntimeError(
                "internal trampoline branch out of range"
            )

        sc[jz_pos + 1] = disp & 0xFF

        write_remote(
            hproc,
            code_ptr,
            bytes(sc),
        )

        print(
            f"[AFDEV] Trampoline @0x{code_ptr:08X}"
        )
        print(
            f"[AFDEV] Command    @0x{command_ptr:08X}: "
            f"{command}"
        )
        exec_this = (engine_ptr + 0x3C) & 0xFFFFFFFF

        print(
            f"[AFDEV] GEngine=0x{engine_ptr:08X} "
            f"GLog=0x{log_ptr:08X}"
        )
        print(
            f"[AFDEV] Exec this = GEngine+0x3C = "
            f"0x{exec_this:08X}"
        )

        # Useful structural diagnostic. In this build the Exec implementation
        # uses [this-0x3C], which must resolve back to the actual GEngine.
        try:
            main_vtable = read_u32(hproc, engine_ptr)
            subobject_word = read_u32(hproc, exec_this)
            print(
                f"[AFDEV] [GEngine]      = 0x{main_vtable:08X}"
            )
            print(
                f"[AFDEV] [GEngine+3C]   = 0x{subobject_word:08X}"
            )
        except Exception as e:
            print(
                f"[AFDEV] Exec-layout diagnostic skipped: {e}"
            )

        ctx.Eip = code_ptr

        if not kernel32.Wow64SetThreadContext(
            hthread,
            ctypes.byref(ctx),
        ):
            winerr("Wow64SetThreadContext")

        resumed = kernel32.ResumeThread(hthread)

        if resumed == 0xFFFFFFFF:
            winerr("ResumeThread(trampoline)")

        suspended = False

        # Wait for trampoline to write the UTGameEngine::Exec result.
        deadline = time.time() + 60.0

        while time.time() < deadline:
            if not process_alive(hproc):
                raise RuntimeError(
                    "TGame exited while executing UE3 OPEN."
                )

            result = read_u32(
                hproc,
                result_ptr,
            )

            if result != 0xDEADC0DE:
                print(
                    f"[AFDEV] UTGameEngine::Exec returned: "
                    f"0x{result:08X}"
                )

                # Keep the allocation alive. It is harmless and avoids any
                # tiny race with the trampoline's final instruction.
                return result

            time.sleep(0.05)

        raise RuntimeError(
            "The game-thread Exec trampoline did not finish within 60 sec."
        )

    finally:
        if suspended:
            kernel32.ResumeThread(hthread)


def main():
    if os.name != "nt":
        raise SystemExit("Windows only.")

    ensure_admin()

    print("[AFDEV] Running elevated: YES")

    ap = argparse.ArgumentParser(
        description=(
            "Assault Fire PH offline UE3 game-thread map loader"
        )
    )

    ap.add_argument(
        "--game-dir",
        default=str(DEFAULT_GAME_DIR),
    )
    ap.add_argument(
        "--map",
        default=DEFAULT_MAP,
    )
    ap.add_argument(
        "--game",
        default=DEFAULT_GAME_CLASS,
        help=(
            "GameInfo class forced into the UE3 travel URL "
            f"(default: {DEFAULT_GAME_CLASS})"
        ),
    )
    ap.add_argument(
        "--max-players",
        type=int,
        default=4,
        help=(
            "MaxPlayers URL option for the listen server "
            "(default: 4; AFDEV itself already occupies one local slot)"
        ),
    )

    ap.add_argument(
        "--delay",
        type=float,
        default=3.0,
        help=(
            "extra seconds to wait after GEngine/GLog become valid "
            "(default 3)"
        ),
    )
    ap.add_argument(
        "--resx",
        type=int,
        default=1280,
    )
    ap.add_argument(
        "--resy",
        type=int,
        default=720,
    )

    args = ap.parse_args()

    game_dir = Path(args.game_dir).resolve()
    game_root = game_dir.parent.parent
    exe = game_dir / "TGame_AFDEV.exe"

    if not exe.is_file():
        raise SystemExit(
            f"Missing:\n  {exe}\n\n"
            "Keep the TGame_AFDEV.exe staged by the previous loader."
        )

    digest = sha256_file(exe)

    print(
        "[AFDEV] Assault Fire PH GAME-THREAD MAP TEST"
    )
    print(
        f"[AFDEV] GAME DIR : {game_dir}"
    )
    print(
        f"[AFDEV] DEV EXE  : {exe}"
    )
    print(
        f"[AFDEV] SHA256   : {digest}"
    )

    if digest.lower() != EXPECTED_SHA256:
        raise SystemExit(
            "Unexpected TGame_AFDEV.exe SHA-256."
        )

    # Confirm map exists before launching.
    map_name = Path(args.map).stem
    maps_root = (
        game_root
        / "TGame"
        / "CookedPC"
        / "Maps"
    )

    map_path = None

    if maps_root.is_dir():
        for p in maps_root.rglob("*.udk"):
            if p.stem.lower() == map_name.lower():
                map_path = p
                break

    if not map_path:
        raise SystemExit(
            f"Map not found:\n  {map_name}\n"
            f"under:\n  {maps_root}"
        )

    print(
        f"[AFDEV] MAP FOUND: {map_path}"
    )

    scan_gameinfo_config(
        game_root,
        map_name,
    )

    # Do NOT pass a map, EXEC=, or -q on the command line.
    # v0.7 will issue OPEN itself after the UE3 engine is live.
    cmd = [
        str(exe),
        "-log",
        "-windowed",
        f"ResX={args.resx}",
        f"ResY={args.resy}",
    ]

    cmdline = subprocess.list2cmdline(cmd)

    print(
        f"[AFDEV] CMD      : {cmdline}"
    )
    print(
        "[AFDEV] Creating TGame suspended..."
    )

    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)

    pi = PROCESS_INFORMATION()
    mutable = ctypes.create_unicode_buffer(
        cmdline
    )

    if not kernel32.CreateProcessW(
        str(exe),
        mutable,
        None,
        None,
        False,
        CREATE_SUSPENDED |
        CREATE_UNICODE_ENVIRONMENT,
        None,
        str(game_dir),
        ctypes.byref(si),
        ctypes.byref(pi),
    ):
        winerr("CreateProcessW")

    try:
        print(
            f"[AFDEV] PID={pi.dwProcessId} "
            f"Thread={pi.dwThreadId}"
        )

        try:
            verify_and_patch(
                pi.hProcess,
                LOGININFO_FAIL_VA,
                LOGININFO_EXPECT,
                LOGININFO_PATCH,
                "TCLS LoginInfo bypass",
            )

            verify_and_patch(
                pi.hProcess,
                DEVLOGIN_VA,
                DEVLOGIN_EXPECT,
                DEVLOGIN_OFFLINE_FAIL,
                "TGTenio::DevLogin offline FAIL stub",
            )

            # v21: give only this listen-server process a different named
            # mutex, so a normal TCLS-launched TGame can run beside it.
            mutex_now = read_remote(
                pi.hProcess,
                SINGLE_INSTANCE_MUTEX_VA,
                len(SINGLE_INSTANCE_MUTEX_ORIGINAL),
            )
            print(
                f"[AFDEV] Single-instance mutex @0x{SINGLE_INSTANCE_MUTEX_VA:08X}"
            )
            if mutex_now != SINGLE_INSTANCE_MUTEX_ORIGINAL:
                raise RuntimeError(
                    "single-instance mutex bytes do not match validated image"
                )

            print(
                "[AFDEV]   original: "
                + mutex_now.decode("utf-16le").rstrip("\0")
            )

            write_remote(
                pi.hProcess,
                SINGLE_INSTANCE_MUTEX_VA,
                SINGLE_INSTANCE_MUTEX_SERVER,
            )

            mutex_verify = read_remote(
                pi.hProcess,
                SINGLE_INSTANCE_MUTEX_VA,
                len(SINGLE_INSTANCE_MUTEX_SERVER),
            )
            if mutex_verify != SINGLE_INSTANCE_MUTEX_SERVER:
                raise RuntimeError("server mutex isolation verification failed")

            print(
                "[AFDEV]   server  : "
                + mutex_verify.decode("utf-16le").rstrip("\0")
            )
            print(
                "[AFDEV]   result  : normal TGame mutex remains free"
            )

            stage_marker_ptr, stage_instrumentation_base = (
                install_loadmap_stage_hooks(
                    pi.hProcess,
                )
            )

            boot = read_u32(
                pi.hProcess,
                IS_BOOT_FROM_TCLS_VA,
            )

            print(
                f"[AFDEV] IsBootFromTCLS="
                f"0x{boot:08X}"
            )

            # Keep true direct/dev state.
            if boot != 0:
                write_remote(
                    pi.hProcess,
                    IS_BOOT_FROM_TCLS_VA,
                    b"\x00\x00\x00\x00",
                )

        except Exception:
            kernel32.TerminateProcess(
                pi.hProcess,
                0xAF07,
            )
            raise

        prev = kernel32.ResumeThread(
            pi.hThread
        )

        if prev == 0xFFFFFFFF:
            winerr("ResumeThread")

        print(
            "[AFDEV] TGame resumed; waiting for UE3..."
        )

        engine_ptr, log_ptr = wait_for_engine(
            pi.hProcess,
            timeout=20.0,
        )

        print(
            f"[AFDEV] UE3 ready: "
            f"GEngine=0x{engine_ptr:08X}, "
            f"GLog=0x{log_ptr:08X}"
        )

        if args.delay > 0:
            print(
                f"[AFDEV] Waiting {args.delay:.1f}s "
                "for frontend/render initialization..."
            )
            time.sleep(args.delay)

        if not process_alive(pi.hProcess):
            raise RuntimeError(
                "TGame exited before OPEN injection."
            )

        game_class = args.game.strip()

        # v26: production target is Survival / The Altar.  The previous v25
        # test accidentally inherited tutorial defaults, which caused the
        # real client to reach that listen server and receive
        # Engine.GameMessage.MaxedOutMessage.  Keep an explicit banner here.
        print(
            f"[AFDEV-v26] PVE target: map={map_name!r} "
            f"game={game_class!r}"
        )

        max_players = max(2, int(args.max_players))

        if game_class:
            travel_target = (
                f"{map_name}?game={game_class}?listen"
                f"?MaxPlayers={max_players}"
            )
        else:
            travel_target = (
                f"{map_name}?listen?MaxPlayers={max_players}"
            )

        command = f"OPEN {travel_target}"

        print(
            f"[AFDEV] Forced GameInfo travel target: "
            f"{travel_target}"
        )

        # v24: start the GamePlayers[0] observer guard BEFORE OPEN.
        # It remains inert in the frontend because the PC vtable is not the
        # verified PVE vtable.  As soon as TGSV3's local synthetic PC exists,
        # its PRI is marked bAlwaysObserver so it cannot consume GameStart.
        pve_host_guard_state, pve_host_guard_thread = (
            arm_pve_synthetic_host_observer_v24(
                pi.hProcess,
                engine_ptr,
            )
        )

        result = inject_exec_on_game_thread(
            pi.hProcess,
            pi.hThread,
            engine_ptr,
            log_ptr,
            command,
        )

        print()
        print(
            "[AFDEV] Game-thread UTGameEngine::Exec completed."
        )
        print(
            f"[AFDEV] Command: {command}"
        )
        print(
            f"[AFDEV] Exec return: {result}"
        )
        print()

        highest_stage = monitor_loadmap_stage(
            pi.hProcess,
            stage_marker_ptr,
            seconds=30,
        )

        if highest_stage < 7:
            print(
                "[AFDEV] LoadMap did NOT reach the final milestone."
            )
            sample_primary_thread(
                pi.hProcess,
                pi.hThread,
                samples=16,
                interval=0.25,
            )
        else:
            print(
                "[AFDEV] LoadMap completed all seven instrumented stages."
            )

        print()
        print(
            "[AFDEV] Waiting for OPEN travel request to be consumed..."
        )

        cleared = wait_for_pending_url_clear(
            pi.hProcess,
            engine_ptr,
            timeout=20.0,
        )

        if cleared:
            gworld_now = safe_read_u32(
                pi.hProcess,
                GWORLD_PTR_VA,
            )

            print(
                "[AFDEV] PendingURL cleared."
            )
            print(
                f"[AFDEV] Current GWorld = "
                f"{('0x%08X' % gworld_now) if gworld_now else 'NULL'}"
            )

            players_before = inspect_local_players(
                pi.hProcess,
                engine_ptr,
                label=" BEFORE UI hide",
            )

            print(
                "[AFDEV] Natural loading-completion mode: "
                "NOT forcing UE3 fullscreen-movie stop."
            )
            print(
                "[AFDEV] Natural loading-completion mode: "
                "NOT forcing Assault Fire LoadingMovie hide."
            )
            print(
                "[AFDEV] Leaving the stock movie/streaming completion path "
                "intact so the PlayerController load-complete callback can fire."
            )

            # IMPORTANT:
            # Earlier loader versions manually called:
            #   stop_loading_movie_on_game_thread(...)
            #   hide_af_loading_ui_on_game_thread(...)
            #
            # Current live UnrealScript analysis shows the stock completion path
            # enters an externally-triggered function containing "UT_loadmovie",
            # which sets bInitialProcessingComplete=TRUE and calls the
            # "Load Complete Player:" handler.  Forcing the movie/UI closed here
            # can bypass that native/delegate callback.  Do not short-circuit it.
            time.sleep(2.0)

            players_after = inspect_local_players(
                pi.hProcess,
                engine_ptr,
                label=" AFTER UI hide",
            )

            lp0, pc0 = wait_for_player_controller(
                pi.hProcess,
                engine_ptr,
                timeout=10.0,
            )

            print(
                f"[AFDEV] Controller wait result: "
                f"ULocalPlayer=0x{lp0:08X} "
                f"PlayerController=0x{pc0:08X}"
            )

            final_gworld = wait_for_nonnull_gworld(
                pi.hProcess,
                timeout=10.0,
            )

            print(
                f"[AFDEV] Final GWorld after transition wait: "
                f"0x{final_gworld:08X}"
            )

            authority = inspect_authority_world(
                pi.hProcess,
                pi.hThread,
                final_gworld,
            )

            # v23: TGTeamMatch_Tutorial still returns
            # Engine.GameMessage.MaxedOutMessage even when the OPEN URL
            # contains ?MaxPlayers=4.  Test the live GameInfo object directly
            # through UE3's native SET/GETALL console support after LoadMap,
            # when WorldInfo.Game definitely exists.
            print()
            print("[AFDEV] ===== RUNTIME GAMEINFO CAPACITY OVERRIDE =====")

            capacity_commands = [
                "GETALL GameInfo MaxPlayers",
                f"SET GameInfo MaxPlayers {max_players}",
                f"SET GameInfo MaxSpectators {max_players}",
                "GETALL GameInfo MaxPlayers",
                "GETALL GameInfo MaxSpectators",
            ]

            for cap_cmd in capacity_commands:
                try:
                    cap_result = inject_exec_on_game_thread(
                        pi.hProcess,
                        pi.hThread,
                        engine_ptr,
                        log_ptr,
                        cap_cmd,
                    )
                    print(
                        f"[AFDEV] CAPACITY CMD result=0x{cap_result:08X}: "
                        f"{cap_cmd}"
                    )
                except Exception as e:
                    print(
                        f"[AFDEV] CAPACITY CMD failed: {cap_cmd}: {e}"
                    )

            print("[AFDEV] ===== END RUNTIME CAPACITY OVERRIDE =====")
            print()

            scan_world_for_tggame_and_tgpawn(
                pi.hProcess,
                final_gworld,
            )

            scan_exact_tgplayercontroller(
                pi.hProcess,
                lp0,
                pc0,
                final_gworld,
            )

            global_game_hits, global_pc_hits, global_pawn_hits = (
                scan_tutorial_runtime_globally(
                    pi.hProcess,
                )
            )

            print(
                "[AFDEV] v23 is intentionally NOT running the old "
                "console-command pawn probes. This run is focused on "
                "whether ?listen creates a real authoritative GameInfo."
            )

            print(
                "[AFDEV] NOTE: v0.13's borrowed +0x66C/+0x670/+0x688 "
                "controller offsets were invalid for Assault Fire and "
                "are intentionally NOT used by v0.14."
            )

            print(
                "[AFDEV] Both loading-screen paths have now been "
                "explicitly stopped/hidden."
            )
        else:
            print(
                "[AFDEV] PendingURL did not clear within 20 seconds; "
                "not forcing StopMovie yet."
            )

        monitor_travel_state(
            pi.hProcess,
            engine_ptr,
            game_root,
            seconds=8,
        )

        print()
        print(
            "[AFDEV-v24] Synthetic-host observer guard status: "
            f"first_patch={pve_host_guard_state['first_patch']} "
            f"patch_count={pve_host_guard_state['patch_count']} "
            f"last_pc=0x{pve_host_guard_state['last_pc']:08X} "
            f"last_pri=0x{pve_host_guard_state['last_pri']:08X}"
        )
        if not pve_host_guard_state["first_patch"]:
            print(
                "[AFDEV-v24] WARNING: the guard never saw the verified "
                "PVE GamePlayers[0] controller. Do NOT interpret this run "
                "as a test of the host-observer hypothesis."
            )

        print(
            "Send the console output and a screenshot of what is visible "
            "after the StopMovie call."
        )

        kernel32.WaitForSingleObject(
            pi.hProcess,
            INFINITE,
        )

    finally:
        if pi.hThread:
            kernel32.CloseHandle(
                pi.hThread
            )

        if pi.hProcess:
            kernel32.CloseHandle(
                pi.hProcess
            )


if __name__ == "__main__":
    main()