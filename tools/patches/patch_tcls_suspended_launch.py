#!/usr/bin/env python3
"""
Assault Fire PH - debugger-free TCLS -> TGame suspended launch helper.

Purpose
-------
For the validated Assault Fire PH v1.0.0.24 preservation setup, temporarily
patch the loaded TCLS.dll so its CreateProcessW call launches TGame.exe with
CREATE_SUSPENDED.  As soon as the new child TGame process is observed, this
helper restores TCLS.dll, applies the repository's verified TGame datetime
runtime patch while the child is still suspended, and resumes TGame.

Nothing on disk is modified.  The TCLS patch is process-memory only and is
restored immediately after child creation.

Validated TCLS patch site
-------------------------
    TCLS.dll + 0x000584E0

Expected original bytes:
    8B 55 18 52       mov edx,[ebp+18h] / push edx

Temporary bytes:
    6A 04 90 90       push CREATE_SUSPENDED / nop / nop

Safety rules
------------
* The four original bytes MUST match exactly or nothing is patched.
* Run this only with the validated PH client build / a build independently
  verified to have the same instruction signature.
* Do not distribute a modified TCLS.dll; this helper patches memory only.
* The original TCLS bytes are restored in a finally path on success, timeout,
  Ctrl+C, or most Python exceptions.
* If the TGame datetime patch fails, TGame is intentionally left suspended
  rather than resumed into a known crash path.

Recommended usage
-----------------
1. Start the local emulator.
2. Start client.exe / TCLS normally and log in until START is available.
3. Close/detach x32dbg if it is running.
4. Run from the repository root:

       .\.venv\Scripts\python.exe .\tools\patches\patch_tcls_suspended_launch.py

5. When the helper prints "TCLS ARMED", click START in the launcher.

The helper imports patch_tgame_datetime.py from the same folder and applies
that already-verified runtime compatibility patch before resuming TGame.

Use --leave-suspended to apply the TCLS + datetime patches but leave TGame
suspended for manual inspection.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import sys
import time
from ctypes import wintypes

if os.name != "nt":
    raise SystemExit("This helper must be run on Windows.")

try:
    import patch_tgame_datetime as datetime_patch
except Exception as exc:
    raise SystemExit(
        "Could not import tools/patches/patch_tgame_datetime.py. "
        "Keep both scripts in the same folder.\n"
        f"Import error: {exc}"
    )

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

CLIENT_PROCESS = "client.exe"
GAME_PROCESS = "TGame.exe"
TCLS_MODULE = "TCLS.dll"

TCLS_CREATE_FLAGS_RVA = 0x000584E0
TCLS_CREATE_FLAGS_EXPECTED = bytes.fromhex("8B 55 18 52")
TCLS_CREATE_FLAGS_PATCH = bytes.fromhex("6A 04 90 90")

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020

THREAD_SUSPEND_RESUME = 0x0002
THREAD_QUERY_INFORMATION = 0x0040

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
MAX_PATH = 260

MEM_IMAGE = 0x01000000
PAGE_EXECUTE_READWRITE = 0x40

ULONG_PTR = ctypes.c_size_t


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ULONG_PTR),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * MAX_PATH),
    ]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


class FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    ]


kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

kernel32.Process32FirstW.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(PROCESSENTRY32W),
]
kernel32.Process32FirstW.restype = wintypes.BOOL

kernel32.Process32NextW.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(PROCESSENTRY32W),
]
kernel32.Process32NextW.restype = wintypes.BOOL

kernel32.Thread32First.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(THREADENTRY32),
]
kernel32.Thread32First.restype = wintypes.BOOL

kernel32.Thread32Next.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(THREADENTRY32),
]
kernel32.Thread32Next.restype = wintypes.BOOL

kernel32.OpenProcess.argtypes = [
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD,
]
kernel32.OpenProcess.restype = wintypes.HANDLE

kernel32.OpenThread.argtypes = [
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD,
]
kernel32.OpenThread.restype = wintypes.HANDLE

kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    wintypes.LPVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.LPCVOID,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.WriteProcessMemory.restype = wintypes.BOOL

kernel32.VirtualProtectEx.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    ctypes.c_size_t,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.VirtualProtectEx.restype = wintypes.BOOL

kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t

kernel32.FlushInstructionCache.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    ctypes.c_size_t,
]
kernel32.FlushInstructionCache.restype = wintypes.BOOL

kernel32.GetThreadTimes.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(FILETIME),
    ctypes.POINTER(FILETIME),
    ctypes.POINTER(FILETIME),
    ctypes.POINTER(FILETIME),
]
kernel32.GetThreadTimes.restype = wintypes.BOOL

kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
kernel32.ResumeThread.restype = wintypes.DWORD

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

psapi.GetMappedFileNameW.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    wintypes.LPWSTR,
    wintypes.DWORD,
]
psapi.GetMappedFileNameW.restype = wintypes.DWORD


def winerr(prefix: str) -> RuntimeError:
    err = ctypes.get_last_error()
    return RuntimeError(
        f"{prefix} failed: WinError {err}: {ctypes.FormatError(err).strip()}"
    )


def process_rows():
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE:
        raise winerr("CreateToolhelp32Snapshot(PROCESS)")

    out = []
    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(pe)
        ok = kernel32.Process32FirstW(snap, ctypes.byref(pe))
        while ok:
            out.append(
                {
                    "pid": int(pe.th32ProcessID),
                    "ppid": int(pe.th32ParentProcessID),
                    "name": pe.szExeFile,
                }
            )
            ok = kernel32.Process32NextW(snap, ctypes.byref(pe))
    finally:
        kernel32.CloseHandle(snap)

    return out


def find_process(exe_name: str):
    wanted = exe_name.lower()
    for row in process_rows():
        if row["name"].lower() == wanted:
            return row
    return None


def pids_for(exe_name: str):
    wanted = exe_name.lower()
    return {
        row["pid"]
        for row in process_rows()
        if row["name"].lower() == wanted
    }


def wait_for_process(exe_name: str, timeout: float):
    deadline = time.time() + timeout
    last_msg = 0.0
    while time.time() < deadline:
        row = find_process(exe_name)
        if row:
            return row
        now = time.time()
        if now - last_msg >= 5.0:
            print(f"[WAIT] {exe_name} is not running yet ...", flush=True)
            last_msg = now
        time.sleep(0.20)
    return None


def open_process_rw(pid: int):
    rights = (
        PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE
    )
    handle = kernel32.OpenProcess(rights, False, pid)
    if not handle:
        raise winerr(f"OpenProcess({pid})")
    return handle


def find_image_mapping(process, basename: str):
    """Find a mapped image without relying on the target loader module list."""
    wanted = "\\" + basename.lower()
    addr = 0
    seen_allocations = set()
    mbi = MEMORY_BASIC_INFORMATION()

    while addr < 0x80000000:
        ctypes.set_last_error(0)
        got = kernel32.VirtualQueryEx(
            process,
            ctypes.c_void_p(addr),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi),
        )
        if not got:
            break

        base = int(mbi.BaseAddress or addr)
        region = int(mbi.RegionSize or 0)
        allocation = int(mbi.AllocationBase or 0)

        if mbi.Type == MEM_IMAGE and allocation and allocation not in seen_allocations:
            seen_allocations.add(allocation)
            buf = ctypes.create_unicode_buffer(1024)
            n = psapi.GetMappedFileNameW(
                process,
                ctypes.c_void_p(allocation),
                buf,
                len(buf),
            )
            if n:
                path = buf.value
                if path.lower().endswith(wanted):
                    return allocation, path

        if region <= 0:
            addr += 0x1000
        else:
            nxt = base + region
            if nxt <= addr:
                break
            addr = nxt

    return None, None


def read_memory(process, address: int, size: int) -> bytes:
    buf = (ctypes.c_ubyte * size)()
    got = ctypes.c_size_t(0)
    if not kernel32.ReadProcessMemory(
        process,
        ctypes.c_void_p(address),
        buf,
        size,
        ctypes.byref(got),
    ):
        raise winerr(f"ReadProcessMemory(0x{address:08X})")
    if got.value != size:
        raise RuntimeError(
            f"Short read at 0x{address:08X}: {got.value}/{size} bytes"
        )
    return bytes(buf)


def write_code(process, address: int, expected: bytes, replacement: bytes, label: str):
    if len(expected) != len(replacement):
        raise ValueError("Expected/replacement byte lengths differ")

    current = read_memory(process, address, len(expected))
    if current != expected:
        raise RuntimeError(
            f"{label} signature mismatch at 0x{address:08X}.\n"
            f"Expected: {expected.hex(' ')}\n"
            f"Found:    {current.hex(' ')}\n"
            "Nothing was changed."
        )

    old_protect = wintypes.DWORD(0)
    if not kernel32.VirtualProtectEx(
        process,
        ctypes.c_void_p(address),
        len(replacement),
        PAGE_EXECUTE_READWRITE,
        ctypes.byref(old_protect),
    ):
        raise winerr(f"VirtualProtectEx({label})")

    try:
        buf = (ctypes.c_ubyte * len(replacement)).from_buffer_copy(replacement)
        wrote = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(
            process,
            ctypes.c_void_p(address),
            buf,
            len(replacement),
            ctypes.byref(wrote),
        ):
            raise winerr(f"WriteProcessMemory({label})")
        if wrote.value != len(replacement):
            raise RuntimeError(
                f"Short write for {label}: {wrote.value}/{len(replacement)} bytes"
            )
        kernel32.FlushInstructionCache(
            process, ctypes.c_void_p(address), len(replacement)
        )
    finally:
        ignored = wintypes.DWORD(0)
        kernel32.VirtualProtectEx(
            process,
            ctypes.c_void_p(address),
            len(replacement),
            old_protect.value,
            ctypes.byref(ignored),
        )

    verify = read_memory(process, address, len(replacement))
    if verify != replacement:
        raise RuntimeError(
            f"{label} verification failed: read back {verify.hex(' ')}"
        )


def wait_for_module(process, basename: str, timeout: float):
    deadline = time.time() + timeout
    while time.time() < deadline:
        base, path = find_image_mapping(process, basename)
        if base:
            return int(base), path
        time.sleep(0.10)
    return None, None


def wait_for_new_game(existing_pids: set[int], parent_pid: int, timeout: float):
    deadline = time.time() + timeout
    while time.time() < deadline:
        candidates = [
            row
            for row in process_rows()
            if row["name"].lower() == GAME_PROCESS.lower()
            and row["pid"] not in existing_pids
        ]
        if candidates:
            children = [row for row in candidates if row["ppid"] == parent_pid]
            return (children or candidates)[0]
        time.sleep(0.05)
    return None


def filetime_value(ft: FILETIME) -> int:
    return (int(ft.dwHighDateTime) << 32) | int(ft.dwLowDateTime)


def primary_thread_id(pid: int):
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snap == INVALID_HANDLE_VALUE:
        raise winerr("CreateToolhelp32Snapshot(THREAD)")

    found = []
    try:
        te = THREADENTRY32()
        te.dwSize = ctypes.sizeof(te)
        ok = kernel32.Thread32First(snap, ctypes.byref(te))
        while ok:
            if int(te.th32OwnerProcessID) == pid:
                tid = int(te.th32ThreadID)
                hthread = kernel32.OpenThread(
                    THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME,
                    False,
                    tid,
                )
                if hthread:
                    try:
                        create = FILETIME()
                        exit_ft = FILETIME()
                        kernel = FILETIME()
                        user = FILETIME()
                        if kernel32.GetThreadTimes(
                            hthread,
                            ctypes.byref(create),
                            ctypes.byref(exit_ft),
                            ctypes.byref(kernel),
                            ctypes.byref(user),
                        ):
                            found.append((filetime_value(create), tid))
                    finally:
                        kernel32.CloseHandle(hthread)
            ok = kernel32.Thread32Next(snap, ctypes.byref(te))
    finally:
        kernel32.CloseHandle(snap)

    if not found:
        return None
    found.sort()
    return found[0][1]


def resume_primary_thread(pid: int):
    tid = primary_thread_id(pid)
    if tid is None:
        raise RuntimeError(f"Could not identify a TGame thread for PID {pid}")

    hthread = kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, tid)
    if not hthread:
        raise winerr(f"OpenThread({tid})")

    try:
        previous = int(kernel32.ResumeThread(hthread))
        if previous == 0xFFFFFFFF:
            raise winerr(f"ResumeThread({tid})")
        if previous == 0:
            raise RuntimeError(
                f"TGame primary thread {tid} was not suspended; refusing to guess."
            )
        print(
            f"[RESUME] TGame PID={pid} primary TID={tid} "
            f"previous_suspend_count={previous}"
        )
    finally:
        kernel32.CloseHandle(hthread)


def x32dbg_running() -> bool:
    return find_process("x32dbg.exe") is not None


def parse_args():
    ap = argparse.ArgumentParser(
        description="Debugger-free TCLS -> suspended TGame launch helper"
    )
    ap.add_argument(
        "--timeout",
        type=float,
        default=300.0,
        help="seconds to wait for client/TGame (default: 300)",
    )
    ap.add_argument(
        "--leave-suspended",
        action="store_true",
        help="apply TCLS + datetime patches but do not resume TGame",
    )
    return ap.parse_args()


def main():
    args = parse_args()

    print("Assault Fire PH - TCLS suspended-launch helper")
    print("Runtime-only; no game DLL/EXE is modified on disk.")
    print()

    if x32dbg_running():
        raise RuntimeError(
            "x32dbg.exe is running. Close/detach it before using the clean "
            "launcher path, then run this helper again."
        )

    print(f"[WAIT] Looking for {CLIENT_PROCESS} / {TCLS_MODULE} ...")
    client = wait_for_process(CLIENT_PROCESS, args.timeout)
    if not client:
        raise RuntimeError(
            f"Timed out waiting for {CLIENT_PROCESS}. Start the Assault Fire "
            "launcher, log in until START is available, then retry."
        )

    client_pid = client["pid"]
    hclient = open_process_rw(client_pid)
    patch_site = None
    tcls_armed = False

    try:
        tcls_base, tcls_path = wait_for_module(hclient, TCLS_MODULE, 15.0)
        if not tcls_base:
            raise RuntimeError(
                f"Found {CLIENT_PROCESS} PID={client_pid}, but {TCLS_MODULE} "
                "was not mapped. Leave the launcher at START and retry."
            )

        patch_site = tcls_base + TCLS_CREATE_FLAGS_RVA
        print(f"[TCLS] client PID={client_pid}")
        print(f"[TCLS] base=0x{tcls_base:08X}")
        print(f"[TCLS] path={tcls_path}")
        print(f"[TCLS] patch site=0x{patch_site:08X} (+0x{TCLS_CREATE_FLAGS_RVA:X})")

        existing_tgame = pids_for(GAME_PROCESS)
        if existing_tgame:
            print(
                "[NOTE] Existing TGame PID(s) will be ignored: "
                + ", ".join(str(x) for x in sorted(existing_tgame))
            )

        write_code(
            hclient,
            patch_site,
            TCLS_CREATE_FLAGS_EXPECTED,
            TCLS_CREATE_FLAGS_PATCH,
            "TCLS CREATE_SUSPENDED",
        )
        tcls_armed = True

        print()
        print("TCLS ARMED")
        print("  original :", TCLS_CREATE_FLAGS_EXPECTED.hex(" "))
        print("  temporary:", TCLS_CREATE_FLAGS_PATCH.hex(" "))
        print()
        print("Click START in the Assault Fire launcher now.")
        print(f"Waiting for a new {GAME_PROCESS} child ...")

        child = wait_for_new_game(existing_tgame, client_pid, args.timeout)
        if not child:
            raise RuntimeError(
                f"Timed out waiting for a new {GAME_PROCESS}. TCLS will now "
                "be restored."
            )

        game_pid = child["pid"]
        print(
            f"[CHILD] {GAME_PROCESS} PID={game_pid} PPID={child['ppid']} "
            f"(launcher PID={client_pid})"
        )

        write_code(
            hclient,
            patch_site,
            TCLS_CREATE_FLAGS_PATCH,
            TCLS_CREATE_FLAGS_EXPECTED,
            "TCLS restore",
        )
        tcls_armed = False
        print("[TCLS] Restored original CreateProcessW creation-flag bytes.")

    finally:
        if tcls_armed and patch_site is not None:
            try:
                current = read_memory(hclient, patch_site, len(TCLS_CREATE_FLAGS_PATCH))
                if current == TCLS_CREATE_FLAGS_PATCH:
                    write_code(
                        hclient,
                        patch_site,
                        TCLS_CREATE_FLAGS_PATCH,
                        TCLS_CREATE_FLAGS_EXPECTED,
                        "TCLS emergency restore",
                    )
                    print("[TCLS] Emergency restore completed.")
                elif current == TCLS_CREATE_FLAGS_EXPECTED:
                    print("[TCLS] Original bytes were already restored.")
                else:
                    print(
                        "[WARNING] TCLS patch-site bytes changed unexpectedly; "
                        "refusing to overwrite unknown code."
                    )
            except Exception as restore_exc:
                print(f"[WARNING] Could not restore TCLS automatically: {restore_exc}")
        kernel32.CloseHandle(hclient)

    hgame = open_process_rw(game_pid)
    try:
        game_base, game_path = wait_for_module(hgame, GAME_PROCESS, 15.0)
        if not game_base:
            raise RuntimeError(
                "TGame was created, but its main image mapping could not be found. "
                "The child is being left suspended."
            )
        print(f"[TGAME] base=0x{game_base:08X}")
        print(f"[TGAME] path={game_path}")
    finally:
        kernel32.CloseHandle(hgame)

    try:
        datetime_patch.patch_process(game_pid, game_base)
    except Exception:
        print()
        print(
            "[SAFE STOP] TGame remains suspended because the datetime patch "
            "did not complete successfully."
        )
        raise

    if args.leave_suspended:
        print()
        print("[DONE] TGame is patched and intentionally left suspended.")
        print(f"       PID={game_pid}")
        return

    resume_primary_thread(game_pid)
    print()
    print("DONE")
    print("  TCLS was restored.")
    print("  TGame datetime compatibility patch is active.")
    print("  TGame primary thread was resumed.")
    print("  Watch the emulator for OWNER=TGame.exe ROLE/ZONE connections.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled.")
        sys.exit(130)
    except Exception as exc:
        print(f"\nERROR: {exc}")
        print()
        print(
            "If Windows denied process-memory access, run PowerShell as "
            "Administrator. If the byte signature differs, do not force the "
            "patch on that client build."
        )
        sys.exit(1)
