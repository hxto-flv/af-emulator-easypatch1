#!/usr/bin/env python3
"""
Assault Fire / TGame datetime runtime patcher.

Purpose
-------
Automates the x32dbg patch we proved manually at TGame.exe+0x10B9510
(VA 0x014B9510 when the image base is 0x00400000).

When that function is entered with year < 1900, the injected trampoline
replaces the seven date/time arguments with:

    year   = 2026
    month  = 9
    day    = 19
    hour   = 12
    minute = 0
    second = 0
    isdst  = -1

Then it executes the original overwritten prologue and returns to the
original TGame code at +8.

This is a *runtime-only* patch. It does not modify TGame.exe on disk.

Usage
-----
    python patch_tgame_datetime.py

You can start this script first and then launch TGame.exe.  It waits for
TGame.exe, patches it once, prints PATCHED, and exits.

Run the terminal as Administrator if OpenProcess/WriteProcessMemory is denied.
"""

import ctypes
import os
import struct
import sys
import time
from ctypes import wintypes

if os.name != "nt":
    raise SystemExit("This patcher must be run on Windows.")

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# ---------------------------------------------------------------------------
# Target build / patch constants
# ---------------------------------------------------------------------------

# Accept either the standard or the no-anti-cheat variant.
PROCESS_NAMES = ["TGame.exe", "TGame(No Anti Cheat).exe"]

# 0x014B9510 - 0x00400000
TARGET_RVA = 0x010B9510

# We overwrite exactly these first 8 bytes:
#   83 EC 24          sub esp,24
#   53                push ebx
#   8B 5C 24 2C      mov ebx,[esp+2C]
EXPECTED_ORIGINAL = bytes.fromhex("83 EC 24 53 8B 5C 24 2C")

# Process access rights.
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000

PAGE_EXECUTE_READWRITE = 0x40

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
MAX_PATH = 260


# ---------------------------------------------------------------------------
# Toolhelp structures
# ---------------------------------------------------------------------------

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


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_ubyte)),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.WCHAR * 256),
        ("szExePath", wintypes.WCHAR * MAX_PATH),
    ]


# ---------------------------------------------------------------------------
# WinAPI prototypes
# ---------------------------------------------------------------------------

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

kernel32.Module32FirstW.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(MODULEENTRY32W),
]
kernel32.Module32FirstW.restype = wintypes.BOOL

kernel32.Module32NextW.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(MODULEENTRY32W),
]
kernel32.Module32NextW.restype = wintypes.BOOL

kernel32.OpenProcess.argtypes = [
    wintypes.DWORD,
    wintypes.BOOL,
    wintypes.DWORD,
]
kernel32.OpenProcess.restype = wintypes.HANDLE

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

kernel32.VirtualAllocEx.argtypes = [
    wintypes.HANDLE,
    wintypes.LPVOID,
    ctypes.c_size_t,
    wintypes.DWORD,
    wintypes.DWORD,
]
kernel32.VirtualAllocEx.restype = wintypes.LPVOID

kernel32.FlushInstructionCache.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCVOID,
    ctypes.c_size_t,
]
kernel32.FlushInstructionCache.restype = wintypes.BOOL

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL


def winerr(prefix):
    err = ctypes.get_last_error()
    return RuntimeError(f"{prefix} failed: WinError {err}: {ctypes.FormatError(err).strip()}")


def find_process(exe_names):
    """Return (pid, matched_name) for the first running process whose
    name matches any entry in *exe_names* (case-insensitive), or None."""
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE:
        raise winerr("CreateToolhelp32Snapshot(PROCESS)")

    lower_names = [n.lower() for n in exe_names]
    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(pe)

        ok = kernel32.Process32FirstW(snap, ctypes.byref(pe))
        while ok:
            if pe.szExeFile.lower() in lower_names:
                return int(pe.th32ProcessID), pe.szExeFile

            ok = kernel32.Process32NextW(snap, ctypes.byref(pe))
    finally:
        kernel32.CloseHandle(snap)

    return None


def find_module_base(pid, module_name):
    flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32
    snap = kernel32.CreateToolhelp32Snapshot(flags, pid)
    if snap == INVALID_HANDLE_VALUE:
        return None

    try:
        me = MODULEENTRY32W()
        me.dwSize = ctypes.sizeof(me)

        ok = kernel32.Module32FirstW(snap, ctypes.byref(me))
        while ok:
            if me.szModule.lower() == module_name.lower():
                return ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value

            ok = kernel32.Module32NextW(snap, ctypes.byref(me))
    finally:
        kernel32.CloseHandle(snap)

    return None


def read_memory(process, address, size):
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
            f"short ReadProcessMemory at 0x{address:08X}: "
            f"{got.value}/{size} bytes"
        )

    return bytes(buf)


def write_memory(process, address, data):
    raw = bytes(data)
    buf = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
    wrote = ctypes.c_size_t(0)

    if not kernel32.WriteProcessMemory(
        process,
        ctypes.c_void_p(address),
        buf,
        len(raw),
        ctypes.byref(wrote),
    ):
        raise winerr(f"WriteProcessMemory(0x{address:08X})")

    if wrote.value != len(raw):
        raise RuntimeError(
            f"short WriteProcessMemory at 0x{address:08X}: "
            f"{wrote.value}/{len(raw)} bytes"
        )


def build_trampoline(return_va):
    """
    Entry stack before the original prologue:
        [esp+04] year
        [esp+08] month
        [esp+0C] day
        [esp+10] hour
        [esp+14] minute
        [esp+18] second
        [esp+1C] isdst

    Stub:
        cmp dword [esp+4],1900
        jge original_prologue

        mov [esp+4],2026
        mov [esp+8],9
        mov [esp+C],19
        mov [esp+10],12
        mov [esp+14],0
        mov [esp+18],0
        mov [esp+1C],-1

    original_prologue:
        sub esp,24
        push ebx
        mov ebx,[esp+2C]
        push return_va
        ret
    """
    b = bytearray()

    # cmp dword ptr [esp+4], 1900
    b += bytes.fromhex("81 7C 24 04 6C 07 00 00")

    # jge +0x38 -> skips the seven 8-byte MOV instructions below.
    b += bytes.fromhex("7D 38")

    fixes = [
        (0x04, 2026),
        (0x08, 9),
        (0x0C, 19),
        (0x10, 12),
        (0x14, 0),
        (0x18, 0),
        (0x1C, 0xFFFFFFFF),
    ]

    for disp, value in fixes:
        # C7 44 24 xx imm32  => mov dword ptr [esp+disp], imm32
        b += b"\xC7\x44\x24" + bytes([disp])
        b += struct.pack("<I", value & 0xFFFFFFFF)

    # Original 8-byte prologue we replaced.
    b += EXPECTED_ORIGINAL

    # Absolute continuation without clobbering a register:
    # push return_va
    # ret
    b += b"\x68" + struct.pack("<I", return_va & 0xFFFFFFFF)
    b += b"\xC3"

    return bytes(b)


def patch_process(pid, base):
    access = (
        PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE
    )

    process = kernel32.OpenProcess(access, False, pid)
    if not process:
        raise winerr("OpenProcess")

    try:
        target = base + TARGET_RVA
        continuation = target + len(EXPECTED_ORIGINAL)

        original = read_memory(process, target, len(EXPECTED_ORIGINAL))

        if original != EXPECTED_ORIGINAL:
            raise RuntimeError(
                "TGame build/signature mismatch.\n"
                f"Expected at 0x{target:08X}: {EXPECTED_ORIGINAL.hex(' ')}\n"
                f"Found:                    {original.hex(' ')}\n"
                "Nothing was patched."
            )

        stub = build_trampoline(continuation)

        remote = kernel32.VirtualAllocEx(
            process,
            None,
            max(0x1000, len(stub)),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
        if not remote:
            raise winerr("VirtualAllocEx")

        remote_addr = ctypes.cast(remote, ctypes.c_void_p).value

        write_memory(process, remote_addr, stub)

        # JMP rel32 from TGame function entry to our trampoline.
        rel32 = (remote_addr - (target + 5)) & 0xFFFFFFFF
        entry_patch = b"\xE9" + struct.pack("<I", rel32) + b"\x90\x90\x90"

        write_memory(process, target, entry_patch)

        kernel32.FlushInstructionCache(
            process,
            ctypes.c_void_p(target),
            len(entry_patch),
        )
        kernel32.FlushInstructionCache(
            process,
            ctypes.c_void_p(remote_addr),
            len(stub),
        )

        verify = read_memory(process, target, len(entry_patch))
        if verify != entry_patch:
            raise RuntimeError(
                "patch verification failed: "
                f"read back {verify.hex(' ')}"
            )

        print()
        print("PATCHED")
        print(f"  PID          : {pid}")
        print(f"  TGame base   : 0x{base:08X}")
        print(f"  target       : 0x{target:08X}")
        print(f"  trampoline   : 0x{remote_addr:08X}")
        print(f"  continuation : 0x{continuation:08X}")
        print()
        print("Datetime fix is active for this TGame process.")
        print("You can leave x32dbg's 014B9510 breakpoint disabled.")

    finally:
        kernel32.CloseHandle(process)


def main():
    timeout = 300.0
    start = time.time()

    names_str = " / ".join(PROCESS_NAMES)
    print(f"Waiting for {names_str} ...")
    print("You can launch the game now.")
    print()

    last_pid = None
    last_base = None
    matched_name = None

    while True:
        if time.time() - start > timeout:
            raise SystemExit(
                f"Timed out after {int(timeout)} seconds waiting for {names_str}."
            )

        result = find_process(PROCESS_NAMES)

        if result is None:
            time.sleep(0.25)
            continue

        pid, matched_name = result

        if pid != last_pid:
            print(f"Found {matched_name} PID={pid}; waiting for module base ...")
            last_pid = pid
            last_base = None

        base = find_module_base(pid, matched_name)
        if not base:
            time.sleep(0.10)
            continue

        if base != last_base:
            print(f"Module base found at 0x{base:08X}; waiting for code pages ...")
            last_base = base

        # The module base can be found before Windows has committed the code
        # pages (they read as all-zeros).  Retry until the expected prologue
        # bytes are non-zero or we hit a per-process timeout.
        try:
            access = (
                PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_READ
                | PROCESS_VM_WRITE
            )
            proc = kernel32.OpenProcess(access, False, pid)
            if proc:
                target = base + TARGET_RVA
                try:
                    probe = read_memory(proc, target, len(EXPECTED_ORIGINAL))
                except Exception:
                    probe = None
                kernel32.CloseHandle(proc)
                if probe is None or probe == bytes(len(EXPECTED_ORIGINAL)):
                    # Code pages not yet committed - keep waiting
                    time.sleep(0.15)
                    continue
        except Exception:
            time.sleep(0.15)
            continue

        patch_process(pid, base)
        return


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled.")
    except Exception as exc:
        print(f"\nERROR: {exc}")
        print()
        print(
            "If this is an access-denied error, run Command Prompt / PowerShell "
            "as Administrator and run the script again."
        )
        sys.exit(1)