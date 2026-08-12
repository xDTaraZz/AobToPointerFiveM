import bisect
import ctypes
import json
import os
import random
import re
import subprocess
import sys
import time
from ctypes import wintypes

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002
LIST_MODULES_ALL = 0x03
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
READABLE = (0x02, 0x04, 0x08, 0x20, 0x40, 0x80)
INVALID_HANDLE = ctypes.c_void_p(-1).value
MAX_PATH = 260
PAGE = 0x1000
CHUNK = 16 * 1024 * 1024
MAX_MATCHES = 32
POINTER_DEPTH = 5
POINTER_SPREAD = 0x800
POINTER_STRIDE = 4
POINTER_NODES = 4096
POINTER_PATHS = 6
POINTER_BRANCH = 64
POINTER_ANCHOR_BRANCH = 512
POINTER_ANCHOR = 0x40000
POINTER_TARGETS = 4
POINTER_LADDER = ((5, 0x800), (7, 0x1000), (8, 0x2000))
POINTER_PLAN = (
    (5, 0x800, 0),
    (7, 0x1000, 0),
    (7, 0x1000, "block"),
    (7, 0x1000, 0x10000),
    (8, 0x2000, 0x80000),
    (8, 0x2000, 0x400000),
)
POINTER_REACH = (0x10000, 0x80000, 0x400000, 0x4000000)
POINTER_KEEP = 512
POINTER_ROUNDS = 3
STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "chains.json")
GAME_PROCESS = re.compile(r"^(FiveM|RedM)(_b\d+)?_GTAProcess\.exe$", re.IGNORECASE)
BYTE_TOKEN = re.compile(r"^(0x)?([0-9a-fA-F]{2}|\?\?|\?|\*|[0-9a-fA-F]{4,})$")
STATIC_TARGET = re.compile(r"([\w.\-]+\.(?:exe|dll))\s*\+\s*(?:0x)?([0-9a-fA-F]+)", re.IGNORECASE)
ABSOLUTE_TARGET = re.compile(r"(?:0x|\+)([0-9a-fA-F]+)")
TRAILING_OFFSET = re.compile(r"\+\s*(?:0x)?([0-9a-fA-F]+)")

RESET, BOLD = "\033[0m", "\033[1m"
HIDE, SHOW = "\033[?25l", "\033[?25h"
TEAL, VIOLET = (94, 234, 212), (167, 139, 250)
DIM = "\033[38;2;110;118;129m"
CYAN = "\033[38;2;56;189;248m"
GREEN = "\033[38;2;74;222;128m"
YELLOW = "\033[38;2;250;204;21m"
RED = "\033[38;2;248;113;113m"
WHITE = "\033[38;2;226;232;240m"

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)

try:
    import numpy
except ImportError:
    numpy = None

POINTER_LIMIT = 40_000_000 if numpy is not None else 4_000_000


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * MAX_PATH),
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


class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.c_void_p),
        ("SizeOfImage", wintypes.DWORD),
        ("EntryPoint", ctypes.c_void_p),
    ]


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", ctypes.c_long)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]


kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
kernel32.GetStdHandle.argtypes = [wintypes.DWORD]
kernel32.GetStdHandle.restype = wintypes.HANDLE
kernel32.SetConsoleTitleW.argtypes = [wintypes.LPCWSTR]
psapi.EnumProcessModulesEx.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.HMODULE),
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.DWORD,
]
psapi.GetModuleBaseNameW.argtypes = [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
psapi.GetModuleInformation.argtypes = [
    wintypes.HANDLE,
    wintypes.HMODULE,
    ctypes.POINTER(MODULEINFO),
    wintypes.DWORD,
]


class ScanError(Exception):
    pass


def enable_debug_privilege():
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(token)
    ):
        return
    luid = LUID()
    if advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
        privileges = TOKEN_PRIVILEGES()
        privileges.PrivilegeCount = 1
        privileges.Privileges[0].Luid = luid
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(privileges), 0, None, None)
    kernel32.CloseHandle(token)


def list_processes():
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE:
        raise ScanError("cannot enumerate processes")
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)
    found = []
    ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
    while ok:
        found.append((entry.szExeFile, entry.th32ProcessID))
        ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    kernel32.CloseHandle(snapshot)
    return found


def find_game(name=None):
    def wanted(process):
        return process.lower() == name.lower() if name else bool(GAME_PROCESS.match(process))

    return [(process, pid) for process, pid in list_processes() if wanted(process)]


def game_build(name):
    if not GAME_PROCESS.match(name):
        return None
    match = re.search(r"_b(\d+)_", name)
    return match.group(1) if match else "legacy"


class Process:
    def __init__(self, pid):
        self.pid = pid
        self.handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not self.handle:
            raise ScanError(f"cannot open pid {pid} [{ctypes.get_last_error()}] - run as Administrator")
        flag = wintypes.BOOL()
        kernel32.IsWow64Process(self.handle, ctypes.byref(flag))
        self.wow64 = bool(flag.value)
        self.bits = 32 if self.wow64 else 64
        self.pointer_size = self.bits // 8
        if self.wow64 != (ctypes.sizeof(ctypes.c_void_p) == 4):
            self.close()
            raise ScanError(f"target is {self.bits}-bit - run this tool with {self.bits}-bit Python")

    def close(self):
        if self.handle:
            kernel32.CloseHandle(self.handle)
            self.handle = None

    def alive(self):
        code = wintypes.DWORD()
        kernel32.GetExitCodeProcess(self.handle, ctypes.byref(code))
        return code.value == 259

    def read(self, address, size):
        buffer = (ctypes.c_ubyte * size)()
        done = ctypes.c_size_t(0)
        kernel32.ReadProcessMemory(
            self.handle, ctypes.c_void_p(address), ctypes.byref(buffer), size, ctypes.byref(done)
        )
        return bytes(memoryview(buffer)[: done.value]) if done.value == size else None

    def read_span(self, address, size):
        buffer = bytearray()
        step = 1 << 20
        for offset in range(0, size, step):
            span = min(step, size - offset)
            chunk = self.read(address + offset, span)
            buffer += chunk if chunk else bytes(span)
        return bytes(buffer)

    def read_pointer(self, address):
        data = self.read(address, self.pointer_size)
        return int.from_bytes(data, "little") if data else None

    def modules(self):
        needed = wintypes.DWORD()
        count = 1024
        while True:
            array = (wintypes.HMODULE * count)()
            if not psapi.EnumProcessModulesEx(
                self.handle, array, ctypes.sizeof(array), ctypes.byref(needed), LIST_MODULES_ALL
            ):
                raise ScanError("cannot enumerate modules")
            returned = needed.value // ctypes.sizeof(wintypes.HMODULE)
            if returned <= count:
                array = array[:returned]
                break
            count = returned
        name = ctypes.create_unicode_buffer(MAX_PATH)
        result = []
        for handle in array:
            info = MODULEINFO()
            if handle and psapi.GetModuleInformation(self.handle, handle, ctypes.byref(info), ctypes.sizeof(info)):
                if psapi.GetModuleBaseNameW(self.handle, handle, name, MAX_PATH):
                    result.append((name.value, info.lpBaseOfDll or 0, info.SizeOfImage))
        return result

    def allocation(self, address):
        """Start of the block the address was allocated in, so we can measure how deep inside it sits."""
        info = MEMORY_BASIC_INFORMATION()
        if not kernel32.VirtualQueryEx(
            self.handle, ctypes.c_void_p(address), ctypes.byref(info), ctypes.sizeof(info)
        ):
            return None
        return info.AllocationBase or info.BaseAddress or None

    def regions(self):
        info = MEMORY_BASIC_INFORMATION()
        address = 0
        limit = 0x7FFFFFFF if self.wow64 else 0x7FFFFFFFFFFF
        found = []
        while address < limit:
            if not kernel32.VirtualQueryEx(
                self.handle, ctypes.c_void_p(address), ctypes.byref(info), ctypes.sizeof(info)
            ):
                break
            base, size = info.BaseAddress or 0, info.RegionSize
            if not size:
                break
            if info.State == MEM_COMMIT and (info.Protect & 0xFF) in READABLE and not info.Protect & PAGE_GUARD:
                if found and found[-1][0] + found[-1][1] == base:
                    found[-1][1] += size
                else:
                    found.append([base, size])
            address = base + size
        return [(base, size) for base, size in found]


def parse_pattern(text):
    tokens = text.replace("0x", " ").replace(",", " ").replace("\\x", " ").split()
    if len(tokens) == 1 and len(tokens[0]) > 2 and "?" not in tokens[0]:
        raw = tokens[0]
        if len(raw) % 2:
            raise ScanError("hex string must have an even number of digits")
        tokens = [raw[index : index + 2] for index in range(0, len(raw), 2)]
    if not tokens:
        raise ScanError("empty pattern")
    if tokens[0] in ("??", "?", "*"):
        raise ScanError("pattern cannot start with a wildcard")
    expression = b""
    wildcards = 0
    for token in tokens:
        if token in ("??", "?", "*"):
            expression += b"."
            wildcards += 1
            continue
        try:
            expression += re.escape(bytes([int(token, 16)]))
        except ValueError:
            raise ScanError(f"invalid byte: {token}")
    return re.compile(expression, re.DOTALL), len(tokens), wildcards


def filler(process, buffer):
    done = ctypes.c_size_t(0)

    def fill(address, size):
        if kernel32.ReadProcessMemory(
            process.handle, ctypes.c_void_p(address), ctypes.byref(buffer), size, ctypes.byref(done)
        ) and done.value == size:
            return
        for offset in range(0, size, PAGE):
            span = min(PAGE, size - offset)
            ok = kernel32.ReadProcessMemory(
                process.handle,
                ctypes.c_void_p(address + offset),
                ctypes.byref(buffer, offset),
                span,
                ctypes.byref(done),
            )
            if not ok or done.value != span:
                ctypes.memset(ctypes.byref(buffer, offset), 0, span)

    return fill


def scan(process, blocks, pattern, length, progress=None):
    buffer = (ctypes.c_ubyte * CHUNK)()
    view = memoryview(buffer)
    total = sum(size for _, size in blocks)
    scanned = 0
    matches = []
    fill = filler(process, buffer)

    for base, size in blocks:
        offset = 0
        while offset < size:
            window = min(CHUNK, size - offset)
            fill(base + offset, window)
            for match in pattern.finditer(view[:window]):
                address = base + offset + match.start()
                if address not in matches:
                    matches.append(address)
                    if len(matches) >= MAX_MATCHES:
                        return matches
            scanned += window
            if progress:
                progress(min(scanned, total), total)
            if offset + window >= size:
                break
            offset += window - (length - 1)
    return matches


PREFIXES = {0x66, 0x67, 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65}
REGISTERS = (
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)
ONE_BYTE_MODRM = (
    {op for op in range(0x40) if op & 0x07 < 4}
    | {0x62, 0x63, 0x69, 0x6B}
    | set(range(0x80, 0x90))
    | {0xC0, 0xC1, 0xC4, 0xC5, 0xC6, 0xC7}
    | set(range(0xD0, 0xD4))
    | set(range(0xD8, 0xE0))
    | {0xF6, 0xF7, 0xFE, 0xFF}
)
ONE_BYTE_IMM8 = (
    {op for op in range(0x40) if op & 0x07 == 4}
    | {0x6A, 0x6B, 0x80, 0x83, 0xA8, 0xC0, 0xC1, 0xC6, 0xCD, 0xEB}
    | set(range(0x70, 0x80))
    | set(range(0xB0, 0xB8))
    | set(range(0xE0, 0xE4))
)
ONE_BYTE_IMM32 = (
    {op for op in range(0x40) if op & 0x07 == 5}
    | {0x68, 0x69, 0x81, 0xA9, 0xC7, 0xE8, 0xE9}
    | set(range(0xB8, 0xC0))
)
TWO_BYTE_PLAIN = (
    {0x05, 0x06, 0x07, 0x08, 0x09, 0x0B, 0x0E, 0x77, 0xA0, 0xA1, 0xA2, 0xA8, 0xA9, 0xAA}
    | set(range(0x30, 0x38))
    | set(range(0x80, 0x90))
    | set(range(0xC8, 0xD0))
)
TWO_BYTE_IMM8 = set(range(0x70, 0x74)) | {0xA4, 0xAC, 0xBA, 0xC2, 0xC4, 0xC5, 0xC6}
RELATIVE_ONE_BYTE = {0xE8, 0xE9, 0xEB} | set(range(0x70, 0x80)) | set(range(0xE0, 0xE4))


def decode(data, start):
    index = start
    while index < len(data) and data[index] in PREFIXES:
        index += 1
    rex = 0
    if index < len(data) and 0x40 <= data[index] <= 0x4F:
        rex = data[index]
        index += 1
    if index >= len(data):
        return None
    opcode = data[index]
    index += 1
    immediate = 0
    two_byte = opcode == 0x0F
    if opcode == 0x0F:
        if index >= len(data):
            return None
        opcode = data[index]
        index += 1
        if opcode in (0x38, 0x3A):
            escape = opcode
            if index >= len(data):
                return None
            index += 1
            immediate = 1 if escape == 0x3A else 0
            has_modrm = True
        else:
            has_modrm = opcode not in TWO_BYTE_PLAIN
            immediate = 1 if opcode in TWO_BYTE_IMM8 else (4 if 0x80 <= opcode <= 0x8F else 0)
    else:
        has_modrm = opcode in ONE_BYTE_MODRM
        immediate = 1 if opcode in ONE_BYTE_IMM8 else (4 if opcode in ONE_BYTE_IMM32 else 0)
        if opcode == 0xC2:
            immediate = 2
        if 0xB8 <= opcode <= 0xBF and rex & 0x08:
            immediate = 8
    displacement = None
    position = None
    base = None
    rip = False
    if has_modrm:
        if index >= len(data):
            return None
        modrm = data[index]
        index += 1
        mod, register, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
        if opcode in (0xF6, 0xF7) and register in (0, 1):
            immediate = 1 if opcode == 0xF6 else 4
        elif opcode in (0xF6, 0xF7):
            immediate = 0
        if mod != 3:
            size = 0
            if rm == 4:
                if index >= len(data):
                    return None
                sib = data[index]
                index += 1
                base = REGISTERS[(sib & 7) | ((rex & 0x01) << 3)]
                if mod == 0 and sib & 7 == 5:
                    size = 4
            elif mod == 0 and rm == 5:
                size, rip = 4, True
            else:
                base = REGISTERS[rm | ((rex & 0x01) << 3)]
            if mod == 1:
                size = 1
            elif mod == 2:
                size = 4
            if size:
                if index + size > len(data):
                    return None
                position = index - start
                displacement = int.from_bytes(data[index : index + size], "little", signed=True)
                index += size
    if index + immediate > len(data):
        return None
    index += immediate
    relative = (0x80 <= opcode <= 0x8F) if two_byte else opcode in RELATIVE_ONE_BYTE
    return {
        "length": index - start,
        "displacement": displacement,
        "position": position,
        "base": base,
        "rip": rip,
        "immediate": immediate,
        "relative": relative,
    }


def analyze(data):
    instructions = []
    index = 0
    while index < len(data):
        info = decode(data, index)
        if not info or info["length"] <= 0:
            break
        info["start"] = index
        instructions.append(info)
        index += info["length"]
    return instructions


def static_name(modules, address):
    for name, base, size in modules:
        if base <= address < base + size:
            return f"{name}+{address - base:X}"
    return f"0x{address:X}"


def resolve_rip(process, address, spec):
    parts = spec.split(":")
    displacement_offset = int(parts[0], 16)
    instruction_length = int(parts[1], 16) if len(parts) > 1 else displacement_offset + 4
    raw = process.read(address + displacement_offset, 4)
    if not raw:
        raise ScanError("cannot read the RIP displacement")
    return address + instruction_length + int.from_bytes(raw, "little", signed=True)


def walk_chain(process, address, offsets):
    steps = [address]
    current = address
    for offset in offsets:
        pointer = process.read_pointer(current)
        if pointer is None:
            return steps, None
        current = pointer + offset
        steps.append(current)
    return steps, current


class Pointers:
    """Every aligned slot in the process that stores something looking like an address.

    Built in a single memory pass, then queried in memory - walking one more level costs
    a binary search, not another scan.
    """

    def __init__(self, process, blocks, progress=None):
        self.size = process.pointer_size
        self.low = min(base for base, _ in blocks)
        self.high = max(base + span for base, span in blocks)
        self.values = []
        self.holders = []
        self.count = 0
        self.capped = False
        self._collect(process, blocks, progress)
        self._finish()

    def _collect(self, process, blocks, progress):
        buffer = (ctypes.c_ubyte * CHUNK)()
        view = memoryview(buffer)
        fill = filler(process, buffer)
        total = sum(span for _, span in blocks)
        scanned = 0
        for base, span in blocks:
            offset = 0
            while offset < span:
                window = min(CHUNK, span - offset)
                fill(base + offset, window)
                slots = window // self.size
                if slots:
                    self._absorb(view[: slots * self.size], base + offset)
                scanned += window
                if progress:
                    progress(min(scanned, total), total)
                if self.count > POINTER_LIMIT:
                    self.capped = True
                    return
                offset += window

    def _absorb(self, data, base):
        if numpy is not None:
            kind = numpy.uint64 if self.size == 8 else numpy.uint32
            raw = numpy.frombuffer(data, dtype=kind).astype(numpy.int64)
            keep = (raw >= self.low) & (raw <= self.high) & (raw % POINTER_STRIDE == 0)
            picked = numpy.nonzero(keep)[0]
            if picked.size:
                self.values.append(raw[picked])
                self.holders.append(base + picked * self.size)
                self.count += int(picked.size)
            return
        for slot in range(len(data) // self.size):
            start = slot * self.size
            value = int.from_bytes(data[start : start + self.size], "little")
            if self.low <= value <= self.high and not value % POINTER_STRIDE:
                self.values.append(value)
                self.holders.append(base + start)
        self.count = len(self.values)

    def _finish(self):
        if numpy is not None:
            if not self.values:
                self.values = numpy.empty(0, dtype=numpy.int64)
                self.holders = numpy.empty(0, dtype=numpy.int64)
                return
            self.values = numpy.concatenate(self.values)
            self.holders = numpy.concatenate(self.holders)
            order = numpy.argsort(self.values, kind="stable")
            self.values = self.values[order]
            self.holders = self.holders[order]
            return
        order = sorted(range(len(self.values)), key=self.values.__getitem__)
        self.values = [self.values[index] for index in order]
        self.holders = [self.holders[index] for index in order]

    def locate(self, target, spread, limit):
        """Slots holding a pointer that lands `0..spread` bytes below `target`, nearest first.

        Nearest first matters: when the limit bites it has to drop the far-fetched
        candidates, not the tight ones that look like real struct fields.
        """
        if numpy is not None:
            start = int(numpy.searchsorted(self.values, target - spread, side="left"))
            stop = int(numpy.searchsorted(self.values, target, side="right"))
        else:
            start = bisect.bisect_left(self.values, target - spread)
            stop = bisect.bisect_right(self.values, target)
        start = max(start, stop - limit)
        found = [(int(self.holders[index]), target - int(self.values[index])) for index in range(stop - 1, start - 1, -1)]
        return found


def inside_module(modules, address):
    return any(base <= address < base + size for _, base, size in modules)


def pointer_scan(table, modules, target, depth, spread, anchor=0):
    """`anchor` widens the first hop only: a value buried in a buffer is reached from the
    front of that buffer, which can be far further away than a struct field ever is."""
    nodes = [(target, None, None)]
    frontier = [0]
    complete = []
    seen = {target}
    for level in range(depth):
        reach = max(spread, anchor) if not level else spread
        branch = POINTER_ANCHOR_BRANCH if not level else POINTER_BRANCH
        following = []
        for parent in frontier:
            for holder, offset in table.locate(nodes[parent][0], reach, branch):
                static = inside_module(modules, holder)
                if not static and holder in seen:
                    continue
                seen.add(holder)
                index = len(nodes)
                nodes.append((holder, offset, parent))
                if static:
                    complete.append(index)
                else:
                    following.append((offset, index))
        following.sort()
        frontier = [index for _, index in following[:POINTER_NODES]]
        if complete or not frontier:
            break
    return nodes, complete


def unwind(nodes, index):
    offsets = []
    address = nodes[index][0]
    while True:
        _, offset, parent = nodes[index]
        if parent is None:
            break
        offsets.append(offset)
        index = parent
    return address, offsets


def chain_expression(label, offsets):
    expression = f"[{label}]"
    for index, offset in enumerate(offsets):
        expression += f"+0x{offset:X}"
        if index < len(offsets) - 1:
            expression = f"[{expression}]"
    return expression


def split_input(text):
    tokens = text.replace(",", " ").split()
    edge = len(tokens)
    for index, token in enumerate(tokens):
        if not BYTE_TOKEN.match(token):
            edge = index
            break
    return " ".join(tokens[:edge]), " ".join(tokens[edge:])


def parse_options(text):
    tokens = text.replace(",", " ").split()
    options = {"offset": 0, "rip": None, "chain": [], "all": False}
    index = 0
    while index < len(tokens):
        token = tokens[index].lower()
        if token == "all":
            options["all"] = True
            index += 1
        elif token == "rip" and index + 1 < len(tokens):
            options["rip"] = tokens[index + 1]
            index += 2
        elif token == "chain":
            options["chain"] = [int(value, 16) for value in tokens[index + 1 :]]
            break
        elif token[0] in "+-":
            options["offset"] = int(token.replace("+", ""), 16)
            index += 1
        else:
            raise ScanError(f"unknown option: {tokens[index]}")
    return options


def clipboard(text):
    try:
        subprocess.run("clip", input=text.encode("utf-16-le"), check=True, stdout=subprocess.DEVNULL)
        return True
    except Exception:
        return False


def line(text="", color=""):
    print(f"{MARGIN}{color}{text}{RESET}" if color else f"{MARGIN}{text}")


def ask(label):
    try:
        raw = input(f"{MARGIN}{CYAN}>{RESET} {BOLD}{WHITE}{label}{RESET} {DIM}:{RESET} ")
    except (EOFError, KeyboardInterrupt):
        raise SystemExit(0)
    return raw.strip().lstrip("﻿").strip()


def shade(level):
    start, end = TEAL, VIOLET
    channels = [int(start[index] + (end[index] - start[index]) * level) for index in range(3)]
    return f"\033[38;2;{channels[0]};{channels[1]};{channels[2]}m"


def gradient(text):
    span = max(len(text) - 1, 1)
    return "".join(shade(index / span) + char for index, char in enumerate(text)) + RESET


INNER = 66
COLUMNS, ROWS = 84, 34
MARGIN = " " * ((COLUMNS - INNER - 2) // 2)
ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")


def setup_console():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    handle = kernel32.GetStdHandle(-11)
    mode = ctypes.c_ulong()
    if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    if sys.stdout.isatty():
        os.system(f"mode con: cols={COLUMNS} lines={ROWS} >nul 2>&1")


def clear():
    os.system("cls")


def visible(text):
    return len(ANSI.sub("", text))


def fit(text, size):
    if visible(text) <= size:
        return text + " " * (size - visible(text))
    plain = ANSI.sub("", text)
    return plain[: size - 1] + "..."


def panel(title, rows, tone=None):
    head = f"{shade(0)}+- {RESET}{BOLD}{tone or WHITE}{title}{RESET} "
    fill = INNER + 1 - visible(f"+- {title} ")
    print(f"{MARGIN}{head}{gradient('-' * fill)}{shade(1)}+{RESET}")
    for row in rows:
        print(f"{MARGIN}{shade(0)}|{RESET} {fit(row, INNER - 1)}{shade(1)}|{RESET}")
    print(f"{MARGIN}{gradient('+' + '-' * INNER)}{shade(1)}+{RESET}")


def hexdump(tokens):
    rows = []
    for start in range(0, len(tokens), 16):
        group = tokens[start : start + 16]
        tail = " ".join(group[8:])
        rows.append(f" {WHITE}{' '.join(group[:8])}{'  ' + tail if tail else ''}{RESET}")
    return rows


LOGO = (
    " █████   ██████  ██████      ██████      ██████  ████████ ██████ ",
    "██   ██ ██    ██ ██   ██          ██     ██   ██    ██    ██   ██",
    "███████ ██    ██ ██████       █████      ██████     ██    ██████ ",
    "██   ██ ██    ██ ██   ██     ██          ██         ██    ██   ██",
    "██   ██  ██████  ██████      ███████     ██         ██    ██   ██",
)


def banner():
    indent = " " * ((INNER + 2 - max(len(row) for row in LOGO)) // 2)
    print()
    for row in LOGO:
        line(indent + gradient(row))
    print()


def progress_bar(done, total, label="scanning"):
    width = 30
    ratio = done / total if total else 1.0
    filled = int(width * ratio)
    bar = "".join(shade(index / width) + "=" for index in range(filled)) + DIM + "-" * (width - filled)
    percent = int(100 * ratio)
    title(f"{label} {percent}%", percent)
    print(f"\r{MARGIN}{DIM}{fit(label, 10)}{RESET}{bar}{RESET}  {WHITE}{percent:3d}%{RESET}", end="", flush=True)




def pulse(frame, cells=9):
    cell = lambda index: shade(index / cells) + "=" if (frame - index) % (cells + 4) < 3 else DIM + "-"
    return "".join(cell(index) for index in range(cells)) + RESET


TAGS = ("INIT", "LINK", "SYNC", "PROBE", "TRACE", "HOOK", "EXEC")
NOISE = "0123456789ABCDEF"


def title(status, frame=0):
    tag = TAGS[frame % len(TAGS)]
    noise = "".join(random.choice(NOISE) for _ in range(8))
    kernel32.SetConsoleTitleW(f"[{tag}] aob>ptr :: 0x{noise} :: {status}")


def standby_row(frame, target, clock):
    label = f"{DIM}waiting for{RESET}  {WHITE}{target}{RESET}"
    return f" {pulse(frame)}   {fit(label, 34)}{DIM}{clock}{RESET}"


def wait_for(name):
    found = find_game(name)
    if found:
        return found
    target = name or "FiveM / RedM"
    panel("STANDBY", [standby_row(0, target, "0:00")], YELLOW)
    started = time.time()
    frame = 0
    print(HIDE, end="", flush=True)
    while not found:
        elapsed = int(time.time() - started)
        clock = f"{elapsed // 60}:{elapsed % 60:02d}"
        row = standby_row(frame, target, clock)
        sys.stdout.write("\033[2A\r")
        print(f"{MARGIN}{shade(0)}|{RESET} {fit(row, INNER - 1)}{shade(1)}|{RESET}", end="")
        sys.stdout.write("\r\033[2B")
        sys.stdout.flush()
        time.sleep(0.07)
        frame += 1
        if frame % 7 == 0:
            found = find_game(name)
            title(f"waiting for {target} {clock}", frame // 7)
    sys.stdout.write(f"\033[3A\033[J{SHOW}")
    sys.stdout.flush()
    return found


def attach(name=None):
    found = wait_for(name)
    process_name, pid = found[0]
    process = Process(pid)
    process.name = process_name
    modules = process.modules()
    main = next((m for m in modules if m[0].lower() == process_name.lower()), modules[0])
    build = game_build(process_name)
    rows = [
        f" {WHITE}{process_name}{RESET}" + (f"   {DIM}build{RESET} {build}" if build else ""),
        f" {DIM}pid{RESET} {pid}   {DIM}x{RESET}{process.bits}"
        f"   {DIM}0x{main[1]:X}{RESET}   {DIM}{main[2] / 1048576:.0f} MB{RESET}",
    ]
    if len(found) > 1:
        rows.append(f" {YELLOW}{len(found)} instances{RESET}")
    title(f"linked {process_name} pid {pid}")
    process.card = rows
    panel("TARGET", rows, GREEN)
    print()
    return process, modules, main


def parse_target(text, modules, main):
    match = STATIC_TARGET.search(text)
    if match:
        wanted = match.group(1).lower()
        module = next((m for m in modules if m[0].lower() == wanted), None)
        if module is None:
            raise ScanError(f"module not loaded: {match.group(1)}")
        address = module[1] + int(match.group(2), 16)
        tail = text[match.end() :]
    else:
        match = ABSOLUTE_TARGET.search(text)
        if not match:
            raise ScanError("invalid input")
        address = int(match.group(1), 16)
        if address < main[1]:
            address += main[1]
        tail = text[match.end() :]
    offsets = [int(value, 16) for value in TRAILING_OFFSET.findall(tail)]
    return address, offsets


def count_matches(image, pattern):
    total = 0
    for _ in pattern.finditer(image):
        total += 1
        if total > 1:
            break
    return total


def trim(tokens):
    end = len(tokens)
    while end and tokens[end - 1] == "??":
        end -= 1
    return tokens[:end]


def build_signature(process, image, address, minimum=10, span=160):
    data = process.read(address, span) or b""
    tokens = []
    for info in analyze(data):
        chunk = data[info["start"] : info["start"] + info["length"]]
        parts = [f"{byte:02X}" for byte in chunk]
        if info["rip"] and info["position"] is not None:
            parts[info["position"] : info["position"] + 4] = ["??"] * 4
        if info["relative"] and info["immediate"]:
            parts[info["length"] - info["immediate"] :] = ["??"] * info["immediate"]
        tokens += parts
        candidate = trim(tokens)
        if len(candidate) < minimum:
            continue
        pattern, _, _ = parse_pattern(" ".join(candidate))
        if count_matches(image, pattern) == 1:
            return candidate, True
    return trim(tokens), False


def reverse(process, modules, main, text):
    address, offsets = parse_target(text, modules, main)
    label = static_name(modules, address)
    if not any(base <= address < base + size for _, base, size in modules):
        raise ScanError("address out of range")
    image = process.read_span(main[1], main[2])
    tokens, unique = build_signature(process, image, address)
    if not tokens:
        raise ScanError("unreadable")
    signature = " ".join(tokens)
    wildcards = tokens.count("??")
    quality = f"{GREEN}unique{RESET}" if unique else f"{YELLOW}ambiguous{RESET}"
    found, _ = inspect(process, address, len(tokens))
    rows = hexdump(tokens)
    rows.append("")
    rows.append(f" {WHITE}{label if not offsets else chain_expression(label, offsets)}{RESET}")
    detail = f" {DIM}{len(tokens)} bytes   {wildcards} wildcards{RESET}   {quality}"
    if found:
        detail += "    " + offsets_row(found)
    rows.append(detail)
    if offsets:
        steps, final = walk_chain(process, address, offsets)
        rows.append(f" {DIM}{' -> '.join(f'0x{step:X}' for step in steps)}{RESET}")
    panel("SIGNATURE", rows)
    print()
    return signature


def parse_pointer_request(text):
    tokens = text.replace(",", " ").split()[1:]
    if not tokens:
        raise ScanError("usage: ptr <address> [depth N] [spread HEX] [as <name>]")
    request = {"depth": POINTER_DEPTH, "spread": POINTER_SPREAD, "label": "manual"}
    try:
        address = int(tokens[0].lower().replace("0x", ""), 16)
    except ValueError:
        raise ScanError(f"invalid address: {tokens[0]}")
    index = 1
    while index < len(tokens):
        token = tokens[index].lower()
        if token == "as" and index + 1 < len(tokens):
            request["label"] = " ".join(tokens[index + 1 :])
            break
        if token in ("depth", "spread") and index + 1 < len(tokens):
            value = tokens[index + 1].lower().replace("0x", "")
            request[token] = int(value) if token == "depth" else int(value, 16)
            index += 2
        else:
            raise ScanError(f"unknown option: {tokens[index]}")
    if not 1 <= request["depth"] <= 8:
        raise ScanError("depth must be 1-8")
    request["address"] = address
    return request


def pointer_table(process):
    """One memory pass per command, reused by every level and every address after it."""
    if numpy is None:
        line(f"{YELLOW}numpy not installed - slow mode, try: pip install numpy{RESET}")
    sys.stdout.write(HIDE)
    started = time.time()
    try:
        table = Pointers(process, process.regions(), lambda done, total: progress_bar(done, total, "mapping"))
    finally:
        print(SHOW, end="")
    note = f"{table.count} pointers   {time.time() - started:.1f}s"
    if table.capped:
        note += "   truncated"
    print(f"\r{MARGIN}{DIM}{note}{RESET}" + " " * 40)
    print()
    return table


def resolve_paths(process, modules, main, table, address, depth, spread, anchor=0):
    nodes, complete = pointer_scan(table, modules, address, depth, spread, anchor)
    paths = []
    for index in complete:
        base, offsets = unwind(nodes, index)
        _, final = walk_chain(process, base, offsets)
        if final != address:
            continue
        home = 0 if main[1] <= base < main[1] + main[2] else 1
        paths.append((home, len(offsets), base, offsets))
    paths.sort(key=lambda path: (path[0], path[1], max(path[3][:-1] or [0]), path[3]))
    return paths


def anchor_for(process, address):
    """How far into its own allocation the value sits - the first hop has to cover that gap."""
    base = process.allocation(address)
    if not base or not 0 < address - base <= POINTER_ANCHOR:
        return 0
    return address - base


def nearest_pointer(table, address):
    """Closest pointer aimed below the value, however far - tells us what we are up against."""
    found = table.locate(address, POINTER_REACH[-1], 1)
    return found[0] if found else None


def widen(process, modules, main, table, address, depth, spread):
    """The table is already built, so a deeper walk is nearly free - keep going before giving up."""
    measured = anchor_for(process, address)
    if measured:
        line(f"{DIM}value sits 0x{measured:X} into its block{RESET}")
        print()
    attempts = []
    for deep, wide, reach in POINTER_PLAN:
        step = (max(deep, depth), max(wide, spread), measured if reach == "block" else reach)
        if step not in attempts:
            attempts.append(step)
    for deep, wide, reach in attempts:
        paths = resolve_paths(process, modules, main, table, address, deep, wide, reach)
        if paths:
            if reach > wide:
                line(f"{DIM}reached it from 0x{reach:X} back - the value sits inside a buffer{RESET}")
                print()
            return paths, deep
        if reach:
            line(f"{DIM}nothing within depth {deep} reaching 0x{reach:X} back - widening{RESET}")
        else:
            line(f"{DIM}nothing within depth {deep} - widening{RESET}")
        print()
    return [], attempts[-1][0]


def pointer_panel(modules, address, paths, depth, rounds=1):
    if not paths:
        rows = [f" {DIM}no static pointer within depth {depth}{RESET}", ""]
        rows.append(f" {DIM}the value may sit in a buffer nothing points straight at{RESET}")
        rows.append(f" {DIM}widen it by hand: {RESET}ptr {address:X} depth 8 spread 2000{RESET}")
        panel("NO PATH", rows, RED)
        print()
        return None
    rows = []
    for _, _, base, offsets in paths[:POINTER_PATHS]:
        rows += path_rows(modules, base, offsets)
    best = paths[0]
    rows.append("")
    rows += cheat_engine_rows(modules, best[2], best[3])
    rows.append("")
    rows.append(f" {DIM}0x{address:X}   {len(paths)} paths   depth {len(best[3])}{RESET}")
    if rounds < POINTER_ROUNDS:
        rows.append(f" {YELLOW}round {rounds} of {POINTER_ROUNDS} - restart the game and run this again{RESET}")
    else:
        rows.append(f" {GREEN}verified across {rounds} restarts - ready to use{RESET}")
    panel("POINTER", rows, GREEN if rounds >= POINTER_ROUNDS else YELLOW)
    print()
    return chain_expression(static_name(modules, best[2]), best[3])


def cheat_engine_rows(modules, base, offsets):
    """Cheat Engine fills its offset boxes bottom up - the last hop goes in the top box."""
    rows = [f" {DIM}Cheat Engine boxes, top to bottom{RESET}"]
    for offset in reversed(offsets):
        rows.append(f"   {WHITE}{offset:X}{RESET}")
    rows.append(f"   {WHITE}{static_name(modules, base)}{RESET}   {DIM}base{RESET}")
    return rows


def path_rows(modules, base, offsets):
    """Cheat Engine reads it as a base plus a list of offsets, and it fits the panel."""
    rows = [f" {GREEN}>{RESET} {BOLD}{WHITE}{static_name(modules, base)}{RESET}"]
    trail = [f"0x{offset:X}" for offset in offsets]
    while trail:
        take = 0
        width = 0
        while take < len(trail) and width + len(trail[take]) + 2 <= INNER - 8:
            width += len(trail[take]) + 2
            take += 1
        rows.append(f"   {DIM}{'  '.join(trail[: take or 1])}{RESET}")
        trail = trail[take or 1 :]
    return rows


def stored_paths(label):
    try:
        with open(STORE, encoding="utf-8") as handle:
            saved = json.load(handle)
    except Exception:
        return {}, []
    entry = saved.get(label) or {}
    return saved, entry.get("paths", [])


def keep_paths(label, saved, modules, paths, rounds):
    saved[label] = {
        "rounds": rounds,
        "paths": [
            {"base": static_name(modules, base), "offsets": [f"{offset:X}" for offset in offsets]}
            for _, _, base, offsets in paths[:POINTER_KEEP]
        ],
    }
    try:
        with open(STORE, "w", encoding="utf-8") as handle:
            json.dump(saved, handle, indent=1)
    except Exception:
        pass


def survivors(process, modules, main, records, address):
    """A path that still lands on the value after a restart is the one worth keeping."""
    kept = []
    for record in records:
        try:
            base, _ = parse_target(record["base"], modules, main)
        except (ScanError, ValueError):
            continue
        offsets = [int(offset, 16) for offset in record["offsets"]]
        _, final = walk_chain(process, base, offsets)
        if final != address:
            continue
        home = 0 if main[1] <= base < main[1] + main[2] else 1
        kept.append((home, len(offsets), base, offsets))
    kept.sort()
    return kept


def chain_for(process, modules, main, address, label, depth=POINTER_DEPTH, spread=POINTER_SPREAD):
    saved, records = stored_paths(label)
    rounds = (saved.get(label) or {}).get("rounds", 0)
    if records:
        kept = survivors(process, modules, main, records, address)
        if kept:
            line(f"{DIM}{len(kept)} of {len(records)} saved paths survived - round {rounds + 1}{RESET}")
            print()
            keep_paths(label, saved, modules, kept, rounds + 1)
            return pointer_panel(modules, address, kept, depth, rounds + 1)
        line(f"{YELLOW}saved paths no longer reach the value - scanning again{RESET}")
        print()
    table = pointer_table(process)
    paths, reached = widen(process, modules, main, table, address, depth, spread)
    if paths:
        keep_paths(label, saved, modules, paths, 1)
        return pointer_panel(modules, address, paths, reached, 1)
    return dead_end(modules, table, address, reached)


def dead_end(modules, table, address, depth):
    rows = [f" {DIM}no static pointer within depth {depth}{RESET}", ""]
    close = nearest_pointer(table, address)
    if close is None:
        rows.append(f" {DIM}nothing in the process points anywhere near this value{RESET}")
        rows.append(f" {DIM}it is loose data - chase the code that reads it instead{RESET}")
    else:
        holder, offset = close
        rows.append(f" {DIM}closest pointer is 0x{offset:X} below it, held at {RESET}0x{holder:X}")
        rows.append(f" {DIM}{static_name(modules, holder)}{RESET}")
        if offset > POINTER_REACH[1]:
            rows.append(f" {DIM}that is a long way - the value is deep inside a big buffer{RESET}")
    panel("NO PATH", rows, RED)
    print()
    return None


def pointer(process, modules, main, text):
    request = parse_pointer_request(text)
    address = request["address"]
    if process.read_pointer(address) is None:
        raise ScanError(f"cannot read 0x{address:X}")
    if inside_module(modules, address):
        raise ScanError(f"already static: {static_name(modules, address)}")
    return chain_for(process, modules, main, address, request["label"], request["depth"], request["spread"])


STACK = ("rsp", "rbp")


def inspect(process, address, size):
    data = process.read(address, size)
    if not data:
        return [], None
    offsets = []
    rip = None
    for info in analyze(data):
        if info["rip"] and rip is None:
            rip = (info["start"] + info["position"], info["start"] + info["length"])
        elif info["displacement"] is not None and info["base"] not in (None, *STACK):
            offsets.append((info["displacement"], info["base"]))
    return offsets, rip


def offsets_row(found):
    return "  ".join(f"{WHITE}0x{value:X}{RESET}{DIM}[{base}]{RESET}" for value, base in found)


def summary(expression, offsets):
    if not offsets:
        return expression
    return expression + "\noffsets  " + ", ".join(f"0x{value:X}" for value, _ in offsets)


def show(process, modules, addresses, options, length):
    if not addresses:
        rows = [f" {DIM}-{RESET}", ""]
        rows.append(f" {DIM}nothing in the module or on the heap{RESET}")
        rows.append(f" {DIM}the value may have moved - rescan in Cheat Engine{RESET}")
        panel("NO MATCH", rows, RED)
        print()
        return None
    unique = {}
    for address in addresses:
        resolved = resolve_rip(process, address, options["rip"]) if options["rip"] else address
        resolved += options["offset"]
        label = static_name(modules, resolved)
        expression = chain_expression(label, options["chain"]) if options["chain"] else label
        unique.setdefault(expression, (resolved, address))
    entries = list(unique.items())
    expression, (resolved, address) = entries[0]
    found, rip = inspect(process, address, length)
    detail = f" {DIM}0x{resolved:X}{RESET}"
    if found:
        detail += "    " + offsets_row(found)
    if rip and not options["rip"]:
        detail += f"    {DIM}rip {rip[0]:X}:{rip[1]:X}{RESET}"
    rows = [f" {GREEN}>{RESET} {BOLD}{WHITE}{expression}{RESET}", detail]
    if options["chain"]:
        steps, final = walk_chain(process, resolved, options["chain"])
        rows.append(f" {DIM}{' -> '.join(f'0x{step:X}' for step in steps)}{RESET}")
        rows.append(f" {WHITE}{'0x%X' % final if final is not None else 'unreadable'}{RESET}")
    if len(entries) > 1:
        rows.append("")
        rows.append(f" {YELLOW}{len(entries)} matches{RESET}")
        for other, _ in entries[1:6]:
            rows.append(f" {DIM}  {other}{RESET}")
    panel("MATCH", rows, GREEN if len(entries) == 1 else YELLOW)
    print()
    return summary(expression, found)


def sweep_for(process, blocks, pattern, length, label):
    sys.stdout.write(HIDE)
    started = time.time()
    try:
        addresses = scan(process, blocks, pattern, length, lambda done, total: progress_bar(done, total, label))
    finally:
        print(SHOW, end="")
    megabytes = sum(size for _, size in blocks) / 1048576
    print(f"\r{MARGIN}{DIM}{megabytes:.0f} MB   {time.time() - started:.2f}s{RESET}" + " " * 40)
    print()
    return addresses


def chase(process, modules, main, addresses, options, label):
    """Matches that live outside every module are data on the heap - chain them back to static."""
    loose = []
    for address in addresses[:POINTER_TARGETS]:
        resolved = address + options["offset"]
        if not inside_module(modules, resolved) and process.read_pointer(resolved) is not None:
            loose.append(resolved)
    if not loose:
        return None
    line(f"{DIM}heap address {RESET}")
    print()
    return chain_for(process, modules, main, loose[0], label)


def handle(process, modules, main, raw):
    raw = raw.replace(",", " ").replace(";", " ").strip()
    if raw.split()[0].lower() in ("ptr", "pointer"):
        if not process.alive():
            raise ScanError("process closed")
        return pointer(process, modules, main, raw)
    if not BYTE_TOKEN.match(raw.split()[0]):
        return reverse(process, modules, main, raw)
    signature, extras = split_input(raw)
    pattern, length, wildcards = parse_pattern(signature)
    options = parse_options(extras)
    if not process.alive():
        raise ScanError("process closed")
    everywhere = options["all"]
    blocks = process.regions() if everywhere else [(main[1], main[2])]
    addresses = sweep_for(process, blocks, pattern, length, "module" if not everywhere else "process")
    if not addresses and not everywhere:
        line(f"{DIM}not in the main module {RESET}")
        print()
        everywhere = True
        addresses = sweep_for(process, process.regions(), pattern, length, "process")
    result = show(process, modules, addresses, options, length)
    if addresses and everywhere and not options["rip"] and not options["chain"]:
        return chase(process, modules, main, addresses, options, signature) or result
    return result


def hints():
    line(f"{DIM}paste the AOB or ptr (addr) {RESET}")
    print()


def session(process, modules, main, name):
    hints()
    while True:
        raw = ask("Input Aob / ptr")
        if not raw:
            return process
        clear()
        banner()
        if process.alive():
            panel("TARGET", process.card, GREEN)
            print()
        else:
            line(f"{YELLOW}the game closed - waiting for it to come back{RESET}")
            print()
            process.close()
            process, modules, main = attach(name)
        line(f"{CYAN}>{RESET} {DIM}{fit(raw, INNER).rstrip()}{RESET}")
        print()
        try:
            result = handle(process, modules, main, raw)
        except (ScanError, ValueError) as error:
            panel("ERROR", [f" {RED}{error}{RESET}"], RED)
            print()
            continue
        if result:
            clipboard(result)
        title(f"idle :: {process.name}")


def main():
    if sys.platform != "win32":
        return 2
    setup_console()
    clear()
    banner()
    enable_debug_privilege()
    name = sys.argv[1] if len(sys.argv) > 1 else None
    try:
        process, modules, image = attach(name)
    except ScanError as error:
        line(str(error), RED)
        return 1
    try:
        process = session(process, modules, image, name)
    finally:
        process.close()
    return 0


if __name__ == "__main__":
    try:
        code = main()
    except (SystemExit, KeyboardInterrupt):
        code = 0
    print(SHOW)
    sys.exit(code)