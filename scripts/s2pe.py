"""s2pe - offline model of a Source 2 game DLL (CS2, Deadlock) for static reverse engineering.

The DLL is mapped the way the loader would map it (sections at their RVAs, no relocations applied, so a
pointer stored in data is a VA against the preferred ImageBase). Everything this module takes and returns
is an RVA unless the name says _va.

Pieces:
  Image              sections, exports, imports, .pdata functions (+ chained-unwind primaries)
  Image.index()      every rip-relative operand and direct call/jmp/jcc target -> the instructions that
                     reference it; built once per DLL build and cached (see cache_dir())
  Image.vtables()    every MSVC RTTI vtable: start -> (class, COL offset, slot count, COL rva); cached
  Image.dis*()       capstone disassembly annotated with strings, floats, imports, exports, vtables
  scan / make_sig    IDA-style byte patterns ("48 8B 0D ? ? ? ?")
  schema_class       static SchemaClassInfoData_t (Source 2 schema system) -> declared fields + offsets
  convar_*           ConVar static initializers: name <-> object, and the code that reads the object
  protos             serialized FileDescriptorProtos embedded in the DLL -> .proto text
"""
import bisect
import glob
import hashlib
import os
import pickle
import re
import shutil
import struct
import sys
from collections import defaultdict, deque, namedtuple

from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP

CACHE_VERSION = 3  # bump when the index / vtable algorithms change
GAMES = {
    # game -> (steamapps\common folder, mod folder under game\)
    "cs2": ("Counter-Strike Global Offensive", "csgo"),
    "deadlock": ("Deadlock", "citadel"),
    # folder names from the Steam defaults; not tested (neither game was installed when these were added)
    "dota2": ("dota 2 beta", "dota"),
    "hlalyx": ("Half-Life Alyx", "hlvr"),
}
# more games without editing code: S2RE_GAMES="name=Steam folder:mod;other=Folder:mod"
for _entry in filter(None, os.environ.get("S2RE_GAMES", "").split(";")):
    _k, _, _v = _entry.partition("=")
    if ":" in _v:
        GAMES[_k.strip()] = tuple(x.strip() for x in _v.rsplit(":", 1))

PARALLEL = False  # the CLI turns this on; library users opt in (multiprocessing re-imports the main script)
KEEP_SNAPSHOTS = 2  # per module: the current build and the one before it
SCN_EXECUTE = 0x20000000
UNW_FLAG_CHAININFO = 4
BRANCHES_REL = ("call", "jmp", "loop", "loope", "loopne", "jrcxz", "jecxz")

Section = namedtuple("Section", "name rva size flags")
VTable = namedtuple("VTable", "start cls col_offset slots col")


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _i32(b, o):
    return struct.unpack_from("<i", b, o)[0]


def _u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


# ---------------------------------------------------------------------------------------------- locating DLLs

def steam_libraries():
    """Steam library roots: $S2RE_STEAM, the default install, and every path in libraryfolders.vdf."""
    roots = []
    if os.environ.get("S2RE_STEAM"):
        roots.append(os.environ["S2RE_STEAM"])
    default = r"C:\Program Files (x86)\Steam"
    roots.append(default)
    try:
        with open(os.path.join(default, "steamapps", "libraryfolders.vdf"), encoding="utf-8", errors="replace") as fh:
            for m in re.finditer(r'"path"\s+"([^"]+)"', fh.read()):
                roots.append(m.group(1).replace("\\\\", "\\"))
    except OSError:
        pass
    seen, out = set(), []
    for r in roots:
        k = os.path.normcase(os.path.abspath(r))
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out


def resolve_module(game, module):
    """`module` is a path, or a DLL name looked up in game\\<mod>\\bin\\win64 then game\\bin\\win64."""
    if os.path.isfile(module):
        return os.path.abspath(module)
    name = module if module.lower().endswith(".dll") else module + ".dll"
    folder, mod = GAMES[game]
    tried = []
    for root in steam_libraries():
        game_dir = os.path.join(root, "steamapps", "common", folder, "game")
        for sub in (os.path.join(mod, "bin", "win64"), os.path.join("bin", "win64")):
            p = os.path.join(game_dir, sub, name)
            tried.append(p)
            if os.path.isfile(p):
                return p
    raise FileNotFoundError(f"{name} not found for {game}; tried:\n  " + "\n  ".join(tried))


def cache_dir():
    d = os.environ.get("S2RE_CACHE") or os.path.join(
        os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "s2re-cache")
    os.makedirs(d, exist_ok=True)
    return d


# ---------------------------------------------------------------------------------------------- the image

class Image:
    def __init__(self, path, dump=False, layout=None, base=None, headers_from=None):
        """A DLL from disk, or (dump=True) a module dumped from a running process.
        layout        'file' (sections at their raw offsets: a DLL, or a rebuilt dump) or 'mapped' (file offset =
                      RVA: a raw copy of the module's memory). Detected when omitted; 'mapped' implies dump.
        base          the runtime base the dump's pointers were relocated to. Detected when omitted: the header's
                      ImageBase if the relocated pointers agree with it, else the base they point from.
        headers_from  a DLL of the same build whose PE headers replace missing or erased ones in the dump."""
        self.path = os.path.abspath(path)
        self.name = os.path.basename(self.path)
        with open(self.path, "rb") as fh:
            raw = fh.read()
        st = os.stat(self.path)
        self.file_size, self.mtime = st.st_size, int(st.st_mtime)
        self.headers_from = os.path.abspath(headers_from) if headers_from else None
        hdr = raw
        if self.headers_from:
            with open(self.headers_from, "rb") as fh:
                hdr = fh.read(0x10000)
        if hdr[:2] != b"MZ":
            raise ValueError(f"{path}: no PE header" + (" (erased? pass headers_from / --headers-from with the matching"
                                                        " DLL)" if dump or layout == "mapped" else "; not a PE file"))
        nt = _u32(hdr, 0x3C)
        if hdr[nt:nt + 4] != b"PE\0\0" or _u16(hdr, nt + 4) != 0x8664:
            raise ValueError(f"{path}: not an x64 PE")
        self.timestamp = _u32(hdr, nt + 8)
        nsec, optsz = _u16(hdr, nt + 6), _u16(hdr, nt + 20)
        opt = nt + 24
        if _u16(hdr, opt) != 0x20B:
            raise ValueError(f"{path}: not PE32+")
        self.header_base = self.base = _u64(hdr, opt + 24)
        self.size = _u32(hdr, opt + 56)
        headers = _u32(hdr, opt + 60)
        ndir = min(_u32(hdr, opt + 108), 16)
        self.dirs = [struct.unpack_from("<II", hdr, opt + 112 + 8 * i) for i in range(ndir)] + [(0, 0)] * (16 - ndir)
        secs = []
        for i in range(nsec):
            o = opt + optsz + 40 * i
            vsize, va, rsize, rptr = struct.unpack_from("<IIII", hdr, o + 8)
            secs.append((hdr[o:o + 8].rstrip(b"\0").decode("latin1"), vsize, va, rsize, rptr, _u32(hdr, o + 36)))
        if layout is None:
            layout = _detect_layout(raw, secs, self.size, self.dirs[3], dump, self.dirs[4])
        mem = bytearray(self.size)
        if layout == "mapped":
            n = min(len(raw), self.size)
            mem[:n] = raw[:n]
            if self.headers_from:
                mem[:headers] = hdr[:headers]
        else:
            mem[:headers] = hdr[:headers]
            for _, vsize, va, rsize, rptr, _ in secs:
                n = max(0, min(rsize, vsize or rsize, self.size - va, len(raw) - rptr))
                mem[va:va + n] = raw[rptr:rptr + n]
        self.sections = [Section(name, va, vsize or rsize, flags) for name, vsize, va, rsize, rptr, flags in secs]
        self.mem = bytes(mem)
        self.layout = layout
        self.dump = bool(dump or layout == "mapped" or self.headers_from or base is not None)
        self.code_sections = [s for s in self.sections if s.flags & SCN_EXECUTE]
        self.text = self.section(".text") or self.code_sections[0]
        self._load_pdata()
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True
        self._index = self._vtables = self._vt_starts = self._exports = self._imports = None
        self._export_at = self._chunks = self._relocs = None
        self.base_source = "header"
        if self.dump:
            if base is not None:
                self.base, self.base_source = base, "given"
            else:
                self.base, self.base_source = self._detect_base()

    def open_args(self):
        """Keyword arguments that reopen this exact image (used by the index workers)."""
        return {"dump": self.dump, "layout": self.layout, "base": self.base if self.dump else None,
                "headers_from": self.headers_from}

    # ------------------------------------------------------------------ dumps
    def relocations(self):
        """RVAs of the 64-bit absolute pointers the loader rebases (IMAGE_REL_BASED_DIR64 entries), sorted. A dump
        without a usable .reloc falls back to the relocations of `headers_from`."""
        if self._relocs is None:
            self._relocs = _parse_relocs(self.mem, self.dirs[5])
            if not self._relocs and self.headers_from:
                self._relocs = Image(self.headers_from).relocations()
        return self._relocs

    def _detect_base(self):
        """(base, how) for a dump. Every relocated pointer that lands on a .pdata function start votes for
        `value - start`; only 64 KB-aligned bases count (Windows maps images on that granularity). The header's
        ImageBase wins when it is (nearly) as good, since the loader writes the real base there."""
        slots = self.relocations()
        if not slots:
            return self.header_base, "header (no relocations to check it against)"
        step = max(1, len(slots) // 50000)
        vals = [_u64(self.mem, s) for s in slots[::step] if s + 8 <= len(self.mem)]
        buckets = defaultdict(list)
        for s in self.func_starts:
            buckets[s & 0xFFFF].append(s)
        votes = defaultdict(int)
        for v in vals:
            for s in buckets.get(v & 0xFFFF, ()):
                if v > s:
                    votes[v - s] += 1
        if not votes:
            raise ValueError(f"{self.path}: cannot determine the runtime base (no relocated pointer lands on a "
                             f"function start); pass base / --base")
        best, n = max(votes.items(), key=lambda kv: kv[1])
        if n < max(25, len(vals) // 100):
            raise ValueError(f"{self.path}: cannot determine the runtime base (best guess {best:#x} explains only {n}"
                             f" of {len(vals)} relocated pointers); pass base / --base")
        if votes.get(self.header_base, 0) >= 0.9 * n:
            return self.header_base, f"header, confirmed by {votes[self.header_base]} relocated pointers"
        return best, f"relocations ({n} of {len(vals)} sampled pointers; header says {self.header_base:#x})"

    # ------------------------------------------------------------------ basics
    def section(self, name):
        return next((s for s in self.sections if s.name == name), None)

    def section_of(self, rva):
        for s in self.sections:
            if s.rva <= rva < s.rva + s.size:
                return s.name
        return None

    def is_code(self, rva):
        return any(s.rva <= rva < s.rva + s.size for s in self.code_sections)

    def to_rva(self, value):
        """Accept an RVA or a VA (against the preferred ImageBase, or the runtime base for a dump)."""
        return value - self.base if value >= self.base else value

    def u32(self, rva):
        return _u32(self.mem, rva)

    def i32(self, rva):
        return _i32(self.mem, rva)

    def u64(self, rva):
        return _u64(self.mem, rva)

    def ptr(self, rva):
        """The qword at rva as an RVA when it points into the image, else None."""
        v = _u64(self.mem, rva)
        return v - self.base if self.base <= v < self.base + self.size else None

    def cstr(self, rva, limit=256):
        end = self.mem.find(b"\0", rva, rva + limit)
        return self.mem[rva:end if end != -1 else rva + limit].decode("latin1")

    def printable_at(self, rva, minlen=4, limit=120):
        s = self.cstr(rva, limit)
        if len(s) >= minlen and all(32 <= ord(c) < 127 or c in "\t\r\n" for c in s):
            return s
        return None

    def find_bytes(self, needle, lo=0, hi=None):
        hi = len(self.mem) if hi is None else hi
        out, i = [], self.mem.find(needle, lo, hi)
        while i != -1:
            out.append(i)
            i = self.mem.find(needle, i + 1, hi)
        return out

    def find_cstr(self, s):
        """Exact NUL-terminated string that starts after a NUL (not the tail of a longer string)."""
        return [i for i in self.find_bytes(s.encode("latin1") + b"\0") if i == 0 or self.mem[i - 1] == 0]

    def find_cstr_partial(self, sub, section=".rdata"):
        """Start rvas of NUL-delimited strings containing `sub`."""
        sec = self.section(section)
        lo, hi = (sec.rva, sec.rva + sec.size) if sec else (0, len(self.mem))
        out = set()
        for i in self.find_bytes(sub.encode("latin1"), lo, hi):
            st = self.mem.rfind(b"\0", lo, i) + 1
            out.add(st)
        return sorted(out)

    def stored_at(self, rva):
        """Where the VA of `rva` is stored as a qword (pointer tables, vtables, static structs)."""
        return self.find_bytes(struct.pack("<Q", self.base + rva))

    # ------------------------------------------------------------------ functions (.pdata)
    def _load_pdata(self):
        rva, size = self.dirs[3]
        self.funcs, self.unwind = [], {}
        if rva:
            for b, e, u in struct.iter_unpack("<III", self.mem[rva:rva + size - size % 12]):
                if b and e > b:
                    self.funcs.append((b, e))
                    self.unwind[b] = u
        self.funcs.sort()
        self.func_starts = [f[0] for f in self.funcs]

    def func_of(self, rva):
        """(begin, end) of the .pdata entry containing rva, or None (leaf function without unwind info)."""
        i = bisect.bisect_right(self.func_starts, rva) - 1
        if i >= 0 and self.funcs[i][0] <= rva < self.funcs[i][1]:
            return self.funcs[i]
        return None

    def primary(self, begin):
        """Follow chained unwind info (split function chunks) back to the primary function's start."""
        seen = set()
        while begin not in seen:
            seen.add(begin)
            u = self.unwind.get(begin)
            if u is None:
                return begin
            if u & 1:  # RUNTIME_FUNCTION_INDIRECT: points at another RUNTIME_FUNCTION
                begin = _u32(self.mem, u - 1)
                continue
            if not (self.mem[u] >> 3) & UNW_FLAG_CHAININFO:
                return begin
            count = self.mem[u + 2]
            begin = _u32(self.mem, u + 4 + 2 * ((count + 1) & ~1))
        return begin

    def function_start(self, rva):
        """Primary function start for any rva inside a .pdata function, else None."""
        f = self.func_of(rva)
        return self.primary(f[0]) if f else None

    # ------------------------------------------------------------------ exports / imports
    def exports(self):
        """name -> rva (forwarders skipped)."""
        if self._exports is None:
            out = {}
            rva, size = self.dirs[0]
            if rva:
                m = self.mem
                nname = _u32(m, rva + 24)
                afun, aname, aord = _u32(m, rva + 28), _u32(m, rva + 32), _u32(m, rva + 36)
                for i in range(nname):
                    f = _u32(m, afun + 4 * _u16(m, aord + 2 * i))
                    if not (rva <= f < rva + size):
                        out[self.cstr(_u32(m, aname + 4 * i))] = f
            self._exports = out
            self._export_at = {v: k for k, v in out.items()}
        return self._exports

    def imports(self):
        """IAT slot rva -> 'dll!name' (or 'dll!#ordinal'); delay-load slots are tagged '[delay] dll!name'."""
        if self._imports is None:
            out = {}
            m = self.mem

            def thunks(names_rva, iat_rva, label):
                i = 0
                while True:
                    t = _u64(m, names_rva + 8 * i)
                    if not t:
                        break
                    out[iat_rva + 8 * i] = label + (f"#{t & 0xFFFF}" if t >> 63 else self.cstr((t & 0x7FFFFFFF) + 2))
                    i += 1

            rva, _ = self.dirs[1]
            d = rva
            while rva:
                oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", m, d)
                if not ft:
                    break
                thunks(oft or ft, ft, f"{self.cstr(name_rva)}!")
                d += 20
            rva, _ = self.dirs[13]  # delay-load imports: {attrs, dll name, hmodule, IAT, INT, ...} 32 bytes each
            d = rva
            while rva:
                _, name_rva, _, iat, names = struct.unpack_from("<IIIII", m, d)
                if not name_rva:
                    break
                thunks(names, iat, f"[delay] {self.cstr(name_rva)}!")
                d += 32
            self._imports = out
        return self._imports

    def find_wstr(self, s):
        """Exact NUL-terminated UTF-16LE string (preceded by a 16-bit NUL or the image start)."""
        return [i for i in self.find_bytes(s.encode("utf-16-le") + b"\0\0")
                if i % 2 == 0 and (i == 0 or self.mem[i - 2:i] == b"\0\0")]

    def wstr(self, rva, limit=256):
        end = rva
        while end < rva + 2 * limit and self.mem[end:end + 2] != b"\0\0":
            end += 2
        return self.mem[rva:end].decode("utf-16-le", "replace")

    # ------------------------------------------------------------------ caches
    def _cache_path(self, kind):
        dump = f"_dump{self.layout[0]}{self.base:x}" if self.dump else ""  # vtable rvas depend on the base
        return os.path.join(cache_dir(), f"{kind}{CACHE_VERSION}_{self.name}_{self.file_size}_{self.mtime}{dump}.pkl")

    def _cached(self, kind, build):
        path = self._cache_path(kind)
        if os.path.exists(path):
            try:
                with open(path, "rb") as fh:
                    return pickle.load(fh)
            except Exception:
                pass
        print(f"[s2re] building the {kind} cache for {self.name} (once per DLL build)...", file=sys.stderr, flush=True)
        data = build()
        tmp = path + ".tmp"
        with open(tmp, "wb") as fh:
            pickle.dump(data, fh, protocol=pickle.HIGHEST_PROTOCOL)
        os.replace(tmp, path)
        if kind == "idx":
            self.snapshot()  # a build we haven't seen: keep a copy so `port` works after the next update
        return data

    # ------------------------------------------------------------------ snapshots (for porting across builds)
    def snapshot_dir(self):
        key = hashlib.sha1(os.path.normcase(os.path.dirname(self.path)).encode()).hexdigest()[:8]
        return os.path.join(cache_dir(), "snapshots", f"{self.name}_{key}")

    def is_snapshot(self):
        return os.path.normcase(self.path).startswith(os.path.normcase(os.path.join(cache_dir(), "snapshots")))

    def snapshot(self, force=False):
        """Copy this DLL into the snapshot store (mtime kept, so its caches stay valid). Keeps the newest
        KEEP_SNAPSHOTS builds per module. Off with S2RE_NO_SNAPSHOT=1. Returns the copy's path or None."""
        if self.dump or self.is_snapshot() or (os.environ.get("S2RE_NO_SNAPSHOT") == "1" and not force):
            return None
        d = self.snapshot_dir()
        os.makedirs(d, exist_ok=True)
        dst = os.path.join(d, f"{self.file_size}_{self.mtime}.dll")
        if not os.path.exists(dst):
            shutil.copy2(self.path, dst)
            with open(os.path.join(d, "source.txt"), "w", encoding="utf-8") as fh:
                fh.write(self.path)
            print(f"[s2re] saved a snapshot of this {self.name} build (for `port` after the next update): {dst}",
                  file=sys.stderr, flush=True)
        keep = sorted(glob.glob(os.path.join(d, "*.dll")), key=os.path.getmtime, reverse=True)
        for old in keep[max(KEEP_SNAPSHOTS, 1):]:
            try:
                os.remove(old)
            except OSError:
                pass
        return dst

    def snapshots(self):
        """Saved builds of this module other than the current file, newest first (none for a dump)."""
        if self.dump:
            return []
        own = f"{self.file_size}_{self.mtime}.dll"
        files = glob.glob(os.path.join(self.snapshot_dir(), "*.dll"))
        return sorted((f for f in files if os.path.basename(f) != own), key=os.path.getmtime, reverse=True)

    def cache_status(self):
        return {k: os.path.exists(self._cache_path(k)) for k in ("idx", "vt")}

    # ------------------------------------------------------------------ reference index
    def _sweep_regions(self):
        """Linear-sweep regions over the executable sections: each .pdata function, plus the gaps between
        them (leaf functions without unwind info, e.g. tiny global accessors, live in the gaps)."""
        out = []
        for s in self.code_sections:
            lo, hi = s.rva, s.rva + s.size
            pos = lo
            i = bisect.bisect_left(self.func_starts, lo)
            while i < len(self.funcs) and self.funcs[i][0] < hi:
                b, e = self.funcs[i]
                if b > pos:
                    out.append((pos, b))
                b = max(b, pos)
                e = min(e, hi)
                if e > b:
                    out.append((b, e))
                pos = max(pos, e)
                i += 1
            if pos < hi:
                out.append((pos, hi))
        return out

    def _build_index(self):
        regions = self._sweep_regions()
        parts = None
        jobs = int(os.environ.get("S2RE_JOBS") or min(os.cpu_count() or 1, 8))
        if PARALLEL and jobs > 1 and len(regions) > 2000:
            total = sum(h - l for l, h in regions)
            per = total // (jobs * 4) + 1
            chunks, cur, acc = [], [], 0
            for r in regions:
                cur.append(r)
                acc += r[1] - r[0]
                if acc >= per:
                    chunks.append(cur)
                    cur, acc = [], 0
            if cur:
                chunks.append(cur)
            try:
                import multiprocessing as mp
                with mp.get_context("spawn").Pool(jobs) as pool:
                    parts = pool.map(_index_worker, [(self.path, self.open_args(), c) for c in chunks])
            except Exception as e:  # fall back to one process
                print(f"[s2re] parallel index build failed ({e}); using one process", file=sys.stderr)
                parts = None
        if parts is None:
            parts = [_sweep_index(self, regions)]
        idx = defaultdict(list)
        for p in parts:
            for k, v in p.items():
                idx[k].extend(v)
        return dict(idx)

    def index(self):
        if self._index is None:
            self._index = self._cached("idx", self._build_index)
            try:
                self.snapshot()  # no-op when this build is already saved
            except OSError as e:
                print(f"[s2re] snapshot failed: {e}", file=sys.stderr)
        return self._index

    def xrefs(self, target):
        """Instruction rvas that reference `target` (rip-relative operand or direct call/jmp/jcc)."""
        return sorted(self.index().get(target, []))

    # ------------------------------------------------------------------ RTTI
    @staticmethod
    def demangle_type(mangled):
        """'.?AVInner@Outer@@' -> 'Outer::Inner'; templates ('?$') are returned without the prefix only."""
        s = mangled
        for p in (".?AV", ".?AU"):
            if s.startswith(p):
                s = s[len(p):]
                break
        if s.endswith("@@"):
            s = s[:-2]
        if "?" in s:
            return s
        return "::".join(reversed(s.split("@")))

    def _build_vtables(self):
        """MSVC x64 RTTI. CompleteObjectLocator = {u32 sig=1, offset, cdOffset, rva TypeDescriptor,
        rva ClassHierarchyDescriptor, rva self}; the qword before every vtable holds its COL's VA.
        TypeDescriptor = {pVFTable, spare, char name[]}."""
        m, base = self.mem, self.base
        cols = {}
        # MSVC emits COLs and vtables in .rdata; scanning .data too would unpack its (large, zero) bss tail
        rdata = [s for s in self.sections if s.name == ".rdata"] or \
                [s for s in self.sections if not s.flags & SCN_EXECUTE and not s.flags & 0x80000000]
        for sec in rdata:
            if sec.size < 24:
                continue
            lo = (sec.rva + 3) & ~3
            n = (sec.rva + sec.size - lo) // 4
            arr = struct.unpack_from(f"<{n}I", m, lo)
            i = -1
            while True:
                try:
                    i = arr.index(1, i + 1)
                except ValueError:
                    break
                if i + 5 < n and arr[i + 5] == lo + 4 * i:
                    td = arr[i + 3]
                    if 0 < td < self.size - 16:
                        name = self.cstr(td + 16, 512)
                        if name.startswith(".?A"):
                            cols[lo + 4 * i] = (name, arr[i + 1])
        col_va = {base + c: c for c in cols}
        vts = []
        for sec in rdata:
            if sec.size < 16:
                continue
            lo = (sec.rva + 7) & ~7
            n = (sec.rva + sec.size - lo) // 8
            q = struct.unpack_from(f"<{n}Q", m, lo)
            for j, v in enumerate(q):
                c = col_va.get(v)
                if c is None:
                    continue
                start = lo + 8 * j + 8
                k = 0
                while start + 8 * k + 8 <= self.size:
                    t = _u64(m, start + 8 * k) - base
                    if not (0 <= t < self.size and self.is_code(t)):
                        break
                    k += 1
                name, off = cols[c]
                vts.append(VTable(start, name, off, k, c))
        vts.sort()
        return [tuple(v) for v in vts]

    def vtables(self):
        if self._vtables is None:
            self._vtables = [VTable(*v) for v in self._cached("vt", self._build_vtables)]
            self._vt_starts = {v.start: v for v in self._vtables}
            self._vt_sorted = [v.start for v in self._vtables]
        return self._vtables

    def vtable_at(self, start):
        self.vtables()
        return self._vt_starts.get(start)

    def vtable_slot(self, pos):
        """(VTable, slot index) when the qword at `pos` is inside a known vtable."""
        self.vtables()
        i = bisect.bisect_right(self._vt_sorted, pos) - 1
        if i >= 0:
            v = self._vtables[i]
            if v.start <= pos < v.start + 8 * v.slots and (pos - v.start) % 8 == 0:
                return v, (pos - v.start) // 8
        return None

    def vtable_slots(self, vt):
        return [_u64(self.mem, vt.start + 8 * i) - self.base for i in range(vt.slots)]

    def base_classes(self, col):
        """Base class names from the COL's ClassHierarchyDescriptor (first entry = the class itself)."""
        m = self.mem
        chd = _u32(m, col + 16)
        if not (0 < chd < self.size - 16):
            return []
        num, arr = _u32(m, chd + 8), _u32(m, chd + 12)
        out = []
        for i in range(min(num, 256)):
            bcd = _u32(m, arr + 4 * i)
            td = _u32(m, bcd)
            out.append(self.demangle_type(self.cstr(td + 16, 512)))
        return out

    # ------------------------------------------------------------------ disassembly
    def target_of(self, ins):
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                return ins.address + ins.size + op.mem.disp
        if (ins.mnemonic in BRANCHES_REL or ins.mnemonic.startswith("j")) and ins.operands \
                and ins.operands[0].type == X86_OP_IMM:
            return ins.operands[0].imm
        return None

    def describe(self, t, mnemonic=""):
        """Short annotation for a referenced rva."""
        if not (0 <= t < self.size):
            return ""
        imp = self.imports().get(t)
        if imp:
            return f"[IAT] {imp}"
        self.exports()
        sec = self.section_of(t) or "?"
        note = f"{t:#x} {sec}"
        if t in self._export_at:
            note += f" export {self._export_at[t]}"
        vt = self.vtable_at(t)
        if vt:
            return note + f" vtable {self.demangle_type(vt.cls)}" + (f" (COL offset {vt.col_offset:#x})" if vt.col_offset else "")
        if sec in (".rdata", ".data"):
            s = self.printable_at(t)
            if s:
                return note + ' "' + (s if len(s) <= 80 else s[:77] + "...") + '"'
            if sec == ".rdata":
                if "sd" in mnemonic or "pd" in mnemonic:
                    return note + f" (f64 {struct.unpack_from('<d', self.mem, t)[0]:g})"
                if any(x in mnemonic for x in ("ss", "ps", "movd")) or mnemonic in ("movss", "comiss", "ucomiss"):
                    return note + f" (f32 {struct.unpack_from('<f', self.mem, t)[0]:g})"
                p = self.ptr(t)
                if p is not None:
                    return note + f" (-> {p:#x} {self.section_of(p) or ''})"
                return note + f" (f32 {struct.unpack_from('<f', self.mem, t)[0]:g})"
        return note

    def fmt(self, ins, annotate=True):
        note = ""
        if annotate:
            t = self.target_of(ins)
            if t is not None:
                d = self.describe(t, ins.mnemonic)
                if d:
                    note = "  ; -> " + d
        return f"{ins.address:#010x}: {ins.mnemonic:8} {ins.op_str}{note}"

    def dis(self, start, end=None, count=None, annotate=True, stop_at_ret=False):
        lines = []
        end = end or start + 0x4000
        for ins in self.md.disasm(self.mem[start:end], start):
            lines.append(self.fmt(ins, annotate))
            if count and len(lines) >= count:
                break
            if stop_at_ret and ins.mnemonic in ("ret", "int3"):
                break
        return "\n".join(lines)

    def chunks_of(self, primary):
        """[(begin, end)] of the split chunks (chained unwind) belonging to a primary function, sorted."""
        if self._chunks is None:
            ch = defaultdict(list)
            for b, e in self.funcs:
                u = self.unwind.get(b)
                if u is not None and (u & 1 or (self.mem[u] >> 3) & UNW_FLAG_CHAININFO):
                    p = self.primary(b)
                    if p != b:
                        ch[p].append((b, e))
            self._chunks = dict(ch)
        return sorted(self._chunks.get(primary, []))

    def function_ranges(self, rva):
        """All code ranges of the function containing rva: the primary entry first, then its chunks. A leaf
        function (no .pdata) is one range up to its first ret / int3 (max 200 instructions)."""
        f = self.func_of(rva)
        if not f:
            end = rva
            for ins in self.md.disasm(self.mem[rva:rva + 0x1000], rva):
                end = ins.address + ins.size
                if ins.mnemonic in ("ret", "int3") or end - rva > 0xC00:
                    break
            return [(rva, end)]
        p = self.primary(f[0])
        pf = self.func_of(p) or f
        return [pf] + self.chunks_of(p)

    def dis_func(self, rva, stitch=True):
        f = self.func_of(rva)
        if not f:
            return (f"; {rva:#x}: no .pdata entry (leaf function or not code); up to the first ret, max 200 insns\n"
                    + self.dis(rva, count=200, stop_at_ret=True))
        p = self.primary(f[0])
        ranges = self.function_ranges(rva) if stitch else [f]
        out = [f"; function {p:#x}: {len(ranges)} range(s), {sum(e - b for b, e in ranges)} bytes; "
               f"{len(self.xrefs(p))} refs to {p:#x}"]
        for b, e in ranges:
            out.append(f"; ---- {b:#x}-{e:#x} ({e - b} bytes)" + ("" if b == p else " chunk (chained unwind)"))
            out.append(self.dis(b, e))
        return "\n".join(out)

    def insn_at(self, rva):
        return next(self.md.disasm(self.mem[rva:rva + 16], rva, 1), None)

    def insns(self, rva):
        """Decoded instructions of the whole function containing rva (all chunks)."""
        out = []
        for b, e in self.function_ranges(rva):
            out.extend(self.md.disasm(self.mem[b:e], b))
        return out

    def callees(self, rva):
        """[(site, target, how)] for direct calls / tail jumps out of the function (how: call, jmp, iat)."""
        ranges = self.function_ranges(rva)
        inside = lambda t: any(b <= t < e for b, e in ranges)  # noqa: E731
        out = []
        imps = self.imports()
        for ins in self.insns(rva):
            if ins.mnemonic not in ("call", "jmp"):
                continue
            t = self.target_of(ins)
            if t is None:
                continue
            if t in imps:
                out.append((ins.address, t, "iat"))
            elif ins.mnemonic == "call" or not inside(t):
                if self.is_code(t):
                    out.append((ins.address, t, ins.mnemonic))
        return out

    def field_map(self, rva, reg="rcx"):
        """Offsets accessed through a register in the function containing rva: [(site, offset, size, access,
        text)]. Linear approximation: copies (mov r2, r1) are followed, any other write to a tracked register
        drops it; branches are ignored. Sizes come from the memory operand (lea = 0)."""
        reg = reg.lower()
        tracked = {reg}
        out = []
        for ins in self.insns(rva):
            ops = ins.operands
            for i, op in enumerate(ops):
                if op.type == X86_OP_MEM and op.mem.base and ins.reg_name(op.mem.base) in tracked and not op.mem.index:
                    access = "lea" if ins.mnemonic == "lea" else ("write" if i == 0 and ins.mnemonic.startswith(("mov", "and", "or", "add", "sub", "xor", "inc", "dec")) and ins.mnemonic not in ("movzx", "movsx", "movsxd") else "read")
                    out.append((ins.address, op.mem.disp, 0 if ins.mnemonic == "lea" else op.size, access,
                                f"{ins.mnemonic} {ins.op_str}"))
            if ops and ops[0].type == X86_OP_REG:
                dst = ins.reg_name(ops[0].reg)
                full = _full_reg(dst)
                if ins.mnemonic == "mov" and len(ops) == 2 and ops[1].type == X86_OP_REG and \
                        _full_reg(ins.reg_name(ops[1].reg)) in tracked and dst == full:
                    tracked.add(full)
                elif full in tracked and ins.mnemonic not in ("cmp", "test", "push") and full != "rsp":
                    tracked.discard(full)
            if ins.mnemonic == "call":  # volatile registers are gone after a call
                tracked -= {"rax", "rcx", "rdx", "r8", "r9", "r10", "r11"}
            if not tracked:
                break
        return out

    # ------------------------------------------------------------------ patterns
    @staticmethod
    def pattern_regex(pattern, mask=None):
        out = b""
        for b in parse_pattern(pattern, mask):
            out += b"." if b is None else re.escape(bytes([b]))
        return re.compile(out, re.S)

    def scan(self, pattern, region="image", limit=None, mask=None):
        """region 'image' = the whole mapped image from offset 0 (what a module scanner sees), 'code' =
        executable sections only. `pattern` may be IDA / x64dbg / compact hex, or a code-style "\\x48\\x8B"
        string with `mask` ("xx??")."""
        rx = self.pattern_regex(pattern, mask)
        ranges = [(0, self.size)] if region == "image" else [(s.rva, s.rva + s.size) for s in self.code_sections]
        out = []
        for lo, hi in ranges:
            pos = lo
            while True:
                m = rx.search(self.mem, pos, hi)
                if not m:
                    break
                out.append(m.start())
                if limit and len(out) >= limit:
                    return out
                pos = m.start() + 1
        return out

    def rel(self, rva, disp_off, insn_len):
        """Resolve a rel32 operand: rva + insn_len + i32 at (rva + disp_off)."""
        return rva + insn_len + _i32(self.mem, rva + disp_off)

    def make_sig(self, rva, max_insns=32, loose=False):
        """Shortest prefix pattern starting at `rva` that is unique in the image. Wildcards: rip-relative
        displacements and rel32 branch targets; loose also wildcards rel8 branches, other disp32 (struct
        offsets) and imm32 constants. Returns (pattern, n_insns, unique, rel) where rel = (disp_off, insn_len)
        of the first rip-relative/branch operand (for resolving the pattern to its target)."""
        toks, rel, n = [], None, 0
        pos = rva
        for ins in self.md.disasm(self.mem[rva:rva + 16 * max_insns], rva):
            raw = self.mem[ins.address:ins.address + ins.size]
            wild = set()
            rip_mem = any(op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP for op in ins.operands)
            is_branch = (ins.mnemonic in BRANCHES_REL or ins.mnemonic.startswith("j")) and ins.operands \
                and ins.operands[0].type == X86_OP_IMM
            if rip_mem and ins.disp_size:
                wild.update(range(ins.disp_offset, ins.disp_offset + ins.disp_size))
                if rel is None:
                    rel = (ins.address - rva + ins.disp_offset, ins.address - rva + ins.size)
            elif ins.disp_size == 4 and loose:
                wild.update(range(ins.disp_offset, ins.disp_offset + 4))
            if is_branch and ins.imm_size and (ins.imm_size >= 4 or loose):
                wild.update(range(ins.imm_offset, ins.imm_offset + ins.imm_size))
                if rel is None and ins.imm_size == 4:
                    rel = (ins.address - rva + ins.imm_offset, ins.address - rva + ins.size)
            elif not is_branch and ins.imm_size == 4 and loose:
                wild.update(range(ins.imm_offset, ins.imm_offset + 4))
            toks += ["?" if i in wild else f"{b:02X}" for i, b in enumerate(raw)]
            n += 1
            pos = ins.address + ins.size
            pat = " ".join(toks)
            if len(self.scan(pat, "image", limit=2)) == 1:
                return pat, n, True, rel
            if n >= max_insns:
                break
        return " ".join(toks), n, False, rel

    def operand_field(self, ins, target):
        """(offset in instruction, size) of the rel32/disp32 field in `ins` that resolves to `target`."""
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP and ins.address + ins.size + op.mem.disp == target:
                return ins.disp_offset, ins.disp_size
        if ins.operands and ins.operands[0].type == X86_OP_IMM and ins.operands[0].imm == target and ins.imm_size == 4:
            return ins.imm_offset, ins.imm_size
        return None

    def make_sig_target(self, target, max_insns=32, loose=False, max_sites=40):
        """Signatures that LEAD to `target` (a global, a function, a string): a unique pattern at the target
        itself (when it is code) and at each instruction referencing it, with the --rel that resolves the
        referencing operand. Returns [(site, pattern, n_insns, rel)] for unique ones, shortest first."""
        out = []
        if self.is_code(target):
            pat, n, unique, _ = self.make_sig(target, max_insns, loose)
            if unique:
                out.append((target, pat, n, None))
        for site in self.xrefs(target)[:max_sites]:
            ins = self.insn_at(site)
            fld = ins and self.operand_field(ins, target)
            if not fld:
                continue
            pat, n, unique, _ = self.make_sig(site, max_insns, loose)
            if unique:
                out.append((site, pat, n, (fld[0], ins.size)))
        out.sort(key=lambda x: (len(x[1]), x[0] != target))
        return out

    # ------------------------------------------------------------------ Source 2: schema system
    def schema_class(self, name):
        """Static SchemaClassInfoData_t whose +0x08 points at `name`: +0x20 i32 sizeof, +0x24 i16 field
        count, +0x30 SchemaClassFieldData_t* (0x20 each: +0x00 name*, +0x10 i32 offset). Fields are the
        class's OWN declared fields (not inherited). Returns [(info_rva, sizeof, [(field, offset), ...])]."""
        res = []
        for s in self.find_cstr(name):
            for p in self.stored_at(s):
                if p % 8:
                    continue
                ci = p - 0x08
                size = _i32(self.mem, ci + 0x20)
                cnt = struct.unpack_from("<h", self.mem, ci + 0x24)[0]
                farr = self.ptr(ci + 0x30)
                raw_farr = _u64(self.mem, ci + 0x30)
                if not (0 < size < 0x100000 and 0 <= cnt < 4096 and (raw_farr == 0 or farr is not None)):
                    continue
                fields = []
                for i in range(cnt if farr is not None else 0):
                    e = farr + 0x20 * i
                    np_ = self.ptr(e)
                    if np_ is None:
                        break
                    fields.append((self.cstr(np_), _i32(self.mem, e + 0x10)))
                res.append((ci, size, fields))
        return res

    # ------------------------------------------------------------------ Source 2: convars
    def _leas_near(self, ref, before=0x60, after=0x60):
        """(addr, dest reg name, target) for every `lea reg,[rip+X]` within [ref-before, ref+after], decoded
        from the containing function's start (or from ref-before when there is no .pdata entry)."""
        f = self.func_of(ref)
        lo = f[0] if f else max(0, ref - before)
        hi = f[1] if f else ref + after
        out = []
        for ins in self.md.disasm(self.mem[lo:hi], lo):
            if ins.address > ref + after:
                break
            if ins.address < ref - before or ins.mnemonic != "lea" or len(ins.operands) != 2:
                continue
            dst, src = ins.operands
            if src.type == X86_OP_MEM and src.mem.base == X86_REG_RIP:
                out.append((ins.address, ins.reg_name(dst.reg), ins.address + ins.size + src.mem.disp))
        return out

    def _convar_help(self, leas, exclude):
        best = None
        for addr, reg, t in leas:
            if t in exclude or self.section_of(t) != ".rdata":
                continue
            s = self.printable_at(t, minlen=13, limit=600)
            if s and (best is None or len(s) > len(best)):
                best = s
        return best

    def convar_by_name(self, name):
        """ConVar static initializer: `lea rdx,[name]` with `lea rcx,[object in .data]` next to it.
        Returns [(object, name_ref, init_function_or_None, help_text_or_None)]."""
        out = []
        for s in self.find_cstr(name):
            for r in self.xrefs(s):
                leas = self._leas_near(r)
                objs = [(abs(a - r), t) for a, reg, t in leas if reg == "rcx" and self.section_of(t) == ".data"]
                if not objs:
                    continue
                obj = min(objs)[1]
                if any(o[0] == obj for o in out):
                    continue
                out.append((obj, r, self.function_start(r), self._convar_help(leas, {s, obj})))
        return out

    def convar_by_object(self, obj):
        """Inverse: the initializer that does `lea rcx,[obj]` next to `lea rdx,[name in .rdata]`.
        Returns (name, init_ref, help) or (None, None, None)."""
        for r in self.xrefs(obj):
            leas = self._leas_near(r)
            if not any(a == r and reg == "rcx" for a, reg, t in leas):
                continue
            names = [(abs(a - r), t) for a, reg, t in leas if reg == "rdx" and self.section_of(t) == ".rdata"
                     and self.printable_at(t, minlen=2)]
            if names:
                t = min(names)[1]
                return self.cstr(t), r, self._convar_help(leas, {t, obj})
        return None, None, None

    def object_readers(self, obj, span=0x10):
        """[(instruction, offset into the object, function start)] for rip refs to obj+0 .. obj+span.
        CS2 (client.dll 2026-11-04) packs ConVar objects 0x10 apart, so a wider span picks up the neighbours'
        initializers."""
        out = []
        for off in range(0, span, 8):
            for r in self.xrefs(obj + off):
                out.append((r, off, self.function_start(r)))
        return sorted(out)

    # ------------------------------------------------------------------ Source 2: embedded protobuf descriptors
    def protos(self):
        """[(rva, name)] of serialized FileDescriptorProtos: tag 0x0A, 1-byte length, '<path>.proto'."""
        out = []
        ok = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_/.-")
        for i in self.find_bytes(b".proto"):
            end = i + 6
            st = i
            while st > 0 and self.mem[st - 1] in ok:
                st -= 1
            for L in range(7, min(127, end - st + 1) + 1):
                s = end - L
                if s >= 2 and self.mem[s - 1] == L and self.mem[s - 2] == 0x0A and all(c in ok for c in self.mem[s:end]):
                    out.append((s - 2, self.mem[s:end].decode()))
                    break
        return out

    def proto_descriptor(self, rva):
        """Decode the FileDescriptorProto at rva (stops where field numbers stop ascending)."""
        return _decode_file(self.mem, rva)


# ---------------------------------------------------------------------------------------------- helpers

_REG_FAMILIES = {}
for _full, _names in {
    "rax": "eax ax al ah", "rbx": "ebx bx bl bh", "rcx": "ecx cx cl ch", "rdx": "edx dx dl dh",
    "rsi": "esi si sil", "rdi": "edi di dil", "rbp": "ebp bp bpl", "rsp": "esp sp spl",
}.items():
    for _n in _names.split():
        _REG_FAMILIES[_n] = _full
for _i in range(8, 16):
    for _suf in ("d", "w", "b"):
        _REG_FAMILIES[f"r{_i}{_suf}"] = f"r{_i}"
REGS64 = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"} | {f"r{i}" for i in range(8, 16)}


def _full_reg(name):
    return _REG_FAMILIES.get(name, name)


def parse_pattern(text, mask=None):
    """Bytes (None = wildcard) from any common signature format:
    IDA "48 8B ? ?", x64dbg "48 8B ?? ??", compact "488B????", or code-style "\\x48\\x8B\\x00\\x00" + mask "xx??"."""
    text = text.strip()
    if "\\x" in text:
        vals = [int(h, 16) for h in re.findall(r"\\x([0-9a-fA-F]{2})", text)]
        if mask is None:
            mask = "x" * len(vals)
        if len(mask) != len(vals):
            raise ValueError(f"mask has {len(mask)} chars for {len(vals)} bytes")
        return [v if c == "x" else None for v, c in zip(vals, mask)]
    toks = text.split()
    if len(toks) == 1 and len(text) > 2:  # compact: "488B0D????????"
        toks = [text[i:i + 2] for i in range(0, len(text), 2)]
    return [None if t.startswith("?") else int(t, 16) for t in toks]


def format_pattern(vals, style="ida"):
    """style: ida ("48 8B ? ?"), x64dbg ("48 8B ?? ??"), code (('\\x48\\x8B\\x00\\x00', 'xx??'))."""
    if isinstance(vals, str):
        vals = parse_pattern(vals)
    if style == "ida":
        return " ".join("?" if v is None else f"{v:02X}" for v in vals)
    if style == "x64dbg":
        return " ".join("??" if v is None else f"{v:02X}" for v in vals)
    if style == "code":
        return ("".join(f"\\x{0 if v is None else v:02X}" for v in vals),
                "".join("?" if v is None else "x" for v in vals))
    raise ValueError(f"unknown style {style}")


_RIP = re.compile(r"\[rip(?: ([+-]) (0x[0-9a-f]+|\d+))?\]")
_TABLE_LOAD = re.compile(r"^(\w+), dword ptr \[(\w+) \+ (\w+)\*4 \+ (0x[0-9a-f]+)\]$")


def _sweep_index(img, regions):
    """Linear sweep: rip-relative operand targets and direct branch targets -> referencing instructions, plus
    MSVC x64 switch tables (`lea rB,[__ImageBase]` ... `mov e?x,[rB+rI*4+table]` ... `jmp r?x`: entries are
    u32 rvas inside the function; each case target is indexed as referenced by the jmp, the table by the load)."""
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    idx = defaultdict(list)
    mem = img.mem
    chunk = 0x10000
    for lo, hi in regions:
        off = lo
        base_regs = set()
        recent = deque(maxlen=12)
        while off < hi:
            code = mem[off:min(hi, off + chunk)]
            nxt = off
            for addr, size, mnem, ops in md.disasm_lite(code, off):
                nxt = addr + size
                if "rip" in ops:
                    m = _RIP.search(ops)
                    if m:
                        d = int(m.group(2), 0) if m.group(2) else 0
                        t = nxt + (-d if m.group(1) == "-" else d)
                        idx[t].append(addr)
                        if mnem == "lea" and t == 0:
                            base_regs.add(ops.split(",")[0])
                elif (mnem == "call" or mnem[0] == "j") and ops.startswith("0x"):
                    t = int(ops, 16)
                    if t < img.size:
                        idx[t].append(addr)
                elif mnem == "jmp" and ops in REGS64 and base_regs:
                    _jump_table(img, idx, addr, recent, base_regs)
                recent.append((addr, mnem, ops))
            off = nxt if nxt > off else off + 1  # undecodable byte: skip it
    return dict(idx)


def _jump_table(img, idx, jmp_addr, recent, base_regs):
    for addr, mnem, ops in reversed(recent):
        if mnem != "mov":
            continue
        m = _TABLE_LOAD.match(ops)
        if not m or m.group(2) not in base_regs:
            continue
        table = int(m.group(4), 16)
        ranges = img.function_ranges(jmp_addr) if img.func_of(jmp_addr) else \
            [(jmp_addr - 0x10000, jmp_addr + 0x10000)]
        if not (0 < table < img.size - 4):
            return
        idx[table].append(addr)
        seen = set()
        for i in range(1024):
            t = _u32(img.mem, table + 4 * i)
            if not any(b <= t < e for b, e in ranges):
                break
            if t not in seen:
                seen.add(t)
                idx[t].append(jmp_addr)
        return


_WORKER_IMG = None


def _index_worker(args):
    global _WORKER_IMG
    path, kw, regions = args
    if _WORKER_IMG is None or _WORKER_IMG.path != path or _WORKER_IMG.open_args() != kw:
        _WORKER_IMG = Image(path, **kw)
    return _sweep_index(_WORKER_IMG, regions)


def _parse_relocs(mem, directory):
    """DIR64 slot rvas from a base relocation directory: blocks of {u32 page rva, u32 block size, u16 entries},
    entry = type << 12 | page offset; type 10 = DIR64, 0 = padding."""
    rva, size = directory
    out = []
    pos, end = rva, min(rva + size, len(mem))
    while rva and pos + 8 <= end:
        page, bsz = struct.unpack_from("<II", mem, pos)
        if bsz < 8 or pos + bsz > end:
            break
        for (e,) in struct.iter_unpack("<H", mem[pos + 8:pos + bsz - (bsz - 8) % 2]):
            if e >> 12 == 10:
                out.append(page + (e & 0xFFF))
        pos += bsz
    return sorted(out)


def _detect_layout(raw, secs, size, pdata, dump, cert=(0, 0)):
    """'file' or 'mapped' for an input file. Sections whose raw offset equals their RVA make the two the same.
    Otherwise the .pdata table is read where each layout would put it; real entries are ascending and inside
    the code sections. A file that is not marked as a dump is only treated as mapped when the file layout gives
    garbage and the mapped one doesn't, so ordinary DLLs never take this path."""
    if all(rptr == va for _, _, va, rsize, rptr, _ in secs if rsize):
        return "file"
    code = [(va, va + (vs or rs)) for _, vs, va, rs, _, fl in secs if fl & SCN_EXECUTE]
    rva, psize = pdata

    def score(off):
        if not rva or off is None:
            return 0
        good, prev = 0, -1
        n = min(256, psize // 12)
        for i in range(n):
            o = off + 12 * i
            if o + 12 > len(raw):
                break
            b, e, _ = struct.unpack_from("<III", raw, o)
            if b > prev and e > b and any(lo <= b < hi for lo, hi in code):
                good += 1
            prev = max(prev, b)
        return good / n if n else 0

    file_off = next((rva - va + rp for _, vs, va, rs, rp, _ in secs if rs and va <= rva < va + max(vs, rs)), None)
    as_file, as_mapped = score(file_off), score(rva)
    if not dump:
        return "mapped" if as_file < 0.5 and as_mapped > 0.9 else "file"
    if abs(as_file - as_mapped) > 0.2:
        return "mapped" if as_mapped > as_file else "file"
    # Both readings look valid (a raw-offset shift that is a multiple of 12 lands on whole entries). A file-layout
    # image ends where its last section's raw data, or its Authenticode block (a file offset), ends.
    file_end = max((rp + rs for _, _, _, rs, rp, _ in secs if rs), default=0)
    if len(raw) == file_end or (cert[0] and cert[0] + cert[1] == len(raw)):
        return "file"
    return "mapped" if len(raw) >= 0.98 * size else "file"


# ---------------------------------------------------------------------------------------------- protobuf decoding

def _varint(d, p):
    r = s = 0
    while p < len(d):
        b = d[p]
        p += 1
        r |= (b & 0x7F) << s
        if not b & 0x80:
            return r, p
        s += 7
        if s > 63:
            break
    raise ValueError("bad varint")


def _fields(d, lo, hi):
    p = lo
    while p < hi:
        tag, p = _varint(d, p)
        fn, wt = tag >> 3, tag & 7
        if wt == 0:
            v, p = _varint(d, p)
        elif wt == 1:
            v, p = _u64(d, p), p + 8
        elif wt == 2:
            n, p = _varint(d, p)
            if p + n > hi:
                raise ValueError("length past end")
            v, p = d[p:p + n], p + n
        elif wt == 5:
            v, p = _u32(d, p), p + 4
        else:
            raise ValueError(f"wire type {wt}")
        yield fn, wt, v


_TYPES = {1: "double", 2: "float", 3: "int64", 4: "uint64", 5: "int32", 6: "fixed64", 7: "fixed32", 8: "bool",
          9: "string", 10: "group", 11: "message", 12: "bytes", 13: "uint32", 14: "enum", 15: "sfixed32",
          16: "sfixed64", 17: "sint32", 18: "sint64"}
_LABELS = {1: "optional", 2: "required", 3: "repeated"}


def _s(v):
    return bytes(v).decode("utf-8", "replace")


def _decode_field(d):
    f = {}
    for fn, wt, v in _fields(d, 0, len(d)):
        if fn == 1 and wt == 2: f["name"] = _s(v)
        elif fn == 2 and wt == 2: f["extendee"] = _s(v)
        elif fn == 3 and wt == 0: f["number"] = v
        elif fn == 4 and wt == 0: f["label"] = _LABELS.get(v, f"label{v}")
        elif fn == 5 and wt == 0: f["type"] = _TYPES.get(v, f"type{v}")
        elif fn == 6 and wt == 2: f["type_name"] = _s(v)
        elif fn == 7 and wt == 2: f["default"] = _s(v)
        elif fn == 9 and wt == 0: f["oneof"] = v
    return f


def _decode_enum(d):
    e = {"name": "", "values": []}
    for fn, wt, v in _fields(d, 0, len(d)):
        if fn == 1 and wt == 2:
            e["name"] = _s(v)
        elif fn == 2 and wt == 2:
            ev = {}
            for efn, ewt, evv in _fields(v, 0, len(v)):
                if efn == 1 and ewt == 2: ev["name"] = _s(evv)
                elif efn == 2 and ewt == 0: ev["number"] = evv - (1 << 64) if evv >> 63 else evv
            e["values"].append(ev)
    return e


def _decode_message(d):
    m = {"name": "", "fields": [], "nested": [], "enums": [], "extensions": [], "oneofs": []}
    for fn, wt, v in _fields(d, 0, len(d)):
        if wt != 2:
            continue
        if fn == 1: m["name"] = _s(v)
        elif fn == 2: m["fields"].append(_decode_field(v))
        elif fn == 3: m["nested"].append(_decode_message(v))
        elif fn == 4: m["enums"].append(_decode_enum(v))
        elif fn == 6: m["extensions"].append(_decode_field(v))
        elif fn == 8: m["oneofs"].append(next((_s(x) for f2, w2, x in _fields(v, 0, len(v)) if f2 == 1), "?"))
    return m


def _decode_service(d):
    s = {"name": "", "methods": []}
    for fn, wt, v in _fields(d, 0, len(d)):
        if fn == 1 and wt == 2:
            s["name"] = _s(v)
        elif fn == 2 and wt == 2:
            mm = {}
            for f2, w2, x in _fields(v, 0, len(v)):
                if w2 == 2 and f2 in (1, 2, 3):
                    mm[("name", "input", "output")[f2 - 1]] = _s(x)
            s["methods"].append(mm)
    return s


_FD_REPEATED = {3, 4, 5, 6, 7, 10, 11}


def _decode_file(mem, rva):
    """FileDescriptorProto fields are serialized in ascending field-number order; the next thing in memory
    (often another descriptor, starting again at field 1) breaks that order, which marks the end."""
    fd = {"name": "", "package": "", "deps": [], "messages": [], "enums": [], "services": [], "extensions": [],
          "syntax": "", "size": 0}
    p, last, hi = rva, 0, len(mem)
    while p < hi:
        try:
            tag, q = _varint(mem, p)
            fn, wt = tag >> 3, tag & 7
            if not (1 <= fn <= 14) or fn < last or (fn == last and fn not in _FD_REPEATED):
                break
            if wt == 2:
                n, q = _varint(mem, q)
                if q + n > hi:
                    break
                v, q = mem[q:q + n], q + n
            elif wt == 0:
                v, q = _varint(mem, q)
            else:
                break
            if fn == 1: fd["name"] = _s(v)
            elif fn == 2: fd["package"] = _s(v)
            elif fn == 3: fd["deps"].append(_s(v))
            elif fn == 4: fd["messages"].append(_decode_message(v))
            elif fn == 5: fd["enums"].append(_decode_enum(v))
            elif fn == 6: fd["services"].append(_decode_service(v))
            elif fn == 7: fd["extensions"].append(_decode_field(v))
            elif fn == 12: fd["syntax"] = _s(v)
        except (ValueError, struct.error):
            break
        last, p = fn, q
    fd["size"] = p - rva
    return fd


def _short(t):
    return t.lstrip(".")


def _field_line(f, oneofs):
    typ = _short(f["type_name"]) if f.get("type_name") else f.get("type", "?")
    label = f.get("label", "")
    label = "" if label == "optional" and "oneof" in f else label
    opt = f" [default = {f['default']}]" if f.get("default") else ""
    note = f"  // oneof {oneofs[f['oneof']]}" if "oneof" in f and f["oneof"] < len(oneofs) else ""
    return f"{label + ' ' if label else ''}{typ} {f.get('name', '?')} = {f.get('number', '?')}{opt};{note}"


def format_proto(fd, only_message=None):
    lines = []

    def enum(e, ind):
        lines.append(f"{ind}enum {e['name']} {{")
        for v in e["values"]:
            lines.append(f"{ind}  {v.get('name', '?')} = {v.get('number', '?')};")
        lines.append(f"{ind}}}")

    def msg(m, ind):
        lines.append(f"{ind}message {m['name']} {{")
        for e in m["enums"]:
            enum(e, ind + "  ")
        for n in m["nested"]:
            msg(n, ind + "  ")
        for f in sorted(m["fields"], key=lambda x: x.get("number", 0)):
            lines.append(f"{ind}  {_field_line(f, m['oneofs'])}")
        for f in m["extensions"]:
            lines.append(f"{ind}  // extend {_short(f.get('extendee', '?'))}: {_field_line(f, [])}")
        lines.append(f"{ind}}}")

    def find(ms, name):
        for m in ms:
            if m["name"] == name:
                return m
            r = find(m["nested"], name)
            if r:
                return r
        return None

    if only_message:
        m = find(fd["messages"], only_message)
        if m:
            msg(m, "")
        else:
            lines.append(f"// no message {only_message} in {fd['name']}")
        return "\n".join(lines)
    lines.append(f"// {fd['name']} ({fd['size']} bytes serialized)")
    if fd["syntax"]:
        lines.append(f'syntax = "{fd["syntax"]}";')
    if fd["package"]:
        lines.append(f"package {fd['package']};")
    for d in fd["deps"]:
        lines.append(f'import "{d}";')
    for e in fd["enums"]:
        enum(e, "")
    for m in fd["messages"]:
        msg(m, "")
    for s in fd["services"]:
        lines.append(f"service {s['name']} {{")
        for mm in s["methods"]:
            lines.append(f"  rpc {mm.get('name', '?')} ({_short(mm.get('input', '?'))}) returns ({_short(mm.get('output', '?'))});")
        lines.append("}")
    for f in fd["extensions"]:
        lines.append(f"extend {_short(f.get('extendee', '?'))} {{ {_field_line(f, [])} }}")
    return "\n".join(lines)
