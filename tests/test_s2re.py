"""source2-re tests. Run from the skill folder:  python -m unittest discover -s tests -v

Three groups:
  Pure          pattern formats, address parsing, signature files, script rendering: no DLL needed
  GenericPE     invariants on Windows' own kernel32.dll (skipped elsewhere), with a throwaway cache
  Pinned*       facts read from specific CS2 / Deadlock builds. Each class skips unless the installed DLL has the
                exact size and mtime below, so a game update turns them into skips, not failures. To re-pin,
                update the PIN and the expected values from s2re output on the new build.
Nothing here writes snapshots (S2RE_NO_SNAPSHOT=1). Pinned classes use the normal cache, so the first run after a
cache wipe builds the index single-process (10-20 s per DLL).
"""
import ast
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(HERE), "scripts")
sys.path.insert(0, SCRIPTS)
sys.path.insert(0, HERE)
os.environ["S2RE_NO_SNAPSHOT"] = "1"

import s2export  # noqa: E402
import s2pe  # noqa: E402
import s2port  # noqa: E402
import s2re  # noqa: E402
import s2source2 as s2  # noqa: E402

CLI = os.path.join(SCRIPTS, "s2re.py")


def run_cli(*args, env=None):
    p = subprocess.run([sys.executable, CLI, *args], capture_output=True, text=True, encoding="utf-8",
                       errors="replace", env={**os.environ, **(env or {})})
    return p.returncode, p.stdout, p.stderr


_images = {}


def pinned(game, module, size, mtime):
    """The Image when the installed DLL is exactly this build, else None."""
    key = (game, module, size, mtime)
    if key not in _images:
        try:
            path = s2pe.resolve_module(game, module)
        except (FileNotFoundError, KeyError):
            _images[key] = None
            return None
        st = os.stat(path)
        _images[key] = s2pe.Image(path) if (st.st_size, int(st.st_mtime)) == (size, mtime) else None
    return _images[key]


CS2_CLIENT = ("cs2", "client", 39227544, 1793840863)          # 2026-11-04 17:07
CS2_ENGINE2 = ("cs2", "engine2", 7498392, 1793782024)         # 2026-11-04 00:47
DL_CLIENT = ("deadlock", "client", 60326552, 1793244620)      # 2026-10-28 20:30
DL_ENGINE2 = ("deadlock", "engine2", 6394008, 1793244620)     # 2026-10-28 20:30


# ---------------------------------------------------------------------------------------------- pure

class Pure(unittest.TestCase):
    def test_parse_formats(self):
        want = [0x48, 0x8B, None, None]
        self.assertEqual(s2pe.parse_pattern("48 8B ? ?"), want)
        self.assertEqual(s2pe.parse_pattern("48 8b ?? ??"), want)
        self.assertEqual(s2pe.parse_pattern("488B????"), want)
        self.assertEqual(s2pe.parse_pattern(r"\x48\x8B\x00\x00", "xx??"), want)
        with self.assertRaises(ValueError):
            s2pe.parse_pattern(r"\x48\x8B", "x")

    def test_format_round_trip(self):
        vals = [0x48, 0x8B, 0x0D, None, None, None, None, 0xC3]
        self.assertEqual(s2pe.format_pattern(vals, "ida"), "48 8B 0D ? ? ? ? C3")
        self.assertEqual(s2pe.format_pattern(vals, "x64dbg"), "48 8B 0D ?? ?? ?? ?? C3")
        code, mask = s2pe.format_pattern(vals, "code")
        self.assertEqual(mask, "xxx????x")
        self.assertEqual(s2pe.parse_pattern(code, mask), vals)
        self.assertEqual(s2re.fmt_sig(vals, "compact"), "488B0D????????C3")
        for style in ("ida", "x64dbg", "compact"):
            self.assertEqual(s2pe.parse_pattern(s2re.fmt_sig(vals, style)), vals)

    def test_hexint(self):
        self.assertEqual(s2re.hexint("0x10"), 16)
        self.assertEqual(s2re.hexint("10"), 16)
        self.assertEqual(s2re.hexint("-0x10"), -16)
        self.assertEqual(s2re.hexint("00000001`80001000"), 0x180001000)  # WinDbg style

    def test_sig_file_plain_list(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "sigs.txt")
            with open(f, "w") as fh:
                fh.write("# comment\nfoo = 48 8B 05 ? ? ? ? rel=3,7\n\nE8 ? ? ? ?\n"
                         "code = \\x48\\x8B\\x00 xx?\n")
            a = types.SimpleNamespace(file=f, pattern=[], rel=None, mask=None)
            got = s2re.sig_entries(types.SimpleNamespace(a=a))
        self.assertEqual(got[0], ("foo", "48 8B 05 ? ? ? ?", None, (3, 7), None))
        self.assertEqual(got[1], ("line 4", "E8 ? ? ? ?", None, None, None))
        self.assertEqual(got[2], ("code", "\\x48\\x8B\\x00", "xx?", None, None))

    def test_sig_file_from_source(self):
        src = ('namespace sigs {\n'
               '    constexpr const char* CreateMove = "48 8B C4 48 89 58 ? 55";\n'
               '    inline std::string_view Other{ "E8 ?? ?? ?? ?? 84 C0" };\n'
               '    const char* not_a_sig = "hello world";\n}\n')
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "sigs.hpp")
            with open(f, "w") as fh:
                fh.write(src)
            got = s2re.sig_entries(types.SimpleNamespace(a=types.SimpleNamespace(file=f, pattern=[], rel=None, mask=None)))
        self.assertEqual([(n, p) for n, p, _, _, _ in got],
                         [("CreateMove", "48 8B C4 48 89 58 ? 55"), ("Other", "E8 ?? ?? ?? ?? 84 C0")])

    def test_sig_file_sdk_table(self):
        src = ('static const sig_t sigs[] = {\n'
               '    {"TraceHull", "client.dll", "48 89 5C 24 ? 48 89 74 24 ? 57", kind::raw, 0, 0},\n'
               '    {"Alloc", "tier0.dll", "E8 ? ? ? ? 48 8B D8", kind::rel, 1, 5},\n};\n')
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "signatures.cpp")
            with open(f, "w") as fh:
                fh.write(src)
            got = s2re.sig_entries(types.SimpleNamespace(a=types.SimpleNamespace(file=f, pattern=[], rel=None, mask=None)))
        self.assertEqual([(n, m) for n, _, _, _, m in got], [("TraceHull", "client.dll"), ("Alloc", "tier0.dll")])

    def test_shell_split_pattern_is_joined(self):
        a = types.SimpleNamespace(file=None, pattern=["48", "8B", "?", "?"], rel=["3", "7"], mask=None)
        self.assertEqual(s2re.sig_entries(types.SimpleNamespace(a=a)), [(None, "48 8B ? ?", None, (3, 7), None)])

    def test_port_confidence(self):
        C = s2port.Candidate
        self.assertEqual(s2port.confidence([]), "none")
        self.assertEqual(s2port.confidence([C(1, 20, 10, 1, {}, []), C(2, 5, 0, .5, {}, [])]), "high")
        self.assertEqual(s2port.confidence([C(1, 20, 10, 1, {}, []), C(2, 19, 9, .9, {}, [])]), "low")

    def test_export_scripts_parse(self):
        img = types.SimpleNamespace(name="client.dll", file_size=1, mtime=2)
        syms = [s2export.Symbol(0x1000, "CFoo::vf3", "vfunc", True, None),
                s2export.Symbol(0x2000, "cvar::sv_cheats", "cvar", False, 'help "quoted"'),
                s2export.Symbol(0x3000, "Odd<Name>::x", "vtable", False, None)]
        for tool in ("ida", "ghidra", "binja"):
            ast.parse(s2export.render(img, syms, tool, "build"))
        self.assertEqual(len(json.loads(s2export.render(img, syms, "json"))["symbols"]), 3)


# ---------------------------------------------------------------------------------------------- any PE

KERNEL32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "kernel32.dll")


@unittest.skipUnless(os.path.isfile(KERNEL32), "needs Windows' kernel32.dll")
class GenericPE(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="s2re-test-")
        cls.old_cache = os.environ.get("S2RE_CACHE")
        os.environ["S2RE_CACHE"] = cls.tmp
        cls.img = s2pe.Image(KERNEL32)

    @classmethod
    def tearDownClass(cls):
        if cls.old_cache is None:
            os.environ.pop("S2RE_CACHE", None)
        else:
            os.environ["S2RE_CACHE"] = cls.old_cache
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_pdata(self):
        f = self.img.funcs
        self.assertGreater(len(f), 500)
        self.assertTrue(all(b < e for b, e in f))
        self.assertEqual(f, sorted(f))

    def test_exports_are_code(self):
        ex = self.img.exports()
        self.assertIn("GetProcAddress", ex)
        self.assertTrue(self.img.is_code(ex["GetProcAddress"]))

    def test_import_xrefs_resolve_to_the_slot(self):
        imps = self.img.imports()
        self.assertTrue(imps)
        checked = 0
        for slot in list(imps)[:200]:
            for r in self.img.xrefs(slot)[:3]:
                self.assertEqual(self.img.target_of(self.img.insn_at(r)), slot)
                checked += 1
        self.assertGreater(checked, 10)

    def test_sigmake_round_trip(self):
        b, e = max(self.img.funcs, key=lambda f: f[1] - f[0])
        pat, n, unique, _ = self.img.make_sig(b)
        self.assertTrue(unique)
        self.assertEqual(self.img.scan(pat), [b])
        self.assertEqual(self.img.insns(b)[0].address, b)

    def test_cli(self):
        env = {"S2RE_CACHE": self.tmp}
        code, out, _ = run_cli("-m", KERNEL32, "--json", "exports", "GetProcAddress", env=env)
        self.assertEqual(code, 0)
        res = json.loads(out)["result"]
        self.assertIn({"rva": hex(self.img.exports()["GetProcAddress"]), "name": "GetProcAddress"}, res)
        code, out, _ = run_cli("-m", KERNEL32, "info", env=env)
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("# kernel32.dll: "))  # a path module gets no game prefix
        code, _, err = run_cli("-m", KERNEL32, "rtti", env=env)
        self.assertEqual(code, 2)
        self.assertIn("rtti:", err)


@unittest.skipUnless(os.path.isfile(KERNEL32), "needs Windows' kernel32.dll")
class GenericDump(unittest.TestCase):
    """Synthetic dumps of kernel32.dll: every layout / header state the loader has to handle."""
    BASE = 0x7FFA55550000

    @classmethod
    def setUpClass(cls):
        import synth_dump as sd
        cls.sd = sd
        cls.tmp = tempfile.mkdtemp(prefix="s2re-dump-test-")
        cls.old_cache = os.environ.get("S2RE_CACHE")
        os.environ["S2RE_CACHE"] = cls.tmp
        cls.disk = s2pe.Image(KERNEL32)
        mem = sd.mapped(cls.disk, cls.BASE, "updated")
        cls.hook = max(cls.disk.funcs, key=lambda f: f[1] - f[0])[0]
        sd.inline_hook(mem, cls.hook, cls.BASE, cls.BASE + cls.disk.size + 0x100000)
        data = cls.disk.section(".data")
        cls.written = data.rva + 0x40
        sd.put_u64(mem, cls.written, 0x1D2C3B4A5968)
        cls.mem = mem
        cls.files = {}
        default = bytearray(mem)
        struct.pack_into("<Q", default, struct.unpack_from("<I", default, 0x3C)[0] + 48, cls.disk.base)
        erased = sd.mapped(cls.disk, cls.BASE, "erased")
        for name, buf in (("updated", mem), ("default", default), ("erased", erased), ("rebuilt", sd.file_layout(mem))):
            cls.files[name] = sd.write(os.path.join(cls.tmp, f"k32_{name}.bin"), bytes(buf))

    @classmethod
    def tearDownClass(cls):
        if cls.old_cache is None:
            os.environ.pop("S2RE_CACHE", None)
        else:
            os.environ["S2RE_CACHE"] = cls.old_cache
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def check(self, d, layout, source):
        self.assertEqual((d.base, d.layout, d.dump), (self.BASE, layout, True))
        self.assertTrue(d.base_source.startswith(source), d.base_source)
        self.assertEqual(d.funcs, self.disk.funcs)
        self.assertEqual(d.exports(), self.disk.exports())
        self.assertEqual(d.to_rva(self.BASE + 0x1234), 0x1234)
        self.assertEqual(d.snapshots(), [])

    def test_mapped_header_updated(self):
        self.check(s2pe.Image(self.files["updated"], dump=True), "mapped", "header")

    def test_mapped_header_default(self):
        self.check(s2pe.Image(self.files["default"], dump=True), "mapped", "relocations")

    def test_mapped_header_erased(self):
        with self.assertRaises(ValueError):
            s2pe.Image(self.files["erased"], dump=True)
        self.check(s2pe.Image(self.files["erased"], dump=True, headers_from=KERNEL32), "mapped", "relocations")

    def test_rebuilt_file_layout(self):
        self.check(s2pe.Image(self.files["rebuilt"], dump=True), "file", "header")

    def test_mapped_detected_without_flag(self):
        self.assertEqual(s2pe.Image(self.files["updated"]).layout, "mapped")

    def test_diff(self):
        import s2dump
        d = s2pe.Image(self.files["updated"], dump=True)
        ch = s2dump.diff(d, self.disk)
        code = [c for c in ch if c.kind == "code"]
        self.assertEqual([c.rva for c in code], [self.hook])
        self.assertTrue(any("leaves the image" in n for n in code[0].notes))
        self.assertIn(self.written, [c.rva for c in ch if c.kind == "data"])
        self.assertEqual([c for c in ch if c.kind in ("vtable", "rdata")], [])

    def test_cli(self):
        env = {"S2RE_CACHE": self.tmp}
        code, out, _ = run_cli("--memdump", self.files["default"], "--json", "info", env=env)
        self.assertEqual(code, 0)
        b = json.loads(out)["build"]
        self.assertEqual((b["base"], b["layout"]), (hex(self.BASE), "mapped"))
        code, out, _ = run_cli("--memdump", self.files["updated"], "--json", "dumpdiff", "--disk", KERNEL32,
                               "--kind", "code", env=env)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["result"]["counts"], {"code": 1})
        code, _, err = run_cli("--base", "0x1000", "info", env=env)
        self.assertEqual(code, 2)
        self.assertIn("--memdump", err)


# ---------------------------------------------------------------------------------------------- pinned builds

class PinnedCS2Client(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.img = pinned(*CS2_CLIENT)
        if cls.img is None:
            raise unittest.SkipTest("CS2 client.dll is not the 2026-11-04 build")

    def test_pe(self):
        self.assertEqual(len(self.img.funcs), 128392)
        self.assertEqual(self.img.exports()["CreateInterface"], 0x19D0FF0)

    def test_schema(self):
        self.assertEqual(len(s2.schema_classes(self.img)), 988)
        self.assertEqual(len(s2.schema_enums(self.img)), 265)
        self.assertEqual(s2.find_field(self.img, "C_BaseEntity", "m_iHealth"), (0x34C, "C_BaseEntity"))
        self.assertEqual(s2.find_field(self.img, "C_BaseEntity", "m_pGameSceneNode"), (0x330, "C_BaseEntity"))
        self.assertEqual(s2.find_field(self.img, "C_CSPlayerPawn", "m_iHealth"), (0x34C, "C_BaseEntity"))
        self.assertEqual(s2.base_chain(self.img, "C_BaseModelEntity")[:2], ["C_BaseModelEntity", "C_BaseEntity"])
        self.assertEqual(s2.schema_class_map(self.img)["C_CSPlayerPawn"].size, 0x3720)
        e = {e.name: e for e in s2.schema_enums(self.img)}["MoveType_t"]
        self.assertEqual(len(e.values), 14)
        self.assertIn(("MOVETYPE_WALK", 2), e.values)

    def test_convars_and_commands(self):
        cv = {r.name: r for r in s2.registrations(self.img, "convar")}
        cc = {r.name: r for r in s2.registrations(self.img, "concmd")}
        self.assertEqual((len(cv), len(cc)), (1992, 336))
        self.assertEqual((cv["sv_cheats"].obj, cv["sv_cheats"].init), (0x2564538, 0xD1E60))
        self.assertEqual(cv["sv_jump_spam_penalty_time"].obj, 0x2537620)
        self.assertEqual(cc["cl_anim_eval_stats"].callbacks[0], 0x38E220)

    def test_interfaces(self):
        ifs = {i.name: i for i in s2.interfaces(self.img)}
        self.assertEqual(len(ifs), 8)
        i = ifs["Source2Client002"]
        self.assertEqual((i.factory, i.instance), (0xB86EE0, 0x2564620))
        self.assertTrue(i.instance_class.startswith("CSource2Client"))

    def test_strings_xrefs_vtables(self):
        s = self.img.find_cstr("CPlayer_MovementServices::DoMovement::Subtick")
        self.assertEqual(s, [0x1C40648])
        self.assertIn(0xA674DC, self.img.xrefs(s[0]))
        self.assertEqual(self.img.function_start(0xA674DC), 0xA673B0)
        slots = {(self.img.demangle_type(v.cls), i) for v, i in filter(None, map(self.img.vtable_slot, self.img.stored_at(0xA74130)))}
        self.assertEqual(slots, {("CPlayer_MovementServices", 32), ("CPlayer_MovementServices_Humanoid", 32)})
        v = self.img.vtable_at(0x1C40238)
        self.assertEqual((self.img.demangle_type(v.cls), v.slots), ("CPlayer_MovementServices", 54))

    def test_signatures(self):
        pat, n, unique, _ = self.img.make_sig(0x8C4D90)
        self.assertEqual((pat, n, unique), ("40 55 53 56 57 41 56 41 57 48 8D 6C 24 D1 48 81 EC 88 00 00 00 8B 9A D4 00 00 00", 9, True))
        sites = {site: rel for site, _, _, rel in self.img.make_sig_target(0x2537620)}
        self.assertEqual(sites.get(0x8C4E94), (3, 7))
        self.assertEqual(self.img.rel(0x8C4E94, 3, 7), 0x2537620)

    def test_fields(self):
        offs = {o for _, o, *_ in self.img.field_map(0xAE50F0, "rcx")}
        self.assertTrue({0x10, 0x380, 0x3E0} <= offs)

    def test_protos(self):
        ps = self.img.protos()
        self.assertEqual(len(ps), 33)
        self.assertIn((0x1B31E60, "usercmd.proto"), ps)
        text = s2pe.format_proto(self.img.proto_descriptor(0x1B31E60), "CSubtickMoveStep")
        self.assertIn("optional float yaw_delta = 9;", text)

    def test_export_counts(self):
        syms = s2export.collect(self.img, ("cvar", "iface", "schema"))
        kinds = {k: sum(1 for s in syms if s.kind == k) for k in ("cvar", "iface", "schema")}
        self.assertEqual(kinds, {"cvar": 1992, "iface": 24, "schema": 1253})

    def test_cli_json(self):
        code, out, _ = run_cli("-g", "cs2", "schema", "C_BaseEntity", "m_iHealth", "--json")
        self.assertEqual(code, 0)
        d = json.loads(out)
        self.assertEqual((d["build"]["file_size"], d["build"]["mtime"]), (39227544, 1793840863))
        self.assertEqual(d["result"], [{"field": "m_iHealth", "offset": "0x34c", "declared_in": "C_BaseEntity"}])

    def test_cli_sig_file(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "sigs.txt")
            with open(f, "w") as fh:
                fh.write("jump = 40 55 53 56 57 41 56 41 57 48 8D 6C 24 D1 48 81 EC 88 00 00 00 8B 9A D4 00 00 00\n"
                         "none = DE AD BE EF 13 37 DE AD\n")
            code, out, _ = run_cli("-g", "cs2", "--json", "sig", "--file", f)
        self.assertEqual(code, 0)
        res = {r["name"]: r for r in json.loads(out)["result"]}
        self.assertEqual((res["jump"]["status"], res["jump"]["hits"][0]["rva"]), ("unique", "0x8c4d90"))
        self.assertEqual(res["none"]["status"], "missing")


class PinnedDeadlockClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.img = pinned(*DL_CLIENT)
        if cls.img is None:
            raise unittest.SkipTest("Deadlock client.dll is not the 2026-10-28 build")

    def test_schema(self):
        self.assertEqual(len(s2.schema_classes(self.img)), 3967)
        self.assertEqual(len(s2.schema_enums(self.img)), 480)
        self.assertEqual(s2.find_field(self.img, "C_BaseEntity", "m_iHealth"), (0x354, "C_BaseEntity"))
        self.assertEqual(s2.find_field(self.img, "C_BaseEntity", "m_iTeamNum"), (0x3EF, "C_BaseEntity"))

    def test_registrations_and_protos(self):
        self.assertEqual(len(s2.registrations(self.img, "convar")), 2227)
        self.assertEqual(len(s2.registrations(self.img, "concmd")), 412)
        self.assertEqual(len(self.img.protos()), 42)


class PinnedPort(unittest.TestCase):
    """Deadlock engine2 -> CS2 engine2: two games' builds of the same engine module, a harder case than one game's
    consecutive builds."""

    @classmethod
    def setUpClass(cls):
        old, new = pinned(*DL_ENGINE2), pinned(*CS2_ENGINE2)
        if old is None or new is None:
            raise unittest.SkipTest("needs Deadlock engine2.dll (2026-10-28) and CS2 engine2.dll (2026-11-04)")
        cls.porter = s2port.Porter(old, new)

    def test_function(self):
        res = self.porter.port(0x604D0)
        self.assertEqual(res.kind, "code")
        self.assertEqual(res.candidates[0].start, 0x626C0)
        self.assertEqual(s2port.confidence(res.candidates), "high")

    def test_convar_object(self):
        res = self.porter.port(0x8B4DE8)
        self.assertEqual(res.kind, "data")
        self.assertEqual(res.candidates[0][0], 0x9BAC68)

    def test_interfaces_engine2(self):
        self.assertEqual(len(s2.interfaces(self.porter.new)), 28)


class PinnedEngine2Dump(unittest.TestCase):
    """A synthetic dump of CS2 engine2.dll with runtime state written in (linked interface list, schema +0x00
    pointers, a convar data pointer, an inline hook, a redirected vtable slot): Source 2 parsers must give the
    disk answers, and dumpdiff must find exactly what was written."""
    BASE = 0x7FFB12340000

    @classmethod
    def setUpClass(cls):
        cls.disk = pinned(*CS2_ENGINE2)
        if cls.disk is None:
            raise unittest.SkipTest("needs CS2 engine2.dll (2026-11-04)")
        import synth_dump as sd
        cls.tmp = tempfile.mkdtemp(prefix="s2re-e2dump-test-")
        cls.old_cache = os.environ.get("S2RE_CACHE")
        os.environ["S2RE_CACHE"] = cls.tmp
        disk, B = cls.disk, cls.BASE
        mem = sd.mapped(disk, B, "erased")
        cls.writes = set()
        put = sd.put_u64

        def track(m, rva, v):
            if struct.unpack_from("<Q", m, rva)[0] != v:  # writing the value already there changes nothing
                cls.writes.add(rva)
            put(m, rva, v)
        sd = types.SimpleNamespace(put_u64=track, inline_hook=sd.inline_hook, write=sd.write)
        cls.ifs = [i for i in s2.interfaces(disk) if i.reg is not None]
        for k, i in enumerate(cls.ifs):
            sd.put_u64(mem, i.reg, B + i.factory)
            sd.put_u64(mem, i.reg + 8, B + disk.find_cstr(i.name)[0])
            sd.put_u64(mem, i.reg + 0x10, B + cls.ifs[k + 1].reg if k + 1 < len(cls.ifs) else 0)
        sd.put_u64(mem, s2.interface_list_head(disk), B + cls.ifs[0].reg)
        for k, c in enumerate(s2.schema_classes(disk)):
            sd.put_u64(mem, c.info, 0x23A00000000 + 0x100 * k)
        cls.cvar = {r.name: r for r in s2.registrations(disk, "convar")}["host_timescale"]
        sd.put_u64(mem, cls.cvar.obj + 8, 0x23A00005550)
        cls.hook = 0x626C0
        sd.inline_hook(mem, cls.hook, B, B + disk.size + 0x200000)
        vt = disk.vtables()[0]
        cls.slot = vt.start + 8
        sd.put_u64(mem, cls.slot, 0x7FFC00001000)
        cls.writes.discard(cls.slot)
        cls.dump = s2pe.Image(sd.write(os.path.join(cls.tmp, "engine2.bin"), bytes(mem)), dump=True,
                              headers_from=disk.path)

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "old_cache", None) is None:
            os.environ.pop("S2RE_CACHE", None)
        else:
            os.environ["S2RE_CACHE"] = cls.old_cache
        shutil.rmtree(getattr(cls, "tmp", ""), ignore_errors=True)

    def test_base_from_relocations(self):
        self.assertEqual(self.dump.base, self.BASE)
        self.assertTrue(self.dump.base_source.startswith("relocations"))

    def test_parsers_match_disk(self):
        d, k = self.dump, self.disk
        self.assertEqual([(c.name, c.size, len(c.fields)) for c in s2.schema_classes(d)],
                         [(c.name, c.size, len(c.fields)) for c in s2.schema_classes(k)])
        self.assertEqual([e.name for e in s2.schema_enums(d)], [e.name for e in s2.schema_enums(k)])
        for kind in ("convar", "concmd"):
            self.assertEqual([(r.name, r.obj) for r in s2.registrations(d, kind)],
                             [(r.name, r.obj) for r in s2.registrations(k, kind)])
        self.assertEqual(s2.interfaces(d), s2.interfaces(k))
        self.assertEqual(len(d.vtables()), len(k.vtables()))

    def test_runtime_interface_list(self):
        import s2dump
        self.assertEqual([(n, nm) for n, nm, _ in s2dump.interface_list(self.dump)],
                         [(i.reg, i.name) for i in self.ifs])

    def test_diff(self):
        import s2dump
        ch = s2dump.diff(self.dump, self.disk)
        self.assertEqual([c.rva for c in ch if c.kind == "code"], [self.hook])
        self.assertEqual([c.rva for c in ch if c.kind == "vtable"], [self.slot])
        data = [c for c in ch if c.kind == "data"]
        self.assertTrue(all(c.owner for c in data))
        self.assertIn(f"cvar host_timescale+0x8", [c.owner for c in data])
        covered = {q for c in data for q in range(c.rva, c.rva + c.size, 8)}
        self.assertEqual(covered, self.writes)  # every runtime write found, nothing else reported


if __name__ == "__main__":
    unittest.main()
