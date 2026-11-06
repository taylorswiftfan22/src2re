#!/usr/bin/env python3
"""s2re - offline static reverse engineering of Source 2 game DLLs (CS2, Deadlock, ...) from the files on disk.

usage: python s2re.py [-g GAME] [-m MODULE|PATH] [--json] [-o FILE] [--limit N] [-q] <command> ...
       (the global options may also follow the command)

Addresses are RVAs (hex, 0x optional). A VA >= ImageBase is accepted and converted. Negative values go after
`--`, with every option before it: disp --in 0xae50f0 -- -0x8

navigation   info | str TEXT... [--partial] [--wide] | xrefs RVA... | func RVA... | range RVA [N]
             callers RVA... [--depth N] | callees RVA...
objects      rtti CLASS... | rtti --grep TEXT | vtwho RVA... | fields RVA [--reg rcx] [--schema CLASS]
             disp DISP... --in RVA... | --range LO HI [--imm]
source 2     schema CLASS [FIELD...] [--flat] | schema --list [FILTER] | schema --dump [--format text|cpp|json]
             enum NAME... | enum --list [FILTER] | iface [FILTER]
             cvar NAME... | cvar --list [FILTER] | cvarobj RVA... | concmd NAME... | concmd --list [FILTER]
             (cvar / cvarobj / concmd take --span HEX: bytes of the object that count as a reference)
             proto [NAME.proto] [--message M]
signatures   sig PATTERN... [--rel OFF LEN] [--mask M] [--region image|code] | sig --file FILE
             sigmake RVA... [--loose] [--format ida|x64dbg|code|compact] [--target] | sigconv PATTERN [--mask M]
builds       port RVA... [--old DLL] [--top N] | snapshots | snapshot
export       export --tool ida|ghidra|binja|json [--only KIND,...] -o FILE
dumps        --memdump FILE [--base HEX] [--layout mapped|file] [--headers-from DLL] <any command>
             dumpdiff [--disk DLL] [--kind code,vtable,rdata,data] [--section S...] [--all-data]
raw          hex RVA [N] [--qwords] | exports [FILTER] | imports [FILTER]

Text output starts with "# <game> <dll>: <size> bytes, modified <date>" (-q drops it) and is capped at --limit
rows per list (default 50, 0 = all). --json output is never capped and is wrapped as {"module", "build", "result"}.
"""
import argparse
import datetime
import json
import os
import re
import struct
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import s2pe  # noqa: E402
import s2source2 as s2  # noqa: E402
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP, X86_REG_RSP  # noqa: E402


class Fail(Exception):
    """A user-facing error (bad name, missing build, ...): printed without a traceback."""


class BadNumber(Fail, ValueError):
    """ValueError for argparse `type=` checks, Fail for main()."""


def hexint(s):
    t = str(s).strip().lower().replace("`", "")
    neg = t.startswith("-")
    try:
        v = int(t.lstrip("-").removeprefix("0x"), 16)
    except ValueError:
        raise BadNumber(f"not a hex number: {s!r}") from None
    return -v if neg else v


def h(x):
    return None if x is None else f"{x:#x}"


def build_line(img):
    t = datetime.datetime.fromtimestamp(img.mtime)
    dump = f" (memory dump, {img.layout} layout, base {img.base:#x})" if img.dump else ""
    return f"{img.name}{dump}: {img.file_size} bytes, modified {t:%Y-%m-%d %H:%M}"


def build_json(img):
    d = {"file_size": img.file_size, "mtime": img.mtime, "pe_timestamp": h(img.timestamp)}
    if img.dump:
        d.update(dump=True, layout=img.layout, base=h(img.base), base_source=img.base_source)
    return d


def runtime_qwords(img, obj, n=2):
    """[(offset, value, note)] of an object's first qwords: in a dump, what the game wrote there."""
    out = []
    for k in range(n):
        v = img.u64(obj + 8 * k)
        r = v - img.base
        note = (img.describe(r) or f"{r:#x}") if v and 0 <= r < img.size else ("outside the image" if v else "")
        out.append((8 * k, v, note))
    return out


class Ctx:
    """Command context: the image, parsed args, and the output (text lines, one JSON value, or raw text)."""

    def __init__(self, img, a):
        self.img, self.a = img, a
        self.lines = []
        self.data = None
        self.raw = None   # written verbatim (generated scripts, schema dumps)
        self.note = None  # one-line summary for stderr

    def p(self, *parts):
        self.lines.append(" ".join(str(x) for x in parts))

    def lim(self, seq):
        seq = list(seq)
        return seq if self.a.json or self.a.limit <= 0 else seq[:self.a.limit]

    def more(self, n):
        if not self.a.json and 0 < self.a.limit < n:
            self.p(f"  ... {n - self.a.limit} more (--limit N, 0 = all)")

    def where(self, r):
        f = self.img.function_start(r)
        return f"fn {f:#x}" if f is not None else "no .pdata (leaf/gap)"

    def insn(self, r):
        ins = self.img.insn_at(r)
        return self.img.fmt(ins) if ins else f"{r:#010x}: (undecodable)"

    def ref_json(self, r):
        ins = self.img.insn_at(r)
        return {"rva": h(r), "function": h(self.img.function_start(r)),
                "insn": f"{ins.mnemonic} {ins.op_str}" if ins else None}

    def rva(self, s):
        return self.img.to_rva(hexint(s))


def insn_json(img, ins):
    t = img.target_of(ins)
    return {"rva": h(ins.address), "mnemonic": ins.mnemonic, "operands": ins.op_str,
            "target": h(t), "note": (img.describe(t, ins.mnemonic) or None) if t is not None else None}


def slot_label(img, pos):
    vs = img.vtable_slot(pos)
    if not vs:
        return None
    v, slot = vs
    return f"{img.demangle_type(v.cls)}" + (f"@{v.col_offset:#x}" if v.col_offset else "") + f" vtable slot [{slot}]"


def flat_fields(img, cls, add=0, seen=None):
    """[(absolute offset, field, declaring class)] for a schema class including every schema base."""
    cmap = s2.schema_class_map(img)
    seen = set() if seen is None else seen
    k = cmap.get(cls)
    if k is None or cls in seen:
        return []
    seen.add(cls)
    out = []
    for boff, bname in k.bases:
        if bname:
            out += flat_fields(img, bname, add + boff, seen)
    out += [(add + f.offset, f.name, cls) for f in k.fields]
    return sorted(out)


# ---------------------------------------------------------------------------------------------- navigation

def cmd_info(c):
    img = c.img
    t = datetime.datetime.fromtimestamp(img.mtime)
    c.data = {"path": img.path, "file_size": img.file_size, "mtime": img.mtime, "pe_timestamp": h(img.timestamp),
              "image_base": h(img.base), "size_of_image": h(img.size),
              "sections": [{"name": s.name, "rva": h(s.rva), "size": h(s.size), "flags": h(s.flags)} for s in img.sections],
              "pdata_functions": len(img.funcs), "exports": len(img.exports()), "imports": len(img.imports()),
              "cache_dir": s2pe.cache_dir(), "cache": img.cache_status(), "snapshots": img.snapshots()}
    c.p(f"path       {img.path}")
    c.p(f"file       {img.file_size} bytes, modified {t:%Y-%m-%d %H:%M:%S} (mtime {img.mtime}), PE timestamp {img.timestamp:#x}")
    c.p(f"image      base {img.base:#x}, SizeOfImage {img.size:#x}")
    for s in img.sections:
        c.p(f"  {s.name:8} {s.rva:#010x} size {s.size:#010x} flags {s.flags:#010x}")
    c.p(f"functions  {len(img.funcs)} .pdata entries")
    c.p(f"exports    {len(img.exports())}, imports {len(img.imports())}")
    c.p(f"cache      {s2pe.cache_dir()}: " + ", ".join(f"{k} {'ready' if v else 'not built'}" for k, v in img.cache_status().items()))
    c.p(f"snapshots  {len(img.snapshots())} older build(s) saved for `port`")
    c.p(f"relocs     {len(img.relocations())} DIR64 slots")
    if img.dump:
        c.p(f"dump       {img.layout} layout, runtime base {img.base:#x} ({img.base_source}), header ImageBase "
            f"{img.header_base:#x}" + (f", headers from {img.headers_from}" if img.headers_from else ""))
        c.data.update(dump=True, layout=img.layout, base=h(img.base), base_source=img.base_source,
                      header_base=h(img.header_base), headers_from=img.headers_from)


def cmd_func(c):
    out = []
    for r in c.a.rva:
        r = c.rva(r)
        out.append({"query": h(r), "ranges": [[h(b), h(e)] for b, e in c.img.function_ranges(r)],
                    "insns": [insn_json(c.img, i) for i in c.img.insns(r)]})
        c.p(c.img.dis_func(r))
        c.p()
    c.data = out


def cmd_range(c):
    r = c.rva(c.a.rva)
    insns = list(c.img.md.disasm(c.img.mem[r:r + 16 * c.a.count], r, c.a.count))
    c.data = [insn_json(c.img, i) for i in insns]
    for i in insns:
        c.p(c.img.fmt(i))


def cmd_xrefs(c):
    img = c.img
    out = []
    for t in c.a.rva:
        t = c.rva(t)
        refs = img.xrefs(t)
        stored = img.stored_at(t)
        out.append({"target": h(t), "describe": img.describe(t) or None, "count": len(refs),
                    "refs": [c.ref_json(r) for r in c.lim(refs)],
                    "stored_at": [{"rva": h(p), "vtable_slot": slot_label(img, p)} for p in c.lim(stored)]})
        c.p(f"xrefs to {t:#x} ({img.describe(t) or '?'}): {len(refs)} code ref(s), {len(stored)} stored pointer(s)")
        for r in c.lim(refs):
            c.p(f"  {c.insn(r)}    [{c.where(r)}]")
        c.more(len(refs))
        for p in c.lim(stored):
            lab = slot_label(img, p)
            c.p(f"  stored at {p:#010x}" + (f"  ({lab})" if lab else ""))
        c.more(len(stored))
        c.p()
    c.data = out


def cmd_str(c):
    img = c.img
    out = []
    for text in c.a.text:
        if c.a.wide:
            hits = img.find_wstr(text)
        elif c.a.partial:
            hits = img.find_cstr_partial(text, c.a.section)
        else:
            hits = img.find_cstr(text)
        c.p(f'"{text}": {len(hits)} hit(s)')
        rows = []
        for s in c.lim(hits):
            val = img.wstr(s) if c.a.wide else img.cstr(s)
            refs = img.xrefs(s)
            ptrs = [] if refs else img.stored_at(s)  # nothing loads it directly: one level of pointer tables
            rows.append({"rva": h(s), "string": val, "section": img.section_of(s),
                         "refs": [c.ref_json(r) for r in refs],
                         "via_pointers": [{"pointer": h(p), "refs": [c.ref_json(r) for r in img.xrefs(p)]} for p in ptrs]})
            c.p(f"  {s:#010x} {img.section_of(s) or '?'} {val[:100]!r}: {len(refs)} ref(s)"
                + (f", stored as a pointer at {len(ptrs)} place(s)" if ptrs else ""))
            for r in refs[:20]:
                c.p(f"      {c.insn(r)}    [{c.where(r)}]")
            if len(refs) > 20:
                c.p(f"      ... {len(refs) - 20} more (xrefs {s:#x})")
            for p in ptrs[:10]:
                prefs = img.xrefs(p)
                c.p(f"      pointer at {p:#010x}: {len(prefs)} ref(s)")
                for r in prefs[:5]:
                    c.p(f"          {c.insn(r)}    [{c.where(r)}]")
        c.more(len(hits))
        out.append({"query": text, "hits": rows})
    c.data = out


def cmd_callers(c):
    img = c.img
    out = []

    def walk(fn, depth, ind, seen):
        nodes = []
        by_fn = {}
        for r in img.xrefs(fn):
            by_fn.setdefault(img.function_start(r), []).append(r)
        for p in img.stored_at(fn):
            lab = slot_label(img, p)
            nodes.append({"kind": "vtable" if lab else "pointer", "at": h(p), "label": lab})
            c.p(f"{ind}stored at {p:#010x}" + (f"  ({lab})" if lab else ""))
        items = sorted(by_fn.items(), key=lambda kv: (kv[0] is None, kv[0] or 0))
        for f, rs in c.lim(items):
            ins = img.insn_at(rs[0])
            lab = f"{f:#010x}" if f is not None else "(no .pdata)"
            extra = f" (+{len(rs) - 1} more site(s))" if len(rs) > 1 else ""
            c.p(f"{ind}{lab}  via {rs[0]:#x} {ins.mnemonic if ins else '?'}{extra}")
            node = {"kind": "code", "function": h(f), "sites": [h(r) for r in rs], "callers": []}
            if f is not None and depth > 1 and f not in seen:
                seen.add(f)
                node["callers"] = walk(f, depth - 1, ind + "    ", seen)
            nodes.append(node)
        if not c.a.json and 0 < c.a.limit < len(items):
            c.p(f"{ind}... {len(items) - c.a.limit} more caller function(s)")
        return nodes

    for q in c.a.rva:
        r = c.rva(q)
        root = img.function_start(r)
        root = r if root is None else root
        c.p(f"callers of {root:#x}" + (f" (function containing {r:#x})" if root != r else "") + f", depth {c.a.depth}:")
        out.append({"function": h(root), "callers": walk(root, c.a.depth, "  ", {root})})
        c.p()
    c.data = out


def cmd_callees(c):
    img = c.img
    out = []
    for q in c.a.rva:
        r = c.rva(q)
        cs = img.callees(r)
        fn = img.function_start(r)
        c.p(f"callees of {h(fn if fn is not None else r)}: {len(cs)}")
        rows = []
        for site, t, how in cs:
            d = img.describe(t, "call") or ""
            rows.append({"site": h(site), "target": h(t), "how": how, "note": d or None})
            c.p(f"  {site:#010x} {how:4} {t:#010x}  {d}")
        out.append({"function": h(fn), "callees": rows})
        c.p()
    c.data = out


# ---------------------------------------------------------------------------------------------- objects

def cmd_rtti(c):
    img = c.img
    vts = img.vtables()
    if c.a.grep:
        g = c.a.grep.lower()
        rows = sorted({(img.demangle_type(v.cls), v.start, v.col_offset, v.slots) for v in vts
                       if g in img.demangle_type(v.cls).lower()})
        for name, st, off, n in c.lim(rows):
            c.p(f"{st:#010x}  {name}" + (f"@{off:#x}" if off else "") + f"  ({n} slots)")
        c.more(len(rows))
        c.data = [{"class": n, "vtable": h(st), "col_offset": off, "slots": k} for n, st, off, k in rows]
        return
    if not c.a.names:
        raise Fail("rtti: give class names, or --grep TEXT")
    out = []
    for name in c.a.names:
        matches = sorted((v for v in vts if img.demangle_type(v.cls) == name), key=lambda v: v.col_offset)
        if not matches:
            c.p(f"{name}: no RTTI vtable (try rtti --grep {name})")
            continue
        for v in matches:
            slots = img.vtable_slots(v)
            bases = img.base_classes(v.col)
            c.p(f"== {name} vtable {v.start:#x}" + (f" (sub-object @{v.col_offset:#x})" if v.col_offset else "")
                + f", {len(slots)} slots, COL {v.col:#x}")
            if bases[1:]:
                c.p(f"   bases: {', '.join(bases[1:])}")
            for i, t in enumerate(c.lim(slots)):
                c.p(f"   [{i:3}] {t:#010x}  {img.describe(t, 'call') or ''}")
            c.more(len(slots))
            out.append({"class": name, "vtable": h(v.start), "col": h(v.col), "col_offset": v.col_offset,
                        "bases": bases[1:], "slots": [h(t) for t in slots]})
    c.data = out


def cmd_vtwho(c):
    img = c.img
    out = []
    for q in c.a.rva:
        r = c.rva(q)
        own = slot_label(img, r)
        if own:  # the address is a vtable entry itself
            t = img.u64(r) - img.base
            c.p(f"{r:#x} is {own}, pointing at {t:#x}")
            out.append({"query": h(r), "is_slot": own, "target": h(t)})
            continue
        stored = img.stored_at(r)
        slots = [(p, slot_label(img, p)) for p in stored]
        in_vt = [(p, lab) for p, lab in slots if lab]
        c.p(f"{r:#x}: in {len(in_vt)} vtable slot(s)" + (f", plus {len(slots) - len(in_vt)} other pointer(s)" if len(slots) > len(in_vt) else ""))
        for p, lab in c.lim(slots):
            c.p(f"  {p:#010x}  {lab or '(not a vtable)'}")
        c.more(len(slots))
        out.append({"query": h(r), "slots": [{"at": h(p), "label": lab} for p, lab in slots]})
    c.data = out


def cmd_fields(c):
    img = c.img
    r = c.rva(c.a.rva)
    rows = img.field_map(r, c.a.reg)
    names = {}
    flat = []
    if c.a.schema:
        flat = flat_fields(img, c.a.schema)
        if not flat:
            raise Fail(f"fields --schema: no schema class {c.a.schema} in {img.name}")
        names = {off: (n, cls) for off, n, cls in flat}
    by_off = {}
    for site, off, size, access, text in rows:
        by_off.setdefault(off, []).append((site, size, access, text))

    def label(off):
        if off in names:
            n, cls = names[off]
            return f"{cls}::{n}" if cls != c.a.schema else n
        lower = [f for f in flat if f[0] < off]
        if lower and off >= 0:
            fo, n, cls = lower[-1]
            return f"~{n}+{off - fo:#x}"
        return None

    fn = img.function_start(r)
    c.p(f"fields through {c.a.reg} in fn {h(fn if fn is not None else r)}: {len(by_off)} offset(s), {len(rows)} access(es)"
        + (f", named from schema {c.a.schema}" if c.a.schema else ""))
    data = []
    for off in sorted(by_off):
        acc = by_off[off]
        sizes = sorted({s for _, s, _, _ in acc if s})
        kinds = sorted({a for _, _, a, _ in acc})
        lab = label(off) if c.a.schema else None
        c.p(f"  {off:+#07x}  size {'/'.join(map(str, sizes)) or '-':5} {','.join(kinds):16}"
            + (f" {lab or '-':32}" if c.a.schema else "") + f"  e.g. {acc[0][0]:#x}: {acc[0][3]}")
        data.append({"offset": h(off), "sizes": sizes, "access": kinds, "schema_field": lab,
                     "sites": [{"rva": h(s), "insn": t} for s, _, _, t in acc]})
    c.data = {"function": h(fn), "register": c.a.reg, "schema": c.a.schema, "fields": data}


def cmd_disp(c):
    img = c.img
    want = {hexint(d) for d in c.a.disp}
    if not c.a.inside and not c.a.range:
        raise Fail("disp: give --in RVA... (functions) or --range LO HI (every .pdata function starting in it)")
    scopes = []  # (label, function rva, instructions)
    for q in c.a.inside or []:
        r = c.rva(q)
        fn = img.function_start(r)
        scopes.append((f"fn {h(fn if fn is not None else r)}", fn, img.insns(r)))
    if c.a.range:
        lo, hi = c.rva(c.a.range[0]), c.rva(c.a.range[1])
        for b, e in img.funcs:
            if lo <= b < hi:
                scopes.append((f"fn {b:#x}", b, list(img.md.disasm(img.mem[b:e], b))))
    out = []
    for lab, fn, insns in scopes:
        hits = []
        for ins in insns:
            for op in ins.operands:
                v = None
                if op.type == X86_OP_MEM and op.mem.base not in (X86_REG_RIP, X86_REG_RSP) and op.mem.disp in want:
                    v = op.mem.disp
                elif c.a.imm and op.type == X86_OP_IMM and op.imm in want:
                    v = op.imm
                if v is not None:
                    hits.append((ins, v))
                    break
        if c.a.range and not c.a.inside and not hits:
            continue
        c.p(f"{lab}: {len(hits)} use(s) of {', '.join(f'{d:#x}' for d in sorted(want))}")
        for ins, v in hits:
            c.p(f"  {img.fmt(ins)}")
        out.append({"function": h(fn), "hits": [{"rva": h(i.address), "value": h(v), "insn": f"{i.mnemonic} {i.op_str}"}
                                                for i, v in hits]})
    if c.a.range:
        c.p(f"-- {len(scopes)} function(s) scanned, {sum(1 for o in out if o['hits'])} with hits")
    c.data = out


# ---------------------------------------------------------------------------------------------- source 2

def class_json(k):
    return {"name": k.name, "info": h(k.info), "size": k.size, "align": k.align, "static_fields": k.static_fields,
            "bases": [{"offset": h(o), "name": b} for o, b in k.bases],
            "fields": [{"name": f.name, "offset": h(f.offset), "metadata": f.metadata} for f in k.fields]}


def cmd_schema(c):
    img = c.img
    if c.a.dump:
        c.raw = s2.dump_schema(img, c.a.format, build_line(img))
        c.note = f"{len(s2.schema_classes(img))} classes, {len(s2.schema_enums(img))} enums ({c.a.format})"
        return
    classes = s2.schema_classes(img)
    if c.a.list is not None:
        f = c.a.list.lower()
        rows = [k for k in classes if f in k.name.lower()]
        for k in c.lim(rows):
            base = f" : {k.bases[0][1] or '<other module>'}" if k.bases else ""
            c.p(f"{k.info:#010x}  sizeof {k.size:#7x}  {len(k.fields):4} fields  {k.name}{base}")
        c.more(len(rows))
        c.p(f"{len(rows)} of {len(classes)} classes")
        c.data = [{"name": k.name, "info": h(k.info), "size": k.size, "fields": len(k.fields),
                   "bases": [b for _, b in k.bases]} for k in rows]
        return
    if not c.a.name:
        raise Fail("schema: give a class name, --list [FILTER] or --dump")
    cmap = s2.schema_class_map(img)
    k = cmap.get(c.a.name)
    if k is None:
        near = sorted(n for n in cmap if c.a.name.lower() in n.lower())
        c.p(f"{c.a.name}: no schema class in {img.name}" + (f"; similar: {', '.join(near[:15])}" if near else ""))
        c.data = {"error": "not found", "similar": near}
        return
    if c.a.fields:
        rows = []
        for f in c.a.fields:
            r = s2.find_field(img, k.name, f)
            if r:
                c.p(f"{k.name}::{f} = {r[0]:#x}" + (f"  (declared in {r[1]})" if r[1] != k.name else ""))
            else:
                c.p(f"{k.name}::{f}: not found (own or inherited)")
            rows.append({"field": f, "offset": h(r[0]) if r else None, "declared_in": r[1] if r else None})
        c.data = rows
        return
    c.p(s2.format_class(k))
    chain = s2.base_chain(img, k.name)
    if len(chain) > 1:
        c.p(f"   chain: {' -> '.join(chain)}")
    c.data = class_json(k)
    c.data["chain"] = chain
    if c.a.flat:
        flat = flat_fields(img, k.name)
        c.p(f"-- all {len(flat)} fields including bases:")
        for off, n, cls in flat:
            c.p(f"   {off:#06x} {n}" + (f"  ({cls})" if cls != k.name else ""))
        c.data["flat"] = [{"offset": h(o), "name": n, "class": cls} for o, n, cls in flat]


def cmd_enum(c):
    img = c.img
    enums = s2.schema_enums(img)
    if c.a.list is not None:
        f = c.a.list.lower()
        rows = [e for e in enums if f in e.name.lower()]
        for e in c.lim(rows):
            c.p(f"{e.info:#010x}  {e.size} byte(s)  {len(e.values):4} values  {e.name}")
        c.more(len(rows))
        c.p(f"{len(rows)} of {len(enums)} enums")
        c.data = [{"name": e.name, "info": h(e.info), "size": e.size, "values": len(e.values)} for e in rows]
        return
    if not c.a.names:
        raise Fail("enum: give enum names, or --list [FILTER]")
    by_name = {e.name: e for e in enums}
    out = []
    for name in c.a.names:
        e = by_name.get(name)
        if e is None:
            near = sorted(n for n in by_name if name.lower() in n.lower())
            c.p(f"{name}: no schema enum in {img.name}" + (f"; similar: {', '.join(near[:15])}" if near else ""))
            continue
        c.p(s2.format_enum(e))
        out.append({"name": e.name, "info": h(e.info), "size": e.size, "values": [{"name": n, "value": v} for n, v in e.values]})
    c.data = out


def cmd_iface(c):
    f = (c.a.filter or "").lower()
    rows = [i for i in s2.interfaces(c.img) if f in i.name.lower()]
    for i in rows:
        c.p(f"{i.name:36} factory {h(i.factory)}  InterfaceReg {h(i.reg)}"
            + (f"  instance {i.instance:#x}" if i.instance is not None else "")
            + (f"  {i.instance_class}" if i.instance_class else ""))
    if not rows:
        c.p("no CreateInterface registrations" + (f" matching {c.a.filter!r}" if f else f" (does {c.img.name} export CreateInterface?)"))
    c.data = [{"name": i.name, "factory": h(i.factory), "reg": h(i.reg), "site": h(i.site),
               "instance": h(i.instance), "instance_class": i.instance_class} for i in rows]
    if c.img.dump:
        import s2dump
        live = s2dump.interface_list(c.img)
        static = {i.reg: i for i in s2.interfaces(c.img)}
        c.p(f"-- runtime list (s_pInterfaceRegs at {h(s2.interface_list_head(c.img))}): {len(live)} node(s), in list order")
        for node, name, create in live:
            known = static.get(node)
            flag = "" if known and known.name == name else "  (not found by the static scan)"
            c.p(f"   {h(node)}  {name or '?':36} create {h(create)}{flag}")
        missing = sorted(set(static) - {n for n, _, _ in live})
        if live and missing:
            c.p(f"   statically registered but not in the live list: {', '.join(static[m].name for m in missing)}")
        c.data = {"static": c.data, "runtime_list": [{"reg": h(n), "name": nm, "create": h(cr)} for n, nm, cr in live]}


def reg_json(r):
    return {"name": r.name, "object": h(r.obj), "site": h(r.site), "init": h(r.init), "help": r.help,
            "callbacks": [h(x) for x in (r.callbacks or [])]}


def show_registrations(c, kind):
    """cvar / concmd: list, or details by name (object, initializer, help, readers / callback)."""
    img = c.img
    regs = s2.registrations(img, kind)
    what = "convars" if kind == "convar" else "console commands"
    if c.a.list is not None:
        f = c.a.list.lower()
        rows = [r for r in regs if f in r.name.lower() or (r.help and f in r.help.lower())]
        for r in c.lim(rows):
            cb = f"  callback {r.callbacks[0]:#x}" if kind == "concmd" and r.callbacks else ""
            c.p(f"{r.obj:#010x}  {r.name}{cb}" + (f"  // {r.help[:90]}" if r.help else ""))
        c.more(len(rows))
        c.p(f"{len(rows)} of {len(regs)} {what}")
        c.data = [reg_json(r) for r in rows]
        return
    if not c.a.names:
        raise Fail(f"{'cvar' if kind == 'convar' else 'concmd'}: give names, or --list [FILTER]")
    by_name = {}
    for r in regs:
        by_name.setdefault(r.name, []).append(r)
    out = []
    for name in c.a.names:
        found = by_name.get(name, [])
        if not found and kind == "convar":  # fall back to the string-anchored heuristic
            for obj, ref, init, hlp in img.convar_by_name(name):
                found.append(s2.Registration(name, obj, ref, init, hlp, []))
        if not found:
            near = sorted(n for n in by_name if name.lower() in n.lower())
            c.p(f"{name}: not registered in {img.name}" + (f"; similar: {', '.join(near[:15])}" if near else ""))
            continue
        for r in found:
            c.p(f"{r.name}: object {r.obj:#x}, registered at {h(r.site)} in fn {h(r.init)}")
            if r.help:
                c.p(f"  help: {r.help}")
            entry = reg_json(r)
            if kind == "concmd":
                for cb in r.callbacks or []:
                    c.p(f"  callback {cb:#x}")
            if img.dump:
                rq = runtime_qwords(img, r.obj)
                c.p("  runtime: " + ", ".join(f"+{o:#x} = {v:#x}" + (f" ({n})" if n else "") for o, v, n in rq))
                entry["runtime"] = [{"offset": o, "value": h(v), "note": n or None} for o, v, n in rq]
            readers = [(s, off, f) for s, off, f in img.object_readers(r.obj, c.a.span) if f != r.init]
            entry["readers"] = [{"rva": h(s), "offset": off, "function": h(f)} for s, off, f in readers]
            c.p(f"  {len(readers)} reference(s) outside the initializer:")
            for s, off, f in c.lim(readers):
                c.p(f"    {c.insn(s)}    [{c.where(s)}]" + (f"  (object+{off:#x})" if off else ""))
            c.more(len(readers))
            out.append(entry)
    c.data = out


def cmd_cvar(c):
    show_registrations(c, "convar")


def cmd_concmd(c):
    show_registrations(c, "concmd")


def cmd_cvarobj(c):
    img = c.img
    by_obj = s2.registration_by_object(img)
    out = []
    for q in c.a.rva:
        r = c.rva(q)
        reg = by_obj.get(r)
        if reg:
            name, init, hlp = reg.name, reg.init, reg.help
        else:
            name, ref, hlp = img.convar_by_object(r)
            init = img.function_start(ref) if ref is not None else None
        readers = img.object_readers(r, c.a.span)
        c.p(f"{r:#x}: {name or '(no convar/concommand registered with this object)'}"
            + (f", initializer {init:#x}" if init is not None else "") + (f"\n  help: {hlp}" if hlp else ""))
        for s, off, f in c.lim(readers):
            c.p(f"  {c.insn(s)}    [{c.where(s)}]" + (f"  (object+{off:#x})" if off else "") + ("  <- initializer" if f == init else ""))
        c.more(len(readers))
        out.append({"object": h(r), "name": name, "init": h(init), "help": hlp,
                    "readers": [{"rva": h(s), "offset": off, "function": h(f)} for s, off, f in readers]})
        if img.dump:
            rq = runtime_qwords(img, r)
            c.p("  runtime: " + ", ".join(f"+{o:#x} = {v:#x}" + (f" ({n})" if n else "") for o, v, n in rq))
            out[-1]["runtime"] = [{"offset": o, "value": h(v), "note": n or None} for o, v, n in rq]
    c.data = out


def cmd_proto(c):
    img = c.img
    ps = img.protos()
    if not c.a.name:
        for r, n in ps:
            c.p(f"{r:#010x}  {n}")
        c.p(f"{len(ps)} embedded .proto file descriptor(s)")
        c.data = [{"rva": h(r), "name": n} for r, n in ps]
        return
    hits = [(r, n) for r, n in ps if n == c.a.name or n.endswith("/" + c.a.name)]
    if not hits:
        hits = [(r, n) for r, n in ps if c.a.name.lower() in n.lower()]
    if not hits:
        raise Fail(f"proto: no descriptor named like {c.a.name!r} ({len(ps)} in {img.name}; run `proto` to list)")
    if len({n for _, n in hits}) > 1:
        c.p(f"{c.a.name!r} matches {len(hits)} descriptors; be more specific:")
        for r, n in hits:
            c.p(f"  {r:#010x}  {n}")
        c.data = [{"rva": h(r), "name": n} for r, n in hits]
        return
    r, n = hits[0]
    fd = img.proto_descriptor(r)
    c.p(f"// {n} @ {r:#x}")
    c.p(s2pe.format_proto(fd, c.a.message))
    c.data = {"rva": h(r), "name": n, "descriptor": fd}


# ---------------------------------------------------------------------------------------------- signatures

_TOKEN = re.compile(r"[0-9A-Fa-f]{2}|\?{1,2}")
_QUOTED = re.compile(r'"((?:[0-9A-Fa-f]{2}|\?{1,2})(?: (?:[0-9A-Fa-f]{2}|\?{1,2}))+)"')
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_:]*")


def fmt_sig(pat, style):
    vals = s2pe.parse_pattern(pat) if isinstance(pat, str) else pat
    if style == "compact":
        return "".join("??" if v is None else f"{v:02X}" for v in vals)
    out = s2pe.format_pattern(vals, style)
    return f'"{out[0]}", "{out[1]}"' if style == "code" else out


_STRLIT = re.compile(r'"([^"\\\n]*)"')
_MODULE = re.compile(r"[\w.-]+\.(?:dll|so|exe)", re.I)
_NAMELIKE = re.compile(r"[A-Za-z_][\w:<>~.-]*")
_KEYWORDS = {"const", "constexpr", "static", "inline", "auto", "char", "std", "string_view", "return"}


def sig_entries(c):
    """(name, pattern, mask, rel, module) from the command line or --file. A file is either one signature per
    line (`[name =] PATTERN [rel=OFF,LEN]`, '#' comments, code-style patterns followed by their mask) or source
    code (C/C++/Python/...), from which every quoted IDA-style pattern is taken. In source, the name is a quoted
    identifier earlier on the same line (`{"TraceHull", "client.dll", "48 8B ..."}`), else the last bare
    identifier before the pattern; a quoted "*.dll" on the line is the signature's module."""
    if not c.a.file:
        pats = c.a.pattern
        if pats and all(_TOKEN.fullmatch(t) for t in pats):  # an unquoted IDA pattern split by the shell
            pats = [" ".join(pats)]
        rel = tuple(int(x, 0) for x in c.a.rel) if c.a.rel else None
        return [(None, p, c.a.mask, rel, None) for p in pats]
    with open(c.a.file, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    quoted = list(_QUOTED.finditer(text))
    out = []
    if quoted:
        for m in quoted:
            line_start = text.rfind("\n", 0, m.start()) + 1
            pre = text[line_start:m.start()]
            lits = [s for s in _STRLIT.findall(pre) if not _QUOTED.fullmatch(f'"{s}"')]
            mods = [s for s in lits if _MODULE.fullmatch(s)]
            names = [s for s in lits if _NAMELIKE.fullmatch(s) and s not in mods]
            idents = [i for i in _IDENT.findall(_STRLIT.sub("", pre)) if i not in _KEYWORDS]
            lineno = text.count("\n", 0, m.start()) + 1
            name = names[-1] if names else (idents[-1] if idents else f"line {lineno}")
            out.append((name, m.group(1), None, None, mods[-1] if mods else None))
        return out
    for lineno, ln in enumerate(text.splitlines(), 1):
        ln = ln.split("#", 1)[0].strip()
        if not ln:
            continue
        name, _, rest = ln.partition("=") if "=" in ln.split("rel=")[0] else ("", "", ln)
        toks = rest.split()
        rel = mask = None
        if toks and toks[-1].startswith("rel="):
            off, ln_ = toks.pop()[4:].split(",")
            rel = (int(off, 0), int(ln_, 0))
        if "\\x" in rest and toks and set(toks[-1]) <= set("x?"):
            mask = toks.pop()
        out.append((name.strip() or f"line {lineno}", " ".join(toks), mask, rel, None))
    return out


def cmd_sig(c):
    img = c.img
    entries = sig_entries(c)
    if not entries:
        raise Fail("sig: give a pattern, or --file FILE")
    other = Counter(m.lower() for *_, m in entries if m and m.lower() != img.name.lower())
    entries = [e for e in entries if not e[4] or e[4].lower() == img.name.lower()]
    if not entries:
        raise Fail(f"sig --file: no signatures for {img.name}; the file has "
                   + ", ".join(f"{m} ({n})" for m, n in sorted(other.items())) + ". Pass -m <module>.")
    out = []
    status = Counter()
    for name, pat, mask, rel, _ in entries:
        try:
            hits = img.scan(pat, c.a.region, limit=1000, mask=mask)
        except ValueError as e:
            c.p(f"{name or pat}: bad pattern ({e})")
            status["bad"] += 1
            out.append({"name": name, "pattern": pat, "error": str(e)})
            continue
        st = "unique" if len(hits) == 1 else ("missing" if not hits else "ambiguous")
        status[st] += 1
        rows = []
        for a in hits:
            row = {"rva": h(a), "function": h(img.function_start(a))}
            if rel:
                t = img.rel(a, *rel)
                row["resolved"] = h(t)
                row["resolved_note"] = img.describe(t) or None
            rows.append(row)
        out.append({"name": name, "pattern": pat, "status": st, "count": len(hits), "hits": rows})
        label = f"{name}: " if name else ""
        c.p(f"{label}{st.upper()} ({len(hits)}{'+' if len(hits) == 1000 else ''} hit(s))  {pat}")
        if c.a.file and st != "ambiguous" and not c.a.verbose:
            if st == "unique":
                row = rows[0]
                c.p(f"    {row['rva']} [{c.where(hits[0])}]" + (f" -> {row['resolved']} {row['resolved_note'] or ''}" if rel else ""))
            continue
        brief = c.a.file and not c.a.verbose
        shown = list(zip(hits, rows))[:3] if brief else list(zip(c.lim(hits), c.lim(rows)))
        for a, row in shown:
            c.p(f"    {c.insn(a)}    [{c.where(a)}]")
            if rel:
                c.p(f"      rel {rel[0]},{rel[1]} -> {row['resolved']}  {row['resolved_note'] or ''}")
        if brief and len(hits) > 3:
            c.p(f"    ... {len(hits) - 3} more (-v to list)")
        elif not brief:
            c.more(len(hits))
    if len(entries) > 1 or other:
        c.p(f"-- {len(entries)} signatures for {img.name}: " + ", ".join(f"{n} {k}" for k, n in status.most_common())
            + (f"; skipped {sum(other.values())} for other modules ("
               + ", ".join(f"{m} {n}" for m, n in sorted(other.items())) + "): rerun with -m" if other else ""))
    c.data = out


def cmd_sigmake(c):
    img = c.img
    out = []
    for q in c.a.rva:
        r = c.rva(q)
        if c.a.target:
            res = img.make_sig_target(r, c.a.max, c.a.loose)
            c.p(f"signatures leading to {r:#x} ({img.describe(r) or '?'}): {len(res)} unique")
            for site, pat, n, rel in c.lim(res):
                c.p(f"  {site:#010x} [{n} insns] {fmt_sig(pat, c.a.format)}"
                    + (f"  --rel {rel[0]} {rel[1]}" if rel else "  (at the target itself)"))
            c.more(len(res))
            if not res:
                c.p("  none: no unique pattern at the target or at any referencing instruction (try --loose / --max)")
            out.append({"target": h(r), "signatures": [{"site": h(s), "pattern": fmt_sig(p, c.a.format), "insns": n,
                                                        "rel": list(rel) if rel else None} for s, p, n, rel in res]})
            continue
        pat, n, unique, rel = img.make_sig(r, c.a.max, c.a.loose)
        c.p(f"{r:#x}: {'unique' if unique else 'NOT unique'} after {n} insns" + (" (loose)" if c.a.loose else ""))
        c.p(f"  {fmt_sig(pat, c.a.format)}")
        if rel:
            t = img.rel(r, *rel)
            c.p(f"  first rip-relative/branch operand: --rel {rel[0]} {rel[1]} -> {t:#x}  {img.describe(t) or ''}")
        out.append({"rva": h(r), "pattern": fmt_sig(pat, c.a.format), "unique": unique, "insns": n,
                    "rel": list(rel) if rel else None})
    c.data = out


def cmd_sigconv(c):
    pats = c.a.pattern
    text = " ".join(pats) if all(_TOKEN.fullmatch(t) for t in pats) else pats[0]
    vals = s2pe.parse_pattern(text, c.a.mask)
    c.data = {}
    for style in ("ida", "x64dbg", "compact", "code"):
        c.data[style] = fmt_sig(vals, style)
        c.p(f"{style:8} {c.data[style]}")


# ---------------------------------------------------------------------------------------------- builds

def cmd_port(c):
    import s2port
    new = c.img
    if c.a.old:
        old_path = s2pe.resolve_module(c.a.game, c.a.old)
    else:
        snaps = new.snapshots()
        if not snaps:
            raise Fail(f"port: no older build of {new.name} is saved (snapshots are taken automatically when a "
                       f"build is first indexed). Pass --old PATH to an old copy of the DLL.")
        old_path = snaps[0]
    old = s2pe.Image(old_path)
    if (old.file_size, old.mtime) == (new.file_size, new.mtime):
        c.p("note: the old and new files are the same build")
    porter = s2port.Porter(old, new)
    c.p(f"old: {old.path} ({old.file_size} bytes, mtime {old.mtime})")
    c.p(f"new: {build_line(new)}")
    out = []
    for q in c.a.rva:
        r = old.to_rva(hexint(q))
        res = porter.port(r, top=c.a.top)
        c.p()
        if res.kind == "code":
            conf = s2port.confidence(res.candidates)
            best = res.candidates[0].start if res.candidates else None
            answer = best
            how = None
            if res.mapped:
                answer, how = res.mapped
            c.p(f"{r:#x} (code, in old fn {res.old_function:#x}) -> {h(answer)}  confidence {conf}"
                + (f"  [{how}]" if how else ""))
            for cd in res.candidates:
                c.p(f"  {cd.start:#010x}  score {cd.score:5.1f}  (anchors {cd.anchor:.1f}, similarity {cd.similarity:.2f})")
                for e in cd.evidence[:4]:
                    c.p("      " + e.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t"))
                if len(cd.evidence) > 4:
                    c.p(f"      ... {len(cd.evidence) - 4} more anchor(s)")
            out.append({"old": h(r), "kind": "code", "old_function": h(res.old_function), "new": h(answer),
                        "confidence": conf, "mapping": how,
                        "candidates": [{"function": h(cd.start), "score": round(cd.score, 2), "anchor": round(cd.anchor, 2),
                                        "similarity": round(cd.similarity, 3),
                                        "parts": {k: (None if v is None else round(v, 3)) for k, v in cd.parts.items()},
                                        "evidence": cd.evidence} for cd in res.candidates]})
        else:
            best = res.candidates[0][0] if res.candidates else None
            conf = "high" if len(res.candidates) == 1 else ("none" if not res.candidates else "low")
            if len(res.candidates) > 1 and res.candidates[0][2] >= 2 * res.candidates[1][2]:
                conf = "medium"
            c.p(f"{r:#x} (data: {old.describe(r) or '?'}) -> {h(best)}  confidence {conf}")
            for t, why, n in res.candidates[:c.a.top]:
                c.p(f"  {t:#010x}  {why}")
            for n in res.notes:
                c.p(f"  note: {n}")
            out.append({"old": h(r), "kind": "data", "new": h(best), "confidence": conf, "notes": res.notes,
                        "candidates": [{"rva": h(t), "why": why, "votes": n} for t, why, n in res.candidates]})
    c.data = {"old": {"path": old.path, "file_size": old.file_size, "mtime": old.mtime}, "ports": out}


def cmd_snapshots(c):
    img = c.img
    snaps = img.snapshots()
    c.p(f"current: {build_line(img)}")
    c.p(f"store:   {img.snapshot_dir()}")
    rows = []
    for p in snaps:
        size, _, mt = os.path.basename(p)[:-4].partition("_")
        when = datetime.datetime.fromtimestamp(int(mt)) if mt.isdigit() else None
        rows.append({"path": p, "file_size": int(size) if size.isdigit() else None, "mtime": int(mt) if mt.isdigit() else None})
        c.p(f"  {p}" + (f"  ({size} bytes, built {when:%Y-%m-%d %H:%M})" if when else ""))
    if not snaps:
        c.p("  no older builds saved yet (the current build is saved when first indexed; `port` needs an older one)")
    c.data = {"current": {"path": img.path, "file_size": img.file_size, "mtime": img.mtime},
              "store": img.snapshot_dir(), "snapshots": rows}


def cmd_snapshot(c):
    p = c.img.snapshot(force=True)
    if p is None:
        raise Fail(f"{c.img.path} is itself a snapshot")
    c.p(f"saved: {p}")
    c.data = {"path": p}


# ---------------------------------------------------------------------------------------------- export

def cmd_export(c):
    import s2export
    kinds = tuple(k.strip() for k in c.a.only.split(",")) if c.a.only else s2export.KINDS
    bad = set(kinds) - set(s2export.KINDS)
    if bad:
        raise Fail(f"export --only: unknown kind(s) {', '.join(sorted(bad))}; known: {', '.join(s2export.KINDS)}")
    syms = s2export.collect(c.img, kinds)
    c.raw = s2export.render(c.img, syms, c.a.tool, build_line(c.img))
    counts = Counter(s.kind for s in syms)
    c.note = f"{len(syms)} names for {c.a.tool} (" + ", ".join(f"{k} {counts[k]}" for k in kinds if counts[k]) + ")"


# ---------------------------------------------------------------------------------------------- raw

def cmd_hex(c):
    img = c.img
    r = c.rva(c.a.rva)
    n = max(0, min(hexint(c.a.count), img.size - r))
    if c.a.qwords:
        rows = []
        for i in range(0, n - n % 8, 8):
            v = struct.unpack_from("<Q", img.mem, r + i)[0]
            t = v - img.base
            note = (img.describe(t) or "") if 0 <= t < img.size else ""
            rows.append({"rva": h(r + i), "value": h(v), "note": note or None})
            c.p(f"{r + i:#010x}  {v:#018x}  {note}")
        c.data = rows
        return
    data = bytes(img.mem[r:r + n])
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        c.p(f"{r + i:#010x}  {' '.join(f'{b:02x}' for b in chunk):47}  "
            + "".join(chr(b) if 32 <= b < 127 else "." for b in chunk))
    c.data = {"rva": h(r), "hex": data.hex()}


def cmd_exports(c):
    f = (c.a.filter or "").lower()
    rows = sorted((r, n) for n, r in c.img.exports().items() if f in n.lower())
    for r, n in c.lim(rows):
        c.p(f"{r:#010x}  {n}")
    c.more(len(rows))
    c.data = [{"rva": h(r), "name": n} for r, n in rows]


def cmd_imports(c):
    f = (c.a.filter or "").lower()
    rows = sorted((r, n) for r, n in c.img.imports().items() if f in n.lower())
    for r, n in c.lim(rows):
        c.p(f"{r:#010x}  {len(c.img.xrefs(r)):5} ref(s)  {n}")
    c.more(len(rows))
    c.data = [{"slot": h(r), "name": n, "refs": len(c.img.xrefs(r))} for r, n in rows]


# ---------------------------------------------------------------------------------------------- dumps

def cmd_dumpdiff(c):
    import s2dump
    dump = c.img
    if not dump.dump:
        raise Fail("dumpdiff: load a dump with --memdump FILE; -m / --disk name the DLL to compare it with")
    disk = s2pe.Image(s2pe.resolve_module(c.a.game, c.a.disk or c.a.module))
    kinds = set(c.a.kind.split(",")) if c.a.kind else {"code", "vtable", "rdata", "data"}
    try:
        changes = [ch for ch in s2dump.diff(dump, disk, c.a.section) if ch.kind in kinds]
    except s2dump.BuildMismatch as e:
        raise Fail(str(e))
    c.p(f"dump  {build_line(dump)} (base from {dump.base_source})")
    c.p(f"disk  {disk.path}")
    by = {k: [ch for ch in changes if ch.kind == k] for k in ("code", "vtable", "rdata", "data")}
    titles = {"code": "code changed (patches / inline hooks)", "vtable": "vtable slots redirected",
              "rdata": "other read-only data changed", "data": "written at runtime"}
    q0 = lambda hx: int.from_bytes(bytes.fromhex(hx)[:8], "little")  # noqa: E731
    for k in ("code", "vtable", "rdata", "data"):
        if k not in kinds:
            continue
        rows = by[k]
        named = sum(1 for ch in rows if ch.owner)
        c.p(f"{titles[k]}: {len(rows)}" + (f" range(s), {named} with a known owner" if k == "data" else ""))
        if k == "data" and not c.a.all_data:
            rows = [ch for ch in rows if ch.owner]  # unnamed runtime writes are the norm: --all-data lists them
        for ch in c.lim(rows):
            if k == "code":
                c.p(f"  {ch.rva:#010x} {ch.section} [{ch.owner or 'no .pdata'}] {ch.size} byte(s)")
                c.p("     disk: " + " | ".join(ch.disk))
                c.p("     dump: " + " | ".join(ch.dump))
                for n in ch.notes:
                    c.p(f"     ! {n}")
            elif k == "vtable":
                c.p(f"  {ch.rva:#010x} {ch.owner}: shipped {ch.disk} -> now {ch.dump}")
            else:
                c.p(f"  {ch.rva:#010x} {ch.size:4} byte(s)  {ch.owner or '?':44} {q0(ch.disk):#018x} -> {q0(ch.dump):#018x}"
                    + (f"  {ch.notes[0]}" if ch.notes else ""))
        c.more(len(rows))
    c.data = {"dump": build_json(dump), "disk": disk.path,
              "counts": {k: len(v) for k, v in by.items() if k in kinds},
              "changes": [{"kind": ch.kind, "section": ch.section, "rva": h(ch.rva), "size": ch.size, "owner": ch.owner,
                           "disk": ch.disk, "dump": ch.dump, "notes": ch.notes} for ch in changes]}


# ---------------------------------------------------------------------------------------------- CLI

COMMANDS = {
    "info": (cmd_info, "module, sections, cache and snapshot status"),
    "str": (cmd_str, "find strings and the code referencing them"),
    "xrefs": (cmd_xrefs, "code references and stored pointers to an address"),
    "func": (cmd_func, "disassemble the function containing an address (chunks stitched)"),
    "range": (cmd_range, "disassemble N instructions from an address"),
    "callers": (cmd_callers, "caller tree (direct calls, tail jumps, vtable slots)"),
    "callees": (cmd_callees, "direct calls / tail jumps / imports out of a function"),
    "rtti": (cmd_rtti, "RTTI vtables of a class with every slot, or --grep class names"),
    "vtwho": (cmd_vtwho, "which vtable slots hold a function"),
    "fields": (cmd_fields, "struct offsets accessed through a register (optionally named from the schema)"),
    "disp": (cmd_disp, "instructions using given displacements inside functions"),
    "schema": (cmd_schema, "schema classes: one class, field offsets, --list, --dump"),
    "enum": (cmd_enum, "schema enums: values, --list"),
    "iface": (cmd_iface, "CreateInterface registrations"),
    "cvar": (cmd_cvar, "ConVars: object, initializer, help, readers, --list"),
    "cvarobj": (cmd_cvarobj, "which ConVar / ConCommand an object address belongs to"),
    "concmd": (cmd_concmd, "ConCommands: object, callback, help, --list"),
    "proto": (cmd_proto, "embedded protobuf descriptors as .proto text"),
    "sig": (cmd_sig, "scan IDA / x64dbg / compact / code+mask patterns, or check a --file of them"),
    "sigmake": (cmd_sigmake, "shortest unique signature at an address, or --target ones that lead to it"),
    "sigconv": (cmd_sigconv, "convert a pattern between formats"),
    "port": (cmd_port, "find an old build's address in the current build"),
    "snapshots": (cmd_snapshots, "list saved older builds"),
    "snapshot": (cmd_snapshot, "save the current build now"),
    "export": (cmd_export, "names as an IDA / Ghidra / Binary Ninja script or JSON"),
    "dumpdiff": (cmd_dumpdiff, "a --memdump against its DLL: patched code, redirected vtables, runtime writes"),
    "hex": (cmd_hex, "hex dump, or --qwords with pointer annotations"),
    "exports": (cmd_exports, "PE exports"),
    "imports": (cmd_imports, "PE imports (IAT slots, delay-load tagged)"),
}


def build_parser():
    S = argparse.SUPPRESS

    def globals_(parser, defaults):
        d = (lambda v: v) if defaults else (lambda v: S)
        parser.add_argument("-g", "--game", default=d(os.environ.get("S2RE_GAME", "cs2")), choices=sorted(s2pe.GAMES),
                            help="game preset (env S2RE_GAME; more via S2RE_GAMES)")
        parser.add_argument("-m", "--module", default=d("client"), help="client, server, engine2, ... or a DLL path")
        parser.add_argument("--json", action="store_true", default=d(False), help="machine-readable output")
        parser.add_argument("-o", "--out", default=d(None), metavar="FILE", help="write the output to FILE")
        parser.add_argument("--limit", type=int, default=d(50), help="rows per list in text output (0 = all)")
        parser.add_argument("-q", "--quiet", action="store_true", default=d(False), help="no '# <build>' header line")
        parser.add_argument("--memdump", metavar="FILE", default=d(None),
                            help="work on a module dumped from a running process instead of the DLL")
        parser.add_argument("--base", type=hexint, default=d(None), help="--memdump: runtime base (default: detected)")
        parser.add_argument("--layout", choices=["mapped", "file"], default=d(None),
                            help="--memdump: raw memory image or rebuilt PE (default: detected)")
        parser.add_argument("--headers-from", metavar="DLL", default=d(None),
                            help="--memdump: take PE headers from this DLL / module (erased headers)")

    p = argparse.ArgumentParser(prog="s2re", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    globals_(p, True)
    common = argparse.ArgumentParser(add_help=False)
    globals_(common, False)  # same options after the command, without overriding the ones given before it
    sub = p.add_subparsers(dest="cmd", metavar="command")
    sub.required = True
    sp = {name: sub.add_parser(name, parents=[common], help=hlp, description=hlp) for name, (_, hlp) in COMMANDS.items()}

    sp["str"].add_argument("text", nargs="+")
    sp["str"].add_argument("--partial", action="store_true", help="strings containing TEXT")
    sp["str"].add_argument("--wide", action="store_true", help="UTF-16LE strings")
    sp["str"].add_argument("--section", default=".rdata", help="section for --partial (default .rdata)")
    sp["xrefs"].add_argument("rva", nargs="+")
    sp["func"].add_argument("rva", nargs="+")
    sp["range"].add_argument("rva")
    sp["range"].add_argument("count", nargs="?", type=int, default=30)
    sp["callers"].add_argument("rva", nargs="+")
    sp["callers"].add_argument("--depth", type=int, default=1)
    sp["callees"].add_argument("rva", nargs="+")

    sp["rtti"].add_argument("names", nargs="*", metavar="CLASS")
    sp["rtti"].add_argument("--grep", metavar="TEXT")
    sp["vtwho"].add_argument("rva", nargs="+")
    sp["fields"].add_argument("rva")
    sp["fields"].add_argument("--reg", default="rcx", help="register holding the object at entry (default rcx)")
    sp["fields"].add_argument("--schema", metavar="CLASS", help="name offsets from this schema class and its bases")
    sp["disp"].add_argument("disp", nargs="+")
    sp["disp"].add_argument("--in", dest="inside", nargs="+", metavar="RVA", help="functions containing these addresses")
    sp["disp"].add_argument("--range", nargs=2, metavar=("LO", "HI"), help=".pdata functions starting in [LO, HI)")
    sp["disp"].add_argument("--imm", action="store_true", help="also match immediates (add rcx, 0x120)")

    sp["schema"].add_argument("name", nargs="?", metavar="CLASS")
    sp["schema"].add_argument("fields", nargs="*", metavar="FIELD")
    sp["schema"].add_argument("--list", nargs="?", const="", metavar="FILTER")
    sp["schema"].add_argument("--dump", action="store_true")
    sp["schema"].add_argument("--format", choices=["text", "cpp", "json"], default="text")
    sp["schema"].add_argument("--flat", action="store_true", help="also list inherited fields at absolute offsets")
    sp["enum"].add_argument("names", nargs="*", metavar="NAME")
    sp["enum"].add_argument("--list", nargs="?", const="", metavar="FILTER")
    sp["iface"].add_argument("filter", nargs="?")
    for name in ("cvar", "cvarobj", "concmd"):
        sp[name].add_argument("--span", type=hexint, default=0x10,
                              help="bytes of the object counted as a reference (hex, default 0x10 = object spacing)")
    sp["cvar"].add_argument("names", nargs="*", metavar="NAME")
    sp["cvar"].add_argument("--list", nargs="?", const="", metavar="FILTER")
    sp["cvarobj"].add_argument("rva", nargs="+")
    sp["concmd"].add_argument("names", nargs="*", metavar="NAME")
    sp["concmd"].add_argument("--list", nargs="?", const="", metavar="FILTER")
    sp["proto"].add_argument("name", nargs="?", metavar="NAME.proto")
    sp["proto"].add_argument("--message", metavar="M", help="only this message")

    sp["sig"].add_argument("pattern", nargs="*")
    sp["sig"].add_argument("--rel", nargs=2, metavar=("OFF", "LEN"), help="resolve a rel32 at OFF in an insn of LEN")
    sp["sig"].add_argument("--mask", help="mask for a code-style \\x48\\x8B pattern (xx??)")
    sp["sig"].add_argument("--file", help="signature list, or source code containing quoted patterns")
    sp["sig"].add_argument("--region", choices=["image", "code"], default="image")
    sp["sig"].add_argument("-v", "--verbose", action="store_true", help="with --file: show every hit")
    sp["sigmake"].add_argument("rva", nargs="+")
    sp["sigmake"].add_argument("--loose", action="store_true", help="also wildcard struct offsets / imm32 / rel8")
    sp["sigmake"].add_argument("--format", choices=["ida", "x64dbg", "code", "compact"], default="ida")
    sp["sigmake"].add_argument("--target", action="store_true", help="signatures that lead TO the address")
    sp["sigmake"].add_argument("--max", type=int, default=32, help="max instructions (default 32)")
    sp["sigconv"].add_argument("pattern", nargs="+")
    sp["sigconv"].add_argument("--mask")

    sp["port"].add_argument("rva", nargs="+", help="address(es) in the OLD build")
    sp["port"].add_argument("--old", metavar="DLL", help="old build (default: newest snapshot)")
    sp["port"].add_argument("--top", type=int, default=5)

    sp["export"].add_argument("--tool", required=True, choices=["ida", "ghidra", "binja", "json"])
    sp["export"].add_argument("--only", metavar="KIND,...", help="scope,concmd,cvar,iface,schema,vtable,vfunc")

    sp["hex"].add_argument("rva")
    sp["hex"].add_argument("count", nargs="?", default="0x80", help="bytes, hex (default 0x80)")
    sp["hex"].add_argument("--qwords", action="store_true")
    sp["exports"].add_argument("filter", nargs="?")
    sp["imports"].add_argument("filter", nargs="?")

    sp["dumpdiff"].add_argument("--disk", metavar="DLL", help="DLL / module to compare with (default: -m)")
    sp["dumpdiff"].add_argument("--kind", metavar="KIND,...", help="code,vtable,rdata,data (default: all)")
    sp["dumpdiff"].add_argument("--section", nargs="+", metavar="NAME", help="only these sections")
    sp["dumpdiff"].add_argument("--all-data", action="store_true", help="also list runtime writes with no known owner")
    return p


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError):
            pass
    s2pe.PARALLEL = True
    a = build_parser().parse_args(argv)
    try:
        if a.memdump:
            hf = s2pe.resolve_module(a.game, a.headers_from) if a.headers_from else None
            try:
                img = s2pe.Image(a.memdump, dump=True, layout=a.layout, base=a.base, headers_from=hf)
            except ValueError as e:
                raise Fail(str(e))
        elif a.base is not None or a.layout or a.headers_from:
            raise Fail("--base / --layout / --headers-from apply to --memdump FILE")
        else:
            img = s2pe.Image(s2pe.resolve_module(a.game, a.module))
        c = Ctx(img, a)
        COMMANDS[a.cmd][0](c)
    except (Fail, FileNotFoundError) as e:
        print(f"s2re: {e}", file=sys.stderr)
        return 2
    if c.raw is not None:
        text = c.raw
    elif a.json:
        text = json.dumps({"module": img.path, "build": build_json(img), "result": c.data}, indent=1, default=str)
    else:
        text = "\n".join(c.lines).rstrip("\n")
        if not a.quiet:  # RVAs are per build: keep this line next to any address you record
            game = "" if a.memdump or os.path.isfile(a.module) else f"{a.game} "
            text = f"# {game}{build_line(img)}\n{text}"
    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text + "\n")
        print(f"[s2re] {build_line(img)}; wrote {a.out}" + (f": {c.note}" if c.note else ""), file=sys.stderr)
    else:
        if c.note:
            print(f"[s2re] {c.note}", file=sys.stderr)
        sys.stdout.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
