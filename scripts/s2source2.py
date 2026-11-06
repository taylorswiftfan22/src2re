"""s2source2 - Source 2 specifics on top of s2pe.

  schema_classes / schema_enums   every static SchemaClassInfoData_t / SchemaEnumInfoData_t in a module
  dump_schema                     text / C++ header / JSON of all classes, offsets and enums
  registrations                   every ConVar or ConCommand registered by a module (name, object, callback, help)
  interfaces                      CreateInterface registrations: version string -> factory, instance

Layouts were confirmed on CS2 client.dll (2026-11-04) and Deadlock client.dll (2026-10-28); see
references/layouts.md for the evidence behind each field.
"""
import json
import re
import struct
from collections import namedtuple

SchemaField = namedtuple("SchemaField", "name offset metadata")
SchemaClass = namedtuple("SchemaClass", "info name size align fields bases static_fields")
SchemaEnum = namedtuple("SchemaEnum", "info name size values")
Registration = namedtuple("Registration", "name obj site init help callbacks")
Interface = namedtuple("Interface", "name factory reg site instance instance_class")

FF4 = b"\xff\xff\xff\xff"


def _qwords(img, sec):
    lo = (sec.rva + 7) & ~7
    n = (sec.rva + sec.size - lo) // 8
    return lo, struct.unpack_from(f"<{n}Q", img.mem, lo)


def _ptr_or_null(img, rva):
    v = img.u64(rva)
    return v == 0 or img.base <= v < img.base + img.size


def _name_at(img, rva, limit=300):
    """Printable C string the qword at rva points to, else None."""
    p = img.ptr(rva)
    if p is None:
        return None
    s = img.cstr(p, limit)
    return s if s and s.isprintable() else None


# ---------------------------------------------------------------------------------------------- schema classes

def schema_classes(img):
    """All static SchemaClassInfoData_t in .data, sorted by name. Shape:
    +0x00 0 (self, set at runtime)  +0x08 name*  +0x10/+0x18 0  +0x20 i32 sizeof  +0x24 i16 fields
    +0x26 i16 static fields  +0x28 u8 align (0xff = unknown)  +0x29 u8 bases  +0x2a ff ff ff ff
    +0x30 SchemaClassFieldData_t* (0x20 each: name*, type* (null on disk), i32 offset, i32 metadata count,
    metadata* (0x10 each: name*, value*))  +0x38 SchemaBaseClassInfoData_t* (0x10 each: u32 offset, class*)."""
    cached = getattr(img, "_schema_classes", None)
    if cached is not None:
        return cached
    m = img.mem
    out = []
    sec = img.section(".data")
    if sec is None:
        img._schema_classes = out
        return out
    lo, q = _qwords(img, sec)
    base, end = img.base, img.base + img.size
    relaxed = getattr(img, "dump", False)  # in a dump, +0x00 (set at runtime) may be non-zero
    for j in range(len(q) - 8):
        if not (base <= q[j + 1] < end) or q[j + 2] or q[j + 3] or (q[j] and not relaxed):
            continue
        ci = lo + 8 * j
        if m[ci + 0x2A:ci + 0x2E] != FF4:
            continue
        name = _name_at(img, ci + 8)
        if not name:
            continue
        size = struct.unpack_from("<i", m, ci + 0x20)[0]
        nfields, nstatic = struct.unpack_from("<hh", m, ci + 0x24)
        align, nbases = m[ci + 0x28], m[ci + 0x29]
        if relaxed and not (0 < size < 0x1000000 and 0 <= nfields < 4096 and nbases <= 16
                            and _ptr_or_null(img, ci + 0x30) and _ptr_or_null(img, ci + 0x38)):
            continue
        fields = []
        farr = img.ptr(ci + 0x30)
        for i in range(max(nfields, 0) if farr is not None else 0):
            e = farr + 0x20 * i
            fname = _name_at(img, e)
            if fname is None:
                break
            off, nmd = struct.unpack_from("<ii", m, e + 0x10)
            md = []
            mdp = img.ptr(e + 0x18)
            for k in range(min(max(nmd, 0), 32) if mdp is not None else 0):
                mn = _name_at(img, mdp + 0x10 * k, 120)
                if mn is None:
                    break
                vp = img.ptr(mdp + 0x10 * k + 8)
                val = img.printable_at(vp, minlen=2) if vp is not None and img.section_of(vp) == ".rdata" else None
                md.append((mn, val))
            fields.append(SchemaField(fname, off, tuple(md)))
        bases = []
        barr = img.ptr(ci + 0x38)
        for i in range(nbases if barr is not None else 0):
            boff = img.u32(barr + 0x10 * i)
            bci = img.ptr(barr + 0x10 * i + 8)
            bases.append((boff, _name_at(img, bci + 8) if bci is not None else None))
        out.append(SchemaClass(ci, name, size, None if align == 0xFF else align, tuple(fields), tuple(bases), nstatic))
    out.sort(key=lambda c: c.name)
    img._schema_classes = out
    return out


def schema_class_map(img):
    return {c.name: c for c in schema_classes(img)}


def find_field(img, cls, field):
    """(offset, declaring class) for a field declared on `cls` or any schema base (base offsets added)."""
    classes = schema_class_map(img)
    seen = set()

    def walk(name, add):
        if name in seen or name not in classes:
            return None
        seen.add(name)
        c = classes[name]
        for f in c.fields:
            if f.name == field:
                return f.offset + add, name
        for boff, bname in c.bases:
            if bname:
                r = walk(bname, add + boff)
                if r:
                    return r
        return None

    return walk(cls, 0)


def base_chain(img, cls):
    """[cls, base, base's base, ...] following the first schema base; '<other module>' when unresolved."""
    classes = schema_class_map(img)
    chain, cur = [], cls
    while cur and cur not in chain:
        chain.append(cur)
        c = classes.get(cur)
        if not c or not c.bases:
            break
        cur = c.bases[0][1] or "<other module>"
        if cur == "<other module>":
            chain.append(cur)
            break
    return chain


# ---------------------------------------------------------------------------------------------- schema enums

def schema_enums(img):
    """All static SchemaEnumInfoData_t in .data, sorted by name. Shape: +0x00 0, +0x08 name*, +0x10 0,
    +0x18 u8 size, +0x19 u8 align, +0x1c u16 enumerator count, +0x20 enumerators* (0x20 each: name*,
    i64 value, metadata count, metadata*), +0x38 = -1."""
    cached = getattr(img, "_schema_enums", None)
    if cached is not None:
        return cached
    m = img.mem
    out = []
    sec = img.section(".data")
    if sec is None:
        img._schema_enums = out
        return out
    lo, q = _qwords(img, sec)
    base, end = img.base, img.base + img.size
    relaxed = getattr(img, "dump", False)  # in a dump, +0x00 (set at runtime) may be non-zero
    for j in range(len(q) - 8):
        if not (base <= q[j + 1] < end) or q[j + 2] or q[j + 7] != 0xFFFFFFFFFFFFFFFF or (q[j] and not relaxed):
            continue
        ei = lo + 8 * j
        if m[ei + 0x2A:ei + 0x2E] == FF4:  # a class info, not an enum
            continue
        name = _name_at(img, ei + 8)
        cnt = struct.unpack_from("<H", m, ei + 0x1C)[0]
        arr = img.ptr(ei + 0x20)
        if not name or not cnt or arr is None or _name_at(img, arr) is None:
            continue
        values = []
        for i in range(cnt):
            e = arr + 0x20 * i
            vn = _name_at(img, e, 160)
            if vn is None:
                break
            values.append((vn, struct.unpack_from("<q", m, e + 8)[0]))
        out.append(SchemaEnum(ei, name, m[ei + 0x18], tuple(values)))
    out.sort(key=lambda e: e.name)
    img._schema_enums = out
    return out


# ---------------------------------------------------------------------------------------------- dumps

def _ident(s):
    s = re.sub(r"[^0-9A-Za-z_]", "_", s)
    return "_" + s if s[:1].isdigit() else s


def _enum_type(e):
    signed = any(v < 0 for _, v in e.values)
    bits = {1: 8, 2: 16, 4: 32, 8: 64}.get(e.size, 32)
    return f"{'int' if signed else 'uint'}{bits}_t"


def dump_schema(img, fmt="text", build_line=""):
    classes, enums = schema_classes(img), schema_enums(img)
    if fmt == "json":
        return json.dumps({
            "module": img.name, "build": {"file_size": img.file_size, "mtime": img.mtime},
            "classes": {c.name: {
                "sizeof": c.size, "align": c.align, "static_fields": c.static_fields,
                "bases": [{"offset": o, "name": n} for o, n in c.bases],
                "fields": {f.name: f.offset for f in c.fields},
                "metadata": {f.name: [n if v is None else f"{n}={v}" for n, v in f.metadata] for f in c.fields if f.metadata},
            } for c in classes},
            "enums": {e.name: {"size": e.size, "values": dict(e.values)} for e in enums},
        }, indent=1)
    lines = []
    if fmt == "cpp":
        ns = _ident(img.name.replace(".dll", "_dll"))
        lines += [f"// {img.name} schema: {len(classes)} classes, {len(enums)} enums. {build_line}",
                  "// Generated by source2-re (offline, from the DLL on disk). Offsets are per build.",
                  "#pragma once", "#include <cstddef>", "#include <cstdint>", "", f"namespace schema::{ns} {{"]
        for e in enums:
            lines.append(f"    enum class {_ident(e.name)} : {_enum_type(e)} {{")
            for vn, v in e.values:
                lines.append(f"        {_ident(vn)} = {v},")
            lines.append("    };")
        for c in classes:
            bases = ", ".join(b or "<other module>" for _, b in c.bases)
            lines.append(f"    // {c.name}" + (f" : {bases}" if bases else "") + f" (sizeof {c.size:#x})")
            lines.append(f"    namespace {_ident(c.name)} {{")
            for f in sorted(c.fields, key=lambda f: f.offset):
                md = " // " + ", ".join(n if v is None else f"{n} {v}" for n, v in f.metadata) if f.metadata else ""
                lines.append(f"        constexpr std::ptrdiff_t {_ident(f.name)} = {f.offset:#x};{md}")
            lines.append("    }")
        lines.append("}")
        return "\n".join(lines)
    lines.append(f"// {img.name}: {len(classes)} classes, {len(enums)} enums. {build_line}")
    for c in classes:
        lines.append(format_class(c))
    for e in enums:
        lines.append(format_enum(e))
    return "\n".join(lines)


def format_class(c, only=None):
    bases = ", ".join(f"{b or '<other module>'}" + (f" @ {o:#x}" if o else "") for o, b in c.bases)
    out = [f"== {c.name}" + (f" : {bases}" if bases else "") + f"  sizeof {c.size:#x}"
           + (f", align {c.align}" if c.align else "") + f", {len(c.fields)} declared fields"
           + (f", {c.static_fields} static" if c.static_fields else "") + f"  (class info {c.info:#x})"]
    for f in sorted(c.fields, key=lambda f: f.offset):
        if only and f.name not in only:
            continue
        md = "  [" + ", ".join(n if v is None else f"{n}={v}" for n, v in f.metadata) + "]" if f.metadata else ""
        out.append(f"   {f.offset:#06x} {f.name}{md}")
    return "\n".join(out)


def format_enum(e):
    out = [f"== enum {e.name} ({e.size} byte{'s' if e.size != 1 else ''}, {len(e.values)} values)  (info {e.info:#x})"]
    out += [f"   {v:>6} {n}" for n, v in e.values]
    return "\n".join(out)


# ---------------------------------------------------------------------------------------------- convars / concommands

ANCHORS = {
    "convar": "RegisterConVar: Unknown error",
    "concmd": "RegisterConCommand: Unknown error",
}


def _branch_to(img, site, target):
    ins = img.insn_at(site)
    return ins is not None and ins.mnemonic in ("call", "jmp") and img.target_of(ins) == target


def registration_functions(img, kind):
    """Functions containing the registration error string (the module's ConVar / ConCommand registrar)."""
    out = set()
    for s in img.find_cstr_partial(ANCHORS[kind]):
        for r in img.xrefs(s):
            f = img.function_start(r)
            if f is not None:
                out.add(f)
    return out


def registrations(img, kind):
    """Every ConVar ('convar') or ConCommand ('concmd') a module registers, from the call sites of its
    registrar and of the small wrappers that call it: `lea rdx,[name]` + `lea rcx,[object]` before the call.
    ConCommands also pass the callback (a code lea, stored into the callback struct) and help text (r9)."""
    key = f"_reg_{kind}"
    cached = getattr(img, key, None)
    if cached is not None:
        return cached
    regs = registration_functions(img, kind)
    sites = [(r, t) for t in regs for r in img.xrefs(t) if _branch_to(img, r, t)]
    wrappers = set()
    for r, t in sites:
        f = img.func_of(r)
        if f and f[1] - f[0] < 0x300:
            p = img.primary(f[0])
            if p not in regs and len(img.xrefs(p)) >= 3:
                wrappers.add(p)
    for w in wrappers:
        sites += [(r, w) for r in img.xrefs(w) if _branch_to(img, r, w)]
    found = {}
    for site, _ in sites:
        leas = [x for x in img._leas_near(site, before=0x80, after=0) if x[0] < site]
        names = [(site - a, t) for a, reg, t in leas if reg == "rdx" and img.section_of(t) == ".rdata"
                 and img.printable_at(t, 1)]
        objs = [(site - a, t) for a, reg, t in leas if reg == "rcx" and img.section_of(t) == ".data"]
        if not names or not objs:
            continue
        name_rva = min(names)[1]
        name, obj = img.cstr(name_rva), min(objs)[1]
        if name in found:
            continue
        init = img.function_start(site)
        if kind == "concmd":
            helps = [t for a, reg, t in leas if reg == "r9" and img.section_of(t) == ".rdata"]
            help_ = img.printable_at(helps[-1], 1, 600) if helps else None
            cbs = tuple(t for a, reg, t in leas if img.is_code(t) and t != init)
        else:
            help_ = img._convar_help(leas, {name_rva, obj})
            cbs = tuple(t for a, reg, t in leas if img.is_code(t) and t != init)
        found[name] = Registration(name, obj, site, init, help_, cbs)
    out = sorted(found.values(), key=lambda r: r.name)
    setattr(img, key, out)
    return out


def registration_by_object(img):
    """object rva -> Registration, for convars and concommands."""
    out = {}
    for kind in ("convar", "concmd"):
        for r in registrations(img, kind):
            out[r.obj] = r
    return out


# ---------------------------------------------------------------------------------------------- interfaces

def interface_list_head(img):
    """rva of s_pInterfaceRegs, the list head CreateInterface walks (empty on disk, filled in a dump), or None."""
    ex = img.exports().get("CreateInterface")
    if ex is None:
        return None
    head, start = None, ex
    for _ in range(2):  # CreateInterface may be a thunk
        for ins in img.md.disasm(img.mem[start:start + 0x60], start):
            if ins.mnemonic == "jmp" and img.target_of(ins) is not None and img.is_code(img.target_of(ins)):
                start = img.target_of(ins)
                break
            if ins.mnemonic == "mov" and len(ins.operands) == 2 and ins.operands[1].type == 3 and \
                    img.target_of(ins) is not None and img.section_of(img.target_of(ins)) == ".data":
                head = img.target_of(ins)
                break
        if head is not None:
            break
    return head


def interfaces(img):
    """CreateInterface registrations. CreateInterface walks s_pInterfaceRegs (InterfaceReg = {create fn,
    name, next}); static initializers do `lea r8,[name]; lea rdx,[factory]; lea rcx,[InterfaceReg]` and
    call/jmp the InterfaceReg constructor, the code that stores into s_pInterfaceRegs."""
    cached = getattr(img, "_interfaces", None)
    if cached is not None:
        return cached
    head = interface_list_head(img)
    if head is None:
        img._interfaces = []
        return []
    ctors = set()
    for r in img.xrefs(head):
        ins = img.insn_at(r)
        if not ins or ins.mnemonic != "mov" or ins.operands[0].type != 3:  # a store into the list head
            continue
        best = None
        for a in range(r, r - 0x60, -1):
            n = sum(1 for x in img.xrefs(a) if _branch_to(img, x, a))
            if n and (best is None or n > best[0]):
                best = (n, a)
        if best:
            ctors.add(best[1])
    out = []
    for c in ctors:
        for site in img.xrefs(c):
            if not _branch_to(img, site, c):
                continue
            leas = [x for x in img._leas_near(site, before=0x40, after=0) if x[0] < site]
            pick = lambda reg, ok: max(((a, t) for a, r, t in leas if r == reg and ok(t)), default=(None, None))[1]  # noqa: E731
            name = pick("r8", lambda t: img.section_of(t) == ".rdata")
            fac = pick("rdx", img.is_code)
            reg = pick("rcx", lambda t: img.section_of(t) == ".data")
            if name is None:
                continue
            inst, cls = _factory_instance(img, fac) if fac is not None else (None, None)
            out.append(Interface(img.cstr(name), fac, reg, site, inst, cls))
    img._interfaces = sorted(out, key=lambda i: i.name)
    return img._interfaces


def _factory_instance(img, fac):
    """A factory that returns a static instance: `lea rax,[X]; ret` -> X. Its class from the instance's
    static vtable, or from the vtable its constructor stores (one call deep)."""
    insns = list(img.md.disasm(img.mem[fac:fac + 0x20], fac, 4))
    inst = None
    for i, ins in enumerate(insns):
        if ins.mnemonic == "lea" and ins.op_str.startswith("rax") and img.target_of(ins) is not None:
            inst = img.target_of(ins)
            break
        if ins.mnemonic == "ret":
            break
    if inst is None:
        return None, None
    vt = img.ptr(inst)
    if vt is not None and img.vtable_at(vt):
        return inst, img.demangle_type(img.vtable_at(vt).cls)
    for r in img.xrefs(inst):
        ins = img.insn_at(r)
        if not ins or ins.mnemonic != "lea" or not ins.op_str.startswith("rcx"):
            continue
        for nxt in img.md.disasm(img.mem[r:r + 0x18], r, 4):
            if nxt.mnemonic == "call" and img.target_of(nxt) is not None and img.is_code(img.target_of(nxt)):
                ctor = img.target_of(nxt)
                for cins in img.md.disasm(img.mem[ctor:ctor + 0x200], ctor, 60):
                    t = img.target_of(cins)
                    if cins.mnemonic == "lea" and t is not None and img.vtable_at(t):
                        return inst, img.demangle_type(img.vtable_at(t).cls) + " (from its constructor)"
                break
    return inst, None
