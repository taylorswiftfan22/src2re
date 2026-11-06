"""s2dump - what a module dumped from a running process holds that the DLL on disk doesn't.

diff(dump, disk) relocates the disk image to the dump's base (so rebased pointers are not reported) and returns
every qword-aligned range that still differs, classified:
  code     bytes changed in an executable section (patches, inline hooks): both disassemblies, and branches
           that leave the image flagged
  vtable   a vtable slot that points somewhere else than the shipped function (VMT hooks)
  rdata    other changes in read-only data
  data     values written at runtime (.data and other writable sections), named where s2re knows the owner:
           convar / concommand objects, schema class / enum infos, InterfaceReg nodes, vtables, exports
"""
import struct
from collections import namedtuple

import s2source2

Change = namedtuple("Change", "kind section rva size disk dump owner notes")


class BuildMismatch(ValueError):
    pass


def check_same_build(dump, disk):
    if (dump.timestamp, dump.size) != (disk.timestamp, disk.size):
        raise BuildMismatch(f"the dump is from another build than {disk.path}: PE timestamp {dump.timestamp:#x} vs "
                            f"{disk.timestamp:#x}, SizeOfImage {dump.size:#x} vs {disk.size:#x}")


def relocated(disk, base):
    """disk.mem with its DIR64 pointers rebased to `base`: what an untouched module would hold in memory."""
    mem = bytearray(disk.mem)
    delta = base - disk.base
    if delta:
        for s in disk.relocations():
            v = struct.unpack_from("<Q", mem, s)[0]
            if v:
                struct.pack_into("<Q", mem, s, (v + delta) & 0xFFFFFFFFFFFFFFFF)
    return mem


def _ranges(a, b, lo, hi):
    """[(start, end)] of differing qword-aligned runs between two buffers inside [lo, hi)."""
    out = []
    page = 0x1000
    lo -= lo % 8
    pos = lo
    while pos < hi:
        end = min(pos + page, hi)
        if a[pos:end] != b[pos:end]:
            n = (end - pos) // 8
            qa = struct.unpack_from(f"<{n}Q", a, pos)
            qb = struct.unpack_from(f"<{n}Q", b, pos)
            for i in range(n):
                if qa[i] != qb[i]:
                    r = pos + 8 * i
                    if out and out[-1][1] == r:
                        out[-1][1] = r + 8
                    else:
                        out.append([r, r + 8])
        pos = end
    return [tuple(r) for r in out]


def _owners(disk):
    """rva -> (name, start, size) for the static objects s2re can name, to label runtime writes."""
    own = {}
    for r in s2source2.registration_by_object(disk).values():
        own[r.obj] = (f"{'concmd' if r.callbacks else 'cvar'} {r.name}", r.obj, 0x10)
    for c in s2source2.schema_classes(disk):
        own[c.info] = (f"schema class {c.name}", c.info, 0x40)
    for e in s2source2.schema_enums(disk):
        own[e.info] = (f"schema enum {e.name}", e.info, 0x40)
    for i in s2source2.interfaces(disk):
        if i.reg is not None:
            own[i.reg] = (f"InterfaceReg {i.name}", i.reg, 0x18)
        if i.instance is not None and i.instance not in own:
            own[i.instance] = (f"{(i.instance_class or i.name).split(' ')[0]} instance", i.instance, 0x8)
    head = s2source2.interface_list_head(disk)
    if head is not None:
        own[head] = ("s_pInterfaceRegs (CreateInterface list head)", head, 0x8)
    for name, rva in disk.exports().items():
        own.setdefault(rva, (f"export {name}", rva, 0x8))
    return own


def _owner_of(owners, starts, rva):
    import bisect
    i = bisect.bisect_right(starts, rva) - 1
    if i >= 0:
        name, st, size = owners[starts[i]]
        if st <= rva < st + size:
            return name + (f"+{rva - st:#x}" if rva != st else "")
    return None


def _first_diff(a, b, lo, hi):
    for i in range(lo, hi):
        if a[i] != b[i]:
            return i
    return lo


def _code_change(dump, disk, exp, lo, hi):
    first = _first_diff(exp, dump.mem, lo, hi)
    ins = disk.insn_at(first)
    start = ins.address if ins and ins.address <= first else first
    end = max(hi, start + 1)
    disk_insns = list(disk.md.disasm(bytes(exp[start:end + 16]), start))
    dump_insns = list(dump.md.disasm(dump.mem[start:end + 16], start))
    take = lambda insns: [i for i in insns if i.address < end] or insns[:1]  # noqa: E731
    notes = []
    for i in take(dump_insns):
        t = dump.target_of(i)
        if t is not None and i.mnemonic in ("jmp", "call") and not (0 <= t < dump.size):
            notes.append(f"{i.mnemonic} at {i.address:#x} leaves the image -> VA {dump.base + t:#x}")
    fmt = lambda insns: [f"{i.address:#x}: {i.mnemonic} {i.op_str}".rstrip() for i in take(insns)]  # noqa: E731
    fn = disk.function_start(start)
    return Change("code", disk.section_of(start), start, end - start, fmt(disk_insns), fmt(dump_insns),
                  f"fn {fn:#x}" if fn is not None else None, notes)


def diff(dump, disk, sections=None):
    """Changes between a dump and the disk DLL of the same build, in section order."""
    check_same_build(dump, disk)
    exp = relocated(disk, dump.base)
    owners = _owners(disk)
    starts = sorted(owners)
    out = []
    for s in disk.sections:
        if sections and s.name not in sections:
            continue
        lo, hi = s.rva, min(s.rva + s.size, disk.size)
        for a, b in _ranges(exp, dump.mem, lo, hi):
            if s.flags & 0x20000000:  # executable
                out.append(_code_change(dump, disk, exp, a, b))
                continue
            writable = bool(s.flags & 0x80000000)
            pos = a
            while pos < b:
                d0 = struct.unpack_from("<Q", exp, pos)[0]
                d1 = struct.unpack_from("<Q", dump.mem, pos)[0]
                vs = disk.vtable_slot(pos)
                if vs and not writable:
                    v, slot = vs
                    shipped = d0 - dump.base
                    now = d1 - dump.base
                    where = f"{now:#x}" if 0 <= now < dump.size else f"VA {d1:#x} (outside the image)"
                    out.append(Change("vtable", s.name, pos, 8, f"{shipped:#x}", where,
                                      f"{disk.demangle_type(v.cls)} vtable slot [{slot}]", []))
                    pos += 8
                    continue
                run = pos + 8
                while run < b and not (disk.vtable_slot(run) and not writable):
                    run += 8
                o = _owner_of(owners, starts, pos)
                vals = struct.unpack_from(f"<{(run - pos) // 8}Q", dump.mem, pos)
                notes = []
                for k, v in enumerate(vals[:4]):
                    r = v - dump.base
                    if v and 0 <= r < dump.size:
                        notes.append(f"+{8 * k:#x} -> {r:#x} {disk.describe(r) or ''}".rstrip())
                out.append(Change("data" if writable else "rdata", s.name, pos, run - pos,
                                  bytes(exp[pos:run]).hex(), bytes(dump.mem[pos:run]).hex(), o, notes))
                pos = run
    return out


def interface_list(img):
    """For a dump: walk the runtime s_pInterfaceRegs list. [(InterfaceReg rva, name, create fn rva)] or [] when
    the head is empty (a DLL on disk) or unreadable."""
    head = s2source2.interface_list_head(img)
    if head is None:
        return []
    out, seen = [], set()
    node = img.ptr(head)
    while node is not None and node not in seen and len(out) < 4096:
        seen.add(node)
        name = img.ptr(node + 8)
        out.append((node, img.cstr(name) if name is not None else None, img.ptr(node)))
        node = img.ptr(node + 0x10)
    return out
