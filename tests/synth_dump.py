"""Synthetic module dumps, built from a DLL on disk: the loader's view of the module (sections at their RVAs,
DIR64 pointers rebased) plus whatever runtime writes a test applies. Used because no real dump is checked in."""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
import s2dump  # noqa: E402


def _opt(mem):
    return struct.unpack_from("<I", mem, 0x3C)[0] + 24


def mapped(disk, base, header="updated"):
    """bytearray of SizeOfImage bytes. header: 'updated' (ImageBase rewritten to the real base, as the loader
    does), 'default' (left as shipped), 'erased' (zeroed, as anti-dump code does)."""
    mem = s2dump.relocated(disk, base)
    opt = _opt(mem)
    if header == "updated":
        struct.pack_into("<Q", mem, opt + 24, base)
    elif header == "erased":
        n = struct.unpack_from("<I", mem, opt + 60)[0]
        mem[:n] = bytes(n)
    return mem


def file_layout(mem):
    """A rebuilt dump, as dump-fixing tools write one: headers, then every section's full virtual size packed at
    new FileAlignment-aligned raw offsets (so raw offset != RVA), section table updated to match."""
    hdrbuf = bytearray(mem[:struct.unpack_from("<I", mem, _opt(mem) + 60)[0]])
    opt = _opt(hdrbuf)
    nt = opt - 24
    nsec = struct.unpack_from("<H", hdrbuf, nt + 6)[0]
    optsz = struct.unpack_from("<H", hdrbuf, nt + 20)[0]
    falign = struct.unpack_from("<I", hdrbuf, opt + 36)[0] or 0x200
    up = lambda x: (x + falign - 1) // falign * falign  # noqa: E731
    out = bytearray(hdrbuf)
    out += bytes(up(len(out)) - len(out))
    for i in range(nsec):
        o = opt + optsz + 40 * i
        vsize, va = struct.unpack_from("<II", hdrbuf, o + 8)
        rptr, rsize = len(out), up(vsize)
        struct.pack_into("<II", out, o + 16, rsize, rptr)
        out += mem[va:va + vsize] + bytes(rsize - vsize)
    return out


def put_u64(mem, rva, value):
    struct.pack_into("<Q", mem, rva, value & 0xFFFFFFFFFFFFFFFF)


def inline_hook(mem, rva, base, target_va):
    """`jmp rel32` at rva to an absolute VA (must be within +-2 GB)."""
    rel = target_va - (base + rva + 5)
    mem[rva:rva + 5] = b"\xE9" + struct.pack("<i", rel)


def write(path, data):
    with open(path, "wb") as fh:
        fh.write(data)
    return path
