# scripts

> The six Python files that make up source2-re: one CLI and five libraries.

Every library is usable on its own: `import s2pe` from a script, work against an `Image`, and you have the
same answers the CLI gives.

```
s2re.py        CLI: argparse front end, text / JSON output, header line, `--memdump` plumbing
s2pe.py        PE loading, disassembly, xref index, RTTI vtables, signatures, protobuf, dump layout
s2source2.py   Source 2 specifics: schema classes and enums, convars, concommands, CreateInterface
s2port.py      carry an address from an old build of a module to the current one
s2export.py    name tables for IDA / Ghidra / Binary Ninja / JSON
s2dump.py      a module dumped from a running game vs. the DLL on disk
```

Nothing writes to the game or touches a running process. Everything reads the DLL on disk, or a dump the user
made themselves. The disk file is never modified either.

## How they fit together

```
s2re.py ──▶ s2pe.Image(path)                 open and map a DLL (or a dump)
            s2pe.Image.index()                xref index (first query that needs it; cached)
            s2pe.Image.vtables()              RTTI vtable map (cached)
         ──▶ s2source2.schema_classes(img)    Source 2 reads layered on the Image
            s2source2.registrations(img, "cvar"|"concmd")
            s2source2.interfaces(img)
         ──▶ s2port.Porter(old, new).port()   cross-build matching
         ──▶ s2export.collect(img); render()  disassembler script
         ──▶ s2dump.diff(dump, disk)          dump vs. DLL of the same build
```

Only `s2pe` touches capstone and the file bytes. Everything above it works in RVAs returned by `s2pe`.

## s2pe — the Image

`Image(path)` maps the DLL the way the loader would: each section placed at its RVA, no relocations applied,
so a pointer stored in `.data` or `.rdata` is a VA against the preferred ImageBase (`0x180000000` for every
Source 2 DLL seen so far).

What an `Image` gives you:

| area | methods |
|---|---|
| PE / sections | `section`, `section_of`, `is_code`, `u32`, `u64`, `ptr`, `cstr`, `find_cstr`, `find_cstr_partial`, `find_wstr`, `exports`, `imports`, `relocations` |
| functions | `func_of`, `function_start`, `function_ranges`, `primary`, `chunks_of`, `dis_func`, `callees` |
| xrefs | `index` (build or load), `xrefs`, `stored_at` |
| disassembly | `insns`, `insn_at`, `dis`, `fmt`, `describe` |
| RTTI | `vtables`, `vtable_at`, `vtable_slot`, `vtable_slots`, `base_classes`, `demangle_type` |
| field use | `field_map` |
| signatures | `scan`, `make_sig`, `make_sig_target`, `operand_field`, `rel` |
| Source 2 | `schema_class`, `convar_by_name`, `convar_by_object`, `object_readers`, `protos`, `proto_descriptor` |
| dumps | `open_args` (how it was opened), the `dump=True`, `layout=`, `base=`, `headers_from=` kwargs on the constructor |

The xref index is built in parallel worker processes across `.pdata` functions plus the gaps between them
(leaf functions) and pickled per build, keyed by file size + mtime. First build takes about 5 s for CS2
`client.dll`, 9 s for Deadlock's, on `min(cores, 8)` workers. Later queries read it in instantly. Cache lives
in `cache_dir()`: `%LOCALAPPDATA%\s2re-cache` on Windows, `~/s2re-cache` elsewhere.

`resolve_module(game, module)` reads `libraryfolders.vdf`, finds the Steam library that holds the game and
returns `game\<mod>\bin\win64\<module>.dll` (or `game\bin\win64\<module>.dll`).

## s2source2 — Source 2 reads

Everything above the raw PE layer:

```python
import s2pe, s2source2
img = s2pe.Image(s2pe.resolve_module("cs2", "client"))

for c in s2source2.schema_classes(img):          # SchemaClass(info, name, size, align, fields, bases, ...)
    ...
for e in s2source2.schema_enums(img):            # SchemaEnum(info, name, size, values)
    ...
for r in s2source2.registrations(img, "cvar"):   # Registration(name, obj, site, init, help, callbacks)
    ...
for i in s2source2.interfaces(img):              # Interface(name, factory, reg, site, instance, instance_class)
    ...

offset, decl_class = s2source2.find_field(img, "C_CSPlayerPawn", "m_iHealth")
chain = s2source2.base_chain(img, "C_CSPlayerPawn")
```

`dump_schema(img, fmt="text"|"cpp"|"json")` renders every class and enum at once. `registration_by_object(img)`
indexes convar and command objects by their address, for `cvarobj`.

The byte layouts these walkers depend on (the `ff ff ff ff` marker at field +0x2a for class infos, `-1` at
+0x38 for enum infos, how the registrars are found, interface list walking) live in
[references/layouts.md](../references/layouts.md).

## s2port — across builds

`Porter(old_img, new_img).port(rva)` returns a `PortResult(kind, old_function, candidates, mapped, notes)`.
Functions are matched in two passes:

1. **Anchors** that survive updates vote for candidates: same vtable class and slot, unique strings
   referenced, convars read, exact or loose signatures, ported callers calling at the same position, and
   ported callees' callers.
2. **Similarity** then scores each candidate against the old function: instruction mnemonic sequence (×3),
   strings (×2), size, imports, constants, call count. Final score is `anchors + 10 × similarity`; the margin
   over the runner-up is the reported confidence (`high`, `medium`, `low`).

Data addresses map by name where they have one (strings, vtables, convar / concommand objects, schema class
infos), otherwise through the ported instructions that reference them. See the module docstring for the exact
anchor weights.

## s2export — disassembler scripts

`collect(img)` walks every source of names s2re can derive offline and returns a list of `Symbol(rva, name,
kind, is_func, comment)`. Kinds, in priority order when two names fight for one address:

```
scope     a function whose only profiler-scope string ("Class::Method") is unique in the module
concmd    ConCommand objects and their callbacks (`concmd::name::callback`)
cvar      ConVar objects
iface     CreateInterface factories, InterfaceReg objects, static instances
schema    schema class infos, enum infos
vtable    RTTI vtables (primary + secondary ones as `Class::vftable@0x10`)
vfunc     virtual functions named after the most-base class holding them; generic stubs skipped
```

`render(img, syms, tool, build_line)` emits a script for `ida`, `ghidra`, `binja`, or `json`. Addresses are
RVAs, meant to be added to the database's image base.

## s2dump — dumps vs. disk

`diff(dump, disk)` relocates the disk image to the dump's base and returns every qword-aligned range that
still differs, classified as `code`, `vtable`, `rdata` or `data`, and labeled by owner where s2re can name
one (convar / concommand object, schema class or enum info, InterfaceReg node, vtable, export).

Open a dump with `s2pe.Image(path, dump=True)`. The layout (`mapped` vs. `file`) is detected from where
`.pdata` reads as valid; the runtime base from the PE header, or from the relocations when the header is
wrong or erased (`headers_from=` points at the disk DLL for its `.reloc`). `check_same_build(dump, disk)`
raises `BuildMismatch` if the two aren't the same build; a dump against another build never gives sane
offsets.

`interface_list(img)` walks the live `s_pInterfaceRegs` list from its head — empty on disk, populated in a
dump.

## s2re — the CLI

`s2re.py` is thin: it parses arguments, opens an `Image` (dump or disk), calls into the libraries, and prints
the result. Every library function is reachable from the CLI, and every CLI command has `--json` output
(uncapped, wrapped as `{module, build, result}`). The library calls stay the same whether the Image is a disk
DLL or a dump.

Global options (`-g`, `-m`, `--json`, `-o`, `--limit`, `-q`, `--memdump`, `--base`, `--layout`,
`--headers-from`) may come before or after the command name.

## Caching and snapshots

- **Cache** (`$S2RE_CACHE`, default `%LOCALAPPDATA%\s2re-cache` or `~/s2re-cache`): the xref index and vtable
  map for each DLL build. Keyed by file size + mtime, so a game update makes a new cache automatically.
- **Snapshots** (inside the cache, `snapshots/`): a copy of the current and previous build per module, taken
  the first time s2re indexes a build. This is what `port` reads from after the next update, because Steam
  overwrites the DLL. `$S2RE_NO_SNAPSHOT=1` turns it off.

## Dependencies

Python 3.9+ and [capstone](https://www.capstone-engine.org/) (tested on 5.0.7). Nothing else. `pip install
capstone`.
