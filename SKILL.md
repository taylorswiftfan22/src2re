---
name: source2-re
description: Offline static reverse engineering of Source 2 game DLLs (CS2 client.dll / server.dll / engine2.dll, Deadlock client.dll, any game\bin\win64 module) straight from the files on disk, or from a module dump the user made of the running game (runtime base detected; diff against the DLL shows patched code, redirected vtables and runtime-written globals), with a capstone CLI. Finds functions from strings, convars and console commands; cross-references, callers and callees; RTTI vtables and slot indices; every schema class, field offset (inherited too) and enum, as a C++ header or JSON; CreateInterface factories; struct offsets a function uses; embedded protobuf messages. Checks whole signature lists (from a list or straight from source code), generates signatures in IDA / x64dbg / code+mask formats, carries addresses from the previous game build to the current one, and exports names to IDA / Ghidra / Binary Ninja. Use when repairing signatures or offsets after a game update, locating an engine function to hook, mapping a virtual's vtable index, rebuilding a class layout, reading how the game uses a convar or schema field, or decoding usercmd protos, for CS2 or Deadlock, without attaching to the running game.
---

# Source 2 offline RE

`scripts/s2re.py` maps a game DLL the way the loader would and answers static questions about it. The libraries
behind it can be imported for one-off loops: `s2pe` (PE, disassembly, xrefs, RTTI, signatures), `s2source2` (schema,
convars, console commands, interfaces), `s2port` (cross-build matching), `s2export` (disassembler scripts). Needs
Python 3.9+ and `capstone` (`pip install capstone`).

Run it from this skill's base directory, or pass the full path to `scripts/s2re.py`:

```bash
python scripts/s2re.py -g cs2 info
python scripts/s2re.py -g deadlock -m server cvar citadel_player_move_speed_scale
```

- `-g cs2|deadlock|dota2|hlalyx`: always pass it (default cs2, or `$S2RE_GAME`; dota2 / hlalyx are untested folder
  guesses; `$S2RE_GAMES="name=Steam folder:mod;..."` adds more). `-m` = module (`client` default, `server`, `engine2`,
  `schemasystem`, ...: looked up in `game\<mod>\bin\win64`, then `game\bin\win64`) or a full DLL path.
- Global options work before or after the command: `--json` (uncapped, wrapped as `{module, build, result}`),
  `-o FILE`, `--limit N` (rows per list in text output, default 50, 0 = all), `-q` (no header line).
- Steam libraries come from `libraryfolders.vdf`; `$S2RE_STEAM` adds one.
- The first query that needs cross-references builds two caches per DLL build: the xref index and the vtable map,
  about 5 s for CS2 client.dll and 9 s for Deadlock's (parallel; `$S2RE_JOBS` workers, default min(cores, 8)). They
  are keyed by file size + mtime and live in `%LOCALAPPDATA%\s2re-cache` (`$S2RE_CACHE`). A game update rebuilds them.
- The same step copies a build it hasn't seen into `s2re-cache\snapshots` (current + previous build per module;
  `$S2RE_NO_SNAPSHOT=1` turns it off). That copy is what `port` reads after the next update, because Steam
  overwrites the DLL.
- Every address in and out is an **RVA**. A VA from IDA/x64dbg (>= ImageBase 0x180000000) is accepted and converted.
  Negative numbers go after `--`, with every option before it (`disp --in <fn> -- -0x10`).
- Text output starts with `# <game> <dll>: <size> bytes, modified <date>`. Copy that line next to any RVA you
  record: RVAs are only valid for that build.
- `--memdump FILE` runs any command on a module dumped from the running game instead of the DLL (see
  "Module dumps"). `--base`, `--layout mapped|file` and `--headers-from DLL` override what is detected.

## Commands

| command | answers |
|---|---|
| `info` | path, size, mtime, sections, .pdata / export / import counts, cache state, saved snapshots |
| `str TEXT... [--partial] [--wide]` | where a C (or UTF-16) string lives and the code that loads it; pointer tables one level deep when nothing loads it directly |
| `xrefs RVA...` | instructions referencing RVA (rip-relative operands, direct branches, jump tables) and where its VA is stored as a pointer |
| `func RVA...` | whole function containing RVA, split chunks stitched together, annotated (strings, floats, imports, vtables) |
| `range RVA [N]` | N instructions from RVA (start on a real instruction boundary) |
| `callers RVA... [--depth N]` | caller tree; vtable slots and other stored pointers shown where direct calls stop |
| `callees RVA...` | direct calls, tail jumps and imports out of a function |
| `rtti CLASS...` / `rtti --grep TEXT` | vtable(s), COL, sub-object offset, base classes, every slot |
| `vtwho RVA...` | which class vtables hold a function, at which slot index |
| `fields RVA [--reg rcx] [--schema CLASS]` | struct offsets read / written / lea'd through a register, with sizes; `--schema` names them from the class and its bases |
| `disp DISP... --in RVA... \| --range LO HI [--imm]` | instructions whose memory operand (not rsp) uses that displacement; `--imm` adds immediates |
| `schema CLASS [FIELD...] [--flat]` | sizeof, bases, declared fields with metadata; FIELD resolves inherited fields; `--flat` lists everything at absolute offsets |
| `schema --list [FILTER]` / `schema --dump --format text\|cpp\|json` | all classes / every class and enum as text, a C++ header or JSON |
| `enum NAME...` / `enum --list [FILTER]` | schema enums and their values |
| `iface [FILTER]` | CreateInterface version → factory, InterfaceReg, static instance and its class |
| `cvar NAME...` / `cvar --list [FILTER]` | ConVar object, initializer, help text, every reference outside the initializer |
| `cvarobj RVA...` | object address → ConVar / ConCommand name and references |
| `concmd NAME...` / `concmd --list [FILTER]` | ConCommand object, **callback (the handler)**, help, references |
| `proto` / `proto NAME.proto [--message M]` | embedded protobuf descriptors as .proto text |
| `sig PATTERN... [--rel OFF LEN] [--mask M] [--region image\|code]` | hits (whole image by default), the function of each, rel32 resolved |
| `sig --file FILE [-v]` | checks a list: UNIQUE / MISSING / AMBIGUOUS per signature plus a summary |
| `sigmake RVA... [--loose] [--max N] [--format F]` | shortest unique pattern at RVA and the `--rel` of its first reference |
| `sigmake RVA --target` | patterns that *lead to* RVA (a global, string or function) through the instructions referencing it, each with its `--rel` |
| `sigconv PATTERN [--mask M]` | one pattern in IDA, x64dbg, compact and `\x48\x8B` + mask forms |
| `port RVA... [--old DLL] [--top N]` | an address from the previous build located in the current one, with confidence and evidence |
| `snapshots` / `snapshot` | saved older builds / save the current one now |
| `export --tool ida\|ghidra\|binja\|json [--only KINDS] -o FILE` | a script that names vtables, vfuncs, convars, concommands, interfaces, schema infos and scope-named functions |
| `--memdump F dumpdiff [--disk DLL] [--kind K] [--all-data]` | a dump against its DLL: patched code (both disassemblies, jumps out of the image flagged), redirected vtable slots, values written at runtime with their owner |
| `hex RVA [N] [--qwords]` | hex dump; `--qwords` decodes pointers (strings, functions, vtables) |
| `exports [FILTER]` / `imports [FILTER]` | export table; IAT slots with reference counts (`xrefs <slot>` lists the callers) |

Pattern input accepts IDA (`48 8B ? ?`), x64dbg (`48 8B ?? ??`), compact (`488B????`) or code style
(`"\x48\x8B\x00\x00" --mask xx??`). An unquoted IDA pattern split by the shell is joined back together.

## Recipes

**Function from a string, log line or profiler scope.** `str "DoMovement::Subtick" --partial` lists the full
string (`CPlayer_MovementServices::DoMovement::Subtick`) and the instruction that loads it. The `[fn ...]` tag is the
function; `func` it. Use `--partial` when the exact string doesn't match: many scopes carry a class prefix.

**What reads a convar.** `cvar sv_jump_spam_penalty_time` gives the object and every reference outside its
initializer. Tiny 32-byte functions that reference the object twice are teardown, not readers. Then `func` each
reader. `cvar --list jump` searches names and help text.

**Console command handler.** `concmd NAME` prints the callback: that function runs when the command is typed.
`concmd --list FILTER` to find the name.

**Interfaces.** `iface` lists what `CreateInterface` hands out. A factory of the form `lea rax,[X]; ret` gives the
static instance X; its class comes from its vtable or its constructor. In engine2 / client this is the way to the
CSource2Client, CEngineClient, ... singletons and their vtables (`rtti <class>`).

**Virtual function index for a hook.** `vtwho <fn>` prints `Class vtable slot [i]`: `i` is the VMT index.
`rtti Class --limit 0` lists every slot. `callers` reports vtable slots where direct callers stop.

**After a game update: repair signatures and addresses.**
1. `sig --file <your signatures.cpp>` (any source file: every quoted IDA pattern is checked, named by a quoted
   identifier on its line or the identifier before it; a quoted `"x.dll"` on the line restricts it to that module
   and the summary says how many were skipped for other modules, so rerun with `-m` for each) or a plain list
   (`name = PATTERN [rel=OFF,LEN]`). Note which are MISSING / AMBIGUOUS. A scanner that takes the first hit may
   still work with an AMBIGUOUS one, but only by luck of order.
2. For each broken one, get its address in the **old** build: `-m <snapshot path> sig "<pattern>"` (`snapshots`
   prints the paths) or the RVA you recorded.
3. `port <old rva>` finds it in the current build. `high` confidence = anchors agree with a clear margin; `medium` /
   `low` = read the evidence and confirm with `func` on both builds (`-m <snapshot> func <old>`).
4. `sigmake <new rva>` for the new pattern (`--loose` when struct offsets or constants churn). For a global or a
   function reached through calls, `sigmake <rva> --target` gives patterns at the referencing instructions with the
   `--rel` to resolve them.
5. Re-run step 1.
`port` needs the old DLL: it exists only if s2re indexed that build before Steam replaced it (or pass `--old PATH`).

**Schema offsets.** `schema C_BaseEntity m_iHealth m_iTeamNum` (inherited fields resolve and say where they are
declared). `schema C_CSPlayerPawn --flat` for the whole layout, `schema --dump --format cpp -o client_schema.hpp`
for every class and enum in the module. Client classes live in client.dll, server classes in server.dll.

**Rebuilding a class layout.** `fields <fn> --schema <Class>` lists each offset the function touches through
`rcx` (`this`), with access size and kind, named where the schema knows the field (`~m_x+0x4` = inside a field).
Non-schema classes: run it over several vfuncs from `rtti <Class>` and combine; `--reg` for other registers.
`callees <fn>` shows what it calls. One access does not establish a field: look for agreement across functions.

**Who uses a field offset.** `disp 0x7b0 --in <fn>...` checks functions; `--range LO HI` checks every .pdata
function starting in a region. It also finds virtual calls by slot: slot 32 = `disp 0x100`.

**Names in a disassembler.** `export --tool ida -o names.py`, then File > Script file in IDA (Ghidra: Script
Manager; Binary Ninja: Python console). `--only scope,cvar,vtable` limits the kinds. Addresses are RVAs added to the
database's image base.

**Module dumps.** A dump is the module's memory, SizeOfImage bytes read from its base while the game runs (the
user makes it; never attach to the game yourself). Raw memory images and rebuilt PE files both work; the runtime
base is read from the header or, if the header is wrong or erased, recovered from the relocations (erased headers
need `--headers-from client`). Then:
- every command works, and runtime VAs from a debugger are accepted directly (`func 0x7ffb131c0d40`);
- `dumpdiff` (with `-m` / `--disk` naming the DLL of the *same build*) lists patched code, redirected vtable slots
  and what the game wrote into the module's globals, named by owner (convar objects, schema infos, InterfaceReg
  nodes, singleton instances);
- `iface` also walks the live `s_pInterfaceRegs` list; `cvar` / `concmd` / `cvarobj` print the object's live
  qwords (`+0x8` = the convar's data pointer).
A dump still does not contain the heap: convar values and schema field types live outside the module. Only
synthetic dumps (built from the disk DLLs) have been tested so far; if a real dump disagrees with the disk DLL on
schema counts, the game fills more of the class infos than `+0x00` (see layouts.md).

**Protobuf messages.** `proto` lists the descriptors (CS2: `usercmd.proto`, `cs_usercmd.proto`,
`networkbasetypes.proto`, ...). `proto usercmd.proto --message CSubtickMoveStep` prints a single message.

**Custom loops.**
```python
import sys; sys.path.insert(0, r"<skill base directory>/scripts")
import s2pe, s2source2
img = s2pe.Image(s2pe.resolve_module("cs2", "client"))
for c in s2source2.schema_classes(img):          # SchemaClass(info, name, size, align, fields, bases, ...)
    if c.name.endswith("Pawn"):
        print(c.name, hex(c.size), [(f.name, hex(f.offset)) for f in c.fields][:3])
```
`Image` also has `xrefs`, `function_start`, `insns`, `callees`, `field_map`, `vtables`, `vtable_slot`, `scan`,
`make_sig`, `make_sig_target`, `stored_at`, `describe`, `protos`, `relocations`; `s2source2` has `find_field`,
`base_chain`, `schema_enums`, `registrations`, `interfaces`; `s2port.Porter(old_img, new_img).port(rva)`;
`s2pe.Image(path, dump=True)` loads a dump and `s2dump.diff(dump_img, disk_img)` compares it (see the docstrings).

## Limits

- **What xrefs can see.** Rip-relative operands, direct branches and MSVC jump tables. Virtual calls
  (`call [rax+0x100]`) and calls through registers never appear: use `vtwho` / `rtti`, `disp` with the slot offset,
  `xrefs` (stored pointers) or `hex --qwords` on tables.
- **Leaf functions.** No `.pdata` entry, shown as `no .pdata (leaf/gap)`. The index still covers them (gaps between
  functions are swept). `func` on a leaf disassembles up to the first `ret`.
- **`fields` is linear.** It follows register copies and drops a register when it is overwritten or after a call,
  ignoring branches. Offsets reached through another pointer are not attributed.
- **`port` is evidence, not proof.** Check `medium` / `low` results by reading both functions. Data addresses with no
  name (not a string, vtable, convar or schema info) are ported through the instructions that reference them.
- **Disk image by default.** You see the initial contents of the DLL, never anything written at runtime. A
  `--memdump` adds what the game wrote into the module itself (live lists, pointers to singletons, patches), but
  never heap objects: convar values and CSchemaType data (field types) stay invisible. For those, add a diagnostic
  to the project and have the user test in game. Don't guess.
- **RTTI names.** Templates are left mangled (`?$CGameAppSystem@VISource2Client@@$0A@`).
- **Evidence.** Keep confirmed (seen in the disassembly) apart from inferred, and say which one you have. One
  matching instruction does not establish a layout.

Binary layouts these commands rely on, with how each was verified, plus anchors already found on specific builds:
[references/layouts.md](references/layouts.md).
