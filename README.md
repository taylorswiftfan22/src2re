# source2-re

**Find your way around the code of Counter-Strike 2 and Deadlock, straight from the game files.**

source2-re reads the game's DLLs (the files that hold the game's code) and answers questions about them: where a
function is, what it does with a console variable, where a player's health is stored, why your signature stopped
working after an update. These are the questions people normally open a disassembler like IDA or Ghidra for, and
here each one is a single command.

It runs on its own from the command line, or as a [Claude Code](https://claude.com/claude-code) skill, so you can
ask Claude about the game's code in plain words and it does the digging.

## What it can do

- **Find code from things you can see in game.** Give it a message the game prints, a console variable such as
  `sv_cheats`, or a console command, and it shows you the code that uses it. For console commands it finds the
  function that runs when you type the command.
- **Look up where game data lives.** Ask where a field like a player's health is stored and get its exact offset
  for the current version, inherited fields included. Or export every class at once (about 1,000 in CS2's client,
  about 4,000 in Deadlock's) as a C++ header or JSON.
- **Follow the code.** See what calls a function, what it calls, which class it belongs to, and which fields of an
  object it reads and writes.
- **Keep your project working after a game update.**
  - Check every signature in your project in one command. It reads them straight out of your source code.
  - Find where a function moved to in the new version.
  - Generate fresh signatures in IDA, x64dbg or `\x48\x8B` + mask style.
- **Name things in your disassembler.** Generate a script that labels around 48,000 functions and objects in IDA,
  Ghidra or Binary Ninja.
- **Read the game's network messages.** Print the message definitions built into the game (player input and the
  like) as readable `.proto` files.
- **Inspect a memory dump.** Load a copy of a game module that you saved from the running game, and see what
  changed compared with the file on disk: patched code, redirected function tables, values the game filled in.

**What it doesn't do:** it never attaches to, injects into or reads the memory of a running game, and it never
changes any file. It works from the files you already have on disk (and dumps, if you make one yourself), so
anything that only exists while you play, like a convar's current value, isn't visible to it.

Tested on Counter-Strike 2 and Deadlock on Windows. Dota 2 and Half-Life: Alyx have presets that haven't been
tried.

## A quick look

Where is health stored on an entity in Deadlock?

```text
$ python scripts/s2re.py -g deadlock schema C_BaseEntity m_iHealth m_iTeamNum m_pGameSceneNode
# deadlock client.dll: 60326552 bytes, modified 2026-10-28 20:30
C_BaseEntity::m_iHealth = 0x354
C_BaseEntity::m_iTeamNum = 0x3ef
C_BaseEntity::m_pGameSceneNode = 0x330
```

The first line says which version of the file the answer is for. Offsets like these change with game updates, so
keep that line next to anything you write down.

## Getting started

You need:
- Windows with the game installed through Steam (it finds the game folder by itself). Any other 64-bit Windows DLL
  can be passed by path.
- Python 3.9 or newer (tested on 3.14).
- One Python package: [capstone](https://www.capstone-engine.org/), the disassembler it uses (tested on 5.0.7).

```bash
git clone https://github.com/taylorswiftfan22/source-2-reversing-skill source2-re
pip install capstone
python source2-re/scripts/s2re.py -g cs2 info
```

A few first commands to try:

```bash
python source2-re/scripts/s2re.py -g cs2 cvar sv_cheats
python source2-re/scripts/s2re.py -g cs2 schema C_CSPlayerPawn --flat
python source2-re/scripts/s2re.py -g cs2 -m engine2 iface
python source2-re/scripts/s2re.py -g cs2 schema --dump --format cpp -o client_schema.hpp
```

`-g` picks the game (`cs2`, `deadlock`) and `-m` the DLL (`client` by default, or `server`, `engine2`, ...).
`python source2-re/scripts/s2re.py --help` lists every command.

**As a Claude Code skill.** Put the folder at `~/.claude/skills/source2-re/` (all your projects) or
`<project>/.claude/skills/source2-re/` (one project). Claude picks it up by itself when you ask about a Source 2
game's code, and runs the commands for you.

## Good to know

- **The first run on a file takes a few seconds.** It builds an index of the DLL once per game version (about 5 s
  for CS2's `client.dll`, 9 s for Deadlock's); after that, answers come quickly. The index lives in
  `%LOCALAPPDATA%\s2re-cache`.
- **It keeps a copy of the previous version.** Steam overwrites the DLLs on every update, so the first time it sees
  a new version it saves a copy (the current and the previous one per DLL, 40 to 60 MB each for the client DLLs).
  That copy is what lets it find where things moved after an update. Set `S2RE_NO_SNAPSHOT=1` to turn this off.
- **Addresses are relative to the start of the DLL.** Every address it prints or accepts is an offset from the
  DLL's start (an RVA), so it doesn't depend on where Windows loaded the game. Addresses copied from IDA or a
  debugger are accepted too.
- **`--json`** on any command gives machine-readable output, and `-o FILE` writes the output to a file.

## Examples

**What code reads this console variable?**
```text
$ python scripts/s2re.py -g cs2 cvar sv_jump_spam_penalty_time
# cs2 client.dll: 39227544 bytes, modified 2026-11-04 17:07
sv_jump_spam_penalty_time: object 0x2537620, registered at 0xb2146 in fn 0xb20c0
  help: For subtick jumps, if this much time or less has elapsed since the last time the user has pressed the jump key, pretend they hadn't. Lowering this makes bunnyhopping easier.
  4 reference(s) outside the initializer:
    0x008c4d09: lea      rcx, [rip + 0x1c72910]  ; -> 0x2537620 .data    [fn 0x8c4c20]
    0x008c4e94: lea      rcx, [rip + 0x1c72785]  ; -> 0x2537620 .data    [fn 0x8c4d90]
    0x01a85d44: lea      rcx, [rip + 0xab18d5]  ; -> 0x2537620 .data    [fn 0x1a85d40]
```

**Which function uses this text?**
```text
$ python scripts/s2re.py -g cs2 str --partial "DoMovement::Subtick"
# cs2 client.dll: 39227544 bytes, modified 2026-11-04 17:07
"DoMovement::Subtick": 1 hit(s)
  0x01c40648 .rdata 'CPlayer_MovementServices::DoMovement::Subtick': 1 ref(s)
      0x00a674dc: lea      rcx, [rip + 0x11d9165]  ; -> 0x1c40648 .rdata "CPlayer_MovementServices::DoMovement::Subtick"    [fn 0xa673b0]
```

**How is this function reached?** Where the calls stop, it shows the class whose function table holds it, and the
slot number you would hook.
```text
$ python scripts/s2re.py -g cs2 callers a674dc --depth 3
callers of 0xa673b0 (function containing 0xa674dc), depth 3:
  0x00a726b0  via 0xa72977 call
      0x00a74130  via 0xa7439a call
          stored at 0x01c40338  (CPlayer_MovementServices vtable slot [32])
          stored at 0x01c40818  (CPlayer_MovementServices_Humanoid vtable slot [32])
          (no .pdata)  via 0x861300 jmp (+1 more site(s))
```

**Which fields does this function touch?**
```text
$ python scripts/s2re.py -g cs2 fields ae50f0 --schema C_BaseEntity
fields through rcx in fn 0xae50f0: 4 offset(s), 6 access(es), named from schema C_BaseEntity
  +0x0000  size 8     read             -                                 e.g. 0xae5107: mov rax, qword ptr [rbx]
  +0x0010  size 8     read             CEntityInstance::m_pEntity        e.g. 0xae5130: mov rdx, qword ptr [rbx + 0x10]
  +0x0380  size 4     read             m_nSubclassID                     e.g. 0xae50fe: cmp dword ptr [rbx + 0x380], 0
  +0x03e0  size 4     read,write       m_flCreateTime                    e.g. 0xae517b: movss xmm0, dword ptr [rbx + 0x3e0]
```

**What does the engine hand out through `CreateInterface`?**
```text
$ python scripts/s2re.py -g cs2 -m engine2 iface Engine
EngineGameUI001                      factory 0x13cbe0  InterfaceReg 0x978eb8  instance 0x6bd720  CEngineGameUI
Source2EngineToClient001             factory 0x75d00  InterfaceReg 0x739720  instance 0x6bd030  CEngineClient
Source2EngineToServer001             factory 0xa3b40  InterfaceReg 0x977cd0  instance 0x6bd108  CEngineServer
...
```

**After an update: check your signatures, find what moved, make new signatures**
```text
$ python scripts/s2re.py -g cs2 sig --file src/sigs.hpp
CheatsReader: UNIQUE (1 hit(s))  40 55 56 57 48 81 EC D0 00 00 00
    0x9ca4f0 [fn 0x9ca4f0]
Missing: MISSING (0 hit(s))  DE AD BE EF 13 37 DE AD
-- 2 signatures: 1 unique, 1 missing

$ python scripts/s2re.py -g cs2 -m engine2 port 604d0 8b4de8 --old <older engine2.dll>
0x604d0 (code, in old fn 0x604d0) -> 0x626c0  confidence high
  0x000626c0  score  68.6  (anchors 58.6, similarity 1.00)
      string "CQ: Server set re-sync at cmd %d\n"
      string "Server sent unknown recent usercommand encoded s"
      ... 11 more anchor(s)
  0x001044c0  score   6.7  (anchors 3.0, similarity 0.37)
      call #6 of ported caller 0x45eb0->0x47b40

0x8b4de8 (data: 0x8b4de8 .data) -> 0x9bac68  confidence high
  0x009bac68  object of host_timescale

$ python scripts/s2re.py -g cs2 sigmake 2537620 --target
signatures leading to 0x2537620 (0x2537620 .data): 2 unique
  0x008c4e94 [5 insns] 48 8D 0D ? ? ? ? 0F 28 F0 E8 ? ? ? ? 0F 2F C6 72 08  --rel 3 7
  0x008c4d09 [4 insns] 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 8B 05 ? ? ? ? F3 0F 58 07  --rel 3 7
```
The `port` above is a stress test: it carries Deadlock's `engine2.dll` over to CS2's, two games' builds of the same
module. Normally `--old` is left out and the saved copy of the previous version is used.

**Names in IDA / Ghidra / Binary Ninja**
```text
$ python scripts/s2re.py -g cs2 export --tool ida -o client_names.py
[s2re] ...; wrote client_names.py: 48160 names for ida (scope 558, concmd 660, cvar 1992, iface 24, schema 1253, vtable 6851, vfunc 36822)
```
In IDA: File > Script file. Ghidra: Script Manager. Binary Ninja: run it in the Python console.

**The game's network messages**
```text
$ python scripts/s2re.py -g cs2 proto usercmd.proto --message CSubtickMoveStep
message CSubtickMoveStep {
  optional uint64 button = 1;
  optional bool pressed = 2;
  optional float when = 3;
  optional float analog_forward_delta = 4;
  optional float analog_left_delta = 5;
  optional float pitch_delta = 8;
  optional float yaw_delta = 9;
}
```

**A memory dump compared with the file on disk**

The output below comes from a *synthetic* dump: CS2 `client.dll` rebased to `0x7ffb12340000` with its header
erased, one function patched with a `jmp`, one vtable slot redirected, and schema / interface / convar fields
filled in the way the game fills them. A real dump is one you make yourself, from the running game.
```text
$ python scripts/s2re.py -g cs2 --memdump client.bin --headers-from client dumpdiff
dump  client.bin (memory dump, mapped layout, base 0x7ffb12340000): ... (base from relocations (17077 of 52107 sampled pointers; header says 0x180000000))
code changed (patches / inline hooks): 1
  0x00e80d40 .text [fn 0xe80d40] 8 byte(s)
     disk: 0xe80d40: mov qword ptr [rsp + 8], rbx | 0xe80d45: mov qword ptr [rsp + 0x10], rbp
     dump: 0xe80d40: jmp 0x2ba3000 | 0xe80d45: mov qword ptr [rsp + 0x10], rbp
     ! jmp at 0xe80d40 leaves the image -> VA 0x7ffb14ee3000
vtable slots redirected: 1
  0x01ac5010 std::exception vtable slot [1]: shipped 0x14ea80 -> now VA 0x7ffc00001000 (outside the image)
other read-only data changed: 0
written at runtime: 1263 range(s), 1263 with a known owner
  0x021c3ce0    8 byte(s)  schema class CInfoOffscreenPanoramaTexture   0x0000000000000000 -> 0x0000023a0000a500
  ...
```

**From Python**
```python
import sys; sys.path.insert(0, "source2-re/scripts")
import s2pe, s2source2

img = s2pe.Image(s2pe.resolve_module("cs2", "client"))
print(s2source2.find_field(img, "C_CSPlayerPawn", "m_iHealth"))   # (844, 'C_BaseEntity')
for r in s2source2.registrations(img, "concmd")[:3]:
    print(r.name, hex(r.callbacks[0]) if r.callbacks else None)
```

---

*Everything below is reference material for people who want the details.*

## Features in detail

**Navigation**
- `str`: exact, partial or UTF-16 string search. Lists every instruction that loads the string, plus one level of
  pointer tables when nothing loads it directly.
- `xrefs`: every rip-relative operand, direct `call` / `jmp` / `jcc` and MSVC jump-table entry that targets an
  address, and every place its address is stored as a pointer (with the vtable slot, when it is one).
- `func` / `range`: annotated disassembly. Split function chunks are stitched together. Operands are labelled with
  strings, `f32` / `f64` constants, IAT imports (`tier0.dll!Plat_FloatTime`), exports, RTTI vtables and pointers.
- `callers`: caller tree to any depth; where direct calls stop, it shows the vtable slots holding the function.
- `callees`: direct calls, tail jumps and imported calls out of a function.

**Classes and structures**
- `rtti`: MSVC RTTI class → vtable(s), complete-object locator, sub-object offset, base classes and every virtual
  slot. `--grep` searches class names.
- `vtwho`: function → every `Class vtable [slot]` that holds it, which gives the VMT index for a hook.
- `fields`: every offset a function reads, writes or takes the address of through a register (`this` by default),
  with access sizes. `--schema CLASS` names the offsets from that class and its schema bases.
- `disp`: instructions whose memory operand uses a given displacement, in chosen functions or every function in a
  range. Finds field users, and virtual calls by slot (slot 32 = `disp 0x100`).

**Source 2 schema**
- `schema CLASS [FIELD...]`: sizeof, alignment, bases, declared fields with their metadata (`MNetworkEnable`,
  `MNotSaved`, ...). Field lookups walk the base classes. `--flat` prints the whole layout at absolute offsets.
- `schema --list` / `schema --dump`: every class in the module (CS2 client.dll: 988; Deadlock: 3967), dumped as
  text, a C++ header or JSON together with every enum.
- `enum`: schema enums with their values (CS2 client.dll: 265; Deadlock: 480).

**Console variables, commands and interfaces**
- `cvar`: name → static object, initializer, help text, and every reference outside the initializer. `--list`
  searches names and help (CS2 client.dll: 1992 convars).
- `concmd`: console command → object, **callback (the handler)**, help text and references (CS2 client.dll: 336).
- `cvarobj`: object address → which convar or command it belongs to.
- `iface`: `CreateInterface` version strings → factory, `InterfaceReg`, the static instance and its class
  (`Source2EngineToClient001` → `CEngineClient`).

**Signatures**
- `sig`: scans IDA (`48 8B ? ?`), x64dbg (`48 8B ?? ??`), compact (`488B????`) or code-style (`\x48\x8B` + mask)
  patterns. Says which function each hit is in and resolves a rel32 at each hit (`--rel OFF LEN`).
- `sig --file`: checks a whole list and reports each signature as UNIQUE / MISSING / AMBIGUOUS. The file can be a
  plain list (`name = PATTERN rel=3,7`) or your source code: every quoted IDA-style pattern in a `.hpp` / `.cpp` /
  `.py` file is checked. Names come from a quoted identifier on the same line or the identifier before the pattern;
  in SDK-style tables (`{"TraceHull", "client.dll", "48 89 ..."}`) the quoted module limits each signature to its
  DLL, and the summary counts the ones left for other modules.
- `sigmake`: shortest unique pattern at an address. Rip-relative displacements and rel32 branches are wildcarded;
  `--loose` also wildcards struct offsets, constants and short branches. Output in IDA, x64dbg, compact or code
  style, with the `--rel` that resolves its first reference.
- `sigmake --target`: patterns that *lead to* an address you can't sign directly (a global, a string, a function
  only reached through calls): one per referencing instruction, each with its `--rel`.
- `sigconv`: one pattern in every format.

**Across builds**
- `port`: takes an address from the previous build and finds it in the current one. Functions are matched by
  anchors that survive updates (vtable class and slot, unique strings, convars read or registered, carried-over
  signatures, ported callers and callees), then by instruction similarity; the instruction inside the function is
  mapped too. Strings, vtables, convar objects and schema infos map by name; other globals through the ported
  instructions that reference them. Every result comes with a confidence and the evidence behind it.
- Snapshots: the first time s2re indexes a build, it keeps a copy (current + previous build per module), because
  Steam overwrites the DLL on update. `snapshots` lists them; `--old PATH` uses any other copy.

**Disassembler export**
- `export --tool ida|ghidra|binja|json`: a script that names RTTI vtables, virtual functions (after the most-base
  class holding them), convar and command objects, command handlers, interface factories and instances, schema
  class infos, and functions identified by a unique profiler-scope string (`Class::Method`). 48,160 names for CS2
  client.dll.

**Module dumps**
- `--memdump FILE` runs any command on a module dumped from a running process: a raw memory image (SizeOfImage
  bytes from the module base) or a rebuilt PE file, detected automatically.
- The runtime base is taken from the PE header when the relocated pointers confirm it. Otherwise (header left at
  the default, or erased and supplied with `--headers-from client`) it is recovered from the relocations alone.
  Runtime addresses from a debugger can then be pasted as they are.
- `dumpdiff`: compares the dump with the DLL of the same build, with relocations accounted for. Reports patched
  code with both disassemblies (and flags jumps that leave the image, the shape of an inline hook), redirected
  vtable slots, and every value the game wrote into the module, named by owner: convar objects, schema infos,
  `InterfaceReg` nodes, singleton instances.
- `iface` also walks the live `CreateInterface` list; `cvar` / `concmd` / `cvarobj` show the object's live values
  (for a convar, `+0x8` is the pointer to its data).

**Protobuf**
- `proto`: lists every serialized `FileDescriptorProto` embedded in the DLL and prints any one as `.proto` text
  (messages, nested types, enums, oneofs, defaults, services, extensions); `--message` prints a single message.

**Raw data, tables, output**
- `hex` (`--qwords` decodes pointers), `exports`, `imports` (reference count per IAT slot, delay-load included),
  `info`.
- `--json` on every command (uncapped, with the module and build it came from), `-o FILE`, `--limit N`.

**Under the hood**
- **Library:** `s2pe`, `s2source2`, `s2port`, `s2export` and `s2dump` expose everything above for your own scripts.
- **Caching:** the cross-reference index and vtable map are built once per DLL build in parallel (5.3 s for CS2
  `client.dll`, 8.5 s for Deadlock's, on 12 cores) and keyed by file size + mtime.
- **Leaf functions:** functions without unwind info (one-line getters in vtables, for example) are swept and
  indexed too.
- **Install discovery:** Steam libraries are found from `libraryfolders.vdf`, so `-g cs2 -m engine2` locates the
  DLL wherever the game is installed.

## Command reference

Global options (before or after the command): `-g cs2|deadlock|dota2|hlalyx` (default `cs2`, or `$S2RE_GAME`),
`-m <module or path>` (default `client`), `--json`, `-o FILE`, `--limit N` (rows per list in text output, default
50, `0` = all), `-q` (no header line). Module names are looked up in `game/<mod>/bin/win64`, then `game/bin/win64`.
Dumps: `--memdump FILE`, plus `--base HEX`, `--layout mapped|file` and `--headers-from DLL` to override detection.
Negative numbers go after `--`, with every option before it (`disp --in <fn> -- -0x10`).

| command | options | does |
|---|---|---|
| `info` | | path, size, mtime, PE timestamp, sections, counts, cache and snapshot state |
| `str TEXT...` | `--partial`, `--wide`, `--section .rdata` | strings + referencing code (+ pointer tables) |
| `xrefs RVA...` | | code references and stored pointers |
| `func RVA...` | | whole function, chunks stitched, annotated |
| `range RVA [N]` | | N instructions (default 30) |
| `callers RVA...` | `--depth 1` | caller tree, vtable slots where calls stop |
| `callees RVA...` | | calls, tail jumps, imports out of a function |
| `rtti CLASS...` | `--grep TEXT` | vtables, bases, slots |
| `vtwho RVA...` | | class + slot index of a virtual |
| `fields RVA` | `--reg rcx`, `--schema CLASS` | offsets used through a register |
| `disp DISP...` | `--in RVA...` / `--range LO HI`, `--imm` | displacement users |
| `schema CLASS [FIELD...]` | `--flat` | sizeof, bases, fields (+ inherited lookups) |
| `schema --list [FILTER]` | | all classes |
| `schema --dump` | `--format text\|cpp\|json` | every class and enum |
| `enum NAME...` / `enum --list [FILTER]` | | schema enums |
| `iface [FILTER]` | | CreateInterface registrations |
| `cvar NAME...` / `cvar --list [FILTER]` | `--span 0x10` | convar object, help, references |
| `cvarobj RVA...` | `--span 0x10` | object → convar / command |
| `concmd NAME...` / `concmd --list [FILTER]` | `--span 0x10` | command object, callback, help |
| `proto [NAME]` | `--message M` | list descriptors / print one as `.proto` |
| `sig PATTERN...` | `--rel OFF LEN`, `--mask M`, `--region image\|code` | hits, functions, resolved targets |
| `sig --file FILE` | `-v` | check a list or source file |
| `sigmake RVA...` | `--loose`, `--max 32`, `--format ida\|x64dbg\|code\|compact`, `--target` | shortest unique pattern(s) |
| `sigconv PATTERN` | `--mask M` | all pattern formats |
| `port RVA...` | `--old DLL`, `--top 5` | old build's address → current build |
| `snapshots` / `snapshot` | | list / save builds for `port` |
| `export` | `--tool ida\|ghidra\|binja\|json`, `--only KINDS`, `-o FILE` | disassembler naming script |
| `dumpdiff` (with `--memdump`) | `--disk DLL`, `--kind code,vtable,rdata,data`, `--section S...`, `--all-data` | dump vs DLL: patches, vtable slots, runtime writes |
| `hex RVA [N]` | `--qwords` | hex dump / pointer decode |
| `exports [FILTER]` / `imports [FILTER]` | | PE tables |

Environment variables:

| variable | sets |
|---|---|
| `S2RE_GAME` | default game |
| `S2RE_GAMES` | extra game presets: `name=Steam folder:mod;...` |
| `S2RE_STEAM` | extra Steam library root |
| `S2RE_CACHE` | cache folder (default `%LOCALAPPDATA%\s2re-cache`, or `~/s2re-cache`) |
| `S2RE_JOBS` | index build workers (default min(cores, 8)) |
| `S2RE_NO_SNAPSHOT` | `1` = don't keep copies of new builds |

## How it works

- **Mapping.** The DLL is mapped the way the Windows loader would: sections at their RVAs, no relocations, so a
  pointer stored in data is a VA against ImageBase. Function boundaries and split chunks come from `.pdata` and
  chained unwind info.
- **Cross-reference index.** A capstone sweep over every function and every gap between functions, split across
  worker processes. It records each rip-relative operand, each direct branch target and each entry of MSVC jump
  tables (`lea rB,[__ImageBase]; mov eR,[rB+rI*4+table]`), and is pickled per build.
- **Vtable map.** Built from MSVC RTTI: complete object locators found by their self-RVA, and vtables found by the
  COL pointer stored just before slot 0.
- **Source 2 schema.** Every static `SchemaClassInfoData_t` and `SchemaEnumInfoData_t` in `.data` is found by its
  shape (an `ff ff ff ff` marker at +0x2a for classes, -1 at +0x38 for enums) and decoded: fields, metadata, bases.
- **Convars and commands.** Found from the call sites of the module's registrar (the function holding
  `RegisterConVar: Unknown error` / `RegisterConCommand: ...`) and its small wrappers: `lea rdx,[name]` +
  `lea rcx,[object]`, plus the callback and help text for commands.
- **Interfaces.** `CreateInterface` is followed to the list head it walks; the constructors that store into it lead
  to every static `InterfaceReg` initializer (`lea r8,[name]; lea rdx,[factory]; lea rcx,[reg]`).
- **Porting.** Anchors vote for candidate functions in the new build; candidates are scored by anchors + 10 ×
  similarity (instruction sequence, strings, size, imports, constants, call count). Confidence comes from the score
  and its margin over the runner-up.
- **Protobuf descriptors.** Located by `0x0A <len> "<path>.proto"`. Decoding stops where the top-level field
  numbers stop ascending.
- **Dumps.** The layout is chosen by where the `.pdata` table reads as valid, with the file length breaking ties.
  For the base, every relocated pointer that lands on a `.pdata` function start votes for `pointer - start`;
  only 64 KB-aligned bases count, and the header's ImageBase wins when the votes confirm it. `dumpdiff` rebases a
  copy of the DLL to the dump's base and compares the two qword by qword.

[`references/layouts.md`](references/layouts.md) documents each layout and how it was verified, plus anchors found
on specific builds.

## Testing

```bash
python -m unittest discover -s tests -v
```

41 tests, about 14 s:
- pattern and file parsing (no game needed);
- invariants on Windows' own `kernel32.dll`, and synthetic dumps of it in every layout and header state;
- facts pinned to specific CS2 and Deadlock builds (counts, offsets, signatures, a cross-game port);
- a synthetic CS2 `engine2.dll` dump with runtime state written in: every Source 2 parser must give the disk
  answers, and `dumpdiff` must report exactly the written qwords, the hook and the redirected vtable slot.

The pinned groups skip themselves when the installed DLL is a different build; re-pin them from s2re output after
an update. `tests/synth_dump.py` builds the synthetic dumps.

Port accuracy was measured separately on `engine2.dll`, Deadlock build → CS2 build, against ground truth from
functions that reference a unique string: 60/60 correct with strings, 119/120 with each function's own strings
hidden, and every `high` confidence answer correct.

## Limitations

- **Static by default.** You see the DLL as shipped. A `--memdump` adds what the game wrote into the module
  itself, but never the heap: convar values and schema field types (CSchemaType data) live outside the module.
- **Dumps are tested synthetically.** Real dumps haven't been tried yet. In a dump, schema class and enum infos
  may differ from disk only at `+0x00`; if the game fills more of them, those classes are skipped (compare the
  counts with the DLL).
- **What xrefs can see.** Rip-relative operands, direct branches and jump tables. Virtual calls and calls through
  registers don't appear; use `vtwho`, `disp`, stored-pointer xrefs and `hex --qwords` for those.
- **`fields` is a linear pass.** It follows register copies but ignores branches, and drops volatile registers at
  calls.
- **`port` needs the old DLL.** It only exists if s2re indexed that build before the update (or you kept a copy).
  `medium` / `low` results need a human look.
- **Template names** in RTTI stay mangled.
- **Export scripts** compile, but haven't been run inside IDA, Ghidra or Binary Ninja yet.
- **Binary formats.** x64 PE with MSVC RTTI only.
- **Tested on** CS2 `client.dll` / `engine2.dll` (2026-11-04 builds) and Deadlock `client.dll` / `engine2.dll`
  (2026-10-28 builds). The Dota 2 and Half-Life: Alyx presets are folder-name guesses; neither game was installed.

## Roadmap

1. **Linux server binaries (ELF).** Needs ELF parsing, Itanium RTTI and `.eh_frame` function boundaries. Blocked on
   having a Linux build of a Source 2 server to test against.
2. **A real module dump** run through `--memdump` and `dumpdiff`, to confirm the synthetic tests' assumptions
   (which schema fields the game fills, an intact `.reloc` in memory).
3. **Template demangling** for RTTI names.
4. **Verify the export scripts** inside each disassembler.

## Disclaimer

Not affiliated with or endorsed by Valve. The tool only reads files: the DLLs on disk, or a dump you provide. It
never touches a running game. You are responsible for using it within the terms of the games and services
involved.

## License

No license has been chosen yet.
