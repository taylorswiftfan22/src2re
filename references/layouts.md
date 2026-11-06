# Layouts and anchors

What the scripts assume about the binaries, and how each assumption was checked. "Verified" means checked against
the DLLs on disk on 2026-11-05: CS2 client.dll 39227544 bytes (modified 2026-11-04 17:07), CS2 engine2.dll 7498392
bytes (2026-11-04 00:47), Deadlock client.dll 60326552 bytes and engine2.dll 6394008 bytes (both 2026-10-28 20:30).
`tests/test_s2re.py` pins the facts below that have exact values.

## PE / unwind (generic x64)

- Sections are mapped at their RVAs. Pointers stored in `.data` / `.rdata` are VAs against ImageBase (0x180000000
  for every Source 2 DLL seen so far).
- `.pdata` holds RUNTIME_FUNCTION entries `{begin, end, unwind}`, 12 bytes each.
- UNWIND_INFO byte 0 = `version | flags << 3`, byte 2 = number of unwind codes.
- `flags & 4` (CHAININFO) means a parent RUNTIME_FUNCTION follows the codes, at `+4 + 2 * ((count + 1) & ~1)`. That is
  how a split chunk maps back to its primary function, and how `func` stitches a function's chunks together.
- `unwind & 1` means the entry points at another RUNTIME_FUNCTION (indirect).
- Leaf functions have no entry. Both CS2 and Deadlock have plenty, for example one-instruction
  `lea rax, [rip+X]; ret` getters in vtables and interface factories. The xref index sweeps the gaps between
  `.pdata` functions to cover them. On CS2 client.dll that adds about 56k refs to a pdata-only index (1.70M vs
  1.64M), and loses nothing that points inside the image.
- **Jump tables (MSVC x64).** `lea rB, [rip -> __ImageBase]`, then `mov eR, dword ptr [rB + rI*4 + table]`, then
  `add rR, rB; jmp rR`: the table holds 32-bit RVAs of the case targets. The index records each entry as a reference
  from the `jmp`. On CS2 client.dll this added about 17k refs.
- **Delay-load imports.** Read from the delay import directory; their IAT slots are tagged `[delay] dll!name`.

## MSVC RTTI (x64)

- **CompleteObjectLocator** (in `.rdata`): `u32 sig = 1, offset, cdOffset, rva TypeDescriptor,
  rva ClassHierarchyDescriptor, rva self`. A COL is found by checking that `self == its own rva`.
- **Vtable**: the qword just before vtable[0] holds the COL's VA. The slots run while they point into executable
  sections.
- **TypeDescriptor**: `pVFTable, spare, char name[]`. The name is mangled: `.?AVClass@@`, `.?AUStruct@@`,
  `.?AVInner@Outer@@`, and `?$` for templates (left mangled in output).
- **ClassHierarchyDescriptor**: `sig, attributes, numBaseClasses, rva BaseClassArray`. Each BaseClassDescriptor
  starts with an rva of its TypeDescriptor. Entry 0 is the class itself.
- COL `offset` != 0 means a secondary vtable (multiple inheritance). The object pointer for that vtable sits
  `offset` bytes into the object (`CSource2Client@0x8`, `@0x30` in CS2 client.dll).
- Verified: CS2 `CPlayer_MovementServices` has 1 vtable (0x1c40238), 54 slots, base `CPlayerPawnComponent`.

## Schema system: static SchemaClassInfoData_t

Emitted into `.data` by the schema generator, so they can be read from disk. Found by shape: qwords 0, 2 and 3 are
zero, qword 1 points at a printable name, and +0x2a holds `ff ff ff ff`.

| offset | field |
|---|---|
| +0x00 | self pointer, 0 on disk (set at runtime) |
| +0x08 | `const char*` class name (the lookup key) |
| +0x10, +0x18 | 0 on disk |
| +0x20 | i32 sizeof |
| +0x24 | i16 number of declared fields |
| +0x26 | i16 number of static fields |
| +0x28 | u8 alignment (0xff = unknown) |
| +0x29 | u8 number of base classes |
| +0x2a | `ff ff ff ff` (the marker used to tell class infos from other structures) |
| +0x30 | pointer to the field array |
| +0x38 | pointer to the base class array |

Field array entries, 0x20 bytes:

| offset | field |
|---|---|
| +0x00 | `const char*` field name |
| +0x08 | CSchemaType pointer. **null on disk** (filled at runtime), so types are not available offline |
| +0x10 | i32 offset |
| +0x14 | i32 metadata count |
| +0x18 | pointer to metadata entries, 0x10 bytes each: `const char*` name (`MNetworkEnable`, `MNotSaved`, ...), value pointer (decoded only when it points at a string in `.rdata`) |

Base class array entries, 0x10 bytes: `u32 offset of the base inside the class`, then a pointer to the base's
SchemaClassInfoData_t. A base in another module (client classes deriving from a schemasystem / engine type) points
outside this image and shows as `<other module>`.

Fields are each class's own declarations; `find_field` and `--flat` walk the bases and add their offsets.

Verified:
- Counts: CS2 client.dll 988 classes, Deadlock client.dll 3967.
- CS2 `C_BaseEntity`: m_iHealth 0x34c, m_iTeamNum 0x3e7, m_pGameSceneNode 0x330. `C_CSPlayerPawn` (sizeof 0x3720)
  resolves m_iHealth to 0x34c through `C_CSPlayerPawnBase -> C_BasePlayerPawn -> ... -> C_BaseEntity`.
- CS2 `CPlayer_MovementServices`: m_nButtons 0x50, m_vecOldViewAngles 0x240.
- Deadlock `C_BaseEntity`: m_iHealth 0x354, m_iTeamNum 0x3ef.
- The base array reading (+0x29 count, +0x38 array) was checked by the inheritance it produces matching the known
  class hierarchy (`C_BaseModelEntity : C_BaseEntity`, `C_CSPlayerPawn : C_CSPlayerPawnBase`) and by inherited
  lookups returning the base class's own offsets.

## Schema system: static SchemaEnumInfoData_t

Found by shape: qwords 0 and 2 zero, qword 1 a printable name, qword 7 (+0x38) = -1, and **no** `ff ff ff ff` at
+0x2a (which would make it a class info).

| offset | field |
|---|---|
| +0x08 | `const char*` enum name |
| +0x18 | u8 size in bytes |
| +0x19 | u8 alignment |
| +0x1c | u16 enumerator count |
| +0x20 | pointer to enumerators, 0x20 bytes each: `const char*` name, i64 value, metadata count, metadata pointer |
| +0x38 | -1 |

Verified: CS2 client.dll 265 enums (`MoveType_t`: 14 values, MOVETYPE_WALK = 2), Deadlock client.dll 480.

## ConVars

- **Registration.** Each module has a registrar function, recognised by the string `RegisterConVar: Unknown error`
  it references. Static initializers call it (or small wrappers around it, < 0x300 bytes with 3+ callers) after
  `lea rdx, [name]` and `lea rcx, [object in .data]`, within 0x80 bytes before the call. The help text is another
  `.rdata` lea nearby (often absent). Example: CS2 `sv_jump_spam_penalty_time` init at 0xb20c0.
- Counts: CS2 client.dll 1992, Deadlock client.dll 2227.
- **Object spacing.** Objects are packed **0x10 apart** in both CS2 and Deadlock: `sv_ladder_dampen`, `sv_ladder_angle`
  and `sv_ladder_scale_speed` sit at 0x2537670 / 0x2537680 / 0x2537690. That is why references are counted from
  obj+0..0xF only (`--span`). A 0x48 window reported the neighbours' initializers as readers.
- **Readers.** Code reaches the value in one of two ways:
  - `lea rcx, [obj]` followed by a call (CS2 modern jump 0x8c4d90 with `sv_jump_spam_penalty_time`);
  - `mov rax, [obj+8]`, loading the object's data pointer (CS2 ladder move 0x8dd2a0 with `sv_ladder_dampen` /
    `sv_ladder_angle`; `sv_standable_normal` readers 0x882d50, 0x8c40b0).

  A 32-byte function that references the object twice is teardown/unregistration (CS2 0x1a85d40, Deadlock 0x25bbe90).
- **Resolved:** the CS2 objects 0x2537630 / 0x2537650 / 0x2537660, earlier listed as having no initializer, are
  `sv_air_max_wishspeed`, `sv_walkable_normal` and `sv_standable_normal`. The registrar call-site scan finds them;
  the older heuristic (a `lea rdx,[name]` next to the object's `lea rcx`) did not. Why it missed them was not
  examined.

## ConCommands

- Same registration scheme, anchored on `RegisterConCommand: Unknown error`. Before the call: `lea rdx, [name]`,
  `lea rcx, [object]`, the help text in `r9` (`lea r9, [.rdata string]`), and the callback as a `lea` of a code
  address (stored into the command's callback struct).
- Counts: CS2 client.dll 336, Deadlock client.dll 412.
- Verified: CS2 `cl_anim_eval_stats` object 0x23c01e8, callback 0x38e220, help "Displays stats about how many
  EvaluatePose calls are unused".

## CreateInterface

- `CreateInterface` (exported) walks a singly linked list `s_pInterfaceRegs` of `InterfaceReg { create fn +0x00,
  const char* name +0x08, next +0x10 }`. It may start with a `jmp` to the real body; the list head is the first
  `mov reg, [rip -> .data]`.
- The list is built at runtime, so it is empty on disk (a dump has it: see "Module dumps"). The `InterfaceReg`
  constructor is the code that stores into the head; its callers are the static initializers:
  `lea r8, [name]; lea rdx, [factory]; lea rcx, [InterfaceReg]`.
- A factory of the form `lea rax, [X]; ret` returns a static instance X. Its class comes from the vtable stored at X,
  or from the vtable its constructor stores (one call deep, marked "from its constructor").
- Verified: CS2 client.dll 8 interfaces (`Source2Client002`: factory 0xb86ee0, instance 0x2564620, CSource2Client),
  CS2 engine2.dll 28 (`Source2EngineToClient001` → CEngineClient at 0x6bd030).

## Module dumps

**Status: tested only on synthetic dumps** built by `tests/synth_dump.py` from the disk DLLs (CS2 client.dll,
CS2 engine2.dll, Windows kernel32.dll): mapped at their RVAs, DIR64 pointers rebased to 0x7ffb12340000 /
0x7ffa55550000, runtime state written in. No real dump has been run yet. Everything under "assumed" needs one.

- **Two input layouts.** `mapped`: a raw copy of the module's memory, file offset = RVA, normally SizeOfImage bytes.
  `file`: a rebuilt PE (sections at raw offsets, as dump-fixing tools write them). Detected by reading the `.pdata`
  directory where each layout would put it (real entries are ascending and inside the code sections). When both
  read as valid (a raw-offset shift that is a multiple of 12 lands on whole entries; CS2's `.text` is shifted by
  0xC00 = 12 * 256), the file length decides: a file-layout image ends where its last section's raw data or its
  Authenticode block ends. A file not marked as a dump is treated as mapped only when the file reading is garbage.
- **Relocations.** Base relocation directory (data directory 5): blocks of `u32 page rva, u32 block size`, then u16
  entries `type << 12 | offset`; type 10 = DIR64, 0 = padding. CS2 client.dll has 260,535 DIR64 slots.
- **Runtime base.** Each relocated qword that equals `base + (a .pdata function start)` votes for that base; only
  64 KB-aligned candidates count. On CS2 client.dll 17,077 of 52,107 sampled pointers vote for the true base (vtable
  slots, mostly). The header's ImageBase is used when it gets at least 90% of the winning votes; otherwise the winner
  is used (header left at the default, or erased and taken from the disk DLL with `--headers-from`).
- **dumpdiff.** The disk DLL is rebased to the dump's base and compared qword by qword. Code ranges are disassembled
  from the containing instruction on both sides; a `jmp` / `call` whose target is outside [0, SizeOfImage) is
  flagged. A changed qword inside an RTTI vtable in read-only data is a redirected slot. Writable sections are
  runtime writes, labelled by the static object they fall in.
- **Assumed (needs a real dump):**
  - `.reloc` is mapped and intact in the dump (user-mode images keep discardable sections mapped). If it is zeroed,
    the relocations of `--headers-from` are used.
  - SchemaClassInfoData_t and SchemaEnumInfoData_t differ from disk only at `+0x00` (zero on disk, documented as set
    at runtime). The dump scan allows `+0x00` to be anything and keeps every other check. If the game writes
    `+0x10` / `+0x18` / `+0x38` too, those classes and enums disappear from the dump scan: compare the counts with
    the DLL. (Relaxing the other checks as well produced a false enum on CS2 engine2.dll, a schema field entry.)
  - `InterfaceReg { create +0x00, name +0x08, next +0x10 }` and `s_pInterfaceRegs` are filled by the static
    initializers, so the live list can be walked from the head in a dump.
  - A ConVar object's `+0x08` holds the pointer to its data (the readers' `mov rax, [obj+8]` shape), which is a
    heap address in a dump. The value itself is not in the module.

## Embedded protobuf descriptors

- Serialized `FileDescriptorProto`s sit in `.rdata`. Each starts with tag `0x0A`, a 1-byte length, and
  `<path>.proto`.
- Top-level fields are serialized in ascending field-number order. The decoder stops at the first field number
  that goes down (usually the next descriptor's `0x0A`).
- Verified counts: 33 in CS2 client.dll (`usercmd.proto` at 0x1b31e60), 42 in Deadlock client.dll. Every other
  `.proto` string in CS2 is a `.google.protobuf.*` type reference, not a descriptor.

## Patterns

- Accepted: IDA (`48 8B ? ?`), x64dbg (`48 8B ?? ??`), compact hex (`488B????`), code style (`\x48\x8B\x00\x00`
  with mask `xx??`).
- `image` scope scans the whole mapped image from offset 0 to SizeOfImage, the way a typical in-process module
  scanner does. `code` scope scans executable sections only.
- `sigmake` always wildcards rip-relative displacements and rel32 branch targets. `--loose` also wildcards rel8
  branches, other disp32 values (struct offsets) and imm32 constants.
- `sigmake --target X`: a unique pattern at X itself when it is code, plus one at each instruction whose rel32 /
  disp32 resolves to X, with `--rel <offset of that field in the instruction> <instruction length>`.
- Convar initializers are near-identical code, so a pattern at an initializer is rarely unique; `--target` on a
  convar object usually finds patterns at its readers instead (CS2 `sv_jump_spam_penalty_time`: 0x8c4e94, 0x8c4d09).

## Anchors on specific builds

RVAs are per build. The anchor column is what survives updates.

**CS2 client.dll, 2026-11-04 build (39227544 bytes).** Verified 2026-11-05:

| what | rva | anchor |
|---|---|---|
| CPlayer_MovementServices::DoMovement | 0xa673b0 | string `CPlayer_MovementServices::DoMovement::Subtick` (lea at 0xa674dc) |
| DoMovement's caller chain | 0xa726b0 <- 0xa74130 | 0xa74130 = CPlayer_MovementServices vtable 0x1c40238 slot [32] (also the `_Humanoid` vtable, slot 32) |
| modern jump | 0x8c4d90 | reads `sv_jump_spam_penalty_time` (object 0x2537620); 0x8c4c20 reads it too |
| ladder convar inits | 0xb22e0 / 0xb2220 / 0xb2160 | `sv_ladder_scale_speed` / `sv_ladder_dampen` / `sv_ladder_angle` |
| button state (`m_nButtons`) | CPlayer_MovementServices+0x50 | schema `CPlayer_MovementServices::m_nButtons` |
| ladder move | 0x8dd2a0 | reads `sv_ladder_dampen` and `sv_ladder_angle` through `[obj+8]` |
| sv_cheats | object 0x2564538, init 0xd1e60 | convar name |
| CSource2Client instance | 0x2564620 | `Source2Client002` factory 0xb86ee0 (`lea rax,[instance]; ret`) |
| CreateInterface | 0x19d0ff0 | export |

**CS2 engine2.dll, 2026-11-04 build (7498392 bytes).**

| what | rva | anchor |
|---|---|---|
| function using the usercmd re-sync strings (role inferred from them only) | 0x626c0 | strings `CQ: Server set re-sync at cmd %d`, `Server sent unknown recent usercommand encoded s...` (ported from Deadlock engine2 0x604d0, confidence high) |
| host_timescale | object 0x9bac68 | convar name |
| CEngineClient instance | 0x6bd030 | `Source2EngineToClient001` factory 0x75d00 |

**Deadlock engine2.dll, 2026-10-28 build (6394008 bytes).**

| what | rva | anchor |
|---|---|---|
| function using the usercmd re-sync strings | 0x604d0 | same strings as CS2 0x626c0 |
| host_timescale | object 0x8b4de8, init 0x18800 | convar name |
