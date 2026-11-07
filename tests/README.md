# tests

> 41 tests, about 14 s on a warm cache.

```bash
python -m unittest discover -s tests -v
```

First run after a cache wipe adds 10 to 20 s per DLL for the index.

The suite never writes snapshots (`S2RE_NO_SNAPSHOT=1`) and never attaches to a running game. Some tests
synthesise a module dump from the DLL on disk; see `synth_dump.py`.

## The three groups

| group | needs | what it covers |
|---|---|---|
| `Pure` | nothing | pattern parsing (IDA / x64dbg / compact / code style), address and negative-hex parsing, signature-file reading, disassembler script rendering — the parts that don't need a DLL at all |
| `GenericPE`, `GenericDump` | Windows `kernel32.dll` | invariants any x64 PE should satisfy (section layout, exports / imports count, RTTI vtables, `.pdata` coverage, sig scan determinism). `GenericDump` synthesises `kernel32.dll` as every supported dump layout (raw mapped, rebuilt PE file, header erased) and checks the base is recovered and the usual commands still work |
| `PinnedCS2Client`, `PinnedDeadlockClient`, `PinnedPort`, `PinnedEngine2Dump` | the exact CS2 / Deadlock builds pinned at the top of `test_s2re.py` | facts read from a specific build: counts of schema classes, enums, convars, concommands, interfaces; known offsets (e.g. `C_BaseEntity::m_iHealth`); specific vtables and slots; a cross-build port with high confidence; an `engine2.dll` synthetic dump with runtime state written in |

Each Pinned class checks the installed DLL's size and mtime against the recorded build. A match runs the
tests; any difference turns the whole class into a skip. A game update means skipped tests, not failures.
The `Generic*` classes skip themselves on non-Windows or when `kernel32.dll` is missing.

## Re-pinning after a game update

1. Run the current tests to see which Pinned classes skipped.
2. For each one, update its build tuple at the top of `test_s2re.py` to the new size and mtime:
   ```python
   CS2_CLIENT = ("cs2", "client", <new size>, <new mtime>)
   ```
   `python scripts/s2re.py -g cs2 info` prints both.
3. Re-run the tests; the pinned values inside each class (counts, offsets, specific addresses) will likely
   fail. For each failure, read the new value from s2re output (`schema`, `cvar --list`, `concmd --list`,
   `iface`, `rtti`, `sig`, `port --old <snapshot>`) and update the expected value in the test.

Pin a port test by running `port <old rva>` from the previous build's snapshot to the new one; the test
expects `high` confidence with the known anchors.

## Synthetic dumps

`tests/synth_dump.py` builds a module dump from a DLL on disk: sections mapped at their RVAs, DIR64 pointers
rebased to a chosen VA (`0x7ffb12340000` and `0x7ffa55550000` in the suite), optional runtime writes applied
on top. This is what `GenericDump` and `PinnedEngine2Dump` run against. A real dump has not been tried, so
the "assumed" entries under *Module dumps* in [../references/layouts.md](../references/layouts.md) still
need confirming.

`PinnedEngine2Dump` writes into its synthetic CS2 `engine2.dll`:
- an inline hook (patched prologue, `jmp` leaving the image) at a known function;
- a redirected vtable slot on a `std::exception`-shaped RTTI vtable;
- every runtime write a Source 2 module does: schema class self-pointers at `+0x00`, convar data pointers at
  `+0x08`, the `InterfaceReg` linked list head and node fields.

Each Source 2 parser must still read the disk answers through the dump, and `dumpdiff` must report exactly
the written qwords plus the hook and the redirected slot.

## Running a subset

```bash
python -m unittest tests.test_s2re.Pure -v                      # no DLL needed
python -m unittest tests.test_s2re.PinnedCS2Client -v           # one game's pinned facts
python -m unittest tests.test_s2re.PinnedCS2Client.test_schema -v
```

The CLI itself is exercised through `run_cli(...)` in a few places; `--json` output is parsed back and
compared, so changes to the output format show up as failures there.
