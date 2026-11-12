# src2re

Offline reverse engineering tools for Source 2 game binaries.

Currently tested with Counter-Strike 2 and Deadlock. Additional presets are available for Dota 2 and Half-Life: Alyx.

## Features

- **Function and string search** — Find functions, strings, console variables, commands, and their references.
- **Schema inspection** — Browse classes, fields, inheritance, and offsets.
- **Code analysis** — Inspect callers, callees, cross-references, and vtables.
- **Signature tools** — Generate, convert, and validate signatures across game versions.
- **Update comparison** — Locate functions and data that have moved between builds.
- **Disassembler exports** — Generate naming scripts for IDA, Ghidra, and Binary Ninja.
- **Engine interfaces** — Inspect registered interfaces and their implementations.
- **Protobuf extraction** — Extract embedded network message definitions as `.proto` files.
- **Memory dump comparison** — Compare a supplied module dump against its on-disk version.

## AI-assisted reverse engineering

Recent improvements in AI models' ability to understand x64 assembly make offline reverse engineering increasingly practical.

With src2re providing binary information, models can inspect functions, follow references, analyze structures, and compare different builds without requiring access to a running game.

This is particularly useful for maintaining projects across game updates. Updated binaries can be analyzed directly to locate relocated functions, recover offsets, and generate new signatures. Some cases still require runtime analysis or manual verification, but much of this work can be done offline.

An agent skill and additional documentation are included for AI-assisted usage.

## Installation

**Requirements:** Windows, Python 3.9+, and [Capstone](https://www.capstone-engine.org/).

```bash
git clone https://github.com/taylorswiftfan22/src2re
cd src2re
pip install capstone
```

## Usage

```bash
# General information
python scripts/s2re.py -g cs2 info

# Search a console variable
python scripts/s2re.py -g cs2 cvar sv_cheats

# Inspect a schema class
python scripts/s2re.py -g cs2 schema C_CSPlayerPawn --flat

# List engine interfaces
python scripts/s2re.py -g cs2 -m engine2 iface

# Export schema definitions
python scripts/s2re.py -g cs2 schema --dump --format cpp -o client_schema.hpp
```

Use `-g` to select a game and `-m` to select a module. Run `python scripts/s2re.py --help` for the full command reference.

## Supported games

| Game | Status |
|---|---|
| Counter-Strike 2 | Tested |
| Deadlock | Tested |
| Dota 2 | Untested |
| Half-Life: Alyx | Untested |

Other compatible 64-bit Windows DLLs can also be supplied manually.

## Documentation

Additional documentation is included in the repository:

- [`scripts/README.md`](scripts/README.md) — Library and module reference.
- [`references/layouts.md`](references/layouts.md) — Binary layouts and verification details.
- [`tests/README.md`](tests/README.md) — Test documentation.

## Disclaimer

Not affiliated with or endorsed by Valve. The tool operates on game files and user-supplied dumps; it does not attach to or inject into running games.

## License

[MIT](LICENSE)
