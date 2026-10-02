# ASM X

ASM X is a small x86-64 assembly simulator and source viewer written in Python.
It has a Tkinter editor and a command line interface. You can step through a
program, inspect registers and memory, and check common mistakes before using
an assembler.

It reads a subset of NASM/Intel, MASM and GAS/AT&T syntax. It does not assemble
source or run native binaries. The instruction reference covers more
instructions than the simulator implements; unsupported operations are reported.

## Run

Requires Python 3.9 or newer. The core uses the standard library. The desktop
interface also needs Tkinter (`python3-tk` on Debian/Ubuntu or
`python3-tkinter` on Fedora).

```sh
git clone https://github.com/Rafawaldrigues/x86-assembly-visualizer.git
cd x86-assembly-visualizer
python3 asmx.py
```

In the window, use **File > Open sample** to load a program. **F5** checks the
source, **F8** steps, **F9** runs and **F10** resets. Click the line-number gutter
to set a breakpoint. Registers, flags, data and the stack are shown beside the
editor. The light interface follows the layout conventions of older desktop
assembly tools, including [MARS](https://dpetersanderson.github.io/).

To use the command line without installing the package:

```sh
python3 -m asmx check examples/linux-hello.asm
python3 -m asmx run examples/linux-function.asm --trace
python3 -m asmx explain examples/linux-hello.asm --line 13
python3 -m asmx report examples/bubble.asm --out results/bubble.html
python3 -m asmx --help
```

`python3 -m pip install .` installs the `asmx` and `asmx-gui` commands.

## Memory checks

The simulator checks whether a memory access fits inside an allocated region
and whether that region is writable. It reports invalid reads and writes,
stack overflow/underflow, uninitialized reads and exhausted simulated memory.
A fatal memory error stops at the offending instruction and appears in the
execution history, CLI output and reports.

```sh
python3 -m asmx run program.asm --max-memory 16 --json
```

`--max-memory` is an allocation budget in MiB, with a default of 512 and a CLI
minimum of 16. It includes declarations, heap allocation through simulated
`brk`, and stack usage. It is **not a limit on the Python process's RAM**.
See [Memory](docs/MEMORY.md) for examples, diagnostic codes and limitations.

## Other tools

- Save branches, line notes, breakpoints and test scenarios in an `.asmproj` file.
- Export analysis as HTML, Markdown, JSON, SVG, DOT or Mermaid.
- Scan source with JSON signature rules and inspect their matching lines.
- Compare files by static features with `cluster`.
- Generate a folder of reports with `analyze`, then browse it with `dashboard`.

Behavior labels, signature matches and risk scores are heuristics. They are not
proof that a program is malicious, safe or correct. Passing the checks does not
replace testing with an assembler and a native debugger.

## Documentation

- [User guide](docs/GUIDE.md)
- [Instruction reference](docs/REFERENCE.md)
- [Memory model and diagnostics](docs/MEMORY.md)
- [Examples](docs/WALKTHROUGHS.md)
- [Signature rule format](docs/RULES.md)
- [Contributing](CONTRIBUTING.md)
- [Changes](CHANGELOG.md)
- [Security policy](.github/SECURITY.md)

## Development

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements-dev.txt
make test
make quality
```

GUI tests need a display; on headless Linux, install `xvfb` and `xauth` and use
`make test-gui`. CI runs the tests, coverage, lint, type checks and generated-file
checks. Test and coverage results belong to those runs, rather than fixed
numbers in this README.

MIT license. See [LICENSE](LICENSE).
