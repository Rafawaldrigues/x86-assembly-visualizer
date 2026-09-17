# ASM X

A desktop environment for studying, validating, testing, and debugging x86-64
assembly. Built with Python and Tkinter—no server or external dependencies.

```bash
python3 asmx.py          # Linux/macOS/Windows (Linux needs python3-tk)
```

## Features

- **Reads and explains code:** every instruction receives a label (such as
  "Writes to memory", "Jumps if equal", or "System call") and a plain-language
  description of its effect. Labels, data, and directives are covered too.
- **Control-flow map:** functions and basic blocks with their incoming and
  outgoing paths, including the reason for every branch.
- **Platform detection:** identifies Linux or Windows, explains the evidence,
  and shows the corresponding ABI.
- **Static validation:** 30 rules catch issues such as strings with no
  terminator, `div` without clearing RDX, unmatched `push`/`pop`, `mov al, 300`,
  infinite loops, missing Windows shadow space, unknown labels, and writes to
  `.rodata`.
- **Step-by-step execution:** inspect registers, flags, stack, and memory;
  set gutter breakpoints and review a history of each instruction's effects.
- **Branches:** keep variations of the same program within a project and
  compare them with a diff.
- **Test scenarios:** define an initial state and expected outcome, then run an
  isolated function or the whole program—useful for questions like "what
  happens if this value is huge?"
- **Per-line annotations:** stored in the project, separately from `.asm`
  source files.
- **Documentation:** reference material for 148 mnemonics, 43 Linux syscalls,
  and key kernel32/user32 functions (currently in Portuguese).

## Project layout

```
asmx.py               launches the interface
asmx/
  isa.py              instruction, register, flag, and syscall data
  parser.py           NASM/Intel, MASM, and GAS/AT&T parser
  analyzer.py         platform, semantics, blocks, and control flow
  emulator.py         virtual machine and runtime issue detection
  linter.py           static validation (30 rules)
  workspace.py        projects, branches, annotations, and scenarios
  examples.py         eight example programs
  ui/                 Tkinter interface (editor, dialogs, theme)
  data/isa.json       documentation data
docs/GUIA.md          user guide (Portuguese)
docs/REFERENCIA.md    148-mnemonic reference (Portuguese)
tests/                141 tests
```

## Tests

```bash
python3 -m unittest discover -s tests               # core
xvfb-run -a python3 -m unittest discover -s tests   # includes the GUI headlessly
```

GUI tests are skipped automatically when no display is available.

## Scope and limitations

ASM X does not assemble, link, or run real binaries. Its virtual machine covers
the essential integer operations; SSE, NASM macros, and most syscalls are not
simulated (although their documentation is still available). It does not replace
`nasm` + `ld` + `gdb`; it helps you understand code and catch issues earlier.

See `docs/GUIA.md` for complete details and limitations (Portuguese).
