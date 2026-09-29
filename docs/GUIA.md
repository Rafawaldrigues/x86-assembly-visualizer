# ASM X Manual

Desktop tool to read, validate, test and debug x86-64 assembly.
Written in Python with Tkinter — the same GUI toolkit IDLE uses.

## Running

```bash
python3 asmx.py                       # graphical interface
python3 -m asmx check program.asm     # command line
```

The only requirement beyond Python 3.9+: Tkinter (and only for the interface —
the command line works without it, which also holds for a minimal container).

| System | How to install |
|---|---|
| Debian/Ubuntu | `sudo apt install python3-tk` |
| Fedora | `sudo dnf install python3-tkinter` |
| Arch | `sudo pacman -S tk` |
| Windows/macOS | ships with the official Python installer |

Nothing is downloaded, nothing leaves the machine, there is no server.

## Command line

The same analysis as the interface, without the interface — and with JSON output
for CI.

```bash
asmx check program.asm                       # validates; exits 1 when it finds a problem
asmx check a.asm b.asm --min-severity error  # only error fails the check
asmx check program.asm --json                # structured report
asmx run program.asm                         # runs on the virtual machine
asmx run program.asm --entry sum_until       # starts at a function, with a clean stack
asmx run program.asm --stdin "text" --trace --max-trace 20
asmx run slow.asm --timeout 2 --limit 500000
asmx explain program.asm --line 12           # explains line 12
asmx explain program.asm --mnemonic div      # documents the instruction
asmx examples --list                         # the 9 examples
asmx examples --dump examples/               # writes them all as .asm
asmx info --json                             # version, instruction set and configuration
```

Exit codes: `0` all good, `1` problems found, `2` usage error, `3` input error
(file, format, configuration, label), `4` time limit.

Global options, before or after the command: `-v` (debug log), `-q` (quiet),
`--log-json`, `--log-file PATH`, `--config PATH`, `--no-color`.

## Report

`asmx report prog.asm` puts everything the analysis found into one self-contained
HTML file: CSS, JavaScript and the SVG graphs are embedded, so it opens offline,
without a CDN and without a server — it can be attached to an e-mail or a commit.

```bash
asmx report prog.asm                        # writes results/prog.report.html
asmx report prog.asm --open                 # writes and opens it in the browser
asmx report prog.asm --out - --format md    # Markdown on the screen
asmx report prog.asm --format json          # raw data (asmx-report/1 schema)
asmx report prog.asm --format dot | dot -Tsvg -o graph.svg
asmx report prog.asm --no-emulate           # static only, no timeline
asmx report prog.asm --fail-on high         # exits 1 if the risk is high or higher
```

The report tabs:

| Tab | What it shows |
|---|---|
| Summary | hashes, size, dialect, platform and ABI, detection hints, executive summary and the risk score (0–100) |
| Flow | control-flow graph and call graph in SVG, basic blocks with "comes from"/"goes to" and the DOT to copy |
| Behaviors | what the program does: severity, confidence, per-line evidence and the MITRE ATT&CK mapping (an indicator, not proof) |
| Indicators | strings, URLs, IPv4, domains, paths, registry keys, commands and sensitive extensions |
| Instructions | every instruction with its explanation, with a search filter |
| Validation | the problems by severity, with the fix hint |
| Execution | output, exit code, registers, flags, problems and the step-by-step timeline |
| Data | the full JSON, to copy or consume |

### Several files at once

```bash
asmx analyze examples/ --out results/             # one report per file + index.html
asmx analyze examples/ --format json --no-index   # batch as JSON
asmx analyze examples/ --fail-on medium           # fails if any of them goes above medium
```

The `index.html` compares the files in a table — risk, platform, instructions,
behaviors, indicators and problems — which is the fastest way to see what stands
out in a directory before opening file after file.

In the interface the same report comes from *Run › Generate report...*
(`Ctrl+R`): pick the path, the file is written and opened in the browser.

## Configuration

ASM X works without any configuration file. When you want to pin limits, create
an `asmx.yaml`, an `asmx.json` or a `~/.config/asmx/config.yaml` — or point to
one with `--config`.

Precedence order: command line → environment variables → file → defaults.

| Field | Default | What it is for |
|---|---|---|
| `timeout` | 30 | wall-clock seconds before a run is stopped |
| `max_steps` | 200000 | limit of executed instructions |
| `max_memory` | 512 | memory reserved for the sandbox, in MB |
| `enable_network` | false | reserved: the virtual machine never accesses the network |
| `log_level` | INFO | DEBUG, INFO, WARNING, ERROR or CRITICAL |
| `log_json` | false | JSON log, one line per event |
| `log_file` | — | file that receives a copy of the logs |
| `workers` | 4 | parallelism in future multi-file analyses |
| `output_dir` | results | directory for the reports |
| `strict` | false | turns a detected problem into an exception |

```bash
ASMX_TIMEOUT=5 ASMX_LOG_JSON=1 asmx run program.asm
asmx --config asmx.json check program.asm
```

YAML requires PyYAML to be installed; JSON always works, because the project has
no mandatory dependency.

## Logging

The log is structured: each line is a named event (`check_finished`,
`project_saved`, `scenario_finished`...) with its own fields. As text it stays
readable; as JSON it becomes data for `jq`, for CI and for Docker.

```bash
asmx -v check program.asm
asmx -v --log-json check program.asm 2>&1 | jq -c '{event, path, errors}'
asmx -v --log-file asmx.log check program.asm
```

In the library, use `asmx.configure_logging(...)` and
`asmx.get_logger(__name__)`; the function
`asmx.log_event(logger, "my_event", field=1)` emits an event.

## Errors

Every library exception has a stable code and context, and is still a
`ValueError`, `KeyError`, `FileNotFoundError` or `TimeoutError` for code that
already handled it that way:

| Code | When it happens |
|---|---|
| `ERR_SOURCE_NOT_FOUND` | the file does not exist |
| `ERR_SOURCE_READ` / `ERR_SOURCE_WRITE` | read or write failure |
| `ERR_UNSUPPORTED_SOURCE` | extension outside the accepted ones |
| `ERR_PROJECT_FORMAT` | `.asmproj` corrupted or from another program |
| `ERR_BRANCH_NOT_FOUND` / `ERR_BRANCH_EXISTS` / `ERR_BRANCH_LAST` | branches |
| `ERR_SCENARIO` | invalid scenario or one with a label that does not exist |
| `ERR_CONFIG` | missing configuration or out of range |
| `ERR_EMULATION` | a run that could not start |
| `ERR_TIMEOUT` | time limit exceeded |
| `ERR_UNKNOWN_MNEMONIC` / `ERR_LINE_NOT_FOUND` | `explain` queries |

```python
from asmx.errors import AsmxError

try:
    analysis = asmx.analyze(open(path, encoding="utf-8").read())
except AsmxError as error:
    print(error.code, error.message, error.context)
```

## The screen

```
┌──────────────────────────────────────────────────────────────────────────┐
│ menu · current branch · Validate · Step · Run · Reset · platform         │
├───────────────┬────────────────────────────────────┬─────────────────────┤
│ Structure     │ editor with numbers, breakpoints   │ Machine             │
│ of the code   │ and highlighting                   │ Docs                │
│               ├────────────────────────────────────┤ Notes               │
│ data          │ Problems · Output · Tests ·        │                     │
│ functions     │ Execution history                  │                     │
│ blocks        │                                    │                     │
├───────────────┴────────────────────────────────────┴─────────────────────┤
│ Ln, Col · branch · count · problem summary · last action                 │
└──────────────────────────────────────────────────────────────────────────┘
```

**Code structure** shows data, functions and basic blocks. Each block shows
"comes from" and "goes to", with the reason for the branch. Double-click to jump
to the line.

**Editor**: syntax highlighting, line numbers, a red breakpoint dot (click the
gutter), a green background on the line about to execute, a red background on
the lines with an error, ✎ on annotated lines.

**Machine**: the 16 registers (whatever changed in the last step turns gold),
flags, the top of the stack with the return address marked, and the content of
each variable in bytes and as text.

**Docs**: as you move the cursor, it shows what that line does — instruction,
label, directive or data — together with the mnemonic entry and the explanation
of the registers involved. There is prefix search across the 148 mnemonics.

## Shortcuts

| Key | What it does |
|---|---|
| F5 | validate the code |
| F7 | run up to the cursor line |
| F8 | execute one step |
| F9 | run to the end or to the next breakpoint |
| F10 | reset the machine |
| F11 | run all test scenarios |
| Ctrl+R | generate the analysis report and open it in the browser |
| Ctrl+/ | comment or uncomment the selection |
| Ctrl+E | annotate the current line |
| Ctrl+B | new branch |
| Ctrl+S / Ctrl+O / Ctrl+N | save / open / new project |
| Ctrl+F / Ctrl+G | find / go to line |

## Project, branches and notes

Everything lives in a single `.asmproj` file (readable JSON). Inside it:

- **branches**: variations of the same program. `Ctrl+B` copies the current code
  into a new branch, with the notes and the scenarios along with it. Switch
  branches with the box in the top bar. *Branch › Compare with another branch...* shows
  the colored diff.
- **notes**: comments that do not pollute the `.asm`. `Ctrl+E` on the line, and
  it gets a ✎ in the gutter. They are listed in the Notes tab.
- **breakpoints**: saved together with the branch.
- **test scenarios**: described below.

To take the code to NASM, use *File › Export branch as .asm...*.

## Test scenarios

A scenario is an initial state plus an expectation:

| Field | What it is for |
|---|---|
| Start at | label where the execution starts. Empty = the whole program. Choosing a function runs **only it**, with a clean stack |
| Initial registers | `rdi=1000000, rsi=0x20` — this is how you pass an argument to the function under test |
| Simulated input | what the `read` syscall returns |
| Expected output | compares with what the program wrote |
| Expected exit code | compares with the value passed to `exit` |
| Passes if it reports a problem | inverts the logic: the test passes when the run detects overflow, an infinite loop, division by zero… |
| Instruction limit | safety catch against an infinite loop |

The typical flow for "what if the number is too high":

1. `Ctrl+B` → branch `high-value`.
2. **Tests** tab › **New** → start at `sum_until`, `rdi=0xFFFFFFFFFFFFFFFF`,
   limit 3000, check *passes if it reports a problem*.
3. **Run all** (F11). The detail below shows on which line the sum overflowed
   64 bits and how many instructions ran until then.
4. The `main` branch stays untouched.

## The validator

F5 runs 15 checks over the code, producing 34 problem codes. Every finding has a
code, a line, an explanation and a fix hint (click the item to read the hint in the
bar below the list).

### Strings

| Code | What it catches |
|---|---|
| STR001 | non-ASCII character in the string (an accent becomes 2+ bytes; `$ - msg` will not match the number of letters) |
| STR002 | unterminated quotes |
| STR003 | string without a trailing `0` handed to `printf`, `MessageBox` and the like |
| STR004 | literal control character inside the string |
| STR005 | backslash that may not be an escape in this syntax |
| STR006 | string without a terminator and without `equ $ - label`: nobody knows where it ends |

### Arithmetic and operands

| Code | What it catches |
|---|---|
| DIV001 | `div`/`idiv` without `xor rdx, rdx` or `cqo` before it |
| DIV002 | literal division by zero |
| DIV003 | `div` with an immediate operand (it does not exist) |
| IMM001 | the value does not fit the destination — `mov al, 300` |
| IMM002 | 64-bit immediate outside `mov` |
| SHF001 | shift larger than the operand size |
| MEM001 | `mov [x], 1` without `byte`/`qword`: ambiguous size |
| MEM002 | memory on both sides |
| UNK001 | mnemonic the tool does not know |

### Stack, functions and ABI

| Code | What it catches |
|---|---|
| STK001 | `push` without `pop` before the `ret` |
| STK002 | one `pop` too many: the function eats the caller's stack |
| STK003 | function called with `call` that has no `ret` |
| ABI001 | Windows call without the 32 bytes of shadow space |
| ABI002 | callee-saved register changed without saving it |
| REG001 | register read before it receives any value |

### Symbols, flow and system

| Code | What it catches |
|---|---|
| SYM001 | `jmp`/`call` to a label that does not exist |
| SYM002 | label never used |
| SYM003 | symbol used in a memory operand and never defined |
| ENT001 / ENT002 | no entry point / `_start` without `global` |
| EXIT001 | program with no explicit exit |
| FLOW001 | block that nothing reaches |
| FLOW002 | loop that changes nothing: infinite |
| SYS001 | `syscall` without setting RAX in the block |
| SYS002 | RCX or R11 read after the `syscall` (they are destroyed) |
| SEC001 / SEC002 | code outside `.text` / write to `.rodata` |

## Debugging a function in isolation

*Run › Debug single function...* starts execution at the chosen label with a clean
stack. Its `ret` ends the simulation instead of reporting a stack error. Combine
it with a scenario to set up the input registers.

## Honest limits

The virtual machine is didactic, not a CPU emulator:

- it does not assemble or link anything; it generates neither `.o` nor an
  executable;
- it executes the integer essentials: SSE/floating point appears in the
  documentation but is not simulated;
- NASM macros (`%macro`, `%define`) and `struc` are read as directives, without
  expansion;
- emulated Linux syscalls: `write`, `read`, `exit`, `exit_group`, `getpid`,
  `time`, `brk`, `getrandom`, `nanosleep`. The others return 0 and warn;
- Windows API: `ExitProcess`, `GetStdHandle`, `WriteConsoleA`, `WriteFile`,
  `MessageBoxA/W`, `Sleep`, `GetLastError`. The others become stubs;
- memory is a dictionary of bytes: there is no paging, no real protection and no
  segmentation — the validator warns about `.rodata`, the execution does not;
- the result of a run here **does not** guarantee that the real binary works. It
  is there to help you understand and to find defects early;
- the behavior classifier and the MITRE ATT&CK mapping are **indicators** read
  from static patterns (syscalls, APIs, loops, strings), with evidence and
  confidence. They are not proof of intent and do not replace an analyst;
- the report is a single file and **makes no network request**: no CDN, no remote
  font, no telemetry. The MITRE links are references, not loaded resources.
