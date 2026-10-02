# User guide

## Starting ASM X

From the source directory, run `python3 asmx.py` or `python3 -m asmx` for the
window. Run `python3 -m asmx --help` for the CLI. After `pip install .`, the
commands are `asmx` and `asmx-gui`.

Python 3.9+ is required. Tkinter is needed only for the window. On Linux it may
be packaged separately as `python3-tk` (Debian/Ubuntu), `python3-tkinter`
(Fedora), or `tk` (Arch).

## Editor and debugger

Use **File > Open sample** for bundled programs, or **Import .asm file...** for
an existing source. The structure tree lists symbols and blocks. The editor
shows syntax, line numbers, breakpoints and the next instruction in yellow.

The **Registers** tab shows register values, flags, memory usage, data and the
stack. Blue register values changed during the last step. **Reference** contains
instruction help; **Notes** contains annotations saved with the project.
The lower tabs contain validation problems, output, scenarios and execution
history. Select a problem to read its hint; double-click to visit the source.

| Key | Action |
| --- | --- |
| F5 | Validate source |
| F7 | Run to cursor |
| F8 | Step one instruction |
| F9 | Run to completion, a fault or a breakpoint |
| F10 | Reset registers, memory and execution history |
| F11 | Run all scenarios |
| Ctrl+R | Save an analysis report |
| Ctrl+/ | Comment or uncomment selected lines |
| Ctrl+E | Annotate the current line |
| Ctrl+B | Create a branch |
| Ctrl+S / Ctrl+O / Ctrl+N | Save / open / new project |
| Ctrl+F / Ctrl+G | Find / go to line |

**Run > Debug single function...** selects a label. The simulator pushes a
synthetic return address so `ret` can finish the isolated run. Use a test
scenario when you also need to set argument registers.

## Projects and scenarios

An `.asmproj` file is JSON containing source branches, notes, breakpoints and
scenarios. New projects start with a `main` branch. Existing branch names are
preserved when loading an older project, including names in other languages.
Branches are variations within the project file, not Git branches.

A scenario can set an entry label, initial registers, simulated input, expected
output, expected exit code and an instruction limit. Check **Passes if it reports
a problem** for a case that should produce a diagnostic. Memory errors count
as problems. A GUI scenario uses the window's configured memory budget.

**File > Export branch as .asm...** writes just the assembly source.

## CLI commands

The following examples use `python3 -m asmx`; installed users can use `asmx`.

```sh
python3 -m asmx check program.asm
python3 -m asmx check a.asm b.asm --min-severity error --json
python3 -m asmx run program.asm --limit 10000 --timeout 2 --max-memory 16
python3 -m asmx run program.asm --stdin "input" --trace --max-trace 20
python3 -m asmx run examples/linux-function.asm --entry add_pair
python3 -m asmx explain examples/linux-hello.asm --line 13
python3 -m asmx explain examples/linux-hello.asm --mnemonic div
python3 -m asmx examples --list
python3 -m asmx info --json
```

`check` is static validation. `run` executes the supported subset in Python.
A static check need not find a fault that depends on register values at runtime.
See [Memory](MEMORY.md) for the memory diagnostics.

| Exit status | Meaning |
| --- | --- |
| 0 | Command succeeded; no failure condition was met |
| 1 | Problems found or a requested failure threshold reached |
| 2 | Invalid command line |
| 3 | Input or configuration error |
| 4 | Execution timeout |

A memory fault in `run` returns 1. The simulated program's exit code is a
separate field. Reports use `--fail-on` to choose a failure condition; merely
writing a report containing execution issues does not make that command fail.

## Reports, rules and comparison

```sh
python3 -m asmx report program.asm --out results/program.html
python3 -m asmx report program.asm --format json --out results/program.json
python3 -m asmx report program.asm --no-emulate --format md
python3 -m asmx analyze examples/ --out results --jobs 2
python3 -m asmx scan examples/suspicious.asm --json
python3 -m asmx rules
python3 -m asmx cluster examples/ --threshold 0.85
python3 -m asmx dashboard results --open
```

HTML reports contain their styles, scripts and graphs and can be opened offline.
`--open` opens a generated report in the browser. Exports include HTML, Markdown,
JSON, DOT, SVG and Mermaid. Rules are described in [RULES.md](RULES.md).

`analyze` writes per-file reports and an `index.json` manifest. Each worker has
its own simulation budget: `--jobs 4 --max-memory 16` is not a shared 16 MiB
limit. `cluster` uses feature vectors and cosine similarity, with single or
complete linkage. It does not use a trained model.

The dashboard serves a results directory on `127.0.0.1` by default. Binding to
another interface enables token authentication. It is a report viewer with
read-only routes, not a way to execute assembly remotely.

## Configuration

Use `--config asmx.json` to select a file. Without that option ASM X searches the
current directory, then `~/.config/asmx` and `~/.asmx`, for `asmx.yaml`,
`asmx.yml`, `asmx.json`, `.asmx.yaml` or `.asmx.json`. `ASMX_CONFIG` can also name
a file. YAML requires the optional PyYAML package; JSON needs no extra package.

Precedence is command line, environment, file, then defaults.

```json
{
  "timeout": 5,
  "max_steps": 100000,
  "max_memory": 16,
  "output_dir": "results"
}
```

```sh
python3 -m asmx --config asmx.json run program.asm
python3 -m asmx --config asmx.json --gui
ASMX_MAX_MEMORY=16 python3 asmx.py
```

| Field | Default | Meaning |
| --- | --- | --- |
| `timeout` | 30 | Execution time budget in seconds; checked between steps |
| `max_steps` | 200000 | Instruction limit |
| `max_memory` | 512 | Simulated allocation budget in MiB, minimum 16 |
| `output_dir` | `results` | Report destination |
| `workers` | 4 | Reserved configuration; pass `analyze --jobs N` to select workers |
| `log_level` | `INFO` | Library logging level |
| `log_json` | `false` | Structured log output |
| `log_file` | `null` | Optional log destination |
| `enable_network` | `false` | Reserved; does not enable simulated network calls |
| `strict` | `false` | Reserved; currently does not change execution behavior |

Environment names use the `ASMX_` prefix, such as `ASMX_TIMEOUT`,
`ASMX_MAX_STEPS` and `ASMX_MAX_MEMORY`. In the CLI, `-v` enables debug logging
and `-q` reduces logging to errors. `--log-json` and `--log-file PATH` control
the format and destination. Logs go to stderr; command results go to stdout.

## Limits

The parser accepts common forms of NASM/Intel, MASM and GAS/AT&T. It is not a
complete assembler frontend: macros are not expanded and some expressions and
data directives are unsupported. The reference describes instructions that the
simulator may not implement. SSE and floating-point execution are incomplete.
Unsupported instructions and system calls produce diagnostics; some stubs
return zero so later register values may be unreliable.

Linux `read`, `write`, `exit`, `exit_group`, `getpid`, `time`, `nanosleep`,
`brk` and `getrandom` have simplified implementations. Windows support includes
`ExitProcess`, `GetStdHandle`, `WriteConsoleA`, `WriteFile`, `MessageBoxA/W`,
`Sleep` and `GetLastError`; these do not reproduce the complete native APIs.

The execution model is primarily 64-bit. Some 32-bit instruction forms and
`int 0x80` calls are recognized, but this is not a full i386 process model.
Memory checks and risk scores do not establish that a native binary is correct
or safe. The simulator is not an operating-system security sandbox.
