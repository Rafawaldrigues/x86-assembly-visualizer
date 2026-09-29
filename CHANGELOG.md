# Changelog

All notable changes to ASM X are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **Signature rules** (`asmx/rules.py`, `asmx scan`, `asmx rules`): a
  dependency-free, YARA-like engine for assembly source. 22 rules ship inside
  the package (`asmx/data/rules/*.json`), in five themed files; a rule declares
  `id`, `name`, `severity`, `description`, `tags`, `mitre` and a `match` object
  whose keys are ANDed (`strings` with comments removed, `syscalls`, `apis`,
  `behaviors`, `sections`, `mnemonics`, `problems`, numeric thresholds) with
  `any_of` for alternatives and `require_all` for strictness. Every match
  carries the evidence with the line number. Format documented in
  `docs/RULES.md`, and a test asserts that no rule fires on the clean examples.
- **Similarity grouping** (`asmx/similarity.py`, `asmx cluster`, and
  `analyze --cluster`): each analysis becomes a normalised feature vector
  (instruction mix, syscalls, behaviours, indicators, shape), compared with
  cosine similarity and grouped by single or complete linkage over a threshold.
  It is algorithmic similarity — no trained model — and the group reports the
  signal it shares.
- **Local dashboard** (`asmx/dashboard.py`, `asmx dashboard`): a read-only
  viewer for a folder of reports, built on `http.server`, with search, sorting,
  links to the full reports and a JSON API (`/api/samples`, `/api/summary`). It
  binds to the loopback by default, answers only `GET`/`HEAD`, refuses paths
  outside the served folder, escapes sample names and generates a token by
  itself when exposed.
- **Batch manifest and parallel analysis**: `asmx analyze` now always writes
  `index.json` (`asmx-analyze/1`) next to the reports, and accepts `--jobs N`
  to analyse files in parallel processes and `--cluster` to add the groups to
  the index and the manifest.
- **Preview pictures** (`tools/capture_screenshots.py`): regenerates the
  interface and report captures used by the README.
- **Reference generator** (`tools/build_reference.py --check`): the instruction
  reference is generated from the catalogue and verified in `make quality` and
  in CI, so documentation cannot drift from the data.

### Changed

- **The whole project is now in English** (en-US): documentation, catalogue,
  interface, command line, report, rules, tests and code comments. Severities
  are `error`/`warning`/`info`, risk levels `low`/`medium`/`high`/`critical`,
  behaviour severities `high`/`medium`/`low`, and the example keys are
  `linux-hello`, `linux-loop`, `linux-function`, `windows-hello`, `gcc-att`,
  `bubble`, `broken`, `overflow` and `suspicious`.

- Nothing yet. Every new contribution lands here before the next release.

### Changed

- Nothing yet.

### Fixed

- Nothing yet.

## [1.0.0] - 2026-09-21

First stable release. ASM X starts as a desktop environment to study, validate,
test and debug x86-64 assembly — Python + Tkinter, the standard library and no
external dependency.

### Added

- **Reading of three syntaxes**: the parser recognizes NASM/Intel (`mov rax, 1`),
  MASM (directives and `PTR`) and GAS/AT&T (`movq $1, %rax`), including labels,
  sections, data directives and the comments of each dialect. AT&T is normalized
  to Intel order, so the rest of the tool works with a single form.
- **Semantic explanation per instruction**: each line gets an effect tag
  ("Writes to memory", "Branches if equal", "System call") and one sentence
  saying what it does, including the effect on the flags and the role of the
  operand (local variable, parameter, pointer, constant).
- **Platform and ABI detection**: identifies Linux or Windows from the hints in
  the source itself (syscall, `kernel32`, directives, calling convention), shows
  the confidence of the conclusion, the evidence and the calling rules of each
  system.
- **Control-flow map**: functions and basic blocks with "comes from" and
  "goes to", the reason for each conditional branch, the path of each jump and
  the reason for each block exit.
- **Static validation**: 15 checks that produce 34 problem codes in three
  severities (error, warning, information), each one with a fix hint — string
  with an accent, string without a terminator, `div` without preparing RDX,
  `push` without `pop`, immediate that does not fit, ambiguous operand size,
  Windows shadow space, label that does not exist, write to `.rodata`, register
  read before it receives a value, infinite loop, unreachable code and so on.
- **Didactic virtual machine**: runs the assembly directly, without assembling
  or linking anything, with registers, flags, stack and memory in view,
  breakpoints, execution history and detection of overflow, division by zero,
  unbalanced stack and read of never-written memory.
- **Single-file project** (`.asmproj`, JSON) with branches of the same program,
  diff between them, per-line notes, breakpoints and test scenarios — all
  versionable together with the code and outside the `.asm`.
- **Test scenarios**: initial state (where to start, which registers, simulated
  input) plus the expectation (output, exit code or "must report a problem"),
  with an instruction limit and a time limit.
- **Tkinter interface**: editor with highlighting and a breakpoint gutter, code
  structure tree, machine panel, documentation panel, tests panel, dark theme
  and keyboard shortcuts.
- **Complete command line**: `check`, `run`, `explain`, `info`, `examples` and
  `version`, with JSON output, stable exit codes (0/1/2/3/4), `--trace`,
  `--timeout`, `--entry` and `--stdin`.
- **Reference of 148 mnemonics**, grouped by purpose, with syntax, description,
  effect on the flags and usage example — available in the interface and in the
  terminal (`asmx explain prog.asm --mnemonic div`).
- **43 Linux syscalls** documented (number, name, arguments and what they do)
  and the main `kernel32`/`user32` functions of Windows.
- **8 ready-made sample programs**, from the "hello world" with syscall to
  bubble sort, including one with deliberate defects and another that overflows
  with a high value — also written to `examples/*.asm`.
- **Structured logging**: named events with their own fields, as readable text
  or one-line JSON per event, without depending on an external library.
- **Standardized error codes** in `asmx.errors`, with a stable code, structured
  context and compatibility with `ValueError`, `KeyError` and
  `FileNotFoundError`.
- **Configuration by file and environment** (`asmx.yaml`, `asmx.json`,
  `ASMX_TIMEOUT`, `--config`), with validation and messages that say which field
  is wrong.
- **Type hints in 100% of the code**, Google-style docstrings with runnable
  examples and comments in every module.
- **Automated quality gates** (`tools/quality_gates.py`): they reject any
  function without a type hint, without a docstring or with an undocumented
  parameter.
- **Test suite** covering parser, analyzer, validator, virtual machine, project,
  configuration, errors, CLI and interface (the latter under `xvfb`).
- **Continuous integration** with GitHub Actions on Python 3.9 to 3.13: flake8,
  mypy, quality gates, tests with coverage and a check that the package installs
  and runs in an empty `venv`.
- **Security scanning** with bandit and pip-audit, plus the security policy in
  `.github/SECURITY.md`.
- **Docker**: lean image with an unprivileged user, `HEALTHCHECK` and the
  targets `check`, `run`, `test`, `quality` and `gui`.
- **Documentation**: `README.md`, `docs/GUIA.md` (user manual, CLI, report,
  configuration, logging and errors) and `docs/REFERENCIA.md` (the instruction
  reference).
- **Behavior classification**: twelve categories (network, files, process,
  memory, evasion, cryptography, persistence, environment, console, data
  processing, string manipulation, self-compilation) with per-line evidence,
  confidence and mapping to 17 MITRE ATT&CK techniques — always as an indicator,
  never as a verdict.
- **Indicators of compromise**: URLs, valid IPv4, domains, e-mail addresses,
  Unix and Windows paths, registry keys, commands, sensitive extensions, words
  of interest and embedded strings, with a false-positive filter.
- **Graphs**: control flow and calls with deterministic layout, drawn in SVG by
  our own code (no graphics library) and exportable as DOT and Mermaid.
- **Report**: self-contained and offline HTML (embedded CSS, JavaScript and SVG)
  with eight tabs — summary with risk from 0 to 100, flow, behaviors,
  indicators, instructions, validation, execution with timeline and raw data —
  plus export to Markdown, JSON, DOT, SVG and Mermaid.
- **Batch analysis**: `asmx analyze` writes one report per file and an
  `index.html` comparing risk, size, platform, behaviors, indicators and
  problems across all of them.
- **9th teaching example** (`suspicious.asm`): a program that talks to the system
  (socket, file in `/tmp`, random bytes, environment information) so the report
  shows real behaviors and techniques. It is not malware and it executes
  nothing: the virtual machine only interprets the instructions in Python.

### Changed

- **Split of work between step-by-step and continuous mode**: "Step" shows the
  effect of one instruction and stops; "Run" goes to the end, to a breakpoint or
  to a detected problem.
- **Platform detection now explains the conclusion**: besides saying "Linux" or
  "Windows", it lists the hints that led there.
- **Notes moved out of the `.asm` into the project**, so they do not pollute the
  source that would later be assembled for real.
- **Library errors gained a stable code** (`ERR_*`) while remaining a
  `ValueError`, `KeyError` or `FileNotFoundError` for code that already handled
  them that way.
- **The command line became a first-class citizen**: the graphical interface is
  one of the front-ends, not the only one.

### Fixed

Real problems found by the tests and by review, each one with a test case that
reproduces it:

- **`times` with a value** wrote zeros instead of repeating the value:
  `times 3 db 7` now produces three `07` bytes.
- **`INT 0x80` used the 64-bit syscall table**, so the classic 32-bit example
  (`eax=4` for `write`) called the wrong syscall; now the i386 numbers are
  translated and whatever has no equivalent is reported.
- **File with a UTF-8 BOM** left the `\ufeff` character stuck to the first
  mnemonic; reading now recognizes and removes the BOM.
- **Negative displacement in AT&T** (`-8(%rbp)`) was converted to `[rbp+-8]`;
  now it comes out as `[rbp-8]`.
- **`SourceReadError` was not imported** in `workspace.py`, which turned a
  project read error into a `NameError`.
- **Corrupted `.asmproj` project** no longer leaks a raw `JSONDecodeError`: it
  now becomes a `ProjectFormatError` with the file and the line of the problem.
- **Division by zero and quotient overflow** no longer take the simulation down:
  they become a detected problem, explained on the line, with the execution
  stopping quietly.
- **`movsx`/`movzx`/`cdq`/`cqo`** fill the upper bits the way the processor
  does, instead of leaving garbage.
- **Examples and the `examples/*.asm` files** cannot drift apart: a test compares
  the two and `tools/export_examples.py` rewrites them from the single source.
- **False positive with a semicolon inside a string**: the validator cut the
  line at `;` by hand and reported "unterminated quotes" (STR002) on things like
  `db "Mozilla/5.0 (compatible; ASMX/1.0)"`. It now uses the code slice the
  parser already split while respecting the quotes.
- **Report with escaped markup**: cells that contain HTML (chips, links,
  path/hash `span`) appeared as text. They now come out as elements.
- **`--out` into a directory that does not exist** failed with a write error;
  the destination directory is now created.

### Performance

- **Instruction catalogue loaded once per process**, at import time.
- **One disk read per file**, with the hash and the fingerprint computed over
  the same bytes.
- **Parser, analysis and validation work over the same in-memory structure** —
  nothing is re-parsed on every interface query.
- **Editor highlighting scheduled with a delay and cancellation of the previous
  job**, instead of redrawing on every keystroke.
- **The log only formats what the requested level requires**; with no handler
  configured, a library embedded in another program prints nothing.

[1.0.0]: https://github.com/Rafawaldrigues/x86-assembly-visualizer/releases/tag/v1.0.0
