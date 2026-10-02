# Contributing

Bug reports should include a small source file, what you expected, what happened
and the output of `python3 -m asmx info --json`. For a new instruction or check,
include an assembly example showing the intended behavior.

## Setup

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements-dev.txt
make test
make quality
```

The core uses Python 3.9+ and the standard library. Tkinter tests require a
display. Use `make test-gui` with `xvfb` and `xauth` on headless Linux. Windows
users can activate `.venv\Scripts\activate` and run the Python commands from
the Makefile directly.

## Code

Use English for documentation, comments, identifiers and UI messages. Keep
messages specific: describe the operation, source line and reason for failure.
Preserve user-supplied names and text, including existing project branch names.

Format with Black at 100 columns. CI checks flake8, mypy, function annotations,
docstrings and coverage. Run the relevant tests while editing and `make quality`
before submitting. Add regression tests for behavior changes; documentation and
simple styling changes do not need tests that repeat the implementation.

The instruction dispatch remains in `asmx/emulator.py`; allocation and region
checks live in `asmx/memory.py`. A new memory operation must validate the full
range before a scalar or buffer write. Test the successful case, boundaries,
permissions and exhausted budgets. Do not call native syscalls from the simulator.

## Generated files

Edit `asmx/data/isa.json` for instruction reference changes, then run:

```sh
python3 tools/build_reference.py
python3 tools/build_reference.py --check
```

Edit `asmx/examples.py` for bundled examples, then run:

```sh
python3 tools/export_examples.py
python3 tools/export_examples.py --check
```

Keep runnable examples small and comments factual. Mark intentional defects.
Avoid fixed test counts, coverage claims, benchmark numbers or release promises
in documentation; link to the relevant checks or explain how to reproduce them.

## Rules and validation

Static checks are functions in `asmx/linter.py`, registered in `ALL_CHECKS`.
Each finding has a stable code, severity, line, message and optional hint.
Signature rules live in `asmx/data/rules/`; see [the format](docs/RULES.md).
Test intended matches and ordinary programs that should not match.

## Pull requests

Describe the problem, the resulting behavior and the validation performed.
Update affected documentation and the unreleased section of [CHANGELOG.md](CHANGELOG.md).
Keep generated-file changes with the source changes that produce them.

Report security issues through the [security policy](.github/SECURITY.md).
The [code of conduct](CODE_OF_CONDUCT.md) applies to project discussions.
