# Security policy

Report vulnerabilities through [GitHub's private reporting form](https://github.com/Rafawaldrigues/x86-assembly-visualizer/security/advisories/new).
Include the affected version, Python version, operating system, reproduction
steps and a minimal input file. If private reporting is unavailable, open an
issue asking for a private contact without publishing exploit details.

Fixes target the current development branch. There is no guaranteed response
time or support end date.

## Execution model

ASM X parses assembly source and simulates supported instructions in Python.
Simulated file and network calls do not perform those operations on the host.
It does not assemble or execute native binaries.

This does not make the application a security sandbox. A crafted source,
project, rule file or report may expose a parser bug, excessive resource use,
unsafe rendering or another application defect. Memory budgets cover the
simulated address space, not the entire Python process. See [the memory model](../docs/MEMORY.md).

Reports of resource exhaustion, path traversal, unintended file access,
script injection or other application vulnerabilities are welcome. Missing
instruction support alone is a feature request; a crash or unsafe fallback
caused by that instruction may still be a bug.

The dashboard binds to loopback by default. Publishing it on another interface
requires authentication and appropriate network restrictions. If source is
later assembled outside ASM X, that binary executes with the permissions of
its native environment; the simulator's findings provide no safety guarantee.
