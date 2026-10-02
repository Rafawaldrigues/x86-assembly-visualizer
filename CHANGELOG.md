# Changelog

## Unreleased

- Use a classic light theme in the desktop interface, HTML reports and dashboard.
- Shorten the README, remove promotional artwork and stale screenshots, and
  replace `GUIA.md` and `REFERENCIA.md` with `GUIDE.md` and `REFERENCE.md`.
- Use `main` for new project branches; preserve names in existing projects.
- Enforce a per-machine simulated memory budget through the CLI, GUI, scenarios
  and reports. Add `--max-memory` and structured memory diagnostics.
- Store memory in sparse pages and check declarations before expanding initializers.
- Check access bounds, read-only regions, stack bounds and partially
  uninitialized reads. Treat BSS as initialized zero-filled memory.
- Model `brk` heap growth and shrinkage. Report exhausted budgets as fatal errors.
- Include memory usage and faults in run JSON and analysis reports.
- Give `main` and `WinMain` a synthetic return address, as for isolated functions.
- Apply configured execution timeouts to CLI runs and report simulations.
- Add signature scanning, feature-based similarity grouping, a local report
  dashboard and parallel batch analysis with a JSON manifest.
- Generate the instruction reference from the same catalog used by the application.

## 1.0.0 — 2026-09-21

- Source parser for common NASM/Intel, MASM and GAS/AT&T forms.
- Platform detection, instruction explanations, control-flow analysis and
  checks for common assembly mistakes.
- Integer instruction simulation with register, flag, stack and output views.
- Tkinter editor with breakpoints, branch comparison, notes and test scenarios.
- CLI commands for validation, execution, explanations and reporting.
- Static behavior classification, indicator extraction and control-flow/call graphs.
- HTML, Markdown, JSON, DOT, SVG and Mermaid exports.
- Configuration files, logging, packaging, Docker support and CI checks.
