"""Tests of the report: collection, risk and the output formats."""

import contextlib
import io
import json
import os
import re
import tempfile
import unittest

from asmx.errors import ProjectError, SourceWriteError
from asmx.examples import EXAMPLES
from asmx.linter import ERROR, INFO, WARNING, Problem
from asmx.report import (
    FORMATS,
    REPORT_SCHEMA,
    ReportData,
    collect,
    executive_summary,
    guess_format,
    render_dot,
    render_html,
    render_index,
    render_json,
    render_markdown,
    render_svg,
    risk_assessment,
    write_report,
)
from asmx.source import read_source

#: Clean program, used in most cases.
CLEAN = EXAMPLES["linux-hello"]["code"]

#: Program with defects on purpose.
BROKEN = EXAMPLES["broken"]["code"]

#: Program with a function and calls.
FUNCTION = EXAMPLES["linux-function"]["code"]


def report_of(code: str = CLEAN, **kwargs: object) -> ReportData:
    """Collect a report from a piece of code, for the tests.

    Args:
        code: Assembly source code.
        **kwargs: Forwarded to :func:`asmx.report.collect`.

    Returns:
        The collected report.
    """
    return collect(code, **kwargs)  # type: ignore[arg-type]


class TestRisk(unittest.TestCase):
    """The risk calculation has to be explainable."""

    def test_nothing_found_is_low(self) -> None:
        """An empty program has the lowest risk."""
        risk = risk_assessment([], [])
        self.assertEqual(risk["level"], "low")
        self.assertEqual(risk["score"], 0)
        self.assertIn("color", risk)
        self.assertIn("emoji", risk)

    def test_error_weighs_more_than_warning(self) -> None:
        """An error weighs more than a warning, and a warning more than an info."""
        error = risk_assessment([Problem(1, ERROR, "X", "m")], [])["score"]
        warning = risk_assessment([Problem(1, WARNING, "X", "m")], [])["score"]
        info = risk_assessment([Problem(1, INFO, "X", "m")], [])["score"]
        self.assertGreater(error, warning)
        self.assertGreater(warning, info)

    def test_high_behavior_weighs(self) -> None:
        """A high behavior adds weight and shows up in the reasons."""
        from asmx.behavior import Behavior

        high = Behavior("network", "Network", "d", "high", 90, (1,), ("e",), ("T1071",))
        risk = risk_assessment([], [high])
        self.assertGreaterEqual(risk["score"], 18)
        self.assertTrue(any("high" in reason for reason in risk["reasons"]))

    def test_cap_at_one_hundred(self) -> None:
        """The score stops at one hundred and the level becomes critical."""
        problems = [Problem(i, ERROR, "X", "m") for i in range(20)]
        self.assertEqual(risk_assessment(problems, [])["score"], 100)
        self.assertEqual(risk_assessment(problems, [])["level"], "critical")


class TestFormatAndUtilities(unittest.TestCase):
    """Format discovery and the executive summary."""

    def test_guess_format(self) -> None:
        """The extension decides the format; an unknown one falls back to HTML."""
        self.assertEqual(guess_format("a.html"), "html")
        self.assertEqual(guess_format("a.md"), "md")
        self.assertEqual(guess_format("a.json"), "json")
        self.assertEqual(guess_format("a.svg"), "svg")
        self.assertEqual(guess_format("a.dot"), "dot")
        self.assertEqual(guess_format("a.mermaid"), "mermaid")
        self.assertEqual(guess_format("a.unknown"), "html")

    def test_declared_formats(self) -> None:
        """The declared formats are exactly the six supported ones."""
        self.assertEqual(set(FORMATS), {"html", "md", "json", "dot", "svg", "mermaid"})

    def test_executive_summary_mentions_file_and_platform(self) -> None:
        """The summary cites the file name, the platform and the instruction count."""
        data = report_of(emulate=False)
        text = executive_summary(data)
        self.assertIn("program.asm", text)
        self.assertIn("linux", text)
        self.assertIn("instruction", text)


class TestCollection(unittest.TestCase):
    """What the report gathers from a piece of code."""

    def test_basic_metadata(self) -> None:
        """The default metadata, the dialect, the platform and the ABI are filled in."""
        data = report_of(emulate=False, source=None)
        self.assertEqual(data.schema, REPORT_SCHEMA)
        self.assertEqual(data.source["name"], "program.asm")
        self.assertTrue(data.source["fingerprint"])
        self.assertEqual(data.dialect, "intel")
        self.assertEqual(data.platform["os"], "linux")
        self.assertIn("System V", str(data.platform["abi"]))
        self.assertTrue(data.platform["arg_regs"])
        self.assertTrue(data.platform["evidence"]["linux"])

    def test_instructions_explained(self) -> None:
        """Each instruction carries the fields of its explanation."""
        data = report_of(emulate=False)
        self.assertEqual(len(data.instructions), data.counts["instructions"])
        first = data.instructions[0]
        self.assertEqual(
            set(first),
            {"line", "text", "mnemonic", "label", "detail", "tag", "func", "section", "block"},
        )
        self.assertTrue(first["detail"])

    def test_blocks_with_neighbors(self) -> None:
        """Blocks bring their name, their neighbors and the first and last line."""
        data = report_of(EXAMPLES["linux-loop"]["code"], emulate=False)
        self.assertTrue(data.blocks)
        block = data.blocks[0]
        self.assertIn("name", block)
        self.assertIn("goes_to", block)
        self.assertEqual(len(block["lines"]), 2)

    def test_graphs_present(self) -> None:
        """The report carries the three renderings of the control-flow graph."""
        data = report_of(FUNCTION, emulate=False)
        self.assertIn("svg", data.cfg)
        self.assertIn("dot", data.cfg)
        self.assertIn("mermaid", data.cfg)
        self.assertFalse(data.cfg["graph"]["empty"])
        self.assertFalse(data.calls["graph"]["empty"])

    def test_syscalls_and_apis(self) -> None:
        """Syscalls are aggregated by name and number; a clean program has no API."""
        data = report_of(emulate=False)
        names = {s["name"]: s for s in data.syscalls}
        self.assertEqual(set(names), {"write", "exit"})
        self.assertEqual(names["write"]["count"], 1)
        self.assertEqual(names["write"]["number"], 1)
        self.assertEqual(names["exit"]["number"], 60)
        self.assertTrue(names["write"]["lines"])
        self.assertEqual(data.apis, [])

    def test_external_windows_apis(self) -> None:
        """A Windows program lists the external APIs it calls."""
        data = report_of(EXAMPLES["windows-hello"]["code"], emulate=False)
        self.assertIn("ExitProcess", data.apis)
        self.assertEqual(data.platform["os"], "windows")

    def test_behaviors_and_mitre(self) -> None:
        """Behaviors come classified and the techniques link to MITRE."""
        data = report_of(emulate=False)
        self.assertTrue(data.behaviors)
        categories = {b["category"] for b in data.behaviors}
        self.assertIn("console-io", categories)
        for technique in data.techniques:
            self.assertIn("tactic", technique)
            self.assertTrue(technique["url"].startswith("https://attack.mitre.org/techniques/"))

    def test_indicators(self) -> None:
        """The string of the program shows up among the indicators."""
        data = report_of(emulate=False)
        self.assertIn("string", data.iocs)
        values = [i["value"] for i in data.iocs["string"]]
        self.assertIn("Hello, world!", values)

    def test_problems_of_the_broken_program(self) -> None:
        """The broken program has problems and a risk above the lowest level."""
        data = report_of(BROKEN, emulate=False)
        self.assertTrue(data.problems)
        self.assertEqual(data.risk["level"] in ("medium", "high", "critical"), True)
        codes = {p["code"] for p in data.problems}
        self.assertIn("DIV001", codes)

    def test_execution_and_timeline(self) -> None:
        """The simulated execution brings output, exit code, registers and timeline."""
        data = report_of()
        self.assertIsNotNone(data.execution)
        self.assertEqual(data.execution["output"], "Hello, world!\n")
        self.assertEqual(data.execution["exit_code"], 0)
        self.assertTrue(data.timeline)
        self.assertIn("registers", data.execution)
        self.assertIn("flags", data.execution)

    def test_without_emulation_there_is_no_execution(self) -> None:
        """Without emulation there is no execution and the timeline stays empty."""
        data = report_of(emulate=False)
        self.assertIsNone(data.execution)
        self.assertEqual(data.timeline, [])

    def test_missing_entry(self) -> None:
        """An entry label that does not exist raises a project error."""
        with self.assertRaises(ProjectError):
            collect(CLEAN, entry="does_not_exist")

    def test_source_read_from_disk(self) -> None:
        """Metadata read from the disk keeps the name, the size and the hash."""
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "prog.asm")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(CLEAN)
            size = os.path.getsize(path)
            data = collect(CLEAN, source=read_source(path), emulate=False)
        self.assertEqual(data.source["name"], "prog.asm")
        self.assertEqual(data.source["size"], size)
        self.assertTrue(data.source["sha256"])

    def test_empty_code_does_not_break(self) -> None:
        """Empty code produces an empty report that still renders."""
        data = collect("", emulate=False)
        self.assertEqual(data.counts["instructions"], 0)
        self.assertEqual(data.blocks, [])
        self.assertIn("No code to draw.", render_html(data))

    def test_emulation_that_hits_the_limit(self) -> None:
        """The emulation stops at the instruction limit and reports it."""
        data = collect("global _start\nsection .text\n_start:\nstuck:\n jmp stuck", limit=500)
        self.assertEqual(data.execution["steps"], 500)
        self.assertTrue(data.execution["issues"])

    def test_counts(self) -> None:
        """The counts property matches the sections of the report."""
        data = report_of(emulate=False)
        counts = data.counts
        self.assertEqual(counts["instructions"], data.stats["instructions"])
        self.assertEqual(counts["behaviors"], len(data.behaviors))
        self.assertEqual(counts["problems"], len(data.problems))
        self.assertEqual(counts["iocs"], sum(len(values) for values in data.iocs.values()))


class TestSerialization(unittest.TestCase):
    """JSON, Markdown, HTML, DOT, SVG and the index."""

    def test_valid_json_with_schema(self) -> None:
        """The JSON carries the schema and leaves the SVG out by default."""
        data = report_of(emulate=False)
        loaded = json.loads(render_json(data))
        self.assertEqual(loaded["schema"], REPORT_SCHEMA)
        self.assertIn("behaviors", loaded)
        self.assertIn("cfg", loaded)
        self.assertNotIn("svg", loaded["cfg"])
        self.assertFalse(render_json(data).endswith("\n\n"))

    def test_json_with_svg_when_requested(self) -> None:
        """The SVG enters the JSON when it is requested."""
        data = report_of(emulate=False)
        loaded = json.loads(render_json(data, include_svg=True))
        self.assertIn("<svg", loaded["cfg"]["svg"])

    def test_to_dict_with_required_fields(self) -> None:
        """Every required field is present in the dictionary."""
        data = report_of(emulate=False)
        keys = set(data.to_dict())
        for expected in (
            "schema",
            "generated_at",
            "version",
            "source",
            "platform",
            "stats",
            "risk",
            "summary",
            "problems",
            "behaviors",
            "techniques",
            "iocs",
            "instructions",
            "blocks",
            "cfg",
            "calls",
            "execution",
            "timeline",
        ):
            self.assertIn(expected, keys)

    def test_risk_is_a_mapping_without_single_reason(self) -> None:
        """Risk comes as a mapping and ``counts`` is a property, not a JSON key."""
        loaded = report_of(emulate=False).to_dict()
        self.assertEqual(
            set(loaded["risk"]),
            {"score", "level", "color", "emoji", "description", "reasons", "instructions"},
        )
        self.assertNotIn("reason", loaded["risk"])
        self.assertNotIn("counts", loaded)
        self.assertIsInstance(loaded["summary"], str)
        for expected in ("stats", "problems", "behaviors", "iocs"):
            self.assertIn(expected, loaded)

    def test_markdown_has_sections_and_tables(self) -> None:
        """The Markdown has the section titles, the Mermaid block and tables."""
        data = report_of(BROKEN, emulate=False)
        text = render_markdown(data)
        for section in (
            "# ASM X",
            "## Metadata",
            "## Numbers",
            "## Behaviors",
            "## Control flow",
            "## Validation",
            "## Instructions",
        ):
            self.assertIn(section, text)
        self.assertIn("```mermaid", text)
        self.assertIn("|", text)

    def test_markdown_of_clean_program(self) -> None:
        """A clean program says that no problem was found."""
        text = render_markdown(collect(CLEAN, emulate=False))
        self.assertIn("## Behaviors", text)
        self.assertIn("No problem found.", text)

    def test_html_without_behavior_explains_the_empty_case(self) -> None:
        """A program without behavior gets an explanatory message."""
        page = render_html(collect("nop", emulate=False))
        self.assertIn("No relevant behavior was identified.", page)

    def test_html_is_self_contained_and_offline(self) -> None:
        """The page starts with the doctype and loads nothing from the network."""
        data = report_of(emulate=False)
        page = render_html(data)
        self.assertTrue(page.startswith("<!DOCTYPE html>"))
        self.assertIn("<title>", page)
        self.assertIn("<svg", page)
        self.assertIn("showTab", page)
        for forbidden in ("<script src", "<link rel=", "cdn.", "@import", "<img src"):
            self.assertNotIn(forbidden, page)

    def test_html_escapes_program_content(self) -> None:
        """Program text with markup is escaped in the page."""
        code = 'section .data\nmsg db "<img src=x onerror=alert(1)>", 0\n'
        page = render_html(collect(code, emulate=False))
        self.assertNotIn("<img src=x", page)
        self.assertIn("&lt;img", page)

    def test_html_does_not_escape_its_own_markup(self) -> None:
        """Cells with markup (chips, links, spans) must come out as HTML.

        When one of them is escaped, the page shows the code instead of the
        element — that is how the ``path`` of the file turned into
        ``&lt;span class="mono"&gt;`` in the first version of the report.
        """
        page = render_html(report_of(EXAMPLES["suspicious"]["code"], emulate=False))
        for escaped in ("&lt;span", "&lt;a href", "&lt;div"):
            self.assertNotIn(escaped, page)
        self.assertIn('<span class="mono">', page)
        self.assertIn("attack.mitre.org", page)

    def test_html_contract_of_ids_scripts_and_styles(self) -> None:
        """The page keeps the agreed ids, scripts, chips and footer."""
        page = render_html(report_of())
        for element in (
            'id="instructions-filter"',
            'id="instructions-table"',
            'id="timeline-table"',
            "id='raw-json'",
        ):
            self.assertIn(element, page)
        for function in ("showTab", "filterRows", "copyText"):
            self.assertIn(function, page)
        for style in (
            ".sev-error",
            ".sev-warning",
            ".sev-info",
            ".behavior.high",
            ".behavior.medium",
            ".behavior.low",
        ):
            self.assertIn(style, page)
        for tab in (
            "summary",
            "flow",
            "behaviors",
            "iocs",
            "instructions",
            "validation",
            "execution",
            "data",
        ):
            self.assertIn("id='%s'" % tab, page)
        self.assertIn("Generated by ASM X", page)
        self.assertIn("self-contained page, no network requests", page)
        self.assertIn("schema %s" % REPORT_SCHEMA, page)

    def test_html_shows_risk_and_counts(self) -> None:
        """The page shows the risk banner, the score, the counts and the codes."""
        data = report_of(BROKEN, emulate=False)
        page = render_html(data)
        self.assertIn("RISK", page.upper())
        self.assertIn("Risk: %s" % data.risk["level"].upper(), page)
        self.assertIn(str(data.risk["score"]), page)
        self.assertIn("instructions", page)
        self.assertIn("DIV001", page)

    def test_html_tabs_appear(self) -> None:
        """The eight tabs appear as buttons."""
        page = render_html(report_of(emulate=False))
        for tab in (
            "Summary",
            "Flow",
            "Behaviors",
            "Indicators",
            "Instructions",
            "Validation",
            "Execution",
            "Data",
        ):
            self.assertIn(">%s</button>" % tab, page)

    def test_dot_and_svg(self) -> None:
        """The DOT and the SVG of the control flow are rendered."""
        data = report_of(FUNCTION, emulate=False)
        self.assertIn("digraph", render_dot(data))
        self.assertIn("<svg", render_svg(data))

    def test_index_compares_reports(self) -> None:
        """The index links both reports and summarizes the batch."""
        first = report_of(CLEAN, emulate=False)
        first.source["report_file"] = "clean.report.html"
        second = report_of(BROKEN, emulate=False)
        second.source["report_file"] = "broken.report.html"
        page = render_index([first, second], command="asmx analyze x")
        self.assertIn("ASM X — analysis index", page)
        self.assertIn("clean.report.html", page)
        self.assertIn("broken.report.html", page)
        self.assertIn("2 file(s) analyzed", page)
        self.assertIn('id="index-table"', page)


class TestWriting(unittest.TestCase):
    """Writing to disk, format by extension and errors."""

    def setUp(self) -> None:
        """Prepare the temporary folder and the report used by the tests."""
        self.dir = tempfile.TemporaryDirectory()
        self.data = report_of(emulate=False)

    def tearDown(self) -> None:
        """Remove the temporary folder."""
        self.dir.cleanup()

    def path_of(self, name: str) -> str:
        """Return the absolute path of a file inside the temporary folder.

        Returns:
            Path of the file inside the temporary folder of the test.
        """
        return os.path.join(self.dir.name, name)

    def test_writes_by_extension(self) -> None:
        """Each extension writes its own format."""
        expected = {
            "rel.html": "<!DOCTYPE html>",
            "rel.md": "# ASM X",
            "rel.json": '"schema"',
            "rel.dot": "digraph",
            "rel.svg": "<svg",
            "rel.mermaid": "flowchart",
        }
        for name, marker in expected.items():
            with self.subTest(file=name):
                path = write_report(self.data, self.path_of(name))
                with open(path, encoding="utf-8") as handle:
                    self.assertIn(marker, handle.read())

    def test_explicit_format(self) -> None:
        """An explicit format overrides the extension."""
        path = write_report(self.data, self.path_of("no_extension"), fmt="json")
        with open(path, encoding="utf-8") as handle:
            self.assertEqual(json.loads(handle.read())["schema"], REPORT_SCHEMA)

    def test_unknown_format(self) -> None:
        """An unknown format raises a project error."""
        with self.assertRaises(ProjectError):
            write_report(self.data, self.path_of("x.html"), fmt="pdf")

    def test_invalid_path(self) -> None:
        """Writing over a directory raises a source write error."""
        with self.assertRaises(SourceWriteError):
            write_report(self.data, self.dir.name)

    def test_default_output(self) -> None:
        """The dash writes the report to the standard output."""
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            written = write_report(self.data, "-", fmt="json")
        self.assertEqual(written, "-")
        self.assertIn(REPORT_SCHEMA, stream.getvalue())

    def test_leaves_no_litter(self) -> None:
        """Only the requested file is left behind."""
        write_report(self.data, self.path_of("rel.html"))
        self.assertEqual(sorted(os.listdir(self.dir.name)), ["rel.html"])

    def test_html_does_not_depend_on_external_files(self) -> None:
        """No src or href points outside the page."""
        page = render_html(self.data)
        self.assertIsNone(
            re.search(r"""(src|href)\s*=\s*["'](?!https://attack\.mitre\.org)""", page)
        )


if __name__ == "__main__":
    unittest.main()
