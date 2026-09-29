"""Tests of the ``report`` and ``analyze`` commands of the command line."""

import contextlib
import io
import json
import os
import tempfile
import unittest
import unittest.mock

from asmx.cli import (
    EXIT_INPUT,
    EXIT_OK,
    EXIT_PROBLEMS,
    _expand_sources,
    _reached,
    _risk_rank,
    build_parser,
    build_payload,
    main,
)
from asmx.examples import EXAMPLES
from asmx.logging_setup import reset_logging

#: Clean program, used in most cases.
CLEAN = EXAMPLES["linux-hello"]["code"]

#: Program with defects on purpose.
BROKEN = EXAMPLES["broken"]["code"]


class BaseCLI(unittest.TestCase):
    """Temporary files, output capture and a clean environment."""

    def setUp(self) -> None:
        """Create the temporary folder, the environment and the sample files."""
        self.dir = tempfile.TemporaryDirectory()
        self.env = unittest.mock.patch.dict(
            os.environ, {"ASMX_OUTPUT_DIR": os.path.join(self.dir.name, "results")}
        )
        self.env.start()
        self.clean = self.write_file("clean.asm", CLEAN)
        self.broken = self.write_file("broken.asm", BROKEN)

    def tearDown(self) -> None:
        """Restore the environment and clean the logging."""
        self.env.stop()
        self.dir.cleanup()
        reset_logging()

    def write_file(self, name: str, content: str) -> str:
        """Write a source file inside the temporary folder and return its path.

        Returns:
            Absolute path of the file that was written.
        """
        path = os.path.join(self.dir.name, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def run_cli(self, *argv: str) -> tuple:
        """Run the command line capturing the output and return the exit code.

        Returns:
            Tuple with the exit code, the standard output and the standard error.
        """
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def run_json(self, *argv: str) -> tuple:
        """Run the command with ``--json`` and return the already loaded JSON.

        Returns:
            Tuple with the exit code, the JSON already loaded and the standard error.
        """
        code, out, err = self.run_cli(*argv, "--json")
        return code, json.loads(out), err


class TestHelpers(unittest.TestCase):
    """Small functions that support both commands."""

    def test_risk_rank_orders(self) -> None:
        """The ranks follow low < medium < high < critical."""
        self.assertLess(_risk_rank("low"), _risk_rank("medium"))
        self.assertLess(_risk_rank("medium"), _risk_rank("high"))
        self.assertLess(_risk_rank("high"), _risk_rank("critical"))
        self.assertEqual(_risk_rank("unknown"), 0)

    def test_reached_with_and_without_limit(self) -> None:
        """The limit is reached when the risk equals or exceeds it."""
        from asmx.report import ReportData

        data = ReportData(risk={"level": "high"})
        self.assertTrue(_reached("high", data))
        self.assertTrue(_reached("medium", data))
        self.assertFalse(_reached("critical", data))
        self.assertFalse(_reached(None, data))

    def test_expand_sources_in_directory(self) -> None:
        """Directories are expanded into sources, hidden folders aside."""
        with tempfile.TemporaryDirectory() as folder:
            for name in ("a.asm", "b.s", "c.txt", "d.bin"):
                with open(os.path.join(folder, name), "w", encoding="utf-8") as handle:
                    handle.write("nop\n")
            os.makedirs(os.path.join(folder, "sub"))
            with open(os.path.join(folder, "sub", "e.asm"), "w", encoding="utf-8") as handle:
                handle.write("nop\n")
            os.makedirs(os.path.join(folder, ".hidden"))
            with open(os.path.join(folder, ".hidden", "f.asm"), "w", encoding="utf-8") as handle:
                handle.write("nop\n")
            found = [os.path.basename(path) for path in _expand_sources([folder])]
        self.assertIn("a.asm", found)
        self.assertIn("b.s", found)
        self.assertIn("c.txt", found)
        self.assertNotIn("d.bin", found)
        self.assertIn("e.asm", found)
        self.assertNotIn("f.asm", found)

    def test_expand_sources_keeps_explicit_file(self) -> None:
        """A file named directly is kept, even with an unknown extension."""
        self.assertEqual(_expand_sources(["/tmp/x.bin"]), ["/tmp/x.bin"])

    def test_payload_includes_out_and_format(self) -> None:
        """The payload records the output and the format of the report."""
        args = build_parser().parse_args(["report", "a.asm", "--out", "r.html", "--format", "json"])
        data = build_payload(args)
        self.assertEqual(data["out"], "r.html")
        self.assertEqual(data["format"], "json")


class TestReport(BaseCLI):
    """The ``report`` command."""

    def test_html_at_the_given_path(self) -> None:
        """The HTML goes to the path given in --out."""
        destination = os.path.join(self.dir.name, "out", "rel.html")
        code, out, _ = self.run_cli("report", self.clean, "--out", destination, "--no-color")
        self.assertEqual(code, EXIT_OK)
        self.assertTrue(os.path.exists(destination))
        with open(destination, encoding="utf-8") as handle:
            content = handle.read()
        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("clean.asm", out + content)

    def test_default_html_goes_to_output_dir(self) -> None:
        """Without --out the HTML goes to the output directory."""
        code, out, _ = self.run_cli("report", self.clean, "--no-color")
        self.assertEqual(code, EXIT_OK)
        expected = os.path.join(os.environ["ASMX_OUTPUT_DIR"], "clean.report.html")
        self.assertTrue(os.path.exists(expected))
        self.assertIn("report written to", out)

    def test_json_summary_writes_no_file(self) -> None:
        """The JSON summary goes to the screen and writes no file."""
        code, data, _ = self.run_json("report", self.clean)
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(data["schema"], "asmx-report/1")
        self.assertEqual(data["file"], "clean.asm")
        self.assertEqual(data["counts"]["instructions"], 8)
        self.assertEqual(data["output"], "-")
        self.assertFalse(
            os.path.exists(os.path.join(os.environ["ASMX_OUTPUT_DIR"], "clean.report.html"))
        )

    def test_json_report_on_screen(self) -> None:
        """The JSON format prints the report on the screen."""
        code, out, _ = self.run_cli("report", self.clean, "--format", "json")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(json.loads(out)["schema"], "asmx-report/1")

    def test_json_summary_with_written_file(self) -> None:
        """With --out the summary cites the file that was written."""
        destination = os.path.join(self.dir.name, "with-summary.html")
        _, data, _ = self.run_json("report", self.clean, "--out", destination)
        self.assertEqual(data["output"], destination)
        self.assertTrue(os.path.exists(destination))

    def test_markdown_and_dot_and_svg(self) -> None:
        """Every text format prints its own marker."""
        for format_name, marker in (
            ("md", "# ASM X"),
            ("dot", "digraph"),
            ("svg", "<svg"),
            ("mermaid", "flowchart"),
        ):
            with self.subTest(format=format_name):
                code, out, _ = self.run_cli("report", self.clean, "--format", format_name)
                self.assertEqual(code, EXIT_OK)
                self.assertIn(marker, out)

    def test_without_emulation(self) -> None:
        """The static report keeps the instruction count."""
        _, data, _ = self.run_json("report", self.clean, "--format", "json", "--no-emulate")
        self.assertEqual(data["counts"]["instructions"], 8)

    def test_fail_on_high(self) -> None:
        """A risk above the limit turns into the problem exit code."""
        code, _, _ = self.run_cli(
            "report",
            self.broken,
            "--fail-on",
            "high",
            "--out",
            os.path.join(self.dir.name, "q.html"),
        )
        self.assertEqual(code, EXIT_PROBLEMS)

    def test_fail_on_not_reached(self) -> None:
        """A risk below the limit keeps the success exit code."""
        code, _, _ = self.run_cli(
            "report",
            self.clean,
            "--fail-on",
            "critical",
            "--out",
            os.path.join(self.dir.name, "l.html"),
        )
        self.assertEqual(code, EXIT_OK)

    def test_json_with_fail_on(self) -> None:
        """The JSON summary carries the exit code of --fail-on."""
        code, data, _ = self.run_json(
            "report",
            self.broken,
            "--fail-on",
            "medium",
            "--out",
            os.path.join(self.dir.name, "q2.html"),
        )
        self.assertEqual(code, EXIT_PROBLEMS)
        self.assertEqual(data["exit_code"], EXIT_PROBLEMS)
        self.assertTrue(data["behaviors"])

    def test_opens_in_browser(self) -> None:
        """The --open flag opens the file URL in the browser."""
        destination = os.path.join(self.dir.name, "opens.html")
        with unittest.mock.patch("asmx.cli.webbrowser.open") as opened:
            code, _, _ = self.run_cli("report", self.clean, "--out", destination, "--open")
        self.assertEqual(code, EXIT_OK)
        opened.assert_called_once()
        self.assertTrue(str(opened.call_args[0][0]).startswith("file://"))

    def test_missing_file(self) -> None:
        """A file that does not exist exits with the input code."""
        code, _, err = self.run_cli("report", os.path.join(self.dir.name, "nothing.asm"))
        self.assertEqual(code, EXIT_INPUT)
        self.assertIn("ERR_SOURCE_NOT_FOUND", err)

    def test_missing_entry(self) -> None:
        """An unknown entry label exits with the input code."""
        code, _, err = self.run_cli("report", self.clean, "--entry", "does_not_exist")
        self.assertEqual(code, EXIT_INPUT)
        self.assertIn("label not found", err)

    def test_stdin_changes_the_output(self) -> None:
        """The simulated input shows up in the report."""
        source = (
            "section .bss\nbuf resb 8\nsection .text\nglobal _start\n_start:\n"
            "mov rax, 0\nmov rdi, 0\nmov rsi, buf\nmov rdx, 3\nsyscall\n"
            "mov rax, 1\nmov rdi, 1\nmov rsi, buf\nmov rdx, 3\nsyscall\n"
            "mov rax, 60\nxor rdi, rdi\nsyscall"
        )
        path = self.write_file("reads.asm", source)
        destination = os.path.join(self.dir.name, "reads.report.html")
        _, _, _ = self.run_cli("report", path, "--stdin", "abc", "--out", destination)
        with open(destination, encoding="utf-8") as handle:
            self.assertIn(">abc<", handle.read())


class TestAnalyze(BaseCLI):
    """The ``analyze`` command (batch with an index)."""

    def setUp(self) -> None:
        """Create the batch folder with four sources and the output folder."""
        super().setUp()
        self.batch = os.path.join(self.dir.name, "batch")
        os.makedirs(self.batch)
        self.write_file("batch/a.asm", CLEAN)
        self.write_file("batch/b.asm", BROKEN)
        self.write_file("batch/c.txt", "nop\n")
        self.write_file("batch/sub/d.asm", EXAMPLES["linux-loop"]["code"])
        self.output = os.path.join(self.dir.name, "batch-output")

    def test_batch_writes_reports_and_index(self) -> None:
        """The batch writes the reports, the index and the manifest."""
        code, out, _ = self.run_cli("analyze", self.batch, "--out", self.output, "--no-color")
        self.assertEqual(code, EXIT_OK)
        files = sorted(os.listdir(self.output))
        self.assertIn("index.html", files)
        self.assertIn("index.json", files)
        self.assertIn("a.report.html", files)
        self.assertIn("b.report.html", files)
        self.assertIn("d.report.html", files)
        with open(os.path.join(self.output, "index.html"), encoding="utf-8") as handle:
            index = handle.read()
        self.assertIn("a.report.html", index)
        self.assertIn("4 file(s)", index)
        self.assertIn("summary:", out)

    def test_manifest_has_schema_files_groups_and_exit_code(self) -> None:
        """The manifest carries the schema, the files, the groups and the exit code."""
        code, _, _ = self.run_cli("analyze", self.batch, "--out", self.output)
        self.assertEqual(code, EXIT_OK)
        with open(os.path.join(self.output, "index.json"), encoding="utf-8") as handle:
            manifest = json.load(handle)
        self.assertEqual(
            set(manifest),
            {"schema", "command", "directory", "format", "files", "groups", "exit_code"},
        )
        self.assertEqual(manifest["schema"], "asmx-analyze/1")
        self.assertEqual(len(manifest["files"]), 4)
        self.assertEqual(manifest["groups"], [])
        self.assertEqual(manifest["exit_code"], EXIT_OK)

    def test_batch_json(self) -> None:
        """The JSON batch lists the four files with their risk."""
        code, data, _ = self.run_json("analyze", self.batch, "--out", self.output)
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(data["schema"], "asmx-analyze/1")
        self.assertEqual(len(data["files"]), 4)
        names = {f["name"] for f in data["files"]}
        self.assertEqual(names, {"a.asm", "b.asm", "c.txt", "d.asm"})
        self.assertTrue(all("risk" in f for f in data["files"]))

    def test_no_index(self) -> None:
        """With --no-index only the manifest is written."""
        _, _, _ = self.run_cli("analyze", self.batch, "--out", self.output, "--no-index")
        files = os.listdir(self.output)
        self.assertNotIn("index.html", files)
        self.assertIn("index.json", files)

    def test_cluster_adds_groups(self) -> None:
        """With --cluster the manifest groups similar files."""
        _, data, _ = self.run_json(
            "analyze", self.batch, "--out", self.output, "--cluster", "--threshold", "0.5"
        )
        self.assertTrue(data["groups"])
        members = {frozenset(group["members"]) for group in data["groups"]}
        self.assertIn(frozenset({"a.asm", "d.asm"}), members)

    def test_json_format_in_batch(self) -> None:
        """The batch in JSON writes .json reports and no HTML index."""
        _, _, _ = self.run_cli("analyze", self.batch, "--out", self.output, "--format", "json")
        files = os.listdir(self.output)
        self.assertIn("a.report.json", files)
        self.assertNotIn("index.html", files)

    def test_fail_on_medium(self) -> None:
        """A file at or above the limit turns into the problem exit code."""
        code, _, _ = self.run_cli(
            "analyze", self.batch, "--out", self.output, "--fail-on", "medium"
        )
        self.assertEqual(code, EXIT_PROBLEMS)

    def test_empty_folder(self) -> None:
        """A folder without sources is an input error."""
        empty = os.path.join(self.dir.name, "empty")
        os.makedirs(empty)
        code, _, err = self.run_cli("analyze", empty, "--out", self.output)
        self.assertEqual(code, EXIT_INPUT)
        self.assertIn("no assembly file", err)

    def test_single_file(self) -> None:
        """A single file is analysed like a batch of one."""
        code, _, _ = self.run_cli("analyze", self.clean, "--out", self.output)
        self.assertEqual(code, EXIT_OK)
        self.assertIn("clean.report.html", os.listdir(self.output))

    def test_without_emulation_in_batch(self) -> None:
        """Without emulation the report of the batch has no execution."""
        _, _, _ = self.run_cli(
            "analyze", self.clean, "--out", self.output, "--no-emulate", "--format", "json"
        )
        with open(os.path.join(self.output, "clean.report.json"), encoding="utf-8") as handle:
            self.assertIsNone(json.load(handle)["execution"])


if __name__ == "__main__":
    unittest.main()
