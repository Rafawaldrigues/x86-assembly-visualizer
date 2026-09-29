"""Tests of the command line: commands, exit codes and JSON."""

import contextlib
import io
import json
import os
import tempfile
import unittest
import unittest.mock

from asmx.analyzer import analyze
from asmx.cli import (
    EXIT_INPUT,
    EXIT_OK,
    EXIT_PROBLEMS,
    EXIT_TIMEOUT,
    EXIT_USAGE,
    Palette,
    build_parser,
    build_payload,
    describe_instruction,
    launch_gui,
    load_config,
    main,
)
from asmx.examples import EXAMPLES
from asmx.linter import summary as problem_summary
from asmx.linter import validate
from asmx.logging_setup import reset_logging

#: Clean program, used in most cases.
CLEAN = EXAMPLES["linux-hello"]["code"]

#: Program with defects on purpose.
BROKEN = EXAMPLES["broken"]["code"]

#: Program that never finishes by itself.
INFINITE = "global _start\nsection .text\n_start:\n.stuck:\n jmp .stuck\n"


class BaseCLI(unittest.TestCase):
    """Temporary files, output capture and clean logging."""

    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.clean = self.write_file("clean.asm", CLEAN)
        self.broken = self.write_file("broken.asm", BROKEN)
        self.infinite = self.write_file("infinite.asm", INFINITE)
        self.overflow = self.write_file("overflow.asm", EXAMPLES["overflow"]["code"])

    def tearDown(self) -> None:
        self.dir.cleanup()
        reset_logging()

    def write_file(self, name: str, content: str) -> str:
        path = os.path.join(self.dir.name, name)
        with open(path, "w", encoding="utf-8") as file:
            file.write(content)
        return path

    def run_cli(self, *argv: str) -> tuple:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def run_json(self, *argv: str) -> tuple:
        code, out, err = self.run_cli(*argv, "--json")
        return code, json.loads(out), err


class TestVersionAndObjects(BaseCLI):
    """Simple commands and helper functions."""

    def test_version_text(self) -> None:
        code, out, _ = self.run_cli("version")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("ASM X 1.0.0", out)

    def test_version_json(self) -> None:
        code, data, _ = self.run_json("version")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(data["version"], "1.0.0")
        self.assertEqual(data["schema"], "asmx-version/1")

    def test_info_text(self) -> None:
        code, out, _ = self.run_cli("info")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("148 instructions", out)
        self.assertIn("configuration:", out)

    def test_info_json(self) -> None:
        code, data, _ = self.run_json("info")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(data["isa"]["mnemonics"], 148)
        self.assertEqual(data["isa"]["linux_syscalls"], 43)
        self.assertEqual(data["isa"]["examples"], 9)
        self.assertIn("tkinter", data)
        self.assertIn("config", data)
        self.assertIn("logging", data)

    def test_no_command_shows_help(self) -> None:
        code, out, _ = self.run_cli()
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("COMMAND", out)

    def test_unknown_command_is_usage_error(self) -> None:
        with self.assertRaises(SystemExit) as context:
            with contextlib.redirect_stderr(io.StringIO()):
                main(["invented"])
        self.assertEqual(context.exception.code, EXIT_USAGE)

    def test_palette_off_does_not_paint(self) -> None:
        self.assertEqual(Palette(False).paint("error", "error"), "error")
        self.assertIn("\033[", Palette(True).paint("error", "error"))
        self.assertEqual(Palette(True).paint("x", "unknown_color"), "x")

    def test_no_color_emits_no_ansi(self) -> None:
        code, out, _ = self.run_cli("check", self.broken, "--no-color")
        self.assertEqual(code, EXIT_PROBLEMS)
        self.assertNotIn("\033[", out)

    def test_describe_instruction(self) -> None:
        instruction = analyze("mov rax, 1").instrs[0]
        record = describe_instruction(instruction)
        self.assertEqual(record["mnemonic"], "mov")
        self.assertEqual(record["tag"], "set")
        self.assertEqual(record["label"], instruction.sem.label)
        self.assertTrue(record["label"])
        self.assertEqual(record["operands"][0]["type"], "reg")
        self.assertTrue(record["documentation"]["syntax"].upper().startswith("MOV"))

    def test_build_payload(self) -> None:
        args = build_parser().parse_args(["check", "a.asm", "b.asm"])
        self.assertEqual(build_payload(args), {"command": "check", "files": ["a.asm", "b.asm"]})

    def test_load_config_merges_command_line(self) -> None:
        args = build_parser().parse_args(["-v", "--log-json", "check", "a.asm"])
        config = load_config(args)
        self.assertEqual(config.log_level, "DEBUG")
        self.assertTrue(config.log_json)

    def test_launch_gui_without_display(self) -> None:
        err = io.StringIO()
        with (
            unittest.mock.patch.dict(os.environ, {"DISPLAY": ""}),
            contextlib.redirect_stderr(err),
        ):
            self.assertEqual(launch_gui(), EXIT_INPUT)
        self.assertIn("could not open the window", err.getvalue())


class TestCheck(BaseCLI):
    """The ``check`` command."""

    def test_clean_file(self) -> None:
        code, out, _ = self.run_cli("check", self.clean, "--no-color")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("no problems found", out)
        self.assertIn("platform  linux", out)

    def test_file_with_defects(self) -> None:
        code, out, _ = self.run_cli("check", self.broken, "--no-color")
        self.assertEqual(code, EXIT_PROBLEMS)
        self.assertIn("DIV001", out)
        self.assertIn("→", out)

    def test_summary_only_hides_the_list(self) -> None:
        _, out, _ = self.run_cli("check", self.broken, "--summary-only", "--no-color")
        self.assertNotIn("DIV001", out)
        expected = problem_summary(validate(analyze(BROKEN)))
        self.assertIn(expected, out)

    def test_exit_zero_forces_success(self) -> None:
        code, _, _ = self.run_cli("check", self.broken, "--exit-zero")
        self.assertEqual(code, EXIT_OK)

    def test_min_severity_info_fails_warnings(self) -> None:
        code, _, _ = self.run_cli("check", self.clean, "--min-severity", "info")
        self.assertEqual(code, EXIT_OK)
        code, _, _ = self.run_cli("check", self.overflow, "--min-severity", "warning")
        self.assertEqual(code, EXIT_PROBLEMS)

    def test_json(self) -> None:
        code, data, _ = self.run_json("check", self.broken)
        self.assertEqual(code, EXIT_PROBLEMS)
        source = data["files"][0]
        self.assertEqual(data["schema"], "asmx-check/1")
        self.assertEqual(source["source"]["name"], "broken.asm")
        self.assertEqual(source["platform"]["os"], "linux")
        self.assertGreater(source["summary"]["errors"], 0)
        self.assertEqual(source["problems"][0]["line"] > 0, True)
        self.assertEqual(data["exit_code"], EXIT_PROBLEMS)

    def test_several_files_summarize_at_the_end(self) -> None:
        code, out, _ = self.run_cli("check", self.clean, self.broken, "--no-color")
        self.assertEqual(code, EXIT_PROBLEMS)
        self.assertIn("2 file(s)", out)

    def test_json_of_several_files(self) -> None:
        _, data, _ = self.run_json("check", self.clean, self.broken)
        self.assertEqual(data["summary"]["files"], 2)

    def test_missing_file(self) -> None:
        code, _, err = self.run_cli("check", os.path.join(self.dir.name, "nothing.asm"))
        self.assertEqual(code, EXIT_INPUT)
        self.assertIn("ERR_SOURCE_NOT_FOUND", err)

    def test_refused_extension(self) -> None:
        path = self.write_file("program.bin", "mov rax, 1")
        code, _, err = self.run_cli("check", path)
        self.assertEqual(code, EXIT_INPUT)
        self.assertIn("ERR_UNSUPPORTED_SOURCE", err)

    def test_latin1_encoding_warned(self) -> None:
        path = os.path.join(self.dir.name, "legacy.asm")
        with open(path, "wb") as file:
            file.write(b"; temp: 20\xb0C\nmov rax, 1\n")
        _, out, _ = self.run_cli("check", path, "--no-color")
        self.assertIn("latin-1", out)


class TestRun(BaseCLI):
    """The ``run`` command."""

    def test_clean_program(self) -> None:
        code, out, _ = self.run_cli("run", self.clean)
        self.assertEqual(code, EXIT_OK)
        self.assertIn("Hello, world!", out)
        self.assertIn("exit code 0", out)

    def test_json(self) -> None:
        code, data, _ = self.run_json("run", self.clean)
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(data["output"], "Hello, world!\n")
        self.assertEqual(data["exit_code"], 0)
        self.assertTrue(data["halted"])
        self.assertFalse(data["timed_out"])
        self.assertEqual(data["registers"]["rax"], "0x3c")
        self.assertIn("ZF", data["flags"])

    def test_trace(self) -> None:
        _, data, _ = self.run_json("run", self.clean, "--trace", "--max-trace", "3")
        self.assertEqual(len(data["trace"]), 3)
        self.assertIn("note", data["trace"][0])

    def test_trace_in_text(self) -> None:
        _, out, _ = self.run_cli("run", self.clean, "--trace", "--no-color")
        self.assertIn("history:", out)

    def test_simulated_input(self) -> None:
        code = (
            "section .bss\nbuf resb 8\nsection .text\nglobal _start\n_start:\n"
            "mov rax, 0\nmov rdi, 0\nmov rsi, buf\nmov rdx, 3\nsyscall\n"
            "mov rax, 1\nmov rdi, 1\nmov rsi, buf\nmov rdx, 3\nsyscall\n"
            "mov rax, 60\nxor rdi, rdi\nsyscall"
        )
        path = self.write_file("read.asm", code)
        _, data, _ = self.run_json("run", path, "--stdin", "abc")
        self.assertEqual(data["output"], "abc")

    def test_isolated_function(self) -> None:
        _, data, _ = self.run_json("run", self.overflow, "--entry", "sum_until")
        self.assertEqual(data["entry"], "sum_until")

    def test_nonexistent_label(self) -> None:
        code, _, err = self.run_cli("run", self.clean, "--entry", "does_not_exist")
        self.assertEqual(code, EXIT_INPUT)
        self.assertIn("label not found", err)

    def test_program_with_problem(self) -> None:
        code, out, _ = self.run_cli("run", self.broken, "--no-color")
        self.assertEqual(code, EXIT_PROBLEMS)
        self.assertIn("⚠", out)

    def test_instruction_limit(self) -> None:
        code, _, _ = self.run_cli("run", self.infinite, "--limit", "500")
        self.assertEqual(code, EXIT_PROBLEMS)

    def test_timeout(self) -> None:
        code, _, err = self.run_cli(
            "run", self.infinite, "--limit", "100000", "--timeout", "0.000001"
        )
        self.assertEqual(code, EXIT_TIMEOUT)
        self.assertIn("ERR_TIMEOUT", err)

    def test_no_output_shows_empty(self) -> None:
        path = self.write_file(
            "silent.asm",
            "global _start\nsection .text\n_start:\n" "mov rax, 60\nxor rdi, rdi\nsyscall\n",
        )
        _, out, _ = self.run_cli("run", path, "--no-color")
        self.assertIn("(empty)", out)


class TestExplain(BaseCLI):
    """The ``explain`` command."""

    def test_instruction_line(self) -> None:
        code, out, _ = self.run_cli("explain", self.clean, "--line", "12", "--no-color")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("MOV", out)
        self.assertIn("syntax", out)

    def test_instruction_line_json(self) -> None:
        _, data, _ = self.run_json("explain", self.clean, "--line", "12")
        self.assertEqual(data["kind"], "instruction")
        self.assertEqual(data["tag"], "set")
        self.assertTrue(data["label"])
        self.assertEqual(data["line"], 12)

    def test_data_line(self) -> None:
        code, out, _ = self.run_cli("explain", self.clean, "--line", "5", "--no-color")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("msg", out)
        self.assertIn("byte", out)

    def test_data_line_json(self) -> None:
        _, data, _ = self.run_json("explain", self.clean, "--line", "5")
        self.assertEqual(data["kind"], "data")
        self.assertEqual(data["label"], "msg")

    def test_directive_line(self) -> None:
        _, data, _ = self.run_json("explain", self.clean, "--line", "4")
        self.assertEqual(data["kind"], "directive")
        self.assertEqual(data["directive"], "section")

    def test_line_that_does_not_exist(self) -> None:
        code, _, err = self.run_cli("explain", self.clean, "--line", "9999")
        self.assertEqual(code, EXIT_INPUT)
        self.assertIn("ERR_LINE_NOT_FOUND", err)

    def test_known_mnemonic(self) -> None:
        code, out, _ = self.run_cli("explain", self.clean, "--mnemonic", "syscall", "--no-color")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("SYSCALL", out)
        self.assertIn("syntax", out)
        self.assertIn("flags", out)

    def test_known_mnemonic_json(self) -> None:
        _, data, _ = self.run_json("explain", self.clean, "--mnemonic", "mov")
        self.assertEqual(data["kind"], "mnemonic")
        self.assertEqual(data["documentation"]["cat"], "data")

    def test_unknown_mnemonic(self) -> None:
        code, _, err = self.run_cli("explain", self.clean, "--mnemonic", "xyzzy")
        self.assertEqual(code, EXIT_INPUT)
        self.assertIn("ERR_UNKNOWN_MNEMONIC", err)

    def test_requires_one_of_the_options(self) -> None:
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                main(["explain", self.clean])


class TestExamples(BaseCLI):
    """The ``examples`` command."""

    def test_list(self) -> None:
        code, out, _ = self.run_cli("examples", "--list")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("linux-hello", out)
        self.assertIn("bubble", out)

    def test_show(self) -> None:
        code, out, _ = self.run_cli("examples", "--show", "linux-hello")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("global _start", out)

    def test_show_unknown(self) -> None:
        code, _, err = self.run_cli("examples", "--show", "does_not_exist")
        self.assertEqual(code, EXIT_INPUT)
        self.assertIn("unknown example", err)

    def test_dump(self) -> None:
        destination = os.path.join(self.dir.name, "output")
        code, out, _ = self.run_cli("examples", "--dump", destination, "--no-color")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(len(os.listdir(destination)), 9)
        self.assertIn("9 examples", out)

    def test_dump_json(self) -> None:
        destination = os.path.join(self.dir.name, "output2")
        _, data, _ = self.run_json("examples", "--dump", destination)
        self.assertEqual(len(data["files"]), 9)

    def test_json_without_dump(self) -> None:
        _, data, _ = self.run_json("examples", "--list")
        self.assertEqual(len(data["examples"]), 9)
        self.assertIn("title", data["examples"][0])


class TestGlobalOptions(BaseCLI):
    """Options that are valid for any command."""

    def test_verbose_shows_log(self) -> None:
        _, _, err = self.run_cli("-v", "check", self.clean)
        self.assertIn("check_finished", err)

    def test_quiet_silences(self) -> None:
        _, _, err = self.run_cli("-q", "check", self.clean)
        self.assertEqual(err.strip(), "")

    def test_log_json(self) -> None:
        _, _, err = self.run_cli("-v", "--log-json", "check", self.clean)
        events = [
            json.loads(line)["event"] for line in err.strip().split("\n") if line.startswith("{")
        ]
        self.assertIn("command_started", events)
        self.assertIn("check_finished", events)
        self.assertEqual(events[-1], "command_finished")

    def test_log_to_file(self) -> None:
        path = os.path.join(self.dir.name, "asmx.log")
        self.run_cli("-v", "--log-file", path, "check", self.clean)
        with open(path, encoding="utf-8") as file:
            self.assertIn("check_finished", file.read())

    def test_invalid_config(self) -> None:
        path = os.path.join(self.dir.name, "config.json")
        with open(path, "w", encoding="utf-8") as file:
            file.write("{invalid}")
        code, _, err = self.run_cli("--config", path, "info")
        self.assertEqual(code, EXIT_INPUT)
        self.assertIn("ERR_CONFIG", err)

    def test_good_config(self) -> None:
        path = os.path.join(self.dir.name, "config.json")
        with open(path, "w", encoding="utf-8") as file:
            json.dump({"max_steps": 123, "log_level": "ERROR"}, file)
        _, data, _ = self.run_json("--config", path, "info")
        self.assertEqual(data["config"]["max_steps"], 123)

    def test_global_help(self) -> None:
        with self.assertRaises(SystemExit) as context:
            with contextlib.redirect_stdout(io.StringIO()):
                main(["--help"])
        self.assertEqual(context.exception.code, EXIT_OK)

    def test_version_through_the_option(self) -> None:
        with self.assertRaises(SystemExit) as context:
            with contextlib.redirect_stdout(io.StringIO()):
                main(["--version"])
        self.assertEqual(context.exception.code, EXIT_OK)


if __name__ == "__main__":
    unittest.main()
