"""Tests of the embedded examples and of their copy in ``examples/``."""

import os
import unittest

from asmx.analyzer import analyze
from asmx.examples import EXAMPLES, count_lines, names, title_of
from asmx.linter import ERROR, validate
from asmx.source import read_source

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FOLDER = os.path.join(ROOT, "examples")

#: Examples that need to pass with no validation error at all.
CLEAN = ("linux-hello", "linux-loop", "linux-function", "windows-hello", "bubble", "suspicious")


class TestCatalog(unittest.TestCase):
    """The catalog in memory."""

    def test_nine_examples(self) -> None:
        self.assertEqual(len(EXAMPLES), 9)

    def test_names_in_order(self) -> None:
        self.assertEqual(names(), sorted(EXAMPLES))
        self.assertEqual(names()[0], "broken")

    def test_every_example_has_a_title_and_code(self) -> None:
        for name, example in EXAMPLES.items():
            with self.subTest(example=name):
                self.assertTrue(example["title"])
                self.assertTrue(example["code"].strip())
                self.assertEqual(set(example), {"title", "code"})

    def test_title_of(self) -> None:
        self.assertIn("Linux", title_of("linux-hello"))
        self.assertEqual(title_of("does_not_exist"), "")

    def test_count_lines(self) -> None:
        self.assertEqual(
            count_lines("linux-hello"), EXAMPLES["linux-hello"]["code"].count("\n") + 1
        )
        self.assertEqual(count_lines("does_not_exist"), 0)


class TestAnalysis(unittest.TestCase):
    """Every example needs to be parsed and validated without blowing up."""

    def test_analyzes_and_validates_all(self) -> None:
        for name, example in EXAMPLES.items():
            with self.subTest(example=name):
                analysis = analyze(example["code"])
                self.assertGreater(analysis.stats["instructions"], 0)
                validate(analysis)

    def test_clean_examples_without_errors(self) -> None:
        for name in CLEAN:
            with self.subTest(example=name):
                errors = [
                    p for p in validate(analyze(EXAMPLES[name]["code"])) if p.severity == ERROR
                ]
                self.assertEqual(errors, [], "%s has an error: %s" % (name, errors))

    def test_broken_reports_the_expected_defects(self) -> None:
        # STR001 (a string with a character outside ASCII) is not in this list on
        # purpose: the sample text is plain ASCII now, and the rule has its own
        # fixture in tests/test_linter.py.
        codes = {p.code for p in validate(analyze(EXAMPLES["broken"]["code"]))}
        for expected in ("STR006", "DIV001", "IMM001", "STK001", "FLOW002", "SYM003"):
            with self.subTest(code=expected):
                self.assertIn(expected, codes)

    def test_detected_platforms(self) -> None:
        self.assertEqual(analyze(EXAMPLES["linux-hello"]["code"]).platform.os, "linux")
        self.assertEqual(analyze(EXAMPLES["windows-hello"]["code"]).platform.os, "windows")

    def test_detected_dialects(self) -> None:
        self.assertEqual(analyze(EXAMPLES["gcc-att"]["code"]).program.flavor, "att")
        self.assertEqual(analyze(EXAMPLES["linux-hello"]["code"]).program.flavor, "intel")


class TestFilesOnDisk(unittest.TestCase):
    """The files in ``examples/`` are the same thing as the catalog."""

    def test_folder_exists(self) -> None:
        self.assertTrue(os.path.isdir(FOLDER), "the examples/ folder should exist")

    def test_one_file_per_example(self) -> None:
        expected = {"%s.asm" % name for name in EXAMPLES}
        found = {f for f in os.listdir(FOLDER) if f.endswith(".asm")}
        self.assertEqual(expected, found)

    def test_content_matches_the_package(self) -> None:
        for name, example in EXAMPLES.items():
            with self.subTest(example=name):
                path = os.path.join(FOLDER, "%s.asm" % name)
                with open(path, encoding="utf-8") as file:
                    self.assertEqual(file.read(), example["code"].rstrip("\n") + "\n")

    def test_files_are_read_by_the_project_reader(self) -> None:
        source = read_source(os.path.join(FOLDER, "linux-hello.asm"))
        self.assertEqual(source.suffix, ".asm")
        self.assertEqual(source.encoding, "utf-8")
        self.assertIn("global _start", source.text)


if __name__ == "__main__":
    unittest.main()
