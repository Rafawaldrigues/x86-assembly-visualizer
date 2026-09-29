"""Tests of the error hierarchy: codes, context and compatibility."""

import unittest

from asmx.errors import (
    ERROR_CODES,
    AnalysisTimeoutError,
    AsmxError,
    BranchExistsError,
    BranchNotFoundError,
    ConfigError,
    EmulationError,
    EmptyBranchNameError,
    LastBranchError,
    LineNotFoundError,
    ParseError,
    ProjectError,
    ProjectFormatError,
    ScenarioError,
    SourceNotFoundError,
    SourceReadError,
    SourceWriteError,
    UnknownMnemonicError,
    UnsupportedSourceError,
)


class TestBase(unittest.TestCase):
    """Behavior common to every error."""

    def test_str_shows_the_code(self) -> None:
        error = AsmxError("something went wrong")
        self.assertEqual(str(error), "[ERR_ASMX] something went wrong")

    def test_code_can_be_replaced(self) -> None:
        error = AsmxError("it broke", code="ERR_CUSTOM", stage="test")
        self.assertEqual(error.code, "ERR_CUSTOM")
        self.assertEqual(error.context["stage"], "test")

    def test_repr_is_short(self) -> None:
        self.assertEqual(repr(AsmxError("x")), "AsmxError(code='ERR_ASMX', message='x')")

    def test_to_dict_without_context(self) -> None:
        data = ProjectError("failed").to_dict()
        self.assertEqual(
            data, {"error": "ProjectError", "code": "ERR_PROJECT", "message": "failed"}
        )

    def test_to_dict_with_context(self) -> None:
        data = SourceNotFoundError("/tmp/x.asm").to_dict()
        self.assertEqual(data["code"], "ERR_SOURCE_NOT_FOUND")
        self.assertEqual(data["context"]["path"], "/tmp/x.asm")

    def test_code_index_covers_every_class(self) -> None:
        for error_class in (
            SourceNotFoundError,
            SourceReadError,
            SourceWriteError,
            UnsupportedSourceError,
            ParseError,
            ProjectError,
            ProjectFormatError,
            BranchNotFoundError,
            BranchExistsError,
            EmptyBranchNameError,
            LastBranchError,
            ScenarioError,
            ConfigError,
            EmulationError,
            AnalysisTimeoutError,
            UnknownMnemonicError,
            LineNotFoundError,
        ):
            with self.subTest(error_class=error_class.__name__):
                self.assertIs(ERROR_CODES[error_class.code], error_class)

    def test_codes_are_unique(self) -> None:
        codes = [c.code for c in ERROR_CODES.values()]
        self.assertEqual(len(codes), len(set(codes)))

    def test_all_start_with_err(self) -> None:
        for code in ERROR_CODES:
            with self.subTest(code=code):
                self.assertTrue(code.startswith("ERR_"))


class TestCompatibilityWithBuiltinErrors(unittest.TestCase):
    """Code that already caught ValueError/KeyError keeps working."""

    def test_missing_document_is_file_not_found(self) -> None:
        with self.assertRaises(FileNotFoundError):
            raise SourceNotFoundError("/tmp/nothing.asm")

    def test_invalid_project_is_value_error(self) -> None:
        with self.assertRaises(ValueError):
            raise ProjectFormatError("p.asmproj", "broken json")

    def test_nonexistent_branch_is_key_error(self) -> None:
        with self.assertRaises(KeyError):
            raise BranchNotFoundError("does_not_exist")

    def test_timeout_is_timeout_error(self) -> None:
        with self.assertRaises(TimeoutError):
            raise AnalysisTimeoutError(2.5, steps=100)

    def test_emulation_is_runtime_error(self) -> None:
        with self.assertRaises(RuntimeError):
            raise EmulationError("could not start")


class TestMessages(unittest.TestCase):
    """The messages need to be useful on their own."""

    def test_file_not_found(self) -> None:
        self.assertIn("/tmp/x.asm", str(SourceNotFoundError("/tmp/x.asm")))

    def test_read_error_brings_the_reason(self) -> None:
        self.assertIn("permission denied", str(SourceReadError("/etc/x", "permission denied")))

    def test_write_error(self) -> None:
        self.assertIn("could not write", str(SourceWriteError("/tmp/x", "disk full")))

    def test_refused_extension_lists_the_accepted_ones(self) -> None:
        error = UnsupportedSourceError("a.bin", ".asm, .s")
        self.assertIn("a.bin", str(error))
        self.assertIn(".asm", str(error))
        self.assertEqual(error.context["expected"], ".asm, .s")

    def test_repeated_branch(self) -> None:
        self.assertEqual(
            str(BranchExistsError("alt")), "[ERR_BRANCH_EXISTS] already exists a branch named alt"
        )

    def test_empty_branch_name(self) -> None:
        self.assertIn("needs a name", str(EmptyBranchNameError()))

    def test_last_branch(self) -> None:
        self.assertIn("at least one branch", str(LastBranchError()))

    def test_scenario_with_a_name(self) -> None:
        error = ScenarioError("invalid limit", scenario="large")
        self.assertEqual(error.scenario, "large")
        self.assertEqual(error.context["scenario"], "large")

    def test_config_with_a_field(self) -> None:
        error = ConfigError("out of range", path="asmx.json", field="timeout")
        self.assertEqual(error.field, "timeout")
        self.assertEqual(error.path, "asmx.json")

    def test_timeout_shows_the_limit(self) -> None:
        error = AnalysisTimeoutError(1.5, steps=256)
        self.assertIn("1.5 s", str(error))
        self.assertEqual(error.steps, 256)

    def test_unknown_mnemonic_shows_the_catalog_size(self) -> None:
        self.assertIn("148", str(UnknownMnemonicError("xyz", 148)))

    def test_nonexistent_line_shows_the_total(self) -> None:
        error = LineNotFoundError(99, 20)
        self.assertIn("99", str(error))
        self.assertIn("20", str(error))

    def test_parse_error_keeps_the_line(self) -> None:
        error = ParseError("strange line", line=7)
        self.assertEqual(error.line, 7)
        self.assertEqual(error.context["line"], 7)


if __name__ == "__main__":
    unittest.main()
