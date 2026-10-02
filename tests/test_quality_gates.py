"""Tests of the quality gates: 100% annotations and docstrings."""

import contextlib
import io
import os
import tempfile
import unittest

from tools import quality_gates as qg


def silent(function: object, *args: object) -> int:
    """Run a gate function swallowing whatever it prints.

    Args:
        function: Function to call.
        *args: Arguments for it.

    Returns:
        The exit code returned by the function.
    """
    with contextlib.redirect_stdout(io.StringIO()):
        return function(*args)  # type: ignore[operator]


def write_module(text: str) -> str:
    """Write a temporary module and return its absolute path.

    Returns:
        Absolute path of the module that was written.
    """
    handle = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False, encoding="utf-8")
    handle.write(text)
    handle.close()
    return handle.name


class TestDetection(unittest.TestCase):
    """The gate has to really find the problems it promises to find."""

    def setUp(self) -> None:
        """Start the list of modules created by the test."""
        self.created = []

    def tearDown(self) -> None:
        """Delete the modules created by the test."""
        for path in self.created:
            os.unlink(path)

    def violations(self, code: str, **kwargs: object) -> list:
        """Check a temporary module and keep its path for the cleanup.

        Returns:
            Violations found in the module.
        """
        path = write_module(code)
        self.created.append(path)
        return qg.check_file(path, **kwargs)  # type: ignore[arg-type]

    def kinds(self, code: str, **kwargs: object) -> set:
        """Return the set of violation kinds found in a module.

        Returns:
            Names of the kinds found, without repetition.
        """
        return {v.kind for v in self.violations(code, **kwargs)}

    def test_module_without_docstring(self) -> None:
        """A module without a docstring is reported."""
        self.assertIn("docstring", self.kinds("x = 1\n"))

    def test_function_without_annotation(self) -> None:
        """A parameter without an annotation is reported."""
        self.assertIn(
            "annotation",
            self.kinds('"""Doc."""\n\n\ndef f(a):\n    """Does something."""\n    return a\n'),
        )

    def test_method_without_return_annotation(self) -> None:
        """A method without a return annotation is reported."""
        code = (
            '"""Doc."""\n\n\nclass C:\n    """Class."""\n\n'
            '    def m(self, a: int):\n        """Method."""\n'
        )
        self.assertIn("annotation", self.kinds(code))

    def test_args_required_from_three_parameters(self) -> None:
        """Three parameters require an Args: section."""
        code = (
            '"""Doc."""\n\n\ndef f(a: int, b: int, c: int) -> int:\n'
            '    """Adds."""\n    return a + b + c\n'
        )
        self.assertIn("args", self.kinds(code))

    def test_args_with_a_missing_parameter(self) -> None:
        """A parameter left out of Args: is reported by name."""
        code = (
            '"""Doc."""\n\n\ndef f(a: int, b: int, c: int) -> int:\n'
            '    """Adds.\n\n    Args:\n        a: first.\n        b: second.\n    """\n'
            "    return a + b + c\n"
        )
        violations = self.violations(code)
        self.assertTrue(any(v.kind == "args" and "c" in v.detail for v in violations))

    def test_returns_required(self) -> None:
        """A function that returns a value requires Returns:."""
        code = '"""Doc."""\n\n\ndef f() -> int:\n    """Returns."""\n    return 1\n'
        self.assertIn("returns", self.kinds(code))

    def test_raises_required(self) -> None:
        """A function that raises requires Raises:."""
        code = '"""Doc."""\n\n\ndef f() -> None:\n    """Raises."""\n' '    raise ValueError("x")\n'
        self.assertIn("raises", self.kinds(code))

    def test_first_line_without_punctuation(self) -> None:
        """The first line of the docstring must end with punctuation."""
        code = '"""Doc."""\n\n\ndef f() -> None:\n    """no period at the end"""\n'
        self.assertIn("docstring", self.kinds(code))

    def test_docstring_free_mode_only_requires_annotations(self) -> None:
        """Without docstrings only the annotations are enforced."""
        code = '"""Doc."""\n\n\ndef f(a: int) -> int:  # no docstring\n    return a\n'
        self.assertEqual(self.violations(code, require_docstrings=False), [])

    def test_syntax_error_is_reported(self) -> None:
        """A syntax error becomes a violation of kind syntax."""
        violations = self.violations("def f(:\n")
        self.assertEqual(violations[0].kind, "syntax")

    def test_varargs_annotated(self) -> None:
        """Annotated *args and **kwargs are enough."""
        code = (
            '"""Doc."""\n\n\ndef f(*args: int, **kwargs: str) -> None:\n'
            '    """Receives everything."""\n'
        )
        self.assertEqual(self.violations(code, require_docstrings=False), [])

    def test_nested_function_is_checked(self) -> None:
        """A function inside another one is checked too."""
        code = (
            '"""Doc."""\n\n\ndef f() -> None:\n    """Outer."""\n\n'
            "    def inner():\n        pass\n"
        )
        self.assertIn("annotation", self.kinds(code))

    def test_static_and_class_methods(self) -> None:
        """Clean static and class methods pass the gate."""
        code = (
            '"""Doc."""\n\n\nclass C:\n    """Class."""\n\n'
            '    @staticmethod\n    def a() -> None:\n        """A."""\n\n'
            '    @classmethod\n    def b(cls) -> None:\n        """B."""\n'
        )
        self.assertEqual(self.violations(code), [])

    def test_summary_counts_by_kind(self) -> None:
        """The summary counts the violations by kind."""
        count = qg.summarize(
            [
                qg.Violation("a.py", 1, "f", "args", "x"),
                qg.Violation("a.py", 2, "g", "args", "y"),
                qg.Violation("a.py", 3, "h", "docstring", "z"),
            ]
        )
        self.assertEqual(count, {"args": 2, "docstring": 1})

    def test_violation_str(self) -> None:
        """The text of a violation follows file:line: kind name — detail."""
        text = str(qg.Violation("a.py", 7, "f", "args", "missing b"))
        self.assertEqual(text, "a.py:7: args f — missing b")


class TestRepository(unittest.TestCase):
    """The project itself has to pass the gates."""

    def test_annotations_and_docstrings_of_the_code(self) -> None:
        """The package code passes both gates."""
        violations = qg.check_paths(list(qg.DEFAULT_PATHS))
        self.assertEqual(
            [str(v) for v in violations],
            [],
            "the package code must be 100% annotated and documented",
        )

    def test_annotations_of_the_tests(self) -> None:
        """The test files are fully annotated."""
        violations = qg.check_paths(list(qg.TEST_PATHS), require_docstrings=False)
        annotations = [str(v) for v in violations if v.kind == "annotation"]
        self.assertEqual(annotations, [], "the tests also need annotations")

    def test_file_list(self) -> None:
        """The walk lists the .py files of a folder."""
        files = qg.iter_python_files(["asmx"])
        self.assertIn("asmx/cli.py", files)
        self.assertTrue(all(name.endswith(".py") for name in files))

    def test_ignores_virtual_environment(self) -> None:
        """The virtual environment is left out of the walk."""
        files = qg.iter_python_files(["."])
        self.assertFalse([name for name in files if name.startswith(".venv")])

    def test_main_approves_the_project(self) -> None:
        """The utility approves the package with exit code zero."""
        self.assertEqual(silent(qg.main, ["asmx", "--quiet"]), 0)

    def test_main_rejects_a_bad_file(self) -> None:
        """The utility rejects a module without annotations."""
        path = write_module("def f(a):\n    return a\n")
        try:
            self.assertEqual(silent(qg.main, [path, "--quiet"]), 1)
        finally:
            os.unlink(path)

    def test_argument_parser(self) -> None:
        """The defaults are the standard paths and no --quiet."""
        args = qg.build_parser().parse_args([])
        self.assertEqual(tuple(args.paths), qg.DEFAULT_PATHS)
        self.assertFalse(args.quiet)


if __name__ == "__main__":
    unittest.main()
