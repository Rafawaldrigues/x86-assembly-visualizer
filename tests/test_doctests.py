"""Runs the code examples written inside the docstrings.

A docstring that never runs ages into a lie: these tests execute every example
in the package modules and fail when one stops matching the code.
"""

from __future__ import annotations

import doctest
import importlib
import pkgutil
import unittest
from typing import List

import asmx

#: Modules that only make sense with a screen attached.
NO_DOCTEST = ("asmx.ui",)

#: Minimum number of examples that must exist, so the test cannot pass by
#: accident when somebody deletes the docstrings.
MINIMUM_EXAMPLES = 40


def package_modules() -> List[str]:
    """Lists the importable modules of the ``asmx`` package.

    Returns:
        Sorted module names, including ``asmx`` itself and excluding the ones in
        :data:`NO_DOCTEST`.
    """
    names = []
    for info in pkgutil.iter_modules(asmx.__path__, "asmx."):
        if info.name.startswith(NO_DOCTEST):
            continue
        names.append(info.name)
    names.append("asmx")
    return sorted(names)


class TestDoctests(unittest.TestCase):
    """The examples inside the docstrings must stay true."""

    def test_every_example_passes(self) -> None:
        """Every module must run its own doctests without a single failure."""
        total = 0
        for name in package_modules():
            with self.subTest(module=name):
                module = importlib.import_module(name)
                result = doctest.testmod(
                    module, verbose=False, report=False, optionflags=doctest.ELLIPSIS
                )
                total += result.attempted
                self.assertEqual(result.failed, 0, "broken example in %s" % name)
        self.assertGreaterEqual(
            total,
            MINIMUM_EXAMPLES,
            "expected at least %d examples in the docstrings" % MINIMUM_EXAMPLES,
        )

    def test_package_modules_are_importable(self) -> None:
        """The discovery helper must find the package modules and skip the UI."""
        self.assertIn("asmx.cli", package_modules())
        self.assertIn("asmx.workspace", package_modules())
        self.assertNotIn("asmx.ui.app", package_modules())


if __name__ == "__main__":
    unittest.main()
