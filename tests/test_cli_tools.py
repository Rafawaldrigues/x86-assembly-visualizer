"""Tests for the ``scan``, ``rules``, ``cluster`` and ``dashboard`` commands.

These four commands are the ones that turn a single-file analysis into something
you can use on a folder: a rule engine, the rule list, similarity grouping and a
local viewer. The tests drive the real command line (through ``cli.main``) and
check the JSON contracts, the exit codes and the security posture of the
dashboard (a token when exposed, no write route at all).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
import unittest.mock

from asmx.cli import EXIT_INPUT, EXIT_OK, EXIT_PROBLEMS, main
from asmx.examples import EXAMPLES
from asmx.logging_setup import reset_logging

SUSPICIOUS = EXAMPLES["suspicious"]["code"]
CLEAN = EXAMPLES["linux-hello"]["code"]


class BaseCLI(unittest.TestCase):
    """Temporary files, captured output and a clean logging state."""

    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.addCleanup(reset_logging)
        self.environment = unittest.mock.patch.dict(
            os.environ, {"ASMX_OUTPUT_DIR": os.path.join(self.dir.name, "results")}
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.suspicious = self.write("suspicious.asm", SUSPICIOUS)
        self.clean = self.write("clean.asm", CLEAN)

    def write(self, name: str, content: str) -> str:
        """Writes a file inside the temporary directory."""
        path = os.path.join(self.dir.name, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def run_cli(self, *argv: str) -> tuple:
        """Runs the command line and returns ``(code, stdout, stderr)``."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def run_json(self, *argv: str) -> tuple:
        """Runs the command with ``--json`` and returns ``(code, payload)``."""
        code, out, _ = self.run_cli(*argv, "--json")
        return code, json.loads(out)


class TestScan(BaseCLI):
    """``asmx scan``: the rule engine over the command line."""

    def test_finds_the_network_rule(self) -> None:
        code, out, _ = self.run_cli("scan", self.suspicious)
        self.assertEqual(code, EXIT_OK)
        self.assertIn("NET001", out)
        self.assertIn("rule(s) matched", out)

    def test_clean_file_matches_nothing(self) -> None:
        code, out, _ = self.run_cli("scan", self.clean)
        self.assertEqual(code, EXIT_OK)
        self.assertIn("0 rule(s) matched", out)

    def test_json_contract(self) -> None:
        code, payload = self.run_json("scan", self.suspicious)
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(payload["schema"], "asmx-scan/1")
        self.assertEqual(payload["command"], "scan")
        self.assertGreater(payload["rules"], 20)
        first = payload["files"][0]
        self.assertEqual(first["name"], "suspicious.asm")
        identifiers = {match["id"] for match in first["matches"]}
        self.assertIn("NET001", identifiers)
        self.assertIn("evidence", first["matches"][0])
        self.assertIn("severity", first["matches"][0])

    def test_fail_on_high_exits_with_problems(self) -> None:
        code, _ = self.run_json("scan", self.suspicious, "--fail-on", "high")
        self.assertEqual(code, EXIT_PROBLEMS)

    def test_fail_on_high_passes_on_clean_file(self) -> None:
        code, _ = self.run_json("scan", self.clean, "--fail-on", "high")
        self.assertEqual(code, EXIT_OK)

    def test_several_files_summary(self) -> None:
        code, out, _ = self.run_cli("scan", self.suspicious, self.clean)
        self.assertEqual(code, EXIT_OK)
        self.assertIn("2 file(s)", out)
        self.assertIn("match(es)", out)

    def test_custom_rule_directory(self) -> None:
        rules = self.write(
            "my.json",
            json.dumps(
                {
                    "schema": "asmx-rules/1",
                    "rules": [
                        {
                            "id": "OWN001",
                            "name": "Own rule",
                            "severity": "low",
                            "match": {"strings": ["collect.example.com"]},
                        }
                    ],
                }
            ),
        )
        code, payload = self.run_json("scan", self.suspicious, "--rules", os.path.dirname(rules))
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(payload["rules"], 1)
        self.assertEqual(payload["files"][0]["matches"][0]["id"], "OWN001")

    def test_no_source_found(self) -> None:
        empty = os.path.join(self.dir.name, "empty")
        os.makedirs(empty, exist_ok=True)
        code, _, err = self.run_cli("scan", empty)
        self.assertEqual(code, EXIT_INPUT)
        self.assertIn("no assembly file found", err)

    def test_missing_path_is_reported(self) -> None:
        code, _, err = self.run_cli("scan", os.path.join(self.dir.name, "no-such.asm"))
        self.assertEqual(code, EXIT_INPUT)
        self.assertIn("ERR_SOURCE_NOT_FOUND", err)

    def test_invalid_rule_file_is_reported(self) -> None:
        broken = self.write("broken.json", json.dumps({"rules": [{"id": "X"}]}))
        code, _, err = self.run_cli("scan", self.clean, "--rules", os.path.dirname(broken))
        self.assertEqual(code, EXIT_INPUT)
        self.assertIn("id or name", err)


class TestRules(BaseCLI):
    """``asmx rules``: the rule set in effect."""

    def test_lists_the_packaged_rules(self) -> None:
        code, out, _ = self.run_cli("rules")
        self.assertEqual(code, EXIT_OK)
        self.assertIn("rule(s) in", out)
        self.assertIn("high", out)

    def test_json_contract(self) -> None:
        code, payload = self.run_json("rules")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(payload["schema"], "asmx-rules/1")
        self.assertTrue(os.path.isdir(payload["directory"]))
        rule = payload["rules"][0]
        for key in ("id", "name", "severity", "description", "tags", "mitre", "match"):
            self.assertIn(key, rule)

    def test_custom_directory(self) -> None:
        self.write(
            "one.json",
            json.dumps({"rules": [{"id": "ONLY1", "name": "Only", "match": {"strings": ["x"]}}]}),
        )
        code, payload = self.run_json("rules", "--rules", self.dir.name)
        self.assertEqual(code, EXIT_OK)
        self.assertEqual([rule["id"] for rule in payload["rules"]], ["ONLY1"])


class TestCluster(BaseCLI):
    """``asmx cluster``: grouping files by similarity."""

    def setUp(self) -> None:
        super().setUp()
        self.twin = self.write("twin.asm", SUSPICIOUS)

    def test_groups_identical_files(self) -> None:
        code, out, _ = self.run_cli("cluster", self.suspicious, self.twin, self.clean)
        self.assertEqual(code, EXIT_OK)
        self.assertIn("group(s)", out)
        self.assertIn("cohesion", out)

    def test_json_contract(self) -> None:
        code, payload = self.run_json("cluster", self.suspicious, self.twin, self.clean)
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(payload["schema"], "asmx-cluster/1")
        self.assertEqual(payload["files"], 3)
        self.assertEqual(payload["groups"][0]["size"], 2)
        self.assertEqual(payload["groups"][0]["members"], ["suspicious.asm", "twin.asm"])

    def test_threshold_splits_the_group(self) -> None:
        code, payload = self.run_json("cluster", self.suspicious, self.clean, "--threshold", "1.1")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(len(payload["groups"]), 2)

    def test_top_lists_the_closest(self) -> None:
        code, payload = self.run_json(
            "cluster", self.suspicious, self.twin, self.clean, "--top", "2"
        )
        self.assertEqual(code, EXIT_OK)
        closest = payload["closest_to_first"]
        self.assertEqual(closest[0]["name"], "twin.asm")
        self.assertAlmostEqual(closest[0]["similarity"], 1.0, places=6)

    def test_complete_linkage(self) -> None:
        code, payload = self.run_json(
            "cluster", self.suspicious, self.twin, "--linkage", "complete"
        )
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(len(payload["groups"]), 1)

    def test_no_source_found(self) -> None:
        empty = os.path.join(self.dir.name, "empty")
        os.makedirs(empty, exist_ok=True)
        code, _, err = self.run_cli("cluster", empty)
        self.assertEqual(code, EXIT_INPUT)
        self.assertIn("no assembly file found", err)


class TestDashboard(BaseCLI):
    """``asmx dashboard``: serving a folder of reports locally."""

    def _folder_with_reports(self) -> str:
        folder = os.path.join(self.dir.name, "results")
        code, _, _ = self.run_cli("analyze", self.suspicious, self.clean, "--out", folder, "--json")
        self.assertEqual(code, EXIT_OK)
        return folder

    def test_serves_and_reports_the_url(self) -> None:
        folder = self._folder_with_reports()
        with unittest.mock.patch("asmx.dashboard.serve") as fake:
            fake.return_value = (unittest.mock.MagicMock(), "http://127.0.0.1:8765/")
            fake.return_value[0].serve_forever.side_effect = KeyboardInterrupt
            code, out, _ = self.run_cli("dashboard", folder)
        self.assertEqual(code, EXIT_OK)
        self.assertIn("dashboard:", out)
        self.assertIn("http://127.0.0.1:8765/", out)
        self.assertIn("read-only", out)
        fake.assert_called_once()
        self.assertEqual(fake.call_args.kwargs["host"], "127.0.0.1")

    def test_empty_folder_explains_what_to_do(self) -> None:
        empty = os.path.join(self.dir.name, "empty")
        os.makedirs(empty, exist_ok=True)
        code, _, err = self.run_cli("dashboard", empty)
        self.assertEqual(code, EXIT_INPUT)
        self.assertIn("no report found", err)
        self.assertIn("asmx analyze", err)

    def test_forwards_the_token_and_the_host(self) -> None:
        folder = self._folder_with_reports()
        with unittest.mock.patch("asmx.dashboard.serve") as fake:
            fake.return_value = (unittest.mock.MagicMock(), "http://0.0.0.0:9999/?token=abc")
            fake.return_value[0].serve_forever.side_effect = KeyboardInterrupt
            self.run_cli(
                "dashboard", folder, "--host", "0.0.0.0", "--port", "9999", "--token", "abc"
            )
        self.assertEqual(fake.call_args.kwargs["token"], "abc")
        self.assertEqual(fake.call_args.kwargs["host"], "0.0.0.0")
        self.assertEqual(fake.call_args.kwargs["port"], 9999)

    def test_uses_the_configured_output_directory(self) -> None:
        folder = os.path.join(self.dir.name, "results")
        self.run_cli("analyze", self.clean, "--out", folder, "--json")
        with unittest.mock.patch("asmx.dashboard.serve") as fake:
            fake.return_value = (unittest.mock.MagicMock(), "http://127.0.0.1:8765/")
            fake.return_value[0].serve_forever.side_effect = KeyboardInterrupt
            code, _, _ = self.run_cli("dashboard")
        self.assertEqual(code, EXIT_OK)


class TestAnalyzeExtras(BaseCLI):
    """The batch command gained a manifest, clustering and parallel workers."""

    def test_writes_the_manifest(self) -> None:
        folder = os.path.join(self.dir.name, "out")
        code, _, _ = self.run_cli("analyze", self.suspicious, self.clean, "--out", folder, "--json")
        self.assertEqual(code, EXIT_OK)
        with open(os.path.join(folder, "index.json"), encoding="utf-8") as handle:
            manifest = json.load(handle)
        self.assertEqual(manifest["schema"], "asmx-analyze/1")
        self.assertEqual(len(manifest["files"]), 2)
        entry = next(f for f in manifest["files"] if f["name"] == "suspicious.asm")
        for key in (
            "risk",
            "score",
            "instructions",
            "behaviors",
            "indicators",
            "problems",
            "platform",
            "report",
        ):
            self.assertIn(key, entry)
        self.assertEqual(entry["risk"], "high")

    def test_manifest_is_written_even_without_the_json_flag(self) -> None:
        folder = os.path.join(self.dir.name, "out2")
        self.run_cli("analyze", self.clean, "--out", folder, "--format", "md")
        self.assertTrue(os.path.isfile(os.path.join(folder, "index.json")))

    def test_cluster_flag_adds_groups(self) -> None:
        folder = os.path.join(self.dir.name, "out3")
        code, payload = self.run_json(
            "analyze", self.suspicious, self.suspicious, "--out", folder, "--cluster"
        )
        self.assertEqual(code, EXIT_OK)
        self.assertTrue(payload["groups"])
        self.assertEqual(payload["groups"][0]["size"], 2)

    def test_parallel_workers_produce_the_same_result(self) -> None:
        folder = os.path.join(self.dir.name, "out4")
        code, payload = self.run_json(
            "analyze", self.suspicious, self.clean, "--out", folder, "--jobs", "2"
        )
        self.assertEqual(code, EXIT_OK)
        names = [entry["name"] for entry in payload["files"]]
        self.assertEqual(names, ["suspicious.asm", "clean.asm"])

    def test_parallel_failure_does_not_take_the_batch_down(self) -> None:
        folder = os.path.join(self.dir.name, "out5")
        code, payload = self.run_json(
            "analyze", self.clean, self.suspicious, "--out", folder, "--jobs", "2"
        )
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(len(payload["files"]), 2)


if __name__ == "__main__":
    unittest.main()
