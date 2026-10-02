"""Tests for the local dashboard (:mod:`asmx.dashboard`).

The dashboard serves files that came from analysing untrusted assembly, so the
tests care about three things beyond the happy path: a hostile sample name must
not become markup, a request must not escape the served directory, and the
server must not become an open door when it is bound beyond the loopback.
"""

from __future__ import annotations

import http.client
import json
import os
import tempfile
import unittest
from unittest import mock

from asmx import dashboard

from asmx.dashboard import (
    DASHBOARD_SCHEMA,
    Sample,
    build_index,
    find_manifest,
    load_samples,
    render_page,
    serve,
)
from asmx.errors import ProjectError, SourceReadError

MANIFEST = {
    "schema": "asmx-analyze/1",
    "files": [
        {
            "name": "clean.asm",
            "risk": "low",
            "score": 3,
            "instructions": 8,
            "behaviors": 1,
            "indicators": 1,
            "problems": 0,
            "platform": "linux · 64-bit",
            "report": "clean.report.html",
            "reason": "nothing stands out",
        },
        {
            "name": "suspicious.asm",
            "risk": "high",
            "score": 42,
            "instructions": 44,
            "behaviors": 5,
            "indicators": 6,
            "problems": 0,
            "report": "suspicious.report.html",
            "reason": "network code",
        },
        {
            "name": "broken.asm",
            "risk": "critical",
            "score": 100,
            "instructions": 10,
            "behaviors": 2,
            "indicators": 2,
            "problems": 10,
            "report": "broken.report.html",
        },
    ],
}

# The real shape of an ``asmx-report/1`` payload: risk is a mapping with
# ``reasons``, the counts live in ``stats`` and in the length of the lists, and
# ``summary`` is a prose string (not a mapping).
REPORT = {
    "schema": "asmx-report/1",
    "source": {"name": "solo.asm", "size": 1200, "lines": 40},
    "platform": {"os": "linux", "bits": 64, "abi": "System V AMD64"},
    "stats": {"instructions": 20, "blocks": 2},
    "risk": {
        "level": "medium",
        "score": 18,
        "description": "worth a read",
        "reasons": ["a few signals"],
    },
    "problems": [{"code": "DIV001"}, {"code": "MEM001"}],
    "behaviors": [{"category": "network"}, {"category": "crypto"}, {"category": "console-io"}],
    "iocs": {
        "url": [{"value": "x"}],
        "string": [{"value": "a"}, {"value": "b"}],
        "path_unix": [{"value": "/tmp/x"}],
    },
    "summary": "solo.asm has 20 instructions...",
}


class TestModel(unittest.TestCase):
    """The sample model and the index it feeds."""

    def test_to_dict_includes_fields_and_extras(self) -> None:
        sample = Sample("a.asm", extra={"size": 10})
        values_data = sample.to_dict()
        self.assertEqual(values_data["name"], "a.asm")
        self.assertEqual(values_data["size"], 10)
        self.assertIn("risk", values_data)

    def test_rank_sorts_by_severity_then_score(self) -> None:
        critical_sample = Sample("a", risk="critical", score=10)
        high_score = Sample("b", risk="high", score=90)
        low_score = Sample("c", risk="high", score=10)
        unknown_sample = Sample("d")
        self.assertLess(critical_sample.rank, high_score.rank)
        self.assertLess(high_score.rank, low_score.rank)
        self.assertLess(low_score.rank, unknown_sample.rank)

    def test_build_index_counts_levels(self) -> None:
        idx = build_index(
            [
                Sample("a", risk="high", score=40),
                Sample("b", risk="high", score=10),
                Sample("c", risk="low", score=1),
            ],
            title="lote",
        )
        self.assertEqual(idx["schema"], DASHBOARD_SCHEMA)
        self.assertEqual(idx["total"], 3)
        self.assertEqual(idx["by_risk"]["high"], 2)
        self.assertEqual(idx["worst"], 40)
        self.assertEqual(idx["title"], "lote")

    def test_build_index_empty(self) -> None:
        idx = build_index([])
        self.assertEqual(idx["total"], 0)
        self.assertEqual(idx["worst"], 0)
        self.assertEqual(idx["samples"], [])


class TestRender(unittest.TestCase):
    """The page must be self-contained, escaped and readable."""

    def page_html(self, **kwargs: object) -> str:
        idx = build_index(
            [
                Sample(
                    "suspicious.asm",
                    risk="high",
                    score=42,
                    instructions=44,
                    behaviors=5,
                    indicators=6,
                    report="suspicious.report.html",
                    reason="network code",
                )
            ],
            title="ASM X",
        )
        return render_page(idx, title="ASM X", **kwargs)

    def test_contains_title_table_and_link(self) -> None:
        page_html = self.page_html()
        self.assertIn("<title>ASM X — dashboard</title>", page_html)
        self.assertIn("suspicious.asm", page_html)
        self.assertIn('href="report/suspicious.report.html"', page_html)
        self.assertIn("network code", page_html)

    def test_no_external_resources(self) -> None:
        page_html = self.page_html()
        for forbidden in ("http://", "https://", "<script src", "<link ", "cdn."):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, page_html)

    def test_page_without_sample_requests_is_static(self) -> None:
        page_html = self.page_html(live=False)
        self.assertNotIn("<script>", page_html)
        self.assertNotIn("oninput", page_html)
        self.assertIn("suspicious.asm", page_html)

    def test_escapes_hostile_name(self) -> None:
        idx = build_index([Sample('<script>alert("x")</script>.asm', risk="low")])
        page_html = render_page(idx)
        self.assertNotIn("<script>alert", page_html)
        self.assertIn("&lt;script&gt;", page_html)

    def test_empty_directory_message(self) -> None:
        self.assertIn("no samples in this folder", render_page(build_index([])))

    def test_cards_show_totals(self) -> None:
        page_html = self.page_html()
        self.assertIn("<b>1</b><span>samples</span>", page_html)
        self.assertIn("<b>42</b><span>worst score</span>", page_html)

    def test_no_link_without_report(self) -> None:
        page_html = render_page(build_index([Sample("sem-report_data.asm", risk="low")]))
        self.assertNotIn('href="report/"', page_html)
        self.assertIn("sem-report_data.asm", page_html)


class TestLoading(unittest.TestCase):
    """Reading a folder: manifest first, then the reports themselves."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder_path = self.tmp.name

    def write_fixture(self, item_name: str, values_data: object) -> str:
        file_path = os.path.join(self.folder_path, item_name)
        with open(file_path, "w", encoding="utf-8") as source_file:
            if isinstance(values_data, str):
                source_file.write(values_data)
            else:
                json.dump(values_data, source_file)
        return file_path

    def test_reads_manifest_and_sorts_by_risk(self) -> None:
        self.write_fixture("index.json", MANIFEST)
        sample_list = load_samples(self.folder_path)
        self.assertEqual(
            [a.name for a in sample_list], ["broken.asm", "suspicious.asm", "clean.asm"]
        )
        self.assertEqual(sample_list[0].risk, "critical")
        self.assertEqual(
            find_manifest(self.folder_path), os.path.join(self.folder_path, "index.json")
        )

    def test_reads_reports_without_manifest(self) -> None:
        self.write_fixture("solo.report.json", REPORT)
        sample_list = load_samples(self.folder_path)
        self.assertEqual(len(sample_list), 1)
        self.assertEqual(sample_list[0].name, "solo")
        self.assertEqual(sample_list[0].risk, "medium")
        self.assertEqual(sample_list[0].score, 18)
        self.assertEqual(sample_list[0].instructions, 20)
        self.assertEqual(sample_list[0].behaviors, 3)
        self.assertEqual(sample_list[0].indicators, 4)
        self.assertEqual(sample_list[0].problems, 2)
        self.assertEqual(sample_list[0].platform, "linux 64-bit")
        self.assertEqual(sample_list[0].reason, "a few signals")
        self.assertEqual(sample_list[0].report, "solo.report.json")

    def test_lists_html_without_manifest_or_json(self) -> None:
        self.write_fixture("velho.report.html", "<html></html>")
        sample_list = load_samples(self.folder_path)
        self.assertEqual([a.name for a in sample_list], ["velho"])
        self.assertEqual(sample_list[0].risk, "")

    def test_broken_json_is_skipped(self) -> None:
        """One broken report must not take the whole folder down."""
        self.write_fixture("broken.report.json", "{ not json }")
        self.write_fixture("bom.report.json", REPORT)
        self.assertEqual([a.name for a in load_samples(self.folder_path)], ["bom"])

    def test_missing_directory(self) -> None:
        with self.assertRaises(ProjectError):
            load_samples(os.path.join(self.folder_path, "does-not-exist"))

    def test_manifest_with_invalid_entries(self) -> None:
        self.write_fixture("index.json", {"files": ["source_text", {"name": "ok.asm"}]})
        self.assertEqual([a.name for a in load_samples(self.folder_path)], ["ok.asm"])

    def test_risk_as_plain_text(self) -> None:
        self.write_fixture("a.report.json", {"risk": "high", "score": 7})
        sample = load_samples(self.folder_path)[0]
        self.assertEqual(sample.risk, "high")
        self.assertEqual(sample.score, 7)

    def test_risk_without_reasons_uses_description(self) -> None:
        self.write_fixture(
            "b.report.json",
            {"risk": {"level": "low", "score": 1, "description": "nothing stands out"}},
        )
        self.assertEqual(load_samples(self.folder_path)[0].reason, "nothing stands out")

    def test_report_without_risk(self) -> None:
        self.write_fixture("b.report.json", {"schema": "asmx-report/1"})
        self.assertEqual(load_samples(self.folder_path)[0].risk, "")

    def test_oversized_file_rejected(self) -> None:
        self.write_fixture("large.report.json", {"x": "y"})
        with mock.patch.object(dashboard, "MAX_REPORT_BYTES", 5):
            with self.assertRaises(SourceReadError) as caught:
                dashboard._load_json(os.path.join(self.folder_path, "large.report.json"))
        self.assertIn("larger than the limit", str(caught.exception))

    def test_unreadable_report_skipped(self) -> None:
        self.write_fixture("large.report.json", {"x": "y"})
        with mock.patch.object(dashboard, "MAX_REPORT_BYTES", 5):
            self.assertEqual(load_samples(self.folder_path), [])

    def test_no_manifest_when_absent(self) -> None:
        self.assertIsNone(find_manifest(self.folder_path))


class TestServer(unittest.TestCase):
    """The HTTP surface: routes, content types, traversal and the token."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        folder_path = cls.tmp.name
        with open(os.path.join(folder_path, "index.json"), "w", encoding="utf-8") as source_file:
            json.dump(MANIFEST, source_file)
        with open(os.path.join(folder_path, "suspicious.report.html"), "w", encoding="utf-8") as a:
            a.write("<html><body>report</body></html>")
        cls.folder_path = folder_path

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def request(
        self,
        server_instance: object,
        file_path: str,
        method_name: str = "GET",
        headers: dict | None = None,
    ) -> tuple:
        """Sends one request to the running dashboard."""
        connection = http.client.HTTPConnection(
            "127.0.0.1", server_instance.server_port, timeout=5  # type: ignore[attr-defined]
        )
        try:
            connection.request(method_name, file_path, headers=headers or {})
            response = connection.getresponse()
            return response.status, response.getheader("Content-Type"), response.read()
        finally:
            connection.close()

    def server_instance(self, **kwargs: object) -> object:
        server_instance, _ = serve(self.folder_path, port=0, background=True, **kwargs)
        self.addCleanup(server_instance.server_close)  # type: ignore[attr-defined]
        self.addCleanup(server_instance.shutdown)  # type: ignore[attr-defined]
        return server_instance

    def test_home_page(self) -> None:
        server_instance = self.server_instance()
        status, item_type, body = self.request(server_instance, "/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", item_type)
        self.assertIn(b"suspicious.asm", body)

    def test_api_samples(self) -> None:
        server_instance = self.server_instance()
        status, item_type, body = self.request(server_instance, "/api/samples")
        self.assertEqual(status, 200)
        self.assertIn("application/json", item_type)
        values_data = json.loads(body)
        self.assertEqual(values_data["schema"], DASHBOARD_SCHEMA)
        self.assertEqual(values_data["total"], 3)

    def test_api_summary(self) -> None:
        server_instance = self.server_instance()
        status, _, body = self.request(server_instance, "/api/summary")
        self.assertEqual(status, 200)
        values_data = json.loads(body)
        self.assertNotIn("samples", values_data)
        self.assertEqual(values_data["by_risk"]["critical"], 1)

    def test_serves_report(self) -> None:
        server_instance = self.server_instance()
        status, item_type, body = self.request(server_instance, "/report/suspicious.report.html")
        self.assertEqual(status, 200)
        self.assertIn("text/html", item_type)
        self.assertIn(b"report", body)

    def test_serves_json_content_type(self) -> None:
        server_instance = self.server_instance()
        status, item_type, _ = self.request(server_instance, "/report/index.json")
        self.assertEqual(status, 200)
        self.assertIn("application/json", item_type)

    def test_head_has_no_body(self) -> None:
        server_instance = self.server_instance()
        status, _, body = self.request(server_instance, "/", method_name="HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")

    def test_traversal_blocked(self) -> None:
        server_instance = self.server_instance()
        for file_path in (
            "/report/../index.json",
            "/report/..%2F..%2Fetc%2Fpasswd",
            "/report/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ):
            with self.subTest(file_path=file_path):
                status, _, _ = self.request(server_instance, file_path)
                self.assertEqual(status, 404)

    def test_unknown_path(self) -> None:
        server_instance = self.server_instance()
        self.assertEqual(self.request(server_instance, "/nothing")[0], 404)
        self.assertEqual(self.request(server_instance, "/report/does-not-exist.html")[0], 404)

    def test_token_protects_routes(self) -> None:
        server_instance = self.server_instance(token="secret_token")
        self.assertEqual(self.request(server_instance, "/")[0], 403)
        self.assertEqual(self.request(server_instance, "/?token=secret_token")[0], 200)
        self.assertEqual(
            self.request(server_instance, "/", headers={"X-ASMX-Token": "secret_token"})[0], 200
        )
        self.assertEqual(self.request(server_instance, "/?token=wrong")[0], 403)

    def test_generated_url(self) -> None:
        server_instance, url = serve(self.folder_path, port=0, background=True)
        self.addCleanup(server_instance.shutdown)
        self.addCleanup(server_instance.server_close)
        self.assertTrue(url.startswith("http://127.0.0.1:"))
        self.assertNotIn("token", url)

    def test_url_includes_required_token(self) -> None:
        server_instance, url = serve(self.folder_path, port=0, background=True, token="abc")
        self.addCleanup(server_instance.shutdown)
        self.addCleanup(server_instance.server_close)
        self.assertIn("?token=abc", url)

    def test_missing_directory_does_not_start(self) -> None:
        with self.assertRaises(ProjectError):
            serve(os.path.join(self.folder_path, "does-not-exist"), port=0)

    def test_external_host_generates_token(self) -> None:
        try:
            server_instance, url = serve(self.folder_path, host="0.0.0.0", port=0, background=True)
        except OSError as caught_error:  # the sandbox may refuse to expose the interface
            self.skipTest("cannot bind 0.0.0.0 here: %s" % caught_error)
        self.addCleanup(server_instance.shutdown)
        self.addCleanup(server_instance.server_close)
        self.assertIn("token=", url)


if __name__ == "__main__":
    unittest.main()
