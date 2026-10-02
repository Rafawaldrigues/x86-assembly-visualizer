"""A local, read-only web dashboard for a folder of analysis reports.

The command line is enough to analyse one sample, but a folder with three
hundred of them needs something you can sort, filter and click through. This
module serves exactly that, using only :mod:`http.server` from the standard
library — no Flask, no template engine, no CDN, no telemetry.

What it does:

* reads the manifest written by ``asmx analyze`` (``index.json``, schema
  ``asmx-analyze/1``) and, when it is not there, falls back to scanning the
  directory for ``*.report.json`` / ``*.report.html``;
* renders one self-contained HTML page with the sample table, the risk of each
  sample, quick filters and links to the full reports;
* exposes the same data as JSON (``/api/samples``, ``/api/summary``) so another
  tool can consume it;
* refuses to write anything and refuses to serve a path outside the directory it
  was pointed at.

Security posture: it binds to ``127.0.0.1`` unless you explicitly ask for
another interface, it only answers ``GET``/``HEAD``, and when it is exposed
beyond the loopback it can require a token (``--token``). There is no login, no
cookie and no session: the dashboard is a viewer for files that are already on
your disk.

Example:
    >>> from asmx.dashboard import build_index, render_page
    >>> page_html = render_page(build_index([]), title="ASM X")
    >>> "no samples" in page_html
    True
"""

from __future__ import annotations

import html
import json
import os
import secrets
import socket
import threading
import webbrowser
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import unquote, urlparse

from .errors import ProjectError, SourceReadError
from .logging_setup import get_logger, log_event

__all__ = [
    "DASHBOARD_SCHEMA",
    "Sample",
    "build_index",
    "find_manifest",
    "load_samples",
    "render_page",
    "serve",
]

logger = get_logger(__name__)

#: Schema of the manifest the dashboard reads and writes.
DASHBOARD_SCHEMA = "asmx-dashboard/1"

#: Risk levels, most serious first, used for sorting and colouring.
RISK_ORDER: Tuple[str, ...] = ("critical", "high", "medium", "low")

#: How many bytes of a report we are willing to read while scanning a folder.
MAX_REPORT_BYTES = 20 * 1024 * 1024


@dataclass
class Sample:
    """One analysed sample, as the dashboard sees it.

    Attributes:
        name: File name, used as the link target and the display name.
        risk: Risk level (``low``..``critical``); empty when unknown.
        score: Risk score from 0 to 100.
        instructions: Instruction count.
        behaviors: Number of behaviours observed.
        indicators: Number of indicators found.
        problems: Number of validation problems.
        platform: Short platform string (``linux · 64-bit``).
        report: Relative path of the full report, when one exists.
        reason: One-line reason for the risk, when available.
        extra: Anything else the manifest carried for this sample.
    """

    name: str
    risk: str = ""
    score: int = 0
    instructions: int = 0
    behaviors: int = 0
    indicators: int = 0
    problems: int = 0
    platform: str = ""
    report: str = ""
    reason: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialises the sample for the JSON API.

        Returns:
            Dictionary with the summary fields and the extras.
        """
        values_data = {
            "name": self.name,
            "risk": self.risk,
            "score": self.score,
            "instructions": self.instructions,
            "behaviors": self.behaviors,
            "indicators": self.indicators,
            "problems": self.problems,
            "platform": self.platform,
            "report": self.report,
            "reason": self.reason,
        }
        values_data.update(self.extra)
        return values_data

    @property
    def rank(self) -> int:
        """Sort key that puts the most serious samples first.

        Returns:
            ``0`` for critical, up to ``4`` for an unknown level, then the score
            in reverse so that within the same level the highest score leads.
        """
        level_name = RISK_ORDER.index(self.risk) if self.risk in RISK_ORDER else len(RISK_ORDER)
        return level_name * 1000 - self.score


def _risk_of(values_data: Dict[str, Any]) -> Tuple[str, int, str]:
    """Extracts the risk level, the score and a one-line reason from a report.

    The report schema (``asmx-report/1``) carries ``risk`` as a mapping with
    ``score``, ``level``, ``description`` and ``reasons``; the summary written by
    ``asmx analyze`` flattens those three fields per sample. Both shapes are
    accepted here, plus the degenerate one where an old report has neither.

    Args:
        values_data: Report dictionary (``asmx-report/1``) or manifest entry.

    Returns:
        Tuple ``(level, score, reason)``, with empty values when the payload has
        no risk assessment at all.
    """
    risk_data = values_data.get("risk")
    if isinstance(risk_data, dict):
        reason_list = risk_data.get("reasons") or []
        first_item = ""
        if isinstance(reason_list, (list, tuple)) and reason_list:
            first_item = str(reason_list[0])
        elif isinstance(reason_list, str):
            first_item = reason_list
        return (
            str(risk_data.get("level") or ""),
            int(risk_data.get("score") or 0),
            first_item or str(risk_data.get("description") or ""),
        )
    if isinstance(risk_data, str):
        return risk_data, int(values_data.get("score") or 0), str(values_data.get("reason") or "")
    return (
        str(values_data.get("level") or ""),
        int(values_data.get("score") or 0),
        str(values_data.get("reason") or ""),
    )


def _sample_from_report(item_name: str, values_data: Dict[str, Any], file_path: str) -> Sample:
    """Builds a :class:`Sample` from a report payload.

    Args:
        item_name: File name to show.
        values_data: Report dictionary (``asmx-report/1``).
        file_path: Relative path of the report file.

    Returns:
        The sample, with whatever the report had to offer. Counts come from
        ``stats`` and from the length of the ``problems``/``behaviors`` lists,
        which is how the report schema exposes them.
    """
    level_name, score_points, reason_text = _risk_of(values_data)
    statistics = values_data.get("stats") or {}
    source_text = values_data.get("source") or {}
    platform_info = values_data.get("platform") or {}
    indicator_count = values_data.get("iocs") or {}
    indicator_total = (
        sum(len(numeric_value) for numeric_value in indicator_count.values())
        if isinstance(indicator_count, dict)
        else 0
    )
    bits = platform_info.get("bits")
    platform_label = " ".join(
        part_name
        for part_name in (str(platform_info.get("os") or ""), "%s-bit" % bits if bits else "")
        if part_name
    )
    return Sample(
        name=item_name,
        risk=level_name,
        score=score_points,
        instructions=int(statistics.get("instructions") or 0),
        behaviors=len(values_data.get("behaviors") or []),
        indicators=indicator_total,
        problems=len(values_data.get("problems") or []),
        platform=platform_label,
        report=file_path,
        reason=reason_text,
        extra={
            "size": int(source_text.get("size") or 0),
            "lines": int(source_text.get("lines") or 0),
        },
    )


def find_manifest(directory: str) -> Optional[str]:
    """Finds the manifest written by ``asmx analyze``.

    Args:
        directory: Folder to inspect.

    Returns:
        Path of ``index.json`` when it exists, otherwise ``None``.
    """
    candidate_path = os.path.join(directory, "index.json")
    return candidate_path if os.path.isfile(candidate_path) else None


def _load_json(path: str) -> Dict[str, Any]:
    """Reads a JSON file with a size ceiling.

    Args:
        path: File to read.

    Returns:
        The parsed object; an empty dictionary when the file is not a JSON
        object.

    Raises:
        SourceReadError: File missing, too big, unreadable or malformed.
    """
    if not os.path.isfile(path):
        raise SourceReadError(path, "file not found")
    byte_count = os.path.getsize(path)
    if byte_count > MAX_REPORT_BYTES:
        raise SourceReadError(path, "is larger than the limit of %d bytes" % MAX_REPORT_BYTES)
    try:
        with open(path, encoding="utf-8") as source_file:
            values_data = json.load(source_file)
    except OSError as caught_error:
        raise SourceReadError(path, str(caught_error)) from caught_error
    except ValueError as caught_error:
        raise SourceReadError(path, "invalid JSON: %s" % caught_error) from caught_error
    return values_data if isinstance(values_data, dict) else {}


def load_samples(directory: str) -> List[Sample]:
    """Collects the samples of a folder, from the manifest or from the files.

    The manifest (``index.json``) is the fast path and carries everything. When
    it is missing, every ``*.report.json`` is read and, as a last resort, the
    ``*.report.html`` files are listed by name so the dashboard still has
    something to link to.

    Args:
        directory: Folder with reports.

    Returns:
        Samples sorted by severity (most serious first), then by score.

    Raises:
        ProjectError: The directory does not exist or is not a directory.
    """
    if not os.path.isdir(directory):
        raise ProjectError("dashboard directory not found: %s" % directory, path=directory)
    sample_list: List[Sample] = []
    manifest_data = find_manifest(directory)
    if manifest_data:
        values_data = _load_json(manifest_data)
        for item in values_data.get("files") or []:
            if not isinstance(item, dict):
                continue
            item_name = str(item.get("name") or item.get("source") or "?")
            report_data = str(item.get("report") or "")
            sample_list.append(
                Sample(
                    name=item_name,
                    risk=str(item.get("risk") or ""),
                    score=int(item.get("score") or 0),
                    instructions=int(item.get("instructions") or 0),
                    behaviors=int(item.get("behaviors") or 0),
                    indicators=int(item.get("indicators") or 0),
                    problems=int(item.get("problems") or 0),
                    platform=str(item.get("platform") or ""),
                    report=report_data,
                    reason=str(item.get("reason") or ""),
                )
            )
        log_event(
            logger, "dashboard_manifest", level=10, path=manifest_data, samples=len(sample_list)
        )
        return sorted(sample_list, key=lambda s: (s.rank, s.name))

    for item_name in sorted(os.listdir(directory)):
        file_path = os.path.join(directory, item_name)
        if not os.path.isfile(file_path):
            continue
        if item_name.endswith(".report.json"):
            try:
                values_data = _load_json(file_path)
            except SourceReadError as caught_error:
                logger.warning("skipping %s: %s", item_name, caught_error)
                continue
            sample_list.append(
                _sample_from_report(item_name[: -len(".report.json")], values_data, item_name)
            )
        elif item_name.endswith(".report.html"):
            sample_list.append(Sample(name=item_name[: -len(".report.html")], report=item_name))
    log_event(logger, "dashboard_scan", level=10, path=directory, samples=len(sample_list))
    return sorted(sample_list, key=lambda s: (s.rank, s.name))


def build_index(samples: Sequence[Sample], *, title: str = "ASM X") -> Dict[str, Any]:
    """Builds the machine-readable index served by the dashboard.

    Args:
        samples: Samples to summarise.
        title: Dashboard title.

    Returns:
        Dictionary with the schema, the title, the totals and the sample list.

    Example:
        >>> build_index([])["total"]
        0
    """
    by_level = {
        level_name: sum(1 for s in samples if s.risk == level_name) for level_name in RISK_ORDER
    }
    return {
        "schema": DASHBOARD_SCHEMA,
        "title": title,
        "total": len(samples),
        "by_risk": by_level,
        "worst": max((s.score for s in samples), default=0),
        "samples": [s.to_dict() for s in samples],
    }


_CSS = """
:root{--bg:#eeeeee;--panel:#ffffff;--line:#aaaaaa;--fg:#202020;--dim:#595959;
--low:#006000;--medium:#775500;--high:#994400;--critical:#a00000;--accent:#003399}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,
BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
header{padding:22px 28px;border-bottom:1px solid var(--line);display:flex;
flex-wrap:wrap;gap:16px;align-items:baseline}
h1{margin:0;font-size:20px;letter-spacing:.2px}
.sub{color:var(--dim);font-size:13px}
main{padding:20px 28px 60px}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:20px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:0;
padding:12px 16px;min-width:120px}
.card b{display:block;font-size:22px}
.card span{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.6px}
input[type=search]{background:var(--panel);border:1px solid var(--line);color:var(--fg);
padding:9px 12px;border-radius:0;min-width:260px;font-size:14px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);
border-radius:0;overflow:hidden}
th,td{padding:9px 12px;text-align:left;border-bottom:1px solid var(--line);font-size:14px}
th{background:#dddddd;color:var(--dim);font-weight:600;cursor:pointer;user-select:none;
white-space:nowrap}
th:hover{color:var(--fg)}
tr:last-child td{border-bottom:0}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.chip{display:inline-block;padding:2px 9px;border-radius:0;font-size:12px;
font-weight:600;border:1px solid transparent}
.low{color:var(--low);border-color:var(--low)}
.medium{color:var(--medium);border-color:var(--medium)}
.high{color:var(--high);border-color:var(--high)}
.critical{color:var(--critical);border-color:var(--critical)}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.empty{color:var(--dim);padding:24px;text-align:center}
footer{color:var(--dim);font-size:12px;padding:18px 28px;border-top:1px solid var(--line)}
"""

_JS = """
function filterRows(){var q=document.getElementById('search_box').value.toLowerCase();
var source_lines=document.querySelectorAll('tbody tr');var seen_items=0;
source_lines.forEach(function(tr){var ok=(tr.dataset.name||'').indexOf(q)>=0;
tr.style.display=ok?'':'none';if(ok)seen_items++;});
document.getElementById('empty_state').style.display=seen_items?'none':'';}
function sortRows(column_index){var tb=document.querySelector('tbody');
var source_lines=Array.prototype.slice.call(tb.querySelectorAll('tr'));
var desc=tb.dataset.col===String(column_index)&&tb.dataset.dir!=='desc';
source_lines.sort(function(a,b){
var x=a.children[column_index].dataset.val||a.children[column_index].innerText;
var y=b.children[column_index].dataset.val||b.children[column_index].innerText;
var nx=parseFloat(x),ny=parseFloat(y);
if(!isNaN(nx)&&!isNaN(ny)){return desc?ny-nx:nx-ny;}
return desc?String(y).localeCompare(String(x)):String(x).localeCompare(String(y));});
source_lines.forEach(function(tr){tb.appendChild(tr);});
tb.dataset.col=column_index;tb.dataset.dir=desc?'desc':'asc';}
"""


def render_page(index: Dict[str, Any], *, title: str = "ASM X", live: bool = True) -> str:
    """Renders the dashboard page as one self-contained HTML document.

    Args:
        index: Index built by :func:`build_index`.
        title: Page title.
        live: When ``True`` the search box and the sortable headers are wired to
            the inline JavaScript; ``False`` renders a static table (useful for
            tests and for saving the page to disk).

    Returns:
        The whole HTML document, with no external resource.
    """
    sample_list = list(index.get("samples") or [])
    by_level = index.get("by_risk") or {}
    total = int(index.get("total") or 0)
    worst = int(index.get("worst") or 0)
    source_lines = []
    for sample in sample_list:
        item_name = html.escape(str(sample.get("name") or "?"))
        risk_data = str(sample.get("risk") or "")
        chip = (
            '<span class="chip %s">%s</span>'
            % (html.escape(risk_data), html.escape(risk_data.upper()))
            if risk_data
            else '<span class="sub">-</span>'
        )
        report_data = str(sample.get("report") or "")
        name_cell = (
            '<a href="report/%s">%s</a>' % (html.escape(report_data), item_name)
            if report_data
            else item_name
        )
        source_lines.append(
            '<tr data-name="%s">'
            "<td>%s</td>"
            '<td data-val="%d">%s</td>'
            '<td class="num" data-val="%d">%d</td>'
            '<td class="num" data-val="%d">%d</td>'
            '<td class="num" data-val="%d">%d</td>'
            '<td class="num" data-val="%d">%d</td>'
            '<td class="num" data-val="%d">%d</td>'
            '<td class="sub">%s</td>'
            "</tr>"
            % (
                html.escape(str(sample.get("name") or "?").lower()),
                name_cell,
                RISK_ORDER.index(risk_data) if risk_data in RISK_ORDER else len(RISK_ORDER),
                chip,
                int(sample.get("score") or 0),
                int(sample.get("score") or 0),
                int(sample.get("instructions") or 0),
                int(sample.get("instructions") or 0),
                int(sample.get("behaviors") or 0),
                int(sample.get("behaviors") or 0),
                int(sample.get("indicators") or 0),
                int(sample.get("indicators") or 0),
                int(sample.get("problems") or 0),
                int(sample.get("problems") or 0),
                html.escape(str(sample.get("reason") or sample.get("platform") or "")),
            )
        )
    cards = [
        ("samples", total),
        ("critical", int(by_level.get("critical") or 0)),
        ("high", int(by_level.get("high") or 0)),
        ("medium", int(by_level.get("medium") or 0)),
        ("low", int(by_level.get("low") or 0)),
        ("worst score", worst),
    ]
    cards_html = "".join(
        '<div class="card"><b>%s</b><span>%s</span></div>' % (numeric_value, label_text)
        for label_text, numeric_value in cards
    )
    body = (
        "".join(source_lines)
        if source_lines
        else '<tr><td colspan="8" class="empty">no samples in this folder</td></tr>'
    )
    controls = (
        '<input type="search" id="search_box" placeholder="filter by file name…" '
        'oninput="filterRows()">'
        if live
        else ""
    )
    script = "<script>%s</script>" % _JS if live else ""
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%(title)s — dashboard</title>
<style>%(css)s</style>
</head>
<body>
<header>
<h1>%(title)s</h1>
<span class="sub">%(total)d sample(s) · generated by <code>asmx dashboard</code> ·
read-only, served from this machine</span>
%(controls)s
</header>
<main>
<div class="cards">%(cards)s</div>
<table>
<thead><tr>
<th onclick="sortRows(0)">sample</th>
<th onclick="sortRows(1)">risk</th>
<th onclick="sortRows(2)">score</th>
<th onclick="sortRows(3)">instructions</th>
<th onclick="sortRows(4)">behaviors</th>
<th onclick="sortRows(5)">indicators</th>
<th onclick="sortRows(6)">problems</th>
<th>note</th>
</tr></thead>
<tbody>%(body)s</tbody>
</table>
<div id="empty_state" class="empty" style="display:none">nothing matches that filter</div>
</main>
<footer>ASM X · this page is generated locally and needs no network ·
<code>asmx analyze DIR --out DIR</code> to produce the reports</footer>
%(script)s
</body>
</html>
""" % {
        "title": html.escape(title),
        "css": _CSS,
        "total": total,
        "controls": controls,
        "cards": cards_html,
        "body": body,
        "script": script,
    }


class _Handler(BaseHTTPRequestHandler):
    """Serves the dashboard page, the reports and the JSON API."""

    server_version = "ASMX-Dashboard/1"
    directory = "."
    title = "ASM X"
    token: Optional[str] = None

    def log_message(self, format_name: str, *args: Any) -> None:
        """Routes the HTTP log through the project logger instead of stderr.

        Args:
            format_name: printf-style format used by :mod:`http.server`.
            *args: Values for the format.
        """
        logger.debug("dashboard %s - %s", self.address_string(), format_name % args)

    # -- helpers ------------------------------------------------------------
    def _authorized(self) -> bool:
        """Checks the optional token.

        Returns:
            ``True`` when no token is configured or the request carries it in
            the ``token`` query parameter or the ``X-ASMX-Token`` header.
        """
        if not self.token:
            return True
        sent = self.headers.get("X-ASMX-Token")
        if sent == self.token:
            return True
        query_string = urlparse(self.path).query
        for part_name in query_string.split("&"):
            key, _, numeric_value = part_name.partition("=")
            if key == "token" and unquote(numeric_value) == self.token:
                return True
        return False

    def _respond(
        self, body: bytes, item_type: str = "text/html; charset=utf-8", status_code: int = 200
    ) -> None:
        """Sends a complete response.

        Args:
            body: Body bytes.
            item_type: Content type.
            status_code: HTTP status code.
        """
        self.send_response(status_code)
        self.send_header("Content-Type", item_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, values_data: Dict[str, Any], status_code: int = 200) -> None:
        """Sends a JSON response.

        Args:
            values_data: Payload to serialise.
            status_code: HTTP status code.
        """
        self._respond(
            json.dumps(values_data, ensure_ascii=False, indent=2).encode("utf-8"),
            "application/json; charset=utf-8",
            status_code,
        )

    def _error(self, status_code: int, message_text: str) -> None:
        """Sends a plain text error.

        Args:
            status_code: HTTP status code.
            message_text: Text shown to the user.
        """
        self._respond(
            (message_text + "\n").encode("utf-8"), "text/plain; charset=utf-8", status_code
        )

    def _safe_path(self, relative_path: str) -> Optional[str]:
        """Resolves a request path inside the served directory.

        Args:
            relative_path: Path taken from the URL, already unquoted.

        Returns:
            Absolute path when it stays inside the directory and points at a
            file, otherwise ``None``.
        """
        base = os.path.abspath(self.directory)
        target_name = os.path.abspath(os.path.join(base, relative_path))
        if target_name != base and not target_name.startswith(base + os.sep):
            return None
        return target_name if os.path.isfile(target_name) else None

    # -- routes -------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 - inherited naming
        """Handles a GET request."""
        self._route()

    def do_HEAD(self) -> None:  # noqa: N802 - inherited naming
        """Handles a HEAD request (same routes, no body)."""
        self._route()

    def _route(self) -> None:
        """Dispatches the request to the right view."""
        if not self._authorized():
            self._error(403, "missing or wrong token")
            return
        file_path = unquote(urlparse(self.path).path)
        try:
            sample_list = load_samples(self.directory)
        except ProjectError as caught_error:
            self._error(500, str(caught_error))
            return
        idx = build_index(sample_list, title=self.title)
        if file_path in ("/", "/index.html"):
            self._respond(render_page(idx, title=self.title).encode("utf-8"))
        elif file_path == "/api/samples":
            self._json(idx)
        elif file_path == "/api/summary":
            self._json(
                {
                    "schema": idx["schema"],
                    "title": idx["title"],
                    "total": idx["total"],
                    "by_risk": idx["by_risk"],
                    "worst": idx["worst"],
                }
            )
        elif file_path.startswith("/report/"):
            self._report(file_path[len("/report/") :])
        else:
            self._error(404, "not found: %s" % file_path)

    def _report(self, relative_path: str) -> None:
        """Serves one report file from inside the directory.

        Args:
            relative_path: File name requested under ``/report/``.
        """
        target_name = self._safe_path(relative_path)
        if target_name is None:
            self._error(404, "report not found: %s" % relative_path)
            return
        try:
            with open(target_name, "rb") as source_file:
                body = source_file.read()
        except OSError as caught_error:
            self._error(500, "could not read %s: %s" % (relative_path, caught_error))
            return
        item_type = (
            "application/json; charset=utf-8"
            if target_name.endswith(".json")
            else "text/html; charset=utf-8"
        )
        self._respond(body, item_type)


def _free_port(host: str) -> int:
    """Asks the operating system for a free TCP port.

    Args:
        host: Interface the port must be free on.

    Returns:
        A port number that can be bound right away.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, 0))
        return int(server_socket.getsockname()[1])


def serve(
    directory: str,
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    title: str = "ASM X",
    token: Optional[str] = None,
    open_browser: bool = False,
    background: bool = False,
) -> Tuple[ThreadingHTTPServer, str]:
    """Starts the dashboard.

    Args:
        directory: Folder with the reports to show.
        host: Interface to bind; the default only accepts local connections.
        port: TCP port; ``0`` picks a free one.
        title: Title shown on the page.
        token: Optional shared secret; generated when ``None`` and the host is
            not a loopback address.
        open_browser: Whether to open the page in the default browser.
        background: When ``True`` the server runs in a daemon thread and the
            caller must call ``shutdown()`` on the returned server.

    Returns:
        Tuple ``(server, url)`` with the running server and the URL to open.

    Raises:
        ProjectError: The directory does not exist.
        OSError: The port is taken or the interface cannot be bound.
    """
    if not os.path.isdir(directory):
        raise ProjectError("dashboard directory not found: %s" % directory, path=directory)
    local = host in ("127.0.0.1", "localhost", "::1")
    secret_token = token
    if not local and not secret_token:
        secret_token = secrets.token_urlsafe(12)
        logger.warning("dashboard exposed on %s: a token was generated (%s)", host, secret_token)
    server_port = int(port) or _free_port(host)
    handler = type(
        "_AsmxDashboard",
        (_Handler,),
        {
            "directory": os.path.abspath(directory),
            "title": title,
            "token": secret_token,
        },
    )
    server_instance = ThreadingHTTPServer((host, server_port), handler)
    url = "http://%s:%d/" % ("127.0.0.1" if local else host, server_port)
    if secret_token:
        url += "?token=%s" % secret_token
    log_event(
        logger,
        "dashboard_started",
        host=host,
        port=server_port,
        directory=directory,
        samples=len(load_samples(directory)),
    )
    if background:
        thread = threading.Thread(
            target=server_instance.serve_forever, name="asmx-dashboard", daemon=True
        )
        thread.start()
    if open_browser:
        webbrowser.open(url)
    return server_instance, url
