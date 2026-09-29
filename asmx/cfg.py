"""Control-flow and call graphs, with rendering as SVG, DOT and Mermaid.

The analyzer already knows where each block starts and ends and where each
branch points; this module turns that into :class:`Graph` — nodes and edges
ready to become a drawing — and writes the drawing in three formats, all
assembled by string concatenation, with no external library:

* :func:`to_svg` — self-contained SVG, made to be pasted into the HTML report
  and also to be opened on its own in the browser;
* :func:`to_dot` — Graphviz DOT, for whoever prefers to render it outside;
* :func:`to_mermaid` — Mermaid ``flowchart``, for the report that uses Mermaid.

The placement (:func:`layout`) is deterministic: the same graph always produces
the same coordinates, because nothing here walks a ``set`` nor depends on the
hash of the names.  The drawing comes out stable between runs and between
machines, which also makes the SVG tests comparable byte by byte.  The layers go
down (the entry on top, what it reaches below), which is the orientation that
survives the narrow column of the report well; unreachable code stays in the
last row.

The ``xmlns`` of the SVG is written with a character reference (``&#104;``) so
that the final text does not cite ``http`` anywhere — the report embeds the
drawing and fetches nothing from the network.  After being read by the browser
or by an XML parser, the attribute value is the normal address of the SVG
standard; the test ``test_svg_namespace`` and the check with the browser confirm
that.

Example:
    >>> from asmx.analyzer import analyze
    >>> graph = control_flow_graph(analyze("_start:\\n    mov rax, 60\\n    syscall"))
    >>> [(node.id, node.kind) for node in graph.nodes]
    [('b0', 'entry')]
    >>> to_dot(graph).splitlines()[0]
    'digraph cfg {'
"""

from __future__ import annotations

import math
import re
from collections import deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, List, Optional, Sequence, Tuple

from .analyzer import Analysis, Block
from .isa import WIN_APIS
from .parser import Line

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------

#: Palette of each theme: ``dark`` (report default) and ``light``.
#:
#: The keys ``bg``, ``node``, ``node_entry``, ``node_exit``, ``text``,
#: ``edge``, ``edge_taken``, ``edge_fall``, ``border`` and ``dim`` are the ones
#: used by the report; ``node_function``, ``node_api``, ``edge_call`` and
#: ``edge_api`` complete the node and edge kinds of the call graph, so that each
#: ``kind`` has its own color.
THEME: Dict[str, Dict[str, str]] = {
    "dark": {
        "bg": "#0f1420",
        "node": "#1d2839",
        "node_entry": "#16452f",
        "node_exit": "#5a2130",
        "node_function": "#22314b",
        "node_api": "#3a2f1c",
        "text": "#e8eef8",
        "edge": "#8296b0",
        "edge_taken": "#f0a35e",
        "edge_fall": "#5fa8d3",
        "edge_call": "#a795f2",
        "edge_api": "#d7b45a",
        "border": "#3a4a63",
        "dim": "#93a3ba",
    },
    "light": {
        "bg": "#ffffff",
        "node": "#eef2f8",
        "node_entry": "#d8f3dc",
        "node_exit": "#fbdcdc",
        "node_function": "#e2ecff",
        "node_api": "#fdf1d6",
        "text": "#16202e",
        "edge": "#5b6b82",
        "edge_taken": "#c2410c",
        "edge_fall": "#1d4ed8",
        "edge_call": "#6d28d9",
        "edge_api": "#a16207",
        "border": "#b6c2d4",
        "dim": "#5f6b7f",
    },
}

#: Theme color key used by each node kind.
_NODE_COLOR: Dict[str, str] = {
    "entry": "node_entry",
    "block": "node",
    "function": "node_function",
    "exit": "node_exit",
    "api": "node_api",
}

#: Theme color key used by each edge kind.
_EDGE_COLOR: Dict[str, str] = {
    "taken": "edge_taken",
    "fallthrough": "edge_fall",
    "jmp": "edge",
    "call": "edge_call",
    "api": "edge_api",
}

# ---------------------------------------------------------------------------
# Drawing measurements
# ---------------------------------------------------------------------------

#: Margin around the drawing, in pixels.
_MARGIN = 26

#: Width and height of a node, in pixels.
_NODE_WIDTH = 190
_NODE_HEIGHT = 56

#: Space between the columns and between the rows of nodes, in pixels.
_GAP_X = 46
_GAP_Y = 42

#: Size of the frame returned for a graph with nothing to draw.
_EMPTY_WIDTH = 360
_EMPTY_HEIGHT = 120

#: From how many nodes on the drawing uses a smaller font and shorter labels.
_LARGE_LIMIT = 60

#: Font size of the node name and of the detail, in both modes.
_FONT = 12.5
_DETAIL_FONT = 9.5
_LARGE_FONT = 9.0
_LARGE_DETAIL_FONT = 7.5

#: Font of the edge labels and character limit in the economical mode.
_EDGE_FONT = 9.0
_LARGE_EDGE_FONT = 7.5
_LARGE_EDGE_LABEL = 16

#: Radius of the rounded corners, in pixels.
_RADIUS = 9

#: Height of the handle drawn for a branch from a block to itself.  It has to
#: fit in the space between two layers, together with the edge label.
_LOOP_HEIGHT = 24.0

#: Recess of the arrow so that the tip does not touch the node border, in pixels.
_ARROW_GAP = 3.0

#: Maximum size of an edge label coming from the analyzer.
_MAX_LABEL = 28

#: Address of the SVG standard, written with a character reference so that the
#: generated text does not cite ``http`` (see the explanation at the top).
_SVG_NAMESPACE = "&#104;ttp://www.w3.org/2000/svg"

#: Type family of the drawing: generic ones only, no external font.
_FONT_FAMILY = "sans-serif"

#: Template of the ``id`` of each arrow: ``asmx-<graph>-<theme>-<kind>``.
_ARROW_ID = "asmx-%s-%s-%s"

#: Labels that mark the entry point, in priority order.
ENTRY_LABELS: Tuple[str, ...] = ("_start", "main", "start", "winmain")

#: Name given to the code that is outside any label (anonymous caller).
_NO_FUNCTION_NAME = "code"


# ---------------------------------------------------------------------------
# Graph structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GraphNode:
    """A node of the graph: a basic block, a function or an external API.

    Attributes:
        id: Stable identifier (``b0``, ``b1``... or ``f:sum``).
        label: Name of the block or of the function, as it appears in the code.
        kind: ``entry``, ``block`` or ``exit`` in the control flow;
            ``entry``, ``function`` or ``api`` in the call graph.
        lines: Lines of the file covered, such as ``(12, 20)``; empty for API.
        detail: Short text shown below the name, such as
            ``8 instructions · L12-L20`` or ``called 3×``.
        func: Function the node belongs to, when there is one.
    """

    id: str
    label: str
    kind: str
    lines: Tuple[int, ...] = ()
    detail: str = ""
    func: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert the node into a simple dictionary, ready to become JSON.

        Returns:
            Dictionary with ``id``, ``label``, ``kind``, ``lines`` (as a list),
            ``detail`` and ``func``.
        """
        return {
            "id": self.id,
            "label": self.label,
            "kind": self.kind,
            "lines": list(self.lines),
            "detail": self.detail,
            "func": self.func,
        }


@dataclass(frozen=True)
class GraphEdge:
    """A link of the graph, already with the label the drawing shows.

    Attributes:
        source: ``id`` of the origin node.
        target: ``id`` of the destination node.
        label: Text shown in the middle of the line, such as ``when equal`` or
            ``3×``.
        kind: ``taken``, ``fallthrough``, ``jmp``, ``call`` or ``api``.
    """

    source: str
    target: str
    label: str = ""
    kind: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert the edge into a simple dictionary, ready to become JSON.

        Returns:
            Dictionary with ``source``, ``target``, ``label`` and ``kind``.
        """
        return {
            "source": self.source,
            "target": self.target,
            "label": self.label,
            "kind": self.kind,
        }


@dataclass(frozen=True)
class Graph:
    """A whole graph: kind, title, nodes and edges.

    Attributes:
        kind: ``cfg`` (control flow) or ``calls`` (calls).
        title: Title of the drawing.
        nodes: Nodes, in the order they must be drawn.
        edges: Edges, in the order they must be drawn.
    """

    kind: str
    title: str
    nodes: Tuple[GraphNode, ...] = ()
    edges: Tuple[GraphEdge, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        """Convert the graph into a simple dictionary, ready to become JSON.

        Returns:
            Dictionary with ``kind``, ``title``, ``nodes``, ``edges`` and
            ``empty`` (the result of :meth:`is_empty`).
        """
        return {
            "kind": self.kind,
            "title": self.title,
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "empty": self.is_empty(),
        }

    def is_empty(self) -> bool:
        """Tell whether the graph has nothing to draw.

        Returns:
            ``True`` when there is no node at all; a program with no calls
            returns an empty call graph.
        """
        return not self.nodes


# ---------------------------------------------------------------------------
# Text
# ---------------------------------------------------------------------------


def escape(text: str) -> str:
    """Escape the characters that XML reserves.

    Args:
        text: Free text, such as a block name or the reason of a branch.

    Returns:
        The text with ``&``, ``<``, ``>`` and ``"`` replaced by entities.
    """
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    )


def _shorten(text: str, limit: int) -> str:
    """Shorten a text up to the limit, marking the cut with an ellipsis.

    Args:
        text: Original text.
        limit: Maximum number of characters of the result.

    Returns:
        The text itself when it already fits; otherwise, the prefix ending in
        ``…``.
    """
    if len(text) <= limit:
        return text
    if limit <= 1:
        return "…"[:limit]
    return text[: limit - 1].rstrip() + "…"


def _wrap_text(text: str, limit: int, max_lines: int = 2) -> List[str]:
    """Break a text into lines of at most ``limit`` characters.

    Args:
        text: Original text.
        limit: Maximum number of characters per line.
        max_lines: Maximum number of lines returned.

    Returns:
        The lines already trimmed; when the text does not fit, the last line
        ends in ``…`` to make it clear that a piece is missing.
    """
    limit = max(4, limit)
    lines: List[str] = []
    current = ""
    for word in text.split():
        if not current:
            current = word
        elif len(current) + 1 + len(word) <= limit:
            current = current + " " + word
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        lines[-1] = _shorten(lines[-1] + "…", limit)
    return [_shorten(line, limit) for line in lines]


def _chars_per_line(width: float, font: float) -> int:
    """Estimate how many characters fit in a line of text.

    Args:
        width: Usable width of the box, in pixels.
        font: Font size, in pixels.

    Returns:
        The number of characters that fit, never less than 6.
    """
    return max(6, int((width - 18) / (font * 0.56)))


def _text_width(text: str, font: float) -> float:
    """Estimate the width of a text, in pixels.

    Args:
        text: Text to measure.
        font: Font size, in pixels.

    Returns:
        The estimated width, used for the background of the edge label.
    """
    return len(text) * font * 0.56


def _number(value: float) -> str:
    """Format a number without useless decimal places.

    Args:
        value: Number to format.

    Returns:
        Text such as ``12`` or ``12.5``.
    """
    if abs(value - round(value)) < 0.05:
        return "%d" % round(value)
    return ("%.1f" % value).rstrip("0").rstrip(".")


# ---------------------------------------------------------------------------
# Assembling the graphs
# ---------------------------------------------------------------------------


def _entry_label(analysis: Analysis) -> Optional[str]:
    """Find which label marks the entry of the program.

    Args:
        analysis: Analysis already done.

    Returns:
        The label name (``_start``, ``main``, ``start`` or ``WinMain``) or
        ``None`` when none of them appears in the code.
    """
    by_lower = {name.lower(): name for name in analysis.label_at}
    for candidate in ENTRY_LABELS:
        if candidate in analysis.label_at:
            return candidate
        if candidate in by_lower:
            return by_lower[candidate]
    return None


def _label_index(analysis: Analysis, name: str) -> Optional[int]:
    """Index of the instruction where a label appears.

    Args:
        analysis: Analysis already done.
        name: Name of the label being looked for.

    Returns:
        The index among the instructions, or ``None`` when the label does not
        exist.
    """
    index = analysis.label_at.get(name)
    if index is None or not 0 <= index < len(analysis.instrs):
        return None
    return index


def _entry_block(analysis: Analysis) -> Optional[int]:
    """Index of the entry block of the program.

    Args:
        analysis: Analysis already done.

    Returns:
        The ``id`` of the block that contains ``_start``/``main``/``start``/
        ``WinMain``; block 0 when the program has blocks but none of those
        labels; and ``None`` when there is no block at all.
    """
    if not analysis.blocks:
        return None
    name = _entry_label(analysis)
    if name is not None:
        index = _label_index(analysis, name)
        if index is not None:
            block = analysis.instrs[index].block
            if block is not None:
                return block
    return 0


def _line_range(instrs: Sequence[Line]) -> Tuple[int, ...]:
    """Lines of the file covered by a sequence of instructions.

    Args:
        instrs: Instructions of the block or of the function, in order.

    Returns:
        ``(first, last)`` or ``()`` when the sequence is empty.
    """
    if not instrs:
        return ()
    return (instrs[0].n, instrs[-1].n)


def _block_detail(block: Block) -> str:
    """Build the supporting text of a block node.

    Args:
        block: Basic block returned by the analyzer.

    Returns:
        Text such as ``3 instructions · L23-L25``; when the block ends the flow,
        the reason comes at the end (``· returns to the caller``).
    """
    how_many = len(block.instrs)
    if not how_many:
        return "block with no instructions"
    span = _line_range(block.instrs)
    detail = "%d %s · L%d-L%d" % (
        how_many,
        "instruction" if how_many == 1 else "instructions",
        span[0],
        span[1],
    )
    if block.exit:
        detail += " · " + block.exit
    return detail


def control_flow_graph(analysis: Analysis) -> Graph:
    """Build the control-flow graph: one node per basic block.

    Unreachable blocks stay in the graph — the report needs to show dead code -
    and :func:`layout` reserves the last columns for them.

    Args:
        analysis: Analysis already done.

    Returns:
        The :class:`Graph` of kind ``cfg``, empty when there is no block at all.
    """
    title = "Control-flow graph"
    if not analysis.blocks:
        return Graph(kind="cfg", title=title)
    entry = _entry_block(analysis)
    nodes: List[GraphNode] = []
    for block in analysis.blocks:
        if block.id == entry:
            kind = "entry"
        elif block.exit:
            kind = "exit"
        else:
            kind = "block"
        nodes.append(
            GraphNode(
                id="b%d" % block.id,
                label=block.name,
                kind=kind,
                lines=_line_range(block.instrs),
                detail=_block_detail(block),
                func=block.func,
            )
        )
    edges: List[GraphEdge] = []
    for block in analysis.blocks:
        for edge in block.succ:
            edges.append(
                GraphEdge(
                    source="b%d" % block.id,
                    target="b%d" % edge.target,
                    label=_shorten(edge.why, _MAX_LABEL),
                    kind=edge.kind,
                )
            )
    return Graph(kind="cfg", title=title, nodes=tuple(nodes), edges=tuple(edges))


def _calls(analysis: Analysis) -> List[Tuple[str, str]]:
    """List the calls of the code, in the order they appear.

    Args:
        analysis: Analysis already done.

    Returns:
        Pairs ``(caller, target)``; the caller is ``code`` when the call is
        outside any label.
    """
    calls: List[Tuple[str, str]] = []
    for ins in analysis.instrs:
        if ins.mnemonic != "call" or not ins.operands:
            continue
        target = ins.operands[0].symbol or ins.operands[0].text
        if not target:
            continue
        calls.append((ins.func or _NO_FUNCTION_NAME, target))
    return calls


def _entry_function(analysis: Analysis) -> Optional[str]:
    """Name of the function that contains the entry point.

    Args:
        analysis: Analysis already done.

    Returns:
        The function name (``_start``, ``main``...) or ``None`` when the program
        has no known entry label.
    """
    name = _entry_label(analysis)
    if name is None:
        return None
    index = _label_index(analysis, name)
    if index is None:
        return None
    return analysis.instrs[index].func or name


def _functions_in_order(analysis: Analysis) -> List[str]:
    """Names of the functions in the order the blocks appear.

    Args:
        analysis: Analysis already done.

    Returns:
        List without repetition, with the entry function first when it exists.
    """
    names: List[str] = []
    for block in analysis.blocks:
        if block.func and block.func not in names:
            names.append(block.func)
    entry = _entry_function(analysis)
    if entry is not None and entry in names:
        names.remove(entry)
        names.insert(0, entry)
    return names


def _function_lines(analysis: Analysis, name: str) -> Tuple[int, ...]:
    """Lines of the file covered by a function.

    Args:
        analysis: Analysis already done.
        name: Name of the function being looked for.

    Returns:
        ``(first, last)`` or ``()`` when no block belongs to that function.
    """
    spans = [_line_range(b.instrs) for b in analysis.blocks if b.func == name]
    spans = [span for span in spans if span]
    if not spans:
        return ()
    return (min(span[0] for span in spans), max(span[1] for span in spans))


def _is_windows_api(target: str) -> bool:
    """Tell whether a call target is a known Windows API.

    Args:
        target: Name of the target, as it appears in the ``call``.

    Returns:
        ``True`` when the name (without a leading ``_`` or a trailing ``@N``) is
        in the collection.
    """
    return re.sub(r"^_+|@.*$", "", target.lower()) in WIN_APIS


def _function_detail(received: int) -> str:
    """Supporting text of a function node of the call graph.

    Args:
        received: How many times the function is called in the code.

    Returns:
        ``called 3×`` when someone calls it, ``no callers`` when nobody does.
    """
    if received:
        return "called %d×" % received
    return "no callers"


def call_graph(analysis: Analysis) -> Graph:
    """Build the call graph, with a count per caller/target pair.

    The functions involved in some call enter the drawing (whoever calls or
    whoever is called) plus an ``api`` node for each target that is not a label
    of the file — a Windows API or an external function.  When the code calls
    nothing, the graph comes back empty (:meth:`Graph.is_empty`), because there
    is no call to draw.

    Args:
        analysis: Analysis already done.

    Returns:
        The :class:`Graph` of kind ``calls``.
    """
    title = "Call graph"
    calls = _calls(analysis)
    if not calls:
        return Graph(kind="calls", title=title)

    received: Dict[str, int] = {}
    pairs: List[Tuple[str, str]] = []
    counts: Dict[Tuple[str, str], int] = {}
    for caller, target in calls:
        received[target] = received.get(target, 0) + 1
        pair = (caller, target)
        if pair not in counts:
            pairs.append(pair)
        counts[pair] = counts.get(pair, 0) + 1

    internal = set(analysis.label_at)
    callers = {caller for caller, _ in calls}
    internal_targets = {target for _, target in calls if target in internal}
    entry = _entry_function(analysis)

    # Every edge endpoint needs a node: besides the declared functions, the
    # internal labels called by ``call`` (a local label, for example) and the
    # code that is outside any label enter here.
    functions = _functions_in_order(analysis)
    names = [name for name in functions if name in callers or name in internal_targets]
    for caller, target in calls:
        for name in (caller, target if target in internal else None):
            if name is not None and name not in functions and name not in names:
                names.append(name)

    nodes: List[GraphNode] = []
    for name in names:
        if name == entry:
            kind = "entry"
        else:
            kind = "function"
        nodes.append(
            GraphNode(
                id="f:" + name,
                label=name,
                kind=kind,
                lines=_function_lines(analysis, name),
                detail=_function_detail(received.get(name, 0)),
                func=None if name == _NO_FUNCTION_NAME else name,
            )
        )
    created = {node.id for node in nodes}
    for _, target in calls:
        if "f:" + target in created:
            continue
        if _is_windows_api(target):
            detail = "API call · %d×" % received.get(target, 0)
        else:
            detail = "external function · %d×" % received.get(target, 0)
        nodes.append(GraphNode(id="f:" + target, label=target, kind="api", lines=(), detail=detail))
        created.add("f:" + target)

    edges = [
        GraphEdge(
            source="f:" + caller,
            target="f:" + target,
            label="%d×" % counts[(caller, target)],
            kind="call" if target in internal else "api",
        )
        for caller, target in pairs
    ]
    return Graph(kind="calls", title=title, nodes=tuple(nodes), edges=tuple(edges))


# ---------------------------------------------------------------------------
# Placement
# ---------------------------------------------------------------------------


def _has_loop(graph: Graph) -> bool:
    """Tell whether the graph has a branch from a node to itself.

    Args:
        graph: Graph to check.

    Returns:
        ``True`` when there is an edge with the same origin and destination.
    """
    return any(edge.source == edge.target for edge in graph.edges)


def _order_key(
    nid: str,
    predecessors: Dict[str, List[str]],
    position: Dict[str, int],
    order: Dict[str, int],
) -> Tuple[int, float, int]:
    """Key that decides the order of the nodes inside a layer.

    The node goes down close to the average of the positions of whoever points
    to it, which reduces crossings without ceasing to be deterministic.

    Args:
        nid: ``id`` of the node.
        predecessors: ``id`` -> list of nodes that point to it.
        position: ``id`` -> position already decided inside its own layer.
        order: ``id`` -> position of the node in the original graph list.

    Returns:
        Tuple ``(no_predecessor, average, tiebreak)`` ready for ``sorted``.
    """
    previous = [position[p] for p in predecessors[nid] if p in position]
    if not previous:
        return (1, 0.0, order[nid])
    return (0, sum(previous) / float(len(previous)), order[nid])


def _layers(graph: Graph) -> List[List[str]]:
    """Group the nodes into layers, by the BFS distance to the entries.

    Args:
        graph: Graph to organize.

    Returns:
        A list of layers; each layer is the list of ``id`` in the order it must
        be drawn.  Nodes that no entry reaches go to the last layer, so that
        dead code does not vanish from the drawing.
    """
    ids = [node.id for node in graph.nodes]
    order = {nid: index for index, nid in enumerate(ids)}
    successors: Dict[str, List[str]] = {nid: [] for nid in ids}
    predecessors: Dict[str, List[str]] = {nid: [] for nid in ids}
    for edge in graph.edges:
        if edge.source in successors and edge.target in successors:
            successors[edge.source].append(edge.target)
            predecessors[edge.target].append(edge.source)

    roots = [node.id for node in graph.nodes if node.kind == "entry"]
    if not roots:
        roots = [nid for nid in ids if not predecessors[nid]]
    if not roots:
        roots = ids[:1]

    distance: Dict[str, int] = {}
    queue: Deque[str] = deque()
    for root in roots:
        if root not in distance:
            distance[root] = 0
            queue.append(root)
    while queue:
        current = queue.popleft()
        for neighbor in successors[current]:
            if neighbor not in distance:
                distance[neighbor] = distance[current] + 1
                queue.append(neighbor)

    bottom = max(distance.values()) + 1 if distance else 0
    for nid in ids:
        if nid not in distance:
            distance[nid] = bottom

    by_layer: Dict[int, List[str]] = {}
    for nid in ids:
        by_layer.setdefault(distance[nid], []).append(nid)

    position: Dict[str, int] = {}
    layers: List[List[str]] = []
    for index in sorted(by_layer):
        ordered = sorted(
            by_layer[index],
            key=lambda nid: _order_key(nid, predecessors, position, order),
        )
        for slot, nid in enumerate(ordered):
            position[nid] = slot
        layers.append(ordered)
    return layers


def layout(
    graph: Graph,
    *,
    node_width: int = 190,
    node_height: int = 56,
    gap_x: int = 46,
    gap_y: int = 42,
) -> Dict[str, Tuple[int, int]]:
    """Place the nodes in layers, without overlap and always the same way.

    The layers come from the BFS distance to the entry and go down: the entry is
    in the first row, what it reaches comes below, and the unreachable nodes
    stay in the last row, side by side in code order.  Inside a layer each node
    takes a column, so two nodes never overlap.  The top-to-bottom flow was
    chosen because the report shows the drawing in a narrow column: a chain too
    long horizontally would shrink until the text became unreadable.

    Args:
        graph: Graph to place.
        node_width: Width of each node, in pixels.
        node_height: Height of each node, in pixels.
        gap_x: Horizontal space between the columns, in pixels.
        gap_y: Vertical space between the layers, in pixels.

    Returns:
        ``id -> (x, y)`` with the top left corner of each node.  The coordinates
        already include the drawing margin; an empty graph returns ``{}``.
    """
    if not graph.nodes:
        return {}
    top = _MARGIN + (_LOOP_HEIGHT + 16 if _has_loop(graph) else 0)
    positions: Dict[str, Tuple[int, int]] = {}
    for line, layer in enumerate(_layers(graph)):
        for column, nid in enumerate(layer):
            positions[nid] = (
                _MARGIN + column * (node_width + gap_x),
                int(top + line * (node_height + gap_y)),
            )
    return positions


def size_of(
    graph: Graph, positions: Optional[Dict[str, Tuple[int, int]]] = None
) -> Tuple[int, int]:
    """Size of the drawing, in pixels.

    The arithmetic uses the default node size (:data:`_NODE_WIDTH` by
    :data:`_NODE_HEIGHT`); positions coming from a :func:`layout` with another
    node size have to be measured from the outside.

    Args:
        graph: Graph to measure.
        positions: Positions already computed by :func:`layout`; when ``None``,
            this function calls :func:`layout` itself.

    Returns:
        ``(width, height)``, counting the margin around; a graph with no nodes
        returns the size of the frame used by :func:`to_svg`.
    """
    positions = layout(graph) if positions is None else positions
    ids = {node.id for node in graph.nodes}
    points = [point for nid, point in positions.items() if nid in ids]
    if not points:
        return (_EMPTY_WIDTH, _EMPTY_HEIGHT)
    width = max(x for x, _ in points) + _NODE_WIDTH + _MARGIN
    height = max(y for _, y in points) + _NODE_HEIGHT + _MARGIN
    return (width, height)


# ---------------------------------------------------------------------------
# Drawing geometry
# ---------------------------------------------------------------------------


def _on_border(
    center: Tuple[float, float], target: Tuple[float, float], width: float, height: float
) -> Tuple[float, float]:
    """Point where the center->target line crosses the border of the node box.

    Args:
        center: Center of the node, in pixels.
        target: Point the line points to, in pixels.
        width: Width of the node, in pixels.
        height: Height of the node, in pixels.

    Returns:
        The exit (or entry) point on the border of the box.
    """
    dx = target[0] - center[0]
    dy = target[1] - center[1]
    if not dx and not dy:
        return center
    scales = []
    if dx:
        scales.append((width / 2.0) / abs(dx))
    if dy:
        scales.append((height / 2.0) / abs(dy))
    scale = min(scales)
    return (center[0] + dx * scale, center[1] + dy * scale)


def _edge_offset(index: int, total: int, has_reverse: bool) -> float:
    """Perpendicular offset of an edge, so that lines do not stick together.

    Args:
        index: Position of the edge among the ones with the same origin and
            destination.
        total: How many edges exist with that same origin and destination.
        has_reverse: Whether the edge in the opposite direction also exists.

    Returns:
        The offset in pixels, positive or negative.
    """
    offset = (index - (total - 1) / 2.0) * 12.0
    if has_reverse:
        offset += 6.0
    return offset


def _edge_offsets(graph: Graph) -> List[float]:
    """Compute the perpendicular offset of each edge of the graph.

    Args:
        graph: Graph to draw.

    Returns:
        One offset per edge, in graph order; repeated edges (same origin and
        destination) and two-way edges come out parallel, without sticking
        together.
    """
    keys = [(a.source, a.target) for a in graph.edges]
    totals: Dict[Tuple[str, str], int] = {}
    for pair in keys:
        totals[pair] = totals.get(pair, 0) + 1
    existing = set(keys)
    seen: Dict[Tuple[str, str], int] = {}
    offsets: List[float] = []
    for pair in keys:
        index = seen.get(pair, 0)
        seen[pair] = index + 1
        offsets.append(_edge_offset(index, totals[pair], (pair[1], pair[0]) in existing))
    return offsets


def _edge_path(
    origin: Tuple[int, int],
    destination: Tuple[int, int],
    offset: float,
) -> Tuple[str, float, float]:
    """Build the ``d`` of an edge and the point where the label must go.

    Args:
        origin: Top left corner of the origin node.
        destination: Top left corner of the destination node.
        offset: Perpendicular offset, in pixels.

    Returns:
        ``(d, x, y)``: the SVG path and the middle of the line, where the label
        goes.  An edge from a node to itself becomes a handle above it.
    """
    if origin == destination:
        center_x = origin[0] + _NODE_WIDTH / 2.0
        top = float(origin[1])
        left = center_x - _NODE_WIDTH * 0.28
        right = center_x + _NODE_WIDTH * 0.28
        path = "M %s %s C %s %s, %s %s, %s %s" % (
            _number(left),
            _number(top),
            _number(left),
            _number(top - _LOOP_HEIGHT),
            _number(right),
            _number(top - _LOOP_HEIGHT),
            _number(right),
            _number(top),
        )
        return (path, center_x, top - _LOOP_HEIGHT - 6)

    origin_center = (origin[0] + _NODE_WIDTH / 2.0, origin[1] + _NODE_HEIGHT / 2.0)
    destination_center = (destination[0] + _NODE_WIDTH / 2.0, destination[1] + _NODE_HEIGHT / 2.0)
    dx = destination_center[0] - origin_center[0]
    dy = destination_center[1] - origin_center[1]
    length = math.hypot(dx, dy) or 1.0
    normal = (-dy / length * offset, dx / length * offset)
    shifted_origin = (origin_center[0] + normal[0], origin_center[1] + normal[1])
    shifted_destination = (destination_center[0] + normal[0], destination_center[1] + normal[1])
    start = _on_border(shifted_origin, shifted_destination, _NODE_WIDTH, _NODE_HEIGHT)
    end = _on_border(shifted_destination, shifted_origin, _NODE_WIDTH, _NODE_HEIGHT)
    back_x = start[0] - end[0]
    back_y = start[1] - end[1]
    back = math.hypot(back_x, back_y) or 1.0
    end = (end[0] + back_x / back * _ARROW_GAP, end[1] + back_y / back * _ARROW_GAP)
    path = "M %s %s L %s %s" % (
        _number(start[0]),
        _number(start[1]),
        _number(end[0]),
        _number(end[1]),
    )
    return (path, (start[0] + end[0]) / 2.0, (start[1] + end[1]) / 2.0)


def _node_lines(
    node: GraphNode, font: float, detail_font: float, width: float
) -> Tuple[List[str], List[str]]:
    """Wrap the name and the detail of a node into what fits inside the box.

    Args:
        node: Node to draw.
        font: Font size of the name, in pixels.
        detail_font: Font size of the detail, in pixels.
        width: Usable width of the box, in pixels.

    Returns:
        Two lists: the lines of the name (up to two) and the ones of the detail
        (up to one, empty when there is no detail).
    """
    label = _wrap_text(node.label, _chars_per_line(width, font), 2)
    detail = _wrap_text(node.detail, _chars_per_line(width, detail_font), 1)
    return (label, detail)


# ---------------------------------------------------------------------------
# SVG
# ---------------------------------------------------------------------------


def _empty_svg(graph: Graph, colors: Dict[str, str]) -> str:
    """Draw the frame shown when there is nothing to draw.

    Args:
        graph: Empty graph.
        colors: Colors of the chosen theme.

    Returns:
        A minimal SVG, with the message in the middle.
    """
    background = colors.get("bg", "#0f1420")
    node = colors.get("node", "#1d2839")
    border = colors.get("border", "#3a4a63")
    dim = colors.get("dim", "#93a3ba")
    if graph.kind == "calls":
        message = "no calls to draw"
    else:
        message = "no code to draw"
    lines = [
        '<svg xmlns="%s" width="%d" height="%d" viewBox="0 0 %d %d" role="img" '
        'aria-label="%s">'
        % (
            _SVG_NAMESPACE,
            _EMPTY_WIDTH,
            _EMPTY_HEIGHT,
            _EMPTY_WIDTH,
            _EMPTY_HEIGHT,
            escape(graph.title),
        ),
        "  <title>%s</title>" % escape(graph.title),
        '  <rect x="0" y="0" width="%d" height="%d" fill="%s"/>'
        % (_EMPTY_WIDTH, _EMPTY_HEIGHT, background),
        '  <rect x="16" y="16" width="%d" height="%d" rx="10" fill="%s" stroke="%s" '
        'stroke-dasharray="7 6"/>' % (_EMPTY_WIDTH - 32, _EMPTY_HEIGHT - 32, node, border),
        '  <text x="%d" y="%d" text-anchor="middle" font-family="%s" font-size="13" '
        'fill="%s">%s</text>'
        % (_EMPTY_WIDTH // 2, _EMPTY_HEIGHT // 2 + 5, _FONT_FAMILY, dim, escape(message)),
        "</svg>",
    ]
    return "\n".join(lines) + "\n"


def to_svg(graph: Graph, *, theme: str = "dark") -> str:
    """Draw the graph as a self-contained and deterministic SVG.

    The drawing has no ``script``, does not use ``href``, does not fetch an
    external font and does not cite ``http``: it can be pasted into the HTML of
    the report or saved as a ``.svg`` file and opened in the browser.  Graphs
    with more than 60 nodes come out with a smaller font and shorter labels, so
    that they do not become a blur — the content stays the same, just tighter.

    Args:
        graph: Graph returned by :func:`control_flow_graph` or
            :func:`call_graph`.
        theme: ``dark`` or ``light``; any other value falls back to ``dark``.

    Returns:
        The complete SVG document, as text.
    """
    theme_name = theme if theme in THEME else "dark"
    colors = THEME[theme_name]
    if not graph.nodes:
        return _empty_svg(graph, colors)

    background = colors.get("bg", "#0f1420")
    text = colors.get("text", "#e8eef8")
    border = colors.get("border", "#3a4a63")
    dim = colors.get("dim", "#93a3ba")

    large = len(graph.nodes) > _LARGE_LIMIT
    font = _LARGE_FONT if large else _FONT
    detail_font = _LARGE_DETAIL_FONT if large else _DETAIL_FONT
    edge_font = _LARGE_EDGE_FONT if large else _EDGE_FONT
    edge_label_limit = _LARGE_EDGE_LABEL if large else _MAX_LABEL

    positions = layout(graph)
    width, height = size_of(graph, positions)

    # One arrow per color used, in the order the edges appear.
    arrows: List[Tuple[str, str]] = []
    for edge in graph.edges:
        key = _EDGE_COLOR.get(edge.kind, "edge")
        color = colors.get(key, "#8296b0")
        if all(color != existente for _, existente in arrows):
            arrows.append((key, color))
    if not arrows:
        arrows.append(("edge", colors.get("edge", "#8296b0")))

    parts: List[str] = [
        '<svg xmlns="%s" width="%d" height="%d" viewBox="0 0 %d %d" role="img" '
        'aria-label="%s">' % (_SVG_NAMESPACE, width, height, width, height, escape(graph.title)),
        "  <title>%s</title>" % escape(graph.title),
        "  <defs>",
    ]
    for key, color in arrows:
        parts.append(
            '    <marker id="%s" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
            'markerHeight="7" orient="auto" markerUnits="strokeWidth">'
            % (_ARROW_ID % (graph.kind, theme_name, key))
        )
        parts.append('      <path d="M 0 0 L 10 5 L 0 10 z" fill="%s"/>' % color)
        parts.append("    </marker>")
    parts.append("  </defs>")
    parts.append(
        '  <rect x="0" y="0" width="%d" height="%d" fill="%s"/>' % (width, height, background)
    )

    # The edges come out before the nodes, so that the line does not invade the box.
    offsets = _edge_offsets(graph)
    parts.append('  <g class="edges">')
    for index, edge in enumerate(graph.edges):
        origin = positions.get(edge.source)
        destination = positions.get(edge.target)
        if origin is None or destination is None:
            continue
        path, _, _ = _edge_path(origin, destination, offsets[index])
        edge_color = colors.get(_EDGE_COLOR.get(edge.kind, "edge"), "#8296b0")
        parts.append(
            '    <path d="%s" fill="none" stroke="%s" stroke-width="1.6" '
            'stroke-linecap="round" marker-end="url(#%s)"/>'
            % (
                path,
                edge_color,
                _ARROW_ID % (graph.kind, theme_name, _EDGE_COLOR.get(edge.kind, "edge")),
            )
        )
    parts.append("  </g>")

    parts.append('  <g class="nodes">')
    for node in graph.nodes:
        point = positions.get(node.id)
        if point is None:
            continue
        x, y = float(point[0]), float(point[1])
        color = colors.get(_NODE_COLOR.get(node.kind, "node"), "#1d2839")
        label, detail = _node_lines(node, font, detail_font, float(_NODE_WIDTH))
        label_height = font + 3.0
        detail_height = detail_font + 2.5
        total = len(label) * label_height + len(detail) * detail_height
        base = y + (_NODE_HEIGHT - total) / 2.0 + font * 0.85
        parts.append('    <g class="node node-%s">' % node.kind)
        parts.append(
            "      <title>%s</title>"
            % escape(node.label + (": " + node.detail if node.detail else ""))
        )
        parts.append(
            '      <rect x="%s" y="%s" width="%d" height="%d" rx="%d" fill="%s" '
            'stroke="%s" stroke-width="1.5"/>'
            % (_number(x), _number(y), _NODE_WIDTH, _NODE_HEIGHT, _RADIUS, color, border)
        )
        for index, line in enumerate(label):
            parts.append(
                '      <text x="%s" y="%s" text-anchor="middle" font-family="%s" '
                'font-size="%s" font-weight="600" fill="%s">%s</text>'
                % (
                    _number(x + _NODE_WIDTH / 2.0),
                    _number(base + index * label_height),
                    _FONT_FAMILY,
                    _number(font),
                    text,
                    escape(line),
                )
            )
        for index, line in enumerate(detail):
            parts.append(
                '      <text x="%s" y="%s" text-anchor="middle" font-family="%s" '
                'font-size="%s" fill="%s">%s</text>'
                % (
                    _number(x + _NODE_WIDTH / 2.0),
                    _number(base + len(label) * label_height + index * detail_height),
                    _FONT_FAMILY,
                    _number(detail_font),
                    dim,
                    escape(line),
                )
            )
        parts.append("    </g>")
    parts.append("  </g>")

    # The labels stay on top of everything, with a semi-transparent background.
    parts.append('  <g class="labels">')
    for index, edge in enumerate(graph.edges):
        origin = positions.get(edge.source)
        destination = positions.get(edge.target)
        if origin is None or destination is None or not edge.label:
            continue
        _, middle_x, middle_y = _edge_path(origin, destination, offsets[index])
        line = _shorten(edge.label, edge_label_limit)
        edge_color = colors.get(_EDGE_COLOR.get(edge.kind, "edge"), "#8296b0")
        text_width = _text_width(line, edge_font)
        parts.append(
            '    <rect x="%s" y="%s" width="%s" height="%s" rx="4" fill="%s" '
            'fill-opacity="0.82"/>'
            % (
                _number(middle_x - text_width / 2.0 - 4),
                _number(middle_y - edge_font),
                _number(text_width + 8),
                _number(edge_font + 4),
                background,
            )
        )
        parts.append(
            '    <text x="%s" y="%s" text-anchor="middle" font-family="%s" '
            'font-size="%s" fill="%s">%s</text>'
            % (
                _number(middle_x),
                _number(middle_y),
                _FONT_FAMILY,
                _number(edge_font),
                edge_color,
                escape(line),
            )
        )
    parts.append("  </g>")
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


# ---------------------------------------------------------------------------
# DOT and Mermaid
# ---------------------------------------------------------------------------


def _dot_escape(text: str) -> str:
    """Escape a text so that it fits between quotes in DOT.

    Args:
        text: Free text.

    Returns:
        The text with backslashes and quotes escaped and line breaks as ``\\n``.
    """
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _node_label(node: GraphNode) -> str:
    """Label of the node in the formats that accept a line break.

    Args:
        node: Node to label.

    Returns:
        The name and, when it exists, the detail on the line below.
    """
    if node.detail:
        return node.label + "\n" + node.detail
    return node.label


def to_dot(graph: Graph) -> str:
    """Write the graph as DOT, the Graphviz format.

    Args:
        graph: Graph to write.

    Returns:
        A valid ``digraph``, with one color per node and edge kind.
    """
    name = "cfg" if graph.kind == "cfg" else "calls"
    lines = [
        "digraph %s {" % name,
        "  rankdir=TB;",
        '  label="%s";' % _dot_escape(graph.title),
        '  labelloc="t";',
        '  fontname="Helvetica";',
        '  node [shape=box, style=filled, fontname="Helvetica", fontsize=11];',
        '  edge [fontname="Helvetica", fontsize=9];',
    ]
    colors = THEME["dark"]
    if not graph.nodes:
        lines.append("  // nothing to draw")
    for node in graph.nodes:
        lines.append(
            '  "%s" [label="%s", fillcolor="%s", color="%s", fontcolor="%s"];'
            % (
                _dot_escape(node.id),
                _dot_escape(_node_label(node)),
                colors.get(_NODE_COLOR.get(node.kind, "node"), "#1d2839"),
                colors.get("border", "#3a4a63"),
                colors.get("text", "#e8eef8"),
            )
        )
    for edge in graph.edges:
        attributes = ['color="%s"' % colors.get(_EDGE_COLOR.get(edge.kind, "edge"), "#8296b0")]
        if edge.label:
            attributes.append('label="%s"' % _dot_escape(edge.label))
        lines.append(
            '  "%s" -> "%s" [%s];'
            % (_dot_escape(edge.source), _dot_escape(edge.target), ", ".join(attributes))
        )
    lines.append("}")
    return "\n".join(lines) + "\n"


def _mermaid_escape(text: str) -> str:
    """Escape a text so that it fits between quotes in Mermaid.

    Args:
        text: Free text.

    Returns:
        The text with quotes, ``&``, ``<`` and ``>`` replaced by entities that
        Mermaid understands.
    """
    return (
        text.replace("&", "#amp;").replace('"', "#quot;").replace("<", "#lt;").replace(">", "#gt;")
    )


def _mermaid_id(nid: str, used: Dict[str, int]) -> str:
    """Turn the ``id`` of the node into an identifier accepted by Mermaid.

    Args:
        nid: Original ``id``, such as ``b0`` or ``f:sum``.
        used: Counter of ids already used, to break collisions.

    Returns:
        An identifier with only letters, digits and ``_``, without repetition.
    """
    base = re.sub(r"[^0-9A-Za-z_]", "_", nid)
    if not base or base[0].isdigit():
        base = "n_" + base
    used[base] = used.get(base, 0) + 1
    if used[base] > 1:
        base = "%s_%d" % (base, used[base])
    return base


def to_mermaid(graph: Graph) -> str:
    """Write the graph as a Mermaid ``flowchart``.

    Args:
        graph: Graph to write.

    Returns:
        The diagram as text, with the labels between ``["..."]`` and the call
        count on the edges.
    """
    lines = ["flowchart TD"]
    if not graph.nodes:
        if graph.kind == "calls":
            message = "no calls to draw"
        else:
            message = "no code to draw"
        lines.append('    empty["%s"]' % _mermaid_escape(message))
        return "\n".join(lines) + "\n"

    used: Dict[str, int] = {}
    identifiers: Dict[str, str] = {}
    for node in graph.nodes:
        identifiers[node.id] = _mermaid_id(node.id, used)
        label = _mermaid_escape(_node_label(node)).replace("\n", "<br/>")
        lines.append('    %s["%s"]' % (identifiers[node.id], label))
    for edge in graph.edges:
        origin = identifiers.get(edge.source)
        destination = identifiers.get(edge.target)
        if origin is None or destination is None:
            continue
        if edge.label:
            lines.append('    %s -->|"%s"| %s' % (origin, _mermaid_escape(edge.label), destination))
        else:
            lines.append("    %s --> %s" % (origin, destination))
    return "\n".join(lines) + "\n"
