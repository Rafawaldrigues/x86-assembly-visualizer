"""Tests for the control-flow and call graphs and for the SVG drawing.

The cases cover the ready-made examples of the project (``linux-loop``,
``linux-function``, ``windows-hello``, ``broken``, ``bubble``...), small
programs assembled on the spot and graphs built by hand, to check:

* the control-flow graph: entry, exit, loops, unreachable code;
* the call graph: functions, external APIs and call count;
* the deterministic placement without overlap;
* the SVG (valid XML, no ``http``, no ``script``, with arrows and colors per
  kind);
* DOT and Mermaid.
"""

from __future__ import annotations

import dataclasses
import json
import unittest
import xml.dom.minidom
from typing import Dict, List, Set, Tuple

from asmx.analyzer import analyze
from asmx.cfg import (
    THEME,
    Graph,
    GraphEdge,
    GraphNode,
    call_graph,
    control_flow_graph,
    escape,
    layout,
    size_of,
    to_dot,
    to_mermaid,
    to_svg,
)
from asmx.examples import EXAMPLES

LOOP = EXAMPLES["linux-loop"]["code"]
FUNCTION = EXAMPLES["linux-function"]["code"]
WINDOWS = EXAMPLES["windows-hello"]["code"]
BROKEN = EXAMPLES["broken"]["code"]
BUBBLE = EXAMPLES["bubble"]["code"]
GCC = EXAMPLES["gcc-att"]["code"]

#: Keys the report expects to find in both themes.
THEME_KEYS = (
    "bg",
    "node",
    "node_entry",
    "node_exit",
    "text",
    "edge",
    "edge_taken",
    "edge_fall",
    "border",
    "dim",
)


def program_with_blocks(count: int) -> str:
    """Build a program with one block per numbered label.

    Args:
        count: Desired number of blocks.

    Returns:
        Code in which each block has a ``nop`` and falls into the next one.
    """
    return "".join("block%d:\n    nop\n" % i for i in range(count))


def without_overlap(positions: Dict[str, Tuple[int, int]]) -> bool:
    """Tell whether two node boxes could overlap.

    Args:
        positions: ``id -> (x, y)`` returned by :func:`layout`.

    Returns:
        ``True`` when no pair of nodes occupies the same area.
    """
    points = list(positions.items())
    for i, (_, (x1, y1)) in enumerate(points):
        for _, (x2, y2) in points[i + 1 :]:
            if abs(x1 - x2) < 190 and abs(y1 - y2) < 56:
                return False
    return True


class TestControlFlow(unittest.TestCase):
    """The control-flow graph: nodes, block kinds and edges."""

    def graph(self, code: str) -> Graph:
        """Control-flow graph of the given code."""
        return control_flow_graph(analyze(code))

    def test_one_node_per_block(self) -> None:
        analysis = analyze(LOOP)
        graph = control_flow_graph(analysis)
        self.assertEqual(len(graph.nodes), len(analysis.blocks))
        self.assertEqual([node.id for node in graph.nodes], ["b0", "b1", "b2", "b3"])

    def test_entry_block_marked(self) -> None:
        graph = self.graph(LOOP)
        entries = [node for node in graph.nodes if node.kind == "entry"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].label, "_start")
        self.assertEqual(entries[0].id, "b0")

    def test_entry_is_not_the_first_block(self) -> None:
        graph = self.graph(FUNCTION)
        entries = [node for node in graph.nodes if node.kind == "entry"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].label, "_start")
        self.assertEqual(entries[0].id, "b4")

    def test_kind_and_title(self) -> None:
        graph = self.graph(LOOP)
        self.assertEqual(graph.kind, "cfg")
        self.assertEqual(graph.title, "Control-flow graph")
        self.assertIn("flow", graph.to_dict()["title"].lower())

    def test_loop_back_edge(self) -> None:
        graph = self.graph(LOOP)
        loops = [a for a in graph.edges if a.source == "b2" and a.target == "b1"]
        self.assertEqual(len(loops), 1)
        self.assertEqual(loops[0].kind, "jmp")

    def test_loop_exit_edge(self) -> None:
        graph = self.graph(LOOP)
        exits = [a for a in graph.edges if a.source == "b1" and a.target == "b3"]
        self.assertEqual(len(exits), 1)
        self.assertEqual(exits[0].kind, "taken")
        self.assertEqual(exits[0].label, "when equal")

    def test_edge_label_is_shortened(self) -> None:
        graph = self.graph(LOOP)
        labels = [a.label for a in graph.edges]
        self.assertTrue(labels)
        for label in labels:
            self.assertLessEqual(len(label), 28)
        long_labels = [r for r in labels if r.endswith("…")]
        self.assertTrue(long_labels)
        self.assertTrue(any(r.startswith("flows naturally") for r in long_labels))

    def test_fallthrough_edge(self) -> None:
        graph = self.graph(LOOP)
        edges = [a for a in graph.edges if a.kind == "fallthrough"]
        self.assertEqual(len(edges), 2)
        self.assertTrue(all(a.label for a in edges))

    def test_exit_block_marked(self) -> None:
        graph = self.graph(LOOP)
        exits = [node for node in graph.nodes if node.kind == "exit"]
        self.assertEqual([node.label for node in exits], [".done"])
        self.assertIn("terminates the process", exits[0].detail)

    def test_detail_counts_instructions(self) -> None:
        graph = self.graph(LOOP)
        by_id = {node.id: node for node in graph.nodes}
        self.assertEqual(by_id["b0"].detail, "1 instruction · L10-L10")
        self.assertEqual(by_id["b1"].detail, "2 instructions · L13-L14")

    def test_block_lines(self) -> None:
        graph = self.graph(LOOP)
        by_id = {node.id: node for node in graph.nodes}
        self.assertEqual(by_id["b1"].lines, (13, 14))
        self.assertEqual(by_id["b3"].lines, (26, 28))

    def test_node_function(self) -> None:
        graph = self.graph(FUNCTION)
        by_id = {node.id: node for node in graph.nodes}
        self.assertEqual(by_id["b0"].func, "add_pair")
        self.assertEqual(by_id["b1"].func, "itoa")
        self.assertEqual(by_id["b4"].func, "_start")

    def test_unreachable_block_appears(self) -> None:
        graph = self.graph(BROKEN)
        by_id = {node.id: node for node in graph.nodes}
        self.assertIn("b0", by_id)
        self.assertEqual(by_id["b0"].label, "divide")
        self.assertNotIn("b0", [a.target for a in graph.edges])
        self.assertEqual(len(graph.nodes), 3)

    def test_infinite_loop(self) -> None:
        graph = self.graph(BROKEN)
        loops = [a for a in graph.edges if a.source == a.target]
        self.assertEqual(len(loops), 1)
        self.assertEqual(loops[0].source, "b2")
        self.assertEqual(loops[0].kind, "jmp")

    def test_jmp_outside_the_code(self) -> None:
        code = "_start:\n    cmp rax, 0\n    je .x\n    jmp outside\n.x:\n    ret\n"
        graph = self.graph(code)
        exits = [node for node in graph.nodes if node.kind == "exit"]
        self.assertTrue(any("outside the loaded code" in node.detail for node in exits))
        self.assertTrue(any("returns to the caller" in node.detail for node in exits))

    def test_empty_program(self) -> None:
        graph = control_flow_graph(analyze(""))
        self.assertTrue(graph.is_empty())
        self.assertEqual(graph.nodes, ())
        self.assertEqual(graph.edges, ())

    def test_program_with_only_a_comment(self) -> None:
        graph = control_flow_graph(analyze("; nothing here\n"))
        self.assertTrue(graph.is_empty())

    def test_single_block(self) -> None:
        graph = self.graph(GCC)
        self.assertEqual(len(graph.nodes), 1)
        self.assertEqual(graph.nodes[0].kind, "entry")
        self.assertEqual(graph.nodes[0].label, "main")
        self.assertEqual(graph.edges, ())
        self.assertIn("returns to the caller", graph.nodes[0].detail)

    def test_all_bubble_blocks(self) -> None:
        analysis = analyze(BUBBLE)
        graph = control_flow_graph(analysis)
        self.assertEqual([node.id for node in graph.nodes], ["b%d" % i for i in range(9)])
        self.assertEqual(len(graph.edges), sum(len(b.succ) for b in analysis.blocks))

    def test_filled_exit_becomes_exit_node(self) -> None:
        analysis = analyze(BUBBLE)
        graph = control_flow_graph(analysis)
        by_id = {node.id: node for node in graph.nodes}
        for block in analysis.blocks:
            if block.exit and by_id["b%d" % block.id].kind != "entry":
                self.assertEqual(by_id["b%d" % block.id].kind, "exit")


class TestCallGraph(unittest.TestCase):
    """The call graph: functions, external APIs and count."""

    def test_functions_of_linux_function(self) -> None:
        graph = call_graph(analyze(FUNCTION))
        self.assertEqual(graph.kind, "calls")
        self.assertEqual([node.id for node in graph.nodes], ["f:_start", "f:add_pair", "f:itoa"])

    def test_entry_function_marked(self) -> None:
        graph = call_graph(analyze(FUNCTION))
        by_id = {node.id: node for node in graph.nodes}
        self.assertEqual(by_id["f:_start"].kind, "entry")
        self.assertEqual(by_id["f:add_pair"].kind, "function")
        self.assertEqual(by_id["f:itoa"].kind, "function")

    def test_call_edges(self) -> None:
        graph = call_graph(analyze(FUNCTION))
        targets = sorted(a.target for a in graph.edges)
        self.assertEqual(targets, ["f:add_pair", "f:itoa"])
        self.assertTrue(all(a.kind == "call" for a in graph.edges))
        self.assertTrue(all(a.source == "f:_start" for a in graph.edges))

    def test_call_detail(self) -> None:
        graph = call_graph(analyze(FUNCTION))
        by_id = {node.id: node for node in graph.nodes}
        self.assertEqual(by_id["f:add_pair"].detail, "called 1×")
        self.assertEqual(by_id["f:_start"].detail, "no callers")

    def test_function_lines(self) -> None:
        graph = call_graph(analyze(FUNCTION))
        by_id = {node.id: node for node in graph.nodes}
        self.assertEqual(by_id["f:add_pair"].lines, (14, 19))
        self.assertEqual(by_id["f:itoa"].lines, (23, 40))

    def test_windows_api_nodes(self) -> None:
        graph = call_graph(analyze(WINDOWS))
        apis = [node for node in graph.nodes if node.kind == "api"]
        self.assertEqual(
            [node.label for node in apis], ["GetStdHandle", "WriteConsoleA", "ExitProcess"]
        )
        self.assertTrue(all(node.lines == () for node in apis))
        self.assertTrue(all("API call" in node.detail for node in apis))
        self.assertTrue(all(a.kind == "api" for a in graph.edges))

    def test_repeated_call_count(self) -> None:
        code = "_start:\n    call foo\n    call foo\n    call foo\n    ret\nfoo:\n    ret\n"
        graph = call_graph(analyze(code))
        self.assertEqual(len(graph.edges), 1)
        self.assertEqual(graph.edges[0].label, "3×")
        by_id = {node.id: node for node in graph.nodes}
        self.assertEqual(by_id["f:foo"].detail, "called 3×")

    def test_external_linux_function(self) -> None:
        code = "_start:\n    call printf\n    ret\n"
        graph = call_graph(analyze(code))
        apis = [node for node in graph.nodes if node.kind == "api"]
        self.assertEqual([node.label for node in apis], ["printf"])
        self.assertIn("external function", apis[0].detail)

    def test_call_outside_a_function(self) -> None:
        graph = call_graph(analyze("call printf\nret\n"))
        self.assertEqual([node.id for node in graph.nodes], ["f:code", "f:printf"])

    def test_call_to_local_label(self) -> None:
        graph = call_graph(analyze("_start:\n    call .sub\n    ret\n.sub:\n    ret\n"))
        self.assertIn("f:.sub", [node.id for node in graph.nodes])
        self.assertEqual(graph.edges[0].kind, "call")

    def test_every_edge_has_a_node(self) -> None:
        ids = {node.id for node in call_graph(analyze(FUNCTION)).nodes}
        for edge in call_graph(analyze(FUNCTION)).edges:
            self.assertIn(edge.source, ids)
            self.assertIn(edge.target, ids)

    def test_no_calls_empty_graph(self) -> None:
        graph = call_graph(analyze(LOOP))
        self.assertTrue(graph.is_empty())
        self.assertEqual(graph.nodes, ())

    def test_empty_program(self) -> None:
        self.assertTrue(call_graph(analyze("")).is_empty())

    def test_stable_order_of_api_nodes(self) -> None:
        first = call_graph(analyze(WINDOWS))
        second = call_graph(analyze(WINDOWS))
        self.assertEqual([node.id for node in first.nodes], [node.id for node in second.nodes])


class TestLayout(unittest.TestCase):
    """Layered placement: deterministic, without overlap."""

    def test_determinism(self) -> None:
        graph = control_flow_graph(analyze(BUBBLE))
        self.assertEqual(layout(graph), layout(graph))

    def test_determinism_between_analyses(self) -> None:
        first = layout(control_flow_graph(analyze(FUNCTION)))
        second = layout(control_flow_graph(analyze(FUNCTION)))
        self.assertEqual(first, second)

    def test_all_nodes_placed(self) -> None:
        graph = control_flow_graph(analyze(BUBBLE))
        positions = layout(graph)
        self.assertEqual(set(positions), {node.id for node in graph.nodes})

    def test_without_overlap(self) -> None:
        for code in (BUBBLE, FUNCTION, BROKEN, LOOP):
            positions = layout(control_flow_graph(analyze(code)))
            self.assertTrue(without_overlap(positions))

    def test_without_overlap_in_call_graph(self) -> None:
        positions = layout(call_graph(analyze(WINDOWS)))
        self.assertTrue(without_overlap(positions))

    def test_layers_by_breadth_first_search(self) -> None:
        positions = layout(control_flow_graph(analyze(LOOP)))
        self.assertLess(positions["b0"][1], positions["b1"][1])
        self.assertLess(positions["b1"][1], positions["b2"][1])
        self.assertEqual(positions["b2"][1], positions["b3"][1])
        self.assertLess(positions["b2"][0], positions["b3"][0])

    def test_unreachable_at_the_end(self) -> None:
        positions = layout(control_flow_graph(analyze(BROKEN)))
        reachable = max(positions[nid][1] for nid in ("b1", "b2"))
        self.assertGreater(positions["b0"][1], reachable)

    def test_empty_graph(self) -> None:
        self.assertEqual(layout(control_flow_graph(analyze(""))), {})

    def test_spacing_follows_the_parameters(self) -> None:
        graph = control_flow_graph(analyze(LOOP))
        positions = layout(graph, node_width=100, node_height=40, gap_x=20, gap_y=10)
        self.assertEqual(positions["b0"], (26, 26))
        self.assertEqual(positions["b1"], (26, 76))
        self.assertGreater(positions["b3"][0], positions["b2"][0])

    def test_loop_adds_space_at_the_top(self) -> None:
        with_loop = layout(control_flow_graph(analyze(BROKEN)))
        without_loop = layout(control_flow_graph(analyze(LOOP)))
        self.assertGreater(with_loop["b1"][1], without_loop["b0"][1])


class TestSvg(unittest.TestCase):
    """The SVG drawing: valid XML, self-contained and with the theme colors."""

    def svg(self, code: str, theme: str = "dark") -> str:
        """SVG of the control-flow graph of the given code."""
        return to_svg(control_flow_graph(analyze(code)), theme=theme)

    def test_contains_svg_and_marker(self) -> None:
        drawing = self.svg(LOOP)
        self.assertIn("<svg", drawing)
        self.assertIn("<marker", drawing)
        self.assertIn("marker-end=", drawing)
        self.assertTrue(drawing.startswith("<svg"))
        self.assertTrue(drawing.rstrip().endswith("</svg>"))

    def test_without_http_and_without_script(self) -> None:
        for code in (LOOP, FUNCTION, WINDOWS, BROKEN, BUBBLE):
            drawing = self.svg(code)
            self.assertNotIn("http", drawing)
            self.assertNotIn("<script", drawing)
            self.assertNotIn("href", drawing)
            self.assertNotIn("<image", drawing)
            self.assertNotIn("@import", drawing)

    def test_valid_xml_in_three_examples(self) -> None:
        for code in (LOOP, WINDOWS, BUBBLE):
            drawing = self.svg(code)
            document = xml.dom.minidom.parseString(drawing)
            self.assertEqual(document.documentElement.tagName, "svg")

    def test_valid_xml_in_call_graph(self) -> None:
        drawing = to_svg(call_graph(analyze(WINDOWS)))
        document = xml.dom.minidom.parseString(drawing)
        self.assertEqual(document.documentElement.tagName, "svg")

    def test_svg_namespace(self) -> None:
        document = xml.dom.minidom.parseString(self.svg(LOOP))
        self.assertEqual(document.documentElement.namespaceURI, "http://www.w3.org/2000/svg")

    def test_viewbox_matches_size_of(self) -> None:
        graph = control_flow_graph(analyze(BUBBLE))
        width, height = size_of(graph)
        drawing = to_svg(graph)
        self.assertIn('viewBox="0 0 %d %d"' % (width, height), drawing)
        self.assertIn('width="%d"' % width, drawing)
        self.assertIn('height="%d"' % height, drawing)

    def test_edge_label_appears(self) -> None:
        self.assertIn("when equal", self.svg(LOOP))

    def test_colors_per_node_kind(self) -> None:
        drawing = self.svg(LOOP)
        self.assertIn(THEME["dark"]["node_entry"], drawing)
        self.assertIn(THEME["dark"]["node"], drawing)
        self.assertIn(THEME["dark"]["node_exit"], drawing)

    def test_light_theme(self) -> None:
        light = self.svg(LOOP, "light")
        dark = self.svg(LOOP, "dark")
        self.assertIn(THEME["light"]["bg"], light)
        self.assertNotEqual(light, dark)
        xml.dom.minidom.parseString(light)

    def test_unknown_theme_falls_back_to_dark(self) -> None:
        self.assertEqual(self.svg(LOOP, "neon"), self.svg(LOOP, "dark"))

    def test_theme_background(self) -> None:
        self.assertIn('fill="%s"' % THEME["dark"]["bg"], self.svg(LOOP))

    def test_empty_graph_has_message(self) -> None:
        drawing = to_svg(control_flow_graph(analyze("")))
        self.assertIn("no code to draw", drawing)
        self.assertIn("<svg", drawing)
        self.assertNotIn("http", drawing)
        xml.dom.minidom.parseString(drawing)

    def test_empty_call_graph_has_message(self) -> None:
        drawing = to_svg(call_graph(analyze(LOOP)))
        self.assertIn("no calls to draw", drawing)
        xml.dom.minidom.parseString(drawing)

    def test_label_escape(self) -> None:
        node = GraphNode(
            id="b0",
            label="a & b <c>",
            kind="block",
            lines=(1, 2),
            detail='says "hi" & bye',
        )
        graph = Graph(kind="cfg", title="Labels & signs", nodes=(node,))
        drawing = to_svg(graph)
        self.assertIn("a &amp; b &lt;c&gt;", drawing)
        self.assertIn("&quot;hi&quot;", drawing)
        self.assertNotIn("a & b <c>", drawing)
        xml.dom.minidom.parseString(drawing)
        self.assertIn("Labels &amp; signs", drawing)

    def test_svg_determinism(self) -> None:
        graph = control_flow_graph(analyze(FUNCTION))
        self.assertEqual(to_svg(graph), to_svg(graph))
        other = control_flow_graph(analyze(FUNCTION))
        self.assertEqual(to_svg(graph), to_svg(other))

    def test_large_graph_reduces_the_font(self) -> None:
        graph = control_flow_graph(analyze(program_with_blocks(70)))
        self.assertGreater(len(graph.nodes), 60)
        drawing = to_svg(graph)
        self.assertIn('font-size="9"', drawing)
        self.assertNotIn('font-size="12.5"', drawing)
        self.assertIn("70", drawing)
        xml.dom.minidom.parseString(drawing)

    def test_small_graph_uses_the_full_font(self) -> None:
        self.assertIn('font-size="12.5"', self.svg(LOOP))

    def test_node_with_long_label_is_wrapped(self) -> None:
        drawing = self.svg(BUBBLE)
        self.assertIn("continuation of", drawing)
        self.assertIn("…", drawing)

    def test_theme_has_the_report_keys(self) -> None:
        for name in ("dark", "light"):
            for key in THEME_KEYS:
                self.assertIn(key, THEME[name])
                self.assertTrue(THEME[name][key].startswith("#"))


class TestDot(unittest.TestCase):
    """The DOT drawing, the Graphviz format."""

    def test_control_flow_digraph(self) -> None:
        dot = to_dot(control_flow_graph(analyze(LOOP)))
        self.assertTrue(dot.startswith("digraph cfg {"))
        self.assertTrue(dot.rstrip().endswith("}"))
        self.assertIn("rankdir=TB", dot)

    def test_call_digraph(self) -> None:
        dot = to_dot(call_graph(analyze(FUNCTION)))
        self.assertIn("digraph calls {", dot)
        self.assertIn('"f:add_pair"', dot)

    def test_shape_and_color_attributes(self) -> None:
        dot = to_dot(control_flow_graph(analyze(LOOP)))
        self.assertIn("shape=box", dot)
        self.assertIn("style=filled", dot)
        self.assertIn(THEME["dark"]["node"], dot)
        self.assertIn(THEME["dark"]["node_entry"], dot)

    def test_edge_labels(self) -> None:
        dot = to_dot(control_flow_graph(analyze(LOOP)))
        self.assertIn('label="when equal"', dot)
        self.assertIn("->", dot)

    def test_call_list_in_the_label(self) -> None:
        dot = to_dot(call_graph(analyze(FUNCTION)))
        self.assertIn('label="add_pair\\ncalled 1×"', dot)
        self.assertIn('label="1×"', dot)

    def test_escaped_quotes(self) -> None:
        node = GraphNode(id="b0", label='says "hi"', kind="block", detail="1 instruction · L1-L1")
        graph = Graph(kind="cfg", title='quotes "here"', nodes=(node,))
        dot = to_dot(graph)
        self.assertIn('\\"hi\\"', dot)
        self.assertIn('label="quotes \\"here\\""', dot)

    def test_empty_graph_is_valid(self) -> None:
        dot = to_dot(control_flow_graph(analyze("")))
        self.assertIn("digraph cfg {", dot)
        self.assertTrue(dot.rstrip().endswith("}"))

    def test_determinism(self) -> None:
        graph = control_flow_graph(analyze(BUBBLE))
        self.assertEqual(to_dot(graph), to_dot(graph))


class TestMermaid(unittest.TestCase):
    """The Mermaid drawing."""

    def test_flowchart(self) -> None:
        text = to_mermaid(control_flow_graph(analyze(LOOP)))
        self.assertTrue(text.startswith("flowchart TD"))
        self.assertIn('["', text)

    def test_labels_between_brackets(self) -> None:
        text = to_mermaid(control_flow_graph(analyze(LOOP)))
        self.assertIn('b0["_start', text)
        self.assertIn("-->", text)

    def test_sanitized_ids(self) -> None:
        text = to_mermaid(call_graph(analyze(FUNCTION)))
        self.assertIn('f_add_pair["add_pair', text)
        self.assertNotIn("f:add_pair", text)
        for line in text.splitlines()[1:]:
            if "[" in line:
                identifier = line.strip().split("[", 1)[0]
                self.assertRegex(identifier, r"^[A-Za-z_][0-9A-Za-z_]*$")

    def test_edge_with_count(self) -> None:
        code = "_start:\n    call foo\n    call foo\n    ret\nfoo:\n    ret\n"
        text = to_mermaid(call_graph(analyze(code)))
        self.assertIn('-->|"2×"|', text)

    def test_label_with_quotes_is_escaped(self) -> None:
        node = GraphNode(id="b0", label='a "b" <c>', kind="block")
        text = to_mermaid(Graph(kind="cfg", title="t", nodes=(node,)))
        self.assertIn("#quot;", text)
        self.assertIn("#lt;", text)

    def test_empty_graph(self) -> None:
        empty = to_mermaid(control_flow_graph(analyze("")))
        self.assertIn("flowchart TD", empty)
        self.assertIn("no code to draw", empty)
        calls = to_mermaid(call_graph(analyze(LOOP)))
        self.assertIn("no calls to draw", calls)

    def test_determinism(self) -> None:
        graph = call_graph(analyze(WINDOWS))
        self.assertEqual(to_mermaid(graph), to_mermaid(graph))


class TestUtilities(unittest.TestCase):
    """Escape, measurements and conversion to a dictionary."""

    def test_escape(self) -> None:
        self.assertEqual(escape("a & b"), "a &amp; b")
        self.assertEqual(escape("<b>"), "&lt;b&gt;")
        self.assertEqual(escape('says "hi"'), "says &quot;hi&quot;")
        self.assertEqual(escape("nothing here"), "nothing here")
        self.assertEqual(escape('&<>"'), "&amp;&lt;&gt;&quot;")

    def test_size_of_graph(self) -> None:
        graph = control_flow_graph(analyze(LOOP))
        positions = layout(graph)
        width, height = size_of(graph)
        self.assertEqual(width, max(x for x, _ in positions.values()) + 190 + 26)
        self.assertEqual(height, max(y for _, y in positions.values()) + 56 + 26)

    def test_size_of_with_given_positions(self) -> None:
        graph = control_flow_graph(analyze(GCC))
        self.assertEqual(size_of(graph, {"b0": (0, 0)}), (216, 82))

    def test_size_of_empty(self) -> None:
        self.assertEqual(size_of(control_flow_graph(analyze(""))), (360, 120))

    def test_size_of_grows_with_the_graph(self) -> None:
        small = size_of(control_flow_graph(analyze(GCC)))
        large = size_of(control_flow_graph(analyze(BUBBLE)))
        self.assertGreater(large[0], small[0])
        self.assertGreater(large[1], small[1])

    def test_node_to_dict(self) -> None:
        node = GraphNode(
            id="b7", label=".end", kind="exit", lines=(26, 28), detail="3 instructions"
        )
        data = node.to_dict()
        self.assertEqual(data["id"], "b7")
        self.assertEqual(data["lines"], [26, 28])
        self.assertEqual(data["detail"], "3 instructions")
        self.assertIsNone(data["func"])

    def test_edge_to_dict(self) -> None:
        edge = GraphEdge(source="b0", target="b1", label="when equal", kind="taken")
        self.assertEqual(
            edge.to_dict(),
            {"source": "b0", "target": "b1", "label": "when equal", "kind": "taken"},
        )

    def test_graph_to_dict_becomes_json(self) -> None:
        graph = control_flow_graph(analyze(LOOP))
        data = graph.to_dict()
        self.assertEqual(set(data), {"kind", "title", "nodes", "edges", "empty"})
        self.assertFalse(data["empty"])
        self.assertEqual(len(data["nodes"]), 4)
        self.assertEqual(len(data["edges"]), 4)
        self.assertIsInstance(json.dumps(data), str)

    def test_empty_graph_to_dict(self) -> None:
        data = control_flow_graph(analyze("")).to_dict()
        self.assertTrue(data["empty"])
        self.assertEqual(data["nodes"], [])

    def test_is_empty(self) -> None:
        self.assertTrue(Graph(kind="cfg", title="empty").is_empty())
        self.assertFalse(
            Graph(kind="cfg", title="t", nodes=(GraphNode("b0", "x", "block"),)).is_empty()
        )
        self.assertTrue(call_graph(analyze(LOOP)).is_empty())
        self.assertFalse(call_graph(analyze(FUNCTION)).is_empty())

    def test_orphan_edge_does_not_break(self) -> None:
        graph = Graph(
            kind="cfg",
            title="edge with no destination",
            nodes=(GraphNode("b0", "start", "block"),),
            edges=(GraphEdge("b0", "b9", "to nowhere", "jmp"),),
        )
        self.assertEqual(list(layout(graph)), ["b0"])
        self.assertEqual(size_of(graph), (242, 108))
        for drawing in (to_svg(graph), to_dot(graph), to_mermaid(graph)):
            self.assertIn("b0", drawing)
        xml.dom.minidom.parseString(to_svg(graph))

    def test_empty_label_does_not_break(self) -> None:
        graph = Graph(
            kind="cfg",
            title="no label",
            nodes=(GraphNode("b0", "", "block"), GraphNode("b1", "x" * 400, "exit")),
        )
        drawing = to_svg(graph)
        xml.dom.minidom.parseString(drawing)
        self.assertIn("…", drawing)
        self.assertIn("x" * 20, drawing)

    def test_nodes_and_edges_are_immutable(self) -> None:
        node = GraphNode(id="b0", label="x", kind="block")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            node.label = "y"  # type: ignore[misc]

    def test_block_and_function_ids(self) -> None:
        blocks: Set[str] = {node.id for node in control_flow_graph(analyze(FUNCTION)).nodes}
        functions: Set[str] = {node.id for node in call_graph(analyze(FUNCTION)).nodes}
        self.assertEqual(blocks, {"b0", "b1", "b2", "b3", "b4"})
        self.assertEqual(functions, {"f:_start", "f:add_pair", "f:itoa"})

    def test_node_order_is_stable(self) -> None:
        first: List[str] = [node.id for node in control_flow_graph(analyze(BUBBLE)).nodes]
        second: List[str] = [node.id for node in control_flow_graph(analyze(BUBBLE)).nodes]
        self.assertEqual(first, second)
        self.assertEqual(first, sorted(first, key=lambda nid: int(nid[1:])))


if __name__ == "__main__":
    unittest.main()
