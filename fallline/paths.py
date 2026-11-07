"""Attack-path engine.

Model: a small directed graph.
  ATTACKER --(exposure)--> host foothold --(exposure)--> other host foothold
  ... --> GOAL (your data)
Each edge costs "attacker minutes" taken from the rules knowledge base, scaled
down by CISA KEV / EPSS data when a CVE is known. The cheapest route (Dijkstra)
is the most likely attack path; its cost is the time-to-compromise.

Fix ranking removes one exposure at a time and re-computes the cheapest route,
so a fix is valued by how much it really slows or stops the attacker.
"""
from __future__ import annotations

import heapq
import itertools
import math
from dataclasses import dataclass

try:
    import networkx as _nx
except ImportError:
    _nx = None

from .intel import Intel
from .knowledge import KnowledgeBase, Rule
from .scanners.base import Finding

ATTACKER = "ATTACKER"
GOAL = "GOAL"
LATERAL_DISCOUNT = 0.6      # an attacker already inside moves faster
POST_EXPLOIT_MINUTES = 15   # time to collect data once a host is controlled
PERSPECTIVES = ("external", "internal")


@dataclass
class Exposure:
    key: str
    finding: Finding
    rule: Rule
    effort: float            # attacker minutes after KEV/EPSS scaling
    notes: list[str]

    @property
    def host(self) -> str:
        return self.finding.host

    @property
    def domain(self) -> str:
        return "aws" if self.finding.host.startswith("aws:") else "net"


@dataclass
class Edge:
    src: str
    dst: str
    cost: float
    key: str | None
    kind: str          # entry | lateral | goal | post
    exposure: Exposure | None = None


def build_exposures(items: list[tuple[str, Finding]], kb: KnowledgeBase,
                    intel: Intel | None = None) -> list[Exposure]:
    out = []
    for key, f in items:
        rule = kb.classify(f)
        if rule is None:
            continue
        cves = list(dict.fromkeys([*rule.cves, *f.cves]))
        factor, notes = intel.factor(cves) if intel else (1.0, [])
        effort = max(1.0, round(rule.effort_for(f) * factor, 1))
        out.append(Exposure(key, f, rule, effort, notes))
    return out


def build_edges(exposures: list[Exposure], perspective: str = "external") -> list[Edge]:
    if perspective not in PERSPECTIVES:
        raise ValueError(f"perspective must be one of {PERSPECTIVES}")
    edges: list[Edge] = []
    foothold_hosts = {e.host: e.domain for e in exposures if e.rule.gives == "foothold"}
    for e in exposures:
        direct = e.rule.stage == "initial" or perspective == "internal"
        lateral_cost = max(1.0, round(e.effort * LATERAL_DISCOUNT, 1))
        if e.rule.gives == "foothold":
            if direct:
                edges.append(Edge(ATTACKER, e.host, e.effort, e.key, "entry", e))
            for h, dom in foothold_hosts.items():
                if h != e.host and dom == e.domain:
                    edges.append(Edge(h, e.host, lateral_cost, e.key, "lateral", e))
        elif e.rule.gives == "data":
            if direct:
                edges.append(Edge(ATTACKER, GOAL, e.effort, e.key, "goal", e))
            for h, dom in foothold_hosts.items():
                if dom == e.domain:
                    edges.append(Edge(h, GOAL, lateral_cost, e.key, "goal", e))
    for h in foothold_hosts:
        edges.append(Edge(h, GOAL, float(POST_EXPLOIT_MINUTES), None, "post"))
    return edges


def build_graph(edges: list[Edge]):
    """Build a directed multigraph using networkx when available, else adjacency dict."""
    if _nx is not None:
        g = _nx.MultiDiGraph()
        for ed in edges:
            g.add_edge(ed.src, ed.dst, weight=ed.cost, edge_obj=ed)
        return g
    adj: dict[str, list[Edge]] = {}
    for ed in edges:
        adj.setdefault(ed.src, []).append(ed)
    return adj


def _out_edges(graph, node: str) -> list[Edge]:
    if _nx is not None and isinstance(graph, _nx.MultiDiGraph):
        if node not in graph:
            return []
        return [data["edge_obj"] for _, _, data in graph.out_edges(node, data=True)]
    return graph.get(node, [])


def shortest_path(edges: list[Edge]) -> tuple[float, list[Edge]] | None:
    graph = build_graph(edges)
    counter = itertools.count()
    heap = [(0.0, next(counter), ATTACKER)]
    best = {ATTACKER: 0.0}
    prev: dict[str, Edge] = {}
    while heap:
        dist, _, node = heapq.heappop(heap)
        if dist > best.get(node, math.inf):
            continue
        if node == GOAL:
            path: list[Edge] = []
            while node != ATTACKER:
                path.append(prev[node])
                node = prev[node].src
            return dist, path[::-1]
        for ed in sorted(_out_edges(graph, node), key=lambda x: (x.cost, x.dst, x.key or "")):
            nd = dist + ed.cost
            if nd < best.get(ed.dst, math.inf):
                best[ed.dst] = nd
                prev[ed.dst] = ed
                heapq.heappush(heap, (nd, next(counter), ed.dst))
    return None


def humanize_minutes(m: float | None) -> str:
    if m is None:
        return "no attack path found"
    if m < 90:
        return f"about {round(m)} minutes"
    if m < 60 * 36:
        return f"about {m / 60:.1f} hours"
    return f"about {m / 1440:.1f} days"


def _step(ed: Edge) -> dict:
    if ed.kind == "post":
        return {"from": ed.src, "to": "your data", "key": None, "host": ed.src, "port": None,
                "title": "Collects data and credentials from the controlled host",
                "technique": "T1005 Data from Local System", "minutes": ed.cost, "kind": "post"}
    e = ed.exposure
    assert e is not None
    return {
        "from": "Attacker" if ed.src == ATTACKER else ed.src,
        "to": "your data" if ed.dst == GOAL else ed.dst,
        "key": ed.key, "host": e.host, "port": e.finding.port,
        "title": e.rule.title,
        "technique": f"{e.rule.technique['id']} {e.rule.technique['name']}",
        "minutes": ed.cost, "kind": ed.kind, "why": e.rule.why,
    }


def _ttc(edges: list[Edge], removed: set[str]) -> tuple[float, list[Edge]] | None:
    return shortest_path([ed for ed in edges if ed.key not in removed])


def fix_plan(edges: list[Edge], exposures: list[Exposure], removed: set[str]) -> list[dict]:
    """Greedy: repeatedly fix the exposure on the current cheapest path whose
    removal slows the attacker most (cheapest fix wins ties)."""
    by_key = {e.key: e for e in exposures}
    plan: list[dict] = []
    removed = set(removed)
    while True:
        cur = _ttc(edges, removed)
        if cur is None:
            break
        before, path = cur
        best = None
        for key in dict.fromkeys(ed.key for ed in path if ed.key):
            after = _ttc(edges, removed | {key})
            after_val = math.inf if after is None else after[0]
            e = by_key[key]
            cand = (-after_val, e.rule.fix_minutes, key)
            if best is None or cand < best[0]:
                best = (cand, key, after_val)
        assert best is not None
        _, key, after_val = best
        e = by_key[key]
        plan.append({
            "key": key, "host": e.host, "port": e.finding.port, "title": e.rule.title,
            "technique": f"{e.rule.technique['id']} {e.rule.technique['name']}",
            "tactic": e.rule.technique.get("tactic", ""),
            "fix_minutes": e.rule.fix_minutes, "remediation": e.rule.remediation,
            "fix_command": e.rule.fix_command,
            "ttc_before": before,
            "ttc_after": None if math.isinf(after_val) else after_val,
            "blocks_all_paths": math.isinf(after_val),
        })
        removed.add(key)
    return plan


def analyze(exposures: list[Exposure], perspective: str = "external",
            removed: set[str] | None = None) -> dict:
    """Full assessment. `removed` = exposures to pretend are fixed (what-if)."""
    removed = set(removed or ())
    edges = build_edges(exposures, perspective)
    result = _ttc(edges, removed)
    plan = fix_plan(edges, exposures, removed)
    in_plan = {p["key"] for p in plan}
    return {
        "perspective": perspective,
        "simulated_fixes": sorted(removed),
        "ttc_minutes": None if result is None else result[0],
        "ttc_human": humanize_minutes(None if result is None else result[0]),
        "path": [] if result is None else [_step(ed) for ed in result[1]],
        "fix_plan": plan,
        "exposures": [
            {"key": e.key, "host": e.host, "port": e.finding.port,
             "protocol": e.finding.protocol, "service": e.finding.service,
             "product": e.finding.product, "version": e.finding.version,
             "rule": e.rule.id, "title": e.rule.title, "severity": e.rule.severity,
             "technique": f"{e.rule.technique['id']} {e.rule.technique['name']}",
             "tactic": e.rule.technique.get("tactic", ""),
             "attacker_minutes": e.effort, "fix_minutes": e.rule.fix_minutes,
             "why": e.rule.why, "remediation": e.rule.remediation,
             "fix_command": e.rule.fix_command,
             "cves": list(dict.fromkeys([*e.rule.cves, *e.finding.cves])),
             "intel_notes": e.notes, "in_fix_plan": e.key in in_plan,
             "simulated_fixed": e.key in removed}
            for e in exposures
        ],
    }
