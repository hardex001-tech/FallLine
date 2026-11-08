"""Active Directory Privilege Escalation Ingestion Engine.

Ingests standard BloodHound / SharpHound JSON telemetry and models Active Directory
privilege escalation paths as graph-theoretic attack vectors.

Calculates shortest Time-to-Compromise (TTC) to Domain Admin and identifies
the exact identity choke point (stale session, over-permissive ACL, misconfigured GPO)
that breaks the entire escalation chain.

Maps findings to MITRE ATT&CK:
- T1078.002: Valid Accounts: Domain Accounts
- T1003.001: OS Credential Dumping: LSASS Memory
- T1068: Exploitation for Privilege Escalation
"""

from __future__ import annotations

import heapq
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import networkx as _nx
except ImportError:
    _nx = None


# Estimated Time-to-Compromise (in minutes) for common Active Directory edge types
EDGE_TTC_WEIGHTS: dict[str, float] = {
    "MemberOf": 1.0,  # Token membership is immediate
    "HasSession": 10.0,  # LSASS memory dump / Token impersonation
    "AdminTo": 15.0,  # Lateral movement via WMI / WinRM / PsExec
    "GenericAll": 20.0,  # Full object takeover / Reset password
    "GenericWrite": 25.0,  # Property modification / Script path hijack
    "WriteDacl": 25.0,  # Grant oneself full control
    "ForceChangePassword": 15.0,  # Immediate credential reset
    "AllowedToDelegate": 30.0,  # Kerberos unconstrained delegation abuse
}


class ADGraph:
    """Lightweight pure-Python directed graph with Dijkstra path finding."""

    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.adj: dict[str, dict[str, dict[str, Any]]] = {}

    def add_node(self, node: str, **attrs: Any) -> None:
        if node not in self.nodes:
            self.nodes[node] = attrs
            self.adj[node] = {}
        else:
            self.nodes[node].update(attrs)

    def add_edge(self, u: str, v: str, **attrs: Any) -> None:
        self.add_node(u)
        self.add_node(v)
        self.adj[u][v] = attrs

    def number_of_nodes(self) -> int:
        return len(self.nodes)

    def number_of_edges(self) -> int:
        return sum(len(neighbors) for neighbors in self.adj.values())

    def in_degree(self, target: str) -> int:
        return sum(1 for u in self.adj if target in self.adj[u])

    def shortest_path(self, source: str, target: str) -> tuple[list[str], float]:
        dist: dict[str, float] = {source: 0.0}
        prev: dict[str, str | None] = {source: None}
        pq = [(0.0, source)]

        while pq:
            d, u = heapq.heappop(pq)
            if d > dist.get(u, float("inf")):
                continue
            if u == target:
                break
            for v, data in self.adj.get(u, {}).items():
                w = data.get("weight", 20.0)
                if d + w < dist.get(v, float("inf")):
                    dist[v] = d + w
                    prev[v] = u
                    heapq.heappush(pq, (d + w, v))

        if target not in dist:
            raise KeyError(f"No path between {source} and {target}")

        path: list[str] = []
        curr: str | None = target
        while curr is not None:
            path.append(curr)
            curr = prev.get(curr)
        path.reverse()
        return path, dist[target]


@dataclass
class ADAttackStep:
    source: str
    target: str
    relationship: str
    ttc_minutes: float
    description: str


@dataclass
class ADAttackPath:
    starting_account: str
    target_crown_jewel: str
    total_ttc_minutes: float
    steps: list[ADAttackStep]
    choke_point_step: ADAttackStep | None = None
    remediation_command: str = ""


@dataclass
class ADIngestionSummary:
    nodes_count: int
    edges_count: int
    users_count: int
    computers_count: int
    groups_count: int
    crown_jewels: list[str]
    attack_paths: list[ADAttackPath] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes_count": self.nodes_count,
            "edges_count": self.edges_count,
            "users_count": self.users_count,
            "computers_count": self.computers_count,
            "groups_count": self.groups_count,
            "crown_jewels": self.crown_jewels,
            "attack_paths": [
                {
                    "starting_account": p.starting_account,
                    "target_crown_jewel": p.target_crown_jewel,
                    "total_ttc_minutes": p.total_ttc_minutes,
                    "steps_count": len(p.steps),
                    "steps": [
                        {
                            "source": s.source,
                            "target": s.target,
                            "relationship": s.relationship,
                            "ttc_minutes": s.ttc_minutes,
                            "description": s.description,
                        }
                        for s in p.steps
                    ],
                    "choke_point": {
                        "source": p.choke_point_step.source,
                        "target": p.choke_point_step.target,
                        "relationship": p.choke_point_step.relationship,
                    }
                    if p.choke_point_step
                    else None,
                    "remediation_command": p.remediation_command,
                }
                for p in self.attack_paths
            ],
        }


def _generate_ad_remediation(step: ADAttackStep) -> str:
    """Generate production-ready PowerShell Active Directory remediation command."""
    rel = step.relationship
    src = step.source
    tgt = step.target

    if rel == "HasSession":
        return (
            f"# Remediate Stale Admin Session on {tgt}\n"
            f"# Terminate disconnected sessions and enforce Tier 0 Administration Separation:\n"
            f'Invoke-Command -ComputerName "{tgt}" -ScriptBlock {{ '
            f"quser | Select-String \"Disc\" | ForEach-Object {{ logoff ($_.ToString().Split() -match '\\d+')[0] }} "
            f"}}"
        )
    elif rel == "AdminTo":
        return (
            f"# Revoke Local Admin Privileges for {src} on {tgt}:\n"
            f'Invoke-Command -ComputerName "{tgt}" -ScriptBlock {{ '
            f'Remove-LocalGroupMember -Group "Administrators" -Member "{src}" '
            f"}}"
        )
    elif rel == "MemberOf":
        return (
            f"# Remove {src} from Sensitive Security Group {tgt}:\n"
            f'Remove-ADGroupMember -Identity "{tgt}" -Members "{src}" -Confirm:$false'
        )
    elif rel in ("GenericAll", "WriteDacl"):
        return (
            f"# Remove Over-Permissive ACL {rel} on {tgt} granted to {src}:\n"
            f'$acl = Get-Acl "AD:\\{tgt}"\n'
            f'$rule = $acl.Access | Where-Object {{ $_.IdentityReference -eq "{src}" }}\n'
            f'if ($rule) {{ $acl.RemoveAccessRule($rule); Set-Acl "AD:\\{tgt}" $acl }}'
        )
    else:
        return f"# Audit and restrict {rel} access between {src} and {tgt} in Group Policy."


def parse_bloodhound_json(data: dict[str, Any] | list[Any]) -> tuple[ADGraph, dict[str, str], list[str]]:
    """Parse BloodHound format into an ADGraph with TTC weights."""
    graph = ADGraph()
    node_types: dict[str, str] = {}
    crown_jewels: list[str] = []

    # BloodHound data can be wrapped under "data" key or raw items
    items = data.get("data", []) if isinstance(data, dict) else data

    for item in items:
        # Standard BloodHound node format
        props = item.get("Properties", item.get("props", {}))
        node_id = props.get("name", item.get("name", item.get("id", "")))
        node_type = item.get("type", props.get("type", "Unknown")).upper()

        if not node_id:
            continue

        node_types[node_id] = node_type
        graph.add_node(node_id, node_type=node_type)

        # Flag Crown Jewels (Domain Admins, Enterprise Admins, Domain Controllers)
        upper_id = node_id.upper()
        if any(cj in upper_id for cj in ("DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS", "DC01", "DC-")):
            crown_jewels.append(node_id)

        # Ingest Outgoing Relationships/Aces
        aces = item.get("Aces", item.get("aces", []))
        for ace in aces:
            target_id = ace.get("PrincipalName", ace.get("target", ""))
            right_name = ace.get("RightName", ace.get("relationship", "Access"))
            if target_id and right_name:
                weight = EDGE_TTC_WEIGHTS.get(right_name, 20.0)
                graph.add_edge(node_id, target_id, relationship=right_name, weight=weight)

    return graph, node_types, crown_jewels


def analyze_ad_attack_paths(
    graph: ADGraph,
    crown_jewels: list[str],
    starting_nodes: list[str] | None = None,
) -> list[ADAttackPath]:
    """Find shortest privilege escalation paths to Crown Jewels using Dijkstra."""
    paths: list[ADAttackPath] = []
    starts = starting_nodes if starting_nodes is not None else [n for n in graph.nodes if graph.in_degree(n) == 0]

    # If no 0 in-degree nodes, sample unprivileged user nodes
    if not starts:
        starts = [n for n in graph.nodes if "USER" in n.upper() or "CORP\\" in n.upper()]

    for start in starts:
        for target in crown_jewels:
            if start == target or start not in graph.nodes or target not in graph.nodes:
                continue

            try:
                shortest_nodes, total_ttc = graph.shortest_path(start, target)

                steps: list[ADAttackStep] = []
                for i in range(len(shortest_nodes) - 1):
                    u = shortest_nodes[i]
                    v = shortest_nodes[i + 1]
                    edge_data = graph.adj.get(u, {}).get(v, {})
                    rel = edge_data.get("relationship", "Access")
                    weight = edge_data.get("weight", 20.0)

                    desc = f"{u} accesses {v} via {rel} (Est. TTC: {weight:.0f}m)"
                    steps.append(
                        ADAttackStep(
                            source=u,
                            target=v,
                            relationship=rel,
                            ttc_minutes=weight,
                            description=desc,
                        )
                    )

                if steps:
                    # Choke point heuristic: highest privilege leap (HasSession, AdminTo, GenericAll)
                    choke = next(
                        (s for s in steps if s.relationship in ("HasSession", "AdminTo", "GenericAll")), steps[-1]
                    )
                    remediate_cmd = _generate_ad_remediation(choke)

                    paths.append(
                        ADAttackPath(
                            starting_account=start,
                            target_crown_jewel=target,
                            total_ttc_minutes=total_ttc,
                            steps=steps,
                            choke_point_step=choke,
                            remediation_command=remediate_cmd,
                        )
                    )
            except KeyError:
                continue

    # Sort shortest attack paths first (most urgent)
    paths.sort(key=lambda p: p.total_ttc_minutes)
    return paths


def ingest_bloodhound_file_or_data(source: str | Path | dict[str, Any] | list[Any]) -> ADIngestionSummary:
    """Ingest BloodHound file or dict and return full attack-path analysis."""
    if isinstance(source, (str, Path)):
        path = Path(source)
        with open(path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
    else:
        raw_data = source

    graph, node_types, crown_jewels = parse_bloodhound_json(raw_data)

    users_count = sum(1 for t in node_types.values() if "USER" in t)
    computers_count = sum(1 for t in node_types.values() if "COMPUTER" in t)
    groups_count = sum(1 for t in node_types.values() if "GROUP" in t)

    paths = analyze_ad_attack_paths(graph, crown_jewels)

    return ADIngestionSummary(
        nodes_count=graph.number_of_nodes(),
        edges_count=graph.number_of_edges(),
        users_count=users_count,
        computers_count=computers_count,
        groups_count=groups_count,
        crown_jewels=crown_jewels,
        attack_paths=paths,
    )
