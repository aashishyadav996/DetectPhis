"""
Data models for the Threat Relationship Investigation Graph.
"""
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class GraphNode:
    id: str
    label: str
    type: str  # "url", "hostname", "domain", "ip", "registrar", "nameserver", "brand_target"
    risk_level: str  # "critical", "high", "suspicious", "low", "safe", "neutral"
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class GraphEdge:
    id: str
    source: str
    target: str
    relationship: str  # "POINTS_TO", "SUBDOMAIN_OF", "REGISTERED_WITH", "DELEGATED_TO", "TARGETS_BRAND"
    label: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ThreatGraph:
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    threat_indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "summary": self.summary,
            "threat_indicators": self.threat_indicators,
        }
