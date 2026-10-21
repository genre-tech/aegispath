"""
Memgraph / Cypher Exporter
Exports an in-memory AdaptiveAttackPathEngine graph as standard Cypher statements
that can be piped into Memgraph or Neo4j via Bolt or Memgraph Lab.
"""

from typing import List
from .adaptive_engine import AdaptiveAttackPathEngine


def export_to_cypher(engine: AdaptiveAttackPathEngine) -> str:
    """
    Translates the NetworkX graph into executable Cypher clauses.
    """
    lines: List[str] = [
        "// ========================================================",
        "// Adaptive Cyber Intelligence & Attack Path Graph Dump",
        "// Clean slate: MATCH (n) DETACH DELETE n;",
        "// ========================================================",
        "MATCH (n) DETACH DELETE n;",
        ""
    ]

    # Export Nodes
    lines.append("// --- 1. Nodes ---")
    for node_id, data in engine.graph.nodes(data=True):
        labels = [data.get("node_type", "Asset")]
        if node_id in engine.crown_jewels:
            labels.append("CrownJewel")
        if node_id in engine.entry_points:
            labels.append("EntryPoint")

        label_str = ":".join(labels)
        name = data.get("name", node_id).replace('"', '\\"')

        props = [f'id: "{node_id}"', f'name: "{name}"']
        for k, v in data.items():
            if k not in ("node_type", "name"):
                if isinstance(v, bool):
                    props.append(f'{k}: {str(v).lower()}')
                elif isinstance(v, str):
                    props.append(f'{k}: "{v}"')
                elif isinstance(v, (int, float)):
                    props.append(f'{k}: {v}')

        lines.append(f"CREATE (:{label_str} {{{', '.join(props)}}});")

    lines.append("")
    lines.append("// --- 2. Relationships with Dynamic Weights ---")
    # Export Edges
    for u, v, data in engine.graph.edges(data=True):
        rel = data.get("relationship", "CONNECTS_TO")
        weight = data.get("weight", 1.0)
        traversability = data.get("traversability", 0.5)
        has_alert = data.get("active_alert", False)

        lines.append(
            f'MATCH (a {{id: "{u}"}}), (b {{id: "{v}"}}) '
            f'CREATE (a)-[:{rel} {{weight: {weight}, traversability: {traversability}, active_alert: {str(has_alert).lower()}}}]->(b);'
        )

    return "\n".join(lines)
