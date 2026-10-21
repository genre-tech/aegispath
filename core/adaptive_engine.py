"""
Adaptive Attack Path & Graph Reasoning Engine
Uses NetworkX for high-speed in-memory graph traversals, dynamic edge weighting,
choke-point identification, and 'what-if' remediation simulation.
"""

from typing import Dict, List, Any, Optional, Tuple, Set
import networkx as nx
from .cti_client import CTIClient


class AdaptiveAttackPathEngine:
    def __init__(self, cti_client: Optional[CTIClient] = None):
        self.cti = cti_client or CTIClient()
        self.graph = nx.DiGraph()
        self.crown_jewels: Set[str] = set()
        self.entry_points: Set[str] = set()
        self.active_telemetry: Dict[str, Dict[str, Any]] = {}

    def add_node(self, node_id: str, node_type: str, name: str, **attributes):
        """
        Adds a node to the attack graph.
        node_type: 'Perimeter', 'Host', 'Identity', 'IAMRole', 'Subnet', 'Vulnerability', 'CrownJewel'
        """
        self.graph.add_node(
            node_id,
            node_type=node_type,
            name=name,
            **attributes
        )
        if node_type == "CrownJewel":
            self.crown_jewels.add(node_id)
        if node_type == "Perimeter" or attributes.get("is_entry_point", False):
            self.entry_points.add(node_id)

    def add_edge(
        self,
        u: str,
        v: str,
        relationship: str,
        base_probability: float = 0.5,
        **attributes
    ):
        """
        Adds a directional traversal edge.
        base_probability: estimated baseline ease of traversal (0.01 to 1.0)
        """
        self.graph.add_edge(
            u,
            v,
            relationship=relationship,
            base_probability=base_probability,
            active_alert=False,
            **attributes
        )
        self._recalculate_edge_weight(u, v)

    def _recalculate_edge_weight(self, u: str, v: str) -> None:
        """
        Calculates dynamic edge traversal weight W(u, v) = 1.0 / Traversability.
        Higher traversability -> lower cost in shortest path calculations.
        """
        edge_data = self.graph.edges[u, v]
        base_p = edge_data.get("base_probability", 0.5)

        # Factor in Vulnerability enrichment if destination or source is a CVE
        cve_id = edge_data.get("cve_id")
        if not cve_id:
            if self.graph.nodes[v].get("node_type") == "Vulnerability":
                cve_id = v
            elif self.graph.nodes[u].get("node_type") == "Vulnerability":
                cve_id = u

        exploitability = base_p
        if cve_id:
            cve_info = self.cti.enrich_vulnerability(cve_id)
            exploitability = cve_info["composite_exploitability"]
            edge_data["cve_enriched"] = cve_info

        # Factor in active real-time EDR / Telemetry alerts
        has_alert = False
        if u in self.active_telemetry or v in self.active_telemetry:
            has_alert = True
            exploitability = max(0.98, exploitability) # Edge becomes almost frictionless
            edge_data["active_alert"] = True
            edge_data["alert_details"] = self.active_telemetry.get(u) or self.active_telemetry.get(v)

        # Traversability bounds: [0.01, 0.99]
        traversability = max(0.01, min(0.99, exploitability))
        edge_data["traversability"] = traversability
        # Weight (cost): lower means more easily traversed by adversary
        edge_data["weight"] = round(1.0 / traversability, 4)

    def inject_telemetry_alert(self, node_id: str, alert_id: str, alert_type: str, severity: str) -> List[Tuple[str, str]]:
        """
        Dynamically adapts the graph when a live EDR or CloudTrail alert fires on a node.
        Returns the list of edges whose weights dropped (friction reduced).
        """
        self.active_telemetry[node_id] = {
            "alert_id": alert_id,
            "type": alert_type,
            "severity": severity
        }
        modified_edges = []
        # Update inbound and outbound edges
        for u, v in self.graph.in_edges(node_id):
            self._recalculate_edge_weight(u, v)
            modified_edges.append((u, v))
        for u, v in self.graph.out_edges(node_id):
            self._recalculate_edge_weight(u, v)
            modified_edges.append((u, v))
        return modified_edges

    def clear_telemetry(self, node_id: Optional[str] = None):
        """Removes telemetry alert state and restores baseline weights."""
        if node_id:
            self.active_telemetry.pop(node_id, None)
            for u, v in self.graph.in_edges(node_id):
                self._recalculate_edge_weight(u, v)
            for u, v in self.graph.out_edges(node_id):
                self._recalculate_edge_weight(u, v)
        else:
            self.active_telemetry.clear()
            for u, v in self.graph.edges:
                self._recalculate_edge_weight(u, v)

    def find_shortest_attack_path(self, source: str, target: str) -> Optional[Dict[str, Any]]:
        """
        Computes the most probable attack path from source to target using Dijkstra
        weighted by inverse traversability.
        """
        try:
            path = nx.dijkstra_path(self.graph, source, target, weight="weight")
            total_cost = nx.dijkstra_path_length(self.graph, source, target, weight="weight")

            # Calculate cumulative breach probability along the path
            cum_prob = 1.0
            steps = []
            for i in range(len(path) - 1):
                u, v = path[i], path[i + 1]
                data = self.graph.edges[u, v]
                p = data.get("traversability", 0.5)
                cum_prob *= p
                steps.append({
                    "from_node": u,
                    "from_name": self.graph.nodes[u].get("name", u),
                    "to_node": v,
                    "to_name": self.graph.nodes[v].get("name", v),
                    "relationship": data.get("relationship", "CONNECTS_TO"),
                    "traversability": p,
                    "step_cost": data.get("weight", 1.0),
                    "has_active_alert": data.get("active_alert", False),
                    "cve_details": data.get("cve_enriched")
                })

            return {
                "source": source,
                "target": target,
                "path_nodes": path,
                "total_cost": round(total_cost, 3),
                "cumulative_probability": round(cum_prob, 5),
                "hop_count": len(path) - 1,
                "steps": steps
            }
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def evaluate_all_attack_paths(self) -> List[Dict[str, Any]]:
        """
        Finds the shortest active attack path from each perimeter entry point to every Crown Jewel.
        """
        results = []
        for entry in self.entry_points:
            for jewel in self.crown_jewels:
                res = self.find_shortest_attack_path(entry, jewel)
                if res:
                    results.append(res)
        # Sort by highest cumulative breach probability (lowest cost first)
        results.sort(key=lambda x: x["total_cost"])
        return results

    def find_choke_points(self, source: Optional[str] = None, target: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Identifies critical Choke Points (Cut Vertices & High Betweenness Centrality)
        on the subgraph of paths reaching Crown Jewels.
        """
        active_paths = self.evaluate_all_attack_paths()
        if not active_paths:
            return []

        # Build subgraph of nodes participating in active paths
        nodes_on_paths = set()
        for p in active_paths:
            nodes_on_paths.update(p["path_nodes"])

        subgraph = self.graph.subgraph(nodes_on_paths).copy()

        # Compute betweenness centrality on this attack subgraph
        centrality = nx.betweenness_centrality(subgraph, weight="weight")

        # Exclude entry points and crown jewels themselves
        excluded = self.entry_points.union(self.crown_jewels)
        candidates = [
            (node, score) for node, score in centrality.items()
            if node not in excluded and score > 0
        ]
        candidates.sort(key=lambda x: x[1], reverse=True)

        choke_points = []
        for node, score in candidates:
            choke_points.append({
                "node_id": node,
                "name": self.graph.nodes[node].get("name", node),
                "node_type": self.graph.nodes[node].get("node_type", "Unknown"),
                "centrality_score": round(score, 4),
                "recommendation": f"Prioritize remediation on [{self.graph.nodes[node].get('name')}] to break critical transit paths."
            })

        return choke_points

    def simulate_remediation(self, node_or_edge_to_sever: str) -> Dict[str, Any]:
        """
        'What-If' Simulation: Simulates the removal of a node (e.g. revoking a role or patching a host)
        and measures the reduction in viable attack paths.
        """
        initial_paths = self.evaluate_all_attack_paths()
        initial_count = len(initial_paths)
        initial_avg_cost = sum(p["total_cost"] for p in initial_paths) / initial_count if initial_count else 0

        # Create temporary simulation copy
        sim_graph = self.graph.copy()
        if sim_graph.has_node(node_or_edge_to_sever):
            sim_graph.remove_node(node_or_edge_to_sever)

        # Re-evaluate
        remaining_paths = []
        for entry in self.entry_points:
            for jewel in self.crown_jewels:
                if sim_graph.has_node(entry) and sim_graph.has_node(jewel):
                    try:
                        cost = nx.dijkstra_path_length(sim_graph, entry, jewel, weight="weight")
                        remaining_paths.append(cost)
                    except (nx.NetworkXNoPath, nx.NodeNotFound):
                        pass

        remaining_count = len(remaining_paths)
        eliminated_count = initial_count - remaining_count
        reduction_pct = (eliminated_count / initial_count * 100.0) if initial_count else 0.0

        return {
            "remediated_target": node_or_edge_to_sever,
            "target_name": self.graph.nodes.get(node_or_edge_to_sever, {}).get("name", node_or_edge_to_sever),
            "initial_attack_paths": initial_count,
            "remaining_attack_paths": remaining_count,
            "paths_eliminated": eliminated_count,
            "risk_reduction_percentage": round(reduction_pct, 1),
            "is_fully_severed": remaining_count == 0
        }
