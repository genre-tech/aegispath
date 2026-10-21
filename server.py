"""
Production-Grade Adaptive Cyber Intelligence & Attack Path Platform Server
Zero-Mock Enterprise Core:
- Real Infrastructure Ingestion:
    * AWS Cloud Cartography (Boto3 Live & JSON Offline)
    * BloodHound Active Directory & Azure Ingestor
    * Trivy Vulnerability Scanner Ingestor (with live EPSS & CISA KEV)
- Dynamic Attack Path Graph Reasoning (Dijkstra on Inverse Traversability)
- Real-Time Server-Sent Events (SSE) Stream
- Automatic Synchronization to Memgraph MAGE In-Memory Database
"""

import os
import sys
import json
import time
import queue
import subprocess
from typing import Dict, List, Any, Optional
from flask import Flask, request, jsonify, send_from_directory, Response

# Ensure root directory is on path
sys.path.insert(0, os.path.dirname(__file__))

from core.cti_client import CTIClient
from core.adaptive_engine import AdaptiveAttackPathEngine
from core.ingestors.bloodhound_ingestor import BloodHoundIngestor
from core.ingestors.aws_ingestor import AWSIngestor
from core.ingestors.trivy_ingestor import TrivyIngestor

app = Flask(__name__, static_folder="web")

cti_client = CTIClient()
engine = AdaptiveAttackPathEngine(cti_client=cti_client)
bh_ingestor = BloodHoundIngestor(engine)
aws_ingestor = AWSIngestor(engine)
trivy_ingestor = TrivyIngestor(engine)

# Real-Time SSE Event Broadcaster
class EventBroadcaster:
    def __init__(self):
        self.listeners: List[queue.Queue] = []

    def listen(self) -> queue.Queue:
        q = queue.Queue(maxsize=100)
        self.listeners.append(q)
        return q

    def remove(self, q: queue.Queue):
        if q in self.listeners:
            self.listeners.remove(q)

    def broadcast(self, event_type: str, data: Dict[str, Any]):
        payload = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
        for q in list(self.listeners):
            try:
                q.put_nowait(payload)
            except queue.Full:
                self.remove(q)

broadcaster = EventBroadcaster()


def sync_to_memgraph_container():
    """
    Pipes current graph state into Memgraph MAGE container in a background thread.
    """
    import threading

    def _do_sync():
        try:
            statements = ["MATCH (n) DETACH DELETE n;"]
            for node_id, data in list(engine.graph.nodes(data=True)):
                labels = [data.get("node_type", "Asset")]
                if node_id in engine.crown_jewels:
                    labels.append("CrownJewel")
                if node_id in engine.entry_points:
                    labels.append("EntryPoint")
                lbl = ":".join(labels)
                name = str(data.get("name", node_id)).replace('"', '\\"')
                props = [f'id: "{node_id}"', f'name: "{name}"']
                for k, v in data.items():
                    if k not in ("name", "node_type"):
                        if isinstance(v, bool):
                            props.append(f"{k}: {str(v).lower()}")
                        elif isinstance(v, (int, float)):
                            props.append(f"{k}: {v}")
                        elif isinstance(v, str):
                            clean_v = v.replace('"', '\\"').replace('\n', ' ')
                            props.append(f'{k}: "{clean_v}"')
                statements.append(f"CREATE (:{lbl} {{{', '.join(props)}}});")

            for u, v, data in list(engine.graph.edges(data=True)):
                rel = str(data.get("relationship", "CONNECTS_TO")).replace("-", "_").replace(" ", "_")
                w = data.get("weight", 1.0)
                t = data.get("traversability", 0.5)
                alert = str(data.get("active_alert", False)).lower()
                statements.append(
                    f'MATCH (a {{id: "{u}"}}), (b {{id: "{v}"}}) '
                    f'CREATE (a)-[:{rel} {{weight: {w}, traversability: {t}, active_alert: {alert}}}]->(b);'
                )

            full_script = "\n".join(statements) + "\n"
            cmd = ["docker", "exec", "-i", "adaptive-memgraph", "mgconsole"]
            subprocess.run(cmd, input=full_script.encode("utf-8"), capture_output=True, timeout=60)
        except Exception as e:
            print(f"[!] Warning: Memgraph background sync skipped: {e}")

    threading.Thread(target=_do_sync, daemon=True).start()


def init_clean_graph():
    """
    Initializes a completely clean slate with zero mock data.
    """
    engine.graph.clear()
    engine.crown_jewels.clear()
    engine.entry_points.clear()
    engine.active_telemetry.clear()

    # Perimeter entry node
    engine.add_node("internet", "Perimeter", "Public Internet", is_entry_point=True)

# Start with zero mock data
init_clean_graph()


# --- Static Frontend Serving ---
@app.route("/")
def index():
    return send_from_directory("web", "index.html")

@app.route("/<path:path>")
def static_files(path):
    return send_from_directory("web", path)


# --- REST API Endpoints ---
@app.route("/api/health", methods=["GET"])
def get_health():
    return jsonify({
        "status": "healthy",
        "engine": "AdaptiveAttackPathEngine",
        "nodes_loaded": engine.graph.number_of_nodes(),
        "edges_loaded": engine.graph.number_of_edges(),
        "crown_jewels": len(engine.crown_jewels),
        "cisa_kev_catalog_size": len(cti_client.kev_set),
        "active_telemetry_alerts": len(engine.active_telemetry)
    })

@app.route("/api/graph", methods=["GET"])
def get_graph():
    mode = request.args.get("mode", "auto")
    total_g_nodes = engine.graph.number_of_nodes()

    # If auto, automatically switch to focused attack paths if graph exceeds 80 nodes to prevent browser UI freezing
    if mode == "auto":
        mode = "paths" if total_g_nodes > 80 else "all"

    selected_nodes = set()
    selected_edges = set()

    if mode == "paths":
        paths = engine.evaluate_all_attack_paths()
        for p in paths:
            p_nodes = p.get("path_nodes", [])
            selected_nodes.update(p_nodes)
            for i in range(len(p_nodes) - 1):
                selected_edges.add((p_nodes[i], p_nodes[i + 1]))

        # Include choke points and crown jewels
        cps = engine.find_choke_points()
        for c in cps:
            selected_nodes.add(c["node_id"])
        selected_nodes.update(engine.crown_jewels)

        # Fallback if no attack paths exist yet
        if not selected_nodes:
            selected_nodes.update(engine.entry_points)
            selected_nodes.update(engine.crown_jewels)

    elif mode == "crown_jewels":
        selected_nodes.update(engine.crown_jewels)
        cps = engine.find_choke_points()
        for c in cps:
            selected_nodes.add(c["node_id"])
        # Include 1-hop inbound neighbors
        for j in list(selected_nodes):
            if engine.graph.has_node(j):
                for u in engine.graph.predecessors(j):
                    selected_nodes.add(u)
                    selected_edges.add((u, j))
    else:  # mode == "all"
        selected_nodes = set(engine.graph.nodes)

    nodes = []
    for node_id in selected_nodes:
        if engine.graph.has_node(node_id):
            data = engine.graph.nodes[node_id]
            nodes.append({
                "id": node_id,
                "label": data.get("name", node_id),
                "type": data.get("node_type", "Asset"),
                "is_crown_jewel": node_id in engine.crown_jewels,
                "is_entry_point": node_id in engine.entry_points,
                "has_active_alert": node_id in engine.active_telemetry,
                "alert_details": engine.active_telemetry.get(node_id),
                "attributes": {k: v for k, v in data.items() if k not in ("name", "node_type")}
            })

    edges = []
    if mode == "all":
        for u, v, data in engine.graph.edges(data=True):
            edges.append({
                "id": f"{u}->{v}",
                "source": u,
                "target": v,
                "relationship": data.get("relationship", "CONNECTS_TO"),
                "weight": data.get("weight", 1.0),
                "traversability": data.get("traversability", 0.5),
                "active_alert": data.get("active_alert", False),
                "cve_details": data.get("cve_enriched")
            })
    else:
        for u, v in selected_edges:
            if engine.graph.has_edge(u, v):
                data = engine.graph.edges[u, v]
                edges.append({
                    "id": f"{u}->{v}",
                    "source": u,
                    "target": v,
                    "relationship": data.get("relationship", "CONNECTS_TO"),
                    "weight": data.get("weight", 1.0),
                    "traversability": data.get("traversability", 0.5),
                    "active_alert": data.get("active_alert", False),
                    "cve_details": data.get("cve_enriched")
                })

    return jsonify({
        "nodes": nodes,
        "edges": edges,
        "metadata": {
            "displayed_nodes": len(nodes),
            "displayed_edges": len(edges),
            "total_nodes": total_g_nodes,
            "total_edges": engine.graph.number_of_edges(),
            "crown_jewels_count": len(engine.crown_jewels),
            "entry_points_count": len(engine.entry_points),
            "view_mode": mode
        }
    })

@app.route("/api/paths", methods=["GET"])
def get_attack_paths():
    paths = engine.evaluate_all_attack_paths()
    return jsonify({
        "count": len(paths),
        "paths": paths
    })

@app.route("/api/chokepoints", methods=["GET"])
def get_chokepoints():
    cps = engine.find_choke_points()
    return jsonify({
        "count": len(cps),
        "chokepoints": cps
    })

@app.route("/api/node/toggle-crown-jewel", methods=["POST"])
def toggle_crown_jewel():
    """
    Allows the operator to designate any discovered infrastructure node as a Tier-0 Crown Jewel.
    """
    data = request.get_json(force=True) or {}
    node_id = data.get("node_id")
    if not node_id or not engine.graph.has_node(node_id):
        return jsonify({"error": f"Node '{node_id}' not found"}), 404

    is_jewel = node_id in engine.crown_jewels
    if is_jewel:
        engine.crown_jewels.remove(node_id)
        orig = engine.graph.nodes[node_id].get("original_type", "Asset")
        engine.graph.nodes[node_id]["node_type"] = orig
        new_status = False
    else:
        engine.crown_jewels.add(node_id)
        if "original_type" not in engine.graph.nodes[node_id]:
            engine.graph.nodes[node_id]["original_type"] = engine.graph.nodes[node_id].get("node_type", "Asset")
        engine.graph.nodes[node_id]["node_type"] = "CrownJewel"
        new_status = True

    paths = engine.evaluate_all_attack_paths()
    chokepoints = engine.find_choke_points()
    sync_to_memgraph_container()
    broadcaster.broadcast("GRAPH_MUTATION", {
        "action": "CROWN_JEWEL_TOGGLED",
        "node_id": node_id,
        "is_crown_jewel": new_status
    })

    return jsonify({
        "status": "success",
        "node_id": node_id,
        "is_crown_jewel": new_status,
        "active_paths_count": len(paths),
        "chokepoints_count": len(chokepoints)
    })

@app.route("/api/telemetry/alert", methods=["POST"])
def post_telemetry_alert():
    """
    Ingests real telemetry / EDR webhook alerts.
    """
    data = request.get_json(force=True) or {}
    node_id = data.get("node_id")

    if not node_id or not engine.graph.has_node(node_id):
        return jsonify({"error": f"Target node '{node_id}' not found in graph."}), 404

    alert_id = data.get("alert_id", f"alert-{int(time.time())}")
    alert_type = data.get("alert_type", "Suspicious Activity Detected")
    severity = data.get("severity", "CRITICAL")

    modified_edges = engine.inject_telemetry_alert(node_id, alert_id, alert_type, severity)
    updated_paths = engine.evaluate_all_attack_paths()
    top_path = updated_paths[0] if updated_paths else None

    broadcaster.broadcast("TELEMETRY_ALERT", {
        "node_id": node_id,
        "alert_id": alert_id,
        "alert_type": alert_type,
        "severity": severity,
        "top_path": top_path
    })

    return jsonify({
        "status": "alert_processed",
        "node_id": node_id,
        "modified_edges": [f"{u}->{v}" for u, v in modified_edges],
        "top_attack_path": top_path
    })

@app.route("/api/simulate/sever", methods=["POST"])
def simulate_sever_chokepoint():
    """
    Evaluates what-if remediation impact if a choke point or node is eliminated.
    """
    data = request.get_json(force=True) or {}
    target_id = data.get("target_id")

    if not target_id:
        cps = engine.find_choke_points()
        if cps:
            target_id = cps[0]["node_id"]
        else:
            return jsonify({"error": "No choke points identified to evaluate."}), 400

    if not engine.graph.has_node(target_id):
        return jsonify({"error": f"Node '{target_id}' not found"}), 404

    sim_res = engine.simulate_remediation(target_id)
    return jsonify(sim_res)

# --- Real Infrastructure Ingestion Endpoints ---

@app.route("/api/ingest/aws/live", methods=["POST"])
def ingest_aws_live():
    """
    Connects to live AWS account via read-only Boto3 session.
    """
    data = request.get_json(force=True) or {}
    key = data.get("access_key")
    secret = data.get("secret_key")
    token = data.get("session_token")
    region = data.get("region", "us-east-1")

    res = aws_ingestor.ingest_from_boto3(
        access_key=key,
        secret_key=secret,
        session_token=token,
        region=region
    )

    sync_to_memgraph_container()

    broadcaster.broadcast("GRAPH_MUTATION", {
        "action": "AWS_LIVE_INGESTED",
        "details": res
    })
    return jsonify(res)

@app.route("/api/ingest/bloodhound", methods=["POST"])
def ingest_bloodhound():
    """
    Ingests BloodHound JSON dump (users, groups, computers, ACLs).
    """
    data = request.get_json(force=True)
    res = bh_ingestor.ingest_data(data)
    sync_to_memgraph_container()
    broadcaster.broadcast("GRAPH_MUTATION", {
        "action": "BLOODHOUND_INGESTED",
        "details": res
    })
    return jsonify({
        "status": "bloodhound_ingested",
        "nodes_added": res["nodes_added"],
        "edges_added": res["edges_added"],
        "total_nodes": engine.graph.number_of_nodes(),
        "total_edges": engine.graph.number_of_edges()
    })

@app.route("/api/ingest/bloodhound/directory", methods=["POST"])
def ingest_bloodhound_directory():
    """
    Ingests all BloodHound files from a local directory (e.g. D:\\ad_sampledata).
    """
    data = request.get_json(force=True) or {}
    dir_path = data.get("directory", r"D:\ad_sampledata")
    domain = data.get("domain", "PHANTOM")

    try:
        res = bh_ingestor.ingest_directory(dir_path, domain_filter=domain)
        sync_to_memgraph_container()
        broadcaster.broadcast("GRAPH_MUTATION", {
            "action": "BLOODHOUND_DIRECTORY_INGESTED",
            "details": res
        })
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/ingest/cve", methods=["POST"])
def ingest_cve():
    """
    Associates a real CVE with an existing host and enriches it via live EPSS & CISA KEV feeds.
    """
    data = request.get_json(force=True) or {}
    host_id = data.get("target_host_id")
    cve_id = data.get("cve_id", "").strip().upper()
    cvss = float(data.get("cvss_score", 8.0))

    if not host_id or not cve_id:
        return jsonify({"error": "target_host_id and cve_id are required"}), 400

    if not engine.graph.has_node(host_id):
        engine.add_node(host_id, "Host", f"Host: {host_id}")

    cve_info = cti_client.enrich_vulnerability(cve_id, cvss_score=cvss)

    engine.add_node(
        node_id=cve_id,
        node_type="Vulnerability",
        name=f"{cve_id} (CVSS: {cvss})",
        cvss=cvss,
        epss=cve_info.get("epss_score"),
        in_cisa_kev=cve_info.get("in_cisa_kev", False)
    )
    engine.add_edge(host_id, cve_id, "VULNERABLE_TO", base_probability=cve_info.get("composite_exploitability", 0.85))

    sync_to_memgraph_container()
    broadcaster.broadcast("GRAPH_MUTATION", {
        "action": "CVE_INGESTED",
        "host_id": host_id,
        "cve_id": cve_id
    })

    return jsonify({
        "status": "cve_ingested",
        "host_id": host_id,
        "cve_id": cve_id,
        "cve_enriched": cve_info
    })

@app.route("/api/ingest/trivy", methods=["POST"])
def ingest_trivy():
    """
    Ingests raw Trivy vulnerability scan JSON report.
    """
    data = request.get_json(force=True)
    host_id = data.get("target_host_id")
    report = data.get("report", {})

    res = trivy_ingestor.ingest_trivy_report(host_id, report)
    sync_to_memgraph_container()
    broadcaster.broadcast("GRAPH_MUTATION", {
        "action": "TRIVY_INGESTED",
        "details": res
    })
    return jsonify(res)

@app.route("/api/reset", methods=["POST"])
def reset_graph():
    """Resets the graph to clean slate."""
    init_clean_graph()
    sync_to_memgraph_container()
    broadcaster.broadcast("GRAPH_RESET", {"status": "clean_slate"})
    return jsonify({"status": "graph_reset_to_clean_slate"})


# --- Real-Time SSE Stream Endpoint ---
@app.route("/api/events")
def sse_events():
    def event_stream():
        q = broadcaster.listen()
        yield f"event: CONNECTED\ndata: {json.dumps({'status': 'active', 'nodes': engine.graph.number_of_nodes()})}\n\n"
        try:
            while True:
                msg = q.get()
                yield msg
        except GeneratorExit:
            broadcaster.remove(q)

    return Response(event_stream(), mimetype="text/event-stream")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8081))
    print(f"[*] AegisPath Real Infrastructure Engine listening on http://localhost:{port}...")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
