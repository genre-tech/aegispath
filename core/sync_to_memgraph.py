import urllib.request
import json
import subprocess

def sync_active_graph_to_memgraph():
    resp = urllib.request.urlopen("http://localhost:8081/api/graph")
    data = json.loads(resp.read().decode("utf-8"))

    statements = ["MATCH (n) DETACH DELETE n;"]

    for n in data["nodes"]:
        labels = [n["type"]]
        if n.get("is_crown_jewel"):
            labels.append("CrownJewel")
        if n.get("is_entry_point"):
            labels.append("EntryPoint")
        lbl = ":".join(labels)
        name = n["label"].replace('"', '\\"')
        props = [f'id: "{n["id"]}"', f'name: "{name}"']
        for k, v in n.get("attributes", {}).items():
            if isinstance(v, bool):
                props.append(f"{k}: {str(v).lower()}")
            elif isinstance(v, (int, float)):
                props.append(f"{k}: {v}")
            elif isinstance(v, str):
                clean_v = v.replace('"', '\\"')
                props.append(f'{k}: "{clean_v}"')
        statements.append(f"CREATE (:{lbl} {{{', '.join(props)}}});")

    for e in data["edges"]:
        rel = e["relationship"]
        w = e.get("weight", 1.0)
        t = e.get("traversability", 0.5)
        alert = str(e.get("active_alert", False)).lower()
        statements.append(
            f'MATCH (a {{id: "{e["source"]}"}}), (b {{id: "{e["target"]}"}}) '
            f'CREATE (a)-[:{rel} {{weight: {w}, traversability: {t}, active_alert: {alert}}}]->(b);'
        )

    for stmt in statements:
        cmd = ["docker", "exec", "-i", "adaptive-memgraph", "mgconsole"]
        subprocess.run(cmd, input=(stmt + ";\n").encode("utf-8"), capture_output=True)

    print(f"Successfully synchronized {len(data['nodes'])} nodes and {len(data['edges'])} edges into Memgraph MAGE!")

if __name__ == "__main__":
    sync_active_graph_to_memgraph()
