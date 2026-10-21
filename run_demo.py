"""
Adaptive Cyber Intelligence & Attack Path POC Demonstration
Demonstrates:
1. Live CTI Enrichment (FIRST.org EPSS API & CISA KEV)
2. Unified Multi-Cloud & Identity Graph Modeling
3. Shortest Lateral Movement Pathfinding
4. Real-time Telemetry Adaptation (EDR/Falco alert injection)
5. Algorithmic Choke-Point Identification
6. 'What-If' Remediation Simulation
"""

import sys
import os
import json

# Ensure core package is on path
sys.path.insert(0, os.path.dirname(__file__))

from core.cti_client import CTIClient
from core.adaptive_engine import AdaptiveAttackPathEngine
from core.memgraph_exporter import export_to_cypher


def build_enterprise_topology(engine: AdaptiveAttackPathEngine):
    """
    Constructs a realistic hybrid enterprise topology:
    - Perimeter (Internet, Public API, Phished Endpoint)
    - Network Subnets (DMZ, Internal K8s)
    - Identities (Active Directory User, Cloud IAM Roles)
    - Vulnerabilities (Log4Shell, Outlook NTLM Leak)
    - Crown Jewels (Production RDS Database, AWS Root)
    """
    print("[*] Building Enterprise Graph Topology...")

    # 1. Entry Points
    engine.add_node("internet", "Perimeter", "Public Internet", is_entry_point=True)
    engine.add_node("phished_email", "Perimeter", "Phishing Campaign (Inbound)", is_entry_point=True)

    # 2. Vulnerabilities with Live CTI Tracking
    # Log4Shell (High EPSS, In CISA KEV)
    engine.add_node("CVE-2021-44228", "Vulnerability", "Apache Log4j RCE (Log4Shell)", cvss=10.0)
    # Outlook NTLM Leak (High EPSS, In CISA KEV)
    engine.add_node("CVE-2023-23397", "Vulnerability", "Microsoft Outlook Elevation of Privilege", cvss=9.8)

    # 3. Perimeter & Internal Compute Assets
    engine.add_node("dmz_nginx_api", "Host", "Public API Gateway (NGINX)", ip="54.210.12.33")
    engine.add_node("bob_workstation", "Host", "Bob Developer Laptop (Windows 11)", ip="10.0.10.45")
    engine.add_node("k8s_worker_node", "Host", "Kubernetes Worker Node (EKS)", ip="10.0.20.101")
    engine.add_node("bastion_host", "Host", "Internal Bastion / Jumpbox", ip="10.0.30.5")

    # 4. Identities & Access Control
    engine.add_node("user_bob", "Identity", "Bob Jenkins (Lead Developer)", email="bob@enterprise.corp")
    engine.add_node("iam_role_k8s_bootstrap", "IAMRole", "k8s-node-bootstrap-role", arn="arn:aws:iam::123:role/k8s-node")
    engine.add_node("iam_role_devops_admin", "IAMRole", "DevOpsAdminAssumeRole", arn="arn:aws:iam::123:role/DevOpsAdmin")

    # 5. Crown Jewels (Tier-0 Assets)
    engine.add_node(
        "rds_customer_db",
        "CrownJewel",
        "Production Customer RDS PostgreSQL (Tier-0)",
        arn="arn:aws:rds:us-east-1:123:db:prod-customer-db",
        criticality="CRITICAL"
    )
    engine.add_node(
        "aws_root_account",
        "CrownJewel",
        "AWS Organization Root Account",
        arn="arn:aws:organizations::123:root",
        criticality="CRITICAL"
    )

    # 6. Topology Relationships (Edges)
    # Path A: Internet -> NGINX (exploiting Log4Shell) -> K8s Node -> IAM Role -> Customer DB
    engine.add_edge("internet", "dmz_nginx_api", "NETWORK_REACHABLE", base_probability=0.90)
    engine.add_edge("dmz_nginx_api", "CVE-2021-44228", "VULNERABLE_TO", base_probability=0.95)
    engine.add_edge("CVE-2021-44228", "k8s_worker_node", "REMOTE_CODE_EXECUTION", base_probability=0.90)
    engine.add_edge("k8s_worker_node", "iam_role_k8s_bootstrap", "HAS_INSTANCE_PROFILE", base_probability=0.85)
    engine.add_edge("iam_role_k8s_bootstrap", "iam_role_devops_admin", "CAN_ASSUME_ROLE", base_probability=0.70)
    engine.add_edge("iam_role_devops_admin", "rds_customer_db", "ADMINISTERS_DATABASE", base_probability=0.95)
    engine.add_edge("iam_role_devops_admin", "aws_root_account", "CAN_ESCALATE_TO_ROOT", base_probability=0.60)

    # Path B: Phishing -> Bob's Laptop (CVE-2023-23397) -> Bob Identity -> Bastion -> DevOps Role
    engine.add_edge("phished_email", "bob_workstation", "TARGETS_ENDPOINT", base_probability=0.75)
    engine.add_edge("bob_workstation", "CVE-2023-23397", "EXPLOITS_VULN", base_probability=0.90)
    engine.add_edge("CVE-2023-23397", "user_bob", "STEALS_CACHED_CREDENTIALS", base_probability=0.80)
    engine.add_edge("user_bob", "bastion_host", "SSH_ACCESS", base_probability=0.85)
    engine.add_edge("bastion_host", "iam_role_devops_admin", "CACHED_AWS_CREDENTIALS", base_probability=0.75)


def print_path(path_result: dict, title: str = "Active Attack Path"):
    print(f"\n{'='*70}")
    print(f"  {title.upper()}")
    print(f"{'='*70}")
    print(f"Origin Entry:         {path_result['source']}")
    print(f"Target Crown Jewel:   {path_result['target']}")
    print(f"Total Traversal Cost: {path_result['total_cost']} (Lower = Higher Risk / Less Friction)")
    print(f"Breach Probability:   {path_result['cumulative_probability']*100:.2f}%")
    print(f"Hops in Chain:        {path_result['hop_count']}")
    print("-" * 70)
    for idx, step in enumerate(path_result["steps"], 1):
        alert_str = " [! ACTIVE EDR ALERT !]" if step["has_active_alert"] else ""
        cve_str = ""
        if step["cve_details"]:
            cve = step["cve_details"]
            cve_str = f" [EPSS: {cve['epss']*100:.1f}%, CISA KEV: {cve['in_cisa_kev']}]"
        print(f" Step {idx}: {step['from_name']}")
        print(f"         |---> ({step['relationship']}){alert_str}{cve_str} (Step Cost: {step['step_cost']})")
        print(f"         |---> {step['to_name']}")
    print("="*70)


def main():
    print("""
    ========================================================================
     ADAPTIVE CYBER INTELLIGENCE & ATTACK PATH REASONING ENGINE (POC)
     100% Free Resources: FIRST.org EPSS + CISA KEV + In-Memory Graph
    ========================================================================
    """)

    # 1. Initialize CTI Client & Sync Free Threat Intel
    cti = CTIClient()
    print("[*] Step 1: Connecting to 100% Free Threat Intel Feeds...")
    cisa_count = cti.sync_cisa_kev()
    print(f"    [+] CISA KEV Catalog Loaded: {cisa_count} actively exploited CVEs.")

    test_cve = "CVE-2021-44228"
    epss_info = cti.enrich_vulnerability(test_cve)
    print(f"    [+] Live EPSS Query for {test_cve}:")
    print(f"        - EPSS Score: {epss_info['epss']*100:.2f}% probability of exploitation in wild")
    print(f"        - CISA KEV Status: {epss_info['in_cisa_kev']}")
    print(f"        - Composite Exploitability: {epss_info['composite_exploitability']}")

    # 2. Build Attack Graph
    engine = AdaptiveAttackPathEngine(cti_client=cti)
    build_enterprise_topology(engine)
    print(f"    [+] Graph initialized: {engine.graph.number_of_nodes()} nodes, {engine.graph.number_of_edges()} directional edges.")

    # 3. Phase 1: Baseline Attack Path Discovery
    print("\n[*] Step 2: Evaluating Baseline Attack Paths to Crown Jewels...")
    baseline_paths = engine.evaluate_all_attack_paths()
    if baseline_paths:
        most_critical = baseline_paths[0]
        print_path(most_critical, title="Baseline Most Critical Attack Path")

    # 4. Phase 2: Dynamic Telemetry Injection (The "Adaptive" Factor)
    print("\n[*] Step 3: Injecting Live Real-Time Telemetry Event...")
    print("    [!] ALERT: Falco eBPF detected Container Escape & Credential Access on [k8s_worker_node]!")
    modified_edges = engine.inject_telemetry_alert(
        node_id="k8s_worker_node",
        alert_id="falco-evt-9901",
        alert_type="Container Escape & IAM Token Theft",
        severity="CRITICAL"
    )
    print(f"    [+] Graph dynamically adapted: Recalculated weights on {len(modified_edges)} edges connected to K8s node.")

    adapted_paths = engine.evaluate_all_attack_paths()
    if adapted_paths:
        adapted_most_critical = adapted_paths[0]
        print_path(adapted_most_critical, title="Adaptive Attack Path After Real-Time Alert")

    # 5. Phase 3: Algorithmic Choke-Point Analysis
    print("\n[*] Step 4: Computing Algorithmic Choke Points (Betweenness Centrality & Cut Vertices)...")
    choke_points = engine.find_choke_points()
    print(f"    {'Asset Name':<35} {'Type':<15} {'Centrality Score'}")
    print("    " + "-"*65)
    for cp in choke_points:
        print(f"    {cp['name']:<35} {cp['node_type']:<15} {cp['centrality_score']:<10}")
        print(f"    |- Recommendation: {cp['recommendation']}")

    # 6. Phase 4: 'What-If' Remediation Simulation
    if choke_points:
        top_choke_point = choke_points[0]["node_id"]
        print(f"\n[*] Step 5: Simulating 'What-If' Remediation on Top Choke Point: [{choke_points[0]['name']}]...")
        sim_result = engine.simulate_remediation(top_choke_point)
        print(f"    [+] Initial Viable Attack Paths:   {sim_result['initial_attack_paths']}")
        print(f"    [+] Remaining Paths After Cut:     {sim_result['remaining_attack_paths']}")
        print(f"    [+] Attack Paths Severed:          {sim_result['paths_eliminated']}")
        print(f"    [+] Risk Reduction Percentage:     {sim_result['risk_reduction_percentage']}%")
        if sim_result['is_fully_severed']:
            print("    [SUCCESS] COMPLETE SEVERANCE: All paths to Tier-0 crown jewels are broken!")

    # 7. Export Cypher for Memgraph Lab
    export_path = os.path.join(os.path.dirname(__file__), "queries", "exported_graph.cypher")
    cypher_content = export_to_cypher(engine)
    with open(export_path, "w", encoding="utf-8") as f:
        f.write(cypher_content)
    print(f"\n[*] Step 6: Exported Memgraph Cypher statements to: {export_path}")
    print("    You can paste this directly into Memgraph Lab (http://localhost:3000) or Neo4j browser!")


if __name__ == "__main__":
    main()
