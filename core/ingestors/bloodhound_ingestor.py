"""
BloodHound Active Directory & Azure Ingestor
Parses BloodHound v4/v5 JSON formats (users.json, computers.json, groups.json, domains.json)
and full BloodHound CE collection directories.
Maps identity privilege escalation vectors, group delegations, and domain trusts into the
canonical attack path graph.
"""

import os
import glob
import json
from typing import Dict, List, Any, Optional
from ..adaptive_engine import AdaptiveAttackPathEngine


class BloodHoundIngestor:
    def __init__(self, engine: AdaptiveAttackPathEngine):
        self.engine = engine

    def ingest_data(self, data: Dict[str, Any]) -> Dict[str, int]:
        """
        Parses a BloodHound JSON payload and populates the graph.
        Returns counts of ingested nodes and edges.
        """
        nodes_added = 0
        edges_added = 0

        items = data.get("data", [])
        if not items and isinstance(data, list):
            items = data

        for item in items:
            props = item.get("Properties", {})
            obj_id = item.get("ObjectIdentifier") or props.get("domainsid") or props.get("name")
            if not obj_id:
                continue

            name = props.get("name") or props.get("distinguishedname") or str(obj_id)
            obj_type = item.get("type") or self._infer_bloodhound_type(name, props, item)

            # Detect Tier-0 Crown Jewels in Active Directory
            is_tier_0 = False
            is_dc = item.get("IsDC", False) or props.get("isdc", False)
            if is_dc:
                is_tier_0 = True
            elif obj_type == "Group":
                name_upper = name.upper()
                if any(kw in name_upper for kw in ("DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS", "ACCOUNT OPERATORS", "ADMINISTRATORS@")):
                    is_tier_0 = True
            elif obj_type == "Computer":
                name_upper = name.upper()
                if "DC0" in name_upper or "-DC" in name_upper or "DOMAIN CONTROLLER" in name_upper:
                    is_tier_0 = True

            node_category = "CrownJewel" if is_tier_0 else ("Identity" if obj_type in ("User", "Group") else ("Host" if obj_type == "Computer" else "Asset"))

            self.engine.add_node(
                node_id=obj_id,
                node_type=node_category,
                name=name,
                bloodhound_type=obj_type,
                enabled=props.get("enabled", True),
                domain=props.get("domain", "CORP.LOCAL"),
                admin_count=props.get("admincount", False),
                is_dc=is_dc
            )
            nodes_added += 1

            # 1. Ingest Group Memberships
            for member in item.get("Members", []):
                member_id = member.get("ObjectIdentifier")
                if member_id:
                    self.engine.add_edge(member_id, obj_id, "MEMBER_OF", base_probability=0.99)
                    edges_added += 1

            # 2. Ingest Access Control Entries (Aces) - High-risk lateral vectors
            for ace in item.get("Aces", []):
                principal_id = ace.get("PrincipalSID")
                right = ace.get("RightName", "GenericAll")
                if principal_id:
                    right_upper = right.upper()
                    # Weight depends on the danger of the permission
                    prob = 0.95 if right_upper in ("GENERICALL", "WRITEDACL", "WRITEOWNER", "ALLRIGHTS", "GETCHANGESALL", "ADDMEMBER") else 0.75
                    self.engine.add_edge(principal_id, obj_id, right_upper, base_probability=prob)
                    edges_added += 1

            # 3. Ingest Active Sessions (Sessions, PrivilegedSessions, RegistrySessions)
            for sess_key in ("Sessions", "PrivilegedSessions", "RegistrySessions"):
                sess_data = item.get(sess_key, [])
                sess_list = sess_data.get("Results", []) if isinstance(sess_data, dict) else (sess_data if isinstance(sess_data, list) else [])
                for session in sess_list:
                    if isinstance(session, dict):
                        user_sid = session.get("UserSID") or session.get("UserId")
                        comp_sid = session.get("ComputerSID") or session.get("ComputerId") or obj_id
                        if user_sid and comp_sid:
                            # Compromising the host yields user credentials in memory
                            self.engine.add_edge(comp_sid, user_sid, "HAS_SESSION", base_probability=0.85)
                            edges_added += 1

            # 4. Ingest Local Admin Rights (LocalAdmins / GPOChanges)
            local_admins = item.get("LocalAdmins") or []
            if isinstance(local_admins, list):
                for admin in local_admins:
                    admin_sid = admin.get("ObjectIdentifier") if isinstance(admin, dict) else None
                    if admin_sid:
                        self.engine.add_edge(admin_sid, obj_id, "ADMIN_TO", base_probability=0.95)
                        edges_added += 1

            # 5. Ingest Domain Trusts (for domains.json)
            for trust in item.get("Trusts", []):
                target_sid = trust.get("TargetDomainSid")
                target_name = trust.get("TargetDomainName", target_sid)
                if target_sid:
                    if not self.engine.graph.has_node(target_sid):
                        self.engine.add_node(target_sid, "Asset", target_name, domain=target_name)
                        nodes_added += 1
                    self.engine.add_edge(obj_id, target_sid, "TRUSTS_DOMAIN", base_probability=0.90)
                    edges_added += 1

        return {"nodes_added": nodes_added, "edges_added": edges_added}

    def ingest_directory(self, folder_path: str, domain_filter: Optional[str] = None) -> Dict[str, Any]:
        """
        Parses all BloodHound JSON files in a directory (e.g. D:\\ad_sampledata).
        domain_filter: can be 'PHANTOM', 'GHOST', 'WRAITH', or None for all.
        """
        if not os.path.exists(folder_path):
            raise FileNotFoundError(f"Directory not found: {folder_path}")

        json_files = glob.glob(os.path.join(folder_path, "*.json"))
        total_nodes = 0
        total_edges = 0
        processed_files = []

        # Map domain filter to timestamp prefixes if known
        prefix_map = {
            "PHANTOM": "20240305110018",
            "GHOST": "20240305110427",
            "WRAITH": "20240305111414"
        }
        active_prefix = prefix_map.get((domain_filter or "").upper().strip())

        for file_path in json_files:
            fname = os.path.basename(file_path)
            if active_prefix and not fname.startswith(active_prefix):
                continue

            try:
                with open(file_path, "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                    res = self.ingest_data(data)
                    total_nodes += res["nodes_added"]
                    total_edges += res["edges_added"]
                    processed_files.append(fname)
            except Exception as e:
                print(f"[!] Warning reading {fname}: {e}")

        # Set default entry points for AD if not already set:
        # All non-admin users act as potential initial compromise footholds
        ad_users = [
            n for n, d in self.engine.graph.nodes(data=True)
            if d.get("bloodhound_type") == "User" and not d.get("admin_count", False)
        ]
        # Register standard users as entry points so Dijkstra computes reachability to Domain Admins
        for u in ad_users:
            self.engine.entry_points.add(u)

        return {
            "status": "success",
            "folder": folder_path,
            "domain_filter": domain_filter or "ALL",
            "files_processed": len(processed_files),
            "nodes_added": total_nodes,
            "edges_added": total_edges,
            "total_graph_nodes": self.engine.graph.number_of_nodes(),
            "total_graph_edges": self.engine.graph.number_of_edges(),
            "crown_jewels_count": len(self.engine.crown_jewels),
            "entry_points_count": len(self.engine.entry_points)
        }

    def _infer_bloodhound_type(self, name: str, props: Dict[str, Any], item: Dict[str, Any]) -> str:
        if item.get("IsDC", False) or props.get("isdc", False) or "operatingsystem" in props or name.endswith("$"):
            return "Computer"
        if "members" in props or item.get("Members"):
            return "Group"
        return "User"
