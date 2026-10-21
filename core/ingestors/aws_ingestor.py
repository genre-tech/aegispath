"""
AWS Cloud Cartography Ingestor
Connects directly to AWS via Boto3 (using read-only credentials / SecurityAudit)
OR parses offline AWS CLI / Cartography JSON exports to map cloud attack surfaces.
"""

import json
import re
from typing import Dict, List, Any, Optional
from ..adaptive_engine import AdaptiveAttackPathEngine


class AWSIngestor:
    def __init__(self, engine: AdaptiveAttackPathEngine):
        self.engine = engine

    def ingest_from_boto3(
        self,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        session_token: Optional[str] = None,
        region: str = "us-east-1"
    ) -> Dict[str, Any]:
        """
        Executes read-only API calls to map active AWS cloud resources.
        Requires minimal read-only permissions (e.g. AWS SecurityAudit policy).
        """
        import boto3

        # Convert Availability Zones (e.g. ap-southeast-2b) to valid Region names (ap-southeast-2)
        raw_region = (region or "us-east-1").strip().lower()
        cleaned_region = re.sub(r'([a-z]{2}-[a-z]+-\d+)[a-z]$', r'\1', raw_region)

        session = boto3.Session(
            aws_access_key_id=access_key.strip() if access_key else None,
            aws_secret_access_key=secret_key.strip() if secret_key else None,
            aws_session_token=session_token.strip() if session_token else None,
            region_name=cleaned_region
        )

        nodes_added = 0
        edges_added = 0
        service_errors = {}
        service_counts = {
            "ec2": 0,
            "security_groups": 0,
            "iam_roles": 0,
            "iam_users": 0,
            "s3": 0,
            "rds": 0
        }

        # Ensure Perimeter entry point exists
        self.engine.add_node("internet", "Perimeter", "Public Internet", is_entry_point=True)

        ec2_client = None
        iam_client = None

        # 1. Inspect EC2 Instances & Security Groups
        try:
            ec2_client = session.client("ec2")
            res_instances = ec2_client.describe_instances()
            discovered_instances = []

            for r in res_instances.get("Reservations", []):
                for inst in r.get("Instances", []):
                    inst_id = inst["InstanceId"]
                    pub_ip = inst.get("PublicIpAddress")
                    priv_ip = inst.get("PrivateIpAddress")
                    state = inst.get("State", {}).get("Name", "running")
                    name = inst_id
                    for t in inst.get("Tags", []):
                        if t.get("Key") == "Name":
                            name = t.get("Value", inst_id)

                    self.engine.add_node(
                        node_id=inst_id,
                        node_type="Host",
                        name=f"EC2: {name}",
                        public_ip=pub_ip or "None",
                        private_ip=priv_ip or "None",
                        instance_type=inst.get("InstanceType", "unknown"),
                        state=state
                    )
                    nodes_added += 1
                    service_counts["ec2"] += 1
                    discovered_instances.append(inst)

                    # If public IP is attached, direct perimeter reachability
                    if pub_ip:
                        self.engine.add_edge("internet", inst_id, "NETWORK_REACHABLE", base_probability=0.95)
                        edges_added += 1

                    # Inspect attached Security Groups
                    for sg in inst.get("SecurityGroups", []):
                        sg_id = sg.get("GroupId")
                        sg_name = sg.get("GroupName", sg_id)
                        if not self.engine.graph.has_node(sg_id):
                            self.engine.add_node(
                                node_id=sg_id,
                                node_type="SecurityGroup",
                                name=f"SG: {sg_name}",
                                group_id=sg_id,
                                group_name=sg_name
                            )
                            nodes_added += 1
                            service_counts["security_groups"] += 1
                        # Inbound traffic permitted through SG to EC2 instance
                        self.engine.add_edge(sg_id, inst_id, "ALLOWS_INGRESS_TO", base_probability=0.90)
                        edges_added += 1

                    # Check IAM Instance Profile (Role attached to EC2)
                    iam_prof = inst.get("IamInstanceProfile", {})
                    if "Arn" in iam_prof:
                        prof_arn = iam_prof["Arn"]
                        prof_name = prof_arn.split("/")[-1]
                        self.engine.add_node(prof_arn, "InstanceProfile", f"Profile: {prof_name}")
                        self.engine.add_edge(inst_id, prof_arn, "HAS_INSTANCE_PROFILE", base_probability=0.95)
                        nodes_added += 1
                        edges_added += 1

            # Inspect Security Group ingress rules (open ports to Internet)
            try:
                sg_resp = ec2_client.describe_security_groups()
                for sg in sg_resp.get("SecurityGroups", []):
                    sg_id = sg.get("GroupId")
                    if self.engine.graph.has_node(sg_id):
                        for perm in sg.get("IpPermissions", []):
                            from_port = perm.get("FromPort")
                            to_port = perm.get("ToPort")
                            protocol = perm.get("IpProtocol", "-1")
                            is_public = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
                            if is_public:
                                if from_port == to_port and from_port is not None:
                                    port_str = f"PORT_{from_port}"
                                elif from_port is not None:
                                    port_str = f"PORTS_{from_port}-{to_port}"
                                else:
                                    port_str = "ALL_TRAFFIC"
                                self.engine.add_edge("internet", sg_id, f"EXPOSED_{port_str}", base_probability=0.95)
                                edges_added += 1
            except Exception as sg_err:
                print(f"[!] Info: Security group detailed rule inspection skipped: {sg_err}")

        except Exception as e:
            service_errors["ec2"] = str(e)
            print(f"[!] Warning: Unable to inspect EC2: {e}")

        # 2. Inspect IAM Roles & Attached Policies
        try:
            iam_client = session.client("iam")
            res_roles = iam_client.list_roles(MaxItems=100)

            for role in res_roles.get("Roles", []):
                role_arn = role["Arn"]
                role_name = role["RoleName"]

                # Detect if this is an Administrator or High-Privilege Role
                is_admin_role = any(term in role_name.lower() for term in ("admin", "root", "devops", "poweruser", "fullaccess"))
                node_category = "CrownJewel" if is_admin_role else "IAMRole"

                # Check attached managed policies if permitted
                attached_policies = []
                try:
                    pol_res = iam_client.list_attached_role_policies(RoleName=role_name)
                    attached_policies = [p["PolicyName"] for p in pol_res.get("AttachedPolicies", [])]
                    if any("admin" in p.lower() or "fullaccess" in p.lower() or "poweruser" in p.lower() for p in attached_policies):
                        node_category = "CrownJewel"
                except Exception:
                    pass

                self.engine.add_node(
                    node_id=role_arn,
                    node_type=node_category,
                    name=f"IAM: {role_name}",
                    arn=role_arn,
                    attached_policies=", ".join(attached_policies) if attached_policies else "Default",
                    criticality="CRITICAL" if node_category == "CrownJewel" else "STANDARD"
                )
                nodes_added += 1
                service_counts["iam_roles"] += 1

                # Parse AssumeRoleTrustPolicyDocument for role-to-role or user-to-role delegation
                trust_doc = role.get("AssumeRolePolicyDocument", {})
                statements = trust_doc.get("Statement", [])
                for stmt in statements:
                    if stmt.get("Effect") == "Allow" and "sts:AssumeRole" in str(stmt.get("Action", "")):
                        principal = stmt.get("Principal", {})
                        aws_principals = principal.get("AWS", [])
                        if isinstance(aws_principals, str):
                            aws_principals = [aws_principals]
                        for p in aws_principals:
                            if not self.engine.graph.has_node(p):
                                self.engine.add_node(p, "Identity", f"Principal: {p.split('/')[-1]}")
                                nodes_added += 1
                            self.engine.add_edge(p, role_arn, "CAN_ASSUME_ROLE", base_probability=0.85)
                            edges_added += 1

            # Resolve Instance Profiles to underlying Roles
            if ec2_client and iam_client:
                for n_id, data in list(self.engine.graph.nodes(data=True)):
                    if data.get("node_type") == "InstanceProfile":
                        prof_name = data.get("name", "").replace("Profile: ", "").strip()
                        try:
                            prof_detail = iam_client.get_instance_profile(InstanceProfileName=prof_name)
                            for r in prof_detail.get("InstanceProfile", {}).get("Roles", []):
                                r_arn = r["Arn"]
                                if not self.engine.graph.has_node(r_arn):
                                    self.engine.add_node(r_arn, "IAMRole", f"IAM: {r['RoleName']}")
                                    nodes_added += 1
                                self.engine.add_edge(n_id, r_arn, "GRANTS_ROLE", base_probability=0.95)
                                edges_added += 1
                        except Exception:
                            pass

        except Exception as e:
            service_errors["iam_roles"] = str(e)
            print(f"[!] Warning: Unable to inspect IAM Roles: {e}")

        # 3. Inspect IAM Users (Identities)
        try:
            if not iam_client:
                iam_client = session.client("iam")
            res_users = iam_client.list_users(MaxItems=100)
            for user in res_users.get("Users", []):
                u_arn = user["Arn"]
                u_name = user["UserName"]
                self.engine.add_node(
                    node_id=u_arn,
                    node_type="Identity",
                    name=f"User: {u_name}",
                    arn=u_arn
                )
                nodes_added += 1
                service_counts["iam_users"] += 1
        except Exception as e:
            service_errors["iam_users"] = str(e)
            print(f"[!] Warning: Unable to inspect IAM Users: {e}")

        # 4. Inspect S3 Buckets as potential Crown Jewels
        try:
            s3 = session.client("s3")
            buckets = s3.list_buckets().get("Buckets", [])
            for b in buckets:
                b_name = b["Name"]
                b_arn = f"arn:aws:s3:::{b_name}"
                self.engine.add_node(
                    node_id=b_arn,
                    node_type="CrownJewel",
                    name=f"S3: {b_name}",
                    criticality="CRITICAL"
                )
                nodes_added += 1
                service_counts["s3"] += 1
        except Exception as e:
            service_errors["s3"] = str(e)
            print(f"[!] Warning: Unable to inspect S3: {e}")

        # 5. Inspect RDS Databases as Crown Jewels
        try:
            rds = session.client("rds")
            dbs = rds.describe_db_instances().get("DBInstances", [])
            for db in dbs:
                db_arn = db.get("DBInstanceArn", db["DBInstanceIdentifier"])
                db_id = db["DBInstanceIdentifier"]
                engine_name = db.get("Engine", "database")
                self.engine.add_node(
                    node_id=db_arn,
                    node_type="CrownJewel",
                    name=f"RDS ({engine_name}): {db_id}",
                    criticality="CRITICAL"
                )
                nodes_added += 1
                service_counts["rds"] += 1
        except Exception as e:
            service_errors["rds"] = str(e)
            print(f"[!] Warning: Unable to inspect RDS: {e}")

        return {
            "status": "success",
            "requested_region": raw_region,
            "resolved_region": cleaned_region,
            "nodes_added": nodes_added,
            "edges_added": edges_added,
            "counts": service_counts,
            "errors": service_errors
        }

    def ingest_from_json(self, data: Dict[str, Any]) -> Dict[str, int]:
        """
        Parses offline AWS Cartography or AWS CLI JSON exports.
        """
        nodes_added = 0
        edges_added = 0

        self.engine.add_node("internet", "Perimeter", "Public Internet", is_entry_point=True)

        for inst in data.get("ec2_instances", []):
            i_id = inst.get("id")
            pub_ip = inst.get("public_ip")
            name = inst.get("name", i_id)
            self.engine.add_node(i_id, "Host", f"EC2: {name}", public_ip=pub_ip or "None")
            nodes_added += 1
            if pub_ip and pub_ip != "None":
                self.engine.add_edge("internet", i_id, "NETWORK_REACHABLE", base_probability=0.95)
                edges_added += 1

        for role in data.get("iam_roles", []):
            r_arn = role.get("arn")
            r_name = role.get("name", r_arn)
            is_admin = role.get("is_admin", False)
            cat = "CrownJewel" if is_admin else "IAMRole"
            self.engine.add_node(r_arn, cat, f"IAM: {r_name}")
            nodes_added += 1

        for bucket in data.get("s3_buckets", []):
            b_id = bucket.get("id")
            b_name = bucket.get("name", b_id)
            self.engine.add_node(b_id, "CrownJewel", f"S3: {b_name}")
            nodes_added += 1

        for link in data.get("relationships", []):
            self.engine.add_edge(
                link["source"],
                link["target"],
                link.get("relationship", "CONNECTS_TO"),
                base_probability=link.get("probability", 0.8)
            )
            edges_added += 1

        return {"nodes_added": nodes_added, "edges_added": edges_added}
