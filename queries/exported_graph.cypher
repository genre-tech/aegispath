// ========================================================
// Adaptive Cyber Intelligence & Attack Path Graph Dump
// Clean slate: MATCH (n) DETACH DELETE n;
// ========================================================
MATCH (n) DETACH DELETE n;

// --- 1. Nodes ---
CREATE (:CrownJewel:CrownJewel {id: "S-1-5-21-1001-512", name: "DOMAIN ADMINS@CORP.LOCAL", bloodhound_type: "Group", enabled: true, domain: "CORP.LOCAL"});
CREATE (:Identity {id: "S-1-5-21-1001-1105", name: "SARAH.CONNER@CORP.LOCAL", bloodhound_type: "User", enabled: true, domain: "CORP.LOCAL"});
CREATE (:Identity {id: "S-1-5-21-1001-1102", name: "DAVE.DEV@CORP.LOCAL", bloodhound_type: "User", enabled: true, domain: "CORP.LOCAL"});
CREATE (:Host {id: "COMP-WS-DAVE.CORP.LOCAL", name: "COMP-WS-DAVE.CORP.LOCAL", bloodhound_type: "Computer", enabled: true, domain: "CORP.LOCAL"});
CREATE (:CrownJewel:CrownJewel {id: "COMP-DC01.CORP.LOCAL", name: "COMP-DC01.CORP.LOCAL (Primary Domain Controller)", bloodhound_type: "Computer", enabled: true, domain: "CORP.LOCAL"});
CREATE (:Perimeter:EntryPoint {id: "internet", name: "Public Internet", is_entry_point: true});
CREATE (:Host {id: "i-09ab12cd34ef5678", name: "Public Ingress NGINX Gateway", cloud_type: "Compute"});
CREATE (:IAMRole {id: "arn:aws:iam::123456789012:role/EC2AppRole", name: "IAM Role: EC2AppRole", cloud_type: "IAMRole"});
CREATE (:IAMRole {id: "arn:aws:iam::123456789012:role/DevOpsCloudAdminRole", name: "IAM Role: DevOpsCloudAdminRole (Tier-0)", cloud_type: "IAMRole"});
CREATE (:CrownJewel:CrownJewel {id: "arn:aws:rds:us-east-1:123456789012:db:production-core-db", name: "Production Customer Relational DB (RDS)", cloud_type: "Database"});
CREATE (:CrownJewel:CrownJewel {id: "arn:aws:s3:::customer-pii-vault", name: "S3 Vault: customer-pii-vault (Encrypted)", cloud_type: "Database"});
CREATE (:Asset {id: "phished_email", name: "phished_email"});

// --- 2. Relationships with Dynamic Weights ---
MATCH (a {id: "S-1-5-21-1001-1105"}), (b {id: "S-1-5-21-1001-512"}) CREATE (a)-[:MEMBER_OF {weight: 1.0101, traversability: 0.99, active_alert: false}]->(b);
MATCH (a {id: "S-1-5-21-1001-1105"}), (b {id: "arn:aws:iam::123456789012:role/DevOpsCloudAdminRole"}) CREATE (a)-[:SAML_SSO_FEDERATION {weight: 1.0101, traversability: 0.99, active_alert: false}]->(b);
MATCH (a {id: "S-1-5-21-1001-1102"}), (b {id: "S-1-5-21-1001-1105"}) CREATE (a)-[:GENERICALL {weight: 1.0526, traversability: 0.95, active_alert: false}]->(b);
MATCH (a {id: "S-1-5-21-1001-1102"}), (b {id: "COMP-WS-DAVE.CORP.LOCAL"}) CREATE (a)-[:HAS_SESSION {weight: 1.1765, traversability: 0.85, active_alert: false}]->(b);
MATCH (a {id: "internet"}), (b {id: "i-09ab12cd34ef5678"}) CREATE (a)-[:NETWORK_REACHABLE {weight: 1.0526, traversability: 0.95, active_alert: false}]->(b);
MATCH (a {id: "i-09ab12cd34ef5678"}), (b {id: "arn:aws:iam::123456789012:role/EC2AppRole"}) CREATE (a)-[:HAS_INSTANCE_PROFILE {weight: 1.0526, traversability: 0.95, active_alert: false}]->(b);
MATCH (a {id: "arn:aws:iam::123456789012:role/EC2AppRole"}), (b {id: "arn:aws:iam::123456789012:role/DevOpsCloudAdminRole"}) CREATE (a)-[:CAN_ASSUME_ROLE {weight: 1.1765, traversability: 0.85, active_alert: false}]->(b);
MATCH (a {id: "arn:aws:iam::123456789012:role/DevOpsCloudAdminRole"}), (b {id: "arn:aws:rds:us-east-1:123456789012:db:production-core-db"}) CREATE (a)-[:ADMINISTERS_DATABASE {weight: 1.0101, traversability: 0.99, active_alert: false}]->(b);
MATCH (a {id: "arn:aws:iam::123456789012:role/DevOpsCloudAdminRole"}), (b {id: "arn:aws:s3:::customer-pii-vault"}) CREATE (a)-[:FULL_S3_ACCESS {weight: 1.0101, traversability: 0.99, active_alert: false}]->(b);
MATCH (a {id: "phished_email"}), (b {id: "COMP-WS-DAVE.CORP.LOCAL"}) CREATE (a)-[:TARGETS_ENDPOINT {weight: 1.25, traversability: 0.8, active_alert: false}]->(b);