// =========================================================================
// Useful Cypher Queries for Memgraph Lab (http://localhost:3000)
// =========================================================================

// 1. View Entire Enterprise Attack Graph
MATCH (n)-[r]->(m)
RETURN n, r, m;

// 2. Find All Attack Paths from Internet to Crown Jewels (up to 6 hops)
MATCH path = (entry:EntryPoint)-[*..6]->(target:CrownJewel)
RETURN path;

// 3. Shortest / Least-Friction Path to Crown Jewels
MATCH path = shortestPath((entry:EntryPoint)-[*..6]->(target:CrownJewel))
RETURN path;

// 4. Find Attack Paths passing through Active EDR Telemetry Alerts
MATCH path = (entry:EntryPoint)-[r*..6]->(target:CrownJewel)
WHERE ANY(rel in r WHERE rel.active_alert = true)
RETURN path;

// 5. Calculate Choke Points using Memgraph MAGE Betweenness Centrality
CALL betweenness_centrality.get()
YIELD node, betweenness_centrality
WHERE NOT "CrownJewel" IN labels(node) AND NOT "EntryPoint" IN labels(node)
RETURN node.name AS Asset, node.id AS NodeID, betweenness_centrality AS ChokePointScore
ORDER BY ChokePointScore DESC
LIMIT 5;

// 6. Simulate Remediation: Verify remaining paths if a Bastion or Role is severed
MATCH path = (entry:EntryPoint)-[*..6]->(target:CrownJewel)
WHERE NONE(n IN nodes(path) WHERE n.id = "iam-role-devops-admin")
RETURN path;
