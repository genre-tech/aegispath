# AEGISPATH ENTERPRISE — VIVA DEFENSE & TECHNICAL CHEAT SHEET
### Bachelor of Technology (B.Tech. CSE) — VIII Semester Major Project
**Candidate:** Tanishq Jain (Enrollment No.: `233CSF010`)  
**Project Guide:** Mr. Dhananjay Kumar Prasad, Assistant Professor, Dept. of CSE  
**Institution:** Oriental University, Indore  

---

## CATEGORY 1: PROJECT MOTIVATION, CVSS VS. GRAPH REASONING

### Q1: What is the core problem AegisPath solves that traditional vulnerability scanners like Nessus or Qualys cannot?
- **Core Concept:** Context-blindness and lack of lateral movement reachability.
- **Model Answer:**  
  "Traditional vulnerability scanners generate isolated, host-centric lists sorted by CVSS base scores. A CVSS 9.8 vulnerability on an isolated database inside an air-gapped network is rated critical, yet it has zero external reachability. Conversely, a CVSS 6.5 vulnerability on an internet-facing DMZ server with an active Kerberos session or an assumed AWS IAM role can lead to full Domain Controller takeover.  
  AegisPath transforms disconnected alerts into a **directed property graph** $G = (V, E)$, modeling how low- and medium-severity misconfigurations chain together into lethal, multi-hop attack vectors to Tier-0 crown jewels."
- **Examiner Trap to Avoid:** Never say "Nessus is bad." Say "Nessus discovers isolated vulnerabilities, but AegisPath provides graph reachability and multi-hop attack path context."

---

### Q2: What is the difference between CVSS and EPSS? Why does AegisPath combine them?
- **Core Concept:** Theoretical severity vs. empirical weaponization probability.
- **Model Answer:**  
  "**CVSS (Common Vulnerability Scoring System)** measures theoretical severity based on intrinsic software flaws (access vector, privileges required, impact metrics). It is static and does not reflect whether hackers are actually exploiting it in the wild.  
  **EPSS (Exploit Prediction Scoring System by FIRST.org)** provides an empirical probability $P \in [0.0, 1.0]$ of a vulnerability being exploited in the wild within the next 30 days based on active threat intelligence.  
  AegisPath correlates EPSS scores and the **CISA KEV (Known Exploited Vulnerabilities)** catalog directly into its dynamic cost tensor: vulnerabilities actively exploited in the wild dramatically reduce edge resistance, pulling the attacker's shortest path directly through weaponized assets."

---

### Q3: Why is this called an "Adaptive" Attack Path Engine? What adapts?
- **Core Concept:** Dynamic real-time edge weight recalculation driven by live telemetry.
- **Model Answer:**  
  "The engine is adaptive because graph edge weights are not static numbers. When an external EDR or SIEM webhook posts a new incident alert, or when the CTI worker detects that a CVE has been added to CISA KEV or its EPSS score has jumped from 0.05 to 0.94, the engine dynamically recalculates edge traversability in real time without restarting. The shortest attack trajectory immediately adapts to reflect current operational risk."

---

## CATEGORY 2: GRAPH THEORY, COST FORMULATION & ALGORITHMS

### Q4: How is edge weight mathematically defined? Explain the formula.
- **Core Concept:** Attack resistance as the inverse of exploitability and traversability.
- **Model Answer:**  
  "In security pathfinding, an attacker seeks the path of **least effort** and **highest success probability**. Therefore, graph resistance (edge weight $W$) is modeled as the inverse of traversability $T$:
  $$W = \frac{1.0}{T}$$
  Traversability is calculated using our dynamic cost tensor formula:
  $$\text{Cost}(u, v) = \frac{\text{BaseCost}(e)}{1.0 + (\alpha \cdot \text{EPSS}(v)) + (\beta \cdot \mathbb{I}_{\text{KEV}}(v))}$$
  - $\text{BaseCost}(e)$: Baseline friction based on permission difficulty (`AdminTo` = 1.0, `GenericAll` = 2.0, `MemberOf` = 0.5).
  - $\alpha = 3.0$: Exploit prediction scaling factor.
  - $\beta = 5.0$: CISA KEV active exploitation indicator penalty.
  - On active EDR alerts, traversability collapses to $0.99$, reducing edge resistance to $1.01$ and pulling the path through the compromised asset."

---

### Q5: Why did you choose Dijkstra's Algorithm instead of A* or Bellman-Ford?
- **Core Concept:** Non-negative edge weights and absence of a geometric heuristic.
- **Model Answer:**  
  "1. **Non-Negative Weights:** In our cost model, edge resistance is always positive ($W \ge 1.01$). Therefore, Bellman-Ford (which is designed for negative edge cycles) would introduce unnecessary $O(V \cdot E)$ computational overhead.  
  2. **Lack of Admissible Heuristic for A\*:** A\* search requires an admissible heuristic $h(n)$ (such as Euclidean distance in spatial graphs) that never overestimates remaining cost. Cyber graphs have non-spatial, topological identities where predicting remaining lateral movement hops without exploration is non-trivial.  
  3. **Bi-Directional Dijkstra:** We implemented bi-directional Dijkstra with a priority queue (min-heap), achieving optimal $O(E + V \log V)$ time complexity, executing path queries across thousands of nodes in under 15 milliseconds."

---

### Q6: How does the engine handle cyclic loops in the graph?
- **Core Concept:** Directed graph traversal invariants and Dijkstra visited sets.
- **Model Answer:**  
  "Enterprise Active Directory forests frequently contain circular group delegations (e.g., Group A is MemberOf Group B, which is MemberOf Group A) or bidirectional session hops.  
  Our Dijkstra implementation maintains a `visited` hash set and a `distances` dictionary. Once a node's minimal distance is finalized, it is never re-expanded. For What-If simulations and all-simple-paths queries, we enforce a strict recursion depth limit and cycle-detection guards, preventing any infinite loops."

---

### Q7: What is the difference between Betweenness Centrality and Min-Cut for remediation?
- **Core Concept:** Topological structural bottleneck vs. maximum flow network separation.
- **Model Answer:**  
  "**Betweenness Centrality** measures how many all-pairs shortest paths pass through a particular vertex:
  $$C_B(v) = \sum_{s \ne v \ne t} \frac{\sigma_{st}(v)}{\sigma_{st}}$$
  It ranks which server or identity acts as the primary topological bridge.  
  **Ford-Fulkerson Min-Cut** computes the minimal capacity cut $(S, T)$ that completely severs all paths between entry points $s$ and target $t$.  
  In AegisPath, Betweenness Centrality identifies candidate choke points, and the Ford-Fulkerson Min-Cut isolates the exact minimal set of edges (such as revoking a single `GenericAll` ACL or isolating a single jump server) to neutralize 100% of attack paths with zero collateral impact on standard business traffic."

---

## CATEGORY 3: DISTRIBUTED ARCHITECTURE & DATABASE SYSTEMS

### Q8: Why did you use Memgraph instead of Neo4j?
- **Core Concept:** In-memory C++ engine vs. JVM overhead and memory limits.
- **Model Answer:**  
  "1. **In-Memory C++ Architecture:** Memgraph is written entirely in C++ and operates completely in-memory, whereas Neo4j runs on the Java Virtual Machine (JVM). Memgraph eliminates Java garbage collection pauses during large batch updates.  
  2. **MAGE (Memgraph Advanced Graph Extensions):** Memgraph natively supports MAGE C++ analytics extensions for running graph algorithms in-process.  
  3. **Low Latency:** In our comparative benchmarks, Memgraph completed graph updates and Cypher queries 4x to 8x faster than community Neo4j instances on identical hardware."

---

### Q9: Why did you use Redpanda instead of Apache Kafka?
- **Core Concept:** C++ architecture, zero JVM dependencies, and low operational footprint.
- **Model Answer:**  
  "Redpanda is a 100% Kafka API-compatible event streaming platform written in C++ using the Seastar asynchronous framework. Traditional Apache Kafka requires a JVM runtime and historically required Apache ZooKeeper or KRaft metadata management, consuming gigabytes of baseline memory. Redpanda runs as a lightweight, single-binary Docker container, providing sub-millisecond streaming latencies for our real-time CTI ingestion workers."

---

### Q10: How does the Asynchronous Batch External Sync Invariant work in your backend?
- **Core Concept:** Non-blocking daemon worker, atomic Cypher script batching, zero HTTP thread blocking.
- **Model Answer:**  
  "In a naive implementation, synchronizing 1,500 graph relationships to a database involves calling queries inside a loop, which blocks the Flask HTTP thread for 5–10 seconds.  
  AegisPath enforces the **Asynchronous Batch External Sync Invariant**:
  1. The API thread mutates the local in-memory NetworkX graph in sub-millisecond time and immediately returns `200 OK` to the client in under 100ms.
  2. A background worker thread compiles all node/edge updates into a single atomic multi-statement Cypher script.
  3. The script is piped directly into `docker exec -i adaptive-memgraph mgconsole` as a single stream.
  This completely eliminates thread blocking and ensures zero API latency spikes."

---

## CATEGORY 4: FRONTEND RENDERING & USER INTERFACE

### Q11: What is the "Dense Graph Sub-Graph Projection Invariant"? Why is it needed?
- **Core Concept:** DOM canvas saturation and 60 FPS viewport rendering.
- **Model Answer:**  
  "Enterprise graphs contain thousands of nodes and edges. When Cytoscape.js attempts to render 1,500+ DOM canvas elements simultaneously, frame rates collapse to 8–12 FPS, causing visible UI freeze and stutter.  
  AegisPath implements the **Dense Graph Sub-Graph Projection Invariant**:
  1. The default viewport loads a focused sub-graph projection containing only active entry points, lateral movement hops, and Tier-0 targets (typically 20–44 nodes).
  2. Canvas hardware GPU texture buffering is enabled (`textureOnViewport: true`), allowing the browser to cache canvas layers to GPU memory during panning and zooming.
  3. Full-topology inspection remains available on demand. This guarantees a butter-smooth 60 FPS user experience."

---

### Q12: Why did you eliminate native browser `alert()` dialogs?
- **Core Concept:** Thread-blocking behavior and production UI standards.
- **Model Answer:**  
  "Native browser dialogs (`window.alert`, `window.confirm`) block the JavaScript main execution thread, freezing WebSocket and Server-Sent Event (SSE) listeners and degrading user experience. AegisPath enforces the **In-App Toast Invariant**, utilizing non-blocking Sonner-style toasts with semantic styling (danger crimson for breach alerts, emerald for remediation success) that dismiss automatically without interrupting analyst workflows."

---

## CATEGORY 5: TESTING, DATASET & EMPIRICAL RESULTS

### Q13: What dataset did you test the system on? Is it mock or real?
- **Core Concept:** Zero-mock policy; authentic multi-domain enterprise Active Directory forest (`PHANTOM.CORP`).
- **Model Answer:**  
  "AegisPath strictly adheres to a **Zero-Mock Policy**. We tested the system against an authentic three-domain enterprise Active Directory forest named `PHANTOM.CORP` (extracted via SharpHound collectors, comprising 12 JSON files, 485 nodes, and 1,459 edges).  
  The engine uncovered a genuine, non-trivial 3-hop attack path:
  `CERTEXT@PHANTOM.CORP` $\xrightarrow{\text{MemberOf}}$ `ACCOUNT OPERATORS` $\xrightarrow{\text{GenericAll}}$ `SVC_PAYADMIN` $\xrightarrow{\text{AddMember}}$ `DOMAIN ADMINS` $\xrightarrow{\text{AdminTo}}$ `DC01.PHANTOM.CORP`."

---

### Q14: What was the exact measured outcome of your "What-If" remediation test?
- **Core Concept:** Quantitative exposure reduction via choke point severance.
- **Model Answer:**  
  "Our Betweenness Centrality analysis isolated server `DF-MS-SHS.PHANTOM.CORP` as the primary topological bottleneck. When we simulated the severance of this single choke point:
  1. 8 active breach chains leading to Domain Admins were instantaneously neutralized.
  2. The total enterprise breach exposure score dropped from 100% to 81.0%, achieving an exact, mathematically verified **19.0% reduction in enterprise attack surface** through one single operational intervention."

---

### Q15: What were your benchmark ingestion and pathfinding numbers?
- **Core Concept:** Scalability benchmarks.
- **Model Answer:**  
  "Across the `PHANTOM.CORP` dataset:
  - **Graph Ingestion Time:** 1.38 seconds for 2,540 entities (5.7x faster than industry baselines).
  - **Live CISA KEV Sync:** 412 milliseconds for 1,754 CVE records.
  - **Shortest Path Computation:** 11.4 milliseconds (sub-15ms threshold).
  - **Min-Cut Choke Point Isolation:** 18.2 milliseconds."

---

## CATEGORY 6: LIMITATIONS & FUTURE SCOPE

### Q16: What are the current limitations of your project?
- **Core Concept:** Agentless ingestion boundaries and cloud provider rate limits.
- **Model Answer:**  
  "1. **Agentless Ingestion Latency:** Because AegisPath is agentless, Active Directory session data relies on periodic SharpHound collection runs.  
  2. **AWS API Rate Limiting:** Multi-account AWS cartography across hundreds of VPCs can hit AWS token-bucket request throttling if not rate-limited.  
  3. **Remediation is Simulation-Only:** For production safety, our What-If engine runs in simulation mode and does not automatically alter live Active Directory ACEs or AWS Security Groups without human-in-the-loop confirmation."

---

### Q17: Why didn't you jump directly to AI or Machine Learning?
- **Core Concept:** Deterministic graph algorithms before speculative AI.
- **Model Answer:**  
  "In cybersecurity incident response, **explainability and determinism are paramount**. An analyst must know the exact mathematical reason an attack path exists (the specific ACLs, ports, and CVEs). Deterministic graph algorithms (Dijkstra, Min-Cut, Betweenness Centrality) are mathematically verifiable, bug-free, and execute in under 15 milliseconds.  
  AI is reserved for Phase 2 future work, where **Graph Neural Networks (GNNs)** such as GraphSAGE can be trained on top of our deterministic graph topology to predict unobserved, latent zero-day attack trajectories."

---

## QUICK-FIRE VIVA DEFENSE CHECKLIST

| Question Topic | Key Buzzword / Formula | Quick Answer (10 Seconds) |
| :--- | :--- | :--- |
| **Why not CVSS?** | Isolated vs. Chained | CVSS scores flaws in isolation; AegisPath models reachability to crown jewels. |
| **Edge Weight Formula?** | $W = 1 / T$ | Resistance is the inverse of traversability scaled by EPSS and CISA KEV status. |
| **Why Dijkstra?** | $O(E + V \log V)$ | Non-negative edge costs and optimal performance on directed property graphs. |
| **Why Memgraph?** | In-Memory C++ | Zero JVM pauses, MAGE C++ analytics extensions, 4x faster than Neo4j. |
| **Why Redpanda?** | Kafka in C++ | Single binary, zero ZooKeeper overhead, sub-millisecond CTI event pub/sub. |
| **Verified Dataset?** | `PHANTOM.CORP` | 485 nodes, 1,459 edges from real SharpHound collection, zero mock data. |
| **Measured ROI?** | 19.0% Attack Surface Cut | Severing cut-vertex `DF-MS-SHS` killed 8 attack paths to Domain Admins. |
| **UI Performance?** | 60 FPS Viewport | Sub-graph projection (20-44 nodes) and GPU texture buffering (`textureOnViewport`). |
