# 📐 AegisPath Enterprise: System Architecture & Diagram Suite

A comprehensive architectural and engineering diagram suite for **AegisPath Enterprise** (Adaptive Attack Path Management & Multi-Cloud Cyber Threat Intelligence Engine).

---

## Table of Contents
1. [End-to-End System Architecture](#1-end-to-end-system-architecture)
2. [Multi-Domain Ingestion & Normalization Pipeline](#2-multi-domain-ingestion--normalization-pipeline)
3. [Mathematical Graph Reasoning & Pathfinding Model](#3-mathematical-graph-reasoning--pathfinding-model)
4. [Asynchronous Batch Database Synchronization Architecture](#4-asynchronous-batch-database-synchronization-architecture)
5. [Real-Time Telemetry & EDR Alert Recalibration Flow](#5-real-time-telemetry--edr-alert-recalibration-flow)
6. [What-If Remediation Simulation Engine](#6-what-if-remediation-simulation-engine)
7. [Sub-Graph Projection & Hardware-Accelerated Canvas Pipeline](#7-sub-graph-projection--hardware-accelerated-canvas-pipeline)
8. [Database & Entity Relationship Schema (ERD)](#8-database--entity-relationship-schema-erd)
9. [Component Class & Module Hierarchy](#9-component-class--module-hierarchy)

---

## 1. End-to-End System Architecture

High-level architecture showing ingestion boundaries, live threat intelligence feeds, graph computation, async persistence, and real-time streaming presentation.

```mermaid
flowchart TD
    subgraph INGESTION["1. Multi-Domain Data Ingestion"]
        AWS["AWS Cloud Cartography (Boto3 API)"]
        BH["BloodHound CE Active Directory (SharpHound JSON)"]
        TRIVY["Trivy / Grype Container & OS Scans"]
    end

    subgraph CTI_LAYER["2. Live Threat Intelligence Layer"]
        CISA["CISA KEV Catalog (1,754 Known Exploited Vulnerabilities)"]
        EPSS["FIRST.org EPSS API (Empirical Exploit Probabilities)"]
        CACHE[("Local CTI Disk Cache (cti_cache.json)")]
        CLIENT["CTI Client (core/cti_client.py)"]
        
        CISA --> CLIENT
        EPSS --> CLIENT
        CLIENT <--> CACHE
    end

    subgraph CORE_ENGINE["3. In-Memory Graph Reasoning Engine"]
        NX["Adaptive Attack Path Engine (NetworkX DiGraph)"]
        DIJKSTRA["Dynamic Dijkstra Pathfinding (W = 1 / Traversability)"]
        CHOKE["Betweenness Centrality & Min-Cut Choke Discovery"]
        WHATIF["What-If Remediation Simulator"]
        
        NX --> DIJKSTRA
        NX --> CHOKE
        NX --> WHATIF
    end

    subgraph PERSISTENCE["4. Asynchronous Database & Streaming Layer"]
        WORKER["Background Daemon Worker (Thread Pool)"]
        BATCH["Atomic Cypher Batch Compiler"]
        MAGE[("Memgraph MAGE (In-Memory C++ Graph DB)")]
        REDPANDA[("Redpanda (Kafka-Compatible Streaming Broker)")]
        LAB["Memgraph Lab Visual Explorer (Port 3000)"]
        CONSOLE["Redpanda Console (Port 8080)"]
        
        WORKER --> BATCH
        BATCH -->|"Non-Blocking Pipe"| MAGE
        MAGE <--> LAB
        WORKER --> REDPANDA
        REDPANDA <--> CONSOLE
    end

    subgraph API_STREAM["5. Presentation & Real-Time API"]
        FLASK["Flask REST API Server (server.py:8081)"]
        SSE["Server-Sent Events (SSE Stream)"]
        SUBGRAPH["Sub-Graph Projection Filter (mode=paths)"]
        
        FLASK --> SUBGRAPH
        FLASK --> SSE
    end

    subgraph FRONTEND["6. Hardware-Accelerated Web Console"]
        CY["Cytoscape.js Canvas (GPU Texture Buffering)"]
        HUD["Telemetry HUD & Metrics Cards"]
        INSPECTOR["Entity Inspector & EPSS Gauge"]
        TOAST["Sonner-Style In-App Toast System"]
        MODAL["Ingestion Hub Modal (AWS / AD / CVE)"]
    end

    AWS -->|"Read-Only API"| FLASK
    BH -->|"JSON / Folder"| FLASK
    TRIVY -->|"Scan Reports"| FLASK
    
    FLASK --> NX
    CLIENT -->|"Vulnerability Enrichment"| NX
    NX -->|"Graph Mutations"| WORKER
    
    SUBGRAPH -->|"Filtered Payload (20-44 Nodes)"| CY
    SSE -->|"Real-Time Push"| FRONTEND
```

---

## 2. Multi-Domain Ingestion & Normalization Pipeline

Detailed data normalization workflow across AWS Boto3 cloud assets, BloodHound Active Directory graphs, and container vulnerability scans.

```mermaid
flowchart LR
    subgraph SOURCES["Data Sources"]
        AWS_SRC["AWS Boto3 API"]
        BH_SRC["Active Directory Exports"]
        CVE_SRC["CVE Ingestion / Scans"]
    end

    subgraph PARSERS["Defensive Normalization Parsers"]
        P_AWS["AWS Cartographer (aws_ingestor.py)"]
        P_BH["BloodHound Ingestor (bloodhound_ingestor.py)"]
        P_TRIVY["Trivy Ingestor (trivy_ingestor.py)"]
    end

    subgraph UNPACKING["Polymorphic Unpacking & Validation"]
        U_AWS["Strip AZ Suffixes (ap-southeast-2b -> ap-southeast-2)<br/>Extract EC2, SG, IAM, S3, RDS"]
        U_BH["Defensive Session Handling (dict vs list)<br/>Resolve MemberOf, GenericAll, WriteDacl, DCSync"]
        U_CVE["Query FIRST.org EPSS & CISA KEV<br/>Calculate Dynamic Traversability"]
    end

    subgraph GRAPH_INSERT["Graph Construction"]
        TARGET_GRAPH["In-Memory Directed Graph (NetworkX)"]
    end

    AWS_SRC --> P_AWS --> U_AWS --> TARGET_GRAPH
    BH_SRC --> P_BH --> U_BH --> TARGET_GRAPH
    CVE_SRC --> P_TRIVY --> U_CVE --> TARGET_GRAPH
```

---

## 3. Mathematical Graph Reasoning & Pathfinding Model

The dynamic inverse exploitability model where real threats reduce edge resistance and pull Dijkstra's shortest path toward compromised assets.

```mermaid
flowchart TD
    subgraph INPUTS["Telemetry & Threat Inputs"]
        BASE["Base Relationship Traversability (0.05 to 0.95)"]
        CVSS["CVSS Base Score (0.0 - 10.0)"]
        EPSS["FIRST.org EPSS Exploit Probability (0.0 - 1.0)"]
        KEV{"In CISA KEV Catalog?"}
        ALERT{"Active EDR / Telemetry Alert?"}
    end

    subgraph FORMULA["Traversability Calculation"]
        T_CALC["Traversability(u, v) = Base * EPSS * KEV_Multiplier"]
        T_ALERT["Alert Override: Traversability -> 0.99 (Resistance Collapses)"]
    end

    subgraph WEIGHT["Dynamic Edge Weight (Resistance)"]
        W_CALC["Weight(u, v) = 1.0 / Traversability(u, v)"]
    end

    subgraph ALGORITHMS["Graph Analytics"]
        DIJKSTRA["Dijkstra Shortest Path:<br/>Minimizes Sum of Weights W(u, v) from Entry Points to Tier-0"]
        PROB["Cumulative Breach Probability:<br/>P_breach = Product of Traversability(i)"]
        BETWEEN["Betweenness Centrality (Choke Point Min-Cut):<br/>C_B(v) = Sum(sigma_st(v) / sigma_st)"]
    end

    BASE --> T_CALC
    CVSS --> T_CALC
    EPSS --> T_CALC
    KEV -->|Yes: 1.5x Boost| T_CALC
    KEV -->|No: 1.0x| T_CALC
    
    ALERT -->|Yes| T_ALERT --> W_CALC
    ALERT -->|No| T_CALC --> W_CALC
    
    W_CALC --> DIJKSTRA
    DIJKSTRA --> PROB
    DIJKSTRA --> BETWEEN
```

---

## 4. Asynchronous Batch Database Synchronization Architecture

Sequence diagram showing how in-memory mutations are batched into atomic Cypher streams and decoupled to background daemon worker threads to keep user-facing APIs responsive (<100ms).

```mermaid
sequenceDiagram
    autonumber
    actor Operator as Security Operator / API
    participant Flask as Flask REST Server (server.py)
    participant Engine as NetworkX Graph Engine
    participant Worker as Background Daemon Thread
    participant Docker as Docker Container (adaptive-memgraph)
    participant Memgraph as Memgraph MAGE (C++ Engine)

    Operator->>Flask: POST /api/ingest/bloodhound/directory
    Note over Flask: Main HTTP Request Thread
    Flask->>Engine: Ingest Active Directory & Map Nodes/Edges
    Engine-->>Flask: Graph Updated in Memory (510 Nodes, 3,550 Edges)
    
    Note over Flask,Worker: Asynchronous Batch Invariant: Decouple Persistence
    Flask->>Worker: Dispatch _do_sync(nodes, edges) in Daemon Thread
    Flask-->>Operator: 200 OK (sub-second response: ~95ms)
    
    Note over Worker: Background Daemon Worker Thread
    Worker->>Worker: Compile all Cypher statements into single script
    Worker->>Docker: Execute single `docker exec -i adaptive-memgraph mgconsole`
    Docker->>Memgraph: Pipe atomic Cypher stream via Bolt protocol
    Memgraph-->>Docker: 0 errors (Batch Execution Complete)
    Docker-->>Worker: Subprocess exited with code 0
    Note over Worker: In-Memory DB state mirrors NetworkX state
```

---

## 5. Real-Time Telemetry & EDR Alert Recalibration Flow

Sequence diagram illustrating real-world incident response: when an EDR alert fires, edge friction collapses, the critical path reroutes instantly, and connected browsers update live via Server-Sent Events (SSE).

```mermaid
sequenceDiagram
    autonumber
    actor EDR as EDR / SIEM Webhook (CrowdStrike / Defender)
    participant Server as AegisPath Server (:8081)
    participant Engine as Adaptive Graph Engine
    participant SSE as SSE Event Broadcaster
    participant Browser as Web Browser (Cytoscape.js)

    EDR->>Server: POST /api/telemetry/alert (node_id: "DF-MS-SHS", type: "Privilege Escalation")
    Server->>Engine: trigger_alert(node_id, alert_type)
    Note over Engine: Collapses incoming/outgoing edge weights: W(u, v) -> 1.01
    Engine->>Engine: Recalculate Dijkstra Shortest Paths
    Note over Engine: Critical path re-routed through breached node!
    Engine-->>Server: Top Path Updated (Cumulative Prob: 98.4%)
    Server->>SSE: Broadcast TELEMETRY_ALERT event
    SSE-->>Browser: Event Received via EventSource stream
    Note over Browser: Browser UI Reacts Instantly:
    Browser->>Browser: Update Telemetry HUD metrics & active alert pill
    Browser->>Browser: Apply .alert-edge style (dashed amber glow)
    Browser->>Browser: Trigger Sonner-style in-app toast notification
    Browser->>Browser: Re-highlight critical breach path in Crimson
```

---

## 6. "What-If" Remediation Simulation Engine

State machine diagram showing the non-destructive simulation lifecycle when evaluating choke point remediation.

```mermaid
stateDiagram-v2
    [*] --> OperationalBaseline: Platform Initialized
    
    OperationalBaseline --> ChokePointSelected: Operator Selects Cut-Vertex Asset
    
    state "Remediation Simulation Lifecycle" as SimState {
        ChokePointSelected --> InMemoryClone: POST /api/simulate/sever
        InMemoryClone --> TopologicalCut: Remove Node & Adjacent Vectors
        TopologicalCut --> DijkstraReEvaluation: Recalculate Paths to Crown Jewels
        DijkstraReEvaluation --> MetricCalculation: Compute Paths Eliminated & Risk Reduction %
    }
    
    MetricCalculation --> CanvasDeltaView: Display Severed Elements on Canvas
    CanvasDeltaView --> ToastFeedback: Display Risk Reduction Toast (e.g. 19.0% Reduction)
    CanvasDeltaView --> OperationalBaseline: Dismiss Simulation / Restore Baseline
```

---

## 7. Sub-Graph Projection & Hardware-Accelerated Canvas Pipeline

Pipeline diagram showing how dense topologies (1,500+ edges) are filtered down to the active attack sub-graph (20–44 nodes) and rendered at 60 FPS using GPU texture buffering.

```mermaid
flowchart LR
    subgraph DENSE["Full Enterprise Topology"]
        ALL["Complete Graph<br/>(485 Nodes, 1,459 Edges)"]
    end

    subgraph PROJECTION["Sub-Graph Projection (server.py)"]
        EXTRACT["Extract Active Paths:<br/>1. Find all paths to Crown Jewels<br/>2. Collect participating nodes & edges<br/>3. Include Crown Jewels & Choke Points"]
        FILTERED["Projected Subgraph<br/>(20-44 Nodes, 36-82 Edges)"]
    end

    subgraph RENDERING["Cytoscape.js Hardware Canvas"]
        GPU["textureOnViewport: true<br/>(GPU texture buffer caching during drag)"]
        EDGES["hideEdgesOnViewport: true<br/>(Skip edge drawing during pan/zoom)"]
        LABELS["Deferred Edge Labeling<br/>(Render labels only on hover / selection)"]
        CANVAS["60 FPS Smooth Canvas"]
    end

    ALL --> EXTRACT --> FILTERED
    FILTERED --> GPU --> CANVAS
    FILTERED --> EDGES --> CANVAS
    FILTERED --> LABELS --> CANVAS
```

---

## 8. Database & Entity Relationship Schema (ERD)

The graph data model detailing node labels, attributes, and relationship vectors.

```mermaid
erDiagram
    Perimeter ||--o{ Host : EXPOSES
    Host ||--o{ SecurityGroup : PROTECTED_BY
    Host ||--o{ IAMRole : ASSUMES_ROLE
    Host ||--o{ Vulnerability : HAS_VULNERABILITY
    IAMRole ||--o{ CrownJewel : HAS_ACCESS
    
    Identity ||--o{ Identity : MEMBER_OF
    Identity ||--o{ Identity : GENERIC_ALL
    Identity ||--o{ Identity : WRITE_DACL
    Identity ||--o{ Host : ADMIN_TO
    Identity ||--o{ Host : HAS_SESSION
    Identity ||--o{ CrownJewel : DCSYNC
    
    Perimeter {
        string id PK "internet"
        string label "Public Internet"
        boolean is_entry_point true
    }

    Host {
        string id PK "Instance ID / Hostname"
        string label "Display Name"
        string type "Host"
        string ip_address "IPv4 Address"
        string os "Operating System"
        string domain "Domain Name"
    }

    SecurityGroup {
        string id PK "sg-xxxx"
        string label "SG Name"
        string inbound_rules "Port Ranges (e.g. 22, 80, 443, 3389)"
    }

    IAMRole {
        string id PK "Role ARN"
        string label "Role Name"
        string policy_type "Admin / ReadOnly"
    }

    Identity {
        string id PK "Object SID (S-1-5-...)"
        string label "Account Name"
        string type "User / Group / Computer"
        boolean is_admin "High Privilege Flag"
    }

    Vulnerability {
        string id PK "CVE-YYYY-XXXXX"
        float cvss "CVSS Base Score"
        float epss "EPSS Probability"
        boolean in_cisa_kev "CISA KEV Catalog Presence"
    }

    CrownJewel {
        string id PK "Target Asset ID"
        string label "Domain Controller / DB"
        string tier "Tier-0"
        boolean is_crown_jewel true
    }
```

---

## 9. Component Class & Module Hierarchy

Object-oriented component hierarchy implementing clean architecture across the engine, CTI client, ingestors, and REST API.

```mermaid
classDiagram
    class AdaptiveAttackPathEngine {
        -nx.DiGraph graph
        -list crown_jewels
        -list entry_points
        +add_node(node_id, label, type, attributes)
        +add_edge(source, target, relationship, traversability)
        +find_shortest_attack_path(source, target)
        +find_all_attack_paths()
        +find_choke_points()
        +simulate_remediation(target_id)
        +trigger_alert(node_id, alert_type)
        +reset_baseline()
        +to_dict()
    }

    class CTIClient {
        -dict kev_catalog
        -dict epss_cache
        +fetch_cisa_kev()
        +query_epss(cve_id)
        +enrich_vulnerability(cve_id, cvss)
    }

    class AWSCartographer {
        -boto3.Session session
        -string region
        +discover_ec2()
        +discover_security_groups()
        +discover_iam_roles()
        +discover_s3_buckets()
        +discover_rds()
    }

    class BloodHoundIngestor {
        -string folder_path
        +parse_users()
        +parse_groups()
        +parse_computers()
        +parse_domains()
        +extract_aces()
        +extract_sessions()
    }

    class TrivyIngestor {
        +parse_report(json_data)
        +extract_cves()
    }

    class ServerApp {
        +GET /api/graph
        +GET /api/paths
        +GET /api/chokepoints
        +POST /api/node/toggle-crown-jewel
        +POST /api/simulate/sever
        +POST /api/ingest/aws/live
        +POST /api/ingest/bloodhound/directory
        +POST /api/ingest/cve
        +GET /api/events
    }

    ServerApp --> AdaptiveAttackPathEngine : Drives
    ServerApp --> CTIClient : Enriches via
    ServerApp --> AWSCartographer : Invokes
    ServerApp --> BloodHoundIngestor : Invokes
    ServerApp --> TrivyIngestor : Invokes
```
