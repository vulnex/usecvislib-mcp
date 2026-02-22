# USecVisLib Security Visualization Skill

Expert guidance for generating security visualizations via the usecvislib MCP server.

---

## 1. Visualization Selection Guide

Match the security question to the right visualization type and MCP tools.

| Security Question | Visualization Type | Primary Tool | Analysis Tools |
|---|---|---|---|
| What are the attack paths to a target? | Attack Tree | `generate_attack_tree` | `validate_attack_tree`, `get_attack_tree_stats`, `build_attack_tree_from_spec` |
| How do attackers traverse the network? | Attack Graph | `generate_attack_graph` | `find_attack_paths`, `analyze_critical_nodes`, `find_chokepoints`, `analyze_centrality` |
| What threats exist in data flows? | Threat Model (DFD) | `generate_threat_model` | `analyze_stride_threats`, `get_threat_model_stats` |
| What does the binary look like inside? | Binary Analysis | `analyze_binary_entropy` | `analyze_binary_distribution`, `analyze_binary_heatmap`, `analyze_binary_all`, `get_binary_stats` |
| What's the cloud architecture? | Cloud Diagram | `generate_cloud_diagram` | `search_cloud_icons`, `list_cloud_providers`, `list_cloud_icons` |
| Where are trust boundary violations? | Privilege Gradient | `generate_privilege_gradient` | `detect_privilege_inversions`, `analyze_zone_influence` |
| What's the system architecture? | Component Diagram | `generate_component_diagram` | `validate_component_diagram`, `get_component_diagram_stats` |
| How do modules depend on each other? | Dependency Graph | `generate_dependency_graph` | `validate_dependency_graph`, `get_dependency_graph_stats` |
| Custom topology or flowchart? | Custom Diagram | `generate_custom_diagram` | `list_shapes`, `validate_custom_diagram` |

**Utility tools** available across all types: `convert_to_mermaid`, `calculate_cvss_score`, `detect_config_type`, `export_data`, `generate_report`, `batch_process`, `compare_visualizations`.

---

## 2. Configuration Best Practices

### Attack Trees

Structure: hierarchical goal decomposition with AND/OR gates.

- **Root**: Single top-level attacker goal
- **Sub-goals**: 3-5 levels of decomposition (depth 3-5 optimal)
- **Gates**: Use AND for multi-step attacks, OR for alternatives
- **Leaves**: Attach CVSS scores for quantitative risk
- **Config keys**: `tree` (name, root, params), `nodes` (styling), `edges` (connections with labels)

```json
{
  "tree": {"name": "...", "root": "Root Goal", "params": {"rankdir": "TB"}},
  "nodes": {"Root Goal": {"shape": "oval", "fillcolor": "#e74c3c"}},
  "edges": {"Root Goal": [{"to": "Sub Goal", "label": "OR"}]}
}
```

### Attack Graphs

Structure: network topology with hosts, vulnerabilities, exploits.

- **Hosts**: Include IP addresses and zone assignments (external/dmz/internal)
- **Vulnerabilities**: Link to specific hosts, include CVE IDs and CVSS scores
- **Exploits**: Define preconditions (vulnerabilities) and postconditions (privileges)
- **Services**: Map to hosts with port/protocol
- **Config keys**: `graph`, `hosts`, `vulnerabilities`, `privileges`, `services`, `exploits`, `network_edges`

```json
{
  "graph": {"name": "..."},
  "hosts": [{"id": "web", "label": "Web Server", "ip": "10.0.1.10", "zone": "dmz"}],
  "vulnerabilities": [{"id": "v1", "label": "RCE", "cvss": 9.8, "affected_host": "web"}],
  "exploits": [{"id": "e1", "preconditions": ["v1"], "postconditions": ["priv_root"]}]
}
```

### Threat Models

Structure: Data Flow Diagram with STRIDE analysis.

- **Format**: Dict-of-dicts (not lists) for processes, datastores, externals, dataflows
- **Processes**: Include `sanitizesInput`, `hasAccessControl` boolean properties
- **Datastores**: Include `isEncrypted`, `storesPII` properties
- **Dataflows**: Must reference valid `from`/`to` element IDs, include `isEncrypted`
- **Boundaries**: Group elements into trust zones
- **Config keys**: `model`, `processes`, `datastores`, `externals`, `dataflows`, `boundaries`

```json
{
  "model": {"name": "...", "description": "..."},
  "processes": {"web_app": {"label": "Web App", "sanitizesInput": true}},
  "datastores": {"db": {"label": "Database", "isEncrypted": true}},
  "externals": {"user": {"label": "User", "isTrusted": true}},
  "dataflows": {"f1": {"from": "user", "to": "web_app", "isEncrypted": true}}
}
```

### Binary Analysis

Pipeline: entropy -> distribution -> heatmap for triage.

- **Input**: Path to binary file on disk
- **Entropy**: Reveals packed/encrypted sections (high entropy regions)
- **Distribution**: Shows byte frequency patterns
- **Heatmap**: 2D visualization of byte patterns across file offset
- **All-in-one**: `analyze_binary_all` generates all three plus stats

### Cloud Diagrams

Structure: nodes with provider icons, edges, optional clusters.

- **Providers**: AWS, GCP, Azure, etc. (use `list_cloud_providers` to discover)
- **Icons**: Provider-specific icon paths (use `search_cloud_icons` or `list_cloud_icons`)
- **Clusters**: Group nodes by VPC, subnet, region
- **Direction**: TB (top-bottom), LR (left-right)
- **Config keys**: `diagram`, `nodes` (with `icon` field), `edges`, `clusters`

```json
{
  "diagram": {"title": "...", "direction": "TB"},
  "nodes": [{"id": "lb", "icon": "aws.network.ELB", "label": "Load Balancer"}],
  "edges": [{"from": "lb", "to": "web", "label": "HTTPS"}]
}
```

### Privilege Gradient

Structure: trust zones with components and cross-zone influences.

- **Zones**: Define trust levels (0 = untrusted, higher = more trusted)
- **Components**: Assign each to a zone
- **Influences**: Cross-zone data flows (from/to component IDs)
- **Inversions**: `detect_privilege_inversions` finds flows from higher to lower trust
- **Config keys**: `gradient`, `zones`, `components`, `influences`

```json
{
  "gradient": {"name": "...", "description": "..."},
  "zones": {"external": {"label": "External", "level": 0}},
  "components": {"cdn": {"label": "CDN", "zone": "external"}},
  "influences": [{"from": "cdn", "to": "web_app", "label": "HTTPS"}]
}
```

### Architecture Diagrams

**Component Diagrams**: layers with ordered components and connections.

- **Config keys**: `diagram`, `layers` (with `order` and `color`), `components` (with `layer`), `connections`

**Dependency Graphs**: modules with dependency relationships.

- **Config keys**: `graph`, `modules` (with `sloc`, `language`), `dependencies` (with `type`)

---

## 3. Style Recommendations

Choose styles based on the target audience:

| Audience | Recommended Styles | Rationale |
|---|---|---|
| Executive / Board | `*_corporate` | Clean, professional, muted colors |
| Security Team | `*_default`, `*_dark` | Standard technical detail, dark theme for SOC screens |
| Pentest Report | `*_neon` | High contrast, emphasizes severity |
| Academic / Research | `*_blueprint` | Technical blueprint aesthetic |

Style ID format: `{module}_{style}` (e.g., `at_corporate`, `ag_dark`, `tm_neon`).

To discover all available styles, use the `usecvislib://styles/list` resource or `usecvislib://styles/{visualization_type}` for a specific type.

---

## 4. Workflow Orchestration

### Workflow 1: Comprehensive Security Assessment

Full threat analysis pipeline from DFD to actionable report.

1. **Threat Model DFD**: `generate_threat_model` with all processes, datastores, externals, dataflows, boundaries
2. **STRIDE Analysis**: `analyze_stride_threats` to identify threats per element
3. **Attack Trees**: `generate_attack_tree` for each high-risk STRIDE threat — decompose into sub-goals
4. **Attack Graph**: `generate_attack_graph` mapping exploits across the network
5. **Chokepoint Analysis**: `find_chokepoints` + `analyze_centrality` to prioritize defensive controls
6. **Report**: `generate_report` on the attack graph for a multi-format deliverable

### Workflow 2: Binary Triage Pipeline

Rapid binary analysis for malware/firmware review.

1. **Stats**: `get_binary_stats` for file size, type, section overview
2. **Entropy**: `analyze_binary_entropy` to identify packed/encrypted regions
3. **Distribution**: `analyze_binary_distribution` for byte frequency anomalies
4. **Heatmap**: `analyze_binary_heatmap` for spatial byte pattern visualization
5. Or simply: `analyze_binary_all` for all four in one call

### Workflow 3: Cloud Security Review

Architecture documentation with security analysis.

1. **Provider Discovery**: `list_cloud_providers` + `list_cloud_icons` to find correct icon paths
2. **Cloud Diagram**: `generate_cloud_diagram` with proper provider icons, VPC clusters
3. **Privilege Gradient**: Map cloud resources to trust zones, `generate_privilege_gradient`
4. **Inversion Detection**: `detect_privilege_inversions` to find misconfigured trust boundaries
5. **Threat Model**: `generate_threat_model` for the cloud data flows

### Workflow 4: Attack Surface Mapping

Network-centric attack surface analysis.

1. **Attack Graph**: `generate_attack_graph` with full host/vulnerability/exploit data
2. **Chokepoints**: `find_chokepoints` — critical defensive positions
3. **Centrality**: `analyze_centrality` — infrastructure bridge nodes
4. **Privilege Gradient**: Map network zones to trust levels, `generate_privilege_gradient`
5. **Inversions**: `detect_privilege_inversions` for trust boundary violations
6. **Comparison**: `compare_visualizations` to diff against previous assessment

---

## 5. Export and Output Guidance

### Data Export (`export_data`)

| Format | Best For | Notes |
|---|---|---|
| `json` | API integration, archives | Returns string directly |
| `yaml` | Human-readable configs | Returns string directly |
| `csv` | Spreadsheets, tabular analysis | Writes file, returns path + row count |
| `md` | Documentation, reports | Returns markdown table string |

### Report Generation (`generate_report`)

- Accepts any Pattern A visualization type (`attack_tree`, `attack_graph`, `threat_model`, `privilege_gradient`, `component_diagram`, `dependency_graph`)
- Produces reports in multiple formats simultaneously
- Default formats: `["json", "csv", "md"]`
- Returns a directory with all generated files

### Batch Processing (`batch_process`)

- Process multiple configs of the same type in parallel
- Set `max_workers` based on system resources (default: 4)
- Returns summary with success/failure counts per file
- Supported types: `attack_tree`, `attack_graph`, `threat_model`, `privilege_gradient`, `component_diagram`, `dependency_graph`

### Mermaid Export (`convert_to_mermaid`)

- Converts attack trees, attack graphs, and threat models to Mermaid diagram syntax
- Useful for embedding in Markdown documentation
- Auto-detects visualization type from config structure

---

## 6. Auto-Detection Guidance

### Config Type Detection (`detect_config_type`)

Pass any config dict to automatically identify the visualization type. Confidence levels:

- **high**: Unique structural markers found (e.g., `tree.root` for attack trees)
- **medium**: Probable match based on field patterns
- **low**: Ambiguous, may need manual specification

### CVSS Version Detection (`calculate_cvss_score`)

Automatically detects CVSS version from vector prefix:
- `CVSS:3.0/...` → CVSS 3.0
- `CVSS:3.1/...` → CVSS 3.1
- `CVSS:4.0/...` → CVSS 4.0

Returns score, severity rating (None/Low/Medium/High/Critical), and parsed vector components.

### Style Fallback

If a specified style ID is not found, the library falls back to the module's default style. Use `usecvislib://styles/{type}` resource to list valid style IDs before generation.
