"""MCP prompt templates for guiding AI assistants in creating visualizations."""

from ..server import mcp


@mcp.prompt()
def create_attack_tree() -> str:
    """Step-by-step guide for creating an attack tree visualization."""
    return """# Creating an Attack Tree with USecVisLib

## Overview
Attack trees model hierarchical attack scenarios. The root node represents the
attacker's goal, and child nodes represent sub-goals or attack steps.

## Step-by-Step Process

1. **Identify the Goal**: Define the root node — what the attacker wants to achieve.
2. **Decompose into Sub-Goals**: Break down into intermediate steps using AND/OR logic.
3. **Add Leaf Nodes**: Specific attack techniques at the leaves.
4. **Assign CVSS Scores**: Add risk scores to leaf nodes for severity coloring.
5. **Choose a Style**: Pick a style preset (at_default, at_corporate, at_neon, etc.).
6. **Generate**: Use the `generate_attack_tree` tool with your config.

## Config Structure

```json
{
  "tree": {
    "name": "Web Application Attack",
    "root": "Compromise Web App",
    "description": "Attack tree for web application threats",
    "params": {"rankdir": "TB"}
  },
  "nodes": {
    "Compromise Web App": {"style": "filled", "fillcolor": "#e74c3c", "shape": "oval"},
    "SQL Injection": {"style": "filled", "cvss": 9.8},
    "XSS Attack": {"style": "filled", "cvss": 6.1},
    "Auth Bypass": {"style": "filled", "fillcolor": "#9b59b6"}
  },
  "edges": {
    "Compromise Web App": [
      {"to": "SQL Injection", "label": "OR"},
      {"to": "XSS Attack", "label": "OR"},
      {"to": "Auth Bypass", "label": "OR"}
    ]
  }
}
```

## Available Tools
- `generate_attack_tree` — Render the tree as an image
- `validate_attack_tree` — Check config for errors before rendering
- `get_attack_tree_stats` — Get metrics (node count, depth, CVSS distribution)
- `build_attack_tree_from_spec` — Build from nodes/edges lists instead of full config

## Available Styles
Read `usecvislib://styles/attack-trees` to see all style presets.

## Tips
- Use `validate_attack_tree` before generating to catch config errors early.
- CVSS scores auto-color nodes by severity (critical=dark red, high=red, medium=orange, low=green).
- Use AND edges for steps that ALL must succeed, OR edges for alternatives.
"""


@mcp.prompt()
def create_threat_model() -> str:
    """Step-by-step guide for creating a threat model DFD."""
    return """# Creating a Threat Model (DFD) with USecVisLib

## Overview
Threat models use Data Flow Diagrams (DFDs) to identify security threats.
Elements include processes, data stores, external entities, data flows,
and trust boundaries.

## Step-by-Step Process

1. **Define the System**: Name and describe what you're modeling.
2. **Identify External Entities**: Users, third-party services, etc.
3. **Map Processes**: Application components that process data.
4. **Define Data Stores**: Databases, file systems, caches.
5. **Draw Data Flows**: How data moves between elements.
6. **Set Trust Boundaries**: Group elements by trust zones.
7. **Run STRIDE Analysis**: Use `analyze_stride_threats` to find threats.

## Config Structure

```json
{
  "model": {
    "name": "E-Commerce Platform",
    "description": "Threat model for online store"
  },
  "processes": {
    "web_app": {"label": "Web Application", "sanitizesInput": true, "hasAccessControl": true}
  },
  "datastores": {
    "db": {"label": "User Database", "isEncrypted": true, "storesPII": true}
  },
  "externals": {
    "user": {"label": "Customer", "isTrusted": false}
  },
  "dataflows": {
    "f1": {"from": "user", "to": "web_app", "label": "HTTPS Request", "isEncrypted": true},
    "f2": {"from": "web_app", "to": "db", "label": "SQL Query", "isEncrypted": false}
  },
  "boundaries": {
    "internal": {"label": "Internal Network", "elements": ["web_app", "db"]}
  }
}
```

Note: All sections use dict-of-dicts keyed by element ID (not arrays).

## Available Tools
- `generate_threat_model` — Render the DFD as an image
- `validate_threat_model` — Check config for errors
- `get_threat_model_stats` — Get element and flow counts
- `analyze_stride_threats` — Run STRIDE analysis to identify threats

## Tips
- Mark `isEncrypted: false` on data flows to surface Information Disclosure threats.
- Set `sanitizesInput: false` on processes to surface Tampering threats.
- Set `isTrusted: false` on external entities to surface Spoofing threats.
- Use the `engine: "pytm"` option for PyTM-compatible threat analysis (if installed).
"""


@mcp.prompt()
def create_attack_graph() -> str:
    """Step-by-step guide for creating an attack graph."""
    return """# Creating an Attack Graph with USecVisLib

## Overview
Attack graphs model network attack scenarios showing how an attacker can
traverse hosts, exploit vulnerabilities, and escalate privileges across
a network topology.

## Step-by-Step Process

1. **Define Hosts**: Network hosts with IPs and zones.
2. **Map Vulnerabilities**: CVEs with CVSS scores, linked to hosts.
3. **Define Privileges**: Access levels (none, user, admin, root) per host.
4. **List Services**: Exposed services with ports.
5. **Create Exploits**: Link vulnerabilities to privilege escalations.
6. **Draw Network Edges**: Network connectivity between hosts.
7. **Analyze Paths**: Use `find_attack_paths` to discover attack routes.

## Config Structure

```json
{
  "graph": {
    "name": "Corporate Network Attack Graph"
  },
  "hosts": [
    {"id": "attacker", "label": "Attacker", "ip": "external", "zone": "external"},
    {"id": "webserver", "label": "Web Server", "ip": "10.0.1.10", "zone": "dmz"},
    {"id": "dbserver", "label": "Database Server", "ip": "10.0.2.20", "zone": "internal"}
  ],
  "vulnerabilities": [
    {"id": "vuln_rce", "label": "Remote Code Execution", "cvss": 9.8, "affected_host": "webserver"},
    {"id": "vuln_sqli", "label": "SQL Injection", "cvss": 8.6, "affected_host": "webserver"}
  ],
  "privileges": [
    {"id": "priv_web_user", "label": "Web User", "host": "webserver", "level": "user"},
    {"id": "priv_db_admin", "label": "DB Admin", "host": "dbserver", "level": "admin"}
  ],
  "services": [
    {"id": "svc_http", "label": "HTTP", "host": "webserver", "port": 80},
    {"id": "svc_mysql", "label": "MySQL", "host": "dbserver", "port": 3306}
  ],
  "exploits": [
    {"id": "exp_rce", "label": "Exploit RCE", "preconditions": ["vuln_rce"], "postconditions": ["priv_web_user"]}
  ],
  "network_edges": [
    {"from": "attacker", "to": "webserver", "label": "Internet"},
    {"from": "webserver", "to": "dbserver", "label": "Internal LAN"}
  ]
}
```

## Available Tools
- `generate_attack_graph` — Render the graph as an image
- `validate_attack_graph` — Check config for errors
- `get_attack_graph_stats` — Get node/edge counts and metrics
- `find_attack_paths` — Find paths from source to target node
- `analyze_critical_nodes` — Identify most critical nodes (chokepoints)

## Tips
- Use `find_attack_paths` with source="attacker" and target= a high-value asset.
- Use `analyze_critical_nodes` to prioritize patching and hardening efforts.
- CVSS scores on vulnerabilities help prioritize the most dangerous paths.
- Network edges define reachability — only connected hosts can be attacked.
"""


@mcp.prompt()
def analyze_binary() -> str:
    """Step-by-step guide for binary file triage and analysis."""
    return """# Binary File Analysis with USecVisLib

## Overview
BinVis provides visual analysis of binary files — entropy maps, byte distributions,
and heatmaps — useful for malware triage, firmware analysis, and identifying
encrypted or compressed regions.

## Step-by-Step Triage Pipeline

1. **Get Stats First**: Use `get_binary_stats` to get file size, entropy, and
   byte distribution overview without generating images.
2. **Check Entropy**: Use `analyze_binary_entropy` to visualize entropy across
   the file. High-entropy regions suggest encryption or compression.
3. **Check Distribution**: Use `analyze_binary_distribution` to see byte value
   frequencies. Uniform distribution suggests encryption; spikes suggest structure.
4. **Visual Patterns**: Use `analyze_binary_heatmap` for a 2D view to spot
   repeating patterns, headers, or anomalies.
5. **Full Analysis**: Use `analyze_binary_all` to generate all visualizations at once.

## Available Tools
- `analyze_binary_entropy` — Entropy visualization across the file
- `analyze_binary_distribution` — Byte frequency distribution chart
- `analyze_binary_heatmap` — 2D byte value heatmap
- `analyze_binary_all` — All visualizations in one call
- `get_binary_stats` — Statistical summary without visualization

## Tips
- Start with `get_binary_stats` for a quick overview before generating images.
- Entropy close to 8.0 bits/byte indicates encrypted or compressed data.
- Low entropy (< 4.0) with byte spikes suggests plain text or structured data.
- Compare regions visually to identify packed vs. unpacked sections in executables.
"""


@mcp.prompt()
def create_privilege_gradient() -> str:
    """Step-by-step guide for creating a privilege gradient visualization."""
    return """# Creating a Privilege Gradient Graph with USecVisLib

## Overview
Privilege gradient graphs visualize trust zone architectures with automatic
inversion detection. They show how components in different trust zones
influence each other, highlighting potential security issues.

## Step-by-Step Process

1. **Define Zones**: Create trust zones with privilege levels (higher = more trusted).
2. **Place Components**: Assign components to their respective trust zones.
3. **Map Influences**: Define how components influence each other across zones.
4. **Detect Inversions**: Use `detect_privilege_inversions` to find cases where
   lower-privilege zones influence higher-privilege zones.
5. **Analyze Influence**: Use `analyze_zone_influence` to see the full influence matrix.
6. **Generate**: Use `generate_privilege_gradient` to visualize the architecture.

## Config Structure

```json
{
  "gradient": {
    "name": "Corporate Trust Architecture",
    "description": "Trust zones for corporate network"
  },
  "zones": {
    "internet": {"label": "Internet", "level": 0, "color": "#e74c3c"},
    "dmz": {"label": "DMZ", "level": 1, "color": "#f39c12"},
    "internal": {"label": "Internal", "level": 2, "color": "#3498db"},
    "restricted": {"label": "Restricted", "level": 3, "color": "#2ecc71"}
  },
  "components": {
    "cdn": {"label": "CDN", "zone": "internet"},
    "web_app": {"label": "Web App", "zone": "dmz"},
    "api_server": {"label": "API Server", "zone": "internal"},
    "database": {"label": "Database", "zone": "restricted"}
  },
  "influences": [
    {"from": "cdn", "to": "web_app", "label": "HTTPS"},
    {"from": "web_app", "to": "api_server", "label": "REST API"},
    {"from": "api_server", "to": "database", "label": "SQL"}
  ]
}
```

## Available Tools
- `generate_privilege_gradient` — Render the gradient graph as an image
- `validate_privilege_gradient` — Check config for errors
- `get_privilege_gradient_stats` — Get zone and component counts
- `detect_privilege_inversions` — Find privilege inversion issues
- `analyze_zone_influence` — Get cross-zone influence matrix

## Tips
- Inversions (low zone influencing high zone) are flagged automatically.
- Use `detect_privilege_inversions` after defining your architecture to find issues.
- The influence matrix from `analyze_zone_influence` helps identify over-connected zones.
"""


@mcp.prompt()
def review_cloud_security() -> str:
    """Step-by-step guide for cloud architecture security review."""
    return """# Cloud Architecture Security Review with USecVisLib

## Overview
Use cloud diagrams to visualize and review cloud architecture for security.
Supports AWS, GCP, Azure, and other providers with native icons.

## Step-by-Step Review Process

1. **Search Icons**: Use `search_cloud_icons` to find the right provider icons
   for your architecture components.
2. **Build Config**: Create the diagram config with nodes (services), edges
   (data flows), and clusters (VPCs, subnets, regions).
3. **Validate**: Use `validate_cloud_diagram` to check icon paths and references.
4. **Generate**: Use `generate_cloud_diagram` to produce the architecture diagram.
5. **Review Stats**: Use `get_cloud_diagram_stats` to see provider distribution
   and cluster organization.

## Security Review Checklist
- Are all data flows encrypted? Mark edges with TLS/SSL labels.
- Are services properly segmented into VPCs/subnets (clusters)?
- Are there direct paths from public-facing to internal services?
- Are databases in private subnets with no direct internet access?
- Are load balancers and WAFs in front of public services?

## Available Tools
- `generate_cloud_diagram` — Render cloud architecture as an image
- `validate_cloud_diagram` — Check config for errors
- `get_cloud_diagram_stats` — Get node/edge/cluster statistics
- `search_cloud_icons` — Find provider icons by name

## Tips
- Use `search_cloud_icons` with queries like "database", "compute", "storage".
- Group related services into clusters to represent VPCs or regions.
- Edge labels should describe the protocol and whether traffic is encrypted.
- Use the diagram alongside a threat model for comprehensive security review.
"""
