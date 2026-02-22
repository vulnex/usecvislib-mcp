# usecvislib-mcp

MCP (Model Context Protocol) server for the [USecVisLib](https://github.com/user/usecvislib) security visualization library.

Provides 49 tools, 15 resources, and 6 prompt templates that give AI assistants full access to security visualization capabilities — attack trees, attack graphs, threat models, cloud diagrams, binary analysis, privilege gradients, and more.

## Installation

```bash
pip install -e .          # from this directory
# or
pip install usecvislib-mcp
```

Requires `usecvislib >= 0.3.4` and system dependencies (Graphviz, mermaid-cli, diagrams) — see the main USecVisLib README.

## Quick Start

### stdio (local)

```bash
usecvislib-mcp
```

### HTTP (remote / Docker)

```bash
USECVISLIB_MCP_TRANSPORT=streamable-http \
USECVISLIB_MCP_HOST=0.0.0.0 \
USECVISLIB_MCP_PORT=8000 \
USECVISLIB_MCP_API_KEY=my-secret-key \
  usecvislib-mcp
```

## Transport Options

| Transport | Use Case | Output Mode |
|-----------|----------|-------------|
| `stdio` (default) | Local CLI clients | `file` — paths on disk |
| `sse` | Legacy HTTP streaming | `base64` — inline data |
| `streamable-http` | Production HTTP | `base64` — inline data |

Set via `USECVISLIB_MCP_TRANSPORT`.

## Authentication

When `USECVISLIB_MCP_API_KEY` is set and the transport is HTTP (`sse` or `streamable-http`), clients must provide a Bearer token:

```
Authorization: Bearer <api-key>
```

The `/health` endpoint is always unauthenticated.

Auth is ignored in `stdio` mode (local pipe — no network exposure).

## Docker Deployment

### With docker-compose (recommended)

From the `usecvislib/` directory:

```bash
# Set API key in .env
echo "USECVISLIB_MCP_API_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" >> .env

# Start all services
docker-compose up -d usecvislib-mcp
```

The MCP server will be available at `http://localhost:8001/mcp`.

### Standalone Docker

```bash
docker build -t usecvislib-mcp .
docker run -p 8001:8000 \
  -e USECVISLIB_MCP_TRANSPORT=streamable-http \
  -e USECVISLIB_MCP_HOST=0.0.0.0 \
  -e USECVISLIB_MCP_API_KEY=my-secret-key \
  usecvislib-mcp
```

### Health Check

```bash
curl http://localhost:8001/health
# {"status": "ok"}
```

## Client Setup

### Claude Desktop / Claude Code (stdio)

Add to your MCP settings (`claude_desktop_config.json` or `.claude/settings.json`):

```json
{
  "mcpServers": {
    "usecvislib": {
      "command": "usecvislib-mcp"
    }
  }
}
```

### Claude Code / Cursor (HTTP — remote or Docker)

```json
{
  "mcpServers": {
    "usecvislib": {
      "type": "streamable-http",
      "url": "http://localhost:8001/mcp",
      "headers": {
        "Authorization": "Bearer <your-api-key>"
      }
    }
  }
}
```

## Configuration Reference

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `USECVISLIB_MCP_TRANSPORT` | `stdio` | Transport mode: `stdio`, `sse`, `streamable-http` |
| `USECVISLIB_MCP_HOST` | `127.0.0.1` | Bind address for HTTP transports |
| `USECVISLIB_MCP_PORT` | `8000` | Port for HTTP transports |
| `USECVISLIB_MCP_API_KEY` | *(empty)* | Bearer token for HTTP auth (disabled when empty) |
| `USECVISLIB_MCP_OUTPUT_MODE` | *(auto)* | `file` (stdio) or `base64` (HTTP) — auto-detected from transport |
| `USECVISLIB_MCP_OUTPUT_DIR` | `/tmp/usecvislib-mcp-output` | Directory for file-mode output |
| `USECVISLIB_MCP_TEMP_DIR` | `/tmp/usecvislib-mcp-temp` | Temp directory for processing |
| `USECVISLIB_MCP_LOG_LEVEL` | `INFO` | Log level: DEBUG, INFO, WARNING, ERROR |
| `USECVISLIB_MCP_DEFAULT_FORMAT` | `png` | Default image format |
| `USECVISLIB_MCP_MAX_CONFIG_SIZE` | `10485760` | Max config size in bytes (10 MB) |

## Tools (49)

### Attack Trees (4)
| Tool | Description |
|------|-------------|
| `generate_attack_tree` | Generate an attack tree visualization from config |
| `validate_attack_tree` | Validate an attack tree configuration |
| `get_attack_tree_stats` | Get statistics (node counts, depth, etc.) |
| `build_attack_tree_from_spec` | Build via structured specification (builder API) |

### Attack Graphs (5)
| Tool | Description |
|------|-------------|
| `generate_attack_graph` | Generate an attack graph visualization |
| `validate_attack_graph` | Validate an attack graph configuration |
| `get_attack_graph_stats` | Get statistics (nodes, edges, etc.) |
| `find_attack_paths` | Find paths between two nodes |
| `analyze_critical_nodes` | Identify most critical nodes |

### Threat Models (4)
| Tool | Description |
|------|-------------|
| `generate_threat_model` | Generate a threat model DFD |
| `validate_threat_model` | Validate a threat model configuration |
| `get_threat_model_stats` | Get statistics (elements, flows, etc.) |
| `analyze_stride_threats` | Perform STRIDE threat analysis |

### Mermaid (1)
| Tool | Description |
|------|-------------|
| `render_mermaid` | Render a Mermaid diagram from source text |

### Binary Analysis (5)
| Tool | Description |
|------|-------------|
| `analyze_binary_entropy` | Entropy visualization of a binary file |
| `analyze_binary_distribution` | Byte distribution visualization |
| `analyze_binary_heatmap` | Byte heatmap visualization |
| `analyze_binary_all` | All binary visualizations at once |
| `get_binary_stats` | Statistical summary of a binary file |

### Cloud Diagrams (6)
| Tool | Description |
|------|-------------|
| `generate_cloud_diagram` | Generate a cloud architecture diagram |
| `validate_cloud_diagram` | Validate a cloud diagram configuration |
| `get_cloud_diagram_stats` | Get statistics (nodes, providers, etc.) |
| `search_cloud_icons` | Search for cloud provider icons |
| `list_cloud_providers` | List available cloud providers |
| `list_cloud_icons` | List icons for a specific provider |

### Privilege Gradient (5)
| Tool | Description |
|------|-------------|
| `generate_privilege_gradient` | Generate a privilege gradient graph |
| `validate_privilege_gradient` | Validate a privilege gradient configuration |
| `get_privilege_gradient_stats` | Get statistics (zones, components, etc.) |
| `detect_privilege_inversions` | Detect privilege inversions |
| `analyze_zone_influence` | Analyze influence between trust zones |

### Custom Diagrams (3)
| Tool | Description |
|------|-------------|
| `generate_custom_diagram` | Generate a custom diagram |
| `validate_custom_diagram` | Validate a custom diagram configuration |
| `get_custom_diagram_stats` | Get statistics (nodes, edges, etc.) |

### Architecture — Component Diagrams (3)
| Tool | Description |
|------|-------------|
| `generate_component_diagram` | Generate a component diagram |
| `validate_component_diagram` | Validate a component diagram configuration |
| `get_component_diagram_stats` | Get statistics (layers, components, etc.) |

### Architecture — Dependency Graphs (3)
| Tool | Description |
|------|-------------|
| `generate_dependency_graph` | Generate a dependency graph |
| `validate_dependency_graph` | Validate a dependency graph configuration |
| `get_dependency_graph_stats` | Get statistics (modules, deps, circular deps) |

### Utilities (4)
| Tool | Description |
|------|-------------|
| `convert_to_mermaid` | Convert config to Mermaid diagram syntax |
| `calculate_cvss_score` | Calculate CVSS score from vector string |
| `detect_config_type` | Detect visualization type from config |
| `list_shapes` | List shapes available for custom diagrams |

### Batch (1)
| Tool | Description |
|------|-------------|
| `batch_process` | Batch-process multiple configs in parallel |

### Export (2)
| Tool | Description |
|------|-------------|
| `export_data` | Export to JSON, CSV, YAML, or Markdown |
| `generate_report` | Generate multi-format report |

### Analysis (3)
| Tool | Description |
|------|-------------|
| `find_chokepoints` | Find network chokepoints in attack graphs |
| `analyze_centrality` | Compute betweenness centrality |
| `compare_visualizations` | Structural diff between two configs |

## Resources (15)

| URI Pattern | Description |
|-------------|-------------|
| `usecvislib://templates/list` | List template categories |
| `usecvislib://templates/{category}/list` | List templates in a category |
| `usecvislib://templates/{category}/{name}` | Get template content |
| `usecvislib://styles/list` | List all style presets |
| `usecvislib://styles/{visualization_type}` | Styles for a visualization type |
| `usecvislib://schemas/attack-tree` | Attack tree config schema |
| `usecvislib://schemas/attack-graph` | Attack graph config schema |
| `usecvislib://schemas/threat-model` | Threat model config schema |
| `usecvislib://schemas/mermaid` | Mermaid parameter schema |
| `usecvislib://schemas/binary-analysis` | Binary analysis parameter schema |
| `usecvislib://schemas/cloud-diagram` | Cloud diagram config schema |
| `usecvislib://schemas/privilege-gradient` | Privilege gradient config schema |
| `usecvislib://schemas/custom-diagram` | Custom diagram config schema |
| `usecvislib://schemas/component-diagram` | Component diagram config schema |
| `usecvislib://schemas/dependency-graph` | Dependency graph config schema |

## Prompts (6)

| Prompt | Description |
|--------|-------------|
| `create_attack_tree` | Step-by-step guide for attack tree creation |
| `create_threat_model` | Step-by-step guide for threat model DFD creation |
| `create_attack_graph` | Step-by-step guide for attack graph creation |
| `analyze_binary` | Guide for binary file triage and analysis |
| `create_privilege_gradient` | Guide for privilege gradient creation |
| `review_cloud_security` | Guide for cloud architecture security review |

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests (requires Docker for full Graphviz/mermaid-cli environment)
docker build -f Dockerfile.test -t usecvislib-mcp-test ..
docker run --rm --tmpfs /tmp:size=512m usecvislib-mcp-test

# Run a subset locally
pytest tests/test_auth.py tests/test_config.py -v
```

## License

Apache-2.0
