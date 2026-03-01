# usecvislib-mcp

MCP (Model Context Protocol) server for the [USecVisLib](https://github.com/vulnex/usecvislib) security visualization library.

Provides 49 tools, 15 resources, and 6 prompt templates that give AI assistants full access to security visualization capabilities — attack trees, attack graphs, threat models, cloud diagrams, binary analysis, privilege gradients, and more.

## Table of Contents

- [Installation](#installation)
  - [Option A: Docker (recommended)](#option-a-docker-recommended)
  - [Option B: Local Installation](#option-b-local-installation)
- [Client Setup](#client-setup)
  - [Claude Code / Cursor (stdio — local)](#claude-code--cursor-stdio--local)
  - [Claude Code / Cursor (HTTP — Docker)](#claude-code--cursor-http--docker)
  - [Claude Desktop (stdio)](#claude-desktop-stdio)
  - [Claude Desktop (HTTP)](#claude-desktop-http)
- [Agent Setup Guides](#agent-setup-guides)
- [Transport Options](#transport-options)
- [Authentication](#authentication)
- [Configuration Reference](#configuration-reference)
- [Tools (49)](#tools-49)
- [Resources (15)](#resources-15)
- [Prompts (6)](#prompts-6)
- [Companion Skill](#companion-skill)
- [Development](#development)
- [License](#license)

## Installation

### Option A: Docker (recommended)

Docker provides a fully self-contained environment with all system dependencies pre-installed. No need to install Graphviz, mermaid-cli, or any other system packages.

#### Using docker-compose (from the usecvislib parent project)

```bash
# Clone the parent project
git clone --recursive https://github.com/vulnex/usecvislib.git
cd usecvislib

# Clone the MCP server alongside it
git clone https://github.com/vulnex/usecvislib-mcp.git ../usecvislib-mcp

# Generate an API key and save it
echo "USECVISLIB_MCP_API_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" >> .env

# Start the MCP server (builds the base image first, then the MCP layer)
docker-compose up -d usecvislib-mcp

# Verify it's running
curl http://localhost:8002/health
# {"status": "ok"}
```

The MCP server will be available at `http://localhost:8002/mcp`.

Then add a `.mcp.json` in your `usecvislib/` directory so Claude Code connects to the Docker container:

```json
{
  "mcpServers": {
    "usecvislib": {
      "type": "http",
      "url": "http://localhost:8002/mcp",
      "headers": {
        "Authorization": "Bearer <your-api-key>"
      }
    }
  }
}
```

Replace `<your-api-key>` with the key generated in the `.env` file.

#### Standalone Docker

```bash
# Build the base image first (from usecvislib directory)
cd /path/to/usecvislib
docker build -t usecvislib-usecvislib-api:latest .

# Build the MCP image
cd /path/to/usecvislib-mcp
docker build -t usecvislib-mcp .

# Run
docker run -p 8001:8000 \
  -e USECVISLIB_MCP_TRANSPORT=streamable-http \
  -e USECVISLIB_MCP_HOST=0.0.0.0 \
  -e USECVISLIB_MCP_API_KEY=my-secret-key \
  usecvislib-mcp
```

Then configure your client with the standalone port (`8001`):

```json
{
  "mcpServers": {
    "usecvislib": {
      "type": "http",
      "url": "http://localhost:8001/mcp",
      "headers": {
        "Authorization": "Bearer my-secret-key"
      }
    }
  }
}
```

#### Health Check

```bash
curl http://localhost:8001/health
# {"status": "ok"}
```

### Option B: Local Installation

Local installation requires system dependencies to be installed separately.

#### 1. System Requirements

| Dependency | Required | Purpose |
|-----------|----------|---------|
| **Python 3.10+** | Yes | Runtime |
| **Graphviz** | Yes | All diagram rendering (attack trees, attack graphs, threat models, etc.) |
| **mermaid-cli** (mmdc) | Optional | Mermaid diagram rendering |
| **diagrams** Python package | Optional | Cloud architecture diagrams |
| **pytm** Python package | Optional | PyTM threat model engine |

#### 2. Install Graphviz

```bash
# macOS
brew install graphviz

# Ubuntu / Debian
sudo apt-get install graphviz

# Fedora / RHEL
sudo dnf install graphviz

# Windows
choco install graphviz
```

Verify: `dot -V` should print the version.

#### 3. Install mermaid-cli (optional — for Mermaid diagrams)

```bash
npm install -g @mermaid-js/mermaid-cli
```

Verify: `mmdc --version` should print the version.

> **Note**: mermaid-cli requires Node.js 18+. If you only need attack trees, attack graphs, and threat models, you can skip this.

#### 4. Install the MCP server

```bash
# Install usecvislib first (if not already installed)
cd /path/to/usecvislib
pip install -e .

# Install the MCP server
cd /path/to/usecvislib-mcp
pip install -e .
```

Or install from PyPI (when published):

```bash
pip install usecvislib-mcp
```

#### 5. Verify the installation

```bash
# Should start and wait for stdio input (Ctrl+C to exit)
usecvislib-mcp
```

#### 6. Install optional Python packages

```bash
# Cloud architecture diagrams (AWS, GCP, Azure icons)
pip install diagrams

# PyTM threat model engine
pip install pytm
```

## Client Setup

A `.mcp.json` file is included in this repository for immediate use with Claude Code. If you open this project directory in Claude Code, the MCP server will be auto-discovered and connected via stdio.

### Claude Code / Cursor (stdio — local)

For local use after `pip install`, add to your project's `.mcp.json` or `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "usecvislib": {
      "command": "usecvislib-mcp"
    }
  }
}
```

This runs the server as a subprocess using stdio transport. No network, no authentication — simplest setup.

### Claude Code / Cursor (HTTP — Docker)

When running via Docker, connect over HTTP:

```json
{
  "mcpServers": {
    "usecvislib": {
      "type": "http",
      "url": "http://localhost:8002/mcp",
      "headers": {
        "Authorization": "Bearer <your-api-key>"
      }
    }
  }
}
```

Replace `<your-api-key>` with the value of `USECVISLIB_MCP_API_KEY` from your `.env` file. Adjust the port if using standalone Docker (default `8001`).

### Claude Desktop (stdio)

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "usecvislib": {
      "command": "usecvislib-mcp"
    }
  }
}
```

> **Tip**: If `usecvislib-mcp` is installed in a virtualenv, use the full path:
> ```json
> {
>   "command": "/path/to/venv/bin/usecvislib-mcp"
> }
> ```

### Claude Desktop (HTTP)

```json
{
  "mcpServers": {
    "usecvislib": {
      "type": "streamable-http",
      "url": "http://localhost:8002/mcp",
      "headers": {
        "Authorization": "Bearer <your-api-key>"
      }
    }
  }
}
```

## Agent Setup Guides

The [`agents/`](agents/) directory contains setup instructions for specific AI coding agents:

| Agent | File | Config Format |
|-------|------|---------------|
| **Claude Code** | [`agents/claude.md`](agents/claude.md) | `.mcp.json` (JSON) |
| **Cursor** | [`agents/cursor.md`](agents/cursor.md) | `.cursor/mcp.json` (JSON) |
| **Windsurf** | [`agents/windsurf.md`](agents/windsurf.md) | `mcp_config.json` (JSON) |
| **OpenClaw** | [`agents/openclaw.md`](agents/openclaw.md) | YAML config |
| **OpenAI Codex** | [`agents/openai.yaml`](agents/openai.yaml) | YAML dependency spec |

Each guide covers MCP server configuration, skill/knowledge loading, and agent-specific notes. All agents connect to the same 49 tools with identical function names.

## Transport Options

| Transport | Use Case | Output Mode | Network |
|-----------|----------|-------------|---------|
| `stdio` (default) | Local CLI clients | `file` — paths on disk | No |
| `sse` | Legacy HTTP streaming | `base64` — inline data | Yes |
| `streamable-http` | Production HTTP | `base64` — inline data | Yes |

Set via `USECVISLIB_MCP_TRANSPORT` environment variable.

**Stdio** is the default for local use — the client launches the server as a subprocess and communicates over stdin/stdout. No network exposure, no authentication needed.

**HTTP transports** (`sse`, `streamable-http`) are for Docker deployments and remote access. They require `USECVISLIB_MCP_HOST=0.0.0.0` to bind to all interfaces and support API key authentication.

## Authentication

When `USECVISLIB_MCP_API_KEY` is set and the transport is HTTP (`sse` or `streamable-http`), clients must provide a Bearer token:

```
Authorization: Bearer <api-key>
```

The `/health` endpoint is always unauthenticated.

Auth is ignored in `stdio` mode (local pipe — no network exposure).

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
| `USECVISLIB_MCP_ALLOWED_INPUT_DIRS` | *(empty)* | Comma-separated allowed dirs for binary file access (unrestricted when empty) |
| `USECVISLIB_MCP_RATE_LIMIT` | `60` | Max tool calls per minute per tool (0 = unlimited) |

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

## Companion Skill

The **[USecVisLib Skill](https://github.com/vulnex/skill/usecvislib)** is a domain knowledge prompt that teaches AI assistants how to effectively use the MCP tools for security assessments. While the MCP server provides the tools, the Skill provides the expertise.

| Layer | Role |
|-------|------|
| **MCP Server** (this package) | Provides tools (actions) and resources (data) — the "hands" |
| **Skill** | Provides domain expertise and workflow guidance — the "brain" |

The Skill includes:
- **Visualization selection guide** — maps security questions to the right tool
- **Configuration best practices** — per-type guidance for all 10 visualization modules
- **Workflow orchestration** — multi-step workflows (security assessment, binary triage, cloud review, attack surface mapping)
- **Style recommendations** — matched to audience (executive, pentest, academic, etc.)

**Using both together** delivers the best results: the Skill guides tool selection and configuration strategy, then the MCP server executes the visualizations.

**Using the MCP server alone** also works — AI assistants can rely on tool descriptions and the 6 built-in prompt templates for guidance. This is suitable for non-Claude clients, automated pipelines, or developers who prefer explicit tool invocation.

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests (requires Docker for full Graphviz/mermaid-cli environment)
docker build -f Dockerfile.test -t usecvislib-mcp-test ..
docker run --rm --tmpfs /tmp:size=512m usecvislib-mcp-test

# Run a subset locally (no Graphviz needed)
pytest tests/test_auth.py tests/test_config.py -v
```

## License

Apache-2.0
