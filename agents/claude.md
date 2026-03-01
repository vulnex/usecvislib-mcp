# USecVisLib — Claude Code Setup

## MCP Server Configuration

### Option A: stdio (local)

Add to your project `.mcp.json` (auto-discovered by Claude Code):

```json
{
  "mcpServers": {
    "usecvislib": {
      "command": "usecvislib-mcp"
    }
  }
}
```

### Option B: HTTP (Docker)

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

## Companion Skill

The [USecVisLib Skill](https://github.com/vulnex/usecvislib-skill) provides domain knowledge and workflow guidance. Install it using the Claude Code slash command:

```
/install-github-skill https://github.com/vulnex/usecvislib-skill
```

This loads `SKILL.md` as domain knowledge and gives Claude access to the complete tool catalog in [REFERENCE.md](https://github.com/vulnex/usecvislib-skill/blob/main/REFERENCE.md).

## Resource URIs

With the MCP server running, Claude Code can read these resources directly:

- `usecvislib://styles/list` — all available styles grouped by type
- `usecvislib://styles/{visualization_type}` — styles for a specific type
- `usecvislib://schemas/{type}` — config schema (e.g., `schemas/attack-tree`, `schemas/cloud-diagram`)
- `usecvislib://templates/list` — all template categories
- `usecvislib://templates/{category}/{name}` — specific template content

## Permissions

The MCP server performs **local file I/O only** (writing generated images to disk). Recommended permission settings:

- Allow `generate_*` tools — they write image files to the working directory
- Allow `analyze_*` tools — read-only analysis, return data
- Allow `export_data` / `generate_report` — write output files
- Review `batch_process` calls — may create many files at once
