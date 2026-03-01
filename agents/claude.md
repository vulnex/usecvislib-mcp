# USecVisLib — Claude Code Setup

## MCP Server Configuration

Add to your Claude Code MCP config (`~/.claude/mcp_servers.json` or project `.mcp.json`):

```json
{
  "mcpServers": {
    "usecvislib": {
      "command": "usecvislib-mcp",
      "args": ["serve"],
      "env": {}
    }
  }
}
```

## Skill Installation

Install the skill so Claude Code loads `SKILL.md` as domain knowledge and gains access to the complete tool catalog in [REFERENCE.md](https://github.com/vulnex/usecvislib-skill/blob/main/REFERENCE.md):

```
claude skill add /path/to/usecvislib
```

Or from the GitHub repo:

```
claude skill add https://github.com/vulnex/usecvislib-skill
```

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
