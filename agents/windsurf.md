# USecVisLib — Windsurf Setup

> Skill repo: <https://github.com/vulnex/usecvislib-skill>

## MCP Server Configuration

### Option A: stdio (local)

Add to your Windsurf MCP config (`~/.codeium/windsurf/mcp_config.json`):

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

Restart Windsurf after saving. The 63 tools will appear in Cascade's tool list.

## Loading Skill Knowledge

Add a rules file so Cascade has domain context when working with USecVisLib:

1. Create a `.windsurfrules` file in your project root with:

```
When working with USecVisLib security visualizations, follow the guidance in SKILL.md
and use the tool catalog in REFERENCE.md for function signatures and parameter details.
```

2. For deeper context, copy `SKILL.md` into your project so Cascade can index it directly.

## Notes

- Windsurf's Cascade agent uses the same MCP protocol — all 63 tools work identically
- Style IDs, config schemas, and workflows in `SKILL.md` apply without modification
