# USecVisLib — Cursor Setup

> Skill repo: <https://github.com/vulnex/usecvislib-skill>

## MCP Server Configuration

### Option A: stdio (local)

Add to your project-level `.cursor/mcp.json` (or global `~/.cursor/mcp.json`):

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

Restart Cursor after saving. The 65 tools will appear in Cursor's tool list.

## Loading Skill Knowledge

Add a rule file so the AI agent has domain context when working with USecVisLib:

1. Copy `SKILL.md` to `.cursor/rules/usecvislib.md` in your project
2. Optionally copy `REFERENCE.md` alongside it for the full tool catalog

Alternatively, reference the skill inline via a `.cursorrules` file:

```
When working with USecVisLib security visualizations, follow the guidance in SKILL.md
and use the tool catalog in REFERENCE.md for function signatures.
```

## Notes

- Cursor's MCP support exposes the same 65 tools with identical function names
- Style IDs, config schemas, and workflows in `SKILL.md` apply without modification
