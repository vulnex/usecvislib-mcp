# USecVisLib — OpenClaw Setup

## Option 1: MCP Server Integration

Add to your OpenClaw MCP configuration:

```yaml
mcp_servers:
  usecvislib:
    command: usecvislib-mcp
```

Then load the skill knowledge:

```
claw skill install /path/to/usecvislib-skill
```

## Option 2: Install from GitHub

```
claw skill install https://github.com/vulnex/usecvislib-skill
```

## Option 3: ClawHub Install

If published to ClawHub:

```
claw install usecvislib-skill
```

This installs both the skill knowledge (`SKILL.md`) and configures the MCP server dependency automatically.

## Skill Files

OpenClaw reads these files for domain knowledge:

- `SKILL.md` — primary skill prompt (visualization guidance, workflows, best practices)
- `REFERENCE.md` — complete tool catalog and integration reference

## Notes

- The MCP server exposes 65 tools, 19 resources, and 10 prompt templates
- Tool function names (e.g., `generate_attack_tree`) are identical across all agent integrations
- All file I/O is local — generated images write to the configured output directory
