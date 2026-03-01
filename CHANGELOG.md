# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-03-01

### Added
- HTTP transport with Uvicorn for remote deployments
- SHA-256 API key authentication for HTTP transport
- Per-tool rate limiting with sliding 60-second window
- Docker support with `Dockerfile` and `Dockerfile.test`
- `.mcp.json` auto-discovery configuration
- Agent setup guides for Claude, Cursor, Windsurf, OpenClaw, and OpenAI
- VULNEX comment headers to all Python source files

### Changed
- Bumped version to 0.4.0 with production hardening
- Improved README with Docker setup, companion skill, and agent setup sections

### Fixed
- Critical broken tools repaired for release readiness
- Image output for PNG/SVG in MCP tools
- `.mcp.json` added to `.gitignore` to prevent leaking credentials

### Security
- Fixed critical finding C3 (input validation)
- Fixed high findings H9, H10
- Fixed medium findings M9, M11-M15

## [0.2.0] - 2026-02-22

### Added
- 26 new tools for Phase 2 bringing total to 40 tools, 15 resources, 6 prompts
- Binary analysis tools (entropy, distribution, heatmap, stats)
- Cloud diagram tools with multi-provider icon support
- Privilege gradient visualization and inversion detection
- Custom diagram support with schema-driven rendering
- Component diagram generation for layered architectures
- Dependency graph visualization with circular dependency detection
- Pattern B helpers (`load_from_string`) for JSON-based tool input
- Batch processing, data export, report generation, and CVSS calculator
- Mermaid diagram rendering and config-to-Mermaid conversion
- Visualization comparison (diff) tool

## [0.1.0] - 2026-02-22

### Added
- Initial MCP server wrapping USecVisLib
- 14 tools: attack tree, attack graph, and threat model generation
- Validation, statistics, and analysis tools for each visualization type
- Attack path finding and critical node analysis for attack graphs
- STRIDE threat analysis for threat models
- 9 resources exposing library documentation and schema information
- 3 prompt templates for guided visualization creation
- Stdio transport support
- Automated output mode detection (file path vs base64)
- Full test suite with pytest-asyncio

[0.4.0]: https://github.com/vulnex/usecvislib-mcp/compare/v0.2.0...v0.4.0
[0.2.0]: https://github.com/vulnex/usecvislib-mcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/vulnex/usecvislib-mcp/releases/tag/v0.1.0
