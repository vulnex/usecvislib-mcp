# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - Unreleased

Requires usecvislib 0.6.0.

### Added
- 14 tools for the usecvislib 0.5/0.6 modules (63 tools in total):
  - Kill chain / MITRE ATT&CK: `generate_kill_chain`, `validate_kill_chain`, `get_kill_chain_stats`, `analyze_kill_chain_coverage`
  - Incident timeline: `generate_incident_timeline` (swimlane, gantt, vertical, compact), `validate_incident_timeline`, `get_incident_timeline_stats`
  - Vulnerability dependency tree: `generate_vuln_tree` (tree, vulnerable_only, critical_path), `validate_vuln_tree`, `get_vuln_tree_stats`
  - MAESTRO agentic-AI threat model: `generate_maestro_threat_model` (layered, graph, heatmap), `validate_maestro_threat_model`, `get_maestro_stats`, `export_maestro` (to STRIDE, attack graph or privilege gradient)
- `render_engine` parameter (`graphviz` or `svg`) on the generate tools whose modules support usecvislib's SVG engine; the tool's default Graphviz style switches to `sv_default` automatically.
- `shine` parameter to post-process Graphviz SVG output.
- Schema resources for the four new modules (19 resources) and their style presets in the styles resources.
- Prompts: `create_kill_chain`, `create_incident_timeline`, `analyze_supply_chain`, `create_maestro_threat_model` (10 prompts).
- Server instructions and README point to the rendered gallery: https://vulnex.github.io/usecvislib-gallery/
- Tests for every new tool, the engine options, and every bundled template of the new modules.

### Changed
- Requires `usecvislib>=0.6.0`.

### Fixed
- `generate_custom_diagram` failed on every call: it passed `styleid` to `BuildCustomDiagram()`, which takes no style. The style is now applied through the diagram settings.
- Component diagram and dependency graph schema resources documented an outdated config format (`diagram`/`graph` sections, dicts of layers and components). They now match what usecvislib reads (`title`, a list of layers with nested components, a list of modules), so configs written from the schema render.
- Component diagram and dependency graph tools defaulted to style IDs that do not exist (`comp_default`, `dep_default`); they now default to `cd_default` and `dg_default`.
- `batch_process` advertised `privilege_gradient`, `component_diagram` and `dependency_graph`, which the usecvislib batch processor rejected. With the extended batch processor in usecvislib it now handles those plus `kill_chain`, `incident_timeline`, `vuln_tree` and `maestro`.
- Component diagram schema: lists the valid component types and the `bidirectional` connection style.
- `detect_config_type` used its own outdated rules: it recognised none of the newer modules and expected the old component/dependency formats. It now uses usecvislib's config detection and reports kill_chain, incident_timeline, vuln_tree, maestro, access_graph and mermaid too.
- `convert_to_mermaid` passed its `viz_type` hint to usecvislib as the Mermaid diagram type. The hint is now checked against the detected type (a mismatch returns an error), the response includes the detected `viz_type`, and the docs list every type the converter supports.
- `generate_report` and `compare_visualizations` accept `kill_chain`, `incident_timeline`, `vuln_tree` and `maestro` (with the matching usecvislib fixes, reports list only the files they wrote).

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
