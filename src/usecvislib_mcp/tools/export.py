"""MCP tools for data export and report generation."""

import asyncio
import json
import uuid

from usecvislib import (
    AttackGraphs,
    AttackTrees,
    ComponentDiagram,
    DependencyGraph,
    Exporter,
    PrivilegeGradient,
    ReportGenerator,
    ThreatModeling,
    USecVisLibError,
)

from ..config import get_output_dir
from ..helpers import format_error, temp_config_file
from ..server import mcp

# Mapping from viz_type string to Pattern A class
_VIZ_CLASS_MAP = {
    "attack_tree": AttackTrees,
    "attack_graph": AttackGraphs,
    "threat_model": ThreatModeling,
    "privilege_gradient": PrivilegeGradient,
    "component_diagram": ComponentDiagram,
    "dependency_graph": DependencyGraph,
}


@mcp.tool()
async def export_data(
    data: dict | list,
    format: str = "json",
) -> str:
    """Export data to JSON, CSV, YAML, or Markdown table format.

    For JSON and YAML, returns the formatted string directly.
    For CSV, writes to a file and returns the path.
    For Markdown, returns the rendered table string.

    Args:
        data: Data to export — a dict or list of dicts.
        format: Export format — 'json', 'csv', 'yaml', or 'md'.

    Returns:
        JSON with the exported content or file path.
    """
    try:

        def _sync_export():
            fmt = format.lower().strip()

            if fmt == "json":
                content = Exporter.to_json(data)
                return {"format": "json", "content": content}

            elif fmt == "yaml":
                content = Exporter.to_yaml(data)
                return {"format": "yaml", "content": content}

            elif fmt == "csv":
                output_dir = get_output_dir()
                output_dir.mkdir(parents=True, exist_ok=True)
                output_path = str(
                    output_dir / f"export_{uuid.uuid4().hex[:8]}.csv"
                )
                rows_data = data if isinstance(data, list) else [data]
                row_count = Exporter.to_csv(rows_data, output=output_path)
                return {
                    "format": "csv",
                    "output_path": output_path,
                    "rows_written": row_count,
                }

            elif fmt in ("md", "markdown"):
                rows_data = data if isinstance(data, list) else [data]
                content = Exporter.to_markdown_table(rows_data)
                return {"format": "markdown", "content": content}

            else:
                return {"error": f"Unsupported format: {fmt}. Use json, csv, yaml, or md."}

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _sync_export)
        return json.dumps(result, indent=2, default=str)
    except (USecVisLibError, Exception) as e:
        return format_error(e)


@mcp.tool()
async def generate_report(
    config: dict,
    viz_type: str,
    formats: list[str] | None = None,
) -> str:
    """Generate a multi-format report from a visualization config.

    Instantiates the visualization, loads the config, and generates
    reports in the requested formats using ReportGenerator.

    Args:
        config: Visualization configuration dictionary.
        viz_type: Visualization type — 'attack_tree', 'attack_graph',
                  'threat_model', 'privilege_gradient', 'component_diagram',
                  or 'dependency_graph'.
        formats: List of output formats — 'json', 'csv', 'yaml', 'md'.
                 Defaults to ['json', 'csv', 'md'].

    Returns:
        JSON mapping format names to output file paths.
    """
    try:

        def _sync_report():
            viz_class = _VIZ_CLASS_MAP.get(viz_type)
            if viz_class is None:
                return {
                    "error": f"Unknown viz_type: {viz_type}",
                    "supported": list(_VIZ_CLASS_MAP.keys()),
                }

            output_dir = get_output_dir()
            output_dir.mkdir(parents=True, exist_ok=True)
            report_dir = output_dir / f"report_{uuid.uuid4().hex[:8]}"
            report_dir.mkdir(parents=True, exist_ok=True)

            with temp_config_file(config) as config_path:
                viz = viz_class(
                    inputfile=config_path,
                    outputfile="/dev/null",
                    format="png",
                    validate_paths=False,
                )
                viz.load()

                rg = ReportGenerator(viz)
                report_formats = formats if formats else ["json", "csv", "md"]
                result = rg.generate_report(
                    output_dir=str(report_dir),
                    formats=report_formats,
                )
                return {"report_dir": str(report_dir), "files": result}

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _sync_report)
        return json.dumps(result, indent=2, default=str)
    except (USecVisLibError, Exception) as e:
        return format_error(e)
