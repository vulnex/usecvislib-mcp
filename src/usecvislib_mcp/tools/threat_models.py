"""MCP tools for threat model visualization and STRIDE analysis."""

import json

from usecvislib import ThreatModeling, USecVisLibError

from ..helpers import build_and_analyze, build_visualization, format_error
from ..server import mcp


@mcp.tool()
async def generate_threat_model(
    config: dict,
    format: str = "png",
    style: str = "tm_default",
    engine: str = "usecvislib",
):
    """Generate a threat model Data Flow Diagram from a configuration dictionary.

    The config should contain 'model', 'processes', 'datastores', 'externals',
    'dataflows', and 'boundaries' sections.

    Args:
        config: Threat model configuration dict.
        format: Output format — png, pdf, svg, or dot.
        style: Style preset ID (e.g. tm_default).
        engine: Rendering engine — 'usecvislib' or 'pytm'.
    """
    try:
        return await build_visualization(
            ThreatModeling,
            config,
            "threat_model",
            fmt=format,
            styleid=style,
            engine=engine,
        )
    except (USecVisLibError, Exception) as e:
        return format_error(e)


@mcp.tool()
async def validate_threat_model(config: dict) -> str:
    """Validate a threat model configuration and return any errors.

    Args:
        config: Threat model configuration to validate.

    Returns:
        JSON with 'valid' boolean and 'errors' list.
    """
    try:
        result = await build_and_analyze(ThreatModeling, config, "validate")
        errors = json.loads(result)
        return json.dumps(
            {"valid": len(errors) == 0, "errors": errors}, indent=2, default=str
        )
    except (USecVisLibError, Exception) as e:
        return format_error(e)


@mcp.tool()
async def get_threat_model_stats(config: dict) -> str:
    """Get statistics about a threat model — element counts, flow counts, etc.

    Args:
        config: Threat model configuration to analyze.
    """
    try:
        return await build_and_analyze(ThreatModeling, config, "get_stats")
    except (USecVisLibError, Exception) as e:
        return format_error(e)


@mcp.tool()
async def analyze_stride_threats(config: dict) -> str:
    """Perform STRIDE threat analysis on a threat model.

    Identifies potential Spoofing, Tampering, Repudiation,
    Information Disclosure, Denial of Service, and Elevation of Privilege
    threats based on the data flow diagram elements.

    Args:
        config: Threat model configuration to analyze.
    """
    try:
        return await build_and_analyze(ThreatModeling, config, "analyze_stride")
    except (USecVisLibError, Exception) as e:
        return format_error(e)
