"""MCP tools for binary file visualization and analysis."""

import asyncio
import json

from usecvislib import BinVis, USecVisLibError

from ..config import validate_input_path
from ..helpers import format_error
from ..output import OutputHandler
from ..server import mcp


@mcp.tool()
async def analyze_binary_entropy(
    file_path: str,
    format: str = "png",
):
    """Generate an entropy visualization of a binary file.

    Displays byte entropy distribution across the file, useful for identifying
    encrypted, compressed, or structured regions.

    Args:
        file_path: Path to the binary file to analyze.
        format: Output format — png, pdf, or svg.
    """
    try:
        validated_path = str(validate_input_path(file_path))
        handler = OutputHandler()
        output_path = handler.make_output_path("binary_entropy", format)

        def _sync_build():
            from pathlib import Path

            output_base = str(Path(output_path).with_suffix(""))
            bv = BinVis(validated_path, output_base, format=format, validate_paths=False)
            bv.build("entropy")
            return output_path

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _sync_build)
        return handler.format_result(output_path, format)
    except (USecVisLibError, ValueError, Exception) as e:
        return format_error(e)


@mcp.tool()
async def analyze_binary_distribution(
    file_path: str,
    format: str = "png",
):
    """Generate a byte distribution visualization of a binary file.

    Shows the frequency distribution of byte values (0-255), useful for
    detecting patterns, padding, or anomalies.

    Args:
        file_path: Path to the binary file to analyze.
        format: Output format — png, pdf, or svg.
    """
    try:
        validated_path = str(validate_input_path(file_path))
        handler = OutputHandler()
        output_path = handler.make_output_path("binary_distribution", format)

        def _sync_build():
            from pathlib import Path

            output_base = str(Path(output_path).with_suffix(""))
            bv = BinVis(validated_path, output_base, format=format, validate_paths=False)
            bv.build("distribution")
            return output_path

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _sync_build)
        return handler.format_result(output_path, format)
    except (USecVisLibError, ValueError, Exception) as e:
        return format_error(e)


@mcp.tool()
async def analyze_binary_heatmap(
    file_path: str,
    format: str = "png",
):
    """Generate a byte heatmap visualization of a binary file.

    Creates a 2D heatmap showing byte value patterns across the file,
    useful for visual pattern recognition and structure identification.

    Args:
        file_path: Path to the binary file to analyze.
        format: Output format — png, pdf, or svg.
    """
    try:
        validated_path = str(validate_input_path(file_path))
        handler = OutputHandler()
        output_path = handler.make_output_path("binary_heatmap", format)

        def _sync_build():
            from pathlib import Path

            output_base = str(Path(output_path).with_suffix(""))
            bv = BinVis(validated_path, output_base, format=format, validate_paths=False)
            bv.build("heatmap")
            return output_path

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _sync_build)
        return handler.format_result(output_path, format)
    except (USecVisLibError, ValueError, Exception) as e:
        return format_error(e)


@mcp.tool()
async def analyze_binary_all(
    file_path: str,
    format: str = "png",
):
    """Generate all binary visualizations (entropy, distribution, heatmap).

    Produces a comprehensive visual analysis of the binary file in one call.

    Args:
        file_path: Path to the binary file to analyze.
        format: Output format — png, pdf, or svg.
    """
    try:
        validated_path = str(validate_input_path(file_path))
        handler = OutputHandler()
        output_path = handler.make_output_path("binary_all", format)

        def _sync_build():
            from pathlib import Path

            output_base = str(Path(output_path).with_suffix(""))
            bv = BinVis(validated_path, output_base, format=format, validate_paths=False)
            bv.build("all")
            return output_path

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _sync_build)
        return handler.format_result(output_path, format)
    except (USecVisLibError, ValueError, Exception) as e:
        return format_error(e)


@mcp.tool()
async def get_binary_stats(file_path: str) -> str:
    """Get statistical summary of a binary file.

    Returns file size, entropy, byte distribution statistics, and other
    metrics without generating a visualization.

    Args:
        file_path: Path to the binary file to analyze.
    """
    try:
        validated_path = str(validate_input_path(file_path))

        def _sync_stats():
            bv = BinVis(validated_path, "/dev/null", validate_paths=False)
            bv.load()
            return bv.get_stats()

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _sync_stats)
        return json.dumps(result, indent=2, default=str)
    except (USecVisLibError, ValueError, Exception) as e:
        return format_error(e)
