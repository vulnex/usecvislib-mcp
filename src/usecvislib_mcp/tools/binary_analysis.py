#
# VULNEX -Universal Security Visualization Library-
#
# File: tools/binary_analysis.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""MCP tools for binary file visualization and analysis."""

import json
from pathlib import Path

from usecvislib import BinVis

from ..config import validate_input_path
from ..helpers import (
    check_rate_limit,
    format_error,
    log_tool_call,
    run_with_timeout,
    validate_format,
)
from ..output import OutputHandler
from ..server import mcp

ALLOWED_BINARY_FORMATS = frozenset({"png", "pdf", "svg"})


async def _build_binary_viz(file_path: str, build_type: str, output_prefix: str, fmt: str):
    """Shared helper for binary visualization tools.

    Validates input, creates BinVis, runs the specified build type, and
    returns the formatted result.

    Args:
        file_path: User-provided file path to analyze.
        build_type: BinVis build type — 'entropy', 'distribution', 'heatmap', or 'all'.
        output_prefix: Prefix for the output filename.
        fmt: Output format — png, pdf, or svg.
    """
    validate_format(fmt, ALLOWED_BINARY_FORMATS)
    check_rate_limit(output_prefix)
    validated_path = str(validate_input_path(file_path))
    handler = OutputHandler()
    output_path = handler.make_output_path(output_prefix, fmt)

    def _sync_build():
        output_base = str(Path(output_path).with_suffix(""))
        bv = BinVis(validated_path, output_base, format=fmt, validate_paths=False)
        bv.build(build_type)
        return output_path

    await run_with_timeout(_sync_build)
    return handler.format_result(output_path, fmt)


@mcp.tool()
@log_tool_call
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
        return await _build_binary_viz(file_path, "entropy", "binary_entropy", format)
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
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
        return await _build_binary_viz(file_path, "distribution", "binary_distribution", format)
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
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
        return await _build_binary_viz(file_path, "heatmap", "binary_heatmap", format)
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
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
        return await _build_binary_viz(file_path, "all", "binary_all", format)
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def get_binary_stats(file_path: str) -> str:
    """Get statistical summary of a binary file.

    Returns file size, entropy, byte distribution statistics, and other
    metrics without generating a visualization.

    Args:
        file_path: Path to the binary file to analyze.
    """
    try:
        check_rate_limit("get_binary_stats")
        validated_path = str(validate_input_path(file_path))

        def _sync_stats():
            bv = BinVis(validated_path, "/dev/null", validate_paths=False)
            bv.load()
            return bv.get_stats()

        result = await run_with_timeout(_sync_stats)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return format_error(e)
