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

import base64
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
BINARY_CHARTS = ("entropy", "distribution", "windrose", "heatmap", "digraph")


async def _build_binary_viz(file_path: str, chart: str, output_prefix: str, fmt: str, style: str):
    """Render one binary chart to the exact path the result reports.

    ``BinVis.build()`` writes ``<base>_<chart>.<fmt>``, so the path this tool
    used to report never existed (size 0, "Output file not found" in base64
    mode). Each chart is now written to the reported path directly.

    Args:
        file_path: User-provided file path to analyze.
        chart: entropy, distribution, windrose, heatmap, or digraph.
        output_prefix: Prefix for the output filename.
        fmt: Output format — png, pdf, or svg.
        style: bv_* style preset ("" for the default).
    """
    validate_format(fmt, ALLOWED_BINARY_FORMATS)
    check_rate_limit(output_prefix)
    validated_path = str(validate_input_path(file_path))
    handler = OutputHandler()
    output_path = handler.make_output_path(output_prefix, fmt)

    def _sync_build():
        output_base = str(Path(output_path).with_suffix(""))
        bv = BinVis(validated_path, output_base, format=fmt, styleid=style, validate_paths=False)
        bv.load()
        getattr(bv, f"visualize_{chart}")(output=output_path)
        return output_path

    await run_with_timeout(_sync_build)
    return handler.format_result(output_path, fmt)


@mcp.tool()
@log_tool_call
async def analyze_binary_entropy(
    file_path: str,
    format: str = "png",
    style: str = "",
):
    """Generate an entropy visualization of a binary file.

    Displays byte entropy distribution across the file, useful for identifying
    encrypted, compressed, or structured regions.

    Args:
        file_path: Path to the binary file to analyze.
        format: Output format — png, pdf, or svg.
        style: Style preset (bv_default, bv_dark, bv_security, ...; "" for default).
    """
    try:
        return await _build_binary_viz(file_path, "entropy", "binary_entropy", format, style)
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def analyze_binary_distribution(
    file_path: str,
    format: str = "png",
    style: str = "",
):
    """Generate a byte distribution visualization of a binary file.

    Shows the frequency distribution of byte values (0-255), useful for
    detecting patterns, padding, or anomalies.

    Args:
        file_path: Path to the binary file to analyze.
        format: Output format — png, pdf, or svg.
        style: Style preset (bv_default, bv_dark, bv_security, ...; "" for default).
    """
    try:
        return await _build_binary_viz(
            file_path, "distribution", "binary_distribution", format, style
        )
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def analyze_binary_heatmap(
    file_path: str,
    format: str = "png",
    style: str = "",
):
    """Generate a byte heatmap visualization of a binary file.

    Creates a 2D heatmap showing byte value patterns across the file,
    useful for visual pattern recognition and structure identification.

    Args:
        file_path: Path to the binary file to analyze.
        format: Output format — png, pdf, or svg.
        style: Style preset (bv_default, bv_dark, bv_security, ...; "" for default).
    """
    try:
        return await _build_binary_viz(file_path, "heatmap", "binary_heatmap", format, style)
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def analyze_binary_digraph(
    file_path: str,
    format: str = "png",
    style: str = "",
):
    """Generate a byte-pair (digraph) plot of a binary file.

    A 256x256 image of how often byte B follows byte A, on a log scale, with
    guides at the printable ASCII range. Machine code, ASCII text, UTF-16,
    compressed and encrypted data each leave a distinct pattern, which makes
    it a quick format-recognition view; random data looks uniform.

    Args:
        file_path: Path to the binary file to analyze.
        format: Output format — png, pdf, or svg.
        style: Style preset (bv_default, bv_dark, bv_security, ...; "" for default).
    """
    try:
        return await _build_binary_viz(file_path, "digraph", "binary_digraph", format, style)
    except Exception as e:
        return format_error(e)


@mcp.tool()
@log_tool_call
async def analyze_binary_all(
    file_path: str,
    format: str = "png",
    style: str = "",
) -> str:
    """Generate every binary chart in one call.

    Entropy, byte distribution, wind rose (polar histogram of byte values),
    heatmap and byte-pair digraph.

    Args:
        file_path: Path to the binary file to analyze.
        format: Output format — png, pdf, or svg.
        style: Style preset (bv_default, bv_dark, bv_security, ...; "" for default).

    Returns:
        JSON ``{"charts": [...]}``: per chart its ``type`` and ``output_path``
        and ``size_bytes`` (file output mode), or ``data_base64`` (base64 mode).
    """
    try:
        validate_format(format, ALLOWED_BINARY_FORMATS)
        check_rate_limit("binary_all")
        validated_path = str(validate_input_path(file_path))
        handler = OutputHandler()
        output_base = str(Path(handler.make_output_path("binary_all", format)).with_suffix(""))

        def _sync_build():
            bv = BinVis(
                validated_path, output_base, format=format, styleid=style, validate_paths=False
            )
            return bv.visualize_all(output_prefix=output_base)

        paths = await run_with_timeout(_sync_build)
        charts = []
        for chart, path in zip(BINARY_CHARTS, paths, strict=True):
            entry = {"type": chart, "format": format}
            if handler.mode == "file":
                entry.update(output_path=path, size_bytes=Path(path).stat().st_size)
            else:
                entry["data_base64"] = base64.b64encode(Path(path).read_bytes()).decode("ascii")
                Path(path).unlink(missing_ok=True)
            charts.append(entry)
        return json.dumps({"charts": charts}, indent=2)
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
