#
# VULNEX -Universal Security Visualization Library-
#
# File: helpers.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Core helper functions used by all MCP tools.

Provides the common pattern: config dict → temp file → viz class → output.
"""

import asyncio
import functools
import json
import logging
import re
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .config import get_max_config_size, get_rate_limiter, get_temp_dir
from .output import OutputHandler

logger = logging.getLogger("usecvislib_mcp")

# Allowed output formats for image generation
ALLOWED_IMAGE_FORMATS = frozenset({"png", "pdf", "svg", "dot"})


def validate_format(fmt: str, allowed: frozenset = ALLOWED_IMAGE_FORMATS) -> None:
    """Validate that the output format is in the allowed set."""
    if fmt not in allowed:
        raise ValueError(f"Invalid format '{fmt}'. Allowed: {', '.join(sorted(allowed))}")


def validate_config_size(config: dict) -> None:
    """Check that a config dict does not exceed the max allowed size.

    Used by Pattern B helpers and other tools that bypass temp_config_file().
    """
    estimated = len(str(config))
    max_size = get_max_config_size()
    if estimated > max_size:
        raise ValueError(
            f"Config estimated size ({estimated} bytes) exceeds maximum ({max_size} bytes)"
        )


def validate_int_range(value: int, name: str, min_val: int = 1, max_val: int = 1000) -> int:
    """Validate that an integer parameter is within an acceptable range.

    Prevents resource exhaustion from extreme values.

    Args:
        value: The integer value to validate.
        name: Parameter name for error messages.
        min_val: Minimum allowed value (inclusive).
        max_val: Maximum allowed value (inclusive).

    Returns:
        The validated value.

    Raises:
        ValueError: If value is outside the allowed range.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"Parameter '{name}' must be an integer, got {type(value).__name__}")
    if value < min_val or value > max_val:
        raise ValueError(f"Parameter '{name}' must be between {min_val} and {max_val}, got {value}")
    return value


def log_tool_call(func):
    """Decorator that logs tool invocation, duration, and success/failure."""

    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        tool_name = func.__name__
        start = time.monotonic()
        logger.info("Tool call started: %s", tool_name)
        try:
            result = await func(*args, **kwargs)
            elapsed = time.monotonic() - start
            # Check if the result indicates an error
            status = "error" if isinstance(result, str) and '"error"' in result[:50] else "ok"
            logger.info(
                "Tool call finished: %s status=%s duration=%.3fs",
                tool_name,
                status,
                elapsed,
            )
            return result
        except Exception:
            elapsed = time.monotonic() - start
            logger.info(
                "Tool call finished: %s status=exception duration=%.3fs",
                tool_name,
                elapsed,
            )
            raise

    return wrapper


# Whitelist of methods allowed via dynamic dispatch (getattr)
# Prevents reflection attacks where arbitrary methods could be invoked
ALLOWED_ANALYSIS_METHODS = frozenset(
    {
        "validate",
        "get_stats",
        "analyze_stride",
        "detect_inversions",
        "analyze_zone_influence",
        "get_zone_influence_matrix",
        "find_paths",
        "find_attack_paths",
        "analyze_critical_nodes",
        "find_chokepoints",
        "betweenness_centrality",
    }
)

ALLOWED_BUILD_METHODS = frozenset(
    {
        "render",
        "build",
        "BuildCustomDiagram",
    }
)


@contextmanager
def temp_config_file(config: dict, suffix: str = ".json"):
    """Context manager that writes config dict to a temp file and cleans up.

    Yields the path to the temporary config file.
    """
    # Pre-serialization size estimate (fast reject before expensive json.dumps)
    estimated = len(str(config))
    if estimated > get_max_config_size():
        raise ValueError(
            f"Config estimated size ({estimated} bytes) exceeds maximum "
            f"({get_max_config_size()} bytes)"
        )

    content = json.dumps(config, indent=2)

    if len(content) > get_max_config_size():
        raise ValueError(
            f"Config size ({len(content)} bytes) exceeds maximum ({get_max_config_size()} bytes)"
        )

    temp_dir = get_temp_dir()
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_path = temp_dir / f"mcp_{uuid.uuid4().hex}{suffix}"

    try:
        temp_path.write_text(content, encoding="utf-8")
        yield str(temp_path)
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            logger.warning("Failed to clean up temp file: %s", temp_path)


async def build_visualization(
    viz_class,
    config: dict,
    output_prefix: str,
    fmt: str = "png",
    styleid: str = "",
    **viz_kwargs,
) -> Any:
    """Build a visualization using Pattern A classes (AttackTrees, AttackGraphs, etc.).

    1. Checks rate limit
    2. Creates temp config file from dict
    3. Creates unique output path
    4. Runs viz_class(inputfile, outputfile, format, styleid).build() in executor
    5. Returns formatted result via OutputHandler
    """
    validate_format(fmt)
    get_rate_limiter().check(output_prefix)
    handler = OutputHandler()
    output_path = handler.make_output_path(output_prefix, fmt)
    # Output path for graphviz: strip extension, the library adds it
    output_base = str(Path(output_path).with_suffix(""))

    def _sync_build():
        with temp_config_file(config) as config_path:
            viz = viz_class(
                inputfile=config_path,
                outputfile=output_base,
                format=fmt,
                styleid=styleid,
                validate_paths=False,
                **viz_kwargs,
            )
            viz.build()
        return output_path

    loop = asyncio.get_running_loop()
    result_path = await loop.run_in_executor(None, _sync_build)
    return handler.format_result(result_path, fmt)


async def build_and_analyze(
    viz_class,
    config: dict,
    analysis_method: str,
    **method_kwargs,
) -> str:
    """Run an analysis method on a visualization class.

    1. Creates temp config, instantiates viz class
    2. Calls viz.load() then getattr(viz, analysis_method)(**kwargs)
    3. Returns the analysis result as JSON
    """
    get_rate_limiter().check(analysis_method)

    if analysis_method not in ALLOWED_ANALYSIS_METHODS:
        raise ValueError(
            f"Method '{analysis_method}' is not allowed. "
            f"Allowed: {', '.join(sorted(ALLOWED_ANALYSIS_METHODS))}"
        )

    def _sync_analyze():
        with temp_config_file(config) as config_path:
            viz = viz_class(
                inputfile=config_path,
                outputfile="/dev/null",
                format="png",
                validate_paths=False,
            )
            viz.load()
            method = getattr(viz, analysis_method)
            return method(**method_kwargs)

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, _sync_analyze)
    return json.dumps(result, indent=2, default=str)


async def build_pattern_b(
    viz_class,
    config: dict,
    output_prefix: str,
    fmt: str = "png",
    build_method: str = "render",
    **build_kwargs,
) -> Any:
    """Build a visualization using Pattern B classes (CloudDiagrams, CustomDiagrams).

    1. Creates OutputHandler and unique output path
    2. Instantiates viz_class(), calls .load_from_string(json.dumps(config), "json")
    3. Calls the build/render method with output path
    4. Returns formatted result
    """
    validate_format(fmt)
    validate_config_size(config)
    get_rate_limiter().check(output_prefix)
    handler = OutputHandler()
    output_path = handler.make_output_path(output_prefix, fmt)
    output_base = str(Path(output_path).with_suffix(""))

    if build_method not in ALLOWED_BUILD_METHODS:
        raise ValueError(
            f"Build method '{build_method}' is not allowed. "
            f"Allowed: {', '.join(sorted(ALLOWED_BUILD_METHODS))}"
        )

    def _sync_build():
        viz = viz_class()
        viz.load_from_string(json.dumps(config), "json")
        method = getattr(viz, build_method)
        method(output=output_base, output_format=fmt, **build_kwargs)
        return output_path

    loop = asyncio.get_running_loop()
    result_path = await loop.run_in_executor(None, _sync_build)
    return handler.format_result(result_path, fmt)


async def analyze_pattern_b(
    viz_class,
    config: dict,
    analysis_method: str,
    **method_kwargs,
) -> str:
    """Run an analysis method on a Pattern B class (CloudDiagrams, CustomDiagrams).

    1. Instantiates viz_class(), calls .load_from_string(json.dumps(config), "json")
    2. Calls analysis method
    3. Returns the analysis result as JSON
    """
    validate_config_size(config)
    get_rate_limiter().check(analysis_method)

    if analysis_method not in ALLOWED_ANALYSIS_METHODS:
        raise ValueError(
            f"Method '{analysis_method}' is not allowed. "
            f"Allowed: {', '.join(sorted(ALLOWED_ANALYSIS_METHODS))}"
        )

    def _sync_analyze():
        viz = viz_class()
        viz.load_from_string(json.dumps(config), "json")
        method = getattr(viz, analysis_method)
        return method(**method_kwargs)

    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, _sync_analyze)
    return json.dumps(result, indent=2, default=str)


def _sanitize_error_message(message: str) -> str:
    """Strip internal file paths and sensitive details from error messages."""
    # Strip absolute file paths (Unix and Windows patterns)
    sanitized = re.sub(r"(/[\w./-]+/)([\w.-]+)", r"\2", message)
    sanitized = re.sub(r"([A-Z]:\\[\w.\\-]+\\)([\w.-]+)", r"\2", sanitized)
    # Strip Python traceback references
    sanitized = re.sub(r'File "[^"]+", line \d+', 'File "<internal>"', sanitized)
    return sanitized


def format_error(exception: Exception) -> str:
    """Format an exception into a user-friendly error string.

    Sanitizes internal paths and sensitive details before returning.
    """
    error_type = type(exception).__name__
    message = _sanitize_error_message(str(exception))

    # Include context from USecVisLibError subclasses, sanitized
    context = {}
    if hasattr(exception, "context"):
        raw_ctx = exception.context
        if isinstance(raw_ctx, dict):
            context = {
                k: _sanitize_error_message(str(v)) if isinstance(v, str) else v
                for k, v in raw_ctx.items()
            }
    elif hasattr(exception, "__dict__"):
        context = {
            k: _sanitize_error_message(str(v)) if isinstance(v, str) else v
            for k, v in exception.__dict__.items()
            if not k.startswith("_") and k != "args"
        }

    result = {"error": error_type, "message": message}
    if context:
        result["context"] = context

    return json.dumps(result, indent=2, default=str)
