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

from .config import (
    current_client_id,
    get_max_config_size,
    get_rate_limiter,
    get_temp_dir,
    get_tool_timeout,
)
from .output import OutputHandler

logger = logging.getLogger("usecvislib_mcp")


def check_rate_limit(tool_name: str) -> None:
    """Check rate limit with per-client context when available."""
    get_rate_limiter().check(tool_name, client_id=current_client_id.get())


async def run_with_timeout(sync_fn, timeout: int | None = None) -> Any:
    """Run a sync function in an executor with an optional timeout.

    Args:
        sync_fn: Synchronous callable to run in the default executor.
        timeout: Max seconds to wait. Uses USECVISLIB_MCP_TOOL_TIMEOUT if None.
                 0 means no timeout.

    Raises:
        TimeoutError: If the operation exceeds the timeout.
    """
    if timeout is None:
        timeout = get_tool_timeout()

    loop = asyncio.get_running_loop()
    future = loop.run_in_executor(None, sync_fn)

    if timeout > 0:
        return await asyncio.wait_for(future, timeout=timeout)
    return await future


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
            logger.exception(
                "Tool call failed: %s duration=%.3fs",
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
        "analyze_coverage_gaps",
        "to_stride",
        "to_attack_graph",
        "to_privilege_gradient",
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


RENDER_ENGINES = frozenset({"graphviz", "svg"})

KEEP_VALUES = frozenset({"inversions"})
MAX_GROUPING_NODES = 10000


def grouping_options(
    group_by: str = "",
    collapse: str | list[str] | bool | None = None,
    max_nodes: int | None = None,
    keep: str = "",
    keep_ids: list[str] | None = None,
) -> dict:
    """Validate the grouping / collapse options and return the viz kwargs that are set.

    ``collapse`` is passed through as usecvislib reads it: "none", "all" (or
    True), "auto" (with ``max_nodes``), or a list of group ids. ``keep`` and
    ``keep_ids`` apply to privilege gradients only.
    """
    options: dict[str, Any] = {}
    if group_by:
        options["group_by"] = group_by
    if collapse not in (None, "", []):
        options["collapse"] = collapse
    if max_nodes is not None:
        options["max_nodes"] = validate_int_range(max_nodes, "max_nodes", 1, MAX_GROUPING_NODES)
    if keep:
        if keep not in KEEP_VALUES:
            raise ValueError(f"Invalid keep '{keep}'. Allowed: {', '.join(sorted(KEEP_VALUES))}")
        options["keep"] = keep
    if keep_ids:
        options["keep_ids"] = list(keep_ids)
    return options


def resolve_render_options(
    viz_class, styleid: str, fmt: str, render_engine: str, shine: bool
) -> tuple[str, dict]:
    """Validate render_engine/shine and return (styleid, extra viz kwargs).

    With render_engine="svg", the module's Graphviz default preset (the tool's
    default ``style`` value) becomes "" so the library picks its sv_* default.
    """
    if render_engine not in RENDER_ENGINES:
        raise ValueError(
            f"Invalid render_engine '{render_engine}'. Allowed: {', '.join(sorted(RENDER_ENGINES))}"
        )
    if shine and (fmt != "svg" or render_engine != "graphviz"):
        raise ValueError(
            "shine post-processes Graphviz SVG: use format='svg' with render_engine='graphviz'"
        )
    if render_engine == "graphviz":
        return styleid, {}
    if fmt == "dot":
        raise ValueError(
            "Format 'dot' is Graphviz-only; use png, pdf or svg with render_engine='svg'"
        )
    if styleid == getattr(viz_class, "DEFAULT_STYLE_ID", None):
        styleid = ""
    return styleid, {"render_engine": "svg"}


async def build_visualization(
    viz_class,
    config: dict,
    output_prefix: str,
    fmt: str = "png",
    styleid: str = "",
    render_engine: str = "graphviz",
    shine: bool = False,
    **viz_kwargs,
) -> Any:
    """Build a visualization using Pattern A classes (AttackTrees, AttackGraphs, etc.).

    1. Checks rate limit
    2. Creates temp config file from dict
    3. Creates unique output path
    4. Runs viz_class(inputfile, outputfile, format, styleid).build() in executor
    5. Applies the shine post-processing when requested
    6. Returns formatted result via OutputHandler
    """
    validate_format(fmt)
    styleid, engine_kwargs = resolve_render_options(viz_class, styleid, fmt, render_engine, shine)
    check_rate_limit(output_prefix)
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
                **engine_kwargs,
                **viz_kwargs,
            )
            viz.build()
        if shine:
            from usecvislib.svgengine import apply_shine_file

            apply_shine_file(output_path)
        return output_path

    result_path = await run_with_timeout(_sync_build)
    return handler.format_result(result_path, fmt)


async def build_and_analyze(
    viz_class,
    config: dict,
    analysis_method: str,
    *,
    viz_options: dict | None = None,
    **method_kwargs,
) -> str:
    """Run an analysis method on a visualization class.

    1. Creates temp config, instantiates viz class (with ``viz_options``, e.g. group_by)
    2. Calls viz.load() then getattr(viz, analysis_method)(**kwargs)
    3. Returns the analysis result as JSON
    """
    check_rate_limit(analysis_method)

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
                **(viz_options or {}),
            )
            viz.load()
            method = getattr(viz, analysis_method)
            return method(**method_kwargs)

    result = await run_with_timeout(_sync_analyze)
    return json.dumps(result, indent=2, default=str)


async def build_pattern_b(
    viz_class,
    config: dict,
    output_prefix: str,
    fmt: str = "png",
    build_method: str = "render",
    style: str = "",
    **build_kwargs,
) -> Any:
    """Build a visualization using Pattern B classes (CloudDiagrams, CustomDiagrams).

    1. Creates OutputHandler and unique output path
    2. Instantiates viz_class(), calls .load_from_string(json.dumps(config), "json")
    3. Applies ``style`` through the loaded settings (the build methods take no style)
    4. Calls the build/render method with output path
    5. Returns formatted result
    """
    validate_format(fmt)
    validate_config_size(config)
    check_rate_limit(output_prefix)
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
        if style and getattr(viz, "settings", None) is not None:
            viz.settings.style = style
        method = getattr(viz, build_method)
        method(output=output_base, output_format=fmt, **build_kwargs)
        return output_path

    result_path = await run_with_timeout(_sync_build)
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
    check_rate_limit(analysis_method)

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

    result = await run_with_timeout(_sync_analyze)
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
