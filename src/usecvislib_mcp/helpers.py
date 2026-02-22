"""Core helper functions used by all MCP tools.

Provides the common pattern: config dict → temp file → viz class → output.
"""

import asyncio
import json
import logging
import uuid
from contextlib import contextmanager
from pathlib import Path

from .config import get_max_config_size, get_temp_dir
from .output import OutputHandler

logger = logging.getLogger("usecvislib_mcp")


@contextmanager
def temp_config_file(config: dict, suffix: str = ".json"):
    """Context manager that writes config dict to a temp file and cleans up.

    Yields the path to the temporary config file.
    """
    content = json.dumps(config, indent=2)

    if len(content) > get_max_config_size():
        raise ValueError(
            f"Config size ({len(content)} bytes) exceeds maximum "
            f"({get_max_config_size()} bytes)"
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
) -> str:
    """Build a visualization using Pattern A classes (AttackTrees, AttackGraphs, etc.).

    1. Creates temp config file from dict
    2. Creates unique output path
    3. Runs viz_class(inputfile, outputfile, format, styleid).build() in executor
    4. Returns formatted result via OutputHandler
    """
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

    loop = asyncio.get_event_loop()
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

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _sync_analyze)
    return json.dumps(result, indent=2, default=str)


async def build_pattern_b(
    viz_class,
    config: dict,
    output_prefix: str,
    fmt: str = "png",
    build_method: str = "render",
    **build_kwargs,
) -> str:
    """Build a visualization using Pattern B classes (CloudDiagrams, CustomDiagrams).

    1. Creates OutputHandler and unique output path
    2. Instantiates viz_class(), calls .load_from_string(json.dumps(config), "json")
    3. Calls the build/render method with output path
    4. Returns formatted result
    """
    handler = OutputHandler()
    output_path = handler.make_output_path(output_prefix, fmt)
    output_base = str(Path(output_path).with_suffix(""))

    def _sync_build():
        viz = viz_class()
        viz.load_from_string(json.dumps(config), "json")
        method = getattr(viz, build_method)
        method(output=output_base, output_format=fmt, **build_kwargs)
        return output_path

    loop = asyncio.get_event_loop()
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

    def _sync_analyze():
        viz = viz_class()
        viz.load_from_string(json.dumps(config), "json")
        method = getattr(viz, analysis_method)
        return method(**method_kwargs)

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _sync_analyze)
    return json.dumps(result, indent=2, default=str)


def format_error(exception: Exception) -> str:
    """Format an exception into a user-friendly error string."""
    error_type = type(exception).__name__
    message = str(exception)

    # Include context from USecVisLibError subclasses
    context = {}
    if hasattr(exception, "context"):
        context = exception.context
    elif hasattr(exception, "__dict__"):
        context = {
            k: v
            for k, v in exception.__dict__.items()
            if not k.startswith("_") and k != "args"
        }

    result = {"error": error_type, "message": message}
    if context:
        result["context"] = context

    return json.dumps(result, indent=2, default=str)
