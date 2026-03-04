#
# VULNEX -Universal Security Visualization Library-
#
# File: tools/batch.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""MCP tool for batch processing multiple visualizations."""

import json
import uuid
from pathlib import Path

from usecvislib import process_batch

from ..config import get_output_dir, get_temp_dir
from ..helpers import (
    check_rate_limit,
    format_error,
    log_tool_call,
    run_with_timeout,
    validate_format,
    validate_int_range,
)
from ..server import mcp

MAX_BATCH_CONFIGS = 100
MAX_BATCH_WORKERS = 8
ALLOWED_MODULE_TYPES = frozenset(
    {
        "attack_tree",
        "attack_graph",
        "threat_model",
        "privilege_gradient",
        "component_diagram",
        "dependency_graph",
    }
)


@mcp.tool()
@log_tool_call
async def batch_process(
    module_type: str,
    configs: list[dict],
    format: str = "png",
    style: str = "",
    max_workers: int = 4,
) -> str:
    """Batch-process multiple visualization configs in parallel.

    Writes each config as a temporary file, runs process_batch(),
    and returns a summary with individual results.

    Args:
        module_type: Visualization type — 'attack_tree', 'attack_graph',
                     'threat_model', 'privilege_gradient', 'component_diagram',
                     or 'dependency_graph'.
        configs: List of configuration dictionaries to process (max 100).
        format: Output format — png, pdf, svg, or dot.
        style: Style ID to apply (empty string for default).
        max_workers: Maximum parallel workers (max 8).

    Returns:
        JSON with summary (success/failure counts) and individual results.
    """
    try:
        validate_format(format)
        check_rate_limit("batch_process")
        if module_type not in ALLOWED_MODULE_TYPES:
            return format_error(
                ValueError(
                    f"Unknown module_type: {module_type}. Supported: {sorted(ALLOWED_MODULE_TYPES)}"
                )
            )
        if len(configs) > MAX_BATCH_CONFIGS:
            return format_error(
                ValueError(f"Batch size ({len(configs)}) exceeds maximum ({MAX_BATCH_CONFIGS})")
            )
        validate_int_range(max_workers, "max_workers", 1, MAX_BATCH_WORKERS)
        max_workers = min(max_workers, MAX_BATCH_WORKERS)

        def _sync_batch():
            temp_dir = get_temp_dir()
            temp_dir.mkdir(parents=True, exist_ok=True)
            output_dir = get_output_dir()
            output_dir.mkdir(parents=True, exist_ok=True)

            batch_id = uuid.uuid4().hex
            temp_files = []
            try:
                # Write each config to a temp file
                for i, cfg in enumerate(configs):
                    temp_path = temp_dir / f"batch_{batch_id}_{i}.json"
                    temp_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
                    temp_files.append(str(temp_path))

                result = process_batch(
                    module_type=module_type,
                    input_files=temp_files,
                    output_dir=str(output_dir),
                    format=format,
                    style=style or None,
                    max_workers=max_workers,
                )
                return result.to_dict()
            finally:
                # Clean up temp files
                for tf in temp_files:
                    try:
                        Path(tf).unlink(missing_ok=True)
                    except OSError:
                        pass

        result = await run_with_timeout(_sync_batch)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return format_error(e)
