#
# VULNEX -Universal Security Visualization Library-
#
# File: output.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Output handling for MCP tool results — file paths or base64-encoded data."""

import base64
import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any

from .config import get_output_dir, get_output_mode, get_output_ttl_seconds

logger = logging.getLogger("usecvislib_mcp")

# Track when we last ran cleanup to avoid doing it on every call
_last_cleanup_time: float = 0.0
_CLEANUP_INTERVAL_SECONDS = 300  # Run cleanup at most every 5 minutes


class OutputHandler:
    """Handles formatting tool output as file paths or base64 data."""

    def __init__(self, mode: str | None = None):
        self.mode = mode or get_output_mode()

    def make_output_path(self, prefix: str, fmt: str) -> str:
        """Generate a unique output file path.

        Periodically cleans up expired output files based on TTL.
        """
        output_dir = get_output_dir()
        output_dir.mkdir(parents=True, exist_ok=True)

        self._cleanup_expired(output_dir)

        unique = uuid.uuid4().hex
        filename = f"{prefix}_{unique}.{fmt}"
        return str(output_dir / filename)

    @staticmethod
    def _cleanup_expired(output_dir: Path) -> None:
        """Remove output files older than the configured TTL.

        Runs at most once every _CLEANUP_INTERVAL_SECONDS to avoid
        filesystem overhead on every tool call.
        """
        global _last_cleanup_time

        now = time.time()
        if now - _last_cleanup_time < _CLEANUP_INTERVAL_SECONDS:
            return
        _last_cleanup_time = now

        ttl = get_output_ttl_seconds()
        if ttl <= 0:
            return

        cutoff = now - ttl
        removed = 0
        try:
            for entry in output_dir.iterdir():
                if not entry.is_file():
                    continue
                try:
                    if entry.stat().st_mtime < cutoff:
                        entry.unlink(missing_ok=True)
                        removed += 1
                except OSError:
                    pass
        except OSError:
            pass

        if removed > 0:
            logger.info("Output cleanup: removed %d expired files from %s", removed, output_dir)

    def format_result(self, output_path: str, fmt: str, metadata: dict | None = None) -> Any:
        """Format a visualization result for MCP response.

        In file mode: returns JSON with path info.
        In base64 mode: returns Image object for png/svg, or JSON with data_base64 for others.
        """
        path = Path(output_path)

        if self.mode == "file":
            result = {
                "output_path": str(path),
                "format": fmt,
                "size_bytes": path.stat().st_size if path.exists() else 0,
            }
            if metadata:
                result["metadata"] = metadata
            return json.dumps(result, indent=2)

        # base64 mode
        if not path.exists():
            return json.dumps({"error": "Output file not found"})

        if fmt in ("png", "svg"):
            try:
                from mcp.server.fastmcp import Image

                return Image(path=path, format=fmt)
            except ImportError:
                pass

        data = path.read_bytes()
        data_b64 = base64.b64encode(data).decode("ascii")

        return json.dumps(
            {
                "format": fmt,
                "data_base64": data_b64,
                "size_bytes": len(data),
            },
            indent=2,
        )
