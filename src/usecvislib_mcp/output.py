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
import os
import uuid
from pathlib import Path
from typing import Any

from .config import get_output_dir, get_output_mode


class OutputHandler:
    """Handles formatting tool output as file paths or base64 data."""

    def __init__(self, mode: str | None = None):
        self.mode = mode or get_output_mode()

    def make_output_path(self, prefix: str, fmt: str) -> str:
        """Generate a unique output file path."""
        output_dir = get_output_dir()
        output_dir.mkdir(parents=True, exist_ok=True)
        unique = uuid.uuid4().hex
        filename = f"{prefix}_{unique}.{fmt}"
        return str(output_dir / filename)

    def format_result(
        self, output_path: str, fmt: str, metadata: dict | None = None
    ) -> Any:
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
            return json.dumps({"error": f"Output file not found: {output_path}"})

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
