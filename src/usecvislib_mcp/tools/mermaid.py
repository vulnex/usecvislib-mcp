"""MCP tool for rendering Mermaid diagrams."""

import asyncio

from usecvislib import MermaidDiagrams, USecVisLibError

from ..helpers import format_error
from ..output import OutputHandler
from ..server import mcp


@mcp.tool()
async def render_mermaid(
    source: str,
    format: str = "png",
    theme: str = "default",
    background: str = "white",
    width: int = 800,
    height: int = 600,
):
    """Render a Mermaid diagram from source text.

    Supports all Mermaid diagram types: flowchart, sequence, class, ER,
    state, gantt, pie, mindmap, and more. Requires mermaid-cli (mmdc).

    Args:
        source: Mermaid diagram source text.
        format: Output format — png, svg, or pdf.
        theme: Mermaid theme — default, dark, forest, or neutral.
        background: Background color (e.g. 'white', 'transparent', '#f0f0f0').
        width: Image width in pixels.
        height: Image height in pixels.
    """
    try:
        handler = OutputHandler()
        output_path = handler.make_output_path("mermaid", format)

        def _sync_render():
            md = MermaidDiagrams(theme=theme, validate_cli=True)
            md.load_from_string(source)
            result = md.render(
                output=output_path,
                format=format,
                width=width,
                height=height,
                theme=theme,
                background=background,
            )
            return result.output_path

        loop = asyncio.get_event_loop()
        result_path = await loop.run_in_executor(None, _sync_render)
        return handler.format_result(result_path, format)
    except (USecVisLibError, Exception) as e:
        return format_error(e)
