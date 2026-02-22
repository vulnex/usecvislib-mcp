"""MCP server for USecVisLib security visualization library."""

from mcp.server.fastmcp import FastMCP

from .config import configure_logging, ensure_directories, get_transport

# Configure logging to stderr before anything else
logger = configure_logging()

# Create the FastMCP instance — tool modules import this
mcp = FastMCP(
    "usecvislib",
    instructions=(
        "Security visualization server providing attack trees, attack graphs, "
        "threat models, mermaid diagrams, binary analysis, cloud diagrams, "
        "privilege gradient graphs, custom diagrams, component diagrams, "
        "dependency graphs, and utility tools via the USecVisLib library."
    ),
)

# Import tool modules — they register via @mcp.tool()
from .tools import attack_graphs  # noqa: E402, F401
from .tools import attack_trees  # noqa: E402, F401
from .tools import mermaid  # noqa: E402, F401
from .tools import threat_models  # noqa: E402, F401
from .tools import binary_analysis  # noqa: E402, F401
from .tools import cloud_diagrams  # noqa: E402, F401
from .tools import privilege_gradient  # noqa: E402, F401
from .tools import custom_diagrams  # noqa: E402, F401
from .tools import architecture  # noqa: E402, F401
from .tools import utilities  # noqa: E402, F401

# Import resource modules — they register via @mcp.resource()
from .resources import schemas  # noqa: E402, F401
from .resources import styles  # noqa: E402, F401
from .resources import templates  # noqa: E402, F401

# Import prompt modules — they register via @mcp.prompt()
from .prompts import guidance  # noqa: E402, F401


def main():
    """Entry point for the MCP server."""
    ensure_directories()
    logger.info("Starting usecvislib MCP server (transport=%s)", get_transport())
    mcp.run(transport=get_transport())


if __name__ == "__main__":
    main()
