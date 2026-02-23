"""MCP resources for browsing USecVisLib templates."""

import json
import re
from pathlib import Path

from ..config import resolve_templates_dir
from ..server import mcp

# Only allow alphanumeric, hyphens, underscores, and dots in path components
_SAFE_NAME_RE = re.compile(r'^[a-zA-Z0-9_\-\.]+$')


def _get_templates_dir() -> Path:
    return resolve_templates_dir()


def _validate_path_component(name: str) -> str:
    """Validate a path component to prevent directory traversal.

    Rejects '..' sequences, absolute paths, and special characters.

    Raises:
        ValueError: If the name is unsafe.
    """
    if not name or '..' in name or '/' in name or '\\' in name or '\x00' in name:
        raise ValueError(f"Invalid path component: {name!r}")
    if not _SAFE_NAME_RE.match(name):
        raise ValueError(f"Invalid characters in path component: {name!r}")
    return name


def _list_categories() -> list[dict]:
    """List template categories (subdirectories)."""
    templates_dir = _get_templates_dir()
    categories = []
    if templates_dir.is_dir():
        for entry in sorted(templates_dir.iterdir()):
            if entry.is_dir():
                template_count = sum(
                    1
                    for f in entry.iterdir()
                    if f.is_file() and f.suffix in (".tml", ".toml", ".json", ".yaml", ".yml")
                )
                categories.append(
                    {"name": entry.name, "template_count": template_count}
                )
    return categories


def _list_templates_in_category(category: str) -> list[dict]:
    """List templates within a category."""
    _validate_path_component(category)
    cat_dir = _get_templates_dir() / category
    templates = []
    if cat_dir.is_dir():
        for f in sorted(cat_dir.iterdir()):
            if f.is_file() and f.suffix in (".tml", ".toml", ".json", ".yaml", ".yml"):
                templates.append(
                    {
                        "name": f.stem,
                        "path": str(f),
                        "format": f.suffix.lstrip("."),
                    }
                )
    return templates


@mcp.resource("usecvislib://templates/list")
def list_template_categories() -> str:
    """List all available template categories and their template counts."""
    categories = _list_categories()
    return json.dumps({"categories": categories}, indent=2)


@mcp.resource("usecvislib://templates/{category}/list")
def list_templates(category: str) -> str:
    """List all templates in a specific category."""
    templates = _list_templates_in_category(category)
    return json.dumps(
        {"category": category, "templates": templates}, indent=2
    )


@mcp.resource("usecvislib://templates/{category}/{name}")
def get_template(category: str, name: str) -> str:
    """Get the content of a specific template."""
    _validate_path_component(category)
    _validate_path_component(name)
    cat_dir = _get_templates_dir() / category

    # Verify resolved path stays within templates directory
    templates_dir = _get_templates_dir().resolve()

    # Try common extensions
    for ext in (".tml", ".toml", ".json", ".yaml", ".yml"):
        candidate = cat_dir / f"{name}{ext}"
        if not str(candidate.resolve()).startswith(str(templates_dir)):
            continue
        if candidate.is_file():
            content = candidate.read_text(encoding="utf-8")
            return json.dumps(
                {
                    "category": category,
                    "name": name,
                    "format": ext.lstrip("."),
                    "content": content,
                },
                indent=2,
            )

    return json.dumps({"error": f"Template '{name}' not found in '{category}'"})
