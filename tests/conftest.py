#
# VULNEX -Universal Security Visualization Library-
#
# File: tests/conftest.py
# Author: Simon Roses Femerling
# Created: 2026-02-23
# Last Modified: 2026-02-24
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Shared fixtures for usecvislib-mcp tests."""

import os
import shutil
import tempfile

import pytest


@pytest.fixture(autouse=True)
def _mcp_env(tmp_path):
    """Set up environment variables pointing to temp directories."""
    output_dir = tmp_path / "output"
    temp_dir = tmp_path / "temp"
    output_dir.mkdir()
    temp_dir.mkdir()

    env_vars = {
        "USECVISLIB_MCP_OUTPUT_DIR": str(output_dir),
        "USECVISLIB_MCP_TEMP_DIR": str(temp_dir),
        "USECVISLIB_MCP_LOG_LEVEL": "DEBUG",
        "USECVISLIB_MCP_OUTPUT_MODE": "file",
    }

    old_env = {}
    for key, value in env_vars.items():
        old_env[key] = os.environ.get(key)
        os.environ[key] = value

    yield

    for key, old_value in old_env.items():
        if old_value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = old_value


@pytest.fixture
def sample_attack_tree_config():
    """Minimal valid attack tree config."""
    return {
        "tree": {
            "name": "Test Attack Tree",
            "root": "Root Goal",
            "params": {"rankdir": "TB"},
        },
        "nodes": {
            "Root Goal": {
                "style": "filled",
                "fillcolor": "#e74c3c",
                "fontcolor": "white",
                "shape": "oval",
            },
            "Sub Goal A": {
                "style": "filled",
                "fillcolor": "#3498db",
                "fontcolor": "white",
            },
            "Sub Goal B": {
                "style": "filled",
                "fillcolor": "#2ecc71",
                "fontcolor": "white",
            },
        },
        "edges": {
            "Root Goal": [
                {"to": "Sub Goal A", "label": "OR"},
                {"to": "Sub Goal B", "label": "OR"},
            ]
        },
    }


@pytest.fixture
def sample_attack_graph_config():
    """Minimal valid attack graph config."""
    return {
        "graph": {"name": "Test Attack Graph"},
        "hosts": [
            {"id": "attacker", "label": "Attacker", "ip": "external", "zone": "external"},
            {"id": "webserver", "label": "Web Server", "ip": "10.0.1.10", "zone": "dmz"},
            {"id": "dbserver", "label": "DB Server", "ip": "10.0.2.20", "zone": "internal"},
        ],
        "vulnerabilities": [
            {
                "id": "vuln1",
                "label": "RCE",
                "cvss": 9.8,
                "affected_host": "webserver",
            }
        ],
        "privileges": [
            {
                "id": "priv_user",
                "label": "Web User",
                "host": "webserver",
                "level": "user",
            }
        ],
        "services": [
            {
                "id": "svc_http",
                "label": "HTTP",
                "host": "webserver",
                "port": 80,
                "protocol": "tcp",
            }
        ],
        "exploits": [
            {
                "id": "exp1",
                "label": "Exploit RCE",
                "preconditions": ["vuln1"],
                "postconditions": ["priv_user"],
            }
        ],
        "network_edges": [
            {"from": "attacker", "to": "webserver", "label": "Internet"},
            {"from": "webserver", "to": "dbserver", "label": "LAN"},
        ],
    }


@pytest.fixture
def sample_threat_model_config():
    """Minimal valid threat model config (dict-of-dicts format)."""
    return {
        "model": {
            "name": "Test Threat Model",
            "description": "Test DFD",
        },
        "processes": {
            "web_app": {
                "label": "Web Application",
                "sanitizesInput": True,
                "hasAccessControl": True,
            },
        },
        "datastores": {
            "db": {
                "label": "Database",
                "isEncrypted": True,
                "storesPII": True,
            },
        },
        "externals": {
            "user": {"label": "User", "isTrusted": True},
        },
        "dataflows": {
            "f1": {
                "from": "user",
                "to": "web_app",
                "label": "HTTPS",
                "isEncrypted": True,
            },
            "f2": {
                "from": "web_app",
                "to": "db",
                "label": "SQL",
                "isEncrypted": False,
            },
        },
        "boundaries": {
            "internal": {
                "label": "Internal",
                "elements": ["web_app", "db"],
            },
        },
    }


@pytest.fixture
def sample_mermaid_source():
    """Simple Mermaid flowchart source."""
    return """flowchart TD
    A[Start] --> B{Decision}
    B -->|Yes| C[Action 1]
    B -->|No| D[Action 2]
    C --> E[End]
    D --> E"""


def has_graphviz():
    """Check if Graphviz is installed."""
    return shutil.which("dot") is not None


def has_mermaid_cli():
    """Check if mermaid-cli (mmdc) is installed."""
    return shutil.which("mmdc") is not None


def has_diagrams_pkg():
    """Check if the 'diagrams' Python package is installed."""
    try:
        import diagrams  # noqa: F401
        return True
    except ImportError:
        return False


skip_no_graphviz = pytest.mark.skipif(
    not has_graphviz(), reason="Graphviz (dot) not installed"
)

skip_no_mermaid = pytest.mark.skipif(
    not has_mermaid_cli(), reason="mermaid-cli (mmdc) not installed"
)

skip_no_diagrams = pytest.mark.skipif(
    not has_diagrams_pkg() or not has_graphviz(),
    reason="diagrams package or Graphviz not installed",
)


@pytest.fixture
def sample_privilege_gradient_config():
    """Minimal valid privilege gradient config."""
    return {
        "gradient": {
            "name": "Test Privilege Gradient",
            "description": "Test trust zones",
        },
        "zones": {
            "external": {"label": "External", "level": 0, "color": "#e74c3c"},
            "dmz": {"label": "DMZ", "level": 1, "color": "#f39c12"},
            "internal": {"label": "Internal", "level": 2, "color": "#3498db"},
        },
        "components": {
            "cdn": {"label": "CDN", "zone": "external"},
            "web_app": {"label": "Web App", "zone": "dmz"},
            "api": {"label": "API Server", "zone": "internal"},
        },
        "influences": [
            {"from": "cdn", "to": "web_app", "label": "HTTPS"},
            {"from": "web_app", "to": "api", "label": "REST"},
        ],
    }


@pytest.fixture
def sample_cloud_diagram_config():
    """Minimal valid cloud diagram config."""
    return {
        "diagram": {
            "title": "Test Cloud Diagram",
            "direction": "TB",
            "outformat": "png",
        },
        "nodes": [
            {"id": "lb", "icon": "aws.network.ELB", "label": "Load Balancer"},
            {"id": "web", "icon": "aws.compute.EC2", "label": "Web Server"},
            {"id": "db", "icon": "aws.database.RDS", "label": "Database"},
        ],
        "edges": [
            {"from": "lb", "to": "web", "label": "HTTP"},
            {"from": "web", "to": "db", "label": "SQL"},
        ],
    }


@pytest.fixture
def sample_custom_diagram_config():
    """Minimal valid custom diagram config."""
    return {
        "diagram": {
            "title": "Test Custom Diagram",
            "layout": "hierarchical",
            "direction": "TB",
        },
        "schema": {
            "nodes": {
                "process": {
                    "shape": "rectangle",
                    "required_fields": ["name"],
                    "style": {"fillcolor": "#3498DB", "fontcolor": "white"},
                    "label_template": "{name}",
                },
            },
            "edges": {
                "flow": {
                    "style": "solid",
                    "color": "#333333",
                },
            },
        },
        "nodes": [
            {"id": "a", "type": "process", "name": "Component A"},
            {"id": "b", "type": "process", "name": "Component B"},
            {"id": "c", "type": "process", "name": "Component C"},
        ],
        "edges": [
            {"from": "a", "to": "b", "type": "flow", "label": "calls"},
            {"from": "b", "to": "c", "type": "flow", "label": "depends"},
        ],
    }


@pytest.fixture
def sample_component_diagram_config():
    """Minimal valid component diagram config."""
    return {
        "diagram": {
            "name": "Test Component Diagram",
            "description": "Test architecture layers",
        },
        "layers": {
            "presentation": {"label": "Presentation Layer", "order": 1, "color": "#3498db"},
            "business": {"label": "Business Layer", "order": 2, "color": "#2ecc71"},
            "data": {"label": "Data Layer", "order": 3, "color": "#e74c3c"},
        },
        "components": {
            "ui": {"label": "Web UI", "layer": "presentation"},
            "api": {"label": "REST API", "layer": "business"},
            "db": {"label": "PostgreSQL", "layer": "data"},
        },
        "connections": [
            {"from": "ui", "to": "api", "label": "HTTP"},
            {"from": "api", "to": "db", "label": "SQL"},
        ],
    }


@pytest.fixture
def sample_dependency_graph_config():
    """Minimal valid dependency graph config."""
    return {
        "graph": {
            "name": "Test Dependency Graph",
            "description": "Test module dependencies",
        },
        "modules": {
            "core": {"label": "Core", "sloc": 500, "language": "python"},
            "api": {"label": "API", "sloc": 300, "language": "python"},
            "utils": {"label": "Utils", "sloc": 100, "language": "python"},
        },
        "dependencies": [
            {"from": "api", "to": "core", "label": "imports", "type": "import"},
            {"from": "core", "to": "utils", "label": "imports", "type": "import"},
        ],
    }


@pytest.fixture
def sample_binary_file(tmp_path):
    """Create a small binary test fixture (1KB of pseudo-random bytes)."""
    import hashlib

    # Deterministic pseudo-random bytes using hash chain
    data = b""
    seed = b"usecvislib-test-binary"
    for i in range(64):
        chunk = hashlib.sha256(seed + i.to_bytes(4, "big")).digest()
        data += chunk[:16]

    binary_path = tmp_path / "test_binary.bin"
    binary_path.write_bytes(data)
    return str(binary_path)
