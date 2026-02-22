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


skip_no_graphviz = pytest.mark.skipif(
    not has_graphviz(), reason="Graphviz (dot) not installed"
)

skip_no_mermaid = pytest.mark.skipif(
    not has_mermaid_cli(), reason="mermaid-cli (mmdc) not installed"
)
