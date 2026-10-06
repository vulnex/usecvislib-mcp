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

import pytest


@pytest.fixture(autouse=True)
def _mcp_env(tmp_path):
    """Set up environment variables pointing to temp directories and reset global state."""
    import usecvislib_mcp.config as _config

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

    # Reset global rate limiter so tests start with a fresh instance
    old_rate_limiter = _config._rate_limiter
    _config._rate_limiter = None

    yield

    # Restore rate limiter
    _config._rate_limiter = old_rate_limiter

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


skip_no_graphviz = pytest.mark.skipif(not has_graphviz(), reason="Graphviz (dot) not installed")

skip_no_mermaid = pytest.mark.skipif(
    not has_mermaid_cli(), reason="mermaid-cli (mmdc) not installed"
)

skip_no_diagrams = pytest.mark.skipif(
    not has_diagrams_pkg() or not has_graphviz(),
    reason="diagrams package or Graphviz not installed",
)


def _can_import(*names):
    """Check if usecvislib exports the given names."""
    try:
        import usecvislib

        return all(hasattr(usecvislib, n) for n in names)
    except ImportError:
        return False


skip_no_component_diagram = pytest.mark.skipif(
    not _can_import("ComponentDiagram"),
    reason="usecvislib.ComponentDiagram not available",
)

skip_no_privilege_gradient = pytest.mark.skipif(
    not _can_import("PrivilegeGradient"),
    reason="usecvislib.PrivilegeGradient not available",
)

skip_no_dependency_graph = pytest.mark.skipif(
    not _can_import("DependencyGraph"),
    reason="usecvislib.DependencyGraph not available",
)

skip_no_kill_chain = pytest.mark.skipif(
    not _can_import("KillChain"),
    reason="usecvislib.KillChain not available",
)

skip_no_timeline = pytest.mark.skipif(
    not _can_import("IncidentTimeline"),
    reason="usecvislib.IncidentTimeline not available",
)

skip_no_vuln_tree = pytest.mark.skipif(
    not _can_import("VulnDependencyTree"),
    reason="usecvislib.VulnDependencyTree not available",
)

skip_no_maestro = pytest.mark.skipif(
    not _can_import("MaestroThreatModel"),
    reason="usecvislib.MaestroThreatModel not available",
)

skip_no_export = pytest.mark.skipif(
    not _can_import("ComponentDiagram", "DependencyGraph", "PrivilegeGradient"),
    reason="Export tools require ComponentDiagram, DependencyGraph, and PrivilegeGradient",
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
        "title": "Test Component Diagram",
        "layers": [
            {
                "name": "Presentation",
                "order": 1,
                "components": [{"id": "ui", "name": "Web UI", "type": "frontend"}],
            },
            {
                "name": "Business",
                "order": 2,
                "components": [{"id": "api", "name": "REST API", "type": "service"}],
            },
            {
                "name": "Data",
                "order": 3,
                "components": [{"id": "db", "name": "PostgreSQL", "type": "database"}],
            },
        ],
        "connections": [
            {"from": "ui", "to": "api", "label": "HTTP", "style": "sync"},
            {"from": "api", "to": "db", "label": "SQL", "style": "sync"},
        ],
    }


@pytest.fixture
def sample_dependency_graph_config():
    """Minimal valid dependency graph config."""
    return {
        "title": "Test Dependency Graph",
        "modules": [
            {"id": "core", "name": "Core", "group": "app", "sloc": 500},
            {"id": "api", "name": "API", "group": "app", "sloc": 300},
            {"id": "utils", "name": "Utils", "group": "lib", "sloc": 100},
        ],
        "dependencies": [
            {"from": "api", "to": "core", "type": "import"},
            {"from": "core", "to": "utils", "type": "import"},
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


@pytest.fixture
def sample_kill_chain_config():
    """Minimal valid kill chain config on a custom phase axis."""
    return {
        "killchain": {
            "name": "Test Kill Chain",
            "framework": "custom",
            "phases": ["Access", "Collection", "Exfiltration"],
        },
        "techniques": {
            "T1": {
                "name": "Valid Accounts",
                "phase": "Access",
                "severity": "high",
                "detected": True,
            },
            "T2": {"name": "Bulk Collection", "phase": "Collection", "severity": "medium"},
            "T3": {
                "name": "Cloud Upload",
                "phase": "Exfiltration",
                "severity": "critical",
                "detected": True,
                "mitigated": True,
            },
        },
        "incidents": [{"id": "INC-1", "name": "Test Incident", "techniques": ["T1", "T2", "T3"]}],
    }


@pytest.fixture
def sample_timeline_config():
    """Minimal valid incident timeline config with detection/containment phases."""
    return {
        "incident": {"name": "Test Incident", "id": "INC-1"},
        "phases": [
            {"name": "Detection", "start": "2026-02-03T14:00:00Z", "end": "2026-02-03T14:30:00Z"},
            {"name": "Containment", "start": "2026-02-03T14:30:00Z", "end": "2026-02-03T15:00:00Z"},
        ],
        "events": [
            {
                "id": "E1",
                "timestamp": "2026-02-03T13:10:00Z",
                "title": "Phishing link clicked",
                "severity": "high",
                "lane": "User",
                "technique": "T1566.002",
            },
            {
                "id": "E2",
                "timestamp": "2026-02-03T14:05:00Z",
                "title": "Alert raised",
                "severity": "medium",
                "lane": "SOC",
            },
            {
                "id": "E3",
                "timestamp": "2026-02-03T14:45:00Z",
                "title": "Session revoked",
                "severity": "low",
                "lane": "SOC",
            },
        ],
    }


@pytest.fixture
def sample_vuln_tree_config():
    """Minimal valid vulnerability tree: app -> lib -> vulnerable transitive dep."""
    return {
        "vulntree": {"name": "Test Vuln Tree", "root_packages": ["app"]},
        "dependencies": {
            "app": {
                "name": "app",
                "version": "1.0.0",
                "direct": True,
                "dependencies": ["lib", "clean"],
            },
            "lib": {"name": "lib", "version": "2.0.0", "direct": True, "dependencies": ["core"]},
            "clean": {"name": "clean", "version": "0.1.0", "direct": True, "dependencies": []},
            "core": {
                "name": "core",
                "version": "2.14.1",
                "dependencies": [],
                "vulnerabilities": [
                    {
                        "id": "CVE-2021-44228",
                        "severity": "critical",
                        "cvss": 10.0,
                        "fixed_version": "2.17.1",
                        "exploited": True,
                    }
                ],
            },
        },
    }


@pytest.fixture
def sample_maestro_config():
    """Minimal valid MAESTRO config: one RAG agent with catalog auto-population."""
    return {
        "meta": {"name": "Test Agent System", "owner": "Security Team"},
        "architecture": {"patterns": ["single-agent", "task-oriented"]},
        "agents": [
            {
                "id": "support_agent",
                "name": "Support Agent",
                "type": "task-oriented",
                "autonomy": "reactive",
                "layers": ["foundation-models", "data-operations", "agent-frameworks"],
                "tools": ["kb-retrieval"],
            }
        ],
        "assets": [
            {
                "id": "kb",
                "name": "Knowledge Base",
                "layer": "data-operations",
                "sensitivity": "medium",
            }
        ],
        "catalog": {"mode": "auto"},
    }
