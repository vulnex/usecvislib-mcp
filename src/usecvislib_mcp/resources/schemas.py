"""MCP resources providing configuration schema documentation."""

import json

from ..server import mcp

ATTACK_TREE_SCHEMA = {
    "description": "Configuration schema for attack tree visualizations",
    "format": "TOML, JSON, or YAML",
    "sections": {
        "tree": {
            "description": "Tree metadata and settings",
            "fields": {
                "name": {"type": "string", "required": True, "description": "Name of the attack tree"},
                "root": {"type": "string", "required": True, "description": "ID of the root node"},
                "description": {"type": "string", "required": False},
                "params": {
                    "type": "object",
                    "fields": {
                        "rankdir": {"type": "string", "default": "TB", "values": ["TB", "BT", "LR", "RL"]},
                    },
                },
            },
        },
        "nodes": {
            "description": "Node definitions keyed by node ID",
            "value_fields": {
                "style": {"type": "string", "default": "filled"},
                "fillcolor": {"type": "string", "description": "Node background color"},
                "fontcolor": {"type": "string", "default": "white"},
                "shape": {"type": "string", "default": "rectangle", "values": ["rectangle", "oval", "diamond", "box"]},
                "cvss": {"type": "float", "description": "CVSS numeric score (0.0-10.0)"},
                "cvss_vector": {"type": "string", "description": "CVSS 3.1 vector string"},
            },
        },
        "edges": {
            "description": "Edge definitions keyed by parent node ID",
            "value_type": "list of objects",
            "item_fields": {
                "to": {"type": "string", "required": True, "description": "Target node ID"},
                "label": {"type": "string", "description": "Edge label (e.g. AND, OR)"},
            },
        },
    },
    "example": {
        "tree": {"name": "Web Attack", "root": "Compromise Server", "params": {"rankdir": "TB"}},
        "nodes": {
            "Compromise Server": {"style": "filled", "fillcolor": "#e74c3c", "shape": "oval"},
            "SQL Injection": {"style": "filled", "cvss": 9.8},
            "XSS": {"style": "filled", "cvss": 6.1},
        },
        "edges": {
            "Compromise Server": [
                {"to": "SQL Injection", "label": "OR"},
                {"to": "XSS", "label": "OR"},
            ]
        },
    },
}

ATTACK_GRAPH_SCHEMA = {
    "description": "Configuration schema for attack graph visualizations",
    "format": "TOML, JSON, or YAML",
    "sections": {
        "graph": {
            "description": "Graph metadata",
            "fields": {
                "name": {"type": "string", "required": True},
            },
        },
        "hosts": {
            "type": "list of objects",
            "fields": {
                "id": {"type": "string", "required": True},
                "label": {"type": "string", "required": True},
                "ip": {"type": "string"},
                "zone": {"type": "string", "values": ["internal", "dmz", "external"]},
            },
        },
        "vulnerabilities": {
            "type": "list of objects",
            "fields": {
                "id": {"type": "string", "required": True},
                "label": {"type": "string", "required": True},
                "cvss": {"type": "float", "required": True},
                "affected_host": {"type": "string", "required": True},
                "cve": {"type": "string"},
            },
        },
        "privileges": {
            "type": "list of objects",
            "fields": {
                "id": {"type": "string", "required": True},
                "label": {"type": "string", "required": True},
                "host": {"type": "string", "required": True},
                "level": {"type": "string", "values": ["none", "user", "admin", "root"]},
            },
        },
        "services": {
            "type": "list of objects",
            "fields": {
                "id": {"type": "string", "required": True},
                "label": {"type": "string", "required": True},
                "host": {"type": "string", "required": True},
                "port": {"type": "integer", "required": True},
                "protocol": {"type": "string", "default": "tcp"},
            },
        },
        "exploits": {
            "type": "list of objects",
            "fields": {
                "id": {"type": "string", "required": True},
                "label": {"type": "string", "required": True},
                "preconditions": {"type": "list of strings"},
                "postconditions": {"type": "list of strings"},
            },
        },
        "network_edges": {
            "type": "list of objects",
            "fields": {
                "from": {"type": "string", "required": True},
                "to": {"type": "string", "required": True},
                "label": {"type": "string"},
            },
        },
    },
}

THREAT_MODEL_SCHEMA = {
    "description": "Configuration schema for threat model DFD visualizations",
    "format": "TOML, JSON, or YAML",
    "note": "All element sections use dict-of-dicts keyed by element ID, not arrays.",
    "sections": {
        "model": {
            "description": "Model metadata",
            "fields": {
                "name": {"type": "string", "required": True},
                "description": {"type": "string"},
            },
        },
        "processes": {
            "type": "dict of dicts, keyed by process ID",
            "value_fields": {
                "label": {"type": "string", "required": True},
                "sanitizesInput": {"type": "boolean", "default": False},
                "hasAccessControl": {"type": "boolean", "default": False},
            },
        },
        "datastores": {
            "type": "dict of dicts, keyed by datastore ID",
            "value_fields": {
                "label": {"type": "string", "required": True},
                "isEncrypted": {"type": "boolean", "default": False},
                "storesPII": {"type": "boolean", "default": False},
            },
        },
        "externals": {
            "type": "dict of dicts, keyed by external entity ID",
            "value_fields": {
                "label": {"type": "string", "required": True},
                "isTrusted": {"type": "boolean", "default": True},
            },
        },
        "dataflows": {
            "type": "dict of dicts, keyed by dataflow ID",
            "value_fields": {
                "from": {"type": "string", "required": True},
                "to": {"type": "string", "required": True},
                "label": {"type": "string"},
                "isEncrypted": {"type": "boolean", "default": False},
            },
        },
        "boundaries": {
            "type": "dict of dicts, keyed by boundary ID",
            "value_fields": {
                "label": {"type": "string", "required": True},
                "elements": {"type": "list of strings", "required": True},
            },
        },
    },
}

MERMAID_SCHEMA = {
    "description": "Parameter schema for Mermaid diagram rendering",
    "parameters": {
        "source": {
            "type": "string",
            "required": True,
            "description": "Mermaid diagram source text",
        },
        "format": {
            "type": "string",
            "default": "png",
            "values": ["png", "svg", "pdf"],
        },
        "theme": {
            "type": "string",
            "default": "default",
            "values": ["default", "dark", "forest", "neutral"],
        },
        "background": {
            "type": "string",
            "default": "white",
            "description": "Background color (e.g. 'white', 'transparent', '#f0f0f0')",
        },
        "width": {"type": "integer", "default": 800},
        "height": {"type": "integer", "default": 600},
    },
    "supported_diagram_types": [
        "flowchart", "sequenceDiagram", "classDiagram", "erDiagram",
        "stateDiagram", "gantt", "pie", "mindmap", "timeline",
        "journey", "quadrantChart", "gitGraph", "sankey-beta",
        "block-beta", "packet-beta", "kanban", "architecture-beta",
        "c4Context", "c4Container", "c4Component", "c4Dynamic",
    ],
}


@mcp.resource("usecvislib://schemas/attack-tree")
def get_attack_tree_schema() -> str:
    """Configuration schema documentation for attack tree visualizations."""
    return json.dumps(ATTACK_TREE_SCHEMA, indent=2)


@mcp.resource("usecvislib://schemas/attack-graph")
def get_attack_graph_schema() -> str:
    """Configuration schema documentation for attack graph visualizations."""
    return json.dumps(ATTACK_GRAPH_SCHEMA, indent=2)


@mcp.resource("usecvislib://schemas/threat-model")
def get_threat_model_schema() -> str:
    """Configuration schema documentation for threat model DFD visualizations."""
    return json.dumps(THREAT_MODEL_SCHEMA, indent=2)


@mcp.resource("usecvislib://schemas/mermaid")
def get_mermaid_schema() -> str:
    """Parameter schema documentation for Mermaid diagram rendering."""
    return json.dumps(MERMAID_SCHEMA, indent=2)
